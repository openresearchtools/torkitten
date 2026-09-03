use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use torkitten_core::{
    Device, DeviceId, GatewayConfig, Guest, GuestId, Mapping, MappingId, Site, SiteId,
    ValidationError,
};
use zeroize::Zeroizing;

use crate::{EncryptedSecret, VaultCipher, cipher::CipherError, key::KeyError};

const DATABASE_FILENAME: &str = "state.sqlite3";
const KEY_FILENAME: &str = "secrets/vault.key";
const DATABASE_SCHEMA_VERSION: i64 = 3;
const LEGACY_SITE_ID: &str = "default";
const LEGACY_SITE_DISPLAY_NAME: &str = "Default site";

pub struct Store {
    connection: Connection,
    cipher: VaultCipher,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    pub expires_unix: i64,
    pub last_seen_unix: i64,
}

pub struct DeviceRecord {
    pub device: Device,
    pub secret_material: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for DeviceRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceRecord")
            .field("device", &self.device)
            .field("secret_material", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationSettings {
    pub resume_after_boot: bool,
    pub emergency_disabled: bool,
}

impl Store {
    /// Opens or creates the database and vault under a private state directory.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe storage, I/O failures, SQLite failures, or
    /// invalid persisted configuration. Schema changes are atomic.
    pub fn open(state_directory: &Path) -> Result<Self, StoreError> {
        ensure_private_directory(state_directory)?;
        let database_path = state_directory.join(DATABASE_FILENAME);
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&database_path)
        {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        ensure_private_database(&database_path)?;

        let key = crate::VaultKey::load_or_create(&state_directory.join(KEY_FILENAME))?;
        let connection = Connection::open(database_path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;

        let mut store = Self {
            connection,
            cipher: VaultCipher::new(&key),
        };
        store.migrate()?;
        store.gateway_config()?.validate()?;
        Ok(store)
    }

    /// Returns the complete, validated multi-site configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite access, JSON decoding, or validation fails.
    pub fn gateway_config(&self) -> Result<GatewayConfig, StoreError> {
        let site_rows = {
            let mut statement = self
                .connection
                .prepare("SELECT id, display_name, enabled FROM sites ORDER BY id")?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        let mut sites = Vec::with_capacity(site_rows.len());
        for (id, display_name, enabled) in site_rows {
            let id = SiteId::new(id)?;
            sites.push(Site {
                mappings: self.site_mappings(&id)?,
                id,
                display_name,
                enabled,
            });
        }
        let config = GatewayConfig {
            sites,
            ..GatewayConfig::default()
        };
        config.validate()?;
        Ok(config)
    }

    /// Returns one site and all mappings beneath it.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite access, JSON decoding, or validation fails.
    pub fn site(&self, id: &SiteId) -> Result<Option<Site>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT display_name, enabled FROM sites WHERE id = ?1",
                [id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?;
        let Some((display_name, enabled)) = row else {
            return Ok(None);
        };
        let site = Site {
            id: id.clone(),
            display_name,
            enabled,
            mappings: self.site_mappings(id)?,
        };
        site.validate()?;
        Ok(Some(site))
    }

    /// Adds or replaces one complete site in an atomic validated transaction.
    /// Mappings omitted from the supplied site are removed.
    ///
    /// # Errors
    ///
    /// Returns an error when the site is invalid or cannot be committed.
    pub fn put_site(&mut self, site: &Site) -> Result<(), StoreError> {
        site.validate()?;
        let mut candidate = self.gateway_config()?;
        candidate.sites.retain(|existing| existing.id != site.id);
        candidate.sites.push(site.clone());
        candidate.validate()?;

        let retained_mapping_ids = site
            .mappings
            .iter()
            .map(|mapping| mapping.id.as_str())
            .collect::<HashSet<_>>();
        let retained_permissions = {
            let mut statement = self.connection.prepare(
                "SELECT guest_id, mapping_id FROM guest_mapping_permissions
                 WHERE site_id = ?1 ORDER BY guest_id, mapping_id",
            )?;
            let rows = statement.query_map([site.id.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|(_, mapping_id)| retained_mapping_ids.contains(mapping_id.as_str()))
                .collect::<Vec<_>>()
        };

        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO sites (id, display_name, enabled) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name,
                                           enabled = excluded.enabled",
            params![site.id.as_str(), site.display_name, site.enabled],
        )?;
        transaction.execute(
            "DELETE FROM mappings WHERE site_id = ?1",
            [site.id.as_str()],
        )?;
        for mapping in &site.mappings {
            insert_mapping(&transaction, &site.id, mapping)?;
        }
        for (guest_id, mapping_id) in retained_permissions {
            transaction.execute(
                "INSERT INTO guest_mapping_permissions (site_id, guest_id, mapping_id)
                 VALUES (?1, ?2, ?3)",
                params![site.id.as_str(), guest_id, mapping_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Removes a site and its mappings, returning whether a site existed.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot apply the deletion.
    pub fn remove_site(&self, id: &SiteId) -> Result<bool, StoreError> {
        Ok(self
            .connection
            .execute("DELETE FROM sites WHERE id = ?1", [id.as_str()])?
            != 0)
    }

    /// Adds or replaces one mapping within an existing site.
    ///
    /// # Errors
    ///
    /// Returns an error when the site is missing, the resulting site is
    /// invalid, or SQLite cannot commit the mapping.
    pub fn put_mapping(&mut self, site_id: &SiteId, mapping: &Mapping) -> Result<(), StoreError> {
        mapping.validate()?;
        let mut site = self
            .site(site_id)?
            .ok_or_else(|| StoreError::SiteNotFound(site_id.clone()))?;
        site.mappings.retain(|existing| existing.id != mapping.id);
        site.mappings.push(mapping.clone());
        site.validate()?;

        let transaction = self.connection.transaction()?;
        insert_mapping(&transaction, site_id, mapping)?;
        transaction.commit()?;
        Ok(())
    }

    /// Removes a mapping from one site, returning whether it existed.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot apply the deletion.
    pub fn remove_mapping(
        &self,
        site_id: &SiteId,
        mapping_id: &MappingId,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM mappings WHERE site_id = ?1 AND id = ?2",
            params![site_id.as_str(), mapping_id.as_str()],
        )? != 0)
    }

    /// Changes the desired publication state for one site.
    ///
    /// # Errors
    ///
    /// Returns an error when the site is missing or cannot be committed.
    pub fn set_site_enabled(&mut self, site_id: &SiteId, enabled: bool) -> Result<(), StoreError> {
        let mut site = self
            .site(site_id)?
            .ok_or_else(|| StoreError::SiteNotFound(site_id.clone()))?;
        site.enabled = enabled;
        self.put_site(&site)
    }

    /// Changes the desired publication state for one mapping without changing
    /// its site or siblings.
    ///
    /// # Errors
    ///
    /// Returns an error when the site or mapping is missing or cannot be
    /// committed.
    pub fn set_mapping_enabled(
        &mut self,
        site_id: &SiteId,
        mapping_id: &MappingId,
        enabled: bool,
    ) -> Result<(), StoreError> {
        let mut site = self
            .site(site_id)?
            .ok_or_else(|| StoreError::SiteNotFound(site_id.clone()))?;
        let mapping = site
            .mappings
            .iter_mut()
            .find(|mapping| mapping.id == *mapping_id)
            .ok_or_else(|| StoreError::MappingNotFound {
                site_id: site_id.clone(),
                mapping_id: mapping_id.clone(),
            })?;
        mapping.enabled = enabled;
        self.put_site(&site)
    }

    /// Adds or replaces one guest within an existing site.
    ///
    /// # Errors
    ///
    /// Returns an error when the guest is invalid, its site is missing, or the
    /// update cannot be committed.
    pub fn put_guest(&self, guest: &Guest) -> Result<(), StoreError> {
        guest.validate()?;
        if self.site(&guest.site_id)?.is_none() {
            return Err(StoreError::SiteNotFound(guest.site_id.clone()));
        }
        self.connection.execute(
            "INSERT INTO guests (site_id, id, display_name, enabled)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(site_id, id) DO UPDATE SET
                 display_name = excluded.display_name,
                 enabled = excluded.enabled",
            params![
                guest.site_id.as_str(),
                guest.id.as_str(),
                guest.display_name,
                guest.enabled
            ],
        )?;
        Ok(())
    }

    /// Returns one site-scoped guest.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite access or persisted validation fails.
    pub fn guest(&self, site_id: &SiteId, guest_id: &GuestId) -> Result<Option<Guest>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT display_name, enabled FROM guests
                 WHERE site_id = ?1 AND id = ?2",
                params![site_id.as_str(), guest_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?;
        let Some((display_name, enabled)) = row else {
            return Ok(None);
        };
        let guest = Guest {
            site_id: site_id.clone(),
            id: guest_id.clone(),
            display_name,
            enabled,
        };
        guest.validate()?;
        Ok(Some(guest))
    }

    /// Returns every guest for one site in stable identifier order.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite access or persisted validation fails.
    pub fn guests(&self, site_id: &SiteId) -> Result<Vec<Guest>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, display_name, enabled FROM guests
             WHERE site_id = ?1 ORDER BY id",
        )?;
        let rows = statement.query_map([site_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
            ))
        })?;
        let mut guests = Vec::new();
        for row in rows {
            let (id, display_name, enabled) = row?;
            let guest = Guest {
                site_id: site_id.clone(),
                id: GuestId::new(id)?,
                display_name,
                enabled,
            };
            guest.validate()?;
            guests.push(guest);
        }
        Ok(guests)
    }

    /// Removes a guest and cascades only that guest's devices and grants.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot apply the deletion.
    pub fn remove_guest(&self, site_id: &SiteId, guest_id: &GuestId) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM guests WHERE site_id = ?1 AND id = ?2",
            params![site_id.as_str(), guest_id.as_str()],
        )? != 0)
    }

    /// Adds or replaces one device and encrypts its Tor client material.
    ///
    /// # Errors
    ///
    /// Returns an error when the device is invalid, its guest is missing, or
    /// encryption and persistence fail.
    pub fn put_device(&self, device: &Device, secret_material: &[u8]) -> Result<(), StoreError> {
        device.validate()?;
        if self.guest(&device.site_id, &device.guest_id)?.is_none() {
            return Err(StoreError::GuestNotFound {
                site_id: device.site_id.clone(),
                guest_id: device.guest_id.clone(),
            });
        }
        let aad = device_secret_name(&device.site_id, &device.guest_id, &device.id);
        let encrypted = self.cipher.encrypt(&aad, secret_material)?;
        self.connection.execute(
            "INSERT INTO devices
                 (site_id, guest_id, id, display_name, tor_client_name, enabled, encrypted_secret)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(site_id, guest_id, id) DO UPDATE SET
                 display_name = excluded.display_name,
                 tor_client_name = excluded.tor_client_name,
                 enabled = excluded.enabled,
                 encrypted_secret = excluded.encrypted_secret",
            params![
                device.site_id.as_str(),
                device.guest_id.as_str(),
                device.id.as_str(),
                device.display_name,
                device.tor_client_name,
                device.enabled,
                encrypted.as_bytes()
            ],
        )?;
        Ok(())
    }

    /// Returns one device and decrypts its Tor client material.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite access, persisted validation, or
    /// authenticated decryption fails.
    pub fn device(
        &self,
        site_id: &SiteId,
        guest_id: &GuestId,
        device_id: &DeviceId,
    ) -> Result<Option<DeviceRecord>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT display_name, tor_client_name, enabled, encrypted_secret
                 FROM devices WHERE site_id = ?1 AND guest_id = ?2 AND id = ?3",
                params![site_id.as_str(), guest_id.as_str(), device_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((display_name, tor_client_name, enabled, encrypted)) = row else {
            return Ok(None);
        };
        let device = Device {
            site_id: site_id.clone(),
            guest_id: guest_id.clone(),
            id: device_id.clone(),
            display_name,
            tor_client_name,
            enabled,
        };
        device.validate()?;
        let aad = device_secret_name(site_id, guest_id, device_id);
        let secret_material = self
            .cipher
            .decrypt(&aad, &EncryptedSecret::from_bytes(encrypted))?;
        Ok(Some(DeviceRecord {
            device,
            secret_material,
        }))
    }

    /// Returns device metadata for one guest without decrypting credentials.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite access or persisted validation fails.
    pub fn devices(&self, site_id: &SiteId, guest_id: &GuestId) -> Result<Vec<Device>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, display_name, tor_client_name, enabled FROM devices
             WHERE site_id = ?1 AND guest_id = ?2 ORDER BY id",
        )?;
        let rows = statement.query_map(params![site_id.as_str(), guest_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })?;
        let mut devices = Vec::new();
        for row in rows {
            let (id, display_name, tor_client_name, enabled) = row?;
            let device = Device {
                site_id: site_id.clone(),
                guest_id: guest_id.clone(),
                id: DeviceId::new(id)?,
                display_name,
                tor_client_name,
                enabled,
            };
            device.validate()?;
            devices.push(device);
        }
        Ok(devices)
    }

    /// Removes one device and its encrypted client material.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot apply the deletion.
    pub fn remove_device(
        &self,
        site_id: &SiteId,
        guest_id: &GuestId,
        device_id: &DeviceId,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM devices WHERE site_id = ?1 AND guest_id = ?2 AND id = ?3",
            params![site_id.as_str(), guest_id.as_str(), device_id.as_str()],
        )? != 0)
    }

    /// Replaces the complete mapping grant set for one guest atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the guest or a mapping is missing, identifiers
    /// are duplicated, or SQLite cannot commit the replacement.
    pub fn set_guest_permissions(
        &mut self,
        site_id: &SiteId,
        guest_id: &GuestId,
        mapping_ids: &[MappingId],
    ) -> Result<(), StoreError> {
        if self.guest(site_id, guest_id)?.is_none() {
            return Err(StoreError::GuestNotFound {
                site_id: site_id.clone(),
                guest_id: guest_id.clone(),
            });
        }
        let mut unique = HashSet::with_capacity(mapping_ids.len());
        for mapping_id in mapping_ids {
            if !unique.insert(mapping_id.clone()) {
                return Err(StoreError::DuplicatePermission(mapping_id.clone()));
            }
            let exists = self.connection.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM mappings WHERE site_id = ?1 AND id = ?2
                 )",
                params![site_id.as_str(), mapping_id.as_str()],
                |row| row.get::<_, bool>(0),
            )?;
            if !exists {
                return Err(StoreError::MappingNotFound {
                    site_id: site_id.clone(),
                    mapping_id: mapping_id.clone(),
                });
            }
        }

        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM guest_mapping_permissions WHERE site_id = ?1 AND guest_id = ?2",
            params![site_id.as_str(), guest_id.as_str()],
        )?;
        for mapping_id in mapping_ids {
            transaction.execute(
                "INSERT INTO guest_mapping_permissions (site_id, guest_id, mapping_id)
                 VALUES (?1, ?2, ?3)",
                params![site_id.as_str(), guest_id.as_str(), mapping_id.as_str()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Returns one guest's granted mappings in stable identifier order.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite access or persisted validation fails.
    pub fn guest_permissions(
        &self,
        site_id: &SiteId,
        guest_id: &GuestId,
    ) -> Result<Vec<MappingId>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT mapping_id FROM guest_mapping_permissions
             WHERE site_id = ?1 AND guest_id = ?2 ORDER BY mapping_id",
        )?;
        let rows = statement.query_map(params![site_id.as_str(), guest_id.as_str()], |row| {
            row.get::<_, String>(0)
        })?;
        let mut mappings = Vec::new();
        for row in rows {
            mappings.push(MappingId::new(row?)?);
        }
        Ok(mappings)
    }

    /// Returns the persistent publication policy and emergency latch.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot read the singleton settings row.
    pub fn publication_settings(&self) -> Result<PublicationSettings, StoreError> {
        self.connection
            .query_row(
                "SELECT resume_after_boot, emergency_disabled
                 FROM publication_settings WHERE singleton = 1",
                [],
                |row| {
                    Ok(PublicationSettings {
                        resume_after_boot: row.get(0)?,
                        emergency_disabled: row.get(1)?,
                    })
                },
            )
            .map_err(Into::into)
    }

    /// Updates whether enabled sites resume automatically after boot.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot commit the setting.
    pub fn set_resume_after_boot(&self, enabled: bool) -> Result<(), StoreError> {
        self.connection.execute(
            "UPDATE publication_settings SET resume_after_boot = ?1 WHERE singleton = 1",
            [enabled],
        )?;
        Ok(())
    }

    /// Sets or clears the persistent publication emergency latch.
    ///
    /// Clearing this value is intended only for local administration.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot commit the latch.
    pub fn set_emergency_disabled(&self, disabled: bool) -> Result<(), StoreError> {
        self.connection.execute(
            "UPDATE publication_settings SET emergency_disabled = ?1 WHERE singleton = 1",
            [disabled],
        )?;
        Ok(())
    }

    /// Stores an encrypted product-wide secret bound to its logical name.
    ///
    /// # Errors
    ///
    /// Returns an error when encryption or SQLite persistence fails.
    pub fn put_secret(&self, name: &str, plaintext: &[u8]) -> Result<(), StoreError> {
        let encrypted = self.cipher.encrypt(name, plaintext)?;
        self.connection.execute(
            "INSERT INTO secrets (name, encrypted) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET encrypted = excluded.encrypted",
            params![name, encrypted.as_bytes()],
        )?;
        Ok(())
    }

    /// Retrieves and decrypts a product-wide named secret.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite access or authenticated decryption fails.
    pub fn get_secret(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        let encoded = self
            .connection
            .query_row(
                "SELECT encrypted FROM secrets WHERE name = ?1",
                [name],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        encoded
            .map(|bytes| {
                self.cipher
                    .decrypt(name, &EncryptedSecret::from_bytes(bytes))
                    .map_err(StoreError::from)
            })
            .transpose()
    }

    /// Persists only a SHA-256 digest of a random session token.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot persist the session.
    pub fn put_session(
        &self,
        token: &[u8],
        expires_unix: i64,
        now_unix: i64,
    ) -> Result<(), StoreError> {
        let token_hash = session_hash(token);
        self.connection.execute(
            "INSERT INTO sessions (token_hash, expires_unix, last_seen_unix, revoked)
             VALUES (?1, ?2, ?3, 0)",
            params![token_hash.as_slice(), expires_unix, now_unix],
        )?;
        Ok(())
    }

    /// Looks up a non-revoked, non-expired session and advances last-seen time.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot query or update the session.
    pub fn touch_session(
        &self,
        token: &[u8],
        now_unix: i64,
    ) -> Result<Option<SessionRecord>, StoreError> {
        let token_hash = session_hash(token);
        let record = self
            .connection
            .query_row(
                "SELECT expires_unix, last_seen_unix FROM sessions
                 WHERE token_hash = ?1 AND revoked = 0 AND expires_unix > ?2",
                params![token_hash.as_slice(), now_unix],
                |row| {
                    Ok(SessionRecord {
                        expires_unix: row.get(0)?,
                        last_seen_unix: row.get(1)?,
                    })
                },
            )
            .optional()?;
        if record.is_some() {
            self.connection.execute(
                "UPDATE sessions SET last_seen_unix = ?2 WHERE token_hash = ?1",
                params![token_hash.as_slice(), now_unix],
            )?;
        }
        Ok(record)
    }

    /// Revokes a session without storing its bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot update the session.
    pub fn revoke_session(&self, token: &[u8]) -> Result<bool, StoreError> {
        let token_hash = session_hash(token);
        Ok(self.connection.execute(
            "UPDATE sessions SET revoked = 1 WHERE token_hash = ?1",
            [token_hash.as_slice()],
        )? != 0)
    }

    fn site_mappings(&self, site_id: &SiteId) -> Result<Vec<Mapping>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT document FROM mappings
             WHERE site_id = ?1 ORDER BY virtual_port, id",
        )?;
        let rows = statement.query_map([site_id.as_str()], |row| row.get::<_, String>(0))?;
        let mut mappings = Vec::new();
        for row in rows {
            mappings.push(serde_json::from_str::<Mapping>(&row?)?);
        }
        Ok(mappings)
    }

    fn migrate(&mut self) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 version INTEGER NOT NULL
             );",
        )?;
        let version = transaction
            .query_row(
                "SELECT version FROM schema_version WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        match version {
            None => {
                create_current_schema(&transaction)?;
                transaction.execute(
                    "INSERT INTO schema_version (singleton, version) VALUES (1, ?1)",
                    [DATABASE_SCHEMA_VERSION],
                )?;
            }
            Some(1) => {
                migrate_v1_to_v2(&transaction)?;
                migrate_v2_to_v3(&transaction)?;
            }
            Some(2) => migrate_v2_to_v3(&transaction)?,
            Some(DATABASE_SCHEMA_VERSION) => create_current_schema(&transaction)?,
            Some(other) => return Err(StoreError::UnsupportedSchema(other)),
        }
        transaction.commit()?;
        Ok(())
    }
}

fn insert_mapping(
    transaction: &Transaction<'_>,
    site_id: &SiteId,
    mapping: &Mapping,
) -> Result<(), StoreError> {
    let document = serde_json::to_string(mapping)?;
    transaction.execute(
        "INSERT INTO mappings (site_id, id, virtual_port, document)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(site_id, id) DO UPDATE SET
             virtual_port = excluded.virtual_port,
             document = excluded.document",
        params![
            site_id.as_str(),
            mapping.id.as_str(),
            i64::from(mapping.virtual_port),
            document
        ],
    )?;
    Ok(())
}

fn device_secret_name(site_id: &SiteId, guest_id: &GuestId, device_id: &DeviceId) -> String {
    format!("device:{site_id}:{guest_id}:{device_id}:tor-client")
}

fn create_current_schema(transaction: &Transaction<'_>) -> Result<(), rusqlite::Error> {
    create_v2_schema(transaction)?;
    create_access_schema(transaction)
}

fn create_v2_schema(transaction: &Transaction<'_>) -> Result<(), rusqlite::Error> {
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS sites (
             id TEXT PRIMARY KEY NOT NULL,
             display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
             enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
         ) STRICT;
         CREATE TABLE IF NOT EXISTS mappings (
             site_id TEXT NOT NULL,
             id TEXT NOT NULL,
             virtual_port INTEGER NOT NULL CHECK (virtual_port BETWEEN 1 AND 65535),
             document TEXT NOT NULL,
             PRIMARY KEY (site_id, id),
             UNIQUE (site_id, virtual_port),
             FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
         ) STRICT;
         CREATE INDEX IF NOT EXISTS mappings_site ON mappings(site_id);
         CREATE TABLE IF NOT EXISTS secrets (
             name TEXT PRIMARY KEY NOT NULL,
             encrypted BLOB NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS sessions (
             token_hash BLOB PRIMARY KEY NOT NULL CHECK (length(token_hash) = 32),
             expires_unix INTEGER NOT NULL,
             last_seen_unix INTEGER NOT NULL,
             revoked INTEGER NOT NULL CHECK (revoked IN (0, 1))
         ) STRICT;
         CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_unix);",
    )
}

fn create_access_schema(transaction: &Transaction<'_>) -> Result<(), rusqlite::Error> {
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS guests (
             site_id TEXT NOT NULL,
             id TEXT NOT NULL,
             display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
             enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
             PRIMARY KEY (site_id, id),
             FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
         ) STRICT;
         CREATE INDEX IF NOT EXISTS guests_site ON guests(site_id);
         CREATE TABLE IF NOT EXISTS devices (
             site_id TEXT NOT NULL,
             guest_id TEXT NOT NULL,
             id TEXT NOT NULL,
             display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
             tor_client_name TEXT NOT NULL,
             enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
             encrypted_secret BLOB NOT NULL,
             PRIMARY KEY (site_id, guest_id, id),
             UNIQUE (site_id, tor_client_name),
             FOREIGN KEY (site_id, guest_id) REFERENCES guests(site_id, id) ON DELETE CASCADE
         ) STRICT;
         CREATE INDEX IF NOT EXISTS devices_guest ON devices(site_id, guest_id);
         CREATE TABLE IF NOT EXISTS guest_mapping_permissions (
             site_id TEXT NOT NULL,
             guest_id TEXT NOT NULL,
             mapping_id TEXT NOT NULL,
             PRIMARY KEY (site_id, guest_id, mapping_id),
             FOREIGN KEY (site_id, guest_id) REFERENCES guests(site_id, id) ON DELETE CASCADE,
             FOREIGN KEY (site_id, mapping_id) REFERENCES mappings(site_id, id) ON DELETE CASCADE
         ) STRICT;
         CREATE TABLE IF NOT EXISTS publication_settings (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             resume_after_boot INTEGER NOT NULL CHECK (resume_after_boot IN (0, 1)),
             emergency_disabled INTEGER NOT NULL CHECK (emergency_disabled IN (0, 1))
         ) STRICT;
         INSERT OR IGNORE INTO publication_settings
             (singleton, resume_after_boot, emergency_disabled) VALUES (1, 1, 0);",
    )
}

fn migrate_v1_to_v2(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    transaction.execute_batch(
        "ALTER TABLE routes RENAME TO routes_v1;
         CREATE TABLE sites (
             id TEXT PRIMARY KEY NOT NULL,
             display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
             enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
         ) STRICT;
         CREATE TABLE mappings (
             site_id TEXT NOT NULL,
             id TEXT NOT NULL,
             virtual_port INTEGER NOT NULL CHECK (virtual_port BETWEEN 1 AND 65535),
             document TEXT NOT NULL,
             PRIMARY KEY (site_id, id),
             UNIQUE (site_id, virtual_port),
             FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
         ) STRICT;
         CREATE INDEX mappings_site ON mappings(site_id);",
    )?;
    transaction.execute(
        "INSERT INTO sites (id, display_name, enabled) VALUES (?1, ?2, 1)",
        params![LEGACY_SITE_ID, LEGACY_SITE_DISPLAY_NAME],
    )?;
    transaction.execute(
        "INSERT INTO mappings (site_id, id, virtual_port, document)
         SELECT ?1, id, virtual_port, document FROM routes_v1",
        [LEGACY_SITE_ID],
    )?;
    transaction.execute_batch("DROP TABLE routes_v1;")?;
    create_v2_schema(transaction)?;
    transaction.execute(
        "UPDATE schema_version SET version = 2 WHERE singleton = 1",
        [],
    )?;
    Ok(())
}

fn migrate_v2_to_v3(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    create_access_schema(transaction)?;
    transaction.execute(
        "UPDATE schema_version SET version = ?1 WHERE singleton = 1",
        [DATABASE_SCHEMA_VERSION],
    )?;
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(StoreError::UnsafeStatePath(path.to_path_buf()));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn ensure_private_database(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StoreError::UnsafeDatabasePath(path.to_path_buf()));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn session_hash(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("unsupported database schema {0}")]
    UnsupportedSchema(i64),
    #[error("site not found: {0}")]
    SiteNotFound(SiteId),
    #[error("mapping {mapping_id} not found in site {site_id}")]
    MappingNotFound {
        site_id: SiteId,
        mapping_id: MappingId,
    },
    #[error("guest {guest_id} not found in site {site_id}")]
    GuestNotFound { site_id: SiteId, guest_id: GuestId },
    #[error("duplicate mapping permission: {0}")]
    DuplicatePermission(MappingId),
    #[error("state path is not a private directory: {path}", path = .0.display())]
    UnsafeStatePath(PathBuf),
    #[error("database path is not a regular file: {path}", path = .0.display())]
    UnsafeDatabasePath(PathBuf),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Cipher(#[from] CipherError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use torkitten_core::{MappingTarget, Transport};

    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(temporary.path()).unwrap();
        (temporary, store)
    }

    fn mapping(id: &str, virtual_port: u16) -> Mapping {
        Mapping {
            id: MappingId::new(id).unwrap(),
            display_name: id.to_owned(),
            virtual_port,
            target: MappingTarget::Tcp {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 3000,
                transport: Transport::Http,
            },
            enabled: true,
        }
    }

    fn site(id: &str, mappings: Vec<Mapping>) -> Site {
        Site {
            id: SiteId::new(id).unwrap(),
            display_name: format!("Site {id}"),
            enabled: true,
            mappings,
        }
    }

    fn guest(site_id: &SiteId, id: &str) -> Guest {
        Guest {
            site_id: site_id.clone(),
            id: GuestId::new(id).unwrap(),
            display_name: format!("Guest {id}"),
            enabled: true,
        }
    }

    fn device(site_id: &SiteId, guest_id: &GuestId, id: &str) -> Device {
        Device {
            site_id: site_id.clone(),
            guest_id: guest_id.clone(),
            id: DeviceId::new(id).unwrap(),
            display_name: format!("Device {id}"),
            tor_client_name: id.to_owned(),
            enabled: true,
        }
    }

    #[test]
    fn persists_sites_and_scopes_mapping_keys_and_ports() {
        let (_temporary, mut store) = store();
        store
            .put_site(&site("alpha", vec![mapping("app", 8443)]))
            .unwrap();
        store
            .put_site(&site("beta", vec![mapping("app", 8443)]))
            .unwrap();

        let config = store.gateway_config().unwrap();
        assert_eq!(config.sites.len(), 2);
        assert_eq!(config.sites[0].mappings[0].id.as_str(), "app");
        assert_eq!(config.sites[1].mappings[0].virtual_port, 8443);
    }

    #[test]
    fn rejects_port_conflicts_without_changing_the_site() {
        let (_temporary, mut store) = store();
        let site_id = SiteId::new("alpha").unwrap();
        store
            .put_site(&site("alpha", vec![mapping("one", 8443)]))
            .unwrap();
        let error = store
            .put_mapping(&site_id, &mapping("two", 8443))
            .unwrap_err();
        assert!(matches!(
            error,
            StoreError::Validation(ValidationError::DuplicateVirtualPort { .. })
        ));
        assert_eq!(store.site(&site_id).unwrap().unwrap().mappings.len(), 1);
    }

    #[test]
    fn site_and_mapping_toggles_are_independent() {
        let (_temporary, mut store) = store();
        let alpha = SiteId::new("alpha").unwrap();
        let beta = SiteId::new("beta").unwrap();
        let app = MappingId::new("app").unwrap();
        store
            .put_site(&site("alpha", vec![mapping("app", 8443)]))
            .unwrap();
        store
            .put_site(&site("beta", vec![mapping("app", 8443)]))
            .unwrap();

        store.set_mapping_enabled(&alpha, &app, false).unwrap();
        store.set_site_enabled(&beta, false).unwrap();
        let config = store.gateway_config().unwrap();
        assert!(!config.sites[0].mappings[0].enabled);
        assert!(config.sites[0].enabled);
        assert!(config.sites[1].mappings[0].enabled);
        assert!(!config.sites[1].enabled);
    }

    #[test]
    fn removing_a_site_cascades_only_its_mappings() {
        let (_temporary, mut store) = store();
        let alpha = SiteId::new("alpha").unwrap();
        let beta = SiteId::new("beta").unwrap();
        store
            .put_site(&site("alpha", vec![mapping("app", 8443)]))
            .unwrap();
        store
            .put_site(&site("beta", vec![mapping("app", 8443)]))
            .unwrap();
        assert!(store.remove_site(&alpha).unwrap());
        assert!(store.site(&alpha).unwrap().is_none());
        assert_eq!(store.site(&beta).unwrap().unwrap().mappings.len(), 1);
    }

    #[test]
    fn migrates_v1_routes_into_a_persistent_default_site() {
        let temporary = tempfile::tempdir().unwrap();
        let database_path = temporary.path().join(DATABASE_FILENAME);
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_version (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     version INTEGER NOT NULL
                 );
                 INSERT INTO schema_version (singleton, version) VALUES (1, 1);
                 CREATE TABLE routes (
                     id TEXT PRIMARY KEY NOT NULL,
                     virtual_port INTEGER UNIQUE NOT NULL,
                     document TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE secrets (
                     name TEXT PRIMARY KEY NOT NULL,
                     encrypted BLOB NOT NULL
                 ) STRICT;
                 CREATE TABLE sessions (
                     token_hash BLOB PRIMARY KEY NOT NULL,
                     expires_unix INTEGER NOT NULL,
                     last_seen_unix INTEGER NOT NULL,
                     revoked INTEGER NOT NULL
                 ) STRICT;",
            )
            .unwrap();
        let legacy_document = r#"{
            "id":"app",
            "display_name":"Application",
            "virtual_port":8443,
            "target":{"kind":"tcp","address":"127.0.0.1","port":3000}
        }"#;
        connection
            .execute(
                "INSERT INTO routes (id, virtual_port, document) VALUES ('app', 8443, ?1)",
                [legacy_document],
            )
            .unwrap();
        drop(connection);

        let store = Store::open(temporary.path()).unwrap();
        let config = store.gateway_config().unwrap();
        assert_eq!(config.sites.len(), 1);
        assert_eq!(config.sites[0].id.as_str(), LEGACY_SITE_ID);
        assert!(config.sites[0].enabled);
        assert_eq!(config.sites[0].mappings.len(), 1);
        assert!(config.sites[0].mappings[0].enabled);
        let version: i64 = store
            .connection
            .query_row(
                "SELECT version FROM schema_version WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, DATABASE_SCHEMA_VERSION);
    }

    #[test]
    fn encrypts_secrets_at_rest() {
        let (temporary, store) = store();
        store.put_secret("totp", b"SECRET-VALUE").unwrap();
        assert_eq!(
            &*store.get_secret("totp").unwrap().unwrap(),
            b"SECRET-VALUE"
        );
        let database = fs::read(temporary.path().join(DATABASE_FILENAME)).unwrap();
        assert!(
            !database
                .windows(b"SECRET-VALUE".len())
                .any(|window| window == b"SECRET-VALUE")
        );
    }

    #[test]
    fn hashes_and_revokes_sessions() {
        let (temporary, store) = store();
        let token = b"a random bearer token that must not be stored";
        store.put_session(token, 200, 100).unwrap();
        assert!(store.touch_session(token, 110).unwrap().is_some());
        assert!(store.revoke_session(token).unwrap());
        assert!(store.touch_session(token, 120).unwrap().is_none());
        let database = fs::read(temporary.path().join(DATABASE_FILENAME)).unwrap();
        assert!(!database.windows(token.len()).any(|window| window == token));
    }

    #[test]
    fn scopes_guests_devices_and_permissions_by_site() {
        let (temporary, mut store) = store();
        let alpha = SiteId::new("alpha").unwrap();
        let beta = SiteId::new("beta").unwrap();
        let guest_id = GuestId::new("family").unwrap();
        let device_id = DeviceId::new("phone").unwrap();
        let mapping_id = MappingId::new("app").unwrap();
        for site_id in [&alpha, &beta] {
            store
                .put_site(&site(site_id.as_str(), vec![mapping("app", 8443)]))
                .unwrap();
            store.put_guest(&guest(site_id, "family")).unwrap();
            store
                .put_device(
                    &device(site_id, &guest_id, "phone"),
                    format!("private credential for {site_id}").as_bytes(),
                )
                .unwrap();
            store
                .set_guest_permissions(site_id, &guest_id, std::slice::from_ref(&mapping_id))
                .unwrap();
        }

        let alpha_device = store
            .device(&alpha, &guest_id, &device_id)
            .unwrap()
            .unwrap();
        let beta_device = store.device(&beta, &guest_id, &device_id).unwrap().unwrap();
        assert_ne!(
            alpha_device.secret_material, beta_device.secret_material,
            "device credentials must not be reused between sites"
        );
        assert!(!format!("{alpha_device:?}").contains("private credential"));
        assert_eq!(
            store.guest_permissions(&alpha, &guest_id).unwrap(),
            vec![mapping_id]
        );
        for filename in [DATABASE_FILENAME, "state.sqlite3-wal"] {
            let path = temporary.path().join(filename);
            if let Ok(database) = fs::read(path) {
                assert!(
                    !database
                        .windows(b"private credential".len())
                        .any(|window| window == b"private credential")
                );
            }
        }
    }

    #[test]
    fn guest_and_mapping_removal_cascade_access_records() {
        let (_temporary, mut store) = store();
        let site_id = SiteId::new("alpha").unwrap();
        let guest_id = GuestId::new("family").unwrap();
        let device_id = DeviceId::new("phone").unwrap();
        let mapping_id = MappingId::new("app").unwrap();
        store
            .put_site(&site("alpha", vec![mapping("app", 8443)]))
            .unwrap();
        store.put_guest(&guest(&site_id, "family")).unwrap();
        store
            .put_device(&device(&site_id, &guest_id, "phone"), b"credential")
            .unwrap();
        store
            .set_guest_permissions(&site_id, &guest_id, std::slice::from_ref(&mapping_id))
            .unwrap();

        store.set_site_enabled(&site_id, false).unwrap();
        store
            .set_mapping_enabled(&site_id, &mapping_id, false)
            .unwrap();
        assert_eq!(
            store.guest_permissions(&site_id, &guest_id).unwrap(),
            vec![mapping_id.clone()],
            "site and mapping toggles must retain guest grants"
        );

        assert!(store.remove_mapping(&site_id, &mapping_id).unwrap());
        assert!(
            store
                .guest_permissions(&site_id, &guest_id)
                .unwrap()
                .is_empty()
        );
        assert!(store.remove_guest(&site_id, &guest_id).unwrap());
        assert!(
            store
                .device(&site_id, &guest_id, &device_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn emergency_latch_and_resume_policy_are_persistent() {
        let (temporary, store) = store();
        assert_eq!(
            store.publication_settings().unwrap(),
            PublicationSettings {
                resume_after_boot: true,
                emergency_disabled: false,
            }
        );
        store.set_resume_after_boot(false).unwrap();
        store.set_emergency_disabled(true).unwrap();
        drop(store);

        let reopened = Store::open(temporary.path()).unwrap();
        assert_eq!(
            reopened.publication_settings().unwrap(),
            PublicationSettings {
                resume_after_boot: false,
                emergency_disabled: true,
            }
        );
    }

    #[test]
    fn migrates_v2_state_without_changing_publication_defaults() {
        let temporary = tempfile::tempdir().unwrap();
        let database_path = temporary.path().join(DATABASE_FILENAME);
        let mut connection = Connection::open(&database_path).unwrap();
        let transaction = connection.transaction().unwrap();
        transaction
            .execute_batch(
                "CREATE TABLE schema_version (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     version INTEGER NOT NULL
                 );
                 INSERT INTO schema_version (singleton, version) VALUES (1, 2);",
            )
            .unwrap();
        create_v2_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        drop(connection);

        let migrated = Store::open(temporary.path()).unwrap();
        assert_eq!(
            migrated.publication_settings().unwrap(),
            PublicationSettings {
                resume_after_boot: true,
                emergency_disabled: false,
            }
        );
        let version: i64 = migrated
            .connection
            .query_row(
                "SELECT version FROM schema_version WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, DATABASE_SCHEMA_VERSION);
    }
}
