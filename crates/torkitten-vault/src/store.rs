use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use thiserror::Error;
use torkitten_auth::{
    CsrfToken, EnrollmentToken, Passkey, PasswordHashValue, SessionToken, TotpSecret,
    decode_passkey, encode_passkey, passkey_credential_id,
};
use torkitten_core::{
    AccountOwner, Device, DeviceId, GatewayConfig, Guest, GuestId, Mapping, MappingId, Site,
    SiteId, ValidationError,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{EncryptedSecret, VaultCipher, cipher::CipherError, key::KeyError};

const DATABASE_FILENAME: &str = "state.sqlite3";
const KEY_FILENAME: &str = "secrets/vault.key";
const DATABASE_SCHEMA_VERSION: i64 = 5;
const LEGACY_SITE_ID: &str = "default";
const LEGACY_SITE_DISPLAY_NAME: &str = "Default site";

pub struct Store {
    connection: Connection,
    cipher: VaultCipher,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    pub account_id: Uuid,
    pub csrf_hash: [u8; 32],
    pub created_unix: i64,
    pub expires_unix: i64,
    pub last_seen_unix: i64,
    pub fresh_until_unix: i64,
}

impl SessionRecord {
    #[must_use]
    pub fn csrf_matches(&self, candidate: &CsrfToken) -> bool {
        candidate.digest_matches(&self.csrf_hash)
    }

    #[must_use]
    pub fn is_fresh(&self, now_unix: i64) -> bool {
        now_unix < self.fresh_until_unix
    }
}

pub struct AuthAccountRecord {
    pub id: Uuid,
    pub owner: AccountOwner,
    pub display_name: String,
    pub password_hash: Option<PasswordHashValue>,
    pub totp_secret: Option<TotpSecret>,
    pub recovery_pepper: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for AuthAccountRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthAccountRecord")
            .field("id", &self.id)
            .field("owner", &self.owner)
            .field("display_name", &self.display_name)
            .field(
                "password_hash",
                &self.password_hash.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "totp_secret",
                &self.totp_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("recovery_pepper", &"[REDACTED]")
            .finish()
    }
}

pub struct PasskeyRecord {
    pub account_id: Uuid,
    pub label: String,
    pub passkey: Passkey,
    pub created_unix: i64,
    pub last_used_unix: Option<i64>,
}

pub struct DeviceRecord {
    pub device: Device,
    pub secret_material: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceEnrollmentRecord {
    pub site_id: SiteId,
    pub guest_id: GuestId,
    pub device_id: DeviceId,
    pub created_unix: i64,
    pub expires_unix: i64,
    pub used_unix: Option<i64>,
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
    pub fn remove_site(&mut self, id: &SiteId) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction()?;
        let removed = transaction.execute("DELETE FROM sites WHERE id = ?1", [id.as_str()])? != 0;
        transaction.execute(
            "DELETE FROM secrets WHERE name GLOB ?1",
            [format!("pki/site/{}/*", id.as_str())],
        )?;
        transaction.commit()?;
        Ok(removed)
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

    /// Creates a hashed, short-lived enrollment token for exactly one device.
    /// Any older enrollment for that device is invalidated atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the device is missing, timestamps are invalid, or
    /// SQLite cannot commit the replacement.
    pub fn put_device_enrollment(
        &mut self,
        token: &EnrollmentToken,
        site_id: &SiteId,
        guest_id: &GuestId,
        device_id: &DeviceId,
        created_unix: i64,
        expires_unix: i64,
    ) -> Result<(), StoreError> {
        if expires_unix <= created_unix {
            return Err(StoreError::InvalidEnrollmentTimes);
        }
        if self.device(site_id, guest_id, device_id)?.is_none() {
            return Err(StoreError::DeviceNotFound {
                site_id: site_id.clone(),
                guest_id: guest_id.clone(),
                device_id: device_id.clone(),
            });
        }
        let token_hash = token.digest();
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM device_enrollments
             WHERE site_id = ?1 AND guest_id = ?2 AND device_id = ?3",
            params![site_id.as_str(), guest_id.as_str(), device_id.as_str()],
        )?;
        transaction.execute(
            "INSERT INTO device_enrollments
                 (token_hash, site_id, guest_id, device_id, created_unix, expires_unix, used_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                token_hash.as_slice(),
                site_id.as_str(),
                guest_id.as_str(),
                device_id.as_str(),
                created_unix,
                expires_unix,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Looks up an unused, unexpired enrollment without exposing its bearer
    /// token from storage.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite access or persisted identifiers are invalid.
    pub fn device_enrollment(
        &self,
        token: &EnrollmentToken,
        now_unix: i64,
    ) -> Result<Option<DeviceEnrollmentRecord>, StoreError> {
        let token_hash = token.digest();
        self.connection
            .query_row(
                "SELECT site_id, guest_id, device_id, created_unix, expires_unix, used_unix
                 FROM device_enrollments
                 WHERE token_hash = ?1 AND used_unix IS NULL AND expires_unix > ?2",
                params![token_hash.as_slice(), now_unix],
                decode_device_enrollment_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Atomically marks an unused, unexpired enrollment as consumed and
    /// returns its device scope. A bearer token can succeed only once.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot query or commit the update.
    pub fn consume_device_enrollment(
        &mut self,
        token: &EnrollmentToken,
        now_unix: i64,
    ) -> Result<Option<DeviceEnrollmentRecord>, StoreError> {
        let token_hash = token.digest();
        let transaction = self.connection.transaction()?;
        let record = transaction
            .query_row(
                "SELECT site_id, guest_id, device_id, created_unix, expires_unix, used_unix
                 FROM device_enrollments
                 WHERE token_hash = ?1 AND used_unix IS NULL AND expires_unix > ?2",
                params![token_hash.as_slice(), now_unix],
                decode_device_enrollment_row,
            )
            .optional()?;
        if record.is_some() {
            transaction.execute(
                "UPDATE device_enrollments SET used_unix = ?2
                 WHERE token_hash = ?1 AND used_unix IS NULL",
                params![token_hash.as_slice(), now_unix],
            )?;
        }
        transaction.commit()?;
        Ok(record.map(|mut record| {
            record.used_unix = Some(now_unix);
            record
        }))
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

    /// Creates one administrator or site-scoped guest authentication account.
    /// TOTP and the recovery-code pepper are encrypted before persistence.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid fields, a missing guest, duplicate owner or
    /// account identifiers, encryption failure, or SQLite failure.
    pub fn create_auth_account(
        &self,
        account_id: Uuid,
        owner: &AccountOwner,
        display_name: &str,
        password_hash: Option<&PasswordHashValue>,
        totp_secret: Option<&TotpSecret>,
        recovery_pepper: &[u8; 32],
    ) -> Result<(), StoreError> {
        validate_auth_account(account_id, owner, display_name)?;
        if let AccountOwner::Guest { site_id, guest_id } = owner
            && self.guest(site_id, guest_id)?.is_none()
        {
            return Err(StoreError::GuestNotFound {
                site_id: site_id.clone(),
                guest_id: guest_id.clone(),
            });
        }

        let totp_aad = account_secret_name(account_id, "totp");
        let encrypted_totp = totp_secret
            .map(|secret| self.cipher.encrypt(&totp_aad, secret.as_bytes()))
            .transpose()?;
        let pepper_aad = account_secret_name(account_id, "recovery-pepper");
        let encrypted_pepper = self.cipher.encrypt(&pepper_aad, recovery_pepper)?;
        let (kind, site_id, guest_id) = owner_columns(owner);
        self.connection.execute(
            "INSERT INTO auth_accounts
                 (id, kind, site_id, guest_id, display_name, password_hash,
                  encrypted_totp, encrypted_recovery_pepper)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                account_id.as_bytes().as_slice(),
                kind,
                site_id,
                guest_id,
                display_name,
                password_hash.map(PasswordHashValue::as_str),
                encrypted_totp.as_ref().map(EncryptedSecret::as_bytes),
                encrypted_pepper.as_bytes(),
            ],
        )?;
        Ok(())
    }

    /// Returns one authentication account by its stable UUID.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed persisted data, authenticated decryption
    /// failure, or SQLite failure.
    pub fn auth_account(&self, account_id: Uuid) -> Result<Option<AuthAccountRecord>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT kind, site_id, guest_id, display_name, password_hash,
                        encrypted_totp, encrypted_recovery_pepper
                 FROM auth_accounts WHERE id = ?1",
                [account_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((kind, site_id, guest_id, display_name, password_hash, totp, pepper)) = row else {
            return Ok(None);
        };
        let owner = decode_owner(&kind, site_id, guest_id)?;
        validate_auth_account(account_id, &owner, &display_name)?;
        let password_hash = password_hash.map(PasswordHashValue::parse).transpose()?;
        let totp_secret = totp
            .map(|encrypted| {
                let aad = account_secret_name(account_id, "totp");
                let plaintext = self
                    .cipher
                    .decrypt(&aad, &EncryptedSecret::from_bytes(encrypted))?;
                TotpSecret::from_bytes(plaintext.to_vec()).map_err(StoreError::from)
            })
            .transpose()?;
        let pepper_aad = account_secret_name(account_id, "recovery-pepper");
        let recovery_pepper = self
            .cipher
            .decrypt(&pepper_aad, &EncryptedSecret::from_bytes(pepper))?;
        if recovery_pepper.len() != 32 {
            return Err(StoreError::InvalidSecretLength);
        }
        Ok(Some(AuthAccountRecord {
            id: account_id,
            owner,
            display_name,
            password_hash,
            totp_secret,
            recovery_pepper,
        }))
    }

    /// Returns an authentication account by its unique owner scope.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid owner identifiers, malformed persisted
    /// data, authenticated decryption failure, or SQLite failure.
    pub fn auth_account_for_owner(
        &self,
        owner: &AccountOwner,
    ) -> Result<Option<AuthAccountRecord>, StoreError> {
        owner.validate()?;
        let id = match owner {
            AccountOwner::Administrator => self
                .connection
                .query_row(
                    "SELECT id FROM auth_accounts WHERE kind = 'administrator'",
                    [],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
            AccountOwner::Guest { site_id, guest_id } => self
                .connection
                .query_row(
                    "SELECT id FROM auth_accounts
                     WHERE kind = 'guest' AND site_id = ?1 AND guest_id = ?2",
                    params![site_id.as_str(), guest_id.as_str()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
        };
        id.map(|bytes| uuid_from_bytes(&bytes))
            .transpose()?
            .map(|id| self.auth_account(id))
            .transpose()
            .map(Option::flatten)
    }

    /// Replaces an account's password hash. `None` enables passkey-only use.
    ///
    /// # Errors
    ///
    /// Returns an error if the account is missing or SQLite cannot update it.
    pub fn set_account_password(
        &self,
        account_id: Uuid,
        password_hash: Option<&PasswordHashValue>,
    ) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE auth_accounts SET password_hash = ?2 WHERE id = ?1",
            params![
                account_id.as_bytes().as_slice(),
                password_hash.map(PasswordHashValue::as_str)
            ],
        )?;
        if changed == 0 {
            Err(StoreError::AccountNotFound(account_id))
        } else {
            Ok(())
        }
    }

    /// Replaces or clears an account's encrypted TOTP secret.
    ///
    /// # Errors
    ///
    /// Returns an error for encryption failure, a missing account, or SQLite
    /// failure.
    pub fn set_account_totp(
        &self,
        account_id: Uuid,
        totp_secret: Option<&TotpSecret>,
    ) -> Result<(), StoreError> {
        let aad = account_secret_name(account_id, "totp");
        let encrypted = totp_secret
            .map(|secret| self.cipher.encrypt(&aad, secret.as_bytes()))
            .transpose()?;
        let changed = self.connection.execute(
            "UPDATE auth_accounts SET encrypted_totp = ?2 WHERE id = ?1",
            params![
                account_id.as_bytes().as_slice(),
                encrypted.as_ref().map(EncryptedSecret::as_bytes)
            ],
        )?;
        if changed == 0 {
            Err(StoreError::AccountNotFound(account_id))
        } else {
            Ok(())
        }
    }

    /// Removes one authentication account and cascades its passkeys, recovery
    /// codes, and sessions.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot apply the deletion.
    pub fn remove_auth_account(&self, account_id: Uuid) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM auth_accounts WHERE id = ?1",
            [account_id.as_bytes().as_slice()],
        )? != 0)
    }

    /// Stores or updates one registered passkey. A credential identifier can
    /// never be reassigned to another account.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid label or credential encoding, a missing
    /// account, credential reassignment, or SQLite failure.
    pub fn put_passkey(
        &self,
        account_id: Uuid,
        label: &str,
        passkey: &Passkey,
        now_unix: i64,
    ) -> Result<(), StoreError> {
        validate_auth_display_name(label)?;
        if self.auth_account(account_id)?.is_none() {
            return Err(StoreError::AccountNotFound(account_id));
        }
        let credential_id = passkey_credential_id(passkey);
        let document = encode_passkey(passkey)?;
        let existing_owner = self
            .connection
            .query_row(
                "SELECT account_id FROM passkeys WHERE credential_id = ?1",
                [credential_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if let Some(existing_owner) = existing_owner
            && uuid_from_bytes(&existing_owner)? != account_id
        {
            return Err(StoreError::CredentialAlreadyAssigned);
        }
        self.connection.execute(
            "INSERT INTO passkeys
                 (credential_id, account_id, label, document, created_unix,
                  last_used_unix, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, 0)
             ON CONFLICT(credential_id) DO UPDATE SET
                 label = excluded.label,
                 document = excluded.document,
                 revoked = 0",
            params![
                credential_id,
                account_id.as_bytes().as_slice(),
                label,
                document,
                now_unix
            ],
        )?;
        Ok(())
    }

    /// Returns every active passkey for one account.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed persisted credentials or SQLite failure.
    pub fn passkeys(&self, account_id: Uuid) -> Result<Vec<PasskeyRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT credential_id, label, document, created_unix, last_used_unix
             FROM passkeys WHERE account_id = ?1 AND revoked = 0
             ORDER BY created_unix, credential_id",
        )?;
        let rows = statement.query_map([account_id.as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (credential_id, label, document, created_unix, last_used_unix) = row?;
            validate_auth_display_name(&label)?;
            let passkey = decode_passkey(&document)?;
            if passkey_credential_id(&passkey) != credential_id {
                return Err(StoreError::CredentialIdentifierMismatch);
            }
            records.push(PasskeyRecord {
                account_id,
                label,
                passkey,
                created_unix,
                last_used_unix,
            });
        }
        Ok(records)
    }

    /// Marks one passkey as used after successful `WebAuthn` verification.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential is missing, belongs to another
    /// account, is revoked, or SQLite cannot update it.
    pub fn mark_passkey_used(
        &self,
        account_id: Uuid,
        passkey: &Passkey,
        now_unix: i64,
    ) -> Result<(), StoreError> {
        let credential_id = passkey_credential_id(passkey);
        let document = encode_passkey(passkey)?;
        let changed = self.connection.execute(
            "UPDATE passkeys SET document = ?3, last_used_unix = ?4
             WHERE credential_id = ?1 AND account_id = ?2 AND revoked = 0",
            params![
                credential_id,
                account_id.as_bytes().as_slice(),
                document,
                now_unix
            ],
        )?;
        if changed == 0 {
            Err(StoreError::CredentialNotFound)
        } else {
            Ok(())
        }
    }

    /// Revokes one passkey without deleting its audit metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot update it.
    pub fn revoke_passkey(
        &self,
        account_id: Uuid,
        credential_id: &[u8],
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "UPDATE passkeys SET revoked = 1
             WHERE credential_id = ?1 AND account_id = ?2 AND revoked = 0",
            params![credential_id, account_id.as_bytes().as_slice()],
        )? != 0)
    }

    /// Atomically replaces an account's unused keyed recovery-code digests.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing account, duplicate digest, invalid count,
    /// or SQLite failure.
    pub fn replace_recovery_codes(
        &mut self,
        account_id: Uuid,
        digests: &[[u8; 32]],
        now_unix: i64,
    ) -> Result<(), StoreError> {
        if !(1..=32).contains(&digests.len()) {
            return Err(StoreError::InvalidRecoveryCodeCount);
        }
        if self.auth_account(account_id)?.is_none() {
            return Err(StoreError::AccountNotFound(account_id));
        }
        let unique = digests.iter().collect::<HashSet<_>>();
        if unique.len() != digests.len() {
            return Err(StoreError::DuplicateRecoveryCode);
        }
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM recovery_codes WHERE account_id = ?1",
            [account_id.as_bytes().as_slice()],
        )?;
        for digest in digests {
            transaction.execute(
                "INSERT INTO recovery_codes
                     (account_id, digest, created_unix, used_unix)
                 VALUES (?1, ?2, ?3, NULL)",
                params![
                    account_id.as_bytes().as_slice(),
                    digest.as_slice(),
                    now_unix
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Atomically consumes one unused recovery-code digest.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot update it.
    pub fn consume_recovery_code(
        &self,
        account_id: Uuid,
        digest: &[u8; 32],
        now_unix: i64,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "UPDATE recovery_codes SET used_unix = ?3
             WHERE account_id = ?1 AND digest = ?2 AND used_unix IS NULL",
            params![
                account_id.as_bytes().as_slice(),
                digest.as_slice(),
                now_unix
            ],
        )? != 0)
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

    pub(crate) fn put_secret_set(&mut self, secrets: &[(&str, &[u8])]) -> Result<(), StoreError> {
        let encrypted = secrets
            .iter()
            .map(|(name, plaintext)| {
                self.cipher
                    .encrypt(name, plaintext)
                    .map(|encrypted| (*name, encrypted))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let transaction = self.connection.transaction()?;
        for (name, encrypted) in encrypted {
            transaction.execute(
                "INSERT INTO secrets (name, encrypted) VALUES (?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET encrypted = excluded.encrypted",
                params![name, encrypted.as_bytes()],
            )?;
        }
        transaction.commit()?;
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

    /// Persists only digests of random session and CSRF tokens, bound to one
    /// authentication account.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot persist the session.
    pub fn put_session(
        &self,
        account_id: Uuid,
        token: &SessionToken,
        csrf: &CsrfToken,
        created_unix: i64,
        expires_unix: i64,
        fresh_until_unix: i64,
    ) -> Result<(), StoreError> {
        if self.auth_account(account_id)?.is_none() {
            return Err(StoreError::AccountNotFound(account_id));
        }
        if !(created_unix <= fresh_until_unix && fresh_until_unix <= expires_unix) {
            return Err(StoreError::InvalidSessionTimes);
        }
        let token_hash = token.digest();
        let csrf_hash = csrf.digest();
        self.connection.execute(
            "INSERT INTO sessions
                 (token_hash, account_id, csrf_hash, created_unix, expires_unix,
                  last_seen_unix, fresh_until_unix, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?4, ?6, 0)",
            params![
                token_hash.as_slice(),
                account_id.as_bytes().as_slice(),
                csrf_hash.as_slice(),
                created_unix,
                expires_unix,
                fresh_until_unix,
            ],
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
        token: &SessionToken,
        now_unix: i64,
    ) -> Result<Option<SessionRecord>, StoreError> {
        let token_hash = token.digest();
        let record = self
            .connection
            .query_row(
                "SELECT account_id, csrf_hash, created_unix, expires_unix,
                        last_seen_unix, fresh_until_unix
                 FROM sessions
                 WHERE token_hash = ?1 AND revoked = 0 AND expires_unix > ?2",
                params![token_hash.as_slice(), now_unix],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;
        if record.is_some() {
            self.connection.execute(
                "UPDATE sessions SET last_seen_unix = ?2 WHERE token_hash = ?1",
                params![token_hash.as_slice(), now_unix],
            )?;
        }
        record
            .map(
                |(account_id, csrf_hash, created, expires, last_seen, fresh_until)| {
                    Ok(SessionRecord {
                        account_id: uuid_from_bytes(&account_id)?,
                        csrf_hash: digest_from_bytes(&csrf_hash)?,
                        created_unix: created,
                        expires_unix: expires,
                        last_seen_unix: last_seen,
                        fresh_until_unix: fresh_until,
                    })
                },
            )
            .transpose()
    }

    /// Revokes a session without storing its bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot update the session.
    pub fn revoke_session(&self, token: &SessionToken) -> Result<bool, StoreError> {
        let token_hash = token.digest();
        Ok(self.connection.execute(
            "UPDATE sessions SET revoked = 1 WHERE token_hash = ?1",
            [token_hash.as_slice()],
        )? != 0)
    }

    /// Revokes every session for one account, including the current one.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot update the sessions.
    pub fn revoke_account_sessions(&self, account_id: Uuid) -> Result<usize, StoreError> {
        self.connection
            .execute(
                "UPDATE sessions SET revoked = 1
                 WHERE account_id = ?1 AND revoked = 0",
                [account_id.as_bytes().as_slice()],
            )
            .map_err(Into::into)
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
                migrate_v3_to_v4(&transaction)?;
                migrate_v4_to_v5(&transaction)?;
            }
            Some(2) => {
                migrate_v2_to_v3(&transaction)?;
                migrate_v3_to_v4(&transaction)?;
                migrate_v4_to_v5(&transaction)?;
            }
            Some(3) => {
                migrate_v3_to_v4(&transaction)?;
                migrate_v4_to_v5(&transaction)?;
            }
            Some(4) => migrate_v4_to_v5(&transaction)?,
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

fn account_secret_name(account_id: Uuid, purpose: &str) -> String {
    format!("account:{account_id}:{purpose}")
}

fn owner_columns(owner: &AccountOwner) -> (&'static str, Option<&str>, Option<&str>) {
    match owner {
        AccountOwner::Administrator => ("administrator", None, None),
        AccountOwner::Guest { site_id, guest_id } => {
            ("guest", Some(site_id.as_str()), Some(guest_id.as_str()))
        }
    }
}

fn decode_owner(
    kind: &str,
    site_id: Option<String>,
    guest_id: Option<String>,
) -> Result<AccountOwner, StoreError> {
    let owner = match (kind, site_id, guest_id) {
        ("administrator", None, None) => AccountOwner::Administrator,
        ("guest", Some(site_id), Some(guest_id)) => AccountOwner::Guest {
            site_id: SiteId::new(site_id)?,
            guest_id: GuestId::new(guest_id)?,
        },
        _ => return Err(StoreError::InvalidAccountOwner),
    };
    owner.validate()?;
    Ok(owner)
}

fn validate_auth_account(
    account_id: Uuid,
    owner: &AccountOwner,
    display_name: &str,
) -> Result<(), StoreError> {
    if account_id.is_nil() {
        return Err(StoreError::InvalidAccountId);
    }
    owner.validate()?;
    validate_auth_display_name(display_name)
}

fn validate_auth_display_name(value: &str) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        Err(StoreError::InvalidAuthDisplayName)
    } else {
        Ok(())
    }
}

fn uuid_from_bytes(bytes: &[u8]) -> Result<Uuid, StoreError> {
    Uuid::from_slice(bytes).map_err(|_| StoreError::InvalidAccountId)
}

fn digest_from_bytes(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::InvalidSecretLength)
}

fn decode_device_enrollment_row(
    row: &rusqlite::Row<'_>,
) -> Result<DeviceEnrollmentRecord, rusqlite::Error> {
    let site_id = row.get::<_, String>(0)?;
    let guest_id = row.get::<_, String>(1)?;
    let device_id = row.get::<_, String>(2)?;
    Ok(DeviceEnrollmentRecord {
        site_id: SiteId::new(site_id).map_err(to_sql_conversion_error)?,
        guest_id: GuestId::new(guest_id).map_err(to_sql_conversion_error)?,
        device_id: DeviceId::new(device_id).map_err(to_sql_conversion_error)?,
        created_unix: row.get(3)?,
        expires_unix: row.get(4)?,
        used_unix: row.get(5)?,
    })
}

fn to_sql_conversion_error(error: ValidationError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

fn create_current_schema(transaction: &Transaction<'_>) -> Result<(), rusqlite::Error> {
    create_v2_schema(transaction)?;
    create_access_schema(transaction)?;
    create_auth_schema(transaction)?;
    create_enrollment_schema(transaction)
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
         ) STRICT;",
    )
}

fn create_auth_schema(transaction: &Transaction<'_>) -> Result<(), rusqlite::Error> {
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS auth_accounts (
             id BLOB PRIMARY KEY NOT NULL CHECK (length(id) = 16),
             kind TEXT NOT NULL CHECK (kind IN ('administrator', 'guest')),
             site_id TEXT,
             guest_id TEXT,
             display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
             password_hash TEXT CHECK (password_hash IS NULL OR length(password_hash) BETWEEN 1 AND 512),
             encrypted_totp BLOB,
             encrypted_recovery_pepper BLOB NOT NULL,
             CHECK (
                 (kind = 'administrator' AND site_id IS NULL AND guest_id IS NULL) OR
                 (kind = 'guest' AND site_id IS NOT NULL AND guest_id IS NOT NULL)
             ),
             FOREIGN KEY (site_id, guest_id) REFERENCES guests(site_id, id) ON DELETE CASCADE
         ) STRICT;
         CREATE UNIQUE INDEX IF NOT EXISTS auth_one_administrator
             ON auth_accounts(kind) WHERE kind = 'administrator';
         CREATE UNIQUE INDEX IF NOT EXISTS auth_guest_owner
             ON auth_accounts(site_id, guest_id) WHERE kind = 'guest';
         CREATE TABLE IF NOT EXISTS passkeys (
             credential_id BLOB PRIMARY KEY NOT NULL
                 CHECK (length(credential_id) BETWEEN 1 AND 1024),
             account_id BLOB NOT NULL,
             label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
             document BLOB NOT NULL,
             created_unix INTEGER NOT NULL,
             last_used_unix INTEGER,
             revoked INTEGER NOT NULL CHECK (revoked IN (0, 1)),
             FOREIGN KEY (account_id) REFERENCES auth_accounts(id) ON DELETE CASCADE
         ) STRICT;
         CREATE INDEX IF NOT EXISTS passkeys_account ON passkeys(account_id, revoked);
         CREATE TABLE IF NOT EXISTS recovery_codes (
             account_id BLOB NOT NULL,
             digest BLOB NOT NULL CHECK (length(digest) = 32),
             created_unix INTEGER NOT NULL,
             used_unix INTEGER,
             PRIMARY KEY (account_id, digest),
             FOREIGN KEY (account_id) REFERENCES auth_accounts(id) ON DELETE CASCADE
         ) STRICT;
         CREATE TABLE IF NOT EXISTS sessions (
             token_hash BLOB PRIMARY KEY NOT NULL CHECK (length(token_hash) = 32),
             account_id BLOB NOT NULL,
             csrf_hash BLOB NOT NULL CHECK (length(csrf_hash) = 32),
             created_unix INTEGER NOT NULL,
             expires_unix INTEGER NOT NULL CHECK (expires_unix >= created_unix),
             last_seen_unix INTEGER NOT NULL,
             fresh_until_unix INTEGER NOT NULL
                 CHECK (fresh_until_unix BETWEEN created_unix AND expires_unix),
             revoked INTEGER NOT NULL CHECK (revoked IN (0, 1)),
             FOREIGN KEY (account_id) REFERENCES auth_accounts(id) ON DELETE CASCADE
         ) STRICT;
         CREATE INDEX IF NOT EXISTS sessions_account ON sessions(account_id, revoked);
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

fn create_enrollment_schema(transaction: &Transaction<'_>) -> Result<(), rusqlite::Error> {
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS device_enrollments (
             token_hash BLOB PRIMARY KEY NOT NULL CHECK (length(token_hash) = 32),
             site_id TEXT NOT NULL,
             guest_id TEXT NOT NULL,
             device_id TEXT NOT NULL,
             created_unix INTEGER NOT NULL,
             expires_unix INTEGER NOT NULL CHECK (expires_unix > created_unix),
             used_unix INTEGER,
             UNIQUE (site_id, guest_id, device_id),
             FOREIGN KEY (site_id, guest_id, device_id)
                 REFERENCES devices(site_id, guest_id, id) ON DELETE CASCADE
         ) STRICT;
         CREATE INDEX IF NOT EXISTS device_enrollments_expiry
             ON device_enrollments(expires_unix, used_unix);",
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
        "UPDATE schema_version SET version = 3 WHERE singleton = 1",
        [],
    )?;
    Ok(())
}

fn migrate_v3_to_v4(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    transaction.execute_batch("DROP TABLE IF EXISTS sessions;")?;
    create_auth_schema(transaction)?;
    transaction.execute(
        "UPDATE schema_version SET version = ?1 WHERE singleton = 1",
        [4],
    )?;
    Ok(())
}

fn migrate_v4_to_v5(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    create_enrollment_schema(transaction)?;
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
    #[error("device {device_id} not found for guest {guest_id} in site {site_id}")]
    DeviceNotFound {
        site_id: SiteId,
        guest_id: GuestId,
        device_id: DeviceId,
    },
    #[error("duplicate mapping permission: {0}")]
    DuplicatePermission(MappingId),
    #[error("authentication account not found: {0}")]
    AccountNotFound(Uuid),
    #[error("invalid or nil authentication account UUID")]
    InvalidAccountId,
    #[error("invalid authentication account owner")]
    InvalidAccountOwner,
    #[error("authentication display name must be 1-128 characters without control characters")]
    InvalidAuthDisplayName,
    #[error("decrypted authentication secret has an invalid length")]
    InvalidSecretLength,
    #[error("passkey credential is already assigned to another account")]
    CredentialAlreadyAssigned,
    #[error("stored passkey identifier does not match its credential document")]
    CredentialIdentifierMismatch,
    #[error("passkey credential was not found or has been revoked")]
    CredentialNotFound,
    #[error("recovery-code set must contain 1-32 entries")]
    InvalidRecoveryCodeCount,
    #[error("recovery-code digests must be unique")]
    DuplicateRecoveryCode,
    #[error("session timestamps are inconsistent")]
    InvalidSessionTimes,
    #[error("device enrollment timestamps are inconsistent")]
    InvalidEnrollmentTimes,
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
    #[error(transparent)]
    Password(#[from] torkitten_auth::PasswordError),
    #[error(transparent)]
    Totp(#[from] torkitten_auth::TotpError),
    #[error(transparent)]
    Passkey(#[from] torkitten_auth::PasskeyError),
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use torkitten_auth::{
        generate_recovery_codes, hash_password, verify_password, verify_recovery_code,
    };
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
        let account_id = Uuid::new_v4();
        store
            .create_auth_account(
                account_id,
                &AccountOwner::Administrator,
                "Administrator",
                None,
                None,
                &[9_u8; 32],
            )
            .unwrap();
        let token = SessionToken::generate().unwrap();
        let csrf = CsrfToken::generate().unwrap();
        store
            .put_session(account_id, &token, &csrf, 100, 200, 120)
            .unwrap();
        let record = store.touch_session(&token, 110).unwrap().unwrap();
        assert_eq!(record.account_id, account_id);
        assert_eq!(record.csrf_hash, csrf.digest());
        assert_eq!(record.fresh_until_unix, 120);
        assert!(record.csrf_matches(&csrf));
        assert!(!record.csrf_matches(&CsrfToken::generate().unwrap()));
        assert!(record.is_fresh(119));
        assert!(!record.is_fresh(120));
        assert!(store.revoke_session(&token).unwrap());
        assert!(store.touch_session(&token, 120).unwrap().is_none());
        for filename in [DATABASE_FILENAME, "state.sqlite3-wal"] {
            let path = temporary.path().join(filename);
            if let Ok(database) = fs::read(path) {
                for secret in [token.expose(), csrf.expose()] {
                    assert!(
                        !database
                            .windows(secret.len())
                            .any(|window| window == secret.as_bytes())
                    );
                }
            }
        }
    }

    #[test]
    fn enrollment_tokens_are_hashed_scoped_expiring_and_one_time() {
        let (temporary, mut store) = store();
        let site_id = SiteId::new("alpha").unwrap();
        let guest_id = GuestId::new("family").unwrap();
        let device_id = DeviceId::new("phone").unwrap();
        store.put_site(&site("alpha", Vec::new())).unwrap();
        store.put_guest(&guest(&site_id, "family")).unwrap();
        store
            .put_device(&device(&site_id, &guest_id, "phone"), b"credential")
            .unwrap();

        let token = EnrollmentToken::generate().unwrap();
        store
            .put_device_enrollment(&token, &site_id, &guest_id, &device_id, 100, 200)
            .unwrap();
        let record = store.device_enrollment(&token, 150).unwrap().unwrap();
        assert_eq!(record.site_id, site_id);
        assert_eq!(record.guest_id, guest_id);
        assert_eq!(record.device_id, device_id);
        assert!(store.device_enrollment(&token, 200).unwrap().is_none());

        let consumed = store
            .consume_device_enrollment(&token, 151)
            .unwrap()
            .unwrap();
        assert_eq!(consumed.used_unix, Some(151));
        assert!(
            store
                .consume_device_enrollment(&token, 152)
                .unwrap()
                .is_none()
        );
        for filename in [DATABASE_FILENAME, "state.sqlite3-wal"] {
            let path = temporary.path().join(filename);
            if let Ok(database) = fs::read(path) {
                assert!(
                    !database
                        .windows(token.expose().len())
                        .any(|window| window == token.expose().as_bytes())
                );
            }
        }
    }

    #[test]
    fn persists_encrypted_account_factors_and_one_time_recovery_codes() {
        let (temporary, mut store) = store();
        let site_id = SiteId::new("alpha").unwrap();
        let guest_id = GuestId::new("family").unwrap();
        store.put_site(&site("alpha", Vec::new())).unwrap();
        store.put_guest(&guest(&site_id, "family")).unwrap();

        let account_id = Uuid::new_v4();
        let owner = AccountOwner::Guest {
            site_id: site_id.clone(),
            guest_id: guest_id.clone(),
        };
        let password = hash_password("correct horse battery staple").unwrap();
        let totp = TotpSecret::generate().unwrap();
        let pepper = [23_u8; 32];
        store
            .create_auth_account(
                account_id,
                &owner,
                "Family",
                Some(&password),
                Some(&totp),
                &pepper,
            )
            .unwrap();

        let account = store.auth_account_for_owner(&owner).unwrap().unwrap();
        assert_eq!(account.id, account_id);
        assert!(
            verify_password(
                "correct horse battery staple",
                account.password_hash.as_ref().unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            account.totp_secret.as_ref().unwrap().as_bytes(),
            totp.as_bytes()
        );
        assert_eq!(account.recovery_pepper.as_slice(), pepper);
        assert!(!format!("{account:?}").contains(password.as_str()));
        assert!(!format!("{account:?}").contains(totp.base32().as_str()));

        let codes = generate_recovery_codes(3).unwrap();
        let digests = codes
            .iter()
            .map(|code| code.digest(&pepper))
            .collect::<Vec<_>>();
        store
            .replace_recovery_codes(account_id, &digests, 100)
            .unwrap();
        assert!(verify_recovery_code(codes[0].expose(), &digests[0], &pepper).unwrap());
        assert!(
            store
                .consume_recovery_code(account_id, &digests[0], 110)
                .unwrap()
        );
        assert!(
            !store
                .consume_recovery_code(account_id, &digests[0], 111)
                .unwrap()
        );

        for filename in [DATABASE_FILENAME, "state.sqlite3-wal"] {
            let path = temporary.path().join(filename);
            if let Ok(database) = fs::read(path) {
                for secret in [totp.as_bytes(), pepper.as_slice()] {
                    assert!(
                        !database
                            .windows(secret.len())
                            .any(|window| window == secret)
                    );
                }
            }
        }
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

    #[test]
    fn migrates_v4_auth_state_and_adds_device_enrollments() {
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
                 INSERT INTO schema_version (singleton, version) VALUES (1, 4);",
            )
            .unwrap();
        create_v2_schema(&transaction).unwrap();
        create_access_schema(&transaction).unwrap();
        create_auth_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        drop(connection);

        let mut migrated = Store::open(temporary.path()).unwrap();
        let site_id = SiteId::new("alpha").unwrap();
        let guest_id = GuestId::new("family").unwrap();
        let device_id = DeviceId::new("phone").unwrap();
        migrated.put_site(&site("alpha", Vec::new())).unwrap();
        migrated.put_guest(&guest(&site_id, "family")).unwrap();
        migrated
            .put_device(&device(&site_id, &guest_id, "phone"), b"credential")
            .unwrap();
        migrated
            .put_device_enrollment(
                &EnrollmentToken::generate().unwrap(),
                &site_id,
                &guest_id,
                &device_id,
                100,
                200,
            )
            .unwrap();
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
