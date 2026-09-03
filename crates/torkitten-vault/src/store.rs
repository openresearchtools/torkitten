use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use torkitten_core::{GatewayConfig, Mapping, MappingId, Site, SiteId, ValidationError};
use zeroize::Zeroizing;

use crate::{EncryptedSecret, VaultCipher, cipher::CipherError, key::KeyError};

const DATABASE_FILENAME: &str = "state.sqlite3";
const KEY_FILENAME: &str = "secrets/vault.key";
const DATABASE_SCHEMA_VERSION: i64 = 2;
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
            Some(1) => migrate_v1_to_v2(&transaction)?,
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

fn create_current_schema(transaction: &Transaction<'_>) -> Result<(), rusqlite::Error> {
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
    create_current_schema(transaction)?;
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
}
