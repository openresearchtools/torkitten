use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use torkitten_core::{GatewayConfig, Route, RouteId, ValidationError};
use zeroize::Zeroizing;

use crate::{EncryptedSecret, VaultCipher, cipher::CipherError, key::KeyError};

const DATABASE_FILENAME: &str = "state.sqlite3";
const KEY_FILENAME: &str = "secrets/vault.key";

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
    /// an invalid stored route configuration.
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

    /// Returns the currently committed, validated route configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite access, JSON decoding, or validation fails.
    pub fn gateway_config(&self) -> Result<GatewayConfig, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT document FROM routes ORDER BY virtual_port, id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut routes = Vec::new();
        for row in rows {
            routes.push(serde_json::from_str::<Route>(&row?)?);
        }
        let config = GatewayConfig {
            routes,
            ..GatewayConfig::default()
        };
        config.validate()?;
        Ok(config)
    }

    /// Adds or replaces one route in an atomic validated transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the route is invalid, conflicts with another
    /// route, or cannot be committed.
    pub fn put_route(&mut self, route: &Route) -> Result<(), StoreError> {
        route.validate()?;
        let mut candidate = self.gateway_config()?;
        candidate.routes.retain(|existing| existing.id != route.id);
        candidate.routes.push(route.clone());
        candidate.validate()?;

        let document = serde_json::to_string(route)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO routes (id, virtual_port, document) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET virtual_port = excluded.virtual_port,
                                           document = excluded.document",
            params![route.id.as_str(), i64::from(route.virtual_port), document],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Removes a route, returning whether a row existed.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot apply the deletion.
    pub fn remove_route(&self, id: &RouteId) -> Result<bool, StoreError> {
        Ok(self
            .connection
            .execute("DELETE FROM routes WHERE id = ?1", [id.as_str()])?
            != 0)
    }

    /// Stores an encrypted secret bound to its logical name.
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

    /// Retrieves and decrypts a named secret.
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

    fn migrate(&mut self) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 version INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO schema_version (singleton, version) VALUES (1, 1);
             CREATE TABLE IF NOT EXISTS routes (
                 id TEXT PRIMARY KEY NOT NULL,
                 virtual_port INTEGER UNIQUE NOT NULL CHECK (virtual_port BETWEEN 1 AND 65535),
                 document TEXT NOT NULL
             ) STRICT;
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
        )?;
        let version: i64 = transaction.query_row(
            "SELECT version FROM schema_version WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if version != 1 {
            return Err(StoreError::UnsupportedSchema(version));
        }
        transaction.commit()?;
        Ok(())
    }
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

    use torkitten_core::{RouteTarget, Transport};

    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(temporary.path()).unwrap();
        (temporary, store)
    }

    fn route(id: &str, virtual_port: u16) -> Route {
        Route {
            id: RouteId::new(id).unwrap(),
            display_name: id.to_owned(),
            virtual_port,
            target: RouteTarget::Tcp {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 3000,
                transport: Transport::Http,
            },
        }
    }

    #[test]
    fn persists_routes_and_rejects_port_conflicts() {
        let (_temporary, mut store) = store();
        store.put_route(&route("one", 8443)).unwrap();
        let error = store.put_route(&route("two", 8443)).unwrap_err();
        assert!(matches!(
            error,
            StoreError::Validation(ValidationError::DuplicateVirtualPort(8443))
        ));
        assert_eq!(
            store.gateway_config().unwrap().routes,
            vec![route("one", 8443)]
        );
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
