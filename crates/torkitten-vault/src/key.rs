use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use getrandom::fill;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const KEY_LENGTH: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; KEY_LENGTH]);

impl VaultKey {
    /// Loads an existing vault key or atomically creates a new private key.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory or key permissions are unsafe, the
    /// key is malformed, randomness fails, or an I/O operation fails.
    pub fn load_or_create(path: &Path) -> Result<Self, KeyError> {
        let parent = path.parent().ok_or(KeyError::MissingParent)?;
        ensure_private_directory(parent)?;

        match Self::load(path) {
            Ok(key) => return Ok(key),
            Err(KeyError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let mut bytes = [0_u8; KEY_LENGTH];
        fill(&mut bytes).map_err(KeyError::Random)?;
        let temporary_path = temporary_key_path(parent)?;
        let mut temporary = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary_path)?;
        temporary.write_all(&bytes)?;
        temporary.sync_all()?;

        match fs::hard_link(&temporary_path, path) {
            Ok(()) => {
                fs::remove_file(&temporary_path)?;
                sync_directory(parent)?;
                Ok(Self(bytes))
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                bytes.zeroize();
                fs::remove_file(&temporary_path)?;
                Self::load(path)
            }
            Err(error) => {
                bytes.zeroize();
                let _ = fs::remove_file(&temporary_path);
                Err(KeyError::Io(error))
            }
        }
    }

    /// Loads a vault key after validating its type, permissions, and size.
    ///
    /// # Errors
    ///
    /// Returns an error for an unreadable key, broad permissions, or a key that
    /// is not exactly 32 bytes.
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(KeyError::NotRegularFile(path.to_path_buf()));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(KeyError::UnsafePermissions { mode });
        }

        let mut file = File::open(path)?;
        let mut bytes = [0_u8; KEY_LENGTH];
        file.read_exact(&mut bytes)?;
        let mut extra = [0_u8; 1];
        if file.read(&mut extra)? != 0 {
            bytes.zeroize();
            return Err(KeyError::InvalidLength);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LENGTH] {
        &self.0
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), KeyError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(KeyError::NotPrivateDirectory(path.to_path_buf()));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn temporary_key_path(parent: &Path) -> Result<PathBuf, KeyError> {
    for _ in 0..32 {
        let mut random = [0_u8; 8];
        fill(&mut random).map_err(KeyError::Random)?;
        let suffix = u64::from_ne_bytes(random);
        let candidate = parent.join(format!(".vault-key-{suffix:016x}.tmp"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(KeyError::TemporaryNameExhausted)
}

fn sync_directory(path: &Path) -> Result<(), KeyError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("vault key path has no parent directory")]
    MissingParent,
    #[error("vault key is not a regular file: {path}", path = .0.display())]
    NotRegularFile(PathBuf),
    #[error("vault key parent is not a private directory: {path}", path = .0.display())]
    NotPrivateDirectory(PathBuf),
    #[error("vault key has unsafe mode {mode:o}; group and other permissions must be zero")]
    UnsafePermissions { mode: u32 },
    #[error("vault key must contain exactly 32 bytes")]
    InvalidLength,
    #[error("could not allocate a temporary vault-key filename")]
    TemporaryNameExhausted,
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_reloads_private_key() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("state/secrets/vault.key");
        let first = VaultKey::load_or_create(&path).unwrap();
        let second = VaultKey::load_or_create(&path).unwrap();
        assert_eq!(first.expose(), second.expose());
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn rejects_group_readable_key() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("vault.key");
        fs::write(&path, [7_u8; KEY_LENGTH]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            VaultKey::load(&path),
            Err(KeyError::UnsafePermissions { .. })
        ));
    }
}
