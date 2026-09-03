use std::fmt;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use getrandom::fill;
use thiserror::Error;

const MINIMUM_PASSWORD_BYTES: usize = 12;
const MAXIMUM_PASSWORD_BYTES: usize = 1024;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const HASH_LENGTH: usize = 32;

#[derive(Clone, Eq, PartialEq)]
pub struct PasswordHashValue(String);

impl PasswordHashValue {
    /// Parses a stored PHC password hash and requires Torkitten's Argon2id
    /// algorithm and version.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, non-Argon2id, or obsolete hashes.
    pub fn parse(encoded: impl Into<String>) -> Result<Self, PasswordError> {
        let encoded = encoded.into();
        let parsed = PasswordHash::new(&encoded).map_err(password_hash_error)?;
        let supported = parsed.algorithm.as_str() == "argon2id"
            && parsed.version == Some(19)
            && parsed.params.iter().count() == 3
            && parsed.params.get_decimal("m") == Some(ARGON2_MEMORY_KIB)
            && parsed.params.get_decimal("t") == Some(ARGON2_ITERATIONS)
            && parsed.params.get_decimal("p") == Some(ARGON2_PARALLELISM)
            && parsed.hash.is_some_and(|hash| hash.len() == HASH_LENGTH);
        if !supported {
            return Err(PasswordError::UnsupportedHash);
        }
        Ok(Self(encoded))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PasswordHashValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordHashValue([REDACTED])")
    }
}

/// Hashes a password with fixed Argon2id v1.3 parameters and a fresh salt.
///
/// # Errors
///
/// Returns an error when the password violates the length policy, operating
/// system randomness fails, or Argon2 cannot initialize or hash it.
pub fn hash_password(password: &str) -> Result<PasswordHashValue, PasswordError> {
    validate_password(password)?;
    let mut salt_bytes = [0_u8; 16];
    fill(&mut salt_bytes).map_err(PasswordError::Random)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(password_hash_error)?;
    let encoded = argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(password_hash_error)?
        .to_string();
    PasswordHashValue::parse(encoded)
}

/// Verifies a candidate against a parsed Argon2id PHC hash.
///
/// # Errors
///
/// Returns an error when the stored hash is malformed or Argon2 cannot be
/// initialized. A wrong password returns `Ok(false)`.
pub fn verify_password(
    candidate: &str,
    expected: &PasswordHashValue,
) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(expected.as_str()).map_err(password_hash_error)?;
    match argon2()?.verify_password(candidate.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(error) => Err(password_hash_error(error)),
    }
}

fn argon2() -> Result<Argon2<'static>, PasswordError> {
    let parameters = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(HASH_LENGTH),
    )
    .map_err(|error| PasswordError::Hash(error.to_string()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters))
}

fn validate_password(password: &str) -> Result<(), PasswordError> {
    if (MINIMUM_PASSWORD_BYTES..=MAXIMUM_PASSWORD_BYTES).contains(&password.len())
        && !password.contains('\0')
    {
        Ok(())
    } else {
        Err(PasswordError::Policy)
    }
}

fn password_hash_error(error: argon2::password_hash::Error) -> PasswordError {
    PasswordError::Hash(error.to_string())
}

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("password must be 12-1024 UTF-8 bytes and contain no NUL")]
    Policy,
    #[error("unsupported password hash algorithm or version")]
    UnsupportedHash,
    #[error("password hashing failed: {0}")]
    Hash(String),
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_verifies_without_exposing_the_hash_in_debug() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(hash.as_str().starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!verify_password("wrong password", &hash).unwrap());
        assert!(!format!("{hash:?}").contains(hash.as_str()));
    }

    #[test]
    fn enforces_password_policy_and_hash_algorithm() {
        assert!(matches!(hash_password("short"), Err(PasswordError::Policy)));
        assert!(matches!(
            PasswordHashValue::parse(
                "$argon2i$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            Err(PasswordError::UnsupportedHash)
        ));
    }
}
