use std::fmt;

use data_encoding::BASE32_NOPAD;
use getrandom::fill;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SECRET_BYTES: usize = 32;
const MINIMUM_SECRET_BYTES: usize = 20;
const MAXIMUM_SECRET_BYTES: usize = 64;
const TIME_STEP_SECONDS: u64 = 30;
const CODE_MODULUS: u32 = 1_000_000;
const MAXIMUM_DRIFT_STEPS: u8 = 10;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TotpSecret(Vec<u8>);

impl TotpSecret {
    /// Generates a 256-bit TOTP secret with operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns an error when operating-system randomness is unavailable.
    pub fn generate() -> Result<Self, TotpError> {
        let mut bytes = vec![0_u8; SECRET_BYTES];
        fill(&mut bytes).map_err(TotpError::Random)?;
        Ok(Self(bytes))
    }

    /// Restores a TOTP secret from raw key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error unless the key contains 20-64 bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, TotpError> {
        if (MINIMUM_SECRET_BYTES..=MAXIMUM_SECRET_BYTES).contains(&bytes.len()) {
            Ok(Self(bytes))
        } else {
            Err(TotpError::InvalidSecret)
        }
    }

    /// Restores an uppercase, unpadded RFC 4648 base32 secret.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed base32 or a key outside 20-64 bytes.
    pub fn from_base32(encoded: &str) -> Result<Self, TotpError> {
        let bytes = BASE32_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|_| TotpError::InvalidSecret)?;
        Self::from_bytes(bytes)
    }

    #[must_use]
    pub fn base32(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE32_NOPAD.encode(&self.0))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Computes the six-digit code for a Unix timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error for a negative timestamp or an HMAC initialization
    /// failure.
    pub fn code_at(&self, unix_seconds: i64) -> Result<String, TotpError> {
        let counter = counter(unix_seconds)?;
        let code = hotp(&self.0, counter)?;
        Ok(format!("{code:06}"))
    }

    /// Verifies a six-digit code in constant time across a bounded clock-drift
    /// window.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, a negative timestamp, an excessive
    /// drift window, or an HMAC initialization failure.
    pub fn verify(
        &self,
        candidate: &str,
        unix_seconds: i64,
        allowed_drift_steps: u8,
    ) -> Result<bool, TotpError> {
        if candidate.len() != 6 || !candidate.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(TotpError::InvalidCode);
        }
        if allowed_drift_steps > MAXIMUM_DRIFT_STEPS {
            return Err(TotpError::DriftTooLarge);
        }
        let current = counter(unix_seconds)?;
        let drift = i64::from(allowed_drift_steps);
        let mut matched = 0_u8;
        for offset in -drift..=drift {
            let Some(counter) = current.checked_add_signed(offset) else {
                continue;
            };
            let code = format!("{:06}", hotp(&self.0, counter)?);
            matched |= code.as_bytes().ct_eq(candidate.as_bytes()).unwrap_u8();
        }
        Ok(matched == 1)
    }
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TotpSecret([REDACTED])")
    }
}

fn counter(unix_seconds: i64) -> Result<u64, TotpError> {
    let unix_seconds = u64::try_from(unix_seconds).map_err(|_| TotpError::InvalidTimestamp)?;
    Ok(unix_seconds / TIME_STEP_SECONDS)
}

fn hotp(secret: &[u8], counter: u64) -> Result<u32, TotpError> {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).map_err(|_| TotpError::InvalidSecret)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(binary % CODE_MODULUS)
}

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("TOTP secret must contain 20-64 bytes")]
    InvalidSecret,
    #[error("TOTP code must contain exactly six ASCII digits")]
    InvalidCode,
    #[error("TOTP timestamp cannot be negative")]
    InvalidTimestamp,
    #[error("TOTP drift window cannot exceed ten steps")]
    DriftTooLarge,
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_6238_sha1_six_digit_vector() {
        let secret = TotpSecret::from_bytes(b"12345678901234567890".to_vec()).unwrap();
        assert_eq!(secret.code_at(59).unwrap(), "287082");
        assert!(secret.verify("287082", 59, 0).unwrap());
        assert!(!secret.verify("287083", 59, 0).unwrap());
    }

    #[test]
    fn accepts_only_the_configured_bounded_drift_window() {
        let secret = TotpSecret::generate().unwrap();
        let prior = secret.code_at(30).unwrap();
        assert!(!secret.verify(&prior, 60, 0).unwrap());
        assert!(secret.verify(&prior, 60, 1).unwrap());
        assert!(matches!(
            secret.verify(&prior, 60, 11),
            Err(TotpError::DriftTooLarge)
        ));
        assert!(!format!("{secret:?}").contains(secret.base32().as_str()));
    }

    #[test]
    fn base32_round_trip_preserves_the_secret() {
        let secret = TotpSecret::generate().unwrap();
        let encoded = secret.base32();
        let restored = TotpSecret::from_base32(&encoded).unwrap();
        assert_eq!(secret.as_bytes(), restored.as_bytes());
    }
}
