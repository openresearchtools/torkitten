use std::{collections::HashSet, fmt};

use data_encoding::BASE32_NOPAD;
use getrandom::fill;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const RANDOM_BYTES: usize = 10;
const ENCODED_CHARACTERS: usize = 16;
const MAXIMUM_CODE_COUNT: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode(String);

impl RecoveryCode {
    /// Parses a grouped or ungrouped recovery code.
    ///
    /// # Errors
    ///
    /// Returns an error unless the normalized value is exactly 16 uppercase
    /// RFC 4648 base32 characters.
    pub fn parse(value: &str) -> Result<Self, RecoveryError> {
        let normalized = normalize(value)?;
        Ok(Self(group(&normalized)))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Computes a keyed digest suitable for persistent one-time-code storage.
    #[must_use]
    pub fn digest(&self, pepper: &[u8; 32]) -> [u8; 32] {
        let normalized = Zeroizing::new(self.0.replace('-', ""));
        digest_normalized(&normalized, pepper)
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryCode([REDACTED])")
    }
}

/// Generates distinct, human-copyable one-time recovery codes.
///
/// # Errors
///
/// Returns an error for a zero or excessive count, or if operating-system
/// randomness is unavailable.
pub fn generate_recovery_codes(count: usize) -> Result<Vec<RecoveryCode>, RecoveryError> {
    if !(1..=MAXIMUM_CODE_COUNT).contains(&count) {
        return Err(RecoveryError::InvalidCount);
    }
    let mut codes = Vec::with_capacity(count);
    let mut unique = HashSet::with_capacity(count);
    while codes.len() < count {
        let mut bytes = [0_u8; RANDOM_BYTES];
        fill(&mut bytes).map_err(RecoveryError::Random)?;
        let encoded = Zeroizing::new(BASE32_NOPAD.encode(&bytes));
        bytes.zeroize();
        if unique.insert(<Sha256 as Digest>::digest(encoded.as_bytes())) {
            codes.push(RecoveryCode(group(&encoded)));
        }
    }
    Ok(codes)
}

/// Verifies a presented recovery code against a keyed stored digest.
///
/// # Errors
///
/// Returns an error for malformed code input.
pub fn verify_recovery_code(
    candidate: &str,
    expected_digest: &[u8; 32],
    pepper: &[u8; 32],
) -> Result<bool, RecoveryError> {
    let normalized = normalize(candidate)?;
    let candidate_digest = digest_normalized(&normalized, pepper);
    Ok(bool::from(candidate_digest.ct_eq(expected_digest)))
}

fn digest_normalized(normalized: &str, pepper: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(pepper).expect("HMAC-SHA256 accepts every 256-bit pepper");
    mac.update(normalized.as_bytes());
    mac.finalize().into_bytes().into()
}

fn normalize(value: &str) -> Result<Zeroizing<String>, RecoveryError> {
    let normalized = value
        .bytes()
        .filter(|byte| *byte != b'-')
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<_>>();
    if normalized.len() != ENCODED_CHARACTERS
        || !normalized
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || matches!(byte, b'2'..=b'7'))
        || BASE32_NOPAD.decode(&normalized).is_err()
    {
        return Err(RecoveryError::InvalidCode);
    }
    String::from_utf8(normalized)
        .map(Zeroizing::new)
        .map_err(|_| RecoveryError::InvalidCode)
}

fn group(normalized: &str) -> String {
    normalized
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("base32 is ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("recovery-code count must be between 1 and 32")]
    InvalidCount,
    #[error("invalid recovery-code format")]
    InvalidCode,
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_are_unique_grouped_and_redacted() {
        let codes = generate_recovery_codes(10).unwrap();
        let visible = codes
            .iter()
            .map(RecoveryCode::expose)
            .collect::<HashSet<_>>();
        assert_eq!(visible.len(), 10);
        assert!(codes.iter().all(|code| code.expose().len() == 19));
        assert!(!format!("{:?}", codes[0]).contains(codes[0].expose()));
    }

    #[test]
    fn keyed_digest_verification_accepts_grouping_and_case() {
        let pepper = [7_u8; 32];
        let code = RecoveryCode::parse("abcd-efgh-jklm-npqr").unwrap();
        let digest = code.digest(&pepper);
        assert!(verify_recovery_code("ABCDEFGHJKLMNPQR", &digest, &pepper).unwrap());
        assert!(!verify_recovery_code("ABCDEFGHJKLMNPQ2", &digest, &pepper).unwrap());
        assert!(!verify_recovery_code("ABCDEFGHJKLMNPQR", &digest, &[8_u8; 32]).unwrap());
    }
}
