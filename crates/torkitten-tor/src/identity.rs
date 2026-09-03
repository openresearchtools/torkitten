use std::fmt;

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::SigningKey;
use sha2::{Digest as Sha2Digest, Sha512};
use sha3::Sha3_256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SECRET_HEADER_TEXT: &[u8] = b"== ed25519v1-secret: type0 ==";
const PUBLIC_HEADER_TEXT: &[u8] = b"== ed25519v1-public: type0 ==";
const TAGGED_HEADER_BYTES: usize = 32;
const ONION_CHECKSUM_PREFIX: &[u8] = b".onion checksum";
const ONION_VERSION: u8 = 3;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OnionIdentity {
    hostname: String,
    secret_key_file: Zeroizing<Vec<u8>>,
    #[zeroize(skip)]
    public_key_file: Vec<u8>,
}

impl OnionIdentity {
    /// Generates a C Tor-compatible persistent v3 onion identity.
    ///
    /// # Errors
    ///
    /// Returns an error when operating-system randomness is unavailable.
    pub fn generate() -> Result<Self, OnionIdentityError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(OnionIdentityError::Random)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();

        let mut expanded = Zeroizing::new(Sha512::digest(seed.as_slice()).to_vec());
        expanded[0] &= 0xf8;
        expanded[31] &= 63;
        expanded[31] |= 64;

        let secret_key_file = tagged_file(SECRET_HEADER_TEXT, &expanded);
        let public_key_file = tagged_file(PUBLIC_HEADER_TEXT, &public_key);
        let hostname = onion_hostname(&public_key);
        Ok(Self {
            hostname,
            secret_key_file: Zeroizing::new(secret_key_file),
            public_key_file,
        })
    }

    #[must_use]
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub(crate) fn secret_key_file(&self) -> &[u8] {
        &self.secret_key_file
    }

    pub(crate) fn public_key_file(&self) -> &[u8] {
        &self.public_key_file
    }
}

impl fmt::Debug for OnionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnionIdentity")
            .field("hostname", &self.hostname)
            .field("secret_key_file", &"[REDACTED]")
            .field("public_key_file", &"[PUBLIC KEY]")
            .finish()
    }
}

fn tagged_file(header_text: &[u8], body: &[u8]) -> Vec<u8> {
    let mut output = vec![0_u8; TAGGED_HEADER_BYTES + body.len()];
    output[..header_text.len()].copy_from_slice(header_text);
    output[TAGGED_HEADER_BYTES..].copy_from_slice(body);
    output
}

fn onion_hostname(public_key: &[u8; 32]) -> String {
    let mut checksum_input = Vec::with_capacity(ONION_CHECKSUM_PREFIX.len() + 33);
    checksum_input.extend_from_slice(ONION_CHECKSUM_PREFIX);
    checksum_input.extend_from_slice(public_key);
    checksum_input.push(ONION_VERSION);
    let checksum = Sha3_256::digest(&checksum_input);
    let mut address = [0_u8; 35];
    address[..32].copy_from_slice(public_key);
    address[32..34].copy_from_slice(&checksum[..2]);
    address[34] = ONION_VERSION;
    format!(
        "{}.onion",
        BASE32_NOPAD.encode(&address).to_ascii_lowercase()
    )
}

#[derive(Debug, Error)]
pub enum OnionIdentityError {
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_tor_tagged_identity_and_v3_address() {
        let identity = OnionIdentity::generate().unwrap();
        assert_eq!(identity.hostname().len(), 62);
        assert!(identity.hostname().strip_suffix(".onion").is_some());
        assert!(
            identity.hostname()[..56]
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
        );
        assert_eq!(identity.secret_key_file().len(), 96);
        assert_eq!(identity.public_key_file().len(), 64);
        assert_eq!(
            &identity.secret_key_file()[..SECRET_HEADER_TEXT.len()],
            SECRET_HEADER_TEXT
        );
        assert_eq!(
            &identity.public_key_file()[..PUBLIC_HEADER_TEXT.len()],
            PUBLIC_HEADER_TEXT
        );
        assert!(!format!("{identity:?}").contains("ed25519v1-secret"));
    }
}
