use std::{fmt, str::FromStr};

use data_encoding::BASE32_NOPAD;
use getrandom::fill;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ClientName(String);

impl ClientName {
    /// Constructs a Tor-compatible client authorization name.
    ///
    /// # Errors
    ///
    /// Returns [`ClientAuthError::InvalidName`] unless the value contains 1-16
    /// characters from Tor's `A-Za-z0-9+-_` client-name alphabet.
    pub fn new(value: impl Into<String>) -> Result<Self, ClientAuthError> {
        let value = value.into();
        let valid = (1..=16).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'_'));
        if valid {
            Ok(Self(value))
        } else {
            Err(ClientAuthError::InvalidName(value))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClientName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ClientName {
    type Err = ClientAuthError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientKeyPair {
    private_base32: String,
    #[zeroize(skip)]
    public_base32: String,
}

impl ClientKeyPair {
    /// Generates a new X25519 keypair using operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns an error when operating-system randomness is unavailable.
    pub fn generate() -> Result<Self, ClientAuthError> {
        let mut private_bytes = [0_u8; 32];
        fill(&mut private_bytes).map_err(ClientAuthError::Random)?;
        let private = StaticSecret::from(private_bytes);
        private_bytes.zeroize();
        let public = PublicKey::from(&private);
        let private_base32 = BASE32_NOPAD.encode(&private.to_bytes());
        let public_base32 = BASE32_NOPAD.encode(public.as_bytes());
        Ok(Self {
            private_base32,
            public_base32,
        })
    }

    #[must_use]
    pub fn server_authorization(&self) -> String {
        format!("descriptor:x25519:{}\n", self.public_base32)
    }

    /// Formats the private client credential for a known v3 onion hostname.
    ///
    /// # Errors
    ///
    /// Returns an error unless the hostname is a syntactically valid 56-character
    /// lowercase base32 v3 onion hostname.
    pub fn client_credential(
        &self,
        onion_hostname: &str,
    ) -> Result<ClientCredential, ClientAuthError> {
        let service_id = validate_onion_hostname(onion_hostname)?;
        Ok(ClientCredential(format!(
            "{service_id}:descriptor:x25519:{}",
            self.private_base32
        )))
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientCredential(String);

impl ClientCredential {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ClientCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientCredential([REDACTED])")
    }
}

pub(crate) fn validate_onion_hostname(hostname: &str) -> Result<&str, ClientAuthError> {
    let service_id = hostname.strip_suffix(".onion").unwrap_or(hostname);
    let valid = service_id.len() == 56
        && service_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'));
    if valid {
        Ok(service_id)
    } else {
        Err(ClientAuthError::InvalidOnionHostname(hostname.to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum ClientAuthError {
    #[error("invalid Tor client name: {0}")]
    InvalidName(String),
    #[error("invalid v3 onion hostname: {0}")]
    InvalidOnionHostname(String),
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    #[test]
    fn emits_tor_client_authorization_formats() {
        let pair = ClientKeyPair::generate().unwrap();
        let server = pair.server_authorization();
        let client = pair.client_credential(ONION).unwrap();
        assert!(server.starts_with("descriptor:x25519:"));
        assert_eq!(server.trim().split(':').nth(2).unwrap().len(), 52);
        assert!(client.expose().starts_with(&format!(
            "{}:descriptor:x25519:",
            ONION.trim_end_matches(".onion")
        )));
        assert_eq!(client.expose().rsplit(':').next().unwrap().len(), 52);
    }

    #[test]
    fn redacts_private_credential_debug() {
        let pair = ClientKeyPair::generate().unwrap();
        let client = pair.client_credential(ONION).unwrap();
        assert!(!format!("{client:?}").contains(client.expose()));
    }

    #[test]
    fn validates_client_names() {
        assert!(ClientName::new("phone_1").is_ok());
        assert!(ClientName::new("has a space").is_err());
        assert!(ClientName::new("abcdefghijklmnopq").is_err());
    }
}
