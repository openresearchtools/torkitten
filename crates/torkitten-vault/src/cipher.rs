use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use getrandom::fill;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::VaultKey;

const FORMAT_VERSION: u8 = 1;
const NONCE_LENGTH: usize = 24;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedSecret(Vec<u8>);

impl EncryptedSecret {
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub struct VaultCipher(XChaCha20Poly1305);

impl VaultCipher {
    #[must_use]
    pub fn new(key: &VaultKey) -> Self {
        Self(XChaCha20Poly1305::new(key.expose().into()))
    }

    /// Encrypts secret bytes and binds them to the supplied logical name.
    ///
    /// # Errors
    ///
    /// Returns an error when operating-system randomness or encryption fails.
    pub fn encrypt(&self, name: &str, plaintext: &[u8]) -> Result<EncryptedSecret, CipherError> {
        let mut nonce = [0_u8; NONCE_LENGTH];
        fill(&mut nonce).map_err(CipherError::Random)?;
        let ciphertext = self
            .0
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: name.as_bytes(),
                },
            )
            .map_err(|_| CipherError::Encryption)?;

        let mut encoded = Vec::with_capacity(1 + NONCE_LENGTH + ciphertext.len());
        encoded.push(FORMAT_VERSION);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        Ok(EncryptedSecret(encoded))
    }

    /// Decrypts secret bytes after authenticating their logical name.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported or truncated format, a mismatched
    /// logical name, a wrong vault key, or modified ciphertext.
    pub fn decrypt(
        &self,
        name: &str,
        secret: &EncryptedSecret,
    ) -> Result<Zeroizing<Vec<u8>>, CipherError> {
        let encoded = secret.as_bytes();
        if encoded.first() != Some(&FORMAT_VERSION) {
            return Err(CipherError::UnsupportedFormat);
        }
        if encoded.len() <= 1 + NONCE_LENGTH {
            return Err(CipherError::Truncated);
        }
        let nonce = XNonce::from_slice(&encoded[1..=NONCE_LENGTH]);
        let plaintext = self
            .0
            .decrypt(
                nonce,
                Payload {
                    msg: &encoded[1 + NONCE_LENGTH..],
                    aad: name.as_bytes(),
                },
            )
            .map_err(|_| CipherError::Authentication)?;
        Ok(Zeroizing::new(plaintext))
    }
}

#[derive(Debug, Error)]
pub enum CipherError {
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
    #[error("secret encryption failed")]
    Encryption,
    #[error("secret authentication failed")]
    Authentication,
    #[error("unsupported encrypted-secret format")]
    UnsupportedFormat,
    #[error("truncated encrypted secret")]
    Truncated,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> VaultCipher {
        let temporary = tempfile::tempdir().unwrap();
        let key = VaultKey::load_or_create(&temporary.path().join("vault.key")).unwrap();
        VaultCipher::new(&key)
    }

    #[test]
    fn round_trip_and_aad_binding() {
        let cipher = cipher();
        let encrypted = cipher.encrypt("totp", b"very secret").unwrap();
        assert_eq!(
            &*cipher.decrypt("totp", &encrypted).unwrap(),
            b"very secret"
        );
        assert!(matches!(
            cipher.decrypt("different-name", &encrypted),
            Err(CipherError::Authentication)
        ));
    }

    #[test]
    fn rejects_modified_ciphertext() {
        let cipher = cipher();
        let mut encoded = cipher.encrypt("key", b"value").unwrap().into_bytes();
        *encoded.last_mut().unwrap() ^= 1;
        assert!(matches!(
            cipher.decrypt("key", &EncryptedSecret::from_bytes(encoded)),
            Err(CipherError::Authentication)
        ));
    }
}
