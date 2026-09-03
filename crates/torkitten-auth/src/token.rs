use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use getrandom::fill;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const TOKEN_BYTES: usize = 32;

macro_rules! secret_token {
    ($name:ident, $debug_name:literal) => {
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name(String);

        impl $name {
            /// Generates a 256-bit URL-safe token using operating-system
            /// randomness.
            ///
            /// # Errors
            ///
            /// Returns an error if operating-system randomness is unavailable.
            pub fn generate() -> Result<Self, TokenError> {
                let mut bytes = [0_u8; TOKEN_BYTES];
                fill(&mut bytes).map_err(TokenError::Random)?;
                let encoded = URL_SAFE_NO_PAD.encode(bytes);
                bytes.zeroize();
                Ok(Self(encoded))
            }

            /// Parses the canonical URL-safe representation of a 256-bit
            /// token.
            ///
            /// # Errors
            ///
            /// Returns an error unless the token decodes to exactly 32 bytes
            /// and is encoded canonically without padding.
            pub fn parse(encoded: impl Into<String>) -> Result<Self, TokenError> {
                let encoded = encoded.into();
                let mut decoded = URL_SAFE_NO_PAD
                    .decode(encoded.as_bytes())
                    .map_err(|_| TokenError::Invalid)?;
                let valid = decoded.len() == TOKEN_BYTES
                    && URL_SAFE_NO_PAD.encode(decoded.as_slice()) == encoded;
                decoded.zeroize();
                if !valid {
                    return Err(TokenError::Invalid);
                }
                Ok(Self(encoded))
            }

            #[must_use]
            pub fn expose(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> [u8; 32] {
                Sha256::digest(self.0.as_bytes()).into()
            }

            #[must_use]
            pub fn digest_matches(&self, expected: &[u8; 32]) -> bool {
                bool::from(self.digest().ct_eq(expected))
            }

            #[must_use]
            pub fn constant_time_eq(&self, candidate: &str) -> bool {
                if candidate.len() != self.0.len() {
                    return false;
                }
                bool::from(self.0.as_bytes().ct_eq(candidate.as_bytes()))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($debug_name, "([REDACTED])"))
            }
        }
    };
}

secret_token!(SessionToken, "SessionToken");
secret_token!(CsrfToken, "CsrfToken");

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("invalid token encoding")]
    Invalid,
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_canonical_random_and_redacted() {
        let first = SessionToken::generate().unwrap();
        let second = SessionToken::generate().unwrap();
        assert_ne!(first.expose(), second.expose());
        assert_eq!(first.expose().len(), 43);
        assert!(first.constant_time_eq(first.expose()));
        assert!(!first.constant_time_eq(second.expose()));
        assert!(!format!("{first:?}").contains(first.expose()));
        assert_eq!(
            SessionToken::parse(first.expose()).unwrap().digest(),
            first.digest()
        );
    }

    #[test]
    fn rejects_noncanonical_or_wrong_length_tokens() {
        assert!(matches!(
            SessionToken::parse("short"),
            Err(TokenError::Invalid)
        ));
        let token = SessionToken::generate().unwrap();
        assert!(matches!(
            SessionToken::parse(format!("{}=", token.expose())),
            Err(TokenError::Invalid)
        ));
    }
}
