use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use thiserror::Error;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Webauthn, WebauthnBuilder,
};

use crate::{SessionToken, TokenError};

const CEREMONY_TIMEOUT: Duration = Duration::from_secs(300);
const MAXIMUM_PENDING_CEREMONIES: usize = 1024;

pub struct PasskeyService {
    webauthn: Webauthn,
    ceremonies: Mutex<HashMap<[u8; 32], Ceremony>>,
}

impl PasskeyService {
    /// Creates a `WebAuthn` relying party for one exact HTTPS onion hostname.
    /// User verification is mandatory and cross-port origins are not accepted.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid v3 onion hostname, display name, URL, or
    /// `WebAuthn` relying-party configuration.
    pub fn new(onion_hostname: &str, relying_party_name: &str) -> Result<Self, PasskeyError> {
        validate_onion_hostname(onion_hostname)?;
        if relying_party_name.is_empty()
            || relying_party_name.len() > 128
            || relying_party_name.chars().any(char::is_control)
        {
            return Err(PasskeyError::InvalidRelyingPartyName);
        }
        let origin = Url::parse(&format!("https://{onion_hostname}"))
            .map_err(|_| PasskeyError::InvalidOrigin)?;
        let webauthn = WebauthnBuilder::new(onion_hostname, &origin)
            .map_err(|_| PasskeyError::Configuration)?
            .rp_name(relying_party_name)
            .timeout(CEREMONY_TIMEOUT)
            .allow_subdomains(false)
            .allow_any_port(false)
            .build()
            .map_err(|_| PasskeyError::Configuration)?;
        Ok(Self {
            webauthn,
            ceremonies: Mutex::new(HashMap::new()),
        })
    }

    /// Starts a user-verifying passkey registration and stores its challenge
    /// state only in server memory under an opaque one-time handle.
    ///
    /// # Errors
    ///
    /// Returns an error when `WebAuthn` rejects the account inputs, randomness is
    /// unavailable, the ceremony store is poisoned, or its bound is reached.
    pub fn start_registration(
        &self,
        account_id: Uuid,
        account_name: &str,
        display_name: &str,
        existing: &[Passkey],
    ) -> Result<RegistrationStart, PasskeyError> {
        validate_account(account_id, account_name, display_name)?;
        let excluded = if existing.is_empty() {
            None
        } else {
            Some(
                existing
                    .iter()
                    .map(|passkey| passkey.cred_id().clone())
                    .collect(),
            )
        };
        let (challenge, state) = self
            .webauthn
            .start_passkey_registration(account_id, account_name, display_name, excluded)
            .map_err(|_| PasskeyError::Protocol)?;
        let handle = self.insert(Ceremony::Registration {
            account_id,
            expires: Instant::now() + CEREMONY_TIMEOUT,
            state,
        })?;
        Ok(RegistrationStart { handle, challenge })
    }

    /// Consumes a registration handle exactly once and verifies the browser's
    /// attestation response.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown, expired, wrong-kind, replayed, or invalid
    /// ceremony responses.
    pub fn finish_registration(
        &self,
        handle: &SessionToken,
        response: &RegisterPublicKeyCredential,
    ) -> Result<RegistrationSuccess, PasskeyError> {
        let ceremony = self.take(handle)?;
        let Ceremony::Registration {
            account_id,
            expires,
            state,
        } = ceremony
        else {
            return Err(PasskeyError::WrongCeremony);
        };
        ensure_unexpired(expires)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &state)
            .map_err(|_| PasskeyError::Protocol)?;
        Ok(RegistrationSuccess {
            account_id,
            passkey,
        })
    }

    /// Starts a user-verifying passkey authentication and keeps all challenge
    /// state server-side.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty credential set, protocol failure,
    /// randomness failure, poisoned state, or a full ceremony store.
    pub fn start_authentication(
        &self,
        account_id: Uuid,
        credentials: Vec<Passkey>,
    ) -> Result<AuthenticationStart, PasskeyError> {
        if account_id.is_nil() {
            return Err(PasskeyError::InvalidAccount);
        }
        if credentials.is_empty() {
            return Err(PasskeyError::NoCredentials);
        }
        let (challenge, state) = self
            .webauthn
            .start_passkey_authentication(&credentials)
            .map_err(|_| PasskeyError::Protocol)?;
        let handle = self.insert(Ceremony::Authentication {
            account_id,
            credentials,
            expires: Instant::now() + CEREMONY_TIMEOUT,
            state,
        })?;
        Ok(AuthenticationStart { handle, challenge })
    }

    /// Consumes an authentication handle exactly once, verifies the assertion,
    /// and returns the credential with any counter or backup-state update.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown, expired, wrong-kind, replayed, unverified,
    /// or invalid ceremony responses.
    pub fn finish_authentication(
        &self,
        handle: &SessionToken,
        response: &PublicKeyCredential,
    ) -> Result<AuthenticationSuccess, PasskeyError> {
        let ceremony = self.take(handle)?;
        let Ceremony::Authentication {
            account_id,
            mut credentials,
            expires,
            state,
        } = ceremony
        else {
            return Err(PasskeyError::WrongCeremony);
        };
        ensure_unexpired(expires)?;
        let result = self
            .webauthn
            .finish_passkey_authentication(response, &state)
            .map_err(|_| PasskeyError::Protocol)?;
        if !result.user_verified() {
            return Err(PasskeyError::UserNotVerified);
        }
        let credential = credentials
            .iter_mut()
            .find(|credential| credential.cred_id() == result.cred_id())
            .ok_or(PasskeyError::CredentialNotFound)?;
        let needs_persistence = credential
            .update_credential(&result)
            .ok_or(PasskeyError::CredentialNotFound)?;
        Ok(AuthenticationSuccess {
            account_id,
            credential: credential.clone(),
            needs_persistence,
            result,
        })
    }

    /// Cancels a pending ceremony, returning whether the handle existed.
    ///
    /// # Errors
    ///
    /// Returns an error if the in-memory ceremony store is poisoned.
    pub fn cancel(&self, handle: &SessionToken) -> Result<bool, PasskeyError> {
        let mut ceremonies = self
            .ceremonies
            .lock()
            .map_err(|_| PasskeyError::StateUnavailable)?;
        purge_expired(&mut ceremonies);
        Ok(ceremonies.remove(&handle.digest()).is_some())
    }

    fn insert(&self, ceremony: Ceremony) -> Result<SessionToken, PasskeyError> {
        let mut ceremonies = self
            .ceremonies
            .lock()
            .map_err(|_| PasskeyError::StateUnavailable)?;
        purge_expired(&mut ceremonies);
        if ceremonies.len() >= MAXIMUM_PENDING_CEREMONIES {
            return Err(PasskeyError::TooManyCeremonies);
        }
        let mut ceremony = Some(ceremony);
        for _ in 0..32 {
            let handle = SessionToken::generate()?;
            if let std::collections::hash_map::Entry::Vacant(entry) =
                ceremonies.entry(handle.digest())
            {
                let value = ceremony.take().ok_or(PasskeyError::TokenAllocation)?;
                entry.insert(value);
                return Ok(handle);
            }
        }
        Err(PasskeyError::TokenAllocation)
    }

    fn take(&self, handle: &SessionToken) -> Result<Ceremony, PasskeyError> {
        self.ceremonies
            .lock()
            .map_err(|_| PasskeyError::StateUnavailable)?
            .remove(&handle.digest())
            .ok_or(PasskeyError::UnknownCeremony)
    }

    #[cfg(test)]
    fn pending_count(&self) -> usize {
        self.ceremonies.lock().unwrap().len()
    }
}

enum Ceremony {
    Registration {
        account_id: Uuid,
        expires: Instant,
        state: PasskeyRegistration,
    },
    Authentication {
        account_id: Uuid,
        credentials: Vec<Passkey>,
        expires: Instant,
        state: PasskeyAuthentication,
    },
}

impl Ceremony {
    fn expires(&self) -> Instant {
        match self {
            Self::Registration { expires, .. } | Self::Authentication { expires, .. } => *expires,
        }
    }
}

pub struct RegistrationStart {
    pub handle: SessionToken,
    pub challenge: CreationChallengeResponse,
}

pub struct RegistrationSuccess {
    pub account_id: Uuid,
    pub passkey: Passkey,
}

pub struct AuthenticationStart {
    pub handle: SessionToken,
    pub challenge: RequestChallengeResponse,
}

pub struct AuthenticationSuccess {
    pub account_id: Uuid,
    pub credential: Passkey,
    pub needs_persistence: bool,
    pub result: AuthenticationResult,
}

/// Serializes a registered passkey for server-side database persistence.
///
/// # Errors
///
/// Returns an error if credential serialization fails.
pub fn encode_passkey(passkey: &Passkey) -> Result<Vec<u8>, PasskeyError> {
    serde_json::to_vec(passkey).map_err(|_| PasskeyError::CredentialEncoding)
}

/// Deserializes a passkey previously stored by [`encode_passkey`].
///
/// # Errors
///
/// Returns an error if the stored credential is malformed.
pub fn decode_passkey(encoded: &[u8]) -> Result<Passkey, PasskeyError> {
    serde_json::from_slice(encoded).map_err(|_| PasskeyError::CredentialEncoding)
}

#[must_use]
pub fn passkey_credential_id(passkey: &Passkey) -> Vec<u8> {
    passkey.cred_id().as_ref().to_vec()
}

fn purge_expired(ceremonies: &mut HashMap<[u8; 32], Ceremony>) {
    let now = Instant::now();
    ceremonies.retain(|_, ceremony| ceremony.expires() > now);
}

fn ensure_unexpired(expires: Instant) -> Result<(), PasskeyError> {
    if expires > Instant::now() {
        Ok(())
    } else {
        Err(PasskeyError::ExpiredCeremony)
    }
}

fn validate_onion_hostname(hostname: &str) -> Result<(), PasskeyError> {
    let service_id = hostname.strip_suffix(".onion");
    let valid = service_id.is_some_and(|service_id| {
        service_id.len() == 56
            && service_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
    });
    if valid {
        Ok(())
    } else {
        Err(PasskeyError::InvalidOnionHostname)
    }
}

fn validate_account(
    account_id: Uuid,
    account_name: &str,
    display_name: &str,
) -> Result<(), PasskeyError> {
    let valid_name = |value: &str| {
        !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
    };
    if !account_id.is_nil() && valid_name(account_name) && valid_name(display_name) {
        Ok(())
    } else {
        Err(PasskeyError::InvalidAccount)
    }
}

#[derive(Debug, Error)]
pub enum PasskeyError {
    #[error("invalid v3 onion hostname")]
    InvalidOnionHostname,
    #[error("invalid relying-party display name")]
    InvalidRelyingPartyName,
    #[error("invalid relying-party origin")]
    InvalidOrigin,
    #[error("invalid passkey account identifier or name")]
    InvalidAccount,
    #[error("invalid WebAuthn relying-party configuration")]
    Configuration,
    #[error("WebAuthn ceremony failed")]
    Protocol,
    #[error("no registered passkey is available")]
    NoCredentials,
    #[error("too many WebAuthn ceremonies are pending")]
    TooManyCeremonies,
    #[error("could not allocate a unique WebAuthn ceremony handle")]
    TokenAllocation,
    #[error("WebAuthn ceremony state is unavailable")]
    StateUnavailable,
    #[error("unknown or already-consumed WebAuthn ceremony")]
    UnknownCeremony,
    #[error("WebAuthn ceremony has expired")]
    ExpiredCeremony,
    #[error("wrong WebAuthn ceremony kind")]
    WrongCeremony,
    #[error("WebAuthn did not verify the user")]
    UserNotVerified,
    #[error("authenticated passkey was not found")]
    CredentialNotFound,
    #[error("stored passkey encoding is invalid")]
    CredentialEncoding,
    #[error("opaque ceremony token failed: {0}")]
    Token(#[from] TokenError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    #[test]
    fn constructs_an_exact_user_verifying_onion_relying_party() {
        let service = PasskeyService::new(ONION, "Torkitten test").unwrap();
        let started = service
            .start_registration(Uuid::new_v4(), "family", "Family", &[])
            .unwrap();
        assert_eq!(service.pending_count(), 1);
        assert!(!format!("{:?}", started.handle).contains(started.handle.expose()));
        assert!(service.cancel(&started.handle).unwrap());
        assert!(!service.cancel(&started.handle).unwrap());
        assert_eq!(service.pending_count(), 0);
    }

    #[test]
    fn rejects_invalid_rp_configuration_and_empty_authentication() {
        assert!(matches!(
            PasskeyService::new("example.com", "Torkitten"),
            Err(PasskeyError::InvalidOnionHostname)
        ));
        assert!(matches!(
            PasskeyService::new(ONION, "bad\nname"),
            Err(PasskeyError::InvalidRelyingPartyName)
        ));
        let service = PasskeyService::new(ONION, "Torkitten").unwrap();
        assert!(matches!(
            service.start_authentication(Uuid::new_v4(), Vec::new()),
            Err(PasskeyError::NoCredentials)
        ));
    }
}
