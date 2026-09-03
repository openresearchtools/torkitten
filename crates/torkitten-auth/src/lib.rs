#![forbid(unsafe_code)]

mod cookie;
mod origin;
mod passkey;
mod password;
mod recovery;
mod token;
mod totp;

pub use cookie::{
    CookieError, SetCookieHeader, clear_local_admin_session_cookie, clear_remote_session_cookie,
    local_admin_session_cookie, remote_session_cookie,
};
pub use origin::{ExpectedOrigin, OriginError};
pub use passkey::{
    AuthenticationStart, AuthenticationSuccess, PasskeyError, PasskeyService, RegistrationStart,
    RegistrationSuccess, decode_passkey, encode_passkey, passkey_credential_id,
};
pub use password::{PasswordError, PasswordHashValue, hash_password, verify_password};
pub use recovery::{RecoveryCode, RecoveryError, generate_recovery_codes, verify_recovery_code};
pub use token::{CsrfToken, EnrollmentToken, SessionToken, TokenError};
pub use totp::{TotpError, TotpSecret};
pub use webauthn_rs::prelude::{Passkey, PublicKeyCredential, RegisterPublicKeyCredential};
