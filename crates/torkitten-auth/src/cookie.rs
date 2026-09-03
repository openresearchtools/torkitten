use std::fmt;

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SessionToken;

const MINIMUM_MAX_AGE_SECONDS: u64 = 300;
const MAXIMUM_MAX_AGE_SECONDS: u64 = 31_536_000;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SetCookieHeader(String);

impl SetCookieHeader {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SetCookieHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SetCookieHeader([REDACTED])")
    }
}

/// Builds the host-only remote guest cookie shared by all ports of one onion
/// hostname. The `__Host-` prefix prevents Domain and non-root Path scope.
///
/// # Errors
///
/// Returns an error when the configured lifetime is under five minutes or
/// over one year.
pub fn remote_session_cookie(
    token: &SessionToken,
    max_age_seconds: u64,
) -> Result<SetCookieHeader, CookieError> {
    session_cookie("__Host-torkitten_session", token, max_age_seconds, true)
}

/// Builds the host-only loopback administration cookie. It intentionally
/// omits `Secure` because the native and container administration listener is
/// plain HTTP on loopback; it retains `HttpOnly` and `SameSite=Strict`.
///
/// # Errors
///
/// Returns an error when the configured lifetime is under five minutes or
/// over one year.
pub fn local_admin_session_cookie(
    token: &SessionToken,
    max_age_seconds: u64,
) -> Result<SetCookieHeader, CookieError> {
    session_cookie("torkitten_admin_session", token, max_age_seconds, false)
}

#[must_use]
pub fn clear_remote_session_cookie() -> &'static str {
    "__Host-torkitten_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
}

#[must_use]
pub fn clear_local_admin_session_cookie() -> &'static str {
    "torkitten_admin_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
}

fn session_cookie(
    name: &str,
    token: &SessionToken,
    max_age_seconds: u64,
    secure: bool,
) -> Result<SetCookieHeader, CookieError> {
    if !(MINIMUM_MAX_AGE_SECONDS..=MAXIMUM_MAX_AGE_SECONDS).contains(&max_age_seconds) {
        return Err(CookieError::InvalidLifetime);
    }
    let secure_attribute = if secure { "; Secure" } else { "" };
    Ok(SetCookieHeader(format!(
        "{name}={}; Path=/; Max-Age={max_age_seconds}{secure_attribute}; HttpOnly; SameSite=Strict",
        token.expose()
    )))
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CookieError {
    #[error("session lifetime must be between five minutes and one year")]
    InvalidLifetime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_cookie_is_secure_host_only_and_hostname_wide() {
        let token = SessionToken::generate().unwrap();
        let header = remote_session_cookie(&token, 2_592_000).unwrap();
        assert!(
            header
                .expose()
                .starts_with(&format!("__Host-torkitten_session={}", token.expose()))
        );
        assert!(header.expose().contains("; Path=/;"));
        assert!(
            header
                .expose()
                .contains("; Secure; HttpOnly; SameSite=Strict")
        );
        assert!(!header.expose().contains("Domain="));
        assert!(!format!("{header:?}").contains(token.expose()));
    }

    #[test]
    fn loopback_cookie_remains_usable_over_local_http() {
        let token = SessionToken::generate().unwrap();
        let header = local_admin_session_cookie(&token, 2_592_000).unwrap();
        assert!(!header.expose().contains("; Secure"));
        assert!(header.expose().contains("; HttpOnly; SameSite=Strict"));
    }
}
