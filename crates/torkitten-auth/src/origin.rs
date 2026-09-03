use thiserror::Error;
use url::Url;

use crate::CsrfToken;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedOrigin {
    scheme: String,
    host: String,
    port: u16,
}

impl ExpectedOrigin {
    /// Parses the one exact browser origin accepted by an HTTP surface.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value is an HTTP(S) origin with no user
    /// information, non-root path, query, or fragment.
    pub fn parse(value: &str) -> Result<Self, OriginError> {
        let parsed = parse_origin(value)?;
        Ok(Self {
            scheme: parsed.scheme().to_owned(),
            host: parsed.host_str().ok_or(OriginError::Invalid)?.to_owned(),
            port: parsed.port_or_known_default().ok_or(OriginError::Invalid)?,
        })
    }

    /// Requires an exact scheme, hostname, and effective-port match.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or non-matching browser origins.
    pub fn validate(&self, candidate: &str) -> Result<(), OriginError> {
        let parsed = parse_origin(candidate)?;
        let matches = parsed.scheme() == self.scheme
            && parsed.host_str() == Some(self.host.as_str())
            && parsed.port_or_known_default() == Some(self.port);
        if matches {
            Ok(())
        } else {
            Err(OriginError::Mismatch)
        }
    }

    /// Returns whether this is an HTTP origin on localhost or a numeric
    /// loopback address using the specified externally published port.
    #[must_use]
    pub fn is_local_http_at_port(&self, port: u16) -> bool {
        let local_host = self.host == "localhost"
            || self
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        self.scheme == "http" && local_host && self.port == port
    }

    /// Enforces Origin and session-bound CSRF checks for every unsafe HTTP
    /// method. Safe methods do not mutate state and require neither value.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or wrong Origin or CSRF token.
    pub fn validate_request(
        &self,
        method: &str,
        origin: Option<&str>,
        csrf_candidate: Option<&str>,
        expected_csrf: &CsrfToken,
    ) -> Result<(), OriginError> {
        if matches!(method, "GET" | "HEAD" | "OPTIONS") {
            return Ok(());
        }
        self.validate(origin.ok_or(OriginError::Missing)?)?;
        let csrf_candidate = csrf_candidate.ok_or(OriginError::Csrf)?;
        if expected_csrf.constant_time_eq(csrf_candidate) {
            Ok(())
        } else {
            Err(OriginError::Csrf)
        }
    }
}

fn parse_origin(value: &str) -> Result<Url, OriginError> {
    let parsed = Url::parse(value).map_err(|_| OriginError::Invalid)?;
    let valid = matches!(parsed.scheme(), "http" | "https")
        && parsed.host_str().is_some()
        && parsed.port_or_known_default().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.path() == "/"
        && parsed.query().is_none()
        && parsed.fragment().is_none();
    if valid {
        Ok(parsed)
    } else {
        Err(OriginError::Invalid)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OriginError {
    #[error("missing request origin")]
    Missing,
    #[error("invalid request origin")]
    Invalid,
    #[error("request origin does not match this service")]
    Mismatch,
    #[error("missing or invalid CSRF token")]
    Csrf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_exact_loopback_origin_including_port() {
        let expected = ExpectedOrigin::parse("http://127.0.0.1:12755").unwrap();
        assert!(expected.validate("http://127.0.0.1:12755").is_ok());
        assert_eq!(
            expected.validate("http://127.0.0.1:12756"),
            Err(OriginError::Mismatch)
        );
        assert_eq!(
            expected.validate("https://127.0.0.1:12755"),
            Err(OriginError::Mismatch)
        );
        assert_eq!(
            expected.validate("http://localhost:12755"),
            Err(OriginError::Mismatch)
        );
        assert!(expected.is_local_http_at_port(12_755));
        assert!(
            ExpectedOrigin::parse("http://localhost:12755")
                .unwrap()
                .is_local_http_at_port(12_755)
        );
        assert!(
            !ExpectedOrigin::parse("https://localhost:12755")
                .unwrap()
                .is_local_http_at_port(12_755)
        );
    }

    #[test]
    fn rejects_values_that_are_urls_but_not_origins() {
        for value in [
            "http://user@127.0.0.1:12755",
            "http://127.0.0.1:12755/admin",
            "http://127.0.0.1:12755?query",
            "file:///tmp/admin",
            "null",
        ] {
            assert!(ExpectedOrigin::parse(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn unsafe_methods_require_origin_and_session_bound_csrf() {
        let expected = ExpectedOrigin::parse("https://example.onion").unwrap();
        let csrf = CsrfToken::generate().unwrap();
        assert!(expected.validate_request("GET", None, None, &csrf).is_ok());
        assert!(
            expected
                .validate_request(
                    "POST",
                    Some("https://example.onion"),
                    Some(csrf.expose()),
                    &csrf,
                )
                .is_ok()
        );
        assert_eq!(
            expected.validate_request("POST", Some("https://example.onion"), None, &csrf),
            Err(OriginError::Csrf)
        );
        assert_eq!(
            expected.validate_request(
                "POST",
                Some("https://other.onion"),
                Some(csrf.expose()),
                &csrf,
            ),
            Err(OriginError::Mismatch)
        );
    }
}
