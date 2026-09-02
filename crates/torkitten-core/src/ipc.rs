use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Route, RouteId};

#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SensitiveString(String);

impl SensitiveString {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveString([REDACTED])")
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum AdminCommand {
    Status,
    Initialize { password: SensitiveString },
    AddRoute { route: Route },
    RemoveRoute { id: RouteId },
    EnrollClient { name: String },
    RevokeClient { name: String },
    OpenCertificateBootstrap { seconds: u32 },
    CloseCertificateBootstrap,
    EmergencyDisable,
    Enable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayMode {
    Uninitialized,
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    Stopped,
    Starting,
    Running,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayStatus {
    pub mode: GatewayMode,
    pub onion_hostname: Option<String>,
    pub bootstrap_expires_unix: Option<i64>,
    pub routes: Vec<Route>,
    pub tor: ComponentState,
    pub caddy: ComponentState,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AdminResponse {
    Ok,
    Status {
        status: GatewayStatus,
    },
    ClientEnrolled {
        onion_hostname: String,
        credential: SensitiveString,
    },
    BootstrapOpened {
        url: String,
        expires_unix: i64,
    },
    Error {
        code: String,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_debug_is_redacted() {
        let secret = SensitiveString::new("correct horse battery staple");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("correct"));
        assert!(debug.contains("REDACTED"));
    }
}
