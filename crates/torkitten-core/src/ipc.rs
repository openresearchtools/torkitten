use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Mapping, MappingId, Site, SiteId};

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

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum AdminCommand {
    Status,
    Initialize {
        password: SensitiveString,
    },
    CreateSite {
        site: Site,
    },
    RenameSite {
        site_id: SiteId,
        display_name: String,
    },
    RotateSite {
        site_id: SiteId,
    },
    RemoveSite {
        site_id: SiteId,
    },
    SetSiteEnabled {
        site_id: SiteId,
        enabled: bool,
    },
    RestartSite {
        site_id: SiteId,
    },
    StopSite {
        site_id: SiteId,
    },
    PutMapping {
        site_id: SiteId,
        mapping: Mapping,
    },
    TestMapping {
        site_id: SiteId,
        mapping: Mapping,
    },
    RemoveMapping {
        site_id: SiteId,
        mapping_id: MappingId,
    },
    SetMappingEnabled {
        site_id: SiteId,
        mapping_id: MappingId,
        enabled: bool,
    },
    EnrollClient {
        site_id: SiteId,
        name: String,
    },
    RevokeClient {
        site_id: SiteId,
        name: String,
    },
    OpenCertificateBootstrap {
        site_id: SiteId,
        seconds: u32,
    },
    CloseCertificateBootstrap {
        site_id: SiteId,
    },
    ControlComponent {
        component: ManagedComponent,
        action: ComponentAction,
    },
    SetResumeAfterBoot {
        enabled: bool,
    },
    EmergencyDisable,
    ClearEmergencyDisable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedComponent {
    Tor,
    Caddy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentAction {
    Start,
    Stop,
    Restart,
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
pub struct SiteStatus {
    pub site: Site,
    pub onion_hostname: Option<String>,
    pub bootstrap_expires_unix: Option<i64>,
    pub publication: ComponentState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayStatus {
    pub mode: GatewayMode,
    pub sites: Vec<SiteStatus>,
    pub tor: ComponentState,
    pub caddy: ComponentState,
    pub resume_after_boot: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AdminResponse {
    Ok,
    Status {
        status: GatewayStatus,
    },
    ClientEnrolled {
        site_id: SiteId,
        onion_hostname: String,
        credential: SensitiveString,
    },
    BootstrapOpened {
        site_id: SiteId,
        url: String,
        expires_unix: i64,
    },
    MappingTested {
        site_id: SiteId,
        mapping_id: MappingId,
        reachable: bool,
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

    #[test]
    fn site_scoped_commands_include_the_site_identifier() {
        let command = AdminCommand::SetMappingEnabled {
            site_id: SiteId::new("personal").unwrap(),
            mapping_id: MappingId::new("photos").unwrap(),
            enabled: false,
        };
        let encoded = serde_json::to_value(command).unwrap();
        assert_eq!(encoded["command"], "set_mapping_enabled");
        assert_eq!(encoded["site_id"], "personal");
        assert_eq!(encoded["mapping_id"], "photos");
    }
}
