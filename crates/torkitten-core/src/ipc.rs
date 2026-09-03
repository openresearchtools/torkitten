use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Device, DeviceId, Guest, GuestId, Mapping, MappingId, RemoteAccessPolicy, Site, SiteId,
};

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
    GenerateSiteCandidate,
    Initialize {
        password: SensitiveString,
    },
    AuthenticateAdministrator {
        password: SensitiveString,
    },
    ValidateAdministratorSession {
        session: SensitiveString,
    },
    AuthorizeAdministratorMutation {
        session: SensitiveString,
        csrf: SensitiveString,
    },
    LogoutAdministrator {
        session: SensitiveString,
        csrf: SensitiveString,
    },
    CreateGeneratedSite {
        site: Site,
        candidate_id: SensitiveString,
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
        candidate_id: SensitiveString,
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
    PutGuest {
        guest: Guest,
    },
    RemoveGuest {
        site_id: SiteId,
        guest_id: GuestId,
    },
    SetGuestPermissions {
        site_id: SiteId,
        guest_id: GuestId,
        mapping_ids: Vec<MappingId>,
    },
    EnrollDevice {
        guest: Guest,
        device: Device,
        mapping_ids: Vec<MappingId>,
    },
    RevokeDevice {
        site_id: SiteId,
        guest_id: GuestId,
        device_id: DeviceId,
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
    SetRemoteAccessPolicy {
        policy: RemoteAccessPolicy,
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
    pub guests: Vec<GuestAccessStatus>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuestAccessStatus {
    pub guest: Guest,
    pub mapping_ids: Vec<MappingId>,
    pub devices: Vec<Device>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayStatus {
    pub mode: GatewayMode,
    pub sites: Vec<SiteStatus>,
    pub tor: ComponentState,
    pub caddy: ComponentState,
    pub resume_after_boot: bool,
    pub remote_access_policy: RemoteAccessPolicy,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AdminResponse {
    Ok,
    SiteCandidate {
        candidate_id: SensitiveString,
        onion_hostname: String,
        expires_unix: i64,
    },
    AdministratorAuthenticated {
        session: SensitiveString,
        csrf: SensitiveString,
        expires_unix: i64,
    },
    AdministratorAuthorized {
        fresh: bool,
    },
    Status {
        status: GatewayStatus,
    },
    DeviceEnrolled {
        site_id: SiteId,
        guest_id: GuestId,
        device_id: DeviceId,
        onion_hostname: String,
        credential: SensitiveString,
        enrollment_url: SensitiveString,
        enrollment_expires_unix: i64,
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum RemoteCommand {
    PublishedSites,
    PortalContext {
        site_id: SiteId,
        session: Option<SensitiveString>,
    },
    AuthorizeMapping {
        site_id: SiteId,
        mapping_id: MappingId,
        session: SensitiveString,
    },
    EnrollmentDetails {
        site_id: SiteId,
        token: SensitiveString,
    },
    CompletePasswordEnrollment {
        site_id: SiteId,
        token: SensitiveString,
        password: SensitiveString,
        totp_code: SensitiveString,
    },
    StartPasskeyEnrollment {
        site_id: SiteId,
        token: SensitiveString,
    },
    FinishPasskeyEnrollment {
        site_id: SiteId,
        token: SensitiveString,
        ceremony: SensitiveString,
        credential: SensitiveString,
    },
    AuthenticateGuest {
        site_id: SiteId,
        guest_id: GuestId,
        password: SensitiveString,
        second_factor: GuestSecondFactor,
    },
    StartPasskeyAuthentication {
        site_id: SiteId,
        guest_id: GuestId,
    },
    FinishPasskeyAuthentication {
        site_id: SiteId,
        guest_id: GuestId,
        ceremony: SensitiveString,
        credential: SensitiveString,
    },
    LogoutGuest {
        site_id: SiteId,
        session: SensitiveString,
    },
    LogoutOtherGuestSessions {
        site_id: SiteId,
        session: SensitiveString,
    },
    BootstrapCertificate {
        site_id: SiteId,
        path: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum GuestSecondFactor {
    Totp(SensitiveString),
    RecoveryCode(SensitiveString),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedSite {
    pub site_id: SiteId,
    pub onion_hostname: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortalMapping {
    pub id: MappingId,
    pub display_name: String,
    pub virtual_port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortalContext {
    pub site_id: SiteId,
    pub display_name: String,
    pub onion_hostname: String,
    pub guest_id: Option<GuestId>,
    pub guest_display_name: Option<String>,
    pub mappings: Vec<PortalMapping>,
    pub remote_access_policy: RemoteAccessPolicy,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum RemoteResponse {
    PublishedSites {
        sites: Vec<PublishedSite>,
    },
    PortalContext {
        context: PortalContext,
    },
    MappingAuthorized {
        guest_id: GuestId,
    },
    EnrollmentDetails {
        site_id: SiteId,
        guest_id: GuestId,
        guest_display_name: String,
        device_id: DeviceId,
        device_display_name: String,
        expires_unix: i64,
        totp_secret: Option<SensitiveString>,
        totp_uri: Option<SensitiveString>,
        remote_access_policy: RemoteAccessPolicy,
    },
    GuestAuthenticated {
        session: SensitiveString,
        expires_unix: i64,
        max_age_seconds: u64,
    },
    EnrollmentCompleted {
        session: SensitiveString,
        expires_unix: i64,
        max_age_seconds: u64,
        recovery_codes: Vec<SensitiveString>,
    },
    PasskeyRegistrationStarted {
        ceremony: SensitiveString,
        public_key: serde_json::Value,
    },
    PasskeyAuthenticationStarted {
        ceremony: SensitiveString,
        public_key: serde_json::Value,
    },
    LoggedOut,
    OtherSessionsRevoked {
        count: usize,
    },
    BootstrapCertificate {
        certificate_pem: String,
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

    #[test]
    fn remote_protocol_has_no_administration_commands() {
        let command = RemoteCommand::AuthorizeMapping {
            site_id: SiteId::new("personal").unwrap(),
            mapping_id: MappingId::new("photos").unwrap(),
            session: SensitiveString::new("secret"),
        };
        let encoded = serde_json::to_value(command).unwrap();
        assert_eq!(encoded["command"], "authorize_mapping");
        assert!(encoded.get("component").is_none());
        assert!(encoded.get("action").is_none());
    }

    #[test]
    fn remote_authentication_factors_are_redacted() {
        let command = RemoteCommand::AuthenticateGuest {
            site_id: SiteId::new("personal").unwrap(),
            guest_id: GuestId::new("family").unwrap(),
            password: SensitiveString::new("password secret"),
            second_factor: GuestSecondFactor::Totp(SensitiveString::new("123456")),
        };
        let debug = format!("{command:?}");
        assert!(!debug.contains("password secret"));
        assert!(!debug.contains("123456"));
    }

    #[test]
    fn passkey_ceremony_and_credential_are_redacted() {
        let command = RemoteCommand::FinishPasskeyAuthentication {
            site_id: SiteId::new("personal").unwrap(),
            guest_id: GuestId::new("family").unwrap(),
            ceremony: SensitiveString::new("ceremony secret"),
            credential: SensitiveString::new("credential assertion secret"),
        };
        let debug = format!("{command:?}");
        assert!(!debug.contains("ceremony secret"));
        assert!(!debug.contains("credential assertion secret"));
        assert_eq!(debug.matches("[REDACTED]").count(), 2);
    }
}
