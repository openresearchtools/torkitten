use serde::{Deserialize, Serialize};

use crate::{DeviceId, GuestId, SiteId, ValidationError};

pub const DEFAULT_REMOTE_SESSION_DAYS: u16 = 30;
pub const MINIMUM_REMOTE_SESSION_DAYS: u16 = 1;
pub const MAXIMUM_REMOTE_SESSION_DAYS: u16 = 365;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteAccessPolicy {
    pub passkeys_enabled: bool,
    pub password_totp_enabled: bool,
    pub recovery_codes_enabled: bool,
    pub session_days: u16,
}

impl RemoteAccessPolicy {
    /// Validates that at least one login method remains available and that the
    /// session lifetime is bounded.
    ///
    /// # Errors
    ///
    /// Returns an error for a lockout policy, a recovery-code policy without
    /// password authentication, or an out-of-range session lifetime.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if !self.passkeys_enabled && !self.password_totp_enabled {
            return Err(ValidationError::NoRemoteLoginMethod);
        }
        if self.recovery_codes_enabled && !self.password_totp_enabled {
            return Err(ValidationError::RecoveryRequiresPasswordTotp);
        }
        if !(MINIMUM_REMOTE_SESSION_DAYS..=MAXIMUM_REMOTE_SESSION_DAYS).contains(&self.session_days)
        {
            return Err(ValidationError::InvalidRemoteSessionDays(self.session_days));
        }
        Ok(())
    }

    #[must_use]
    pub fn session_seconds(self) -> i64 {
        i64::from(self.session_days) * 86_400
    }
}

impl Default for RemoteAccessPolicy {
    fn default() -> Self {
        Self {
            passkeys_enabled: true,
            password_totp_enabled: true,
            recovery_codes_enabled: true,
            session_days: DEFAULT_REMOTE_SESSION_DAYS,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccountOwner {
    Administrator,
    Guest { site_id: SiteId, guest_id: GuestId },
}

impl AccountOwner {
    /// Validates all scoped identifiers in an authentication owner.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid site or guest identifier.
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Administrator => Ok(()),
            Self::Guest { site_id, guest_id } => {
                SiteId::new(site_id.as_str())?;
                GuestId::new(guest_id.as_str())?;
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Guest {
    pub site_id: SiteId,
    pub id: GuestId,
    pub display_name: String,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

impl Guest {
    /// Validates one site-scoped guest record.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identifier or display name.
    pub fn validate(&self) -> Result<(), ValidationError> {
        SiteId::new(self.site_id.as_str())?;
        GuestId::new(self.id.as_str())?;
        validate_display_name(&self.display_name, AccessNameKind::Guest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub site_id: SiteId,
    pub guest_id: GuestId,
    pub id: DeviceId,
    pub display_name: String,
    pub tor_client_name: String,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

impl Device {
    /// Validates one device and its Tor client-authorization filename stem.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers, display names, or Tor client
    /// names.
    pub fn validate(&self) -> Result<(), ValidationError> {
        SiteId::new(self.site_id.as_str())?;
        GuestId::new(self.guest_id.as_str())?;
        DeviceId::new(self.id.as_str())?;
        validate_display_name(&self.display_name, AccessNameKind::Device)?;
        let valid_client_name = (1..=16).contains(&self.tor_client_name.len())
            && self
                .tor_client_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'_'));
        if valid_client_name {
            Ok(())
        } else {
            Err(ValidationError::InvalidTorClientName(
                self.tor_client_name.clone(),
            ))
        }
    }
}

#[derive(Clone, Copy)]
enum AccessNameKind {
    Guest,
    Device,
}

fn validate_display_name(value: &str, kind: AccessNameKind) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        match kind {
            AccessNameKind::Guest => Err(ValidationError::InvalidGuestDisplayName),
            AccessNameKind::Device => Err(ValidationError::InvalidDeviceDisplayName),
        }
    } else {
        Ok(())
    }
}

const fn enabled_by_default() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_site_scoped_guests_and_devices() {
        let site_id = SiteId::new("alpha").unwrap();
        let guest_id = GuestId::new("family").unwrap();
        let guest = Guest {
            site_id: site_id.clone(),
            id: guest_id.clone(),
            display_name: "Family".to_owned(),
            enabled: true,
        };
        let device = Device {
            site_id,
            guest_id,
            id: DeviceId::new("phone").unwrap(),
            display_name: "Phone".to_owned(),
            tor_client_name: "phone_1".to_owned(),
            enabled: true,
        };
        assert!(guest.validate().is_ok());
        assert!(device.validate().is_ok());
        assert!(
            AccountOwner::Guest {
                site_id: guest.site_id,
                guest_id: guest.id,
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn rejects_unsafe_access_names() {
        let site_id = SiteId::new("alpha").unwrap();
        let guest_id = GuestId::new("family").unwrap();
        let guest = Guest {
            site_id: site_id.clone(),
            id: guest_id.clone(),
            display_name: "bad\nname".to_owned(),
            enabled: true,
        };
        let device = Device {
            site_id,
            guest_id,
            id: DeviceId::new("phone").unwrap(),
            display_name: "Phone".to_owned(),
            tor_client_name: "contains space".to_owned(),
            enabled: true,
        };
        assert!(matches!(
            guest.validate(),
            Err(ValidationError::InvalidGuestDisplayName)
        ));
        assert!(matches!(
            device.validate(),
            Err(ValidationError::InvalidTorClientName(_))
        ));
    }

    #[test]
    fn remote_policy_prevents_lockout_and_bounds_long_lived_sessions() {
        assert!(RemoteAccessPolicy::default().validate().is_ok());
        assert!(matches!(
            RemoteAccessPolicy {
                passkeys_enabled: false,
                password_totp_enabled: false,
                recovery_codes_enabled: false,
                session_days: 30,
            }
            .validate(),
            Err(ValidationError::NoRemoteLoginMethod)
        ));
        assert!(matches!(
            RemoteAccessPolicy {
                passkeys_enabled: true,
                password_totp_enabled: false,
                recovery_codes_enabled: true,
                session_days: 30,
            }
            .validate(),
            Err(ValidationError::RecoveryRequiresPasswordTotp)
        ));
        assert!(matches!(
            RemoteAccessPolicy {
                session_days: 0,
                ..RemoteAccessPolicy::default()
            }
            .validate(),
            Err(ValidationError::InvalidRemoteSessionDays(0))
        ));
    }
}
