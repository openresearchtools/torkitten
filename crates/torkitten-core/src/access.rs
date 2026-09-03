use serde::{Deserialize, Serialize};

use crate::{DeviceId, GuestId, SiteId, ValidationError};

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
}
