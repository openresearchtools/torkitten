use std::{
    collections::HashSet,
    fmt,
    net::IpAddr,
    path::{Component, PathBuf},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{BOOTSTRAP_VIRTUAL_PORT, CONFIG_SCHEMA_VERSION, PORTAL_VIRTUAL_PORT};

macro_rules! validated_id {
    ($name:ident, $validator:ident, $error:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Constructs a validated identifier.
            ///
            /// # Errors
            ///
            #[doc = concat!(
                        "Returns [`ValidationError::",
                        stringify!($error),
                        "`] when the identifier is unsafe for persistent keys, paths, or logs."
                    )]
            pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                $validator(&value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ValidationError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

validated_id!(SiteId, validate_site_id, InvalidSiteId);
validated_id!(MappingId, validate_mapping_id, InvalidMappingId);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Http,
    Https,
    H2c,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MappingTarget {
    Tcp {
        address: IpAddr,
        port: u16,
        #[serde(default)]
        transport: Transport,
    },
    Unix {
        path: PathBuf,
        #[serde(default)]
        transport: Transport,
    },
}

impl MappingTarget {
    /// Validates that a target is restricted to a local transport.
    ///
    /// # Errors
    ///
    /// Returns an error for non-loopback TCP addresses, zero ports, relative
    /// Unix paths, or paths containing parent traversal.
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Tcp { address, port, .. } => {
                if !address.is_loopback() {
                    return Err(ValidationError::TargetNotLoopback(*address));
                }
                if *port == 0 {
                    return Err(ValidationError::ZeroTargetPort);
                }
            }
            Self::Unix { path, .. } => {
                if !path.is_absolute() {
                    return Err(ValidationError::UnixPathNotAbsolute(path.clone()));
                }
                if path.components().any(|part| part == Component::ParentDir) {
                    return Err(ValidationError::UnixPathTraversesParent(path.clone()));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Mapping {
    pub id: MappingId,
    pub display_name: String,
    pub virtual_port: u16,
    pub target: MappingTarget,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

impl Mapping {
    /// Validates all fields of one application mapping.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identifier, display name, reserved
    /// virtual port, or unsafe target.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_mapping_id(self.id.as_str())?;
        validate_display_name(&self.display_name, DisplayNameKind::Mapping)?;
        if self.virtual_port == 0 {
            return Err(ValidationError::ZeroVirtualPort);
        }
        if matches!(
            self.virtual_port,
            BOOTSTRAP_VIRTUAL_PORT | PORTAL_VIRTUAL_PORT
        ) {
            return Err(ValidationError::ReservedVirtualPort(self.virtual_port));
        }
        self.target.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Site {
    pub id: SiteId,
    pub display_name: String,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default)]
    pub mappings: Vec<Mapping>,
}

impl Site {
    /// Validates one site and every mapping scoped beneath it.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid fields or mapping identifiers and virtual
    /// ports duplicated within this site. Another site may reuse both.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_site_id(self.id.as_str())?;
        validate_display_name(&self.display_name, DisplayNameKind::Site)?;

        let mut ids = HashSet::with_capacity(self.mappings.len());
        let mut ports = HashSet::with_capacity(self.mappings.len());
        for mapping in &self.mappings {
            mapping.validate()?;
            if !ids.insert(mapping.id.clone()) {
                return Err(ValidationError::DuplicateMappingId {
                    site_id: self.id.clone(),
                    mapping_id: mapping.id.clone(),
                });
            }
            if !ports.insert(mapping.virtual_port) {
                return Err(ValidationError::DuplicateVirtualPort {
                    site_id: self.id.clone(),
                    virtual_port: mapping.virtual_port,
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default = "current_schema")]
    pub schema_version: u32,
    #[serde(default)]
    pub sites: Vec<Site>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            sites: Vec::new(),
        }
    }
}

impl GatewayConfig {
    /// Validates the complete multi-site configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schemas, invalid sites or mappings, or
    /// a duplicate site identifier.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchema(self.schema_version));
        }

        let mut ids = HashSet::with_capacity(self.sites.len());
        for site in &self.sites {
            site.validate()?;
            if !ids.insert(site.id.clone()) {
                return Err(ValidationError::DuplicateSiteId(site.id.clone()));
            }
        }
        Ok(())
    }
}

const fn current_schema() -> u32 {
    CONFIG_SCHEMA_VERSION
}

const fn enabled_by_default() -> bool {
    true
}

fn validate_site_id(value: &str) -> Result<(), ValidationError> {
    if valid_identifier(value) {
        Ok(())
    } else {
        Err(ValidationError::InvalidSiteId(value.to_owned()))
    }
}

fn validate_mapping_id(value: &str) -> Result<(), ValidationError> {
    if valid_identifier(value) {
        Ok(())
    } else {
        Err(ValidationError::InvalidMappingId(value.to_owned()))
    }
}

fn valid_identifier(value: &str) -> bool {
    let valid_length = (1..=64).contains(&value.len());
    let valid_edges = !value.starts_with('-') && !value.ends_with('-');
    let valid_characters = value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    valid_length && valid_edges && valid_characters
}

#[derive(Clone, Copy)]
enum DisplayNameKind {
    Site,
    Mapping,
}

fn validate_display_name(value: &str, kind: DisplayNameKind) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        match kind {
            DisplayNameKind::Site => Err(ValidationError::InvalidSiteDisplayName),
            DisplayNameKind::Mapping => Err(ValidationError::InvalidMappingDisplayName),
        }
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ValidationError {
    #[error("unsupported configuration schema {0}")]
    UnsupportedSchema(u32),
    #[error("site id must be 1-64 lowercase ASCII letters, digits, or interior hyphens: {0}")]
    InvalidSiteId(String),
    #[error("mapping id must be 1-64 lowercase ASCII letters, digits, or interior hyphens: {0}")]
    InvalidMappingId(String),
    #[error("site display name must be 1-128 characters without control characters")]
    InvalidSiteDisplayName,
    #[error("mapping display name must be 1-128 characters without control characters")]
    InvalidMappingDisplayName,
    #[error("virtual port cannot be zero")]
    ZeroVirtualPort,
    #[error("virtual port {0} is reserved by Torkitten")]
    ReservedVirtualPort(u16),
    #[error("duplicate site id: {0}")]
    DuplicateSiteId(SiteId),
    #[error("duplicate mapping id {mapping_id} in site {site_id}")]
    DuplicateMappingId {
        site_id: SiteId,
        mapping_id: MappingId,
    },
    #[error("duplicate virtual port {virtual_port} in site {site_id}")]
    DuplicateVirtualPort { site_id: SiteId, virtual_port: u16 },
    #[error("TCP target must be a numeric loopback address, got {0}")]
    TargetNotLoopback(IpAddr),
    #[error("TCP target port cannot be zero")]
    ZeroTargetPort,
    #[error("Unix target must be an absolute path: {path}", path = .0.display())]
    UnixPathNotAbsolute(PathBuf),
    #[error("Unix target cannot contain parent traversal: {path}", path = .0.display())]
    UnixPathTraversesParent(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(id: &str, virtual_port: u16) -> Mapping {
        Mapping {
            id: MappingId::new(id).unwrap(),
            display_name: "Test application".to_owned(),
            virtual_port,
            target: MappingTarget::Tcp {
                address: "127.0.0.1".parse().unwrap(),
                port: 3000,
                transport: Transport::Http,
            },
            enabled: true,
        }
    }

    fn site(id: &str, mappings: Vec<Mapping>) -> Site {
        Site {
            id: SiteId::new(id).unwrap(),
            display_name: format!("Site {id}"),
            enabled: true,
            mappings,
        }
    }

    #[test]
    fn permits_mapping_ids_and_ports_to_be_reused_by_another_site() {
        let config = GatewayConfig {
            sites: vec![
                site("alpha", vec![mapping("app", 8443)]),
                site("beta", vec![mapping("app", 8443)]),
            ],
            ..GatewayConfig::default()
        };
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn rejects_non_loopback_target() {
        let mut candidate = mapping("bad-target", 8443);
        candidate.target = MappingTarget::Tcp {
            address: "192.0.2.1".parse().unwrap(),
            port: 3000,
            transport: Transport::Http,
        };
        assert!(matches!(
            candidate.validate(),
            Err(ValidationError::TargetNotLoopback(_))
        ));
    }

    #[test]
    fn rejects_reserved_and_same_site_duplicate_ports() {
        assert_eq!(
            mapping("reserved", PORTAL_VIRTUAL_PORT).validate(),
            Err(ValidationError::ReservedVirtualPort(PORTAL_VIRTUAL_PORT))
        );

        let candidate = site("alpha", vec![mapping("one", 8443), mapping("two", 8443)]);
        assert_eq!(
            candidate.validate(),
            Err(ValidationError::DuplicateVirtualPort {
                site_id: SiteId::new("alpha").unwrap(),
                virtual_port: 8443,
            })
        );
    }

    #[test]
    fn rejects_same_site_duplicate_mapping_ids() {
        let candidate = site("alpha", vec![mapping("app", 8443), mapping("app", 8444)]);
        assert_eq!(
            candidate.validate(),
            Err(ValidationError::DuplicateMappingId {
                site_id: SiteId::new("alpha").unwrap(),
                mapping_id: MappingId::new("app").unwrap(),
            })
        );
    }

    #[test]
    fn rejects_duplicate_site_ids() {
        let config = GatewayConfig {
            sites: vec![site("alpha", Vec::new()), site("alpha", Vec::new())],
            ..GatewayConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(ValidationError::DuplicateSiteId(
                SiteId::new("alpha").unwrap()
            ))
        );
    }

    #[test]
    fn rejects_unsafe_unix_path() {
        let target = MappingTarget::Unix {
            path: PathBuf::from("/run/torkitten/../private.sock"),
            transport: Transport::Http,
        };
        assert!(matches!(
            target.validate(),
            Err(ValidationError::UnixPathTraversesParent(_))
        ));
    }

    #[test]
    fn old_mapping_documents_default_to_enabled() {
        let document = r#"{
            "id":"app",
            "display_name":"Application",
            "virtual_port":8443,
            "target":{"kind":"tcp","address":"127.0.0.1","port":3000}
        }"#;
        let mapping: Mapping = serde_json::from_str(document).unwrap();
        assert!(mapping.enabled);
    }
}
