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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RouteId(String);

impl RouteId {
    /// Constructs a validated route identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidRouteId`] when the identifier is not
    /// safe to use in configuration, filenames, and logs.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_route_id(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RouteId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RouteId {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

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
pub enum RouteTarget {
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

impl RouteTarget {
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
pub struct Route {
    pub id: RouteId,
    pub display_name: String,
    pub virtual_port: u16,
    pub target: RouteTarget,
}

impl Route {
    /// Validates all fields of one published route.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identifier, display name, reserved
    /// virtual port, or unsafe target.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_route_id(self.id.as_str())?;
        validate_display_name(&self.display_name)?;
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
pub struct GatewayConfig {
    #[serde(default = "current_schema")]
    pub schema_version: u32,
    #[serde(default)]
    pub routes: Vec<Route>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            routes: Vec::new(),
        }
    }
}

impl GatewayConfig {
    /// Validates a complete configuration and its cross-route invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schemas, invalid routes, duplicate
    /// route identifiers, or duplicate virtual ports.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchema(self.schema_version));
        }

        let mut ids = HashSet::with_capacity(self.routes.len());
        let mut ports = HashSet::with_capacity(self.routes.len());
        for route in &self.routes {
            route.validate()?;
            if !ids.insert(route.id.clone()) {
                return Err(ValidationError::DuplicateRouteId(route.id.clone()));
            }
            if !ports.insert(route.virtual_port) {
                return Err(ValidationError::DuplicateVirtualPort(route.virtual_port));
            }
        }
        Ok(())
    }
}

const fn current_schema() -> u32 {
    CONFIG_SCHEMA_VERSION
}

fn validate_route_id(value: &str) -> Result<(), ValidationError> {
    let valid_length = (1..=64).contains(&value.len());
    let valid_edges = !value.starts_with('-') && !value.ends_with('-');
    let valid_characters = value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid_length && valid_edges && valid_characters {
        Ok(())
    } else {
        Err(ValidationError::InvalidRouteId(value.to_owned()))
    }
}

fn validate_display_name(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        Err(ValidationError::InvalidDisplayName)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ValidationError {
    #[error("unsupported configuration schema {0}")]
    UnsupportedSchema(u32),
    #[error("route id must be 1-64 lowercase ASCII letters, digits, or interior hyphens: {0}")]
    InvalidRouteId(String),
    #[error("route display name must be 1-128 characters without control characters")]
    InvalidDisplayName,
    #[error("virtual port cannot be zero")]
    ZeroVirtualPort,
    #[error("virtual port {0} is reserved by Torkitten")]
    ReservedVirtualPort(u16),
    #[error("duplicate route id: {0}")]
    DuplicateRouteId(RouteId),
    #[error("duplicate virtual port: {0}")]
    DuplicateVirtualPort(u16),
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

    fn route(id: &str, virtual_port: u16) -> Route {
        Route {
            id: RouteId::new(id).unwrap(),
            display_name: "Test application".to_owned(),
            virtual_port,
            target: RouteTarget::Tcp {
                address: "127.0.0.1".parse().unwrap(),
                port: 3000,
                transport: Transport::Http,
            },
        }
    }

    #[test]
    fn accepts_loopback_route() {
        let config = GatewayConfig {
            routes: vec![route("test-app", 8443)],
            ..GatewayConfig::default()
        };
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn rejects_non_loopback_target() {
        let mut candidate = route("bad-target", 8443);
        candidate.target = RouteTarget::Tcp {
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
    fn rejects_reserved_and_duplicate_ports() {
        assert_eq!(
            route("reserved", PORTAL_VIRTUAL_PORT).validate(),
            Err(ValidationError::ReservedVirtualPort(PORTAL_VIRTUAL_PORT))
        );

        let config = GatewayConfig {
            routes: vec![route("one", 8443), route("two", 8443)],
            ..GatewayConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(ValidationError::DuplicateVirtualPort(8443))
        );
    }

    #[test]
    fn rejects_unsafe_unix_path() {
        let target = RouteTarget::Unix {
            path: PathBuf::from("/run/torkitten/../private.sock"),
            transport: Transport::Http,
        };
        assert!(matches!(
            target.validate(),
            Err(ValidationError::UnixPathTraversesParent(_))
        ));
    }
}
