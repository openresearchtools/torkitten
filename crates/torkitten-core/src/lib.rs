#![forbid(unsafe_code)]

mod config;
mod ipc;

pub use config::{
    GatewayConfig, Mapping, MappingId, MappingTarget, Site, SiteId, Transport, ValidationError,
};
pub use ipc::{
    AdminCommand, AdminResponse, ComponentAction, ComponentState, GatewayMode, GatewayStatus,
    ManagedComponent, SensitiveString, SiteStatus,
};

pub const CONFIG_SCHEMA_VERSION: u32 = 2;
pub const BOOTSTRAP_VIRTUAL_PORT: u16 = 80;
pub const PORTAL_VIRTUAL_PORT: u16 = 443;
