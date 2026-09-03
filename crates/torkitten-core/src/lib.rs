#![forbid(unsafe_code)]

mod access;
mod config;
mod ipc;

pub use access::{
    AccountOwner, DEFAULT_REMOTE_SESSION_DAYS, Device, Guest, MAXIMUM_REMOTE_SESSION_DAYS,
    MINIMUM_REMOTE_SESSION_DAYS, RemoteAccessPolicy,
};
pub use config::{
    DeviceId, GatewayConfig, GuestId, Mapping, MappingId, MappingTarget, Site, SiteId, Transport,
    ValidationError,
};
pub use ipc::{
    AdminCommand, AdminResponse, ComponentAction, ComponentState, GatewayMode, GatewayStatus,
    GuestAccessStatus, GuestSecondFactor, ManagedComponent, PortalContext, PortalMapping,
    PublishedSite, RemoteCommand, RemoteResponse, SensitiveString, SiteStatus,
};

pub const CONFIG_SCHEMA_VERSION: u32 = 2;
pub const BOOTSTRAP_VIRTUAL_PORT: u16 = 80;
pub const PORTAL_VIRTUAL_PORT: u16 = 443;
