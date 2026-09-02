#![forbid(unsafe_code)]

mod config;
mod ipc;

pub use config::{GatewayConfig, Route, RouteId, RouteTarget, Transport, ValidationError};
pub use ipc::{
    AdminCommand, AdminResponse, ComponentState, GatewayMode, GatewayStatus, SensitiveString,
};

pub const CONFIG_SCHEMA_VERSION: u32 = 1;
pub const BOOTSTRAP_VIRTUAL_PORT: u16 = 80;
pub const PORTAL_VIRTUAL_PORT: u16 = 443;
