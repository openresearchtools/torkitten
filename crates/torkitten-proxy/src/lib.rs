#![forbid(unsafe_code)]

mod config;
mod instance;

pub use config::{CaddyPaths, ProxyConfig, ProxySite};
pub use instance::{CaddyError, CaddyInstance};
