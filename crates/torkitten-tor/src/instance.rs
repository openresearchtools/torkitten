use std::{
    ffi::OsStr,
    fmt::Write as FmtWrite,
    fs::{self, File, OpenOptions},
    io::Write as IoWrite,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use getrandom::fill;
use thiserror::Error;
use torkitten_core::GatewayConfig;

use crate::{
    ClientKeyPair, ClientName,
    client_auth::{ClientAuthError, validate_onion_hostname},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TorPaths {
    pub binary: PathBuf,
    pub state_directory: PathBuf,
    pub runtime_directory: PathBuf,
}

impl TorPaths {
    #[must_use]
    pub fn new(
        binary: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
        runtime_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            binary: binary.into(),
            state_directory: state_directory.into(),
            runtime_directory: runtime_directory.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TorInstance {
    paths: TorPaths,
}

impl TorInstance {
    #[must_use]
    pub fn new(paths: TorPaths) -> Self {
        Self { paths }
    }

    #[must_use]
    pub fn paths(&self) -> &TorPaths {
        &self.paths
    }

    #[must_use]
    pub fn torrc_path(&self) -> PathBuf {
        self.paths.state_directory.join("torrc")
    }

    #[must_use]
    pub fn onion_directory(&self) -> PathBuf {
        self.paths.state_directory.join("onion")
    }

    #[must_use]
    pub fn control_socket(&self) -> PathBuf {
        self.paths.runtime_directory.join("control.sock")
    }

    #[must_use]
    pub fn bootstrap_socket(&self) -> PathBuf {
        self.paths.runtime_directory.join("bootstrap.sock")
    }

    #[must_use]
    pub fn caddy_socket(&self, virtual_port: u16) -> PathBuf {
        self.paths
            .runtime_directory
            .join(format!("caddy-{virtual_port}.sock"))
    }

    /// Creates private instance directories and atomically writes a complete
    /// configuration for this dedicated Tor process.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid routes, non-UTF-8 or newline-containing
    /// paths, randomness failures, or filesystem failures.
    pub fn prepare(&self, config: &GatewayConfig) -> Result<(), TorError> {
        config.validate()?;
        ensure_private_directory(&self.paths.state_directory)?;
        ensure_private_directory(&self.paths.runtime_directory)?;
        ensure_private_directory(&self.onion_directory())?;
        ensure_private_directory(&self.onion_directory().join("authorized_clients"))?;
        let rendered = self.render_torrc(config)?;
        atomic_write(&self.torrc_path(), rendered.as_bytes(), 0o600)
    }

    /// Installs one authorized client's public X25519 key.
    ///
    /// # Errors
    ///
    /// Returns an error if private directories cannot be created or the
    /// authorization file cannot be atomically written.
    pub fn authorize_client(
        &self,
        name: &ClientName,
        keys: &ClientKeyPair,
    ) -> Result<(), TorError> {
        let directory = self.onion_directory().join("authorized_clients");
        ensure_private_directory(&directory)?;
        atomic_write(
            &directory.join(format!("{}.auth", name.as_str())),
            keys.server_authorization().as_bytes(),
            0o600,
        )
    }

    /// Removes an authorized client, returning whether its file existed.
    ///
    /// # Errors
    ///
    /// Returns an error when the authorization file cannot be inspected or
    /// removed.
    pub fn revoke_client(&self, name: &ClientName) -> Result<bool, TorError> {
        let path = self
            .onion_directory()
            .join("authorized_clients")
            .join(format!("{}.auth", name.as_str()));
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Reads and validates the persistent v3 onion hostname created by Tor.
    ///
    /// # Errors
    ///
    /// Returns an error when the hostname file is unavailable or malformed.
    pub fn onion_hostname(&self) -> Result<String, TorError> {
        let hostname = fs::read_to_string(self.onion_directory().join("hostname"))?;
        let hostname = hostname.trim();
        validate_onion_hostname(hostname)?;
        Ok(format!("{}.onion", hostname.trim_end_matches(".onion")))
    }

    /// Returns a command that launches only the dedicated Torkitten Tor
    /// configuration, with no system or user defaults.
    #[must_use]
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.paths.binary);
        command
            .arg("--defaults-torrc")
            .arg("/dev/null")
            .arg("-f")
            .arg(self.torrc_path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Returns a command that asks the bundled Tor binary to validate the
    /// dedicated configuration without joining the Tor network.
    #[must_use]
    pub fn verify_command(&self) -> Command {
        let mut command = self.command();
        command.arg("--verify-config");
        command
    }

    fn render_torrc(&self, config: &GatewayConfig) -> Result<String, TorError> {
        let data_directory = self.paths.state_directory.join("data");
        ensure_private_directory(&data_directory)?;
        let mut output = String::new();
        setting(&mut output, "DataDirectory", &data_directory)?;
        setting(
            &mut output,
            "CookieAuthFile",
            &self.paths.state_directory.join("control.authcookie"),
        )?;
        setting(&mut output, "ControlSocket", &self.control_socket())?;
        setting(
            &mut output,
            "PidFile",
            &self.paths.runtime_directory.join("tor.pid"),
        )?;
        output.push_str(
            "CookieAuthentication 1\n\
             CookieAuthFileGroupReadable 0\n\
             ControlPort 0\n\
             SocksPort 0\n\
             HTTPTunnelPort 0\n\
             DNSPort 0\n\
             TransPort 0\n\
             NATDPort 0\n\
             ORPort 0\n\
             DirPort 0\n\
             ExtORPort 0\n\
             ClientOnly 1\n\
             ExitRelay 0\n\
             BridgeRelay 0\n\
             PublishServerDescriptor 0\n\
             RunAsDaemon 0\n\
             SafeLogging 1\n\
             Sandbox 1\n\
             Log notice stdout\n",
        );
        setting(&mut output, "HiddenServiceDir", &self.onion_directory())?;
        output.push_str(
            "HiddenServiceVersion 3\n\
             HiddenServiceAllowUnknownPorts 0\n\
             HiddenServiceNumIntroductionPoints 3\n",
        );
        hidden_service_port(&mut output, 80, &self.bootstrap_socket())?;
        hidden_service_port(&mut output, 443, &self.caddy_socket(443))?;
        for route in &config.routes {
            hidden_service_port(
                &mut output,
                route.virtual_port,
                &self.caddy_socket(route.virtual_port),
            )?;
        }
        Ok(output)
    }
}

fn setting(output: &mut String, name: &str, value: &Path) -> Result<(), TorError> {
    let value = quoted_path(value)?;
    output.push_str(name);
    output.push(' ');
    output.push_str(&value);
    output.push('\n');
    Ok(())
}

fn hidden_service_port(
    output: &mut String,
    virtual_port: u16,
    socket: &Path,
) -> Result<(), TorError> {
    let target = format!("unix:{}", quoted_path(socket)?);
    writeln!(output, "HiddenServicePort {virtual_port} {target}")
        .expect("writing to a String cannot fail");
    Ok(())
}

fn quoted_path(path: &Path) -> Result<String, TorError> {
    quote(path_text(path)?)
}

fn path_text(path: &Path) -> Result<&str, TorError> {
    path.to_str()
        .ok_or_else(|| TorError::InvalidPath(path.to_path_buf()))
}

fn quote(value: &str) -> Result<String, TorError> {
    if value.contains(['\n', '\r', '\0']) {
        return Err(TorError::UnsafeConfigValue(value.to_owned()));
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn ensure_private_directory(path: &Path) -> Result<(), TorError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(TorError::UnsafeDirectory(path.to_path_buf()));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<(), TorError> {
    let parent = path
        .parent()
        .ok_or_else(|| TorError::InvalidPath(path.to_path_buf()))?;
    ensure_private_directory(parent)?;
    let (temporary_path, mut temporary) = create_temporary(parent, path.file_name())?;
    temporary.write_all(contents)?;
    temporary.sync_all()?;
    fs::set_permissions(&temporary_path, fs::Permissions::from_mode(mode))?;
    fs::rename(&temporary_path, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn create_temporary(parent: &Path, filename: Option<&OsStr>) -> Result<(PathBuf, File), TorError> {
    let filename = filename.and_then(OsStr::to_str).unwrap_or("file");
    for _ in 0..32 {
        let mut random = [0_u8; 8];
        fill(&mut random).map_err(TorError::Random)?;
        let suffix = u64::from_ne_bytes(random);
        let path = parent.join(format!(".{filename}-{suffix:016x}.tmp"));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(TorError::TemporaryNameExhausted)
}

#[derive(Debug, Error)]
pub enum TorError {
    #[error("invalid filesystem path: {path}", path = .0.display())]
    InvalidPath(PathBuf),
    #[error("path is not a private directory: {path}", path = .0.display())]
    UnsafeDirectory(PathBuf),
    #[error("unsafe Tor configuration value")]
    UnsafeConfigValue(String),
    #[error("could not allocate a temporary filename")]
    TemporaryNameExhausted,
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
    #[error(transparent)]
    ClientAuth(#[from] ClientAuthError),
    #[error(transparent)]
    Validation(#[from] torkitten_core::ValidationError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use torkitten_core::{Route, RouteId, RouteTarget, Transport};

    use super::*;

    fn instance(temporary: &tempfile::TempDir) -> TorInstance {
        TorInstance::new(TorPaths::new(
            "/opt/torkitten/libexec/tor",
            temporary.path().join("state/tor"),
            temporary.path().join("run/tor"),
        ))
    }

    fn config() -> GatewayConfig {
        GatewayConfig {
            routes: vec![Route {
                id: RouteId::new("example").unwrap(),
                display_name: "Example".to_owned(),
                virtual_port: 8443,
                target: RouteTarget::Tcp {
                    address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: 3000,
                    transport: Transport::Http,
                },
            }],
            ..GatewayConfig::default()
        }
    }

    #[test]
    fn dedicated_configuration_disables_client_and_relay_listeners() {
        let temporary = tempfile::tempdir().unwrap();
        let instance = instance(&temporary);
        instance.prepare(&config()).unwrap();
        let torrc = fs::read_to_string(instance.torrc_path()).unwrap();
        for disabled in [
            "SocksPort 0",
            "HTTPTunnelPort 0",
            "DNSPort 0",
            "TransPort 0",
            "NATDPort 0",
            "ORPort 0",
            "DirPort 0",
            "ExtORPort 0",
        ] {
            assert!(torrc.contains(disabled), "missing {disabled}");
        }
        assert!(torrc.contains("ClientOnly 1"));
        assert!(torrc.contains("HiddenServicePort 80"));
        assert!(torrc.contains("HiddenServicePort 443"));
        assert!(torrc.contains("HiddenServicePort 8443"));
        assert!(!torrc.contains("0.0.0.0"));
    }

    #[test]
    fn installs_and_revokes_client_public_key() {
        let temporary = tempfile::tempdir().unwrap();
        let instance = instance(&temporary);
        let name = ClientName::new("phone").unwrap();
        let keys = ClientKeyPair::generate().unwrap();
        instance.authorize_client(&name, &keys).unwrap();
        let path = instance
            .onion_directory()
            .join("authorized_clients/phone.auth");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            keys.server_authorization()
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(instance.revoke_client(&name).unwrap());
        assert!(!instance.revoke_client(&name).unwrap());
    }

    #[test]
    #[ignore = "requires the bundled Tor binary and its Ubuntu 24.04 runtime libraries"]
    fn bundled_tor_accepts_generated_configuration() {
        let binary = std::env::var_os("TORKITTEN_TOR_BINARY")
            .expect("TORKITTEN_TOR_BINARY must identify the bundled Tor binary");
        let temporary = tempfile::tempdir().unwrap();
        let instance = TorInstance::new(TorPaths::new(
            binary,
            temporary.path().join("state/tor"),
            temporary.path().join("run/tor"),
        ));
        instance.prepare(&config()).unwrap();
        let output = instance.verify_command().output().unwrap();
        assert!(
            output.status.success(),
            "Tor rejected the generated configuration:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
