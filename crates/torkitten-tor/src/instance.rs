use std::{
    collections::HashSet,
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
use torkitten_core::{GatewayConfig, SiteId};

use crate::{
    ClientKeyPair, ClientName,
    client_auth::{ClientAuthError, validate_onion_hostname},
};

const LEGACY_SITE_ID: &str = "default";

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

/// Owns the one application-controlled Tor process and every site's isolated
/// hidden-service directory.
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
    pub fn site_state_directory(&self, site_id: &SiteId) -> PathBuf {
        self.paths
            .state_directory
            .join("sites")
            .join(site_id.as_str())
    }

    #[must_use]
    pub fn onion_directory(&self, site_id: &SiteId) -> PathBuf {
        self.site_state_directory(site_id).join("onion")
    }

    #[must_use]
    pub fn site_runtime_directory(&self, site_id: &SiteId) -> PathBuf {
        self.paths
            .runtime_directory
            .join("sites")
            .join(site_id.as_str())
    }

    #[must_use]
    pub fn control_socket(&self) -> PathBuf {
        self.paths.runtime_directory.join("control.sock")
    }

    #[must_use]
    pub fn bootstrap_socket(&self, site_id: &SiteId) -> PathBuf {
        self.site_runtime_directory(site_id).join("bootstrap.sock")
    }

    #[must_use]
    pub fn caddy_socket(&self, site_id: &SiteId, virtual_port: u16) -> PathBuf {
        self.site_runtime_directory(site_id)
            .join(format!("caddy-{virtual_port}.sock"))
    }

    /// Creates private per-site directories and atomically writes the complete
    /// configuration for the one Torkitten Tor process.
    ///
    /// Disabled sites retain their identity directories but are omitted from
    /// the active Tor configuration. Disabled mappings are omitted without
    /// affecting their site or siblings.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, unsafe paths, an ambiguous
    /// legacy identity, randomness failure, or filesystem failure.
    pub fn prepare(&self, config: &GatewayConfig) -> Result<(), TorError> {
        self.prepare_with_bootstrap(config, &HashSet::new())
    }

    /// Writes configuration with temporary certificate-bootstrap listeners
    /// enabled only for the explicitly selected sites.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, an unknown or disabled
    /// bootstrap site, unsafe paths, or filesystem failure.
    pub fn prepare_with_bootstrap(
        &self,
        config: &GatewayConfig,
        bootstrap_sites: &HashSet<SiteId>,
    ) -> Result<(), TorError> {
        self.prepare_directories(config, bootstrap_sites)?;
        let rendered = self.render_torrc(config, bootstrap_sites)?;
        atomic_write(&self.torrc_path(), rendered.as_bytes(), 0o600)
    }

    /// Validates a staged configuration with the bundled Tor binary before
    /// atomically replacing the active file.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, filesystem failure, or a Tor
    /// validation failure. The active configuration is unchanged on failure.
    pub fn prepare_validated(
        &self,
        config: &GatewayConfig,
        bootstrap_sites: &HashSet<SiteId>,
    ) -> Result<(), TorError> {
        self.prepare_directories(config, bootstrap_sites)?;
        let rendered = self.render_torrc(config, bootstrap_sites)?;
        let (temporary_path, mut temporary) =
            create_temporary(&self.paths.state_directory, Some(OsStr::new("torrc")))?;
        if let Err(error) = temporary
            .write_all(rendered.as_bytes())
            .and_then(|()| temporary.sync_all())
            .and_then(|()| fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600)))
        {
            let _ = fs::remove_file(&temporary_path);
            return Err(error.into());
        }
        let output = self.verify_command_for(&temporary_path).output()?;
        if !output.status.success() {
            let _ = fs::remove_file(&temporary_path);
            return Err(command_failure(output.status.code(), &output.stderr));
        }
        fs::rename(&temporary_path, self.torrc_path())?;
        File::open(&self.paths.state_directory)?.sync_all()?;
        Ok(())
    }

    /// Validates a staged candidate with the bundled Tor binary without
    /// replacing the active configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, filesystem failure, or a Tor
    /// validation failure. The active configuration is never changed.
    pub fn validate(
        &self,
        config: &GatewayConfig,
        bootstrap_sites: &HashSet<SiteId>,
    ) -> Result<(), TorError> {
        self.prepare_directories(config, bootstrap_sites)?;
        let rendered = self.render_torrc(config, bootstrap_sites)?;
        let (temporary_path, mut temporary) =
            create_temporary(&self.paths.state_directory, Some(OsStr::new("torrc")))?;
        let result = (|| {
            temporary.write_all(rendered.as_bytes())?;
            temporary.sync_all()?;
            fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600))?;
            let output = self.verify_command_for(&temporary_path).output()?;
            if output.status.success() {
                Ok(())
            } else {
                Err(command_failure(output.status.code(), &output.stderr))
            }
        })();
        let _ = fs::remove_file(&temporary_path);
        result
    }

    fn prepare_directories(
        &self,
        config: &GatewayConfig,
        bootstrap_sites: &HashSet<SiteId>,
    ) -> Result<(), TorError> {
        config.validate()?;
        validate_bootstrap_sites(config, bootstrap_sites)?;
        ensure_private_directory(&self.paths.state_directory)?;
        ensure_private_directory(&self.paths.runtime_directory)?;
        ensure_private_directory(&self.paths.state_directory.join("data"))?;
        self.migrate_legacy_identity(config)?;

        for site in &config.sites {
            ensure_private_directory(&self.site_state_directory(&site.id))?;
            ensure_private_directory(&self.site_runtime_directory(&site.id))?;
            ensure_private_directory(&self.onion_directory(&site.id))?;
            ensure_private_directory(&self.onion_directory(&site.id).join("authorized_clients"))?;
        }

        Ok(())
    }

    /// Installs one authorized client's public X25519 key for exactly one site.
    ///
    /// # Errors
    ///
    /// Returns an error if private directories cannot be created or the
    /// authorization file cannot be atomically written.
    pub fn authorize_client(
        &self,
        site_id: &SiteId,
        name: &ClientName,
        keys: &ClientKeyPair,
    ) -> Result<(), TorError> {
        let directory = self.onion_directory(site_id).join("authorized_clients");
        ensure_private_directory(&directory)?;
        atomic_write(
            &directory.join(format!("{}.auth", name.as_str())),
            keys.server_authorization().as_bytes(),
            0o600,
        )
    }

    /// Removes one site's authorized client, returning whether its file existed.
    ///
    /// # Errors
    ///
    /// Returns an error when the authorization file cannot be inspected or
    /// removed.
    pub fn revoke_client(&self, site_id: &SiteId, name: &ClientName) -> Result<bool, TorError> {
        let path = self
            .onion_directory(site_id)
            .join("authorized_clients")
            .join(format!("{}.auth", name.as_str()));
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Reads and validates one site's persistent v3 onion hostname.
    ///
    /// # Errors
    ///
    /// Returns an error when the hostname file is unavailable or malformed.
    pub fn onion_hostname(&self, site_id: &SiteId) -> Result<String, TorError> {
        let hostname = fs::read_to_string(self.onion_directory(site_id).join("hostname"))?;
        let hostname = hostname.trim();
        validate_onion_hostname(hostname)?;
        Ok(format!("{}.onion", hostname.trim_end_matches(".onion")))
    }

    /// Returns a command that launches only the dedicated Torkitten Tor
    /// configuration, with no system or user defaults.
    #[must_use]
    pub fn command(&self) -> Command {
        self.command_for(&self.torrc_path())
    }

    fn command_for(&self, torrc_path: &Path) -> Command {
        let mut command = Command::new(&self.paths.binary);
        command
            .arg("--defaults-torrc")
            .arg("/dev/null")
            .arg("-f")
            .arg(torrc_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Returns a command that asks the bundled Tor binary to validate the
    /// complete configuration without joining the Tor network.
    #[must_use]
    pub fn verify_command(&self) -> Command {
        self.verify_command_for(&self.torrc_path())
    }

    fn verify_command_for(&self, torrc_path: &Path) -> Command {
        let mut command = self.command_for(torrc_path);
        command.arg("--verify-config");
        command
    }

    fn render_torrc(
        &self,
        config: &GatewayConfig,
        bootstrap_sites: &HashSet<SiteId>,
    ) -> Result<String, TorError> {
        let mut output = String::new();
        setting(
            &mut output,
            "DataDirectory",
            &self.paths.state_directory.join("data"),
        )?;
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

        let mut sites = config
            .sites
            .iter()
            .filter(|site| site.enabled)
            .collect::<Vec<_>>();
        sites.sort_by(|left, right| left.id.cmp(&right.id));
        for site in sites {
            setting(
                &mut output,
                "HiddenServiceDir",
                &self.onion_directory(&site.id),
            )?;
            output.push_str(
                "HiddenServiceVersion 3\n\
                 HiddenServiceAllowUnknownPorts 0\n\
                 HiddenServiceNumIntroductionPoints 3\n",
            );
            if bootstrap_sites.contains(&site.id) {
                hidden_service_port(&mut output, 80, &self.bootstrap_socket(&site.id))?;
            }
            hidden_service_port(&mut output, 443, &self.caddy_socket(&site.id, 443))?;

            let mut mappings = site
                .mappings
                .iter()
                .filter(|mapping| mapping.enabled)
                .collect::<Vec<_>>();
            mappings.sort_by(|left, right| {
                left.virtual_port
                    .cmp(&right.virtual_port)
                    .then_with(|| left.id.cmp(&right.id))
            });
            for mapping in mappings {
                hidden_service_port(
                    &mut output,
                    mapping.virtual_port,
                    &self.caddy_socket(&site.id, mapping.virtual_port),
                )?;
            }
        }
        Ok(output)
    }

    fn migrate_legacy_identity(&self, config: &GatewayConfig) -> Result<(), TorError> {
        let legacy = self.paths.state_directory.join("onion");
        let metadata = match fs::symlink_metadata(&legacy) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(TorError::UnsafeDirectory(legacy));
        }

        let site = config
            .sites
            .iter()
            .find(|site| site.id.as_str() == LEGACY_SITE_ID)
            .ok_or(TorError::LegacyIdentityUnassigned)?;
        let parent = self.site_state_directory(&site.id);
        ensure_private_directory(&parent)?;
        let destination = self.onion_directory(&site.id);
        if destination.exists() {
            return Err(TorError::LegacyIdentityConflict(destination));
        }
        fs::rename(&legacy, &destination)?;
        File::open(&parent)?.sync_all()?;
        File::open(&self.paths.state_directory)?.sync_all()?;
        Ok(())
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

fn validate_bootstrap_sites(
    config: &GatewayConfig,
    bootstrap_sites: &HashSet<SiteId>,
) -> Result<(), TorError> {
    for site_id in bootstrap_sites {
        if !config
            .sites
            .iter()
            .any(|site| site.enabled && site.id == *site_id)
        {
            return Err(TorError::BootstrapSiteUnavailable(site_id.clone()));
        }
    }
    Ok(())
}

fn command_failure(status: Option<i32>, stderr: &[u8]) -> TorError {
    let detail = String::from_utf8_lossy(stderr)
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(4096)
        .collect::<String>();
    TorError::ValidationFailed {
        status,
        detail: detail.trim().to_owned(),
    }
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
    #[error("legacy onion identity has no matching default site")]
    LegacyIdentityUnassigned,
    #[error("legacy and multi-site onion identities both exist at {path}", path = .0.display())]
    LegacyIdentityConflict(PathBuf),
    #[error("certificate bootstrap site is missing or disabled: {0}")]
    BootstrapSiteUnavailable(SiteId),
    #[error("could not allocate a temporary filename")]
    TemporaryNameExhausted,
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
    #[error("Tor configuration validation failed with status {status:?}: {detail}")]
    ValidationFailed { status: Option<i32>, detail: String },
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

    use torkitten_core::{Mapping, MappingId, MappingTarget, Site, Transport};

    use super::*;

    fn instance(temporary: &tempfile::TempDir) -> TorInstance {
        TorInstance::new(TorPaths::new(
            "/opt/torkitten/libexec/tor",
            temporary.path().join("state/tor"),
            temporary.path().join("run/tor"),
        ))
    }

    fn mapping(id: &str, virtual_port: u16, enabled: bool) -> Mapping {
        Mapping {
            id: MappingId::new(id).unwrap(),
            display_name: "Example".to_owned(),
            virtual_port,
            target: MappingTarget::Tcp {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 3000,
                transport: Transport::Http,
            },
            enabled,
        }
    }

    fn site(id: &str, enabled: bool, mappings: Vec<Mapping>) -> Site {
        Site {
            id: SiteId::new(id).unwrap(),
            display_name: format!("Site {id}"),
            enabled,
            mappings,
        }
    }

    fn config() -> GatewayConfig {
        GatewayConfig {
            sites: vec![
                site(
                    "alpha",
                    true,
                    vec![mapping("example", 8443, true), mapping("off", 8444, false)],
                ),
                site("beta", true, vec![mapping("example", 8443, true)]),
                site("disabled", false, vec![mapping("example", 8443, true)]),
            ],
            ..GatewayConfig::default()
        }
    }

    #[test]
    fn one_process_configuration_isolates_enabled_sites_and_ports() {
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
        assert_eq!(torrc.matches("HiddenServiceDir ").count(), 2);
        assert_eq!(torrc.matches("HiddenServicePort 80 ").count(), 0);
        assert_eq!(torrc.matches("HiddenServicePort 443 ").count(), 2);
        assert_eq!(torrc.matches("HiddenServicePort 8443 ").count(), 2);
        assert!(!torrc.contains("HiddenServicePort 8444 "));
        assert!(
            torrc.contains(
                instance
                    .onion_directory(&SiteId::new("alpha").unwrap())
                    .to_str()
                    .unwrap()
            )
        );
        assert!(
            torrc.contains(
                instance
                    .onion_directory(&SiteId::new("beta").unwrap())
                    .to_str()
                    .unwrap()
            )
        );
        assert!(
            !torrc.contains(
                instance
                    .onion_directory(&SiteId::new("disabled").unwrap())
                    .to_str()
                    .unwrap()
            )
        );
        assert!(!torrc.contains("0.0.0.0"));
        assert!(
            instance
                .onion_directory(&SiteId::new("disabled").unwrap())
                .is_dir()
        );
    }

    #[test]
    fn opens_bootstrap_only_for_an_explicit_enabled_site() {
        let temporary = tempfile::tempdir().unwrap();
        let instance = instance(&temporary);
        let alpha = SiteId::new("alpha").unwrap();
        instance
            .prepare_with_bootstrap(&config(), &HashSet::from([alpha.clone()]))
            .unwrap();
        let torrc = fs::read_to_string(instance.torrc_path()).unwrap();
        assert_eq!(torrc.matches("HiddenServicePort 80 ").count(), 1);
        assert!(torrc.contains(instance.bootstrap_socket(&alpha).to_str().unwrap()));

        let disabled = SiteId::new("disabled").unwrap();
        assert!(matches!(
            instance.prepare_with_bootstrap(&config(), &HashSet::from([disabled.clone()])),
            Err(TorError::BootstrapSiteUnavailable(site_id)) if site_id == disabled
        ));
    }

    #[test]
    fn installs_and_revokes_client_keys_per_site() {
        let temporary = tempfile::tempdir().unwrap();
        let instance = instance(&temporary);
        let alpha = SiteId::new("alpha").unwrap();
        let beta = SiteId::new("beta").unwrap();
        let name = ClientName::new("phone").unwrap();
        let keys = ClientKeyPair::generate().unwrap();
        instance.authorize_client(&alpha, &name, &keys).unwrap();
        let alpha_path = instance
            .onion_directory(&alpha)
            .join("authorized_clients/phone.auth");
        let beta_path = instance
            .onion_directory(&beta)
            .join("authorized_clients/phone.auth");
        assert_eq!(
            fs::read_to_string(&alpha_path).unwrap(),
            keys.server_authorization()
        );
        assert!(!beta_path.exists());
        assert!(instance.revoke_client(&alpha, &name).unwrap());
        assert!(!instance.revoke_client(&alpha, &name).unwrap());
    }

    #[test]
    fn migrates_the_single_site_identity_without_changing_it() {
        let temporary = tempfile::tempdir().unwrap();
        let instance = instance(&temporary);
        let legacy = instance.paths.state_directory.join("onion");
        fs::create_dir_all(legacy.join("authorized_clients")).unwrap();
        fs::write(legacy.join("hs_ed25519_secret_key"), b"identity bytes").unwrap();
        let config = GatewayConfig {
            sites: vec![site(LEGACY_SITE_ID, true, Vec::new())],
            ..GatewayConfig::default()
        };

        instance.prepare(&config).unwrap();
        assert!(!legacy.exists());
        assert_eq!(
            fs::read(
                instance
                    .onion_directory(&SiteId::new(LEGACY_SITE_ID).unwrap())
                    .join("hs_ed25519_secret_key")
            )
            .unwrap(),
            b"identity bytes"
        );
    }

    #[test]
    fn torrc_rendering_is_deterministic() {
        let temporary = tempfile::tempdir().unwrap();
        let instance = TorInstance::new(TorPaths::new(
            "/opt/torkitten/libexec/tor",
            temporary.path().join("state"),
            temporary.path().join("run"),
        ));
        let mut reversed = config();
        reversed.sites.reverse();
        for site in &mut reversed.sites {
            site.mappings.reverse();
        }
        instance.prepare(&config()).unwrap();
        let first = fs::read_to_string(instance.torrc_path()).unwrap();
        instance.prepare(&reversed).unwrap();
        let second = fs::read_to_string(instance.torrc_path()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    #[ignore = "requires the bundled Tor binary and its Ubuntu 24.04 runtime libraries"]
    fn bundled_tor_accepts_generated_multi_site_configuration() {
        let binary = std::env::var_os("TORKITTEN_TOR_BINARY")
            .expect("TORKITTEN_TOR_BINARY must identify the bundled Tor binary");
        let temporary = tempfile::tempdir().unwrap();
        let instance = TorInstance::new(TorPaths::new(
            binary,
            temporary.path().join("state/tor"),
            temporary.path().join("run/tor"),
        ));
        instance
            .prepare_validated(&config(), &HashSet::new())
            .unwrap();
    }
}
