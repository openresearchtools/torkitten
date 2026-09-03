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
    ClientKeyPair, ClientName, OnionIdentity,
    client_auth::{ClientAuthError, validate_onion_hostname},
};

const LEGACY_SITE_ID: &str = "default";
const SHARED_DIRECTORY_MODE: u32 = 0o2750;
const SHARED_FILE_MODE: u32 = 0o640;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TorPaths {
    pub binary: PathBuf,
    pub state_directory: PathBuf,
    pub runtime_directory: PathBuf,
    pub proxy_runtime_directory: PathBuf,
    pub service_user: Option<String>,
}

impl TorPaths {
    #[must_use]
    pub fn new(
        binary: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
        runtime_directory: impl Into<PathBuf>,
    ) -> Self {
        let runtime_directory = runtime_directory.into();
        Self {
            binary: binary.into(),
            state_directory: state_directory.into(),
            proxy_runtime_directory: runtime_directory.clone(),
            runtime_directory,
            service_user: None,
        }
    }

    /// Selects the separate runtime directory where Caddy creates the Unix
    /// listeners consumed by Tor hidden-service virtual ports.
    #[must_use]
    pub fn with_proxy_runtime_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.proxy_runtime_directory = directory.into();
        self
    }

    /// Selects the native service account and therefore the owner-private
    /// hidden-service tree populated immediately before Tor starts.
    #[must_use]
    pub fn with_service_user(mut self, user: impl Into<String>) -> Self {
        self.service_user = Some(user.into());
        self
    }
}

/// Owns the one application-controlled Tor process and every site's isolated
/// hidden-service directory.
#[derive(Clone, Debug)]
pub struct TorInstance {
    paths: TorPaths,
}

/// A crash-recoverable swap of one site's identity directory. Dropping an
/// uncommitted rotation restores the previous identity.
pub struct IdentityRotation {
    onion_directory: PathBuf,
    previous_directory: PathBuf,
    committed_directory: PathBuf,
    active: bool,
}

impl IdentityRotation {
    /// Makes the new identity permanent. A committed backup left by an
    /// interrupted cleanup is safely removed during the next prepare.
    ///
    /// # Errors
    ///
    /// Returns an error when the atomic commit marker cannot be installed.
    pub fn commit(mut self) -> Result<(), TorError> {
        fs::rename(&self.previous_directory, &self.committed_directory)?;
        if let Err(error) = sync_parent(&self.onion_directory) {
            let _ = fs::rename(&self.committed_directory, &self.previous_directory);
            return Err(error);
        }
        self.active = false;
        let _ = remove_private_tree(&self.committed_directory);
        Ok(())
    }

    /// Restores the old identity immediately.
    ///
    /// # Errors
    ///
    /// Returns an error when the new directory cannot be removed or the old
    /// directory cannot be restored.
    pub fn rollback(mut self) -> Result<(), TorError> {
        self.rollback_inner()?;
        self.active = false;
        Ok(())
    }

    fn rollback_inner(&self) -> Result<(), TorError> {
        remove_private_tree(&self.onion_directory)?;
        fs::rename(&self.previous_directory, &self.onion_directory)?;
        sync_parent(&self.onion_directory)
    }
}

impl Drop for IdentityRotation {
    fn drop(&mut self) {
        if self.active {
            let _ = self.rollback_inner();
        }
    }
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

    /// Returns the directory Tor reads at runtime. Container/single-user
    /// operation uses the canonical identity directly; native service-user
    /// operation uses an owner-private synchronized copy.
    #[must_use]
    pub fn published_onion_directory(&self, site_id: &SiteId) -> PathBuf {
        if self.paths.service_user.is_some() {
            self.paths
                .state_directory
                .join("hidden-services")
                .join(site_id.as_str())
        } else {
            self.onion_directory(site_id)
        }
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
        self.paths
            .proxy_runtime_directory
            .join("sites")
            .join(site_id.as_str())
            .join("caddy-80.sock")
    }

    #[must_use]
    pub fn caddy_socket(&self, site_id: &SiteId, virtual_port: u16) -> PathBuf {
        self.paths
            .proxy_runtime_directory
            .join("sites")
            .join(site_id.as_str())
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
        let rendered = self.render_torrc(config, bootstrap_sites, false)?;
        atomic_write(&self.torrc_path(), rendered.as_bytes(), SHARED_FILE_MODE)
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
        let validation = self.render_torrc(config, bootstrap_sites, true)?;
        let (temporary_path, mut temporary) =
            create_temporary(&self.paths.state_directory, Some(OsStr::new("torrc")))?;
        if let Err(error) = temporary
            .write_all(validation.as_bytes())
            .and_then(|()| temporary.sync_all())
            .and_then(|()| {
                fs::set_permissions(
                    &temporary_path,
                    fs::Permissions::from_mode(SHARED_FILE_MODE),
                )
            })
        {
            let _ = fs::remove_file(&temporary_path);
            return Err(error.into());
        }
        let output = self.verify_command_for(&temporary_path).output()?;
        if !output.status.success() {
            let _ = fs::remove_file(&temporary_path);
            return Err(command_failure(output.status.code(), &output.stderr));
        }
        fs::remove_file(&temporary_path)?;
        let active = self.render_torrc(config, bootstrap_sites, false)?;
        atomic_write(&self.torrc_path(), active.as_bytes(), SHARED_FILE_MODE)
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
        let rendered = self.render_torrc(config, bootstrap_sites, true)?;
        let (temporary_path, mut temporary) =
            create_temporary(&self.paths.state_directory, Some(OsStr::new("torrc")))?;
        let result = (|| {
            temporary.write_all(rendered.as_bytes())?;
            temporary.sync_all()?;
            fs::set_permissions(
                &temporary_path,
                fs::Permissions::from_mode(SHARED_FILE_MODE),
            )?;
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
        ensure_directory(&self.paths.state_directory, SHARED_DIRECTORY_MODE)?;
        ensure_external_directory(&self.paths.runtime_directory, 0o700)?;
        ensure_external_directory(
            &self.paths.state_directory.join("data"),
            SHARED_DIRECTORY_MODE,
        )?;
        ensure_directory(
            &self.paths.state_directory.join("validation-data"),
            SHARED_DIRECTORY_MODE,
        )?;
        ensure_directory(
            &self.paths.state_directory.join("sites"),
            SHARED_DIRECTORY_MODE,
        )?;
        self.migrate_legacy_identity(config)?;

        for site in &config.sites {
            ensure_directory(&self.site_state_directory(&site.id), SHARED_DIRECTORY_MODE)?;
            ensure_directory(&self.onion_directory(&site.id), SHARED_DIRECTORY_MODE)?;
            ensure_directory(
                &self.onion_directory(&site.id).join("authorized_clients"),
                SHARED_DIRECTORY_MODE,
            )?;
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
        ensure_directory(&directory, SHARED_DIRECTORY_MODE)?;
        atomic_write(
            &directory.join(format!("{}.auth", name.as_str())),
            keys.server_authorization().as_bytes(),
            SHARED_FILE_MODE,
        )
    }

    /// Installs a selected generated identity into an otherwise new site's
    /// persistent hidden-service directory.
    ///
    /// # Errors
    ///
    /// Returns an error when identity material already exists or private files
    /// cannot be installed atomically.
    pub fn install_identity(
        &self,
        site_id: &SiteId,
        identity: &OnionIdentity,
    ) -> Result<(), TorError> {
        ensure_directory(&self.paths.state_directory, SHARED_DIRECTORY_MODE)?;
        ensure_directory(
            &self.paths.state_directory.join("sites"),
            SHARED_DIRECTORY_MODE,
        )?;
        ensure_directory(&self.site_state_directory(site_id), SHARED_DIRECTORY_MODE)?;
        let directory = self.onion_directory(site_id);
        ensure_directory(&directory, SHARED_DIRECTORY_MODE)?;
        ensure_directory(&directory.join("authorized_clients"), SHARED_DIRECTORY_MODE)?;
        let secret = directory.join("hs_ed25519_secret_key");
        let public = directory.join("hs_ed25519_public_key");
        let hostname = directory.join("hostname");
        if [&secret, &public, &hostname]
            .iter()
            .any(|path| path.exists())
        {
            return Err(TorError::IdentityAlreadyExists(site_id.clone()));
        }
        atomic_write(&secret, identity.secret_key_file(), SHARED_FILE_MODE)?;
        atomic_write(&public, identity.public_key_file(), SHARED_FILE_MODE)?;
        atomic_write(
            &hostname,
            format!("{}\n", identity.hostname()).as_bytes(),
            SHARED_FILE_MODE,
        )
    }

    /// Atomically selects a new identity directory while keeping the old one
    /// available for rollback until the caller commits the returned guard.
    /// Existing authorized-client public keys are copied into the candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when the current identity is missing or unsafe, a
    /// previous interrupted rotation cannot be recovered, or filesystem
    /// operations fail.
    pub fn begin_identity_rotation(
        &self,
        site_id: &SiteId,
        identity: &OnionIdentity,
    ) -> Result<IdentityRotation, TorError> {
        self.recover_identity_rotation(site_id)?;
        let onion = self.onion_directory(site_id);
        ensure_existing_private_directory(&onion)?;
        let parent = self.site_state_directory(site_id);
        let staged = parent.join("onion.rotation-new");
        let previous = parent.join("onion.rotation-old");
        let committed = parent.join("onion.rotation-committed");
        ensure_absent(&staged)?;
        ensure_absent(&previous)?;
        ensure_absent(&committed)?;
        ensure_directory(&staged, SHARED_DIRECTORY_MODE)?;
        let result = (|| {
            atomic_write(
                &staged.join("hs_ed25519_secret_key"),
                identity.secret_key_file(),
                SHARED_FILE_MODE,
            )?;
            atomic_write(
                &staged.join("hs_ed25519_public_key"),
                identity.public_key_file(),
                SHARED_FILE_MODE,
            )?;
            atomic_write(
                &staged.join("hostname"),
                format!("{}\n", identity.hostname()).as_bytes(),
                SHARED_FILE_MODE,
            )?;
            copy_authorized_clients(
                &onion.join("authorized_clients"),
                &staged.join("authorized_clients"),
            )?;
            fs::rename(&onion, &previous)?;
            if let Err(error) = fs::rename(&staged, &onion) {
                let _ = fs::rename(&previous, &onion);
                return Err(error.into());
            }
            sync_parent(&onion)
        })();
        if let Err(error) = result {
            let _ = remove_private_tree(&staged);
            return Err(error);
        }
        Ok(IdentityRotation {
            onion_directory: onion,
            previous_directory: previous,
            committed_directory: committed,
            active: true,
        })
    }

    /// Restores or cleans identity directories left by an interrupted rotation.
    /// This is called once by the daemon at startup, never during an active
    /// configuration transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when a rotation path is unsafe or cannot be recovered.
    pub fn recover_identity_rotation(&self, site_id: &SiteId) -> Result<(), TorError> {
        let parent = self.site_state_directory(site_id);
        let onion = self.onion_directory(site_id);
        let staged = parent.join("onion.rotation-new");
        let previous = parent.join("onion.rotation-old");
        let committed = parent.join("onion.rotation-committed");
        if committed.exists() {
            remove_private_tree(&committed)?;
        }
        if previous.exists() {
            if onion.exists() {
                remove_private_tree(&onion)?;
            }
            ensure_existing_private_directory(&previous)?;
            fs::rename(&previous, &onion)?;
            sync_parent(&onion)?;
        }
        if staged.exists() {
            remove_private_tree(&staged)?;
        }
        Ok(())
    }

    /// Removes one site's exact persistent onion identity directory after the
    /// site has been unpublished.
    ///
    /// # Errors
    ///
    /// Returns an error when the exact per-site directory cannot be removed.
    pub fn remove_site_state(&self, site_id: &SiteId) -> Result<bool, TorError> {
        let path = self.site_state_directory(site_id);
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
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
        command
            .arg("--DataDirectory")
            .arg(self.paths.state_directory.join("validation-data"))
            .arg("--verify-config");
        command
    }

    fn render_torrc(
        &self,
        config: &GatewayConfig,
        bootstrap_sites: &HashSet<SiteId>,
        validation: bool,
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
            &self.paths.state_directory.join("data/control.authcookie"),
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
             DataDirectoryGroupReadable 1\n\
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
             ShutdownWaitLength 5 seconds\n\
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
            let onion_directory = if validation {
                self.onion_directory(&site.id)
            } else {
                self.published_onion_directory(&site.id)
            };
            setting(&mut output, "HiddenServiceDir", &onion_directory)?;
            if validation || self.paths.service_user.is_none() {
                output.push_str("HiddenServiceDirGroupReadable 1\n");
            }
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
        ensure_directory(&parent, SHARED_DIRECTORY_MODE)?;
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

fn ensure_directory(path: &Path, mode: u32) -> Result<(), TorError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(TorError::UnsafeDirectory(path.to_path_buf()));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

// The native package owns Tor's mutable data directory with the dedicated
// Tor account. The daemon validates an existing directory without trying to
// chmod storage it deliberately does not own.
fn ensure_external_directory(path: &Path, mode_when_created: u32) -> Result<(), TorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(TorError::UnsafeDirectory(path.to_path_buf()));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure_directory(path, mode_when_created)
        }
        Err(error) => Err(error.into()),
    }
}

fn ensure_existing_private_directory(path: &Path) -> Result<(), TorError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(TorError::UnsafeDirectory(path.to_path_buf()));
    }
    Ok(())
}

fn ensure_absent(path: &Path) -> Result<(), TorError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(TorError::UnsafeDirectory(path.to_path_buf())),
        Err(error) => Err(error.into()),
    }
}

fn remove_private_tree(path: &Path) -> Result<(), TorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(TorError::UnsafeDirectory(path.to_path_buf()));
            }
            fs::remove_dir_all(path)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn copy_authorized_clients(source: &Path, destination: &Path) -> Result<(), TorError> {
    ensure_existing_private_directory(source)?;
    ensure_directory(destination, SHARED_DIRECTORY_MODE)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let filename = entry.file_name();
        let safe_name = filename
            .to_str()
            .is_some_and(|name| !name.contains(['/', '\0']))
            && path.extension() == Some(OsStr::new("auth"));
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() || !safe_name {
            return Err(TorError::UnsafeAuthorizedClient(path));
        }
        atomic_write(
            &destination.join(filename),
            &fs::read(path)?,
            SHARED_FILE_MODE,
        )?;
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), TorError> {
    let parent = path
        .parent()
        .ok_or_else(|| TorError::InvalidPath(path.to_path_buf()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<(), TorError> {
    let parent = path
        .parent()
        .ok_or_else(|| TorError::InvalidPath(path.to_path_buf()))?;
    ensure_directory(parent, SHARED_DIRECTORY_MODE)?;
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
    #[error("onion identity already exists for site {0}")]
    IdentityAlreadyExists(SiteId),
    #[error("unsafe authorized-client entry: {path}", path = .0.display())]
    UnsafeAuthorizedClient(PathBuf),
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
    use std::{
        net::{IpAddr, Ipv4Addr},
        thread,
        time::Duration,
    };

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
        assert!(torrc.contains("ShutdownWaitLength 5 seconds"));
        assert!(torrc.contains("DataDirectoryGroupReadable 1"));
        assert_eq!(torrc.matches("HiddenServiceDir ").count(), 2);
        assert_eq!(torrc.matches("HiddenServiceDirGroupReadable 1").count(), 2);
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
    fn hidden_service_ports_target_the_separate_caddy_runtime() {
        let temporary = tempfile::tempdir().unwrap();
        let caddy_runtime = temporary.path().join("run/caddy");
        let instance = TorInstance::new(
            TorPaths::new(
                "/opt/torkitten/libexec/tor",
                temporary.path().join("state/tor"),
                temporary.path().join("run/tor"),
            )
            .with_proxy_runtime_directory(&caddy_runtime),
        );
        instance.prepare(&config()).unwrap();
        let torrc = fs::read_to_string(instance.torrc_path()).unwrap();
        assert!(
            torrc.contains(
                caddy_runtime
                    .join("sites/alpha/caddy-443.sock")
                    .to_str()
                    .unwrap()
            )
        );
        assert!(
            !torrc.contains(
                temporary
                    .path()
                    .join("run/tor/sites/alpha/caddy-443.sock")
                    .to_str()
                    .unwrap()
            )
        );
    }

    #[test]
    fn service_user_configuration_targets_owner_private_identity_copies() {
        let temporary = tempfile::tempdir().unwrap();
        let instance = TorInstance::new(
            TorPaths::new(
                "/opt/torkitten/libexec/tor",
                temporary.path().join("state/tor"),
                temporary.path().join("run/tor"),
            )
            .with_service_user("torkitten-tor"),
        );
        instance.prepare(&config()).unwrap();
        let torrc = fs::read_to_string(instance.torrc_path()).unwrap();
        assert!(!torrc.contains("User "));
        assert!(
            torrc.contains(
                instance
                    .published_onion_directory(&SiteId::new("alpha").unwrap())
                    .to_str()
                    .unwrap()
            )
        );
        assert!(!torrc.contains("HiddenServiceDirGroupReadable"));
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
    fn installs_a_selected_generated_identity_once() {
        let temporary = tempfile::tempdir().unwrap();
        let instance = instance(&temporary);
        let site_id = SiteId::new("alpha").unwrap();
        let identity = OnionIdentity::generate().unwrap();
        instance.install_identity(&site_id, &identity).unwrap();
        assert_eq!(
            instance.onion_hostname(&site_id).unwrap(),
            identity.hostname()
        );
        assert_eq!(
            fs::read(
                instance
                    .onion_directory(&site_id)
                    .join("hs_ed25519_secret_key")
            )
            .unwrap(),
            identity.secret_key_file()
        );
        let directory_mode = fs::metadata(instance.onion_directory(&site_id))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        let key_mode = fs::metadata(
            instance
                .onion_directory(&site_id)
                .join("hs_ed25519_secret_key"),
        )
        .unwrap()
        .permissions()
        .mode()
            & 0o7777;
        assert_eq!(directory_mode, SHARED_DIRECTORY_MODE);
        assert_eq!(key_mode, SHARED_FILE_MODE);
        assert!(matches!(
            instance.install_identity(&site_id, &OnionIdentity::generate().unwrap()),
            Err(TorError::IdentityAlreadyExists(id)) if id == site_id
        ));
    }

    #[test]
    fn identity_rotation_preserves_clients_and_rolls_back_until_commit() {
        let temporary = tempfile::tempdir().unwrap();
        let instance = instance(&temporary);
        let site_id = SiteId::new("alpha").unwrap();
        let original = OnionIdentity::generate().unwrap();
        instance.install_identity(&site_id, &original).unwrap();
        let name = ClientName::new("phone").unwrap();
        let keys = ClientKeyPair::generate().unwrap();
        instance.authorize_client(&site_id, &name, &keys).unwrap();

        let replacement = OnionIdentity::generate().unwrap();
        let rotation = instance
            .begin_identity_rotation(&site_id, &replacement)
            .unwrap();
        assert_eq!(
            instance.onion_hostname(&site_id).unwrap(),
            replacement.hostname()
        );
        assert_eq!(
            fs::read_to_string(
                instance
                    .onion_directory(&site_id)
                    .join("authorized_clients/phone.auth")
            )
            .unwrap(),
            keys.server_authorization()
        );
        rotation.rollback().unwrap();
        assert_eq!(
            instance.onion_hostname(&site_id).unwrap(),
            original.hostname()
        );

        let committed = OnionIdentity::generate().unwrap();
        instance
            .begin_identity_rotation(&site_id, &committed)
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(
            instance.onion_hostname(&site_id).unwrap(),
            committed.hostname()
        );
    }

    #[test]
    fn prepare_recovers_an_interrupted_identity_rotation() {
        let temporary = tempfile::tempdir().unwrap();
        let instance = instance(&temporary);
        let site_id = SiteId::new("alpha").unwrap();
        let original = OnionIdentity::generate().unwrap();
        instance.install_identity(&site_id, &original).unwrap();
        let rotation = instance
            .begin_identity_rotation(&site_id, &OnionIdentity::generate().unwrap())
            .unwrap();
        std::mem::forget(rotation);

        instance.recover_identity_rotation(&site_id).unwrap();
        assert_eq!(
            instance.onion_hostname(&site_id).unwrap(),
            original.hostname()
        );
        assert!(
            !instance
                .site_state_directory(&site_id)
                .join("onion.rotation-old")
                .exists()
        );
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

    #[test]
    #[ignore = "requires the bundled Tor binary and its Ubuntu 24.04 runtime libraries"]
    fn bundled_tor_loads_a_selected_generated_identity() {
        let binary = std::env::var_os("TORKITTEN_TOR_BINARY")
            .expect("TORKITTEN_TOR_BINARY must identify the bundled Tor binary");
        let temporary = tempfile::tempdir().unwrap();
        let instance = TorInstance::new(TorPaths::new(
            binary,
            temporary.path().join("state/tor"),
            temporary.path().join("run/tor"),
        ));
        let site = site("alpha", true, Vec::new());
        let identity = OnionIdentity::generate().unwrap();
        instance.install_identity(&site.id, &identity).unwrap();
        instance
            .prepare_validated(
                &GatewayConfig {
                    sites: vec![site.clone()],
                    ..GatewayConfig::default()
                },
                &HashSet::new(),
            )
            .unwrap();

        let mut command = instance.command();
        command.args(["--DisableNetwork", "1"]);
        let mut child = command.spawn().unwrap();
        thread::sleep(Duration::from_millis(500));
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            panic!(
                "Tor rejected the installed selected identity:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(
            instance.onion_hostname(&site.id).unwrap(),
            identity.hostname()
        );
    }
}
