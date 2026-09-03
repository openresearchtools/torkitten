#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::Write,
    net::{SocketAddr, TcpStream},
    os::unix::{
        fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
        net::UnixStream as StdUnixStream,
    },
    path::{Path, PathBuf},
    process::{Command, Output},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};
use torkitten_auth::{CsrfToken, SessionToken, hash_password, verify_password};
use torkitten_core::{
    AccountOwner, AdminCommand, AdminResponse, ComponentAction, ComponentState, GatewayConfig,
    GatewayMode, GatewayStatus, ManagedComponent, Mapping, MappingTarget, Site, SiteId, SiteStatus,
};
use torkitten_proxy::{CaddyError, CaddyInstance, CaddyPaths, ProxyConfig, ProxySite};
use torkitten_tor::{OnionIdentity, TorError, TorInstance, TorPaths};
use torkitten_vault::{PkiError, Store, StoreError, TlsAuthority};
use uuid::Uuid;

const MAX_BOOTSTRAP_SECONDS: u32 = 3_600;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAXIMUM_IPC_REQUEST_BYTES: usize = 1024 * 1024;
const IPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CANDIDATE_LIFETIME_SECONDS: i64 = 300;
const ADMIN_SESSION_SECONDS: i64 = 30 * 86_400;
const FRESH_AUTHENTICATION_SECONDS: i64 = 600;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonPaths {
    pub state_directory: PathBuf,
    pub runtime_directory: PathBuf,
    pub tor_binary: PathBuf,
    pub caddy_binary: PathBuf,
}

impl DaemonPaths {
    #[must_use]
    pub fn new(
        state_directory: impl Into<PathBuf>,
        runtime_directory: impl Into<PathBuf>,
        tor_binary: impl Into<PathBuf>,
        caddy_binary: impl Into<PathBuf>,
    ) -> Self {
        Self {
            state_directory: state_directory.into(),
            runtime_directory: runtime_directory.into(),
            tor_binary: tor_binary.into(),
            caddy_binary: caddy_binary.into(),
        }
    }

    #[must_use]
    pub fn admin_socket(&self) -> PathBuf {
        self.runtime_directory.join("admin.sock")
    }

    fn database_directory(&self) -> PathBuf {
        self.state_directory.join("database")
    }

    fn tls_directory(&self) -> PathBuf {
        self.state_directory.join("caddy/tls")
    }

    fn certificate_path(&self, site_id: &SiteId) -> PathBuf {
        self.tls_directory()
            .join(format!("{}.chain.pem", site_id.as_str()))
    }

    fn private_key_path(&self, site_id: &SiteId) -> PathBuf {
        self.tls_directory()
            .join(format!("{}.key.pem", site_id.as_str()))
    }

    fn web_site_directory(&self, site_id: &SiteId) -> PathBuf {
        self.runtime_directory
            .join("web/sites")
            .join(site_id.as_str())
    }
}

pub trait ServiceControl {
    /// Returns the current system-owned component state.
    ///
    /// # Errors
    ///
    /// Returns an error when the service manager cannot inspect the unit.
    fn state(&mut self, component: ManagedComponent) -> Result<ComponentState, ServiceError>;

    /// Applies one lifecycle action to a system-owned component.
    ///
    /// # Errors
    ///
    /// Returns an error when the service manager rejects the action.
    fn control(
        &mut self,
        component: ManagedComponent,
        action: ComponentAction,
    ) -> Result<(), ServiceError>;
}

#[derive(Clone, Debug)]
pub struct SystemdServiceControl {
    systemctl: PathBuf,
    tor_unit: String,
    caddy_unit: String,
}

impl Default for SystemdServiceControl {
    fn default() -> Self {
        Self {
            systemctl: PathBuf::from("/usr/bin/systemctl"),
            tor_unit: "torkitten-tor.service".to_owned(),
            caddy_unit: "torkitten-caddy.service".to_owned(),
        }
    }
}

impl SystemdServiceControl {
    #[must_use]
    pub fn new(
        systemctl: impl Into<PathBuf>,
        tor_unit: impl Into<String>,
        caddy_unit: impl Into<String>,
    ) -> Self {
        Self {
            systemctl: systemctl.into(),
            tor_unit: tor_unit.into(),
            caddy_unit: caddy_unit.into(),
        }
    }

    fn unit(&self, component: ManagedComponent) -> &str {
        match component {
            ManagedComponent::Tor => &self.tor_unit,
            ManagedComponent::Caddy => &self.caddy_unit,
        }
    }
}

impl ServiceControl for SystemdServiceControl {
    fn state(&mut self, component: ManagedComponent) -> Result<ComponentState, ServiceError> {
        let output = Command::new(&self.systemctl)
            .args(["show", "--property=ActiveState", "--value"])
            .arg(self.unit(component))
            .output()?;
        if !output.status.success() {
            return Err(service_command_error("inspect", component, &output));
        }
        let state = String::from_utf8_lossy(&output.stdout);
        Ok(match state.trim() {
            "active" => ComponentState::Running,
            "activating" | "reloading" => ComponentState::Starting,
            "failed" => ComponentState::Failed,
            _ => ComponentState::Stopped,
        })
    }

    fn control(
        &mut self,
        component: ManagedComponent,
        action: ComponentAction,
    ) -> Result<(), ServiceError> {
        let verb = match action {
            ComponentAction::Start => "start",
            ComponentAction::Stop => "stop",
            ComponentAction::Restart => "restart",
        };
        let output = Command::new(&self.systemctl)
            .arg(verb)
            .arg(self.unit(component))
            .output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(service_command_error(verb, component, &output))
        }
    }
}

pub struct Daemon<S> {
    paths: DaemonPaths,
    store: Store,
    authority: TlsAuthority,
    tor: TorInstance,
    caddy: CaddyInstance,
    services: S,
    bootstrap_windows: HashMap<SiteId, BootstrapWindow>,
    active_proxy_config: Option<ProxyConfig>,
    maintenance_enabled: bool,
    candidates: HashMap<[u8; 32], GeneratedCandidate>,
}

#[derive(Clone, Debug)]
struct BootstrapWindow {
    path_token: String,
    expires_unix: i64,
}

struct GeneratedCandidate {
    identity: OnionIdentity,
    expires_unix: i64,
}

impl<S: ServiceControl> Daemon<S> {
    /// Opens persistent state. It does not start publication until
    /// [`Self::startup`] applies the stored resume policy and emergency latch.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe state paths or invalid stored database and
    /// certificate material.
    pub fn open(paths: DaemonPaths, services: S, now_unix: i64) -> Result<Self, DaemonError> {
        ensure_directory(&paths.state_directory, 0o700)?;
        ensure_directory(&paths.runtime_directory, 0o770)?;
        let mut store = Store::open(&paths.database_directory())?;
        let authority = TlsAuthority::load_or_create(&mut store, now_unix)?;
        let tor = TorInstance::new(TorPaths::new(
            &paths.tor_binary,
            paths.state_directory.join("tor"),
            paths.runtime_directory.join("tor"),
        ));
        let caddy = CaddyInstance::new(CaddyPaths::new(
            &paths.caddy_binary,
            paths.state_directory.join("caddy"),
            paths.runtime_directory.join("caddy"),
        ));
        Ok(Self {
            paths,
            store,
            authority,
            tor,
            caddy,
            services,
            bootstrap_windows: HashMap::new(),
            active_proxy_config: None,
            maintenance_enabled: false,
            candidates: HashMap::new(),
        })
    }

    /// Applies boot policy. An uninitialized installation, disabled resume
    /// policy, or persistent emergency latch always stops publication while
    /// leaving this daemon available.
    ///
    /// # Errors
    ///
    /// Returns an error for state, configuration, service, or file failures.
    pub fn startup(&mut self, now_unix: i64) -> Result<(), DaemonError> {
        let initialized = self.initialized()?;
        let settings = self.store.publication_settings()?;
        if !initialized || !settings.resume_after_boot || settings.emergency_disabled {
            self.stop_publication()?;
            return Ok(());
        }
        self.maintenance_enabled = true;
        let config = self.store.gateway_config()?;
        self.validate_runtime(&config, now_unix)?;
        self.install_runtime(&config, now_unix)
    }

    /// Handles one serialized local administration command.
    #[must_use]
    pub fn handle(&mut self, command: AdminCommand, now_unix: i64) -> AdminResponse {
        match self.handle_inner(command, now_unix) {
            Ok(response) => response,
            Err(error) => AdminResponse::Error {
                code: error.code().to_owned(),
                message: error.to_string(),
            },
        }
    }

    /// Closes expired bootstrap listeners and discovers newly-created onion
    /// hostnames without restarting unchanged components.
    ///
    /// # Errors
    ///
    /// Returns an error for state, validation, service, or file failures.
    pub fn maintenance(&mut self, now_unix: i64) -> Result<(), DaemonError> {
        if !self.maintenance_enabled {
            return Ok(());
        }
        let before = self.bootstrap_windows.len();
        self.bootstrap_windows
            .retain(|_, window| window.expires_unix > now_unix);
        self.candidates
            .retain(|_, candidate| candidate.expires_unix > now_unix);
        let config = self.store.gateway_config()?;
        if self.bootstrap_windows.len() == before {
            self.refresh_proxy(&config, now_unix)
        } else {
            self.validate_runtime(&config, now_unix)?;
            self.install_runtime(&config, now_unix)
        }
    }

    #[allow(clippy::too_many_lines)]
    fn handle_inner(
        &mut self,
        command: AdminCommand,
        now_unix: i64,
    ) -> Result<AdminResponse, DaemonError> {
        if !matches!(
            command,
            AdminCommand::Status | AdminCommand::Initialize { .. }
        ) && !self.initialized()?
        {
            return Err(DaemonError::NotInitialized);
        }
        match command {
            AdminCommand::Status => Ok(AdminResponse::Status {
                status: self.status(now_unix)?,
            }),
            AdminCommand::GenerateSiteCandidate => {
                self.candidates
                    .retain(|_, candidate| candidate.expires_unix > now_unix);
                let identity = OnionIdentity::generate()?;
                let candidate_id = random_path_token()?;
                let digest = token_digest(&candidate_id);
                let expires_unix = now_unix
                    .checked_add(CANDIDATE_LIFETIME_SECONDS)
                    .ok_or(DaemonError::InvalidTimestamp(now_unix))?;
                let onion_hostname = identity.hostname().to_owned();
                self.candidates.insert(
                    digest,
                    GeneratedCandidate {
                        identity,
                        expires_unix,
                    },
                );
                Ok(AdminResponse::SiteCandidate {
                    candidate_id: torkitten_core::SensitiveString::new(candidate_id),
                    onion_hostname,
                    expires_unix,
                })
            }
            AdminCommand::Initialize { password } => {
                if self.initialized()? {
                    return Err(DaemonError::AlreadyInitialized);
                }
                let password = hash_password(password.expose())?;
                let mut recovery_pepper = [0_u8; 32];
                getrandom::fill(&mut recovery_pepper).map_err(DaemonError::Random)?;
                self.store.create_auth_account(
                    Uuid::new_v4(),
                    &AccountOwner::Administrator,
                    "Administrator",
                    Some(&password),
                    None,
                    &recovery_pepper,
                )?;
                Ok(AdminResponse::Ok)
            }
            AdminCommand::AuthenticateAdministrator { password } => {
                self.authenticate_administrator(password.expose(), now_unix)
            }
            AdminCommand::ValidateAdministratorSession { session } => {
                let fresh = self.authorize_administrator(session.expose(), None, now_unix)?;
                Ok(AdminResponse::AdministratorAuthorized { fresh })
            }
            AdminCommand::AuthorizeAdministratorMutation { session, csrf } => {
                let fresh =
                    self.authorize_administrator(session.expose(), Some(csrf.expose()), now_unix)?;
                Ok(AdminResponse::AdministratorAuthorized { fresh })
            }
            AdminCommand::LogoutAdministrator { session, csrf } => {
                self.authorize_administrator(session.expose(), Some(csrf.expose()), now_unix)?;
                let session = SessionToken::parse(session.expose().to_owned())?;
                self.store.revoke_session(&session)?;
                Ok(AdminResponse::Ok)
            }
            AdminCommand::CreateSite { site } => {
                if self.store.site(&site.id)?.is_some() {
                    return Err(DaemonError::SiteAlreadyExists(site.id));
                }
                let mut candidate = self.store.gateway_config()?;
                candidate.sites.push(site.clone());
                candidate.validate()?;
                self.apply_runtime_before_store(&candidate, now_unix)?;
                if let Err(error) = self.store.put_site(&site) {
                    self.restore_stored_runtime(now_unix, &error.to_string())?;
                    return Err(error.into());
                }
                Ok(AdminResponse::Ok)
            }
            AdminCommand::CreateGeneratedSite { site, candidate_id } => {
                let candidate = self
                    .candidates
                    .remove(&token_digest(candidate_id.expose()))
                    .ok_or(DaemonError::CandidateNotFound)?;
                if candidate.expires_unix <= now_unix {
                    return Err(DaemonError::CandidateExpired);
                }
                self.create_generated_site(site, &candidate.identity, now_unix)
            }
            AdminCommand::RenameSite {
                site_id,
                display_name,
            } => {
                let mut site = self.required_site(&site_id)?;
                site.display_name = display_name;
                self.put_existing_site(&site, now_unix)
            }
            AdminCommand::RemoveSite { site_id } => {
                let old = self.required_site(&site_id)?;
                let mut candidate = self.store.gateway_config()?;
                candidate.sites.retain(|site| site.id != site_id);
                self.apply_runtime_before_store(&candidate, now_unix)?;
                if let Err(error) = self.store.remove_site(&site_id) {
                    self.restore_runtime(&Self::config_with_site(candidate, old), now_unix)?;
                    return Err(error.into());
                }
                self.remove_runtime_tls(&site_id)?;
                self.tor.remove_site_state(&site_id)?;
                self.bootstrap_windows.remove(&site_id);
                Ok(AdminResponse::Ok)
            }
            AdminCommand::SetSiteEnabled { site_id, enabled } => {
                let mut site = self.required_site(&site_id)?;
                site.enabled = enabled;
                self.put_existing_site(&site, now_unix)
            }
            AdminCommand::StopSite { site_id } => {
                let mut site = self.required_site(&site_id)?;
                site.enabled = false;
                self.put_existing_site(&site, now_unix)
            }
            AdminCommand::PutMapping { site_id, mapping } => {
                let mut site = self.required_site(&site_id)?;
                site.mappings.retain(|current| current.id != mapping.id);
                site.mappings.push(mapping);
                self.put_existing_site(&site, now_unix)
            }
            AdminCommand::RemoveMapping {
                site_id,
                mapping_id,
            } => {
                let mut site = self.required_site(&site_id)?;
                let before = site.mappings.len();
                site.mappings.retain(|mapping| mapping.id != mapping_id);
                if site.mappings.len() == before {
                    return Err(StoreError::MappingNotFound {
                        site_id,
                        mapping_id,
                    }
                    .into());
                }
                self.put_existing_site(&site, now_unix)
            }
            AdminCommand::SetMappingEnabled {
                site_id,
                mapping_id,
                enabled,
            } => {
                let mut site = self.required_site(&site_id)?;
                let mapping = site
                    .mappings
                    .iter_mut()
                    .find(|mapping| mapping.id == mapping_id)
                    .ok_or_else(|| StoreError::MappingNotFound {
                        site_id: site_id.clone(),
                        mapping_id,
                    })?;
                mapping.enabled = enabled;
                self.put_existing_site(&site, now_unix)
            }
            AdminCommand::TestMapping { site_id, mapping } => {
                self.required_site(&site_id)?;
                mapping.validate()?;
                let reachable = test_mapping(&mapping);
                Ok(AdminResponse::MappingTested {
                    site_id,
                    mapping_id: mapping.id,
                    reachable,
                })
            }
            AdminCommand::OpenCertificateBootstrap { site_id, seconds } => {
                if seconds == 0 || seconds > MAX_BOOTSTRAP_SECONDS {
                    return Err(DaemonError::InvalidBootstrapDuration(seconds));
                }
                let site = self.required_site(&site_id)?;
                if !site.enabled {
                    return Err(DaemonError::BootstrapSiteDisabled(site_id));
                }
                let onion_hostname = self.tor.onion_hostname(&site.id)?;
                let window = BootstrapWindow {
                    path_token: random_path_token()?,
                    expires_unix: now_unix
                        .checked_add(i64::from(seconds))
                        .ok_or(DaemonError::InvalidTimestamp(now_unix))?,
                };
                let previous = self
                    .bootstrap_windows
                    .insert(site.id.clone(), window.clone());
                let config = self.store.gateway_config()?;
                if let Err(error) = self
                    .validate_runtime(&config, now_unix)
                    .and_then(|()| self.install_runtime(&config, now_unix))
                {
                    match previous {
                        Some(previous) => {
                            self.bootstrap_windows.insert(site.id.clone(), previous);
                        }
                        None => {
                            self.bootstrap_windows.remove(&site.id);
                        }
                    }
                    return Err(error);
                }
                self.maintenance_enabled = true;
                Ok(AdminResponse::BootstrapOpened {
                    site_id: site.id,
                    url: format!("http://{onion_hostname}/{}/root-ca.pem", window.path_token),
                    expires_unix: window.expires_unix,
                })
            }
            AdminCommand::CloseCertificateBootstrap { site_id } => {
                self.required_site(&site_id)?;
                self.bootstrap_windows.remove(&site_id);
                let config = self.store.gateway_config()?;
                self.validate_runtime(&config, now_unix)?;
                self.install_runtime(&config, now_unix)?;
                Ok(AdminResponse::Ok)
            }
            AdminCommand::ControlComponent { component, action } => {
                if self.store.publication_settings()?.emergency_disabled
                    && action != ComponentAction::Stop
                {
                    return Err(DaemonError::EmergencyLatchSet);
                }
                self.services.control(component, action)?;
                self.maintenance_enabled = action != ComponentAction::Stop;
                Ok(AdminResponse::Ok)
            }
            AdminCommand::SetResumeAfterBoot { enabled } => {
                self.store.set_resume_after_boot(enabled)?;
                Ok(AdminResponse::Ok)
            }
            AdminCommand::EmergencyDisable => {
                self.store.set_emergency_disabled(true)?;
                self.bootstrap_windows.clear();
                self.maintenance_enabled = false;
                self.stop_publication()?;
                Ok(AdminResponse::Ok)
            }
            AdminCommand::ClearEmergencyDisable => {
                self.store.set_emergency_disabled(false)?;
                self.maintenance_enabled = true;
                let config = self.store.gateway_config()?;
                if let Err(error) = self
                    .validate_runtime(&config, now_unix)
                    .and_then(|()| self.install_runtime(&config, now_unix))
                {
                    self.store.set_emergency_disabled(true)?;
                    self.maintenance_enabled = false;
                    self.stop_publication()?;
                    return Err(error);
                }
                Ok(AdminResponse::Ok)
            }
            AdminCommand::RotateSite { .. }
            | AdminCommand::RestartSite { .. }
            | AdminCommand::EnrollClient { .. }
            | AdminCommand::RevokeClient { .. } => Err(DaemonError::UnsupportedCommand),
        }
    }

    fn status(&mut self, now_unix: i64) -> Result<GatewayStatus, DaemonError> {
        self.bootstrap_windows
            .retain(|_, window| window.expires_unix > now_unix);
        let initialized = self.initialized()?;
        let settings = self.store.publication_settings()?;
        let tor = self.services.state(ManagedComponent::Tor)?;
        let caddy = self.services.state(ManagedComponent::Caddy)?;
        let mode = if !initialized {
            GatewayMode::Uninitialized
        } else if settings.emergency_disabled {
            GatewayMode::Disabled
        } else {
            GatewayMode::Active
        };
        let sites = self
            .store
            .gateway_config()?
            .sites
            .into_iter()
            .map(|site| {
                let onion_hostname = match self.tor.onion_hostname(&site.id) {
                    Ok(hostname) => Some(hostname),
                    Err(TorError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                        None
                    }
                    Err(_) => None,
                };
                let publication =
                    if settings.emergency_disabled || !self.maintenance_enabled || !site.enabled {
                        ComponentState::Stopped
                    } else if tor == ComponentState::Failed || caddy == ComponentState::Failed {
                        ComponentState::Failed
                    } else if tor == ComponentState::Running
                        && caddy == ComponentState::Running
                        && onion_hostname.is_some()
                    {
                        ComponentState::Running
                    } else {
                        ComponentState::Starting
                    };
                SiteStatus {
                    bootstrap_expires_unix: self
                        .bootstrap_windows
                        .get(&site.id)
                        .map(|window| window.expires_unix),
                    site,
                    onion_hostname,
                    publication,
                }
            })
            .collect();
        Ok(GatewayStatus {
            mode,
            sites,
            tor,
            caddy,
            resume_after_boot: settings.resume_after_boot,
        })
    }

    fn authenticate_administrator(
        &self,
        password: &str,
        now_unix: i64,
    ) -> Result<AdminResponse, DaemonError> {
        let account = self
            .store
            .auth_account_for_owner(&AccountOwner::Administrator)?
            .ok_or(DaemonError::InvalidCredentials)?;
        let password_hash = account
            .password_hash
            .as_ref()
            .ok_or(DaemonError::InvalidCredentials)?;
        if !verify_password(password, password_hash)? {
            return Err(DaemonError::InvalidCredentials);
        }
        let session = SessionToken::generate()?;
        let csrf = CsrfToken::generate()?;
        let expires_unix = now_unix
            .checked_add(ADMIN_SESSION_SECONDS)
            .ok_or(DaemonError::InvalidTimestamp(now_unix))?;
        let fresh_until_unix = now_unix
            .checked_add(FRESH_AUTHENTICATION_SECONDS)
            .ok_or(DaemonError::InvalidTimestamp(now_unix))?;
        self.store.put_session(
            account.id,
            &session,
            &csrf,
            now_unix,
            expires_unix,
            fresh_until_unix,
        )?;
        Ok(AdminResponse::AdministratorAuthenticated {
            session: torkitten_core::SensitiveString::new(session.expose()),
            csrf: torkitten_core::SensitiveString::new(csrf.expose()),
            expires_unix,
        })
    }

    fn authorize_administrator(
        &self,
        encoded_session: &str,
        encoded_csrf: Option<&str>,
        now_unix: i64,
    ) -> Result<bool, DaemonError> {
        let session = SessionToken::parse(encoded_session.to_owned())
            .map_err(|_| DaemonError::InvalidCredentials)?;
        let record = self
            .store
            .touch_session(&session, now_unix)?
            .ok_or(DaemonError::InvalidCredentials)?;
        let account = self
            .store
            .auth_account(record.account_id)?
            .ok_or(DaemonError::InvalidCredentials)?;
        if account.owner != AccountOwner::Administrator {
            return Err(DaemonError::InvalidCredentials);
        }
        if let Some(encoded_csrf) = encoded_csrf {
            let csrf =
                CsrfToken::parse(encoded_csrf.to_owned()).map_err(|_| DaemonError::InvalidCsrf)?;
            if !record.csrf_matches(&csrf) {
                return Err(DaemonError::InvalidCsrf);
            }
        }
        Ok(record.is_fresh(now_unix))
    }

    fn put_existing_site(
        &mut self,
        site: &Site,
        now_unix: i64,
    ) -> Result<AdminResponse, DaemonError> {
        let old = self.required_site(&site.id)?;
        site.validate()?;
        let mut candidate = self.store.gateway_config()?;
        candidate.sites.retain(|current| current.id != site.id);
        candidate.sites.push(site.clone());
        candidate.validate()?;
        self.apply_runtime_before_store(&candidate, now_unix)?;
        if let Err(error) = self.store.put_site(site) {
            let old_config = Self::config_with_site(candidate, old);
            self.restore_runtime(&old_config, now_unix)?;
            return Err(error.into());
        }
        Ok(AdminResponse::Ok)
    }

    fn create_generated_site(
        &mut self,
        site: Site,
        identity: &OnionIdentity,
        now_unix: i64,
    ) -> Result<AdminResponse, DaemonError> {
        if self.store.site(&site.id)?.is_some() {
            return Err(DaemonError::SiteAlreadyExists(site.id));
        }
        let stored = self.store.gateway_config()?;
        let mut candidate = stored.clone();
        candidate.sites.push(site.clone());
        candidate.validate()?;
        self.validate_runtime(&candidate, now_unix)?;

        if let Err(error) = self.tor.install_identity(&site.id, identity) {
            let _ = self.tor.remove_site_state(&site.id);
            return Err(error.into());
        }
        if let Err(error) = self.store.put_site(&site) {
            let _ = self.tor.remove_site_state(&site.id);
            return Err(error.into());
        }
        if let Err(error) = self
            .validate_runtime(&candidate, now_unix)
            .and_then(|()| self.install_runtime(&candidate, now_unix))
        {
            let operation = error.to_string();
            let cleanup = (|| -> Result<(), DaemonError> {
                self.store.remove_site(&site.id)?;
                self.tor.remove_site_state(&site.id)?;
                self.restore_runtime(&stored, now_unix)
            })();
            if let Err(cleanup) = cleanup {
                return Err(DaemonError::Rollback {
                    operation,
                    rollback: cleanup.to_string(),
                });
            }
            return Err(error);
        }
        self.maintenance_enabled = true;
        Ok(AdminResponse::Ok)
    }

    fn apply_runtime_before_store(
        &mut self,
        candidate: &GatewayConfig,
        now_unix: i64,
    ) -> Result<(), DaemonError> {
        self.validate_runtime(candidate, now_unix)?;
        if let Err(error) = self.install_runtime(candidate, now_unix) {
            self.restore_stored_runtime(now_unix, &error.to_string())?;
            return Err(error);
        }
        self.maintenance_enabled = true;
        Ok(())
    }

    fn validate_runtime(
        &mut self,
        config: &GatewayConfig,
        now_unix: i64,
    ) -> Result<(), DaemonError> {
        let effective = self.effective_config(config)?;
        let bootstrap_sites = self.active_bootstrap_sites(&effective, now_unix);
        self.tor.validate(&effective, &bootstrap_sites)?;
        let proxy = self.proxy_config(&effective, now_unix)?;
        self.caddy.validate(&proxy)?;
        Ok(())
    }

    fn install_runtime(
        &mut self,
        config: &GatewayConfig,
        now_unix: i64,
    ) -> Result<(), DaemonError> {
        let effective = self.effective_config(config)?;
        let bootstrap_sites = self.active_bootstrap_sites(&effective, now_unix);
        self.tor.prepare_validated(&effective, &bootstrap_sites)?;
        let proxy = self.proxy_config(&effective, now_unix)?;
        self.caddy.prepare(&proxy)?;
        self.active_proxy_config = Some(proxy);

        if effective.sites.iter().any(|site| site.enabled) {
            restart_or_start(&mut self.services, ManagedComponent::Tor)?;
            restart_or_start(&mut self.services, ManagedComponent::Caddy)?;
        } else {
            self.stop_publication()?;
        }
        Ok(())
    }

    fn refresh_proxy(&mut self, config: &GatewayConfig, now_unix: i64) -> Result<(), DaemonError> {
        let effective = self.effective_config(config)?;
        if !effective.sites.iter().any(|site| site.enabled) {
            return Ok(());
        }
        let proxy = self.proxy_config(&effective, now_unix)?;
        if self.active_proxy_config.as_ref() == Some(&proxy) {
            return Ok(());
        }
        if self.services.state(ManagedComponent::Caddy)? == ComponentState::Running {
            self.caddy.reload(&proxy)?;
        } else {
            self.caddy.prepare(&proxy)?;
            self.services
                .control(ManagedComponent::Caddy, ComponentAction::Start)?;
        }
        self.active_proxy_config = Some(proxy);
        Ok(())
    }

    fn proxy_config(
        &mut self,
        config: &GatewayConfig,
        now_unix: i64,
    ) -> Result<ProxyConfig, DaemonError> {
        let active_bootstrap = self.active_bootstrap_sites(config, now_unix);
        let mut sites = Vec::new();
        for site in config.sites.iter().filter(|site| site.enabled) {
            let onion_hostname = match self.tor.onion_hostname(&site.id) {
                Ok(hostname) => hostname,
                Err(TorError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if self.store.site(&site.id)?.is_none() {
                continue;
            }
            let certificate = self.authority.site_certificate(
                &mut self.store,
                &site.id,
                &onion_hostname,
                now_unix,
            )?;
            let certificate_path = self.paths.certificate_path(&site.id);
            let private_key_path = self.paths.private_key_path(&site.id);
            atomic_write(
                &certificate_path,
                certificate.certificate_chain_pem().as_bytes(),
                0o640,
            )?;
            atomic_write(
                &private_key_path,
                certificate.private_key_pem().as_bytes(),
                0o640,
            )?;
            let web = self.paths.web_site_directory(&site.id);
            sites.push(ProxySite {
                site: site.clone(),
                onion_hostname,
                certificate_path,
                private_key_path,
                portal_upstream: web.join("portal.sock"),
                authentication_upstream: web.join("auth.sock"),
                bootstrap_upstream: active_bootstrap
                    .contains(&site.id)
                    .then(|| web.join("bootstrap.sock")),
            });
        }
        Ok(ProxyConfig { sites })
    }

    fn effective_config(&self, config: &GatewayConfig) -> Result<GatewayConfig, DaemonError> {
        let mut effective = config.clone();
        if self.store.publication_settings()?.emergency_disabled {
            for site in &mut effective.sites {
                site.enabled = false;
            }
        }
        Ok(effective)
    }

    fn active_bootstrap_sites(&self, config: &GatewayConfig, now_unix: i64) -> HashSet<SiteId> {
        config
            .sites
            .iter()
            .filter(|site| site.enabled)
            .filter(|site| {
                self.bootstrap_windows
                    .get(&site.id)
                    .is_some_and(|window| window.expires_unix > now_unix)
            })
            .map(|site| site.id.clone())
            .collect()
    }

    fn stop_publication(&mut self) -> Result<(), DaemonError> {
        self.services
            .control(ManagedComponent::Caddy, ComponentAction::Stop)?;
        self.services
            .control(ManagedComponent::Tor, ComponentAction::Stop)?;
        self.active_proxy_config = None;
        Ok(())
    }

    fn restore_stored_runtime(
        &mut self,
        now_unix: i64,
        original_error: &str,
    ) -> Result<(), DaemonError> {
        let stored = self.store.gateway_config()?;
        self.restore_runtime(&stored, now_unix)
            .map_err(|rollback| DaemonError::Rollback {
                operation: original_error.to_owned(),
                rollback: rollback.to_string(),
            })
    }

    fn restore_runtime(
        &mut self,
        config: &GatewayConfig,
        now_unix: i64,
    ) -> Result<(), DaemonError> {
        self.validate_runtime(config, now_unix)?;
        self.install_runtime(config, now_unix)
    }

    fn config_with_site(mut config: GatewayConfig, site: Site) -> GatewayConfig {
        config.sites.retain(|current| current.id != site.id);
        config.sites.push(site);
        config
    }

    fn required_site(&self, site_id: &SiteId) -> Result<Site, DaemonError> {
        self.store
            .site(site_id)?
            .ok_or_else(|| StoreError::SiteNotFound(site_id.clone()).into())
    }

    fn initialized(&self) -> Result<bool, DaemonError> {
        Ok(self
            .store
            .auth_account_for_owner(&AccountOwner::Administrator)?
            .is_some())
    }

    fn remove_runtime_tls(&self, site_id: &SiteId) -> Result<(), DaemonError> {
        for path in [
            self.paths.certificate_path(site_id),
            self.paths.private_key_path(site_id),
        ] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

/// Serves newline-delimited local administration requests on a protected Unix
/// socket. Commands are deliberately serialized so this process remains the
/// only SQLite writer.
///
/// # Errors
///
/// Returns an error when the socket path is unsafe, binding fails, a response
/// cannot be written, or periodic reconciliation fails.
pub async fn serve<S: ServiceControl>(
    mut daemon: Daemon<S>,
    socket_path: &Path,
) -> Result<(), DaemonError> {
    prepare_socket_path(socket_path).await?;
    let listener = UnixListener::bind(socket_path)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;
    let _socket_guard = SocketGuard(socket_path.to_path_buf());
    let mut maintenance = tokio::time::interval(Duration::from_secs(2));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal?;
                return Ok(());
            }
            _ = maintenance.tick() => {
                daemon.maintenance(current_unix_time()?)?;
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let _ = tokio::time::timeout(
                    IPC_REQUEST_TIMEOUT,
                    handle_connection(&mut daemon, stream),
                ).await;
            }
        }
    }
}

async fn handle_connection<S: ServiceControl>(
    daemon: &mut Daemon<S>,
    stream: UnixStream,
) -> Result<(), DaemonError> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let request = read_bounded_line(&mut reader).await?;
    let response = match serde_json::from_slice::<AdminCommand>(&request) {
        Ok(command) => daemon.handle(command, current_unix_time()?),
        Err(error) => AdminResponse::Error {
            code: "invalid_request".to_owned(),
            message: format!("invalid administration request: {error}"),
        },
    };
    let mut encoded = serde_json::to_vec(&response)?;
    encoded.push(b'\n');
    writer.write_all(&encoded).await?;
    writer.shutdown().await?;
    Ok(())
}

async fn read_bounded_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, DaemonError> {
    let mut request = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(DaemonError::IncompleteRequest);
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        let content = newline.map_or(available, |position| &available[..position]);
        if request.len().saturating_add(content.len()) > MAXIMUM_IPC_REQUEST_BYTES {
            return Err(DaemonError::RequestTooLarge);
        }
        request.extend_from_slice(content);
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(request);
        }
    }
}

async fn prepare_socket_path(path: &Path) -> Result<(), DaemonError> {
    let parent = path
        .parent()
        .ok_or_else(|| DaemonError::InvalidPath(path.to_path_buf()))?;
    ensure_directory(parent, 0o770)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() || metadata.file_type().is_symlink() {
                return Err(DaemonError::UnsafeSocket(path.to_path_buf()));
            }
            match UnixStream::connect(path).await {
                Ok(_) => return Err(DaemonError::AlreadyRunning(path.to_path_buf())),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) =>
                {
                    fs::remove_file(path)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn current_unix_time() -> Result<i64, DaemonError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DaemonError::SystemClock)?;
    i64::try_from(duration.as_secs()).map_err(|_| DaemonError::SystemClock)
}

struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn restart_or_start(
    services: &mut impl ServiceControl,
    component: ManagedComponent,
) -> Result<(), ServiceError> {
    let action = if services.state(component)? == ComponentState::Running {
        ComponentAction::Restart
    } else {
        ComponentAction::Start
    };
    services.control(component, action)
}

fn test_mapping(mapping: &Mapping) -> bool {
    match &mapping.target {
        MappingTarget::Tcp { address, port, .. } => {
            TcpStream::connect_timeout(&SocketAddr::new(*address, *port), CONNECT_TIMEOUT).is_ok()
        }
        MappingTarget::Unix { path, .. } => StdUnixStream::connect(path).is_ok(),
    }
}

fn random_path_token() -> Result<String, DaemonError> {
    let mut bytes = [0_u8; 24];
    getrandom::fill(&mut bytes).map_err(DaemonError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn ensure_directory(path: &Path, mode: u32) -> Result<(), DaemonError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(DaemonError::UnsafeDirectory(path.to_path_buf()));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<(), DaemonError> {
    let parent = path
        .parent()
        .ok_or_else(|| DaemonError::InvalidPath(path.to_path_buf()))?;
    ensure_directory(parent, 0o750)?;
    let filename = path.file_name().and_then(OsStr::to_str).unwrap_or("file");
    for _ in 0..32 {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(DaemonError::Random)?;
        let temporary_path = parent.join(format!(
            ".{filename}-{:016x}.tmp",
            u64::from_ne_bytes(random)
        ));
        let temporary = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary_path);
        let Ok(mut temporary) = temporary else {
            let error = temporary.unwrap_err();
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(error.into());
        };
        let result = temporary
            .write_all(contents)
            .and_then(|()| temporary.sync_all())
            .and_then(|()| fs::set_permissions(&temporary_path, fs::Permissions::from_mode(mode)))
            .and_then(|()| fs::rename(&temporary_path, path))
            .and_then(|()| File::open(parent)?.sync_all());
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        return result.map_err(Into::into);
    }
    Err(DaemonError::TemporaryNameExhausted)
}

fn service_command_error(
    operation: &'static str,
    component: ManagedComponent,
    output: &Output,
) -> ServiceError {
    let detail = String::from_utf8_lossy(&output.stderr)
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(4096)
        .collect::<String>();
    ServiceError::CommandFailed {
        operation,
        component,
        status: output.status.code(),
        detail: detail.trim().to_owned(),
    }
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("service manager I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("service manager could not {operation} {component:?} (status {status:?}): {detail}")]
    CommandFailed {
        operation: &'static str,
        component: ManagedComponent,
        status: Option<i32>,
        detail: String,
    },
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("Torkitten has not been initialized")]
    NotInitialized,
    #[error("Torkitten already has an administrator account")]
    AlreadyInitialized,
    #[error("invalid administrator credentials or session")]
    InvalidCredentials,
    #[error("missing or invalid CSRF token")]
    InvalidCsrf,
    #[error("site already exists: {0}")]
    SiteAlreadyExists(SiteId),
    #[error("site must be enabled before opening certificate bootstrap: {0}")]
    BootstrapSiteDisabled(SiteId),
    #[error("bootstrap duration must be 1-{MAX_BOOTSTRAP_SECONDS} seconds, got {0}")]
    InvalidBootstrapDuration(u32),
    #[error("publication is blocked by the persistent emergency latch")]
    EmergencyLatchSet,
    #[error("this command requires the enrollment or identity-rotation implementation")]
    UnsupportedCommand,
    #[error("generated onion candidate was not found")]
    CandidateNotFound,
    #[error("generated onion candidate expired")]
    CandidateExpired,
    #[error("another torkittend instance is listening at {path}", path = .0.display())]
    AlreadyRunning(PathBuf),
    #[error("administration socket path is not a Unix socket: {path}", path = .0.display())]
    UnsafeSocket(PathBuf),
    #[error("administration request exceeded {MAXIMUM_IPC_REQUEST_BYTES} bytes")]
    RequestTooLarge,
    #[error("administration connection closed before a complete request")]
    IncompleteRequest,
    #[error("system clock is before or outside the supported Unix epoch")]
    SystemClock,
    #[error("invalid Unix timestamp: {0}")]
    InvalidTimestamp(i64),
    #[error("state path is not a safe directory: {path}", path = .0.display())]
    UnsafeDirectory(PathBuf),
    #[error("invalid state path: {path}", path = .0.display())]
    InvalidPath(PathBuf),
    #[error("could not allocate a temporary filename")]
    TemporaryNameExhausted,
    #[error("operation failed ({operation}) and restoring runtime state failed ({rollback})")]
    Rollback { operation: String, rollback: String },
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Validation(#[from] torkitten_core::ValidationError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Pki(#[from] PkiError),
    #[error(transparent)]
    Identity(#[from] torkitten_tor::OnionIdentityError),
    #[error(transparent)]
    Tor(#[from] TorError),
    #[error(transparent)]
    Caddy(#[from] CaddyError),
    #[error(transparent)]
    Password(#[from] torkitten_auth::PasswordError),
    #[error(transparent)]
    Token(#[from] torkitten_auth::TokenError),
    #[error(transparent)]
    Service(#[from] ServiceError),
}

impl DaemonError {
    const fn code(&self) -> &'static str {
        match self {
            Self::NotInitialized => "not_initialized",
            Self::AlreadyInitialized => "already_initialized",
            Self::InvalidCredentials => "unauthorized",
            Self::InvalidCsrf => "invalid_csrf",
            Self::SiteAlreadyExists(_) => "site_exists",
            Self::BootstrapSiteDisabled(_) | Self::InvalidBootstrapDuration(_) => {
                "invalid_bootstrap"
            }
            Self::EmergencyLatchSet => "emergency_disabled",
            Self::UnsupportedCommand => "unsupported_command",
            Self::CandidateNotFound | Self::CandidateExpired => "invalid_candidate",
            Self::Validation(_) => "validation_failed",
            Self::Store(_) => "state_failed",
            Self::Pki(_) => "certificate_failed",
            Self::Identity(_) => "identity_failed",
            Self::Tor(_) => "tor_failed",
            Self::Caddy(_) => "caddy_failed",
            Self::Service(_) => "service_failed",
            Self::Password(_) => "password_failed",
            Self::Token(_) => "token_failed",
            Self::InvalidTimestamp(_)
            | Self::AlreadyRunning(_)
            | Self::UnsafeSocket(_)
            | Self::RequestTooLarge
            | Self::IncompleteRequest
            | Self::SystemClock
            | Self::UnsafeDirectory(_)
            | Self::InvalidPath(_)
            | Self::TemporaryNameExhausted
            | Self::Rollback { .. }
            | Self::Random(_)
            | Self::Io(_) => "internal_error",
            Self::Json(_) => "invalid_request",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        sync::{Arc, Mutex},
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use torkitten_core::{MappingId, SensitiveString, Transport};

    use super::*;

    const NOW: i64 = 1_900_000_000;
    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    #[derive(Clone, Default)]
    struct FakeServices {
        states: Arc<Mutex<HashMap<ManagedComponent, ComponentState>>>,
        actions: Arc<Mutex<Vec<(ManagedComponent, ComponentAction)>>>,
        fail_next: Arc<Mutex<Option<ManagedComponent>>>,
    }

    impl ServiceControl for FakeServices {
        fn state(&mut self, component: ManagedComponent) -> Result<ComponentState, ServiceError> {
            Ok(*self
                .states
                .lock()
                .unwrap()
                .get(&component)
                .unwrap_or(&ComponentState::Stopped))
        }

        fn control(
            &mut self,
            component: ManagedComponent,
            action: ComponentAction,
        ) -> Result<(), ServiceError> {
            self.actions.lock().unwrap().push((component, action));
            if self.fail_next.lock().unwrap().take() == Some(component) {
                return Err(ServiceError::CommandFailed {
                    operation: "test",
                    component,
                    status: Some(1),
                    detail: "injected failure".to_owned(),
                });
            }
            let state = match action {
                ComponentAction::Start | ComponentAction::Restart => ComponentState::Running,
                ComponentAction::Stop => ComponentState::Stopped,
            };
            self.states.lock().unwrap().insert(component, state);
            Ok(())
        }
    }

    fn daemon() -> (tempfile::TempDir, Daemon<FakeServices>, FakeServices) {
        let temporary = tempfile::tempdir().unwrap();
        let services = FakeServices::default();
        let daemon = Daemon::open(
            DaemonPaths::new(
                temporary.path().join("state"),
                temporary.path().join("run"),
                "/bin/true",
                "/bin/true",
            ),
            services.clone(),
            NOW,
        )
        .unwrap();
        (temporary, daemon, services)
    }

    fn site() -> Site {
        Site {
            id: SiteId::new("alpha").unwrap(),
            display_name: "Alpha".to_owned(),
            enabled: true,
            mappings: vec![Mapping {
                id: MappingId::new("app").unwrap(),
                display_name: "Application".to_owned(),
                virtual_port: 8443,
                target: MappingTarget::Tcp {
                    address: "127.0.0.1".parse::<IpAddr>().unwrap(),
                    port: 9,
                    transport: Transport::Http,
                },
                enabled: true,
            }],
        }
    }

    fn initialize(daemon: &mut Daemon<FakeServices>) {
        assert!(matches!(
            daemon.handle(
                AdminCommand::Initialize {
                    password: SensitiveString::new("correct horse battery staple"),
                },
                NOW,
            ),
            AdminResponse::Ok
        ));
    }

    #[test]
    fn initialization_is_one_time_and_status_is_persistent() {
        let (_temporary, mut daemon, _services) = daemon();
        let AdminResponse::Status { status } = daemon.handle(AdminCommand::Status, NOW) else {
            panic!("expected status");
        };
        assert_eq!(status.mode, GatewayMode::Uninitialized);
        initialize(&mut daemon);
        let response = daemon.handle(
            AdminCommand::Initialize {
                password: SensitiveString::new("another correct horse password"),
            },
            NOW,
        );
        assert!(matches!(
            response,
            AdminResponse::Error { code, .. } if code == "already_initialized"
        ));
    }

    #[test]
    fn administrator_sessions_are_hashed_csrf_bound_and_revocable() {
        let (_temporary, mut daemon, _services) = daemon();
        initialize(&mut daemon);
        assert!(matches!(
            daemon.handle(
                AdminCommand::AuthenticateAdministrator {
                    password: SensitiveString::new("wrong password value"),
                },
                NOW,
            ),
            AdminResponse::Error { code, .. } if code == "unauthorized"
        ));
        let AdminResponse::AdministratorAuthenticated { session, csrf, .. } = daemon.handle(
            AdminCommand::AuthenticateAdministrator {
                password: SensitiveString::new("correct horse battery staple"),
            },
            NOW,
        ) else {
            panic!("expected authenticated session");
        };
        let session_value = session.expose().to_owned();
        let csrf_value = csrf.expose().to_owned();
        assert!(matches!(
            daemon.handle(
                AdminCommand::ValidateAdministratorSession {
                    session: SensitiveString::new(&session_value),
                },
                NOW + 1,
            ),
            AdminResponse::AdministratorAuthorized { fresh: true }
        ));
        assert!(matches!(
            daemon.handle(
                AdminCommand::AuthorizeAdministratorMutation {
                    session: SensitiveString::new(&session_value),
                    csrf: SensitiveString::new("invalid"),
                },
                NOW + 1,
            ),
            AdminResponse::Error { code, .. } if code == "invalid_csrf"
        ));
        assert!(matches!(
            daemon.handle(
                AdminCommand::LogoutAdministrator {
                    session: SensitiveString::new(&session_value),
                    csrf: SensitiveString::new(&csrf_value),
                },
                NOW + 1,
            ),
            AdminResponse::Ok
        ));
        assert!(matches!(
            daemon.handle(
                AdminCommand::ValidateAdministratorSession {
                    session: SensitiveString::new(session_value),
                },
                NOW + 2,
            ),
            AdminResponse::Error { code, .. } if code == "unauthorized"
        ));
    }

    #[test]
    fn creates_toggles_and_emergency_stops_without_losing_desired_state() {
        let (_temporary, mut daemon, services) = daemon();
        initialize(&mut daemon);
        assert!(matches!(
            daemon.handle(AdminCommand::CreateSite { site: site() }, NOW),
            AdminResponse::Ok
        ));
        assert_eq!(
            services.states.lock().unwrap().get(&ManagedComponent::Tor),
            Some(&ComponentState::Running)
        );
        assert!(matches!(
            daemon.handle(AdminCommand::EmergencyDisable, NOW + 1),
            AdminResponse::Ok
        ));
        let AdminResponse::Status { status } = daemon.handle(AdminCommand::Status, NOW + 1) else {
            panic!("expected status");
        };
        assert_eq!(status.mode, GatewayMode::Disabled);
        assert!(status.sites[0].site.enabled);
        assert_eq!(status.sites[0].publication, ComponentState::Stopped);
        assert!(matches!(
            daemon.handle(
                AdminCommand::ControlComponent {
                    component: ManagedComponent::Tor,
                    action: ComponentAction::Start,
                },
                NOW + 1,
            ),
            AdminResponse::Error { code, .. } if code == "emergency_disabled"
        ));
    }

    #[test]
    fn generated_candidate_is_one_time_and_becomes_the_persistent_identity() {
        let (_temporary, mut daemon, _services) = daemon();
        initialize(&mut daemon);
        let AdminResponse::SiteCandidate {
            candidate_id,
            onion_hostname,
            ..
        } = daemon.handle(AdminCommand::GenerateSiteCandidate, NOW)
        else {
            panic!("expected generated candidate");
        };
        let selected_token = candidate_id.expose().to_owned();
        assert!(matches!(
            daemon.handle(
                AdminCommand::CreateGeneratedSite {
                    site: site(),
                    candidate_id,
                },
                NOW + 1,
            ),
            AdminResponse::Ok
        ));
        let AdminResponse::Status { status } = daemon.handle(AdminCommand::Status, NOW + 1) else {
            panic!("expected status");
        };
        assert_eq!(
            status.sites[0].onion_hostname.as_deref(),
            Some(onion_hostname.as_str())
        );
        assert!(matches!(
            daemon.handle(
                AdminCommand::CreateGeneratedSite {
                    site: Site {
                        id: SiteId::new("beta").unwrap(),
                        ..site()
                    },
                    candidate_id: SensitiveString::new(selected_token),
                },
                NOW + 2,
            ),
            AdminResponse::Error { code, .. } if code == "invalid_candidate"
        ));
    }

    #[test]
    fn service_failure_restores_runtime_and_does_not_commit_site() {
        let (_temporary, mut daemon, services) = daemon();
        initialize(&mut daemon);
        *services.fail_next.lock().unwrap() = Some(ManagedComponent::Tor);
        let response = daemon.handle(AdminCommand::CreateSite { site: site() }, NOW);
        assert!(matches!(
            response,
            AdminResponse::Error { code, .. } if code == "service_failed"
        ));
        let AdminResponse::Status { status } = daemon.handle(AdminCommand::Status, NOW) else {
            panic!("expected status");
        };
        assert!(status.sites.is_empty());
        let torrc = fs::read_to_string(daemon.tor.torrc_path()).unwrap();
        assert!(!torrc.contains("HiddenServiceDir"));
    }

    #[test]
    fn bootstrap_port_opens_for_one_window_and_closes_on_expiry() {
        let (_temporary, mut daemon, _services) = daemon();
        initialize(&mut daemon);
        let site = site();
        let site_id = site.id.clone();
        assert!(matches!(
            daemon.handle(AdminCommand::CreateSite { site }, NOW),
            AdminResponse::Ok
        ));
        let onion_directory = daemon.tor.onion_directory(&site_id);
        fs::write(onion_directory.join("hostname"), format!("{ONION}\n")).unwrap();
        daemon.maintenance(NOW + 1).unwrap();

        let response = daemon.handle(
            AdminCommand::OpenCertificateBootstrap {
                site_id: site_id.clone(),
                seconds: 900,
            },
            NOW + 2,
        );
        let AdminResponse::BootstrapOpened { url, .. } = response else {
            panic!("expected bootstrap response");
        };
        assert!(url.starts_with(&format!("http://{ONION}/")));
        let torrc = fs::read_to_string(daemon.tor.torrc_path()).unwrap();
        assert_eq!(torrc.matches("HiddenServicePort 80 ").count(), 1);

        daemon.maintenance(NOW + 903).unwrap();
        let torrc = fs::read_to_string(daemon.tor.torrc_path()).unwrap();
        assert_eq!(torrc.matches("HiddenServicePort 80 ").count(), 0);
    }

    #[test]
    fn disabled_boot_resume_is_not_reversed_by_maintenance() {
        let (temporary, mut daemon, services) = daemon();
        initialize(&mut daemon);
        assert!(matches!(
            daemon.handle(AdminCommand::CreateSite { site: site() }, NOW),
            AdminResponse::Ok
        ));
        assert!(matches!(
            daemon.handle(AdminCommand::SetResumeAfterBoot { enabled: false }, NOW,),
            AdminResponse::Ok
        ));
        let paths = daemon.paths.clone();
        drop(daemon);

        let mut restarted = Daemon::open(paths, services.clone(), NOW + 1).unwrap();
        restarted.startup(NOW + 1).unwrap();
        let action_count = services.actions.lock().unwrap().len();
        restarted.maintenance(NOW + 2).unwrap();
        assert_eq!(services.actions.lock().unwrap().len(), action_count);
        assert_eq!(
            services.states.lock().unwrap().get(&ManagedComponent::Tor),
            Some(&ComponentState::Stopped)
        );
        drop(restarted);
        drop(temporary);
    }

    #[tokio::test]
    async fn ipc_round_trip_uses_the_shared_command_schema() {
        let (_temporary, mut daemon, _services) = daemon();
        let (server, mut client) = UnixStream::pair().unwrap();
        let server_task = async { handle_connection(&mut daemon, server).await };
        let client_task = async {
            let mut request = serde_json::to_vec(&AdminCommand::Status).unwrap();
            request.push(b'\n');
            client.write_all(&request).await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            serde_json::from_slice::<AdminResponse>(&response).unwrap()
        };
        let (server_result, response) = tokio::join!(server_task, client_task);
        server_result.unwrap();
        let AdminResponse::Status { status } = response else {
            panic!("expected status response");
        };
        assert_eq!(status.mode, GatewayMode::Uninitialized);
    }

    #[test]
    #[ignore = "requires downloaded GitHub Actions Tor and Caddy artifacts"]
    fn downloaded_components_validate_a_daemon_site_transition() {
        let tor = std::env::var_os("TORKITTEN_TOR_BINARY")
            .expect("TORKITTEN_TOR_BINARY must identify the downloaded artifact");
        let caddy = std::env::var_os("TORKITTEN_CADDY_BINARY")
            .expect("TORKITTEN_CADDY_BINARY must identify the downloaded artifact");
        let temporary = tempfile::tempdir().unwrap();
        let services = FakeServices::default();
        let mut daemon = Daemon::open(
            DaemonPaths::new(
                temporary.path().join("state"),
                temporary.path().join("run"),
                tor,
                caddy,
            ),
            services,
            NOW,
        )
        .unwrap();
        initialize(&mut daemon);
        let AdminResponse::SiteCandidate { candidate_id, .. } =
            daemon.handle(AdminCommand::GenerateSiteCandidate, NOW)
        else {
            panic!("expected candidate");
        };
        assert!(matches!(
            daemon.handle(
                AdminCommand::CreateGeneratedSite {
                    site: site(),
                    candidate_id,
                },
                NOW,
            ),
            AdminResponse::Ok
        ));
    }
}
