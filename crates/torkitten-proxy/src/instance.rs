use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use getrandom::fill;
use thiserror::Error;
use torkitten_core::SiteId;

use crate::{CaddyPaths, ProxyConfig};

/// Owns the one application-controlled Caddy process and its atomically
/// validated configuration.
#[derive(Clone, Debug)]
pub struct CaddyInstance {
    paths: CaddyPaths,
}

impl CaddyInstance {
    #[must_use]
    pub fn new(paths: CaddyPaths) -> Self {
        Self { paths }
    }

    #[must_use]
    pub fn paths(&self) -> &CaddyPaths {
        &self.paths
    }

    /// Renders, validates with the real Caddy binary, and atomically installs
    /// a complete configuration without contacting a running process.
    ///
    /// # Errors
    ///
    /// Returns an error when inputs are invalid, private directories or the
    /// staged file cannot be created, or Caddy rejects the configuration.
    pub fn prepare(&self, config: &ProxyConfig) -> Result<(), CaddyError> {
        self.ensure_directories(config)?;
        let staged = self.stage(config)?;
        self.validate_staged(staged.path())?;
        staged.commit(&self.paths.config_path())
    }

    /// Atomically installs a validated configuration and asks the running
    /// Caddy process to load it. If the live reload fails, the on-disk file is
    /// restored to the last working configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when rendering, validation, installation, reload, or
    /// restoration of the last working file fails.
    pub fn reload(&self, config: &ProxyConfig) -> Result<(), CaddyError> {
        self.ensure_directories(config)?;
        let staged = self.stage(config)?;
        self.validate_staged(staged.path())?;

        let active = self.paths.config_path();
        let previous = match fs::read(&active) {
            Ok(contents) => Some(contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        staged.commit(&active)?;

        let reload = match self.reload_command().output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => command_failure("reload", output.status, &output.stderr),
            Err(error) => CaddyError::Io(error),
        };
        let restoration = match previous {
            Some(contents) => atomic_write(&active, &contents, 0o600),
            None => remove_file_and_sync(&active),
        };
        match restoration {
            Ok(()) => Err(reload),
            Err(rollback) => Err(CaddyError::ReloadRollback {
                reload: reload.to_string(),
                rollback: rollback.to_string(),
            }),
        }
    }

    /// Returns a command that launches only Torkitten's bundled Caddy with the
    /// installed JSON configuration.
    #[must_use]
    pub fn command(&self) -> Command {
        let mut command = self.base_command();
        command
            .arg("run")
            .arg("--config")
            .arg(self.paths.config_path());
        command
    }

    /// Returns a command that loads and provisions the installed
    /// configuration without starting listeners.
    #[must_use]
    pub fn validate_command(&self) -> Command {
        self.validate_command_for(&self.paths.config_path())
    }

    fn reload_command(&self) -> Command {
        let mut command = self.base_command();
        command
            .arg("reload")
            .arg("--config")
            .arg(self.paths.config_path())
            .arg("--address")
            .arg(unix_admin_address(&self.paths.admin_socket()));
        command
    }

    fn validate_command_for(&self, config_path: &Path) -> Command {
        let mut command = self.base_command();
        command.arg("validate").arg("--config").arg(config_path);
        command
    }

    fn base_command(&self) -> Command {
        let mut command = Command::new(&self.paths.binary);
        command
            .env_clear()
            .env("HOME", self.paths.state_directory.join("home"))
            .env("XDG_DATA_HOME", self.paths.state_directory.join("data"))
            .env("XDG_CONFIG_HOME", self.paths.state_directory.join("config"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn ensure_directories(&self, config: &ProxyConfig) -> Result<(), CaddyError> {
        validate_absolute_path(&self.paths.binary)?;
        validate_absolute_path(&self.paths.state_directory)?;
        validate_absolute_path(&self.paths.runtime_directory)?;
        ensure_directory(&self.paths.state_directory, 0o700)?;
        ensure_directory(&self.paths.state_directory.join("home"), 0o700)?;
        ensure_directory(&self.paths.state_directory.join("data"), 0o700)?;
        ensure_directory(&self.paths.state_directory.join("config"), 0o700)?;
        ensure_directory(&self.paths.runtime_directory, 0o750)?;
        ensure_directory(&self.paths.runtime_directory.join("sites"), 0o750)?;
        for proxy_site in &config.sites {
            ensure_directory(
                &self.paths.site_runtime_directory(&proxy_site.site.id),
                0o750,
            )?;
        }
        Ok(())
    }

    fn stage(&self, config: &ProxyConfig) -> Result<StagedConfig, CaddyError> {
        let rendered = config.render(&self.paths)?;
        StagedConfig::create(&self.paths.state_directory, &rendered)
    }

    fn validate_staged(&self, path: &Path) -> Result<(), CaddyError> {
        let output = self.validate_command_for(path).output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(command_failure("validate", output.status, &output.stderr))
        }
    }
}

struct StagedConfig {
    path: PathBuf,
}

impl StagedConfig {
    fn create(parent: &Path, contents: &[u8]) -> Result<Self, CaddyError> {
        let (path, mut file) = create_temporary(parent, Some(OsStr::new("caddy.json")))?;
        if let Err(error) = file
            .write_all(contents)
            .and_then(|()| file.sync_all())
            .and_then(|()| fs::set_permissions(&path, fs::Permissions::from_mode(0o600)))
        {
            let _ = fs::remove_file(&path);
            return Err(error.into());
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn commit(mut self, destination: &Path) -> Result<(), CaddyError> {
        fs::rename(&self.path, destination)?;
        self.path = PathBuf::new();
        let parent = destination
            .parent()
            .ok_or_else(|| CaddyError::InvalidPath(destination.to_path_buf()))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

impl Drop for StagedConfig {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn ensure_directory(path: &Path, mode: u32) -> Result<(), CaddyError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(CaddyError::UnsafeDirectory(path.to_path_buf()));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<(), CaddyError> {
    let parent = path
        .parent()
        .ok_or_else(|| CaddyError::InvalidPath(path.to_path_buf()))?;
    ensure_directory(parent, 0o700)?;
    let (temporary_path, mut temporary) = create_temporary(parent, path.file_name())?;
    let result = temporary
        .write_all(contents)
        .and_then(|()| temporary.sync_all())
        .and_then(|()| fs::set_permissions(&temporary_path, fs::Permissions::from_mode(mode)))
        .and_then(|()| fs::rename(&temporary_path, path))
        .and_then(|()| File::open(parent)?.sync_all());
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result.map_err(Into::into)
}

fn remove_file_and_sync(path: &Path) -> Result<(), CaddyError> {
    match fs::remove_file(path) {
        Ok(()) => {
            let parent = path
                .parent()
                .ok_or_else(|| CaddyError::InvalidPath(path.to_path_buf()))?;
            File::open(parent)?.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn create_temporary(
    parent: &Path,
    filename: Option<&OsStr>,
) -> Result<(PathBuf, File), CaddyError> {
    let filename = filename.and_then(OsStr::to_str).unwrap_or("file");
    for _ in 0..32 {
        let mut random = [0_u8; 8];
        fill(&mut random).map_err(CaddyError::Random)?;
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
    Err(CaddyError::TemporaryNameExhausted)
}

fn validate_absolute_path(path: &Path) -> Result<(), CaddyError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        || path
            .to_str()
            .is_none_or(|value| value.contains(['\n', '\r', '\0', '|']))
    {
        return Err(CaddyError::InvalidPath(path.to_path_buf()));
    }
    Ok(())
}

fn unix_admin_address(path: &Path) -> String {
    format!("unix/{}", path.display())
}

fn command_failure(operation: &'static str, status: ExitStatus, stderr: &[u8]) -> CaddyError {
    let detail = String::from_utf8_lossy(stderr)
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(4096)
        .collect::<String>();
    CaddyError::CommandFailed {
        operation,
        status: status.code(),
        detail: detail.trim().to_owned(),
    }
}

#[derive(Debug, Error)]
pub enum CaddyError {
    #[error("duplicate site identity: {0}")]
    DuplicateSiteId(SiteId),
    #[error("duplicate onion hostname: {0}")]
    DuplicateOnionHostname(String),
    #[error("invalid v3 onion hostname: {0}")]
    InvalidOnionHostname(String),
    #[error("invalid filesystem path: {path}", path = .0.display())]
    InvalidPath(PathBuf),
    #[error("path is not a directory: {path}", path = .0.display())]
    UnsafeDirectory(PathBuf),
    #[error("could not allocate a temporary filename")]
    TemporaryNameExhausted,
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
    #[error("Caddy {operation} failed with status {status:?}: {detail}")]
    CommandFailed {
        operation: &'static str,
        status: Option<i32>,
        detail: String,
    },
    #[error("Caddy reload failed ({reload}) and restoring its configuration failed ({rollback})")]
    ReloadRollback { reload: String, rollback: String },
    #[error(transparent)]
    Validation(#[from] torkitten_core::ValidationError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::{
        io::{ErrorKind, Read, Write},
        net::{IpAddr, TcpListener},
        os::unix::net::UnixListener,
        process::{Child, Command, Stdio},
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    use torkitten_core::{Mapping, MappingId, MappingTarget, Site, Transport};

    use super::*;
    use crate::ProxySite;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    fn proxy_config(temporary: &tempfile::TempDir) -> ProxyConfig {
        ProxyConfig {
            sites: vec![ProxySite {
                site: Site {
                    id: SiteId::new("alpha").unwrap(),
                    display_name: "Alpha".to_owned(),
                    enabled: true,
                    mappings: vec![Mapping {
                        id: MappingId::new("app").unwrap(),
                        display_name: "Application".to_owned(),
                        virtual_port: 8443,
                        target: MappingTarget::Tcp {
                            address: "127.0.0.1".parse::<IpAddr>().unwrap(),
                            port: 3000,
                            transport: Transport::Http,
                        },
                        enabled: true,
                    }],
                },
                onion_hostname: ONION.to_owned(),
                certificate_path: temporary.path().join("alpha.crt"),
                private_key_path: temporary.path().join("alpha.key"),
                portal_upstream: temporary.path().join("portal.sock"),
                authentication_upstream: temporary.path().join("auth.sock"),
                bootstrap_upstream: Some(temporary.path().join("bootstrap.sock")),
            }],
        }
    }

    fn instance(temporary: &tempfile::TempDir, binary: impl Into<PathBuf>) -> CaddyInstance {
        CaddyInstance::new(CaddyPaths::new(
            binary,
            temporary.path().join("state"),
            temporary.path().join("run"),
        ))
    }

    #[test]
    fn invalid_configuration_is_rejected_before_caddy_runs() {
        let temporary = tempfile::tempdir().unwrap();
        let mut config = proxy_config(&temporary);
        config.sites[0].onion_hostname = "not-an-onion".to_owned();
        let error = instance(&temporary, "/missing/caddy")
            .prepare(&config)
            .unwrap_err();
        assert!(matches!(error, CaddyError::InvalidOnionHostname(_)));
        assert!(!temporary.path().join("state/caddy.json").exists());
    }

    #[test]
    #[ignore = "requires TORKITTEN_CADDY_BINARY and OpenSSL"]
    fn downloaded_caddy_validates_generated_multi_listener_configuration() {
        let binary = std::env::var_os("TORKITTEN_CADDY_BINARY")
            .expect("TORKITTEN_CADDY_BINARY must name the downloaded artifact");
        let temporary = tempfile::tempdir().unwrap();
        let config = proxy_config(&temporary);
        generate_certificate(&config);

        let instance = instance(&temporary, PathBuf::from(binary));
        instance.prepare(&config).unwrap();
        assert!(instance.paths().config_path().is_file());
        assert!(
            instance
                .validate_command()
                .output()
                .unwrap()
                .status
                .success()
        );
    }

    #[test]
    #[ignore = "requires TORKITTEN_CADDY_BINARY and OpenSSL"]
    fn downloaded_caddy_denies_then_proxies_a_browser_style_request() {
        let binary = std::env::var_os("TORKITTEN_CADDY_BINARY")
            .expect("TORKITTEN_CADDY_BINARY must name the downloaded artifact");
        let temporary = tempfile::tempdir().unwrap();
        let mut config = proxy_config(&temporary);
        generate_certificate(&config);

        let application = TcpListener::bind("127.0.0.1:0").unwrap();
        let application_port = application.local_addr().unwrap().port();
        let MappingTarget::Tcp { port, .. } = &mut config.sites[0].site.mappings[0].target else {
            panic!("test mapping must be TCP");
        };
        *port = application_port;

        let authentication = UnixListener::bind(&config.sites[0].authentication_upstream).unwrap();
        let (auth_tx, auth_rx) = mpsc::channel();
        let auth_thread = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = authentication.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let request = read_request(&mut stream);
                let allowed = request.contains("Cookie: torkitten_session=valid\r\n");
                auth_tx.send(request).unwrap();
                if allowed {
                    write_response(&mut stream, "204 No Content", "");
                } else {
                    write_response(&mut stream, "401 Unauthorized", "");
                }
            }
        });

        let (app_tx, app_rx) = mpsc::channel();
        let app_thread = thread::spawn(move || {
            let (mut stream, _) = application.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = read_request(&mut stream);
            app_tx.send(request.clone()).unwrap();
            let request_target = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap();
            write_response(&mut stream, "200 OK", request_target);
        });

        let instance = instance(&temporary, PathBuf::from(binary));
        instance.prepare(&config).unwrap();
        let mut child = ProcessGuard::new(instance.command().spawn().unwrap());
        let mapping_socket = instance.paths().site_socket(&config.sites[0].site.id, 8443);
        wait_for_socket(&mapping_socket, &mut child);
        instance.reload(&config).unwrap();

        let unauthorized = openssl_request(
            &mapping_socket,
            &config.sites[0].onion_hostname,
            &config.sites[0].certificate_path,
            None,
        );
        assert!(
            unauthorized.starts_with("HTTP/1.1 401"),
            "unexpected unauthorized response: {unauthorized}"
        );
        assert!(app_rx.try_recv().is_err(), "denied request reached the app");

        let authorized = openssl_request(
            &mapping_socket,
            &config.sites[0].onion_hostname,
            &config.sites[0].certificate_path,
            Some("torkitten_session=valid"),
        );
        assert!(
            authorized.starts_with("HTTP/1.1 200"),
            "unexpected authorized response: {authorized}"
        );
        assert!(authorized.ends_with("/api/items?q=one%20two"));

        let denied_auth = auth_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let allowed_auth = auth_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        for request in [&denied_auth, &allowed_auth] {
            assert!(
                request.contains("GET /authorize HTTP/1.1"),
                "unexpected auth request: {request}"
            );
            assert!(request.contains("X-Torkitten-Site: alpha"), "{request}");
            assert!(request.contains("X-Torkitten-Mapping: app"), "{request}");
            assert!(request.contains("X-Forwarded-Method: GET"), "{request}");
            assert!(
                request.contains("X-Forwarded-Uri: /api/items?q=one%20two"),
                "{request}"
            );
        }

        let app_request = app_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(app_request.starts_with("GET /api/items?q=one%20two HTTP/1.1"));
        assert!(app_request.contains(&format!(
            "X-Forwarded-Host: {}",
            config.sites[0].onion_hostname
        )));
        assert!(app_request.contains("X-Forwarded-Proto: https"));
        assert!(!app_request.contains("X-Torkitten-Site"));
        assert!(!app_request.contains("X-Real-Ip: 203.0.113.9"));

        child.stop();
        auth_thread.join().unwrap();
        app_thread.join().unwrap();
    }

    #[test]
    #[ignore = "requires TORKITTEN_CADDY_BINARY and OpenSSL"]
    fn downloaded_caddy_reload_failure_restores_last_working_file() {
        let binary = std::env::var_os("TORKITTEN_CADDY_BINARY")
            .expect("TORKITTEN_CADDY_BINARY must name the downloaded artifact");
        let temporary = tempfile::tempdir().unwrap();
        let mut config = proxy_config(&temporary);
        generate_certificate(&config);
        let instance = instance(&temporary, PathBuf::from(binary));
        instance.prepare(&config).unwrap();
        let active = instance.paths().config_path();
        let previous = fs::read(&active).unwrap();

        config.sites[0].bootstrap_upstream = None;
        let error = instance.reload(&config).unwrap_err();
        assert!(
            matches!(
                error,
                CaddyError::CommandFailed {
                    operation: "reload",
                    ..
                }
            ),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(active).unwrap(), previous);
    }

    #[test]
    #[ignore = "requires TORKITTEN_CADDY_BINARY and OpenSSL"]
    fn downloaded_caddy_fails_closed_when_authentication_is_unavailable() {
        let binary = std::env::var_os("TORKITTEN_CADDY_BINARY")
            .expect("TORKITTEN_CADDY_BINARY must name the downloaded artifact");
        let temporary = tempfile::tempdir().unwrap();
        let mut config = proxy_config(&temporary);
        generate_certificate(&config);
        let application = TcpListener::bind("127.0.0.1:0").unwrap();
        application.set_nonblocking(true).unwrap();
        let MappingTarget::Tcp { port, .. } = &mut config.sites[0].site.mappings[0].target else {
            panic!("test mapping must be TCP");
        };
        *port = application.local_addr().unwrap().port();

        let instance = instance(&temporary, PathBuf::from(binary));
        instance.prepare(&config).unwrap();
        let mut child = ProcessGuard::new(instance.command().spawn().unwrap());
        let mapping_socket = instance.paths().site_socket(&config.sites[0].site.id, 8443);
        wait_for_socket(&mapping_socket, &mut child);

        let response = openssl_request(
            &mapping_socket,
            &config.sites[0].onion_hostname,
            &config.sites[0].certificate_path,
            Some("torkitten_session=valid"),
        );
        assert!(
            response.starts_with("HTTP/1.1 503"),
            "unexpected fail-closed response: {response}"
        );
        assert!(
            matches!(application.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock)
        );
        child.stop();
    }

    fn generate_certificate(config: &ProxyConfig) {
        let certificate = &config.sites[0].certificate_path;
        let private_key = &config.sites[0].private_key_path;
        let output = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                &format!("/CN={ONION}"),
                "-addext",
                &format!("subjectAltName=DNS:{ONION}"),
                "-keyout",
            ])
            .arg(private_key)
            .arg("-out")
            .arg(certificate)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "OpenSSL failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn read_request(stream: &mut impl Read) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0, "peer closed an incomplete HTTP request");
            request.extend_from_slice(&buffer[..count]);
            assert!(request.len() <= 1024 * 1024, "HTTP request was too large");
        }
        String::from_utf8(request).unwrap()
    }

    fn write_response(stream: &mut impl Write, status: &str, body: &str) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
    }

    fn openssl_request(
        socket: &Path,
        hostname: &str,
        certificate: &Path,
        cookie: Option<&str>,
    ) -> String {
        let mut child = Command::new("openssl")
            .args(["s_client", "-quiet", "-verify_return_error", "-unix"])
            .arg(socket)
            .arg("-servername")
            .arg(hostname)
            .arg("-CAfile")
            .arg(certificate)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let cookie = cookie.map_or_else(String::new, |value| format!("Cookie: {value}\r\n"));
        write!(
            child.stdin.take().unwrap(),
            "GET /api/items?q=one%20two HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n{cookie}X-Forwarded-Proto: http\r\nX-Torkitten-Site: forged\r\nX-Real-IP: 203.0.113.9\r\n\r\n"
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "OpenSSL client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn wait_for_socket(path: &Path, child: &mut ProcessGuard) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            assert!(
                child.child.try_wait().unwrap().is_none(),
                "Caddy exited before creating {}",
                path.display()
            );
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("Caddy did not create {}", path.display());
    }

    struct ProcessGuard {
        child: Child,
    }

    impl ProcessGuard {
        fn new(child: Child) -> Self {
            Self { child }
        }

        fn stop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for ProcessGuard {
        fn drop(&mut self) {
            self.stop();
        }
    }
}
