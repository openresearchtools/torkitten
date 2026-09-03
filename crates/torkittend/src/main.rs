use std::{env, ffi::OsString, net::SocketAddr, path::PathBuf, process::ExitCode};

use torkitten_admin_web::AdminWebConfig;
use torkittend::{
    Daemon, DaemonPaths, DirectServiceControl, ServiceControl, SystemdServiceControl, serve,
};

const DEFAULT_STATE_DIRECTORY: &str = "/var/lib/torkitten";
const DEFAULT_RUNTIME_DIRECTORY: &str = "/run/torkitten";
const DEFAULT_TOR_BINARY: &str = "/usr/lib/torkitten/tor";
const DEFAULT_CADDY_BINARY: &str = "/usr/lib/torkitten/caddy";
const DEFAULT_ADMIN_LISTEN: &str = "127.0.0.1:12755";

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("torkittend: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let options = arguments()?;
    let now = unix_time()?;
    let socket = options.paths.admin_socket();
    let remote_socket = options.paths.remote_socket();
    let remote_web =
        torkitten_web::RemoteWebConfig::new(&options.paths.runtime_directory, &remote_socket);
    let services: Box<dyn ServiceControl> = match options.service_manager {
        ServiceManager::Systemd => Box::new(SystemdServiceControl::default()),
        ServiceManager::Direct => Box::new(DirectServiceControl::new(
            &options.paths.state_directory,
            &options.paths.runtime_directory,
            &options.paths.tor_binary,
            &options.paths.caddy_binary,
        )),
    };
    let mut daemon = Daemon::open(options.paths, services, now)?;
    daemon.startup(now)?;
    let web = AdminWebConfig::new(options.admin_listen, &socket);
    let servers = async {
        tokio::try_join!(
            async {
                serve(daemon, &socket)
                    .await
                    .map_err(Box::<dyn std::error::Error>::from)
            },
            async {
                torkitten_admin_web::serve(web)
                    .await
                    .map_err(Box::<dyn std::error::Error>::from)
            },
            async {
                torkitten_web::serve(remote_web)
                    .await
                    .map_err(Box::<dyn std::error::Error>::from)
            },
        )?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    tokio::select! {
        result = servers => result?,
        signal = shutdown_signal() => signal?,
    }
    Ok(())
}

async fn shutdown_signal() -> Result<(), std::io::Error> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

struct LaunchOptions {
    paths: DaemonPaths,
    admin_listen: SocketAddr,
    service_manager: ServiceManager,
}

#[derive(Clone, Copy)]
enum ServiceManager {
    Systemd,
    Direct,
}

fn arguments() -> Result<LaunchOptions, String> {
    let mut state = PathBuf::from(DEFAULT_STATE_DIRECTORY);
    let mut runtime = PathBuf::from(DEFAULT_RUNTIME_DIRECTORY);
    let mut tor = PathBuf::from(DEFAULT_TOR_BINARY);
    let mut caddy = PathBuf::from(DEFAULT_CADDY_BINARY);
    let mut admin_listen = DEFAULT_ADMIN_LISTEN
        .parse::<SocketAddr>()
        .map_err(|_| "invalid built-in administration address".to_owned())?;
    let mut service_manager = ServiceManager::Systemd;
    let mut arguments = env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--help" {
            return Err(
                "usage: torkittend [--state-dir PATH] [--runtime-dir PATH] [--tor-binary PATH] [--caddy-binary PATH] [--admin-listen LOOPBACK:PORT] [--service-manager systemd|direct]"
                    .to_owned(),
            );
        }
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {}", argument.to_string_lossy()))?;
        match argument.to_str() {
            Some("--state-dir") => state = PathBuf::from(value),
            Some("--runtime-dir") => runtime = PathBuf::from(value),
            Some("--tor-binary") => tor = PathBuf::from(value),
            Some("--caddy-binary") => caddy = PathBuf::from(value),
            Some("--admin-listen") => {
                admin_listen = value
                    .to_str()
                    .ok_or_else(|| "administration address must be valid UTF-8".to_owned())?
                    .parse()
                    .map_err(|_| "invalid administration listen address".to_owned())?;
            }
            Some("--service-manager") => {
                service_manager = match value.to_str() {
                    Some("systemd") => ServiceManager::Systemd,
                    Some("direct") => ServiceManager::Direct,
                    _ => return Err("service manager must be systemd or direct".to_owned()),
                };
            }
            _ => return Err(format!("unknown option: {}", display(&argument))),
        }
    }
    let mut paths = DaemonPaths::new(state, runtime, tor, caddy);
    if let Some(user) = env::var_os("TORKITTEN_TOR_SERVICE_USER") {
        let user = user
            .into_string()
            .map_err(|_| "Tor service user must be valid UTF-8".to_owned())?;
        paths = paths.with_tor_service_user(user);
    }
    Ok(LaunchOptions {
        paths,
        admin_listen,
        service_manager,
    })
}

fn display(value: &OsString) -> String {
    value.to_string_lossy().into_owned()
}

fn unix_time() -> Result<i64, String> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
    i64::try_from(duration.as_secs()).map_err(|_| "system clock is out of range".to_owned())
}
