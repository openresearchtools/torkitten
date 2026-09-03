use std::{env, ffi::OsString, path::PathBuf, process::ExitCode};

use torkittend::{Daemon, DaemonPaths, SystemdServiceControl, serve};

const DEFAULT_STATE_DIRECTORY: &str = "/var/lib/torkitten";
const DEFAULT_RUNTIME_DIRECTORY: &str = "/run/torkitten";
const DEFAULT_TOR_BINARY: &str = "/usr/lib/torkitten/tor";
const DEFAULT_CADDY_BINARY: &str = "/usr/lib/torkitten/caddy";

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
    let paths = arguments()?;
    let now = unix_time()?;
    let socket = paths.admin_socket();
    let mut daemon = Daemon::open(paths, SystemdServiceControl::default(), now)?;
    daemon.startup(now)?;
    serve(daemon, &socket).await?;
    Ok(())
}

fn arguments() -> Result<DaemonPaths, String> {
    let mut state = PathBuf::from(DEFAULT_STATE_DIRECTORY);
    let mut runtime = PathBuf::from(DEFAULT_RUNTIME_DIRECTORY);
    let mut tor = PathBuf::from(DEFAULT_TOR_BINARY);
    let mut caddy = PathBuf::from(DEFAULT_CADDY_BINARY);
    let mut arguments = env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--help" {
            return Err(
                "usage: torkittend [--state-dir PATH] [--runtime-dir PATH] [--tor-binary PATH] [--caddy-binary PATH]"
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
            _ => return Err(format!("unknown option: {}", display(&argument))),
        }
    }
    Ok(DaemonPaths::new(state, runtime, tor, caddy))
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
