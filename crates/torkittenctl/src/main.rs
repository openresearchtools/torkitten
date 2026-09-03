#![forbid(unsafe_code)]

use std::{
    collections::VecDeque,
    env,
    ffi::OsString,
    io::{self, BufRead, Read, Write},
    net::IpAddr,
    os::unix::net::UnixStream,
    path::PathBuf,
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

use torkitten_core::{
    AdminCommand, AdminResponse, ComponentAction, GatewayStatus, ManagedComponent, Mapping,
    MappingId, MappingTarget, SensitiveString, Site, SiteId, Transport,
};

const DEFAULT_SOCKET: &str = "/run/torkitten/admin.sock";
const MAXIMUM_RESPONSE_BYTES: u64 = 1024 * 1024;
const GENERATOR_DURATION: Duration = Duration::from_secs(3);
const GENERATOR_INTERVAL: Duration = Duration::from_millis(35);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("torkittenctl: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let (options, command) = parse_arguments(env::args_os().skip(1).collect())?;
    match command {
        ParsedCommand::GenerateSite {
            site_id,
            display_name,
        } => generate_site(&options, site_id, display_name),
        ParsedCommand::RotateSite { site_id } => rotate_site(&options, site_id),
        command => {
            let command = command.into_admin_command()?;
            let response = request(&options.socket, &command).map_err(|error| error.to_string())?;
            print_response(response, options.json)
        }
    }
}

#[derive(Debug)]
struct Options {
    socket: PathBuf,
    json: bool,
}

#[derive(Debug)]
enum ParsedCommand {
    Direct(AdminCommand),
    Initialize,
    GenerateSite {
        site_id: SiteId,
        display_name: String,
    },
    RotateSite {
        site_id: SiteId,
    },
}

impl ParsedCommand {
    fn into_admin_command(self) -> Result<AdminCommand, String> {
        match self {
            Self::Direct(command) => Ok(command),
            Self::Initialize => {
                eprint!("Administrator password (read from stdin): ");
                io::stderr().flush().map_err(|error| error.to_string())?;
                let mut password = String::new();
                io::stdin()
                    .lock()
                    .read_line(&mut password)
                    .map_err(|error| error.to_string())?;
                while matches!(password.as_bytes().last(), Some(b'\n' | b'\r')) {
                    password.pop();
                }
                Ok(AdminCommand::Initialize {
                    password: SensitiveString::new(password),
                })
            }
            Self::GenerateSite { .. } | Self::RotateSite { .. } => {
                Err("internal command dispatch error".to_owned())
            }
        }
    }
}

fn parse_arguments(arguments: Vec<OsString>) -> Result<(Options, ParsedCommand), String> {
    let mut arguments = arguments.into_iter().collect::<VecDeque<_>>();
    let mut socket = env::var_os("TORKITTEN_ADMIN_SOCKET")
        .map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from);
    let mut json = false;
    loop {
        match arguments.front().and_then(|argument| argument.to_str()) {
            Some("--socket") => {
                arguments.pop_front();
                socket = PathBuf::from(required_os(&mut arguments, "socket path")?);
            }
            Some("--json") => {
                arguments.pop_front();
                json = true;
            }
            Some("--help" | "-h") => return Err(usage().to_owned()),
            _ => break,
        }
    }
    let verb = required_text(&mut arguments, "command")?;
    let command = match verb.as_str() {
        "status" => ParsedCommand::Direct(AdminCommand::Status),
        "initialize" => ParsedCommand::Initialize,
        "generate-site" => ParsedCommand::GenerateSite {
            site_id: SiteId::new(required_text(&mut arguments, "site id")?)
                .map_err(|error| error.to_string())?,
            display_name: required_text(&mut arguments, "site name")?,
        },
        "rename-site" => ParsedCommand::Direct(AdminCommand::RenameSite {
            site_id: site_id(&mut arguments)?,
            display_name: required_text(&mut arguments, "site name")?,
        }),
        "remove-site" => ParsedCommand::Direct(AdminCommand::RemoveSite {
            site_id: site_id(&mut arguments)?,
        }),
        "enable-site" | "disable-site" => ParsedCommand::Direct(AdminCommand::SetSiteEnabled {
            site_id: site_id(&mut arguments)?,
            enabled: verb == "enable-site",
        }),
        "stop-site" => ParsedCommand::Direct(AdminCommand::StopSite {
            site_id: site_id(&mut arguments)?,
        }),
        "restart-site" => ParsedCommand::Direct(AdminCommand::RestartSite {
            site_id: site_id(&mut arguments)?,
        }),
        "rotate-site" => ParsedCommand::RotateSite {
            site_id: site_id(&mut arguments)?,
        },
        "add-tcp-mapping" => ParsedCommand::Direct(parse_tcp_mapping(&mut arguments)?),
        "add-unix-mapping" => ParsedCommand::Direct(parse_unix_mapping(&mut arguments)?),
        "remove-mapping" => ParsedCommand::Direct(AdminCommand::RemoveMapping {
            site_id: site_id(&mut arguments)?,
            mapping_id: mapping_id(&mut arguments)?,
        }),
        "enable-mapping" | "disable-mapping" => {
            ParsedCommand::Direct(AdminCommand::SetMappingEnabled {
                site_id: site_id(&mut arguments)?,
                mapping_id: mapping_id(&mut arguments)?,
                enabled: verb == "enable-mapping",
            })
        }
        "test-tcp-mapping" => ParsedCommand::Direct(parse_test_tcp_mapping(&mut arguments)?),
        "open-bootstrap" => {
            let site_id = site_id(&mut arguments)?;
            let seconds = arguments
                .pop_front()
                .map(|value| parse_number(&value, "seconds"))
                .transpose()?
                .unwrap_or(900);
            ParsedCommand::Direct(AdminCommand::OpenCertificateBootstrap { site_id, seconds })
        }
        "close-bootstrap" => ParsedCommand::Direct(AdminCommand::CloseCertificateBootstrap {
            site_id: site_id(&mut arguments)?,
        }),
        "resume-after-boot" => ParsedCommand::Direct(AdminCommand::SetResumeAfterBoot {
            enabled: parse_on_off(&mut arguments)?,
        }),
        "emergency-stop" => ParsedCommand::Direct(AdminCommand::EmergencyDisable),
        "emergency-clear" => ParsedCommand::Direct(AdminCommand::ClearEmergencyDisable),
        "tor" => ParsedCommand::Direct(parse_component(ManagedComponent::Tor, &mut arguments)?),
        "caddy" => ParsedCommand::Direct(parse_component(ManagedComponent::Caddy, &mut arguments)?),
        _ => return Err(format!("unknown command: {verb}\n{}", usage())),
    };
    if !arguments.is_empty() {
        return Err("unexpected trailing arguments".to_owned());
    }
    Ok((Options { socket, json }, command))
}

fn parse_tcp_mapping(arguments: &mut VecDeque<OsString>) -> Result<AdminCommand, String> {
    let site_id = site_id(arguments)?;
    let id = mapping_id(arguments)?;
    let display_name = required_text(arguments, "mapping name")?;
    let virtual_port = required_number(arguments, "virtual port")?;
    let address = required_text(arguments, "loopback address")?
        .parse::<IpAddr>()
        .map_err(|_| "mapping address must be a numeric IP address".to_owned())?;
    let port = required_number(arguments, "target port")?;
    let transport = optional_transport(arguments)?;
    Ok(AdminCommand::PutMapping {
        site_id,
        mapping: Mapping {
            id,
            display_name,
            virtual_port,
            target: MappingTarget::Tcp {
                address,
                port,
                transport,
            },
            enabled: true,
        },
    })
}

fn parse_unix_mapping(arguments: &mut VecDeque<OsString>) -> Result<AdminCommand, String> {
    let site_id = site_id(arguments)?;
    let id = mapping_id(arguments)?;
    let display_name = required_text(arguments, "mapping name")?;
    let virtual_port = required_number(arguments, "virtual port")?;
    let path = PathBuf::from(required_os(arguments, "Unix socket path")?);
    let transport = optional_transport(arguments)?;
    Ok(AdminCommand::PutMapping {
        site_id,
        mapping: Mapping {
            id,
            display_name,
            virtual_port,
            target: MappingTarget::Unix { path, transport },
            enabled: true,
        },
    })
}

fn parse_test_tcp_mapping(arguments: &mut VecDeque<OsString>) -> Result<AdminCommand, String> {
    let site_id = site_id(arguments)?;
    let address = required_text(arguments, "loopback address")?
        .parse::<IpAddr>()
        .map_err(|_| "mapping address must be a numeric IP address".to_owned())?;
    let port = required_number(arguments, "target port")?;
    Ok(AdminCommand::TestMapping {
        site_id,
        mapping: Mapping {
            id: MappingId::new("connection-test").map_err(|error| error.to_string())?,
            display_name: "Connection test".to_owned(),
            virtual_port: 8443,
            target: MappingTarget::Tcp {
                address,
                port,
                transport: Transport::Http,
            },
            enabled: true,
        },
    })
}

fn parse_component(
    component: ManagedComponent,
    arguments: &mut VecDeque<OsString>,
) -> Result<AdminCommand, String> {
    let action = match required_text(arguments, "component action")?.as_str() {
        "start" => ComponentAction::Start,
        "stop" => ComponentAction::Stop,
        "restart" => ComponentAction::Restart,
        _ => return Err("component action must be start, stop, or restart".to_owned()),
    };
    Ok(AdminCommand::ControlComponent { component, action })
}

fn generate_site(options: &Options, site_id: SiteId, display_name: String) -> Result<(), String> {
    let (candidate_id, onion_hostname) = select_candidate(options)?;
    let response = request(
        &options.socket,
        &AdminCommand::CreateGeneratedSite {
            site: Site {
                id: site_id,
                display_name,
                enabled: true,
                mappings: Vec::new(),
            },
            candidate_id,
        },
    )
    .map_err(|error| error.to_string())?;
    match response {
        AdminResponse::Ok if !options.json => {
            println!("Created {onion_hostname}");
            Ok(())
        }
        response => print_response(response, options.json),
    }
}

fn rotate_site(options: &Options, site_id: SiteId) -> Result<(), String> {
    let (candidate_id, onion_hostname) = select_candidate(options)?;
    let response = request(
        &options.socket,
        &AdminCommand::RotateSite {
            site_id,
            candidate_id,
        },
    )
    .map_err(|error| error.to_string())?;
    match response {
        AdminResponse::Ok if !options.json => {
            println!("Rotated site to {onion_hostname}");
            Ok(())
        }
        response => print_response(response, options.json),
    }
}

fn select_candidate(options: &Options) -> Result<(SensitiveString, String), String> {
    let deadline = Instant::now() + GENERATOR_DURATION;
    let mut selected = None;
    let mut count = 0_u64;
    while Instant::now() < deadline {
        let response = request(&options.socket, &AdminCommand::GenerateSiteCandidate)
            .map_err(|error| error.to_string())?;
        let AdminResponse::SiteCandidate {
            candidate_id,
            onion_hostname,
            ..
        } = response
        else {
            return match print_response(response, options.json) {
                Ok(()) => Err("unexpected daemon response while generating identity".to_owned()),
                Err(error) => Err(error),
            };
        };
        count += 1;
        if !options.json {
            print!("\rGenerating candidate {count}: {onion_hostname}");
            io::stdout().flush().map_err(|error| error.to_string())?;
        }
        selected = Some((candidate_id, onion_hostname));
        thread::sleep(GENERATOR_INTERVAL);
    }
    let Some(selected) = selected else {
        return Err("site generator produced no candidate".to_owned());
    };
    if !options.json {
        println!();
    }
    Ok(selected)
}

fn request(socket: &PathBuf, command: &AdminCommand) -> io::Result<AdminResponse> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    serde_json::to_writer(&mut stream, command)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut response = Vec::new();
    stream
        .take(MAXIMUM_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)?;
    if response.len() as u64 > MAXIMUM_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon response is too large",
        ));
    }
    serde_json::from_slice(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn print_response(response: AdminResponse, json: bool) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
        );
        return match response {
            AdminResponse::Error { message, .. } => Err(message),
            _ => Ok(()),
        };
    }
    match response {
        AdminResponse::Ok => {
            println!("ok");
            Ok(())
        }
        AdminResponse::Status { status } => {
            print_status(&status);
            Ok(())
        }
        AdminResponse::BootstrapOpened {
            url, expires_unix, ..
        } => {
            println!("Certificate download: {url}");
            println!("Expires: {expires_unix}");
            Ok(())
        }
        AdminResponse::MappingTested { reachable, .. } => {
            println!(
                "{}",
                if reachable {
                    "reachable"
                } else {
                    "unreachable"
                }
            );
            if reachable {
                Ok(())
            } else {
                Err("mapping target is unreachable".to_owned())
            }
        }
        AdminResponse::Error { message, .. } => Err(message),
        AdminResponse::SiteCandidate { .. }
        | AdminResponse::AdministratorAuthenticated { .. }
        | AdminResponse::AdministratorAuthorized { .. }
        | AdminResponse::DeviceEnrolled { .. } => {
            Err("unexpected sensitive response for this command".to_owned())
        }
    }
}

fn print_status(status: &GatewayStatus) {
    println!("Mode: {:?}", status.mode);
    println!("Tor: {:?}", status.tor);
    println!("Caddy: {:?}", status.caddy);
    println!("Resume after boot: {}", status.resume_after_boot);
    for site in &status.sites {
        println!(
            "{} [{}] {}",
            site.site.display_name,
            site.publication_label(),
            site.onion_hostname
                .as_deref()
                .unwrap_or("generating identity")
        );
        for mapping in &site.site.mappings {
            println!(
                "  {} port {} -> {:?} ({})",
                mapping.display_name,
                mapping.virtual_port,
                mapping.target,
                if mapping.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
        }
    }
}

trait SiteStatusLabel {
    fn publication_label(&self) -> &'static str;
}

impl SiteStatusLabel for torkitten_core::SiteStatus {
    fn publication_label(&self) -> &'static str {
        match self.publication {
            torkitten_core::ComponentState::Stopped => "stopped",
            torkitten_core::ComponentState::Starting => "starting",
            torkitten_core::ComponentState::Running => "running",
            torkitten_core::ComponentState::Failed => "failed",
        }
    }
}

fn site_id(arguments: &mut VecDeque<OsString>) -> Result<SiteId, String> {
    SiteId::new(required_text(arguments, "site id")?).map_err(|error| error.to_string())
}

fn mapping_id(arguments: &mut VecDeque<OsString>) -> Result<MappingId, String> {
    MappingId::new(required_text(arguments, "mapping id")?).map_err(|error| error.to_string())
}

fn required_text(arguments: &mut VecDeque<OsString>, name: &str) -> Result<String, String> {
    required_os(arguments, name)?
        .into_string()
        .map_err(|_| format!("{name} must be valid UTF-8"))
}

fn required_os(arguments: &mut VecDeque<OsString>, name: &str) -> Result<OsString, String> {
    arguments
        .pop_front()
        .ok_or_else(|| format!("missing {name}"))
}

fn required_number<T>(arguments: &mut VecDeque<OsString>, name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    let value = required_os(arguments, name)?;
    parse_number(&value, name)
}

fn parse_number<T>(value: &OsString, name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    value
        .to_str()
        .ok_or_else(|| format!("{name} must be valid UTF-8"))?
        .parse()
        .map_err(|_| format!("invalid {name}"))
}

fn optional_transport(arguments: &mut VecDeque<OsString>) -> Result<Transport, String> {
    match arguments.front().and_then(|value| value.to_str()) {
        None => Ok(Transport::Http),
        Some("http") => {
            arguments.pop_front();
            Ok(Transport::Http)
        }
        Some("https") => {
            arguments.pop_front();
            Ok(Transport::Https)
        }
        Some("h2c") => {
            arguments.pop_front();
            Ok(Transport::H2c)
        }
        Some(_) => Err("transport must be http, https, or h2c".to_owned()),
    }
}

fn parse_on_off(arguments: &mut VecDeque<OsString>) -> Result<bool, String> {
    match required_text(arguments, "on/off value")?.as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err("value must be on or off".to_owned()),
    }
}

fn usage() -> &'static str {
    "usage: torkittenctl [--socket PATH] [--json] COMMAND ...\n\
     commands:\n\
       status | initialize | generate-site ID NAME | rename-site ID NAME\n\
       enable-site ID | disable-site ID | stop-site ID | restart-site ID\n\
       rotate-site ID | remove-site ID\n\
       add-tcp-mapping SITE ID NAME VPORT LOOPBACK PORT [http|https|h2c]\n\
       add-unix-mapping SITE ID NAME VPORT PATH [http|https|h2c]\n\
       enable-mapping SITE ID | disable-mapping SITE ID | remove-mapping SITE ID\n\
       test-tcp-mapping SITE LOOPBACK PORT\n\
       open-bootstrap SITE [SECONDS] | close-bootstrap SITE\n\
       resume-after-boot on|off | emergency-stop | emergency-clear\n\
       tor start|stop|restart | caddy start|stop|restart"
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_site_and_loopback_mapping_commands() {
        let (_, command) = parse_arguments(arguments(&[
            "add-tcp-mapping",
            "alpha",
            "photos",
            "Photos",
            "8443",
            "127.0.0.1",
            "3000",
        ]))
        .unwrap();
        let ParsedCommand::Direct(AdminCommand::PutMapping { site_id, mapping }) = command else {
            panic!("expected mapping command");
        };
        assert_eq!(site_id.as_str(), "alpha");
        assert_eq!(mapping.virtual_port, 8443);
        assert!(mapping.validate().is_ok());
    }

    #[test]
    fn rejects_trailing_and_non_loopback_inputs_during_validation() {
        assert!(parse_arguments(arguments(&["status", "extra"])).is_err());
        let (_, command) = parse_arguments(arguments(&[
            "test-tcp-mapping",
            "alpha",
            "192.0.2.1",
            "3000",
        ]))
        .unwrap();
        let ParsedCommand::Direct(AdminCommand::TestMapping { mapping, .. }) = command else {
            panic!("expected mapping test");
        };
        assert!(mapping.validate().is_err());
    }

    #[test]
    fn exchanges_the_shared_newline_delimited_ipc_schema() {
        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join("admin.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(matches!(
                serde_json::from_str::<AdminCommand>(&line).unwrap(),
                AdminCommand::Status
            ));
            let response = AdminResponse::Status {
                status: GatewayStatus {
                    mode: torkitten_core::GatewayMode::Uninitialized,
                    sites: Vec::new(),
                    tor: torkitten_core::ComponentState::Stopped,
                    caddy: torkitten_core::ComponentState::Stopped,
                    resume_after_boot: true,
                },
            };
            serde_json::to_writer(stream, &response).unwrap();
        });
        let response = request(&socket, &AdminCommand::Status).unwrap();
        assert!(matches!(response, AdminResponse::Status { .. }));
        server.join().unwrap();
    }
}
