use std::{
    collections::HashMap,
    ffi::OsString,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use torkitten_core::{ComponentAction, ComponentState, ManagedComponent};

use crate::{ServiceControl, ServiceError, service_command_error};

const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);
const STABLE_PROCESS_AGE: Duration = Duration::from_secs(30);
const MAXIMUM_BACKOFF_EXPONENT: u32 = 5;

/// Owns Tor and Caddy directly when Torkitten runs as the container's main
/// process. Native installations continue to use [`crate::SystemdServiceControl`].
#[derive(Debug)]
pub struct DirectServiceControl {
    processes: HashMap<ManagedComponent, ManagedProcess>,
}

impl DirectServiceControl {
    #[must_use]
    pub fn new(
        state_directory: impl Into<PathBuf>,
        runtime_directory: impl Into<PathBuf>,
        tor_binary: impl Into<PathBuf>,
        caddy_binary: impl Into<PathBuf>,
    ) -> Self {
        let state_directory = state_directory.into();
        let runtime_directory = runtime_directory.into();
        let tor_binary = tor_binary.into();
        let caddy_binary = caddy_binary.into();
        let caddy_state = state_directory.join("caddy");
        let caddy_environment = vec![
            (
                OsString::from("HOME"),
                caddy_state.join("home").into_os_string(),
            ),
            (
                OsString::from("XDG_DATA_HOME"),
                caddy_state.join("data").into_os_string(),
            ),
            (
                OsString::from("XDG_CONFIG_HOME"),
                caddy_state.join("config").into_os_string(),
            ),
        ];

        let tor = ProcessSpec {
            binary: tor_binary,
            arguments: vec![
                OsString::from("--defaults-torrc"),
                OsString::from("/dev/null"),
                OsString::from("-f"),
                state_directory.join("tor/torrc").into_os_string(),
            ],
            environment: Vec::new(),
            clear_environment: false,
            stop_signal: "-INT",
            reload: ReloadStrategy::Signal("-HUP"),
        };
        let caddy = ProcessSpec {
            binary: caddy_binary,
            arguments: vec![
                OsString::from("run"),
                OsString::from("--config"),
                caddy_state.join("caddy.json").into_os_string(),
            ],
            environment: caddy_environment.clone(),
            clear_environment: true,
            stop_signal: "-TERM",
            reload: ReloadStrategy::Command(vec![
                OsString::from("reload"),
                OsString::from("--config"),
                caddy_state.join("caddy.json").into_os_string(),
                OsString::from("--address"),
                OsString::from(format!(
                    "unix//{}",
                    runtime_directory.join("caddy/admin.sock").display()
                )),
            ]),
        };
        Self {
            processes: HashMap::from([
                (ManagedComponent::Tor, ManagedProcess::new(tor)),
                (ManagedComponent::Caddy, ManagedProcess::new(caddy)),
            ]),
        }
    }

    fn process(&mut self, component: ManagedComponent) -> &mut ManagedProcess {
        self.processes
            .get_mut(&component)
            .expect("all managed components have a direct process")
    }
}

impl ServiceControl for DirectServiceControl {
    fn state(&mut self, component: ManagedComponent) -> Result<ComponentState, ServiceError> {
        self.process(component).state()
    }

    fn control(
        &mut self,
        component: ManagedComponent,
        action: ComponentAction,
    ) -> Result<(), ServiceError> {
        let process = self.process(component);
        match action {
            ComponentAction::Start => process.start(true),
            ComponentAction::Stop => process.stop(component),
            ComponentAction::Restart => {
                process.stop(component)?;
                process.start(true)
            }
        }
    }

    fn reload(&mut self, component: ManagedComponent) -> Result<(), ServiceError> {
        self.process(component).reload(component)
    }

    fn reconcile(&mut self) {
        for process in self.processes.values_mut() {
            process.reconcile();
        }
    }
}

impl Drop for DirectServiceControl {
    fn drop(&mut self) {
        for (component, process) in &mut self.processes {
            let _ = process.stop(*component);
        }
    }
}

#[derive(Debug)]
struct ManagedProcess {
    spec: ProcessSpec,
    child: Option<Child>,
    desired_running: bool,
    crash_count: u32,
    retry_at: Option<Instant>,
    started_at: Option<Instant>,
}

impl ManagedProcess {
    fn new(spec: ProcessSpec) -> Self {
        Self {
            spec,
            child: None,
            desired_running: false,
            crash_count: 0,
            retry_at: None,
            started_at: None,
        }
    }

    fn state(&mut self) -> Result<ComponentState, ServiceError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(if self.desired_running {
                ComponentState::Failed
            } else {
                ComponentState::Stopped
            });
        };
        if child.try_wait()?.is_none() {
            if self
                .started_at
                .is_some_and(|started| started.elapsed() >= STABLE_PROCESS_AGE)
            {
                self.crash_count = 0;
            }
            Ok(ComponentState::Running)
        } else {
            self.child = None;
            self.started_at = None;
            if self.desired_running {
                self.schedule_retry();
                Ok(ComponentState::Failed)
            } else {
                Ok(ComponentState::Stopped)
            }
        }
    }

    fn start(&mut self, reset_backoff: bool) -> Result<(), ServiceError> {
        if self.state()? == ComponentState::Running {
            self.desired_running = true;
            return Ok(());
        }
        self.desired_running = true;
        if reset_backoff {
            self.crash_count = 0;
        }
        match self.spec.command().spawn() {
            Ok(child) => {
                self.child = Some(child);
                self.retry_at = None;
                self.started_at = Some(Instant::now());
                Ok(())
            }
            Err(error) => {
                self.schedule_retry();
                Err(error.into())
            }
        }
    }

    fn stop(&mut self, component: ManagedComponent) -> Result<(), ServiceError> {
        self.desired_running = false;
        self.retry_at = None;
        self.crash_count = 0;
        self.started_at = None;
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        let output = signal(child.id(), self.spec.stop_signal)?;
        if !output.status.success() && child.try_wait()?.is_none() {
            let error = service_command_error("stop direct process", component, &output);
            child.kill()?;
            child.wait()?;
            return Err(error);
        }
        let deadline = Instant::now() + STOP_TIMEOUT;
        while Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            thread::sleep(STOP_POLL_INTERVAL);
        }
        child.kill()?;
        child.wait()?;
        Ok(())
    }

    fn reload(&mut self, component: ManagedComponent) -> Result<(), ServiceError> {
        if self.state()? != ComponentState::Running {
            return Err(ServiceError::CommandFailed {
                operation: "reload direct process",
                component,
                status: None,
                detail: "component is not running".to_owned(),
            });
        }
        match &self.spec.reload {
            ReloadStrategy::Signal(signal_name) => {
                let child = self.child.as_ref().expect("running process has a child");
                let output = signal(child.id(), signal_name)?;
                if output.status.success() {
                    Ok(())
                } else {
                    Err(service_command_error(
                        "reload direct process",
                        component,
                        &output,
                    ))
                }
            }
            ReloadStrategy::Command(arguments) => {
                let output = self.spec.auxiliary_command(arguments).output()?;
                if output.status.success() {
                    Ok(())
                } else {
                    Err(service_command_error(
                        "reload direct process",
                        component,
                        &output,
                    ))
                }
            }
        }
    }

    fn reconcile(&mut self) {
        let _ = self.state();
        if self.desired_running
            && self.child.is_none()
            && self
                .retry_at
                .is_some_and(|retry_at| retry_at <= Instant::now())
        {
            let _ = self.start(false);
        }
    }

    fn schedule_retry(&mut self) {
        self.crash_count = self.crash_count.saturating_add(1);
        let exponent = self
            .crash_count
            .saturating_sub(1)
            .min(MAXIMUM_BACKOFF_EXPONENT);
        self.retry_at = Some(Instant::now() + Duration::from_secs(1_u64 << exponent));
    }
}

#[derive(Debug)]
struct ProcessSpec {
    binary: PathBuf,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    clear_environment: bool,
    stop_signal: &'static str,
    reload: ReloadStrategy,
}

impl ProcessSpec {
    fn command(&self) -> Command {
        let mut command = self.auxiliary_command(&self.arguments);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        command
    }

    fn auxiliary_command(&self, arguments: &[OsString]) -> Command {
        let mut command = Command::new(&self.binary);
        if self.clear_environment {
            command.env_clear();
        }
        command
            .args(arguments)
            .envs(self.environment.iter().cloned());
        command
    }
}

#[derive(Debug)]
enum ReloadStrategy {
    Signal(&'static str),
    Command(Vec<OsString>),
}

fn signal(pid: u32, signal_name: &str) -> Result<std::process::Output, ServiceError> {
    Ok(Command::new("/bin/kill")
        .arg(signal_name)
        .arg(pid.to_string())
        .output()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sleep_process() -> ManagedProcess {
        ManagedProcess::new(ProcessSpec {
            binary: PathBuf::from("/bin/sleep"),
            arguments: vec![OsString::from("30")],
            environment: Vec::new(),
            clear_environment: false,
            stop_signal: "-TERM",
            reload: ReloadStrategy::Signal("-HUP"),
        })
    }

    #[test]
    fn starts_and_gracefully_stops_a_direct_child() {
        let mut process = sleep_process();
        process.start(true).unwrap();
        assert_eq!(process.state().unwrap(), ComponentState::Running);
        process.stop(ManagedComponent::Tor).unwrap();
        assert_eq!(process.state().unwrap(), ComponentState::Stopped);
    }

    #[test]
    fn a_crashed_desired_child_is_backed_off() {
        let mut process = ManagedProcess::new(ProcessSpec {
            binary: PathBuf::from("/bin/false"),
            arguments: Vec::new(),
            environment: Vec::new(),
            clear_environment: false,
            stop_signal: "-TERM",
            reload: ReloadStrategy::Signal("-HUP"),
        });
        process.start(true).unwrap();
        for _ in 0..20 {
            if process.state().unwrap() == ComponentState::Failed {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(process.state().unwrap(), ComponentState::Failed);
        assert!(process.desired_running);
        assert_eq!(process.crash_count, 1);
        assert!(
            process
                .retry_at
                .is_some_and(|retry_at| retry_at > Instant::now())
        );
    }
}
