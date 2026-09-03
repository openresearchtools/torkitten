#![forbid(unsafe_code)]

use std::{
    fs,
    net::{SocketAddr, TcpStream},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

use gtk::prelude::*;
use url::Url;
use wry::{NewWindowResponse, WebContext, WebViewBuilder, WebViewBuilderExtUnix};

const ADMIN_URL: &str = "http://127.0.0.1:12755/";
const ADMIN_PORT: u16 = 12_755;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(12);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
const RETRY_INTERVAL: Duration = Duration::from_millis(150);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("torkitten-desktop: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_administration(
        SocketAddr::from(([127, 0, 0, 1], ADMIN_PORT)),
        STARTUP_TIMEOUT,
    )?;
    gtk::init()?;
    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title("Torkitten");
    window.set_default_size(1180, 780);
    window.set_size_request(420, 480);
    window.connect_delete_event(|_, _| {
        gtk::main_quit();
        gtk::glib::Propagation::Proceed
    });

    let profile_directory = prepare_webview_profile(&gtk::glib::user_data_dir())?;
    let mut web_context = WebContext::new(Some(profile_directory));
    let _webview = WebViewBuilder::new_with_web_context(&mut web_context)
        .with_url(ADMIN_URL)
        .with_user_agent("Torkitten Desktop/0.1 WebKitGTK")
        .with_navigation_handler(|url| navigation_is_local(&url))
        .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
        .with_clipboard(true)
        .build_gtk(&window)?;
    window.show_all();
    gtk::main();
    Ok(())
}

fn prepare_webview_profile(user_data_directory: &Path) -> std::io::Result<PathBuf> {
    if !user_data_directory.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the desktop data directory must be absolute",
        ));
    }
    let application_directory = user_data_directory.join("torkitten");
    ensure_private_directory(&application_directory)?;
    let profile_directory = application_directory.join("webview");
    ensure_private_directory(&profile_directory)?;
    Ok(profile_directory)
}

fn ensure_private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("desktop data path is not a directory: {}", path.display()),
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn wait_for_administration(address: SocketAddr, timeout: Duration) -> std::io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(_) => return Ok(()),
            Err(_) if Instant::now() < deadline => {
                thread::sleep(RETRY_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
}

fn navigation_is_local(candidate: &str) -> bool {
    let Ok(url) = Url::parse(candidate) else {
        return false;
    };
    url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port_or_known_default() == Some(12_755)
        && url.username().is_empty()
        && url.password().is_none()
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEMPORARY_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMPORARY_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "torkitten-desktop-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn navigation_never_leaves_the_exact_local_control_origin() {
        for allowed in [
            "http://127.0.0.1:12755/",
            "http://127.0.0.1:12755/api/status",
            "http://127.0.0.1:12755/#settings",
        ] {
            assert!(navigation_is_local(allowed), "rejected {allowed}");
        }
        for denied in [
            "https://127.0.0.1:12755/",
            "http://localhost:12755/",
            "http://127.0.0.1:12756/",
            "http://user@127.0.0.1:12755/",
            "https://example.onion/",
            "file:///etc/passwd",
        ] {
            assert!(!navigation_is_local(denied), "accepted {denied}");
        }
    }

    #[test]
    fn webview_profile_is_persistent_and_private() {
        let temporary = TemporaryDirectory::new();
        let profile = prepare_webview_profile(temporary.path()).unwrap();
        assert_eq!(profile, temporary.path().join("torkitten/webview"));
        for directory in [profile.parent().unwrap(), profile.as_path()] {
            let metadata = fs::metadata(directory).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
        assert_eq!(prepare_webview_profile(temporary.path()).unwrap(), profile);
    }

    #[test]
    fn webview_profile_repairs_existing_directory_permissions() {
        let temporary = TemporaryDirectory::new();
        let application = temporary.path().join("torkitten");
        let profile = application.join("webview");
        fs::create_dir(&application).unwrap();
        fs::create_dir(&profile).unwrap();
        fs::set_permissions(&application, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o777)).unwrap();

        prepare_webview_profile(temporary.path()).unwrap();

        assert_eq!(
            fs::metadata(application).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(profile).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn webview_profile_rejects_relative_and_unsafe_paths() {
        assert!(prepare_webview_profile(Path::new("relative")).is_err());

        let temporary = TemporaryDirectory::new();
        let target = temporary.path().join("target");
        fs::create_dir(&target).unwrap();
        symlink(&target, temporary.path().join("torkitten")).unwrap();
        assert!(prepare_webview_profile(temporary.path()).is_err());

        let temporary = TemporaryDirectory::new();
        let application = temporary.path().join("torkitten");
        fs::create_dir(&application).unwrap();
        symlink(&target, application.join("webview")).unwrap();
        assert!(prepare_webview_profile(temporary.path()).is_err());

        let temporary = TemporaryDirectory::new();
        fs::write(temporary.path().join("torkitten"), b"not a directory").unwrap();
        assert!(prepare_webview_profile(temporary.path()).is_err());
    }
}
