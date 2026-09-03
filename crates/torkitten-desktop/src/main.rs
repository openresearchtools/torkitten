#![forbid(unsafe_code)]

use std::{
    net::{SocketAddr, TcpStream},
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

use gtk::prelude::*;
use url::Url;
use wry::{NewWindowResponse, WebViewBuilder, WebViewBuilderExtUnix};

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

    let _webview = WebViewBuilder::new()
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
    use super::*;

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
}
