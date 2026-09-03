#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    fs,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use askama::Template;
use axum::{
    Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode, Uri,
        header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, COOKIE, LOCATION},
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};
use torkitten_core::{
    MappingId, PortalContext, PortalMapping, PublishedSite, RemoteCommand, RemoteResponse,
    SensitiveString, SiteId,
};

const SESSION_COOKIE: &str = "__Host-torkitten_session";
const MAXIMUM_IPC_RESPONSE_BYTES: u64 = 1024 * 1024;
const IPC_TIMEOUT: Duration = Duration::from_secs(10);
const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct RemoteWebConfig {
    pub runtime_directory: PathBuf,
    pub daemon_socket: PathBuf,
}

impl RemoteWebConfig {
    #[must_use]
    pub fn new(runtime_directory: impl Into<PathBuf>, daemon_socket: impl Into<PathBuf>) -> Self {
        Self {
            runtime_directory: runtime_directory.into(),
            daemon_socket: daemon_socket.into(),
        }
    }
}

#[derive(Clone)]
struct SiteState {
    site_id: SiteId,
    onion_hostname: Arc<str>,
    daemon_socket: Arc<PathBuf>,
}

struct SiteServer {
    onion_hostname: String,
    task: JoinHandle<Result<(), RemoteWebError>>,
}

/// Reconciles one set of site-scoped Unix HTTP listeners with the daemon's
/// enabled publication set. This frontend never binds a TCP socket.
///
/// # Errors
///
/// Returns when IPC or a site listener fails after startup.
pub async fn serve(config: RemoteWebConfig) -> Result<(), RemoteWebError> {
    ensure_directory(&config.runtime_directory.join("web"), 0o770)?;
    let mut servers = HashMap::<SiteId, SiteServer>::new();
    let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Some(failed_id) = servers
            .iter()
            .find_map(|(site_id, server)| server.task.is_finished().then(|| site_id.clone()))
            && let Some(server) = servers.remove(&failed_id)
        {
            return server.task.await.map_err(RemoteWebError::Join)?;
        }
        let sites = match published_sites(&config.daemon_socket).await {
            Ok(sites) => sites,
            Err(RemoteWebError::Connect(_)) if servers.is_empty() => continue,
            Err(error) => return Err(error),
        };
        reconcile_servers(&config, &mut servers, sites);
    }
}

fn reconcile_servers(
    config: &RemoteWebConfig,
    servers: &mut HashMap<SiteId, SiteServer>,
    sites: Vec<PublishedSite>,
) {
    let desired = sites
        .iter()
        .map(|site| (site.site_id.clone(), site.onion_hostname.as_str()))
        .collect::<HashMap<_, _>>();
    servers.retain(|site_id, server| {
        let keep = desired.get(site_id).is_some_and(|hostname| {
            *hostname == server.onion_hostname && !server.task.is_finished()
        });
        if !keep {
            server.task.abort();
        }
        keep
    });
    for site in sites {
        if servers.contains_key(&site.site_id) {
            continue;
        }
        let state = SiteState {
            site_id: site.site_id.clone(),
            onion_hostname: Arc::from(site.onion_hostname.as_str()),
            daemon_socket: Arc::new(config.daemon_socket.clone()),
        };
        let site_directory = config
            .runtime_directory
            .join("web/sites")
            .join(site.site_id.as_str());
        let task = tokio::spawn(serve_site(site_directory, state));
        servers.insert(
            site.site_id,
            SiteServer {
                onion_hostname: site.onion_hostname,
                task,
            },
        );
    }
}

async fn published_sites(daemon_socket: &Path) -> Result<Vec<PublishedSite>, RemoteWebError> {
    match request_daemon(daemon_socket, RemoteCommand::PublishedSites).await? {
        RemoteResponse::PublishedSites { sites } => Ok(sites),
        RemoteResponse::Error { code, message } => Err(RemoteWebError::Daemon { code, message }),
        _ => Err(RemoteWebError::UnexpectedResponse),
    }
}

async fn serve_site(site_directory: PathBuf, state: SiteState) -> Result<(), RemoteWebError> {
    ensure_directory(&site_directory, 0o770)?;
    let portal = bind_site_socket(&site_directory.join("portal.sock"))?;
    let auth = bind_site_socket(&site_directory.join("auth.sock"))?;
    let bootstrap = bind_site_socket(&site_directory.join("bootstrap.sock"))?;
    let _guards = [
        SocketGuard(site_directory.join("portal.sock")),
        SocketGuard(site_directory.join("auth.sock")),
        SocketGuard(site_directory.join("bootstrap.sock")),
    ];
    tokio::try_join!(
        serve_router(portal, portal_router(state.clone())),
        serve_router(auth, auth_router(state.clone())),
        serve_router(bootstrap, bootstrap_router(state)),
    )?;
    Ok(())
}

fn bind_site_socket(path: &Path) -> Result<UnixListener, RemoteWebError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)?;
        }
        Ok(_) => return Err(RemoteWebError::UnsafeSocket(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o220))?;
    Ok(listener)
}

async fn serve_router(listener: UnixListener, router: Router) -> Result<(), RemoteWebError> {
    axum::serve(listener, router)
        .await
        .map_err(RemoteWebError::Serve)
}

fn portal_router(state: SiteState) -> Router {
    Router::new()
        .route("/", get(portal))
        .route("/assets/app.css", get(stylesheet))
        .route("/enroll/{token}", get(enrollment))
        .fallback(not_found)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

fn auth_router(state: SiteState) -> Router {
    Router::new()
        .route("/authorize", get(authorize_mapping))
        .fallback(not_found)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

fn bootstrap_router(state: SiteState) -> Router {
    Router::new()
        .fallback(bootstrap_resource)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn portal(State(state): State<SiteState>, headers: HeaderMap) -> WebResult<Html<String>> {
    let session = cookie(&headers, SESSION_COOKIE).map(SensitiveString::new);
    let response = request_daemon(
        &state.daemon_socket,
        RemoteCommand::PortalContext {
            site_id: state.site_id.clone(),
            session,
        },
    )
    .await?;
    let RemoteResponse::PortalContext { context } = response else {
        return Err(WebError::from_response(response));
    };
    render_portal(context)
}

fn render_portal(context: PortalContext) -> WebResult<Html<String>> {
    let template = PortalTemplate {
        display_name: context.display_name,
        onion_hostname: context.onion_hostname,
        guest_display_name: context.guest_display_name,
        mappings: context.mappings,
    };
    Ok(Html(template.render().map_err(WebError::Template)?))
}

async fn enrollment(
    State(state): State<SiteState>,
    AxumPath(token): AxumPath<String>,
) -> WebResult<Html<String>> {
    let response = request_daemon(
        &state.daemon_socket,
        RemoteCommand::EnrollmentDetails {
            site_id: state.site_id.clone(),
            token: SensitiveString::new(token),
        },
    )
    .await?;
    let RemoteResponse::EnrollmentDetails {
        guest_display_name,
        device_display_name,
        expires_unix,
        ..
    } = response
    else {
        return Err(WebError::from_response(response));
    };
    let template = EnrollmentTemplate {
        guest_display_name,
        device_display_name,
        expires_unix,
    };
    Ok(Html(template.render().map_err(WebError::Template)?))
}

async fn authorize_mapping(
    State(state): State<SiteState>,
    headers: HeaderMap,
) -> WebResult<Response> {
    let header_site = required_header(&headers, "x-torkitten-site")?;
    if header_site != state.site_id.as_str() {
        return Err(WebError::Unauthorized);
    }
    let mapping_id = MappingId::new(required_header(&headers, "x-torkitten-mapping")?)
        .map_err(WebError::Validation)?;
    let Some(session) = cookie(&headers, SESSION_COOKIE) else {
        return safe_portal_redirect(&state);
    };
    let response = request_daemon(
        &state.daemon_socket,
        RemoteCommand::AuthorizeMapping {
            site_id: state.site_id.clone(),
            mapping_id,
            session: SensitiveString::new(session),
        },
    )
    .await?;
    match response {
        RemoteResponse::MappingAuthorized { .. } => Ok(StatusCode::NO_CONTENT.into_response()),
        RemoteResponse::Error { code, .. } if code == "unauthorized" => {
            safe_portal_redirect(&state)
        }
        response => Err(WebError::from_response(response)),
    }
}

fn safe_portal_redirect(state: &SiteState) -> WebResult<Response> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&format!("https://{}/", state.onion_hostname))
            .map_err(WebError::Header)?,
    );
    Ok(response)
}

async fn bootstrap_resource(State(state): State<SiteState>, method: Method, uri: Uri) -> Response {
    match bootstrap_resource_inner(&state, &method, &uri).await {
        Ok(response) => response,
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn bootstrap_resource_inner(
    state: &SiteState,
    method: &Method,
    uri: &Uri,
) -> WebResult<Response> {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return Err(WebError::NotFound);
    }
    let segments = uri.path().split('/').collect::<Vec<_>>();
    let ["", token, filename] = segments.as_slice() else {
        return Err(WebError::NotFound);
    };
    if !matches!(
        *filename,
        "root-ca.pem" | "install.html" | "app.css" | "torkitten-root.mobileconfig"
    ) {
        return Err(WebError::NotFound);
    }
    let validation_path = format!("/{token}/root-ca.pem");
    let response = request_daemon(
        &state.daemon_socket,
        RemoteCommand::BootstrapCertificate {
            site_id: state.site_id.clone(),
            path: validation_path,
        },
    )
    .await?;
    let RemoteResponse::BootstrapCertificate {
        certificate_pem, ..
    } = response
    else {
        return Err(WebError::from_response(response));
    };
    let (content_type, disposition, body) = match *filename {
        "root-ca.pem" => (
            "application/x-pem-file",
            "attachment; filename=\"torkitten-root-ca.pem\"",
            certificate_pem,
        ),
        "torkitten-root.mobileconfig" => (
            "application/x-apple-aspen-config",
            "attachment; filename=\"torkitten-root.mobileconfig\"",
            mobileconfig(&certificate_pem)?,
        ),
        "app.css" => (
            "text/css; charset=utf-8",
            "inline",
            include_str!("../assets/app.css").to_owned(),
        ),
        _ => (
            "text/html; charset=utf-8",
            "inline",
            installation_page(token),
        ),
    };
    let body = if *method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(body)
    };
    Ok((
        [
            (CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (CONTENT_DISPOSITION, HeaderValue::from_static(disposition)),
        ],
        body,
    )
        .into_response())
}

fn installation_page(token: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Install Torkitten certificate</title><link rel=\"stylesheet\" href=\"/{token}/app.css\"><main><div class=\"eyebrow\">Certificate bootstrap</div><h1>Trust this onion site</h1><section class=\"card\"><p>Install only on the device being enrolled. This window is temporary.</p><p><a href=\"/{token}/root-ca.pem\">Download public root certificate</a></p><p><a href=\"/{token}/torkitten-root.mobileconfig\">Download Apple configuration profile</a></p></section></main></html>"
    )
}

fn mobileconfig(certificate_pem: &str) -> WebResult<String> {
    let encoded = certificate_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let der = STANDARD.decode(encoded).map_err(WebError::Certificate)?;
    let payload = STANDARD.encode(der);
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>PayloadContent</key><array><dict><key>PayloadCertificateFileName</key><string>Torkitten Root CA</string><key>PayloadContent</key><data>{payload}</data><key>PayloadDisplayName</key><string>Torkitten Root CA</string><key>PayloadIdentifier</key><string>org.torkitten.root-ca</string><key>PayloadType</key><string>com.apple.security.root</string><key>PayloadUUID</key><string>2FE7B250-2493-46D1-A321-86AE5B5082A7</string><key>PayloadVersion</key><integer>1</integer></dict></array><key>PayloadDisplayName</key><string>Torkitten Root CA</string><key>PayloadIdentifier</key><string>org.torkitten.profile</string><key>PayloadOrganization</key><string>Torkitten</string><key>PayloadType</key><string>Configuration</string><key>PayloadUUID</key><string>2B64D0AB-63DF-47BC-AFBE-F2098A03DFD4</string><key>PayloadVersion</key><integer>1</integer></dict></plist>"
    ))
}

async fn stylesheet() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../assets/app.css"),
    )
}

async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn security_headers(request: axum::http::Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'none'; style-src 'self'",
        ),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> WebResult<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(WebError::Unauthorized)
}

async fn request_daemon(
    socket: &Path,
    command: RemoteCommand,
) -> Result<RemoteResponse, RemoteWebError> {
    let operation = async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(RemoteWebError::Connect)?;
        let mut encoded = serde_json::to_vec(&command)?;
        encoded.push(b'\n');
        stream.write_all(&encoded).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream
            .take(MAXIMUM_IPC_RESPONSE_BYTES + 1)
            .read_to_end(&mut response)
            .await?;
        if response.len() as u64 > MAXIMUM_IPC_RESPONSE_BYTES {
            return Err(RemoteWebError::ResponseTooLarge);
        }
        serde_json::from_slice(&response).map_err(RemoteWebError::Json)
    };
    tokio::time::timeout(IPC_TIMEOUT, operation)
        .await
        .map_err(|_| RemoteWebError::Timeout)?
}

fn ensure_directory(path: &Path, mode: u32) -> Result<(), RemoteWebError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(RemoteWebError::UnsafeDirectory(path.to_path_buf()));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Template)]
#[template(path = "portal.html")]
struct PortalTemplate {
    display_name: String,
    onion_hostname: String,
    guest_display_name: Option<String>,
    mappings: Vec<PortalMapping>,
}

#[derive(Template)]
#[template(path = "enrollment.html")]
struct EnrollmentTemplate {
    guest_display_name: String,
    device_display_name: String,
    expires_unix: i64,
}

type WebResult<T> = Result<T, WebError>;

#[derive(Debug, Error)]
enum WebError {
    #[error("authorization failed")]
    Unauthorized,
    #[error("resource not found")]
    NotFound,
    #[error("daemon unavailable: {0}")]
    Daemon(#[from] RemoteWebError),
    #[error("daemon rejected request: {message}")]
    DaemonResponse { code: String, message: String },
    #[error("invalid identifier: {0}")]
    Validation(torkitten_core::ValidationError),
    #[error("template rendering failed")]
    Template(askama::Error),
    #[error("invalid response header")]
    Header(axum::http::header::InvalidHeaderValue),
    #[error("public certificate is malformed")]
    Certificate(base64::DecodeError),
}

impl WebError {
    fn from_response(response: RemoteResponse) -> Self {
        match response {
            RemoteResponse::Error { code, message } => Self::DaemonResponse { code, message },
            _ => Self::Daemon(RemoteWebError::UnexpectedResponse),
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::DaemonResponse { code, .. } if code == "not_found" => StatusCode::NOT_FOUND,
            Self::DaemonResponse { code, .. } if code == "unauthorized" => StatusCode::UNAUTHORIZED,
            Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Daemon(_)
            | Self::DaemonResponse { .. }
            | Self::Template(_)
            | Self::Header(_)
            | Self::Certificate(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        self.status().into_response()
    }
}

#[derive(Debug, Error)]
pub enum RemoteWebError {
    #[error("remote daemon socket is unavailable: {0}")]
    Connect(#[source] std::io::Error),
    #[error("remote daemon rejected request ({code}): {message}")]
    Daemon { code: String, message: String },
    #[error("remote daemon response was unexpected")]
    UnexpectedResponse,
    #[error("remote daemon request timed out")]
    Timeout,
    #[error("remote daemon response exceeded the size limit")]
    ResponseTooLarge,
    #[error("site web listener failed: {0}")]
    Serve(#[source] std::io::Error),
    #[error("site web task failed: {0}")]
    Join(#[source] tokio::task::JoinError),
    #[error("unsafe remote web directory: {}", .0.display())]
    UnsafeDirectory(PathBuf),
    #[error("unsafe remote web socket path: {}", .0.display())]
    UnsafeSocket(PathBuf),
    #[error("remote web I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("remote IPC encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    use super::*;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    fn site_state(socket: PathBuf) -> SiteState {
        SiteState {
            site_id: SiteId::new("alpha").unwrap(),
            onion_hostname: Arc::from(ONION),
            daemon_socket: Arc::new(socket),
        }
    }

    fn mock_daemon(socket: &Path, response: &RemoteResponse) -> JoinHandle<RemoteCommand> {
        let listener = UnixListener::bind(socket).unwrap();
        let encoded = serde_json::to_vec(&response).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            stream.write_all(&encoded).await.unwrap();
            stream.shutdown().await.unwrap();
            serde_json::from_slice(&request).unwrap()
        })
    }

    #[test]
    fn extracts_only_the_exact_host_cookie_name() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static(
                "unrelated=1; __Host-torkitten_session=valid; torkitten_session=wrong",
            ),
        );
        assert_eq!(cookie(&headers, SESSION_COOKIE).as_deref(), Some("valid"));
    }

    #[test]
    fn mobile_profile_contains_only_the_public_certificate() {
        let pem = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
        let profile = mobileconfig(pem).unwrap();
        assert!(profile.contains("<data>AQID</data>"));
        assert!(!profile.contains("PRIVATE KEY"));
    }

    #[test]
    fn installation_page_keeps_the_unguessable_path_scope() {
        let page = installation_page("one-time-path");
        assert!(page.contains("/one-time-path/root-ca.pem"));
        assert!(page.contains("/one-time-path/app.css"));
        assert!(page.contains("/one-time-path/torkitten-root.mobileconfig"));
    }

    #[tokio::test]
    async fn reconciliation_starts_and_stops_site_scoped_tasks() {
        let runtime = tempfile::tempdir().unwrap();
        let config = RemoteWebConfig::new(runtime.path(), runtime.path().join("remote.sock"));
        let mut servers = HashMap::new();
        reconcile_servers(
            &config,
            &mut servers,
            vec![PublishedSite {
                site_id: SiteId::new("alpha").unwrap(),
                onion_hostname: ONION.to_owned(),
            }],
        );
        assert!(servers.contains_key(&SiteId::new("alpha").unwrap()));
        reconcile_servers(&config, &mut servers, Vec::new());
        assert!(servers.is_empty());
    }

    #[tokio::test]
    async fn bootstrap_router_serves_only_allowlisted_temporary_resources() {
        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join("daemon.sock");
        let daemon = mock_daemon(
            &socket,
            &RemoteResponse::BootstrapCertificate {
                certificate_pem: "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"
                    .to_owned(),
                expires_unix: 200,
            },
        );
        let response = bootstrap_router(site_state(socket))
            .oneshot(
                Request::builder()
                    .uri("/secret/root-ca.pem")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"
        );
        assert!(matches!(
            daemon.await.unwrap(),
            RemoteCommand::BootstrapCertificate { path, .. } if path == "/secret/root-ca.pem"
        ));

        let response = bootstrap_router(site_state(temporary.path().join("unused.sock")))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/secret/root-ca.pem")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn forward_auth_redirects_an_invalid_guest_session_to_safe_portal() {
        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join("daemon.sock");
        let daemon = mock_daemon(
            &socket,
            &RemoteResponse::Error {
                code: "unauthorized".to_owned(),
                message: "authorization failed".to_owned(),
            },
        );
        let response = auth_router(site_state(socket))
            .oneshot(
                Request::builder()
                    .uri("/authorize")
                    .header("x-torkitten-site", "alpha")
                    .header("x-torkitten-mapping", "app")
                    .header(COOKIE, "__Host-torkitten_session=invalid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(LOCATION).unwrap(),
            &format!("https://{ONION}/")
        );
        assert!(matches!(
            daemon.await.unwrap(),
            RemoteCommand::AuthorizeMapping { site_id, mapping_id, .. }
                if site_id.as_str() == "alpha" && mapping_id.as_str() == "app"
        ));
    }

    #[tokio::test]
    async fn forward_auth_redirects_when_the_cookie_is_absent() {
        let response = auth_router(site_state(PathBuf::from("/unused/daemon.sock")))
            .oneshot(
                Request::builder()
                    .uri("/authorize")
                    .header("x-torkitten-site", "alpha")
                    .header("x-torkitten-mapping", "app")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(LOCATION).unwrap(),
            &format!("https://{ONION}/")
        );
    }

    #[tokio::test]
    async fn portal_never_discloses_local_upstream_targets() {
        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join("daemon.sock");
        let daemon = mock_daemon(
            &socket,
            &RemoteResponse::PortalContext {
                context: PortalContext {
                    site_id: SiteId::new("alpha").unwrap(),
                    display_name: "Alpha".to_owned(),
                    onion_hostname: ONION.to_owned(),
                    guest_id: Some(torkitten_core::GuestId::new("family").unwrap()),
                    guest_display_name: Some("Family".to_owned()),
                    mappings: vec![PortalMapping {
                        id: MappingId::new("app").unwrap(),
                        display_name: "Application".to_owned(),
                        virtual_port: 8443,
                    }],
                },
            },
        );
        let response = portal_router(site_state(socket))
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains(&format!("https://{ONION}:8443/")));
        assert!(!body.contains("127.0.0.1"));
        assert!(matches!(
            daemon.await.unwrap(),
            RemoteCommand::PortalContext { site_id, .. } if site_id.as_str() == "alpha"
        ));
    }
}
