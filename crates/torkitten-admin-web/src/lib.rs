#![forbid(unsafe_code)]

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use askama::Template;
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{
        HeaderMap, HeaderValue, Request, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, ORIGIN, SET_COOKIE},
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
};
use torkitten_auth::{
    CsrfToken, ExpectedOrigin, SessionToken, clear_local_admin_session_cookie,
    local_admin_session_cookie,
};
use torkitten_core::{
    AdminCommand, AdminResponse, ComponentAction, ComponentState, Device, DeviceId, GatewayMode,
    GatewayStatus, Guest, GuestId, ManagedComponent, Mapping, MappingId, MappingTarget,
    SensitiveString, Site, SiteId, Transport,
};

const SESSION_COOKIE: &str = "torkitten_admin_session";
const CSRF_COOKIE: &str = "torkitten_admin_csrf";
const CSRF_HEADER: &str = "x-torkitten-csrf";
const ADMIN_SESSION_SECONDS: u64 = 30 * 86_400;
const MAXIMUM_IPC_RESPONSE_BYTES: u64 = 1024 * 1024;
const IPC_TIMEOUT: Duration = Duration::from_secs(15);
const MAXIMUM_REQUEST_BYTES: usize = 64 * 1024;
const DEFAULT_BOOTSTRAP_SECONDS: u32 = 900;

#[derive(Clone, Debug)]
pub struct AdminWebConfig {
    pub listen_address: SocketAddr,
    pub daemon_socket: PathBuf,
}

impl AdminWebConfig {
    #[must_use]
    pub fn new(listen_address: SocketAddr, daemon_socket: impl Into<PathBuf>) -> Self {
        Self {
            listen_address,
            daemon_socket: daemon_socket.into(),
        }
    }

    /// Validates that the native administration server is machine-local.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured listener is not a numeric loopback
    /// address.
    pub fn validate(&self) -> Result<(), AdminWebError> {
        if self.listen_address.ip().is_loopback() {
            Ok(())
        } else {
            Err(AdminWebError::NonLoopbackListener(self.listen_address))
        }
    }
}

#[derive(Debug, Error)]
pub enum AdminWebError {
    #[error("local administration listener must use a loopback address, got {0}")]
    NonLoopbackListener(SocketAddr),
    #[error("invalid administration origin: {0}")]
    Origin(#[from] torkitten_auth::OriginError),
    #[error("failed to bind local administration listener: {0}")]
    Bind(#[source] std::io::Error),
    #[error("local administration server failed: {0}")]
    Serve(#[source] std::io::Error),
}

#[derive(Clone)]
struct AppState {
    daemon_socket: Arc<PathBuf>,
    origin: ExpectedOrigin,
}

/// Serves the shared administration application on its loopback-only listener.
///
/// # Errors
///
/// Returns an error for a non-loopback listener, invalid origin, bind failure,
/// or HTTP server failure.
pub async fn serve(config: AdminWebConfig) -> Result<(), AdminWebError> {
    config.validate()?;
    let origin = ExpectedOrigin::parse(&format!("http://{}", config.listen_address))?;
    let listener = TcpListener::bind(config.listen_address)
        .await
        .map_err(AdminWebError::Bind)?;
    axum::serve(listener, router(config.daemon_socket, origin))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(AdminWebError::Serve)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn router(daemon_socket: PathBuf, origin: ExpectedOrigin) -> Router {
    let state = AppState {
        daemon_socket: Arc::new(daemon_socket),
        origin,
    };
    Router::new()
        .route("/", get(index))
        .route("/assets/app.css", get(stylesheet))
        .route("/assets/app.js", get(script))
        .route("/api/status", get(api_status))
        .route("/api/setup", post(setup))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/generator/candidate", post(generate_candidate))
        .route("/api/sites", post(create_site))
        .route("/api/sites/{site_id}/enabled", post(set_site_enabled))
        .route("/api/sites/{site_id}/rename", post(rename_site))
        .route("/api/sites/{site_id}/stop", post(stop_site))
        .route("/api/sites/{site_id}/restart", post(restart_site))
        .route("/api/sites/{site_id}/rotate", post(rotate_site))
        .route("/api/sites/{site_id}/remove", post(remove_site))
        .route("/api/sites/{site_id}/bootstrap/open", post(open_bootstrap))
        .route(
            "/api/sites/{site_id}/bootstrap/close",
            post(close_bootstrap),
        )
        .route("/api/sites/{site_id}/mappings", post(put_mapping))
        .route("/api/sites/{site_id}/mappings/test", post(test_mapping))
        .route(
            "/api/sites/{site_id}/mappings/{mapping_id}/enabled",
            post(set_mapping_enabled),
        )
        .route(
            "/api/sites/{site_id}/mappings/{mapping_id}/remove",
            post(remove_mapping),
        )
        .route("/api/sites/{site_id}/devices/enroll", post(enroll_device))
        .route(
            "/api/sites/{site_id}/guests/{guest_id}/devices/{device_id}/revoke",
            post(revoke_device),
        )
        .route(
            "/api/sites/{site_id}/guests/{guest_id}/remove",
            post(remove_guest),
        )
        .route("/api/settings/resume", post(set_resume_after_boot))
        .route("/api/emergency/stop", post(emergency_stop))
        .route("/api/emergency/clear", post(emergency_clear))
        .route(
            "/api/components/{component}/{action}",
            post(control_component),
        )
        .layer(DefaultBodyLimit::max(MAXIMUM_REQUEST_BYTES))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'",
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

async fn index(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Html<String>> {
    let status = request_daemon(&state, AdminCommand::Status).await?;
    let status = expect_status(status)?;
    let initialized = status.mode != GatewayMode::Uninitialized;
    let authenticated = if initialized {
        validate_session(&state, &headers).await.is_ok()
    } else {
        false
    };
    let page = if !initialized {
        "setup"
    } else if authenticated {
        "dashboard"
    } else {
        "login"
    };
    let template = IndexTemplate::new(&status, page);
    Ok(Html(template.render().map_err(ApiError::Template)?))
}

async fn stylesheet() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../assets/app.css"),
    )
}

async fn script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../assets/app.js"),
    )
}

async fn api_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    validate_session(&state, &headers).await?;
    Ok(Json(request_daemon(&state, AdminCommand::Status).await?))
}

#[derive(Deserialize)]
struct PasswordInput {
    password: String,
}

async fn setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<PasswordInput>,
) -> ApiResult<Response> {
    validate_origin(&state, &headers)?;
    expect_ok(
        request_daemon(
            &state,
            AdminCommand::Initialize {
                password: SensitiveString::new(input.password.clone()),
            },
        )
        .await?,
    )?;
    authenticate(&state, input.password).await
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<PasswordInput>,
) -> ApiResult<Response> {
    validate_origin(&state, &headers)?;
    authenticate(&state, input.password).await
}

async fn authenticate(state: &AppState, password: String) -> ApiResult<Response> {
    let response = request_daemon(
        state,
        AdminCommand::AuthenticateAdministrator {
            password: SensitiveString::new(password),
        },
    )
    .await?;
    let AdminResponse::AdministratorAuthenticated {
        session,
        csrf,
        expires_unix,
    } = response
    else {
        return Err(ApiError::from_daemon_response(response));
    };
    let token = SessionToken::parse(session.expose().to_owned()).map_err(ApiError::Token)?;
    let session_cookie =
        local_admin_session_cookie(&token, ADMIN_SESSION_SECONDS).map_err(ApiError::Cookie)?;
    let csrf_cookie = format!(
        "{CSRF_COOKIE}={}; Path=/; Max-Age={ADMIN_SESSION_SECONDS}; SameSite=Strict",
        csrf.expose()
    );
    let mut response = Json(json!({ "ok": true, "expires_unix": expires_unix })).into_response();
    response.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_str(session_cookie.expose()).map_err(ApiError::Header)?,
    );
    response.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_str(&csrf_cookie).map_err(ApiError::Header)?,
    );
    Ok(response)
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let auth = mutation_auth(&state, &headers)?;
    expect_ok(
        request_daemon(
            &state,
            AdminCommand::LogoutAdministrator {
                session: SensitiveString::new(auth.session),
                csrf: SensitiveString::new(auth.csrf),
            },
        )
        .await?,
    )?;
    let mut response = Json(json!({ "ok": true })).into_response();
    response.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_static(clear_local_admin_session_cookie()),
    );
    response.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_static("torkitten_admin_csrf=; Path=/; Max-Age=0; SameSite=Strict"),
    );
    Ok(response)
}

async fn generate_candidate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    authorize_mutation(&state, &headers).await?;
    daemon_json(&state, AdminCommand::GenerateSiteCandidate).await
}

#[derive(Deserialize)]
struct CreateSiteInput {
    id: String,
    display_name: String,
    candidate_id: String,
}

async fn create_site(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateSiteInput>,
) -> ApiResult<Json<AdminResponse>> {
    authorize_mutation(&state, &headers).await?;
    let site = Site {
        id: SiteId::new(input.id).map_err(ApiError::Validation)?,
        display_name: input.display_name,
        enabled: true,
        mappings: Vec::new(),
    };
    site.validate().map_err(ApiError::Validation)?;
    daemon_json(
        &state,
        AdminCommand::CreateGeneratedSite {
            site,
            candidate_id: SensitiveString::new(input.candidate_id),
        },
    )
    .await
}

#[derive(Deserialize)]
struct EnabledInput {
    enabled: bool,
}

async fn set_site_enabled(
    State(state): State<AppState>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<EnabledInput>,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::SetSiteEnabled {
            site_id: parse_site_id(site_id)?,
            enabled: input.enabled,
        },
    )
    .await
}

#[derive(Deserialize)]
struct RenameInput {
    display_name: String,
}

async fn rename_site(
    State(state): State<AppState>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<RenameInput>,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::RenameSite {
            site_id: parse_site_id(site_id)?,
            display_name: input.display_name,
        },
    )
    .await
}

async fn stop_site(
    State(state): State<AppState>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::StopSite {
            site_id: parse_site_id(site_id)?,
        },
    )
    .await
}

async fn restart_site(
    State(state): State<AppState>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::RestartSite {
            site_id: parse_site_id(site_id)?,
        },
    )
    .await
}

async fn rotate_site(
    State(state): State<AppState>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    authorize_mutation(&state, &headers).await?;
    let candidate = request_daemon(&state, AdminCommand::GenerateSiteCandidate).await?;
    let AdminResponse::SiteCandidate { candidate_id, .. } = candidate else {
        return Err(ApiError::from_daemon_response(candidate));
    };
    daemon_json(
        &state,
        AdminCommand::RotateSite {
            site_id: parse_site_id(site_id)?,
            candidate_id,
        },
    )
    .await
}

async fn remove_site(
    State(state): State<AppState>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::RemoveSite {
            site_id: parse_site_id(site_id)?,
        },
    )
    .await
}

#[derive(Deserialize)]
struct BootstrapInput {
    #[serde(default = "default_bootstrap_seconds")]
    seconds: u32,
}

const fn default_bootstrap_seconds() -> u32 {
    DEFAULT_BOOTSTRAP_SECONDS
}

async fn open_bootstrap(
    State(state): State<AppState>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<BootstrapInput>,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::OpenCertificateBootstrap {
            site_id: parse_site_id(site_id)?,
            seconds: input.seconds,
        },
    )
    .await
}

async fn close_bootstrap(
    State(state): State<AppState>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::CloseCertificateBootstrap {
            site_id: parse_site_id(site_id)?,
        },
    )
    .await
}

#[derive(Deserialize)]
struct MappingInput {
    id: String,
    display_name: String,
    virtual_port: u16,
    target_kind: String,
    address: Option<String>,
    port: Option<u16>,
    path: Option<PathBuf>,
    transport: String,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
}

const fn enabled_by_default() -> bool {
    true
}

impl MappingInput {
    fn into_mapping(self) -> Result<Mapping, ApiError> {
        let transport = match self.transport.as_str() {
            "http" => Transport::Http,
            "https" => Transport::Https,
            "h2c" => Transport::H2c,
            _ => return Err(ApiError::BadRequest("invalid mapping transport")),
        };
        let target = match self.target_kind.as_str() {
            "tcp" => MappingTarget::Tcp {
                address: self
                    .address
                    .ok_or(ApiError::BadRequest("mapping address is required"))?
                    .parse()
                    .map_err(|_| ApiError::BadRequest("mapping address must be numeric"))?,
                port: self
                    .port
                    .ok_or(ApiError::BadRequest("mapping target port is required"))?,
                transport,
            },
            "unix" => MappingTarget::Unix {
                path: self
                    .path
                    .ok_or(ApiError::BadRequest("mapping socket path is required"))?,
                transport,
            },
            _ => return Err(ApiError::BadRequest("invalid mapping target kind")),
        };
        let mapping = Mapping {
            id: MappingId::new(self.id).map_err(ApiError::Validation)?,
            display_name: self.display_name,
            virtual_port: self.virtual_port,
            target,
            enabled: self.enabled,
        };
        mapping.validate().map_err(ApiError::Validation)?;
        Ok(mapping)
    }
}

async fn put_mapping(
    State(state): State<AppState>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<MappingInput>,
) -> ApiResult<Json<AdminResponse>> {
    let mapping = input.into_mapping()?;
    authorized_command(
        &state,
        &headers,
        AdminCommand::PutMapping {
            site_id: parse_site_id(site_id)?,
            mapping,
        },
    )
    .await
}

async fn test_mapping(
    State(state): State<AppState>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<MappingInput>,
) -> ApiResult<Json<AdminResponse>> {
    let mapping = input.into_mapping()?;
    authorized_command(
        &state,
        &headers,
        AdminCommand::TestMapping {
            site_id: parse_site_id(site_id)?,
            mapping,
        },
    )
    .await
}

async fn set_mapping_enabled(
    State(state): State<AppState>,
    Path((site_id, mapping_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<EnabledInput>,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::SetMappingEnabled {
            site_id: parse_site_id(site_id)?,
            mapping_id: parse_mapping_id(mapping_id)?,
            enabled: input.enabled,
        },
    )
    .await
}

async fn remove_mapping(
    State(state): State<AppState>,
    Path((site_id, mapping_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::RemoveMapping {
            site_id: parse_site_id(site_id)?,
            mapping_id: parse_mapping_id(mapping_id)?,
        },
    )
    .await
}

#[derive(Deserialize)]
struct EnrollDeviceInput {
    guest_id: String,
    guest_name: String,
    device_id: String,
    device_name: String,
    client_name: String,
    mapping_ids: Vec<String>,
}

async fn enroll_device(
    State(state): State<AppState>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<EnrollDeviceInput>,
) -> ApiResult<Json<AdminResponse>> {
    let site_id = parse_site_id(site_id)?;
    let guest_id = GuestId::new(input.guest_id).map_err(ApiError::Validation)?;
    let mapping_ids = input
        .mapping_ids
        .into_iter()
        .map(|id| MappingId::new(id).map_err(ApiError::Validation))
        .collect::<Result<Vec<_>, _>>()?;
    let guest = Guest {
        site_id: site_id.clone(),
        id: guest_id.clone(),
        display_name: input.guest_name,
        enabled: true,
    };
    let device = Device {
        site_id,
        guest_id,
        id: DeviceId::new(input.device_id).map_err(ApiError::Validation)?,
        display_name: input.device_name,
        tor_client_name: input.client_name,
        enabled: true,
    };
    authorized_command(
        &state,
        &headers,
        AdminCommand::EnrollDevice {
            guest,
            device,
            mapping_ids,
        },
    )
    .await
}

async fn revoke_device(
    State(state): State<AppState>,
    Path((site_id, guest_id, device_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::RevokeDevice {
            site_id: parse_site_id(site_id)?,
            guest_id: GuestId::new(guest_id).map_err(ApiError::Validation)?,
            device_id: DeviceId::new(device_id).map_err(ApiError::Validation)?,
        },
    )
    .await
}

async fn remove_guest(
    State(state): State<AppState>,
    Path((site_id, guest_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::RemoveGuest {
            site_id: parse_site_id(site_id)?,
            guest_id: GuestId::new(guest_id).map_err(ApiError::Validation)?,
        },
    )
    .await
}

async fn set_resume_after_boot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<EnabledInput>,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(
        &state,
        &headers,
        AdminCommand::SetResumeAfterBoot {
            enabled: input.enabled,
        },
    )
    .await
}

async fn emergency_stop(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(&state, &headers, AdminCommand::EmergencyDisable).await
}

async fn emergency_clear(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    authorized_command(&state, &headers, AdminCommand::ClearEmergencyDisable).await
}

async fn control_component(
    State(state): State<AppState>,
    Path((component, action)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminResponse>> {
    let component = match component.as_str() {
        "tor" => ManagedComponent::Tor,
        "caddy" => ManagedComponent::Caddy,
        _ => return Err(ApiError::BadRequest("unknown managed component")),
    };
    let action = match action.as_str() {
        "start" => ComponentAction::Start,
        "stop" => ComponentAction::Stop,
        "restart" => ComponentAction::Restart,
        _ => return Err(ApiError::BadRequest("unknown component action")),
    };
    authorized_command(
        &state,
        &headers,
        AdminCommand::ControlComponent { component, action },
    )
    .await
}

async fn authorized_command(
    state: &AppState,
    headers: &HeaderMap,
    command: AdminCommand,
) -> ApiResult<Json<AdminResponse>> {
    authorize_mutation(state, headers).await?;
    daemon_json(state, command).await
}

async fn daemon_json(state: &AppState, command: AdminCommand) -> ApiResult<Json<AdminResponse>> {
    let response = request_daemon(state, command).await?;
    if matches!(response, AdminResponse::Error { .. }) {
        Err(ApiError::from_daemon_response(response))
    } else {
        Ok(Json(response))
    }
}

fn parse_site_id(value: String) -> Result<SiteId, ApiError> {
    SiteId::new(value).map_err(ApiError::Validation)
}

fn parse_mapping_id(value: String) -> Result<MappingId, ApiError> {
    MappingId::new(value).map_err(ApiError::Validation)
}

async fn validate_session(state: &AppState, headers: &HeaderMap) -> ApiResult<bool> {
    let session = required_cookie(headers, SESSION_COOKIE)?;
    SessionToken::parse(session.clone()).map_err(|_| ApiError::Unauthorized)?;
    let response = request_daemon(
        state,
        AdminCommand::ValidateAdministratorSession {
            session: SensitiveString::new(session),
        },
    )
    .await?;
    match response {
        AdminResponse::AdministratorAuthorized { fresh } => Ok(fresh),
        response => Err(ApiError::from_daemon_response(response)),
    }
}

struct MutationAuth {
    session: String,
    csrf: String,
}

fn mutation_auth(state: &AppState, headers: &HeaderMap) -> ApiResult<MutationAuth> {
    let session = required_cookie(headers, SESSION_COOKIE)?;
    SessionToken::parse(session.clone()).map_err(|_| ApiError::Unauthorized)?;
    let csrf = required_cookie(headers, CSRF_COOKIE)?;
    let token = CsrfToken::parse(csrf.clone()).map_err(|_| ApiError::Unauthorized)?;
    let origin = header_text(headers, ORIGIN)?;
    let candidate = header_text_named(headers, CSRF_HEADER)?;
    state
        .origin
        .validate_request("POST", Some(origin), Some(candidate), &token)
        .map_err(ApiError::Origin)?;
    Ok(MutationAuth { session, csrf })
}

async fn authorize_mutation(state: &AppState, headers: &HeaderMap) -> ApiResult<bool> {
    let auth = mutation_auth(state, headers)?;
    let response = request_daemon(
        state,
        AdminCommand::AuthorizeAdministratorMutation {
            session: SensitiveString::new(auth.session),
            csrf: SensitiveString::new(auth.csrf),
        },
    )
    .await?;
    match response {
        AdminResponse::AdministratorAuthorized { fresh } => Ok(fresh),
        response => Err(ApiError::from_daemon_response(response)),
    }
}

fn validate_origin(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    state
        .origin
        .validate(header_text(headers, ORIGIN)?)
        .map_err(ApiError::Origin)
}

fn required_cookie(headers: &HeaderMap, name: &str) -> ApiResult<String> {
    let mut found = None;
    for header in headers.get_all(COOKIE) {
        let text = header.to_str().map_err(|_| ApiError::Unauthorized)?;
        for pair in text.split(';') {
            let Some((candidate_name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if candidate_name == name {
                if found.is_some() || value.is_empty() {
                    return Err(ApiError::Unauthorized);
                }
                found = Some(value.to_owned());
            }
        }
    }
    found.ok_or(ApiError::Unauthorized)
}

fn header_text(headers: &HeaderMap, name: axum::http::header::HeaderName) -> ApiResult<&str> {
    headers
        .get(name)
        .ok_or(ApiError::Forbidden)?
        .to_str()
        .map_err(|_| ApiError::Forbidden)
}

fn header_text_named<'a>(headers: &'a HeaderMap, name: &str) -> ApiResult<&'a str> {
    headers
        .get(name)
        .ok_or(ApiError::Forbidden)?
        .to_str()
        .map_err(|_| ApiError::Forbidden)
}

async fn request_daemon(state: &AppState, command: AdminCommand) -> ApiResult<AdminResponse> {
    let operation = async {
        let mut stream = UnixStream::connect(state.daemon_socket.as_ref()).await?;
        let mut request = serde_json::to_vec(&command).map_err(IpcError::Json)?;
        request.push(b'\n');
        stream.write_all(&request).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream
            .take(MAXIMUM_IPC_RESPONSE_BYTES + 1)
            .read_to_end(&mut response)
            .await?;
        if response.len() as u64 > MAXIMUM_IPC_RESPONSE_BYTES {
            return Err(IpcError::ResponseTooLarge);
        }
        serde_json::from_slice(&response).map_err(IpcError::Json)
    };
    tokio::time::timeout(IPC_TIMEOUT, operation)
        .await
        .map_err(|_| ApiError::DaemonUnavailable("daemon request timed out".to_owned()))?
        .map_err(ApiError::Ipc)
}

fn expect_status(response: AdminResponse) -> ApiResult<GatewayStatus> {
    match response {
        AdminResponse::Status { status } => Ok(status),
        response => Err(ApiError::from_daemon_response(response)),
    }
}

fn expect_ok(response: AdminResponse) -> ApiResult<()> {
    match response {
        AdminResponse::Ok => Ok(()),
        response => Err(ApiError::from_daemon_response(response)),
    }
}

type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Error)]
enum IpcError {
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid daemon response: {0}")]
    Json(serde_json::Error),
    #[error("daemon response exceeded the size limit")]
    ResponseTooLarge,
}

#[derive(Debug, Error)]
enum ApiError {
    #[error("authentication is required")]
    Unauthorized,
    #[error("request origin or CSRF verification failed")]
    Forbidden,
    #[error("{0}")]
    BadRequest(&'static str),
    #[error("{0}")]
    Validation(torkitten_core::ValidationError),
    #[error("{1}")]
    Daemon(String, String),
    #[error("administration daemon is unavailable: {0}")]
    DaemonUnavailable(String),
    #[error("administration daemon is unavailable: {0}")]
    Ipc(IpcError),
    #[error("template rendering failed")]
    Template(askama::Error),
    #[error("invalid session token")]
    Token(torkitten_auth::TokenError),
    #[error("invalid session cookie")]
    Cookie(torkitten_auth::CookieError),
    #[error("invalid response header")]
    Header(axum::http::header::InvalidHeaderValue),
    #[error("{0}")]
    Origin(torkitten_auth::OriginError),
}

impl ApiError {
    fn from_daemon_response(response: AdminResponse) -> Self {
        match response {
            AdminResponse::Error { code, message } => Self::Daemon(code, message),
            _ => Self::DaemonUnavailable("unexpected daemon response".to_owned()),
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden | Self::Origin(_) => StatusCode::FORBIDDEN,
            Self::BadRequest(_) | Self::Validation(_) | Self::Token(_) | Self::Cookie(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::Daemon(code, _) if code == "unauthorized" => StatusCode::UNAUTHORIZED,
            Self::Daemon(code, _) if code == "invalid_csrf" => StatusCode::FORBIDDEN,
            Self::Daemon(_, _) => StatusCode::CONFLICT,
            Self::DaemonUnavailable(_) | Self::Ipc(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Template(_) | Self::Header(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    ok: bool,
    error: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let message = self.to_string();
        (
            status,
            Json(ErrorBody {
                ok: false,
                error: &message,
            }),
        )
            .into_response()
    }
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    page: &'static str,
    disabled: bool,
    mode: &'static str,
    tor_state: &'static str,
    caddy_state: &'static str,
    resume_after_boot: bool,
    sites: Vec<SiteView>,
}

impl IndexTemplate {
    fn new(status: &GatewayStatus, page: &'static str) -> Self {
        Self {
            page,
            disabled: status.mode == GatewayMode::Disabled,
            mode: mode_label(status.mode),
            tor_state: state_label(status.tor),
            caddy_state: state_label(status.caddy),
            resume_after_boot: status.resume_after_boot,
            sites: status.sites.iter().map(SiteView::from_status).collect(),
        }
    }
}

struct SiteView {
    id: String,
    display_name: String,
    onion_hostname: String,
    enabled: bool,
    state: &'static str,
    bootstrap_open: bool,
    mappings: Vec<MappingView>,
    guests: Vec<GuestView>,
}

impl SiteView {
    fn from_status(status: &torkitten_core::SiteStatus) -> Self {
        Self {
            id: status.site.id.as_str().to_owned(),
            display_name: status.site.display_name.clone(),
            onion_hostname: status
                .onion_hostname
                .clone()
                .unwrap_or_else(|| "Identity is being prepared".to_owned()),
            enabled: status.site.enabled,
            state: state_label(status.publication),
            bootstrap_open: status.bootstrap_expires_unix.is_some(),
            mappings: status
                .site
                .mappings
                .iter()
                .map(MappingView::from_mapping)
                .collect(),
            guests: status
                .guests
                .iter()
                .map(|access| GuestView {
                    id: access.guest.id.as_str().to_owned(),
                    display_name: access.guest.display_name.clone(),
                    mapping_count: access.mapping_ids.len(),
                    devices: access
                        .devices
                        .iter()
                        .map(|device| DeviceView {
                            id: device.id.as_str().to_owned(),
                            display_name: device.display_name.clone(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

struct GuestView {
    id: String,
    display_name: String,
    mapping_count: usize,
    devices: Vec<DeviceView>,
}

struct DeviceView {
    id: String,
    display_name: String,
}

struct MappingView {
    id: String,
    display_name: String,
    virtual_port: u16,
    target: String,
    target_kind: &'static str,
    address: String,
    port: u16,
    path: String,
    transport: &'static str,
    enabled: bool,
}

impl MappingView {
    fn from_mapping(mapping: &Mapping) -> Self {
        let (target, target_kind, address, port, path, transport) = match &mapping.target {
            MappingTarget::Tcp {
                address,
                port,
                transport,
            } => (
                format!("{}://{address}:{port}", transport_label(*transport)),
                "tcp",
                address.to_string(),
                *port,
                String::new(),
                transport_label(*transport),
            ),
            MappingTarget::Unix { path, transport } => (
                format!("{}+unix://{}", transport_label(*transport), path.display()),
                "unix",
                String::new(),
                0,
                path.display().to_string(),
                transport_label(*transport),
            ),
        };
        Self {
            id: mapping.id.as_str().to_owned(),
            display_name: mapping.display_name.clone(),
            virtual_port: mapping.virtual_port,
            target,
            target_kind,
            address,
            port,
            path,
            transport,
            enabled: mapping.enabled,
        }
    }
}

const fn mode_label(mode: GatewayMode) -> &'static str {
    match mode {
        GatewayMode::Uninitialized => "Setup required",
        GatewayMode::Active => "Publication available",
        GatewayMode::Disabled => "Emergency stop active",
    }
}

const fn state_label(state: ComponentState) -> &'static str {
    match state {
        ComponentState::Stopped => "Stopped",
        ComponentState::Starting => "Starting",
        ComponentState::Running => "Running",
        ComponentState::Failed => "Failed",
    }
}

const fn transport_label(transport: Transport) -> &'static str {
    match transport {
        Transport::Http => "http",
        Transport::Https => "https",
        Transport::H2c => "h2c",
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use axum::http::{Method, Uri};
    use http_body_util::BodyExt;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tower::ServiceExt;

    use super::*;

    #[test]
    fn refuses_a_non_loopback_listener() {
        let config = AdminWebConfig::new(
            SocketAddr::from(([0, 0, 0, 0], 12_755)),
            "/run/torkitten/admin.sock",
        );
        assert!(matches!(
            config.validate(),
            Err(AdminWebError::NonLoopbackListener(_))
        ));
    }

    #[test]
    fn renders_escaped_site_data_and_indented_mappings() {
        let status = GatewayStatus {
            mode: GatewayMode::Active,
            sites: vec![torkitten_core::SiteStatus {
                site: Site {
                    id: SiteId::new("personal").unwrap(),
                    display_name: "<script>alert(1)</script>".to_owned(),
                    enabled: true,
                    mappings: vec![Mapping {
                        id: MappingId::new("photos").unwrap(),
                        display_name: "Photos".to_owned(),
                        virtual_port: 8443,
                        target: MappingTarget::Tcp {
                            address: IpAddr::from_str("127.0.0.1").unwrap(),
                            port: 3000,
                            transport: Transport::Http,
                        },
                        enabled: true,
                    }],
                },
                onion_hostname: Some("example.onion".to_owned()),
                bootstrap_expires_unix: None,
                publication: ComponentState::Running,
                guests: Vec::new(),
            }],
            tor: ComponentState::Running,
            caddy: ComponentState::Running,
            resume_after_boot: true,
        };
        let html = IndexTemplate::new(&status, "dashboard").render().unwrap();
        assert!(html.contains("alert"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("http://127.0.0.1:3000"));
        assert!(html.contains("mapping-row"));
    }

    #[test]
    fn rejects_duplicate_security_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static(
                "torkitten_admin_session=first; torkitten_admin_session=second",
            ),
        );
        assert!(matches!(
            required_cookie(&headers, SESSION_COOKIE),
            Err(ApiError::Unauthorized)
        ));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn setup_cookies_and_csrf_protect_the_daemon_boundary() {
        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join("admin.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let session = SessionToken::generate().unwrap();
        let csrf = CsrfToken::generate().unwrap();
        let session_value = session.expose().to_owned();
        let csrf_value = csrf.expose().to_owned();
        let fake_session = session_value.clone();
        let fake_csrf = csrf_value.clone();
        let daemon = tokio::spawn(async move {
            for request_number in 0..5 {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut line = String::new();
                BufReader::new(reader).read_line(&mut line).await.unwrap();
                let command = serde_json::from_str::<AdminCommand>(&line).unwrap();
                let response = match (request_number, command) {
                    (0, AdminCommand::Status) => AdminResponse::Status {
                        status: uninitialized_status(),
                    },
                    (1, AdminCommand::Initialize { password }) => {
                        assert_eq!(password.expose(), "long-enough-password");
                        AdminResponse::Ok
                    }
                    (2, AdminCommand::AuthenticateAdministrator { password }) => {
                        assert_eq!(password.expose(), "long-enough-password");
                        AdminResponse::AdministratorAuthenticated {
                            session: SensitiveString::new(fake_session.clone()),
                            csrf: SensitiveString::new(fake_csrf.clone()),
                            expires_unix: 2_000_000_000,
                        }
                    }
                    (3, AdminCommand::AuthorizeAdministratorMutation { session, csrf }) => {
                        assert_eq!(session.expose(), fake_session);
                        assert_eq!(csrf.expose(), fake_csrf);
                        AdminResponse::AdministratorAuthorized { fresh: true }
                    }
                    (4, AdminCommand::GenerateSiteCandidate) => AdminResponse::SiteCandidate {
                        candidate_id: SensitiveString::new("candidate-token"),
                        onion_hostname: "candidate.onion".to_owned(),
                        expires_unix: 2_000_000_000,
                    },
                    (_, command) => panic!("unexpected daemon request: {command:?}"),
                };
                let mut encoded = serde_json::to_vec(&response).unwrap();
                encoded.push(b'\n');
                writer.write_all(&encoded).await.unwrap();
            }
        });
        let app = router(
            socket,
            ExpectedOrigin::parse("http://127.0.0.1:12755").unwrap(),
        );

        let index_response = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(index_response.status(), StatusCode::OK);
        let index = index_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert!(String::from_utf8_lossy(&index).contains("Set up Torkitten"));

        let setup_response = app
            .clone()
            .oneshot(json_request(
                "/api/setup",
                r#"{"password":"long-enough-password"}"#,
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(setup_response.status(), StatusCode::OK);
        let cookies = setup_response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        assert!(cookies[0].contains("HttpOnly; SameSite=Strict"));
        assert!(!cookies[1].contains("HttpOnly"));
        let cookie_header = format!("{SESSION_COOKIE}={session_value}; {CSRF_COOKIE}={csrf_value}");

        let rejected = app
            .clone()
            .oneshot(json_request(
                "/api/generator/candidate",
                "{}",
                Some(&cookie_header),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

        let accepted = app
            .oneshot(json_request(
                "/api/generator/candidate",
                "{}",
                Some(&cookie_header),
                Some(&csrf_value),
            ))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let body = accepted.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("candidate.onion"));
        daemon.await.unwrap();
    }

    fn json_request(
        uri: &str,
        body: &'static str,
        cookie: Option<&str>,
        csrf: Option<&str>,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(Uri::from_str(uri).unwrap())
            .header(CONTENT_TYPE, "application/json")
            .header(ORIGIN, "http://127.0.0.1:12755");
        if let Some(cookie) = cookie {
            request = request.header(COOKIE, cookie);
        }
        if let Some(csrf) = csrf {
            request = request.header(CSRF_HEADER, csrf);
        }
        request.body(Body::from(body)).unwrap()
    }

    fn uninitialized_status() -> GatewayStatus {
        GatewayStatus {
            mode: GatewayMode::Uninitialized,
            sites: Vec::new(),
            tor: ComponentState::Stopped,
            caddy: ComponentState::Stopped,
            resume_after_boot: true,
        }
    }
}
