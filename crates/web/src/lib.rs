//! # web — axum HTTP layer
//!
//! Routes:
//!   GET  /                       dashboard (auth required)
//!   GET  /login                  login form
//!   POST /login                  sign in, set session cookie
//!   POST /logout                 clear session
//!   GET  /r/:token               vendor: access-code prompt
//!   POST /r/:token               vendor: submit code, stream file
//!   GET  /health                 liveness
//!
//! TLS termination is the host's job (reverse proxy or external). This crate
//! binds to plain HTTP on the loopback interface.

use askama::Template;
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use std::sync::Arc;

/// Max total upload size for /shares/new. 100 MB covers realistic CAD files.
const MAX_UPLOAD_BYTES: usize = 100 * 1024 * 1024;

mod auth;

use auth::CurrentUser;

pub const SESSION_COOKIE: &str = "fips_session";

pub fn router(app: Arc<service::App>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login_get).post(login_post))
        .route("/logout", post(logout_post))
        .route(
            "/shares/new",
            get(share_new_get).post(share_new_post).layer(
                DefaultBodyLimit::max(MAX_UPLOAD_BYTES),
            ),
        )
        .route("/tokens", get(tokens_get).post(tokens_post))
        .route("/tokens/:id/revoke", post(token_revoke))
        .route("/r/:token", get(redeem_get).post(redeem_post))
        .route("/health", get(health))
        .with_state(app)
}

async fn health() -> &'static str {
    "ok"
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    user_email: String,
    fips_status: &'static str,
}

#[derive(Template)]
#[template(path = "redeem_prompt.html")]
struct RedeemPromptPage {
    token: String,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "tokens.html")]
struct TokensPage {
    tokens: Vec<TokenRow>,
}

struct TokenRow {
    id: String,
    label: String,
    created: String,
    last_seen: String,
    revoked: bool,
}

#[derive(Template)]
#[template(path = "token_created.html")]
struct TokenCreatedPage {
    label: String,
    raw_token: String,
}

#[derive(Template)]
#[template(path = "share_new.html")]
struct ShareNewPage {
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "share_created.html")]
struct ShareCreatedPage {
    vendor_email: String,
    vendor_phone: Option<String>,
    share_url: String,
    access_code: String,
    notifications_sent: bool,
    sms_sent: bool,
}

fn render<T: Template>(t: &T) -> Result<Html<String>, StatusCode> {
    t.render()
        .map(Html)
        .map_err(|e| {
            tracing::error!(?e, "template render failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

// ---------------------------------------------------------------------------
// Dashboard (auth required)
// ---------------------------------------------------------------------------

async fn dashboard(
    State(app): State<Arc<service::App>>,
    user: CurrentUser,
) -> Result<Html<String>, StatusCode> {
    let fips_status = if app.fips_mode_enabled {
        "enabled"
    } else {
        "DISABLED (dev mode)"
    };
    render(&DashboardPage {
        user_email: user.0.email,
        fips_status,
    })
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

async fn login_get(user: Option<CurrentUser>) -> Result<Response, StatusCode> {
    if user.is_some() {
        return Ok(Redirect::to("/").into_response());
    }
    Ok(render(&LoginPage { error: None })?.into_response())
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    password: String,
}

async fn login_post(
    State(app): State<Arc<service::App>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response, StatusCode> {
    let ip = client_ip(&headers);
    let ua = user_agent(&headers);

    let req = service::LoginRequest {
        email: form.email.trim().to_lowercase(),
        password: form.password,
        ip,
        user_agent: ua,
    };

    match app.login(req).await {
        Ok(issued) => {
            let cookie = build_session_cookie(&issued.raw_token, issued.session.expires_at);
            let mut resp = Redirect::to("/").into_response();
            resp.headers_mut()
                .insert(header::SET_COOKIE, cookie.parse().unwrap());
            Ok(resp)
        }
        Err(service::ServiceError::InvalidCredentials) => Ok(render(&LoginPage {
            error: Some("Incorrect email or password.".into()),
        })?
        .into_response()),
        Err(e) => {
            tracing::error!(?e, "login failure");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ---------------------------------------------------------------------------
// API tokens (admin management of workstation credentials)
// ---------------------------------------------------------------------------

async fn tokens_get(
    State(app): State<Arc<service::App>>,
    user: CurrentUser,
) -> Result<Html<String>, StatusCode> {
    let list = app.list_api_tokens(user.0.id).await.map_err(|e| {
        tracing::error!(?e, "list_api_tokens");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let rows = list
        .into_iter()
        .map(|t| TokenRow {
            id: t.id.to_string(),
            label: t.label,
            created: format_dt(t.created_at),
            last_seen: t
                .last_seen_at
                .map(format_dt)
                .unwrap_or_else(|| "never".to_string()),
            revoked: t.revoked_at.is_some(),
        })
        .collect();
    render(&TokensPage { tokens: rows })
}

#[derive(Deserialize)]
struct TokenMintForm {
    label: String,
}

async fn tokens_post(
    State(app): State<Arc<service::App>>,
    user: CurrentUser,
    headers: HeaderMap,
    Form(form): Form<TokenMintForm>,
) -> Result<Response, StatusCode> {
    let label = form.label.trim().to_string();
    if label.is_empty() {
        return Ok(Redirect::to("/tokens").into_response());
    }
    let issued = app
        .mint_api_token(user.0.id, label.clone(), client_ip(&headers), user_agent(&headers))
        .await
        .map_err(|e| {
            tracing::error!(?e, "mint_api_token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(render(&TokenCreatedPage {
        label,
        raw_token: issued.raw_token,
    })?
    .into_response())
}

async fn token_revoke(
    State(app): State<Arc<service::App>>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Redirect, StatusCode> {
    let token_id = uuid::Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Err(e) = app
        .revoke_api_token(token_id, user.0.id, client_ip(&headers), user_agent(&headers))
        .await
    {
        tracing::warn!(?e, "revoke_api_token");
    }
    Ok(Redirect::to("/tokens"))
}

fn format_dt(dt: time::OffsetDateTime) -> String {
    // UTC, YYYY-MM-DD HH:MM — no seconds, no timezone noise
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day] [hour]:[minute] UTC"
    );
    dt.format(&fmt).unwrap_or_else(|_| "?".to_string())
}

// ---------------------------------------------------------------------------
// Create share
// ---------------------------------------------------------------------------

async fn share_new_get(_user: CurrentUser) -> Result<Html<String>, StatusCode> {
    render(&ShareNewPage { error: None })
}

async fn share_new_post(
    State(app): State<Arc<service::App>>,
    user: CurrentUser,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, StatusCode> {
    let mut filename: Option<String> = None;
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut vendor_email: Option<String> = None;
    let mut vendor_phone: Option<String> = None;
    let mut vendor_display_name: Option<String> = None;
    let mut expires_in_hours: u32 = 72;
    let mut max_downloads: u32 = 3;
    let mut note: Option<String> = None;
    let mut cui_attested: bool = false;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                filename = field.file_name().map(|s| s.to_string());
                let b = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                file_bytes = Some(b.to_vec());
            }
            "vendor_email" => {
                vendor_email =
                    Some(field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?);
            }
            "vendor_phone" => {
                let t = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                vendor_phone = if t.trim().is_empty() { None } else { Some(t) };
            }
            "vendor_display_name" => {
                vendor_display_name =
                    Some(field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?);
            }
            "expires_in_hours" => {
                let t = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                expires_in_hours = t.parse().unwrap_or(72);
            }
            "max_downloads" => {
                let t = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                max_downloads = t.parse().unwrap_or(3);
            }
            "note" => {
                let t = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                note = if t.trim().is_empty() { None } else { Some(t) };
            }
            "cui_attested" => {
                cui_attested = true;
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let filename = match filename {
        Some(f) if !f.is_empty() => f,
        _ => {
            return Ok(render(&ShareNewPage {
                error: Some("No file selected.".into()),
            })?
            .into_response())
        }
    };
    let file_bytes = file_bytes.filter(|b| !b.is_empty()).ok_or(StatusCode::BAD_REQUEST)?;
    let vendor_email = vendor_email
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let vendor_display_name = vendor_display_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;

    if !cui_attested {
        return Ok(render(&ShareNewPage {
            error: Some(
                "You must attest that this file is correctly marked before sending.".into(),
            ),
        })?
        .into_response());
    }

    let has_phone = vendor_phone.is_some();
    let req = service::NewShareRequest {
        print_filename: filename,
        print_bytes: file_bytes,
        vendor_email: vendor_email.clone(),
        vendor_phone: vendor_phone.clone(),
        vendor_display_name,
        expires_in_hours,
        max_downloads,
        note,
        cui_attested,
        created_by: user.0.id,
        ip: client_ip(&headers),
        user_agent: user_agent(&headers),
    };

    match app.create_share(req).await {
        Ok(created) => {
            // With the default Null notifier, nothing was actually sent. A
            // follow-up commit will plumb real delivery status back through
            // service::ShareCreated. For now, assume manual delivery.
            render(&ShareCreatedPage {
                vendor_email: created.vendor_email,
                vendor_phone: created.vendor_phone,
                share_url: created.share_url,
                access_code: created.access_code,
                notifications_sent: false,
                sms_sent: has_phone,
            })
            .map(IntoResponse::into_response)
        }
        Err(e) => {
            tracing::error!(?e, "create_share failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn logout_post(
    State(app): State<Arc<service::App>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let token = cookie_value(&headers, SESSION_COOKIE).unwrap_or_default();
    let ip = client_ip(&headers);
    let ua = user_agent(&headers);
    if !token.is_empty() {
        if let Err(e) = app.logout(token, ip, ua).await {
            tracing::warn!(?e, "logout error");
        }
    }
    let mut resp = Redirect::to("/login").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, clear_session_cookie().parse().unwrap());
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Vendor redeem flow
// ---------------------------------------------------------------------------

async fn redeem_get(Path(token): Path<String>) -> Result<Html<String>, StatusCode> {
    render(&RedeemPromptPage { token, error: None })
}

#[derive(Deserialize)]
struct RedeemForm {
    access_code: String,
}

async fn redeem_post(
    State(app): State<Arc<service::App>>,
    Path(token): Path<String>,
    headers: HeaderMap,
    Form(form): Form<RedeemForm>,
) -> Result<Response, StatusCode> {
    let ip = client_ip(&headers);
    let ua = user_agent(&headers);
    let req = service::RedeemRequest {
        token: token.clone(),
        access_code: form.access_code.trim().to_string(),
        ip,
        user_agent: ua,
    };
    match app.redeem_share(req).await {
        Ok(resp) => {
            let filename = sanitize_filename(&resp.filename);
            let disposition = format!("attachment; filename=\"{}\"", filename);
            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_DISPOSITION, disposition),
                ],
                resp.content,
            )
                .into_response())
        }
        Err(service::ServiceError::InvalidCredentials) => Ok(render(&RedeemPromptPage {
            token,
            error: Some("That access code is not correct. Check the SMS and try again.".into()),
        })?
        .into_response()),
        Err(service::ServiceError::ShareUnavailable) => Ok(render(&RedeemPromptPage {
            token,
            error: Some(
                "This share has expired, been revoked, or reached its download limit.".into(),
            ),
        })?
        .into_response()),
        Err(service::ServiceError::NotFound) => Ok(render(&RedeemPromptPage {
            token,
            error: Some("This share link is not valid.".into()),
        })?
        .into_response()),
        Err(e) => {
            tracing::error!(?e, "redeem error");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let hdr = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in hdr.split(';') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            let (k, v) = part.split_at(eq);
            if k == name {
                return Some(v[1..].to_string());
            }
        }
    }
    None
}

fn build_session_cookie(token: &str, expires_at: time::OffsetDateTime) -> String {
    // Max-Age in seconds from now.
    let now = time::OffsetDateTime::now_utc();
    let max_age = (expires_at - now).whole_seconds().max(0);
    // Secure attribute omitted so dev over plain HTTP works. Reverse proxy /
    // production should set Secure via response rewrite or we'll add a config
    // toggle in a follow-up.
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        SESSION_COOKIE, token, max_age
    )
}

fn clear_session_cookie() -> String {
    format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        SESSION_COOKIE
    )
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '"' | '\r' | '\n' | '\0' | '/' | '\\'))
        .take(255)
        .collect()
}
