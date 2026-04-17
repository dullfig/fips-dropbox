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
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use std::sync::Arc;

mod auth;

use auth::CurrentUser;

pub const SESSION_COOKIE: &str = "fips_session";

pub fn router(app: Arc<service::App>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login_get).post(login_post))
        .route("/logout", post(logout_post))
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
