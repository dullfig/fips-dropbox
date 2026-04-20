//! Auth extractors.
//!
//! `CurrentUser`  — session-cookie auth for browser routes; redirects to /login.
//! `ApiCaller`    — bearer-token auth for /api/* routes; returns JSON 401.

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use std::sync::Arc;

use crate::{cookie_value, SESSION_COOKIE};

// ---------------------------------------------------------------------------
// Session-cookie (browser)
// ---------------------------------------------------------------------------

pub struct CurrentUser(pub service::User);

/// Rejection that redirects unauthenticated requests to /login.
pub struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::to("/login").into_response()
    }
}

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
    Arc<service::App>: FromRef<S>,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match resolve_user(parts, state).await {
            Ok(Some(user)) => Ok(CurrentUser(user)),
            _ => Err(AuthRedirect),
        }
    }
}

async fn resolve_user<S>(
    parts: &mut Parts,
    state: &S,
) -> Result<Option<service::User>, StatusCode>
where
    Arc<service::App>: FromRef<S>,
{
    let token = match cookie_value(&parts.headers, SESSION_COOKIE) {
        Some(t) => t,
        None => return Ok(None),
    };
    let app = Arc::<service::App>::from_ref(state);
    match app.find_authenticated(token).await {
        Ok(Some((_sess, user))) => Ok(Some(user)),
        Ok(None) => Ok(None),
        Err(e) => {
            tracing::error!(?e, "session lookup failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ---------------------------------------------------------------------------
// Bearer token (API)
// ---------------------------------------------------------------------------

/// Authenticated API caller resolved from an `Authorization: Bearer fdbx_...` header.
pub struct ApiCaller {
    pub user: service::User,
    pub token: service::ApiToken,
}

/// JSON-bodied error response for /api/* routes.
pub struct ApiError {
    pub status: StatusCode,
    pub message: &'static str,
}

impl ApiError {
    pub const fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for ApiCaller
where
    S: Send + Sync,
    Arc<service::App>: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "missing Authorization header",
            ))?;

        let raw_token = auth.strip_prefix("Bearer ").ok_or(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Authorization must be a Bearer token",
        ))?;

        let app = Arc::<service::App>::from_ref(state);
        match app.verify_api_token(raw_token.to_string()).await {
            Ok(Some((token, user))) => Ok(ApiCaller { user, token }),
            Ok(None) => Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid or revoked token",
            )),
            Err(e) => {
                tracing::error!(?e, "verify_api_token");
                Err(ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error",
                ))
            }
        }
    }
}
