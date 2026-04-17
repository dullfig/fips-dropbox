//! Session cookie extractor.
//!
//! `CurrentUser` — handler parameter; redirects to /login if unauthenticated.
//! `Option<CurrentUser>` — resolves to `None` when unauthenticated, lets the
//! handler decide (used on /login to redirect already-signed-in users).

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use std::sync::Arc;

use crate::{cookie_value, SESSION_COOKIE};

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
