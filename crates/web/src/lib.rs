//! # web — axum HTTP layer
//!
//! Routes:
//!   GET  /                       — dashboard (admin)
//!   GET  /login                  — login form
//!   POST /login                  — credentials + TOTP
//!   GET  /shares                 — admin: list outgoing shares
//!   POST /api/shares             — sender-agent: create a share
//!   GET  /r/:token               — vendor: access-code prompt
//!   POST /r/:token               — vendor: submit code, receive file
//!   GET  /health                 — liveness
//!
//! TLS is provided by the host (IIS reverse-proxy or direct Schannel),
//! NOT by this crate. The binary binds to 127.0.0.1 and the reverse proxy
//! handles TLS termination using the FIPS-mode Schannel stack.

use axum::{routing::get, Router};
use std::sync::Arc;

pub fn router(app: Arc<service::App>) -> Router {
    Router::new()
        .route("/health", get(health))
        .with_state(app)
    // TODO week 3: add /, /login, /shares, /api/shares, /r/:token.
}

async fn health() -> &'static str {
    "ok"
}
