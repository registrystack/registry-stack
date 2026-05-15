// SPDX-License-Identifier: Apache-2.0
//! Axum middleware that runs an [`AuthProvider`] in front of a router.
//!
//! On success the layer inserts [`Principal`] into request extensions
//! so handlers can extract it via `axum::Extension<Principal>` and so
//! the audit middleware (Wave 0 Track 5) can project it into audit
//! records. On failure it short-circuits with the RFC 9457 Problem
//! Details body produced by `crate::error::Error::into_response`.
//!
//! ## What this layer does NOT do
//!
//! * **No logging.** Audit owns request-level events; this module
//!   emits at most `trace`/`debug` for verification outcomes inside
//!   [`super::api_key::ApiKeyAuth`]. Per `decisions/wave-0.md`
//!   Section 7 the auth middleware "annotates the request extension
//!   with the error code so the audit middleware can still emit a
//!   record"; that annotation will be wired in when audit lands. For
//!   Wave 0 Track 4 in isolation the response carries the code in
//!   its Problem Details body, which is sufficient to assert against
//!   from integration tests.
//! * **No scope check.** Scope authorisation is a handler-level
//!   concern; handlers call [`super::scopes::require_scope`] on the
//!   extracted principal. A middleware-level enforcement layer for
//!   admin paths is in scope for Wave 4.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;

use crate::error::Error;

use super::AuthProvider;

/// Attach an authentication layer to `router`.
///
/// The provider is held in an `Arc` so the layer is cheap to clone
/// per request without duplicating the keyring. The function is
/// generic on the provider type to avoid `dyn` dispatch on the hot
/// path; callers stamp one `auth_layer::<ApiKeyAuth>(...)` site at
/// startup.
///
/// This function is shaped as `(Router, Arc<P>) -> Router` rather
/// than `Arc<P> -> impl Layer` because axum's
/// [`axum::middleware::FromFnLayer`] has a fistful of internal type
/// parameters (function pointer, state, extractor tuple) that are
/// awkward to spell in a return type without a public type alias.
/// Wrapping it here keeps the public surface a single function and
/// lets the server wiring call `auth_layer(router, provider)` in a
/// single line.
///
/// Usage in the server wiring (Wave 0 Track 6):
/// ```ignore
/// let provider = Arc::new(ApiKeyAuth::new(entries));
/// let app = auth_layer(
///     Router::new().route("/datasets", get(list_datasets)),
///     provider,
/// );
/// ```
pub fn auth_layer<P, S>(router: Router<S>, provider: Arc<P>) -> Router<S>
where
    P: AuthProvider,
    S: Clone + Send + Sync + 'static,
{
    router.layer(from_fn_with_state(provider, run::<P>))
}

/// Middleware body. Reads the bearer token, calls the provider, and
/// either short-circuits with a Problem Details response or
/// forwards with [`super::Principal`] in request extensions.
///
/// On success the principal is also cloned onto the response
/// extensions after the inner handler runs. The audit middleware sits
/// *outside* this layer in the production stack (`crate::server`), so
/// it cannot observe extensions that this layer attaches to the
/// request. The response-side copy is the channel by which the outer
/// audit layer reads `api_key_id`, `auth_mode`, and `scopes_used` for
/// the `AuditRecord`. Mirrors the `ErrorCodeExt` pattern in
/// `crate::error::Error::into_response`.
async fn run<P>(State(provider): State<Arc<P>>, mut req: Request, next: Next) -> Response
where
    P: AuthProvider,
{
    let remote = remote_addr(&req);
    let principal = match provider.authenticate(req.headers(), remote).await {
        Ok(p) => p,
        Err(e) => return Error::from(e).into_response(),
    };
    let principal_for_audit = principal.clone();
    req.extensions_mut().insert(principal);
    let mut response = next.run(req).await;
    response.extensions_mut().insert(principal_for_audit);
    response
}

/// Resolve the peer IP for the trait method. Falls back to
/// `0.0.0.0` when the connection info extension is not present (e.g.
/// in `tower::ServiceExt::oneshot` tests). Production callers install
/// `tower-http`'s request-id / trust-proxy layers upstream of this
/// middleware so the trusted-proxy policy in
/// `ServerConfig::trust_proxy` takes effect before the IP reaches us.
fn remote_addr(req: &Request) -> IpAddr {
    req.extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ci| ci.0.ip())
}
