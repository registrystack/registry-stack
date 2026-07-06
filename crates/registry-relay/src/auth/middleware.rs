// SPDX-License-Identifier: Apache-2.0
//! Axum middleware that runs an [`super::AuthProvider`] in front of a router.
//!
//! On success the layer inserts [`super::Principal`] into request extensions
//! so handlers can extract it via `axum::Extension<Principal>` and so
//! the audit middleware can project it into audit records. On failure
//! it short-circuits with the RFC 9457 Problem
//! Details body produced by `crate::error::Error::into_response`.
//!
//! ## What this layer does NOT do
//!
//! * **No logging.** Audit owns request-level events; this module
//!   emits at most `trace`/`debug` for verification outcomes inside
//!   the active provider implementation. Error responses carry stable
//!   Problem Details codes and the audit layer records those codes
//!   through response extensions.
//! * **No scope check.** Scope authorisation is a handler-level
//!   concern; handlers call [`super::scopes::require_scope`] on the
//!   extracted principal.

use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;

use crate::auth::failure_throttle::{AuthFailureThrottle, Decision};
use crate::auth::Principal;
use crate::error::AuthError;
use crate::error::Error;
use crate::runtime_config::RelayRuntimeHandle;

use super::AuthProvider;

/// Type alias for the boxed, shared auth provider passed through the
/// layer. Held by `Arc<dyn>` so startup picks one implementation
/// (API-key or OIDC) and the rest of the wiring is provider-agnostic.
/// The dyn dispatch cost is one virtual call per request, dominated by
/// SHA-256 hashing (API-key path) or JWT signature verification plus
/// occasional JWKS fetches (OIDC path).
pub type AuthProviderRef = Arc<dyn AuthProvider>;

/// Auth provider facade that delegates each request to the active runtime
/// snapshot.
///
/// The protected router captures this facade once at startup. Governed apply
/// can then swap `RelayRuntimeSnapshot.auth` and subsequent requests observe
/// the new provider without rebuilding axum routes.
pub struct RuntimeAuthProvider {
    handle: Arc<RelayRuntimeHandle>,
}

impl RuntimeAuthProvider {
    #[must_use]
    pub fn new(handle: Arc<RelayRuntimeHandle>) -> Self {
        Self { handle }
    }
}

impl AuthProvider for RuntimeAuthProvider {
    fn authenticate<'a>(
        &'a self,
        headers: &'a HeaderMap,
        remote_addr: IpAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Principal, AuthError>> + Send + 'a>> {
        let provider = self.handle.load_full().auth.clone();
        Box::pin(async move { provider.authenticate(headers, remote_addr).await })
    }
}

/// Attach an authentication layer to `router`.
///
/// The provider is held in an `Arc<dyn AuthProvider>` so the startup
/// branch on `config::AuthMode` produces a single value that flows
/// through every router builder unchanged. The function is shaped as
/// `(Router, AuthProviderRef) -> Router` rather than
/// `AuthProviderRef -> impl Layer` because axum's
/// [`axum::middleware::FromFnLayer`] has a fistful of internal type
/// parameters (function pointer, state, extractor tuple) that are
/// awkward to spell in a return type without a public type alias.
/// Wrapping it here keeps the public surface a single function and
/// lets the server wiring call `auth_layer(router, provider)` in a
/// single line.
///
/// Usage in the server wiring:
/// ```ignore
/// let provider: AuthProviderRef = Arc::new(ApiKeyAuth::new(entries));
/// let app = auth_layer(
///     Router::new().route("/v1/datasets", get(list_datasets)),
///     provider,
/// );
/// ```
pub fn auth_layer<S>(router: Router<S>, provider: AuthProviderRef) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    auth_layer_with_failure_throttle(router, provider, None, false, Vec::new())
}

/// State threaded through the auth middleware. `throttle` is `None`
/// unless `auth.failure_throttle.enabled` is set, in which case
/// [`run`] is a strict no-op addition to the disabled path: every
/// branch that reads `throttle`/`trust_proxy_enabled`/`trusted_proxies`
/// is gated on `throttle.is_some()`.
#[derive(Clone)]
struct AuthMiddlewareState {
    provider: AuthProviderRef,
    throttle: Option<Arc<AuthFailureThrottle>>,
    trust_proxy_enabled: bool,
    trusted_proxies: Vec<String>,
}

/// Attach an authentication layer to `router` with an optional local
/// auth-failure throttle.
///
/// `throttle` is built from `auth.failure_throttle` (see
/// [`crate::auth::failure_throttle`]); passing `None` reproduces
/// [`auth_layer`]'s behavior exactly. `trust_proxy_enabled` and
/// `trusted_proxies` mirror `ServerConfig::trust_proxy` and are used
/// only to resolve the throttle's keying address the same way the
/// audit middleware resolves its `remote_addr` (see
/// [`crate::net::resolve_remote_addr`]); they have no effect when
/// `throttle` is `None`.
pub fn auth_layer_with_failure_throttle<S>(
    router: Router<S>,
    provider: AuthProviderRef,
    throttle: Option<Arc<AuthFailureThrottle>>,
    trust_proxy_enabled: bool,
    trusted_proxies: Vec<String>,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let state = AuthMiddlewareState {
        provider,
        throttle,
        trust_proxy_enabled,
        trusted_proxies,
    };
    router.layer(from_fn_with_state(state, run))
}

/// Middleware body. When a failure throttle is configured, resolves the
/// trust-proxy-aware client address once and checks it before calling
/// the provider; an over-limit address short-circuits with
/// `auth.rate_limited` / 429 without running authentication. Every
/// `Err` outcome from the provider (throttled or not) records a
/// failure for that address; the throttle short-circuit itself does
/// not, since it did not run authentication.
///
/// Otherwise reads the bearer token, calls the provider, and either
/// short-circuits with a Problem Details response or forwards with
/// [`super::Principal`] in request extensions.
///
/// On success the principal is also cloned onto the response
/// extensions after the inner handler runs. The audit middleware sits
/// *outside* this layer in the production stack (`crate::server`), so
/// it cannot observe extensions that this layer attaches to the
/// request. The response-side copy is the channel by which the outer
/// audit layer reads `principal_id`, `auth_mode`, and `scopes_used` for
/// the `AuditRecord`. Mirrors the `ErrorCodeExt` pattern in
/// `crate::error::Error::into_response`.
async fn run(State(state): State<AuthMiddlewareState>, mut req: Request, next: Next) -> Response {
    let remote = remote_addr(&req);

    let throttle_key = state.throttle.as_ref().map(|_| {
        crate::net::resolve_remote_addr(
            req.headers(),
            req.extensions().get::<ConnectInfo<std::net::SocketAddr>>(),
            state.trust_proxy_enabled,
            &state.trusted_proxies,
        )
        .to_string()
    });

    if let (Some(throttle), Some(key)) = (&state.throttle, &throttle_key) {
        if let Decision::Throttled {
            retry_after_seconds,
        } = throttle.check(key)
        {
            return Error::from(AuthError::RateLimited {
                retry_after_seconds,
            })
            .into_response();
        }
    }

    let principal = match state.provider.authenticate(req.headers(), remote).await {
        Ok(p) => p,
        Err(e) => {
            if let (Some(throttle), Some(key)) = (&state.throttle, &throttle_key) {
                throttle.record_failure(key);
            }
            return Error::from(e).into_response();
        }
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
