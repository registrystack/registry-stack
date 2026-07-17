// SPDX-License-Identifier: Apache-2.0
//! Axum middleware that runs an [`super::AuthProvider`] in front of a router.
//!
//! On success the layer inserts [`super::Principal`] into request extensions.
//! The coupled [`super::AuthenticationResult`] is also inserted so consultation
//! handlers can bind verified OIDC issuer, audiences, and client claims to
//! fixed workload configuration without pairing independent extensions. The
//! audit middleware projects the common principal into audit records. On failure
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

use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::HeaderMap;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;

use crate::auth::failure_throttle::{AuthFailureThrottle, Decision};
use crate::auth::AuthenticationResult;
use crate::error::{AuthError, ConsultationError, Error};
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
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<AuthenticationResult, AuthError>> + Send + 'a>,
    > {
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
/// `auth.rate_limited` / 429 without running authentication. Client-
/// attributable `Err` outcomes from the provider record a failure for
/// that address; infrastructure errors such as JWKS outages do not.
/// The throttle short-circuit itself does not record a failure, since
/// it did not run authentication.
///
/// Otherwise reads the bearer token, calls the provider, and either
/// short-circuits with a Problem Details response or forwards with
/// [`super::Principal`] and the coupled [`super::AuthenticationResult`] in
/// request extensions.
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
    let consultation_operation = matches!(
        req.extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
        Some(crate::api::consultation::PROFILE_ROUTE)
            | Some(crate::api::consultation::EXECUTE_ROUTE)
    );

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
            return auth_error_response(
                AuthError::RateLimited {
                    retry_after_seconds,
                },
                consultation_operation,
            );
        }
    }

    let authentication = match state.provider.authenticate(req.headers(), remote).await {
        Ok(authentication) => authentication,
        Err(e) => {
            if e.counts_toward_failure_throttle() {
                if let (Some(throttle), Some(key)) = (&state.throttle, &throttle_key) {
                    throttle.record_failure(key);
                }
            }
            return auth_error_response(e, consultation_operation);
        }
    };
    if consultation_operation {
        // Consultation owns a narrower audit identity boundary. The handler
        // needs the coupled verified authentication, but the generic HTTP
        // audit deliberately never consumes a standalone principal or scopes.
        req.extensions_mut().insert(authentication);
        return next.run(req).await;
    }

    let principal_for_audit = authentication.principal().clone();
    req.extensions_mut().insert(principal_for_audit.clone());
    req.extensions_mut().insert(authentication);
    let mut response = next.run(req).await;
    response.extensions_mut().insert(principal_for_audit);
    response
}

/// Render shared authentication failures through the closed consultation
/// taxonomy only for the two exact mounted consultation operations. Every
/// other Relay route keeps the existing granular `auth.*` contract.
fn auth_error_response(error: AuthError, consultation_operation: bool) -> Response {
    if !consultation_operation {
        return Error::from(error).into_response();
    }

    let (error, retry_after_seconds) = match error {
        AuthError::MissingCredential
        | AuthError::InvalidCredential
        | AuthError::MalformedCredential
        | AuthError::TokenExpired
        | AuthError::TokenNotYetValid
        | AuthError::TokenSignatureInvalid
        | AuthError::IssuerMismatch
        | AuthError::AudienceMismatch
        | AuthError::KidUnknown
        | AuthError::AlgorithmNotAllowed
        | AuthError::ClientNotAllowed => (ConsultationError::InvalidCredentials, None),
        AuthError::MultipleCredentials => (ConsultationError::MultipleCredentials, None),
        AuthError::PurposeRequired => (ConsultationError::InvalidRequest, None),
        AuthError::ScopeDenied { .. } | AuthError::PurposeDenied | AuthError::AdminRequired => {
            (ConsultationError::Denied, None)
        }
        AuthError::JwksUnavailable => (ConsultationError::Unavailable, None),
        AuthError::RateLimited {
            retry_after_seconds,
        } => (ConsultationError::RateLimited, Some(retry_after_seconds)),
    };
    crate::api::consultation::consultation_error_response(error, retry_after_seconds)
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use axum::body::{to_bytes, Body};
    use axum::extract::Extension;
    use axum::http::{header, Method, Request, StatusCode};
    use axum::routing::{get, post};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{AuthMode, AuthenticationResult, Principal, ScopeSet, VerifiedOidcIdentity};

    struct FixedAuthProvider(AuthenticationResult);

    impl AuthProvider for FixedAuthProvider {
        fn authenticate<'a>(
            &'a self,
            _headers: &'a HeaderMap,
            _remote_addr: IpAddr,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<AuthenticationResult, AuthError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(self.0.clone()) })
        }
    }

    struct RejectingAuthProvider(fn() -> AuthError);

    impl AuthProvider for RejectingAuthProvider {
        fn authenticate<'a>(
            &'a self,
            _headers: &'a HeaderMap,
            _remote_addr: IpAddr,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<AuthenticationResult, AuthError>>
                    + Send
                    + 'a,
            >,
        > {
            let error = (self.0)();
            Box::pin(async move { Err(error) })
        }
    }

    async fn authentication_handler(
        Extension(authentication): Extension<AuthenticationResult>,
    ) -> axum::Json<Value> {
        let identity = authentication.verified_oidc();
        axum::Json(serde_json::json!({
            "auth_mode": match authentication.auth_mode {
                AuthMode::ApiKey => "api_key",
                AuthMode::Oidc => "oidc",
            },
            "issuer": identity.map(VerifiedOidcIdentity::issuer),
            "audiences": identity.map(|identity| identity.audiences().collect::<Vec<_>>()),
            "authorized_party": identity.and_then(VerifiedOidcIdentity::authorized_party),
            "client_id_claim": identity.and_then(VerifiedOidcIdentity::client_id_claim),
        }))
    }

    fn oidc_authentication() -> AuthenticationResult {
        let identity = VerifiedOidcIdentity::from_verified_claims(
            "https://issuer.example".to_string(),
            BTreeSet::from(["registry-relay".to_string()]),
            Some("registry-notary".to_string()),
            Some("notary-client-id".to_string()),
            4_102_444_800,
        )
        .expect("valid verified identity");
        AuthenticationResult::oidc(
            Principal {
                principal_id: "notary-service".to_string(),
                scopes: ScopeSet::from_iter(["registry:consult"]),
                auth_mode: AuthMode::Oidc,
            },
            identity,
        )
        .expect("consistent OIDC authentication")
    }

    #[tokio::test]
    async fn middleware_inserts_verified_oidc_identity_from_the_same_authentication() {
        let app = auth_layer(
            Router::new().route("/identity", get(authentication_handler)),
            Arc::new(FixedAuthProvider(oidc_authentication())),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert!(response.status().is_success());
        let body = to_bytes(response.into_body(), 8 * 1024)
            .await
            .expect("bounded response");
        let value: Value = serde_json::from_slice(&body).expect("JSON response");
        assert_eq!(value["issuer"], "https://issuer.example");
        assert_eq!(value["audiences"], serde_json::json!(["registry-relay"]));
        assert_eq!(value["authorized_party"], "registry-notary");
        assert_eq!(value["client_id_claim"], "notary-client-id");
    }

    #[tokio::test]
    async fn api_key_authentication_replaces_preloaded_oidc_context() {
        let api_key_authentication = AuthenticationResult::api_key(Principal {
            principal_id: "api-key-client".to_string(),
            scopes: ScopeSet::from_iter(["registry:consult"]),
            auth_mode: AuthMode::ApiKey,
        })
        .expect("consistent API-key authentication");
        let app = auth_layer(
            Router::new().route("/identity", get(authentication_handler)),
            Arc::new(FixedAuthProvider(api_key_authentication)),
        );
        let mut request = Request::builder()
            .uri("/identity")
            .body(Body::empty())
            .expect("request");
        request.extensions_mut().insert(oidc_authentication());

        let response = app.oneshot(request).await.expect("response");
        assert!(response.status().is_success());
        let body = to_bytes(response.into_body(), 8 * 1024)
            .await
            .expect("bounded response");
        let value: Value = serde_json::from_slice(&body).expect("JSON response");
        assert_eq!(value["auth_mode"], "api_key");
        assert_eq!(value["issuer"], Value::Null);
        assert_eq!(value["authorized_party"], Value::Null);
        assert_eq!(value["client_id_claim"], Value::Null);
    }

    #[tokio::test]
    async fn exact_consultation_routes_collapse_every_typed_auth_failure() {
        type ErrorFactory = fn() -> AuthError;
        let cases: Vec<(ErrorFactory, StatusCode, &'static str, Option<&'static str>)> = vec![
            (
                || AuthError::MissingCredential,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
                None,
            ),
            (
                || AuthError::InvalidCredential,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
                None,
            ),
            (
                || AuthError::MalformedCredential,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
                None,
            ),
            (
                || AuthError::MultipleCredentials,
                StatusCode::BAD_REQUEST,
                "auth.multiple_credentials",
                None,
            ),
            (
                || AuthError::ScopeDenied {
                    required: "configured-sensitive-scope".to_string(),
                },
                StatusCode::FORBIDDEN,
                "consultation.denied",
                None,
            ),
            (
                || AuthError::PurposeRequired,
                StatusCode::BAD_REQUEST,
                "consultation.invalid_request",
                None,
            ),
            (
                || AuthError::PurposeDenied,
                StatusCode::FORBIDDEN,
                "consultation.denied",
                None,
            ),
            (
                || AuthError::AdminRequired,
                StatusCode::FORBIDDEN,
                "consultation.denied",
                None,
            ),
            (
                || AuthError::TokenExpired,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
                None,
            ),
            (
                || AuthError::TokenNotYetValid,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
                None,
            ),
            (
                || AuthError::TokenSignatureInvalid,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
                None,
            ),
            (
                || AuthError::IssuerMismatch,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
                None,
            ),
            (
                || AuthError::AudienceMismatch,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
                None,
            ),
            (
                || AuthError::KidUnknown,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
                None,
            ),
            (
                || AuthError::AlgorithmNotAllowed,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
                None,
            ),
            (
                || AuthError::ClientNotAllowed,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
                None,
            ),
            (
                || AuthError::JwksUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "consultation.unavailable",
                None,
            ),
            (
                || AuthError::RateLimited {
                    retry_after_seconds: 600,
                },
                StatusCode::TOO_MANY_REQUESTS,
                "consultation.rate_limited",
                Some("60"),
            ),
        ];
        let routes = [
            (
                crate::api::consultation::PROFILE_ROUTE,
                "/v1/consultations/example",
                Method::GET,
            ),
            (
                crate::api::consultation::EXECUTE_ROUTE,
                "/v1/consultations/example/execute",
                Method::POST,
            ),
        ];

        for (route, uri, method) in routes {
            for (error, expected_status, expected_code, expected_retry_after) in &cases {
                let app = auth_layer(
                    Router::new()
                        .route(
                            crate::api::consultation::PROFILE_ROUTE,
                            get(|| async { StatusCode::NO_CONTENT }),
                        )
                        .route(
                            crate::api::consultation::EXECUTE_ROUTE,
                            post(|| async { StatusCode::NO_CONTENT }),
                        ),
                    Arc::new(RejectingAuthProvider(*error)),
                );
                let response = app
                    .oneshot(
                        Request::builder()
                            .method(method.clone())
                            .uri(uri)
                            .body(Body::empty())
                            .expect("consultation request builds"),
                    )
                    .await
                    .expect("auth middleware responds");
                assert_eq!(response.status(), *expected_status, "route {route}");
                assert_eq!(
                    response
                        .extensions()
                        .get::<crate::audit::ErrorCodeExt>()
                        .map(|code| code.0.as_str()),
                    Some(*expected_code),
                    "route {route}"
                );
                assert_eq!(
                    response
                        .headers()
                        .get(header::RETRY_AFTER)
                        .and_then(|value| value.to_str().ok()),
                    *expected_retry_after,
                    "route {route}"
                );
                let body = to_bytes(response.into_body(), 8 * 1024)
                    .await
                    .expect("bounded problem body reads");
                let body: Value = serde_json::from_slice(&body).expect("problem body is JSON");
                assert_eq!(body["code"], *expected_code, "route {route}");
                assert!(!body.to_string().contains("configured-sensitive-scope"));
            }
        }
    }

    #[tokio::test]
    async fn successful_consultation_auth_does_not_retain_generic_audit_principal() {
        let app = auth_layer(
            Router::new().route(
                crate::api::consultation::PROFILE_ROUTE,
                get(authentication_handler),
            ),
            Arc::new(FixedAuthProvider(oidc_authentication())),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/consultations/example")
                    .body(Body::empty())
                    .expect("consultation request builds"),
            )
            .await
            .expect("auth middleware responds");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.extensions().get::<Principal>().is_none());
        let body = to_bytes(response.into_body(), 8 * 1024)
            .await
            .expect("bounded response reads");
        let body: Value = serde_json::from_slice(&body).expect("response body is JSON");
        assert_eq!(body["authorized_party"], "registry-notary");
    }

    #[tokio::test]
    async fn non_consultation_route_keeps_granular_auth_failure() {
        let app = auth_layer(
            Router::new().route("/identity", get(|| async { StatusCode::NO_CONTENT })),
            Arc::new(RejectingAuthProvider(|| AuthError::TokenExpired)),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("auth middleware responds");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .extensions()
                .get::<crate::audit::ErrorCodeExt>()
                .map(|code| code.0.as_str()),
            Some("auth.token_expired")
        );
        let body = to_bytes(response.into_body(), 8 * 1024)
            .await
            .expect("bounded problem body reads");
        let body: Value = serde_json::from_slice(&body).expect("problem body is JSON");
        assert_eq!(body["code"], "auth.token_expired");
    }

    #[tokio::test]
    async fn consultation_auth_throttle_short_circuit_uses_closed_taxonomy() {
        let throttle = Arc::new(
            AuthFailureThrottle::new(&crate::config::AuthFailureThrottleConfig {
                enabled: true,
                max_failures: 1,
                window_seconds: 600,
            })
            .expect("enabled throttle"),
        );
        throttle.record_failure("0.0.0.0");
        let app = auth_layer_with_failure_throttle(
            Router::new().route(
                crate::api::consultation::PROFILE_ROUTE,
                get(|| async { StatusCode::NO_CONTENT }),
            ),
            Arc::new(FixedAuthProvider(oidc_authentication())),
            Some(throttle),
            false,
            Vec::new(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/consultations/example")
                    .body(Body::empty())
                    .expect("consultation request builds"),
            )
            .await
            .expect("auth middleware responds");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .extensions()
                .get::<crate::audit::ErrorCodeExt>()
                .map(|code| code.0.as_str()),
            Some("consultation.rate_limited")
        );
        assert_eq!(response.headers()[header::RETRY_AFTER], "60");
    }
}
