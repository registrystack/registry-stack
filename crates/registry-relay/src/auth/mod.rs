// SPDX-License-Identifier: Apache-2.0
//! Authentication trait, [`Principal`], and mode tags.
//!
//! In V1 the only implementation is [`api_key::ApiKeyAuth`], which
//! verifies `Authorization: Bearer <token>` or `x-api-key: <token>`
//! against SHA-256 fingerprints loaded from environment variables.
//!
//! ## Trait method asynchrony
//!
//! [`AuthProvider::authenticate`] is `async` so future JWT, JWKS
//! lookup, and dataspace round-trips fit without a breaking signature
//! change. V1's API-key implementation does not perform I/O during
//! verification; the async signature is purely future-proofing.
//!
//! ## Confidentiality
//!
//! Implementations MUST NOT log, format, or otherwise surface the raw
//! credential. The error returned from [`AuthProvider::authenticate`]
//! is mapped to a Problem Details response that carries only the
//! stable taxonomy code, never the token bytes.

use std::net::IpAddr;

use crate::error::AuthError;

pub mod api_key;
pub mod middleware;
pub mod oidc;
pub mod runtime;
pub mod scopes;

pub use scopes::ScopeSet;

/// Authentication mode tag. Carried on every authenticated
/// [`Principal`]; surfaced into audit records as `auth_mode`.
///
/// New variants force the compiler to flag every exhaustive match
/// site (audit serialisation, label lookup); that's the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// High-entropy API key verified against a stored SHA-256
    /// fingerprint. The mirror of `config::AuthMode::ApiKey`.
    ApiKey,
    /// Bearer JWT verified against an external OIDC / OAuth2 IdP.
    /// The mirror of `config::AuthMode::Oidc`.
    Oidc,
}

/// Result of successful authentication. Inserted into request
/// extensions by [`middleware::auth_layer`] and read by audit and
/// downstream handlers.
///
/// Keep this struct small and explicit: audit and handlers read these
/// fields directly on every protected request.
#[derive(Debug, Clone)]
pub struct Principal {
    /// Stable identifier of the authenticated caller. Source depends on
    /// the provider that produced it: for API keys, it is the configured
    /// `auth.api_keys[].id`; for OIDC, it is the JWT `sub` (or
    /// `client_id` for client-credentials tokens). Never the secret,
    /// never the hash, never a JWT; safe to log and surface in audit
    /// records.
    pub principal_id: String,

    /// Resolved scopes; gates authorisation in handlers via
    /// [`scopes::require_scope`].
    pub scopes: ScopeSet,

    /// Which auth provider produced this principal.
    pub auth_mode: AuthMode,
}

/// Authenticates inbound requests.
///
/// V1 implementation: [`api_key::ApiKeyAuth`], reading
/// `Authorization: Bearer <key>` or `x-api-key: <key>` and verifying
/// it against SHA-256 fingerprints loaded from the configured
/// `auth.api_keys[].fingerprint` references. V2 will add JWT and dataspace
/// implementations; the trait surface does not change.
///
/// ## Implementation contract
///
/// * Never log, format, or surface the raw credential. The error path
///   maps to a Problem Details response that carries only the stable
///   taxonomy code.
/// * Never store raw credential bytes in provider state. V1 stores
///   only SHA-256 fingerprints of high-entropy generated keys.
/// * Return the appropriate [`AuthError`] variant. The HTTP-status
///   mapping is owned by `crate::error`; this trait does not pick
///   statuses.
pub trait AuthProvider: Send + Sync + 'static {
    /// Authenticate a request from its headers and peer address.
    ///
    /// Returns `Ok(Principal)` on success and `Err(AuthError)`
    /// otherwise. The `remote_addr` is passed for future
    /// implementations that gate by source IP (e.g. dataspace
    /// connectors); V1 ignores it but logs it via audit downstream.
    ///
    /// Uses the explicit `Future` return type rather than `async fn`
    /// so the trait stays straightforwardly dyn-compatible if a
    /// future caller needs `dyn AuthProvider`; today the middleware
    /// is generic.
    fn authenticate<'a>(
        &'a self,
        headers: &'a axum::http::HeaderMap,
        remote_addr: IpAddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Principal, AuthError>> + Send + 'a>,
    >;
}
