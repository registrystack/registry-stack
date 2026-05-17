// SPDX-License-Identifier: Apache-2.0
//! OIDC / OAuth2 resource-server [`AuthProvider`].
//!
//! The relay is a resource server, not an authorization server: it
//! validates inbound bearer JWTs against an external IdP's JWKS but
//! never mints, refreshes, or stores tokens. Token verification covers
//! the standard claims (`iss`, `aud`, `exp`, optional `nbf`) plus the
//! relay-specific shape checks documented on [`provider::OidcAuth`].
//!
//! Submodules:
//!
//! * [`jwks`]: lock-free JWKS cache with refresh-on-unknown-kid and
//!   rate-limited retries.
//! * [`provider`]: the [`super::AuthProvider`] implementation, plus
//!   claim parsing and scope extraction.
//! * [`fetcher`]: HTTP [`jwks::JwksFetcher`] backed by reqwest, plus
//!   optional discovery-document resolution.
//!
//! All three modules are re-exported below so call sites can `use
//! crate::auth::oidc::{JwksCache, OidcAuth, ReqwestJwksFetcher, ...}`
//! without naming the internal layout.

pub mod fetcher;
pub mod jwks;
pub mod provider;

pub use fetcher::ReqwestJwksFetcher;
pub use jwks::{
    static_fetcher, JwksCache, JwksError, JwksFetchError, JwksFetchResult, JwksFetcher,
};
pub use provider::OidcAuth;
