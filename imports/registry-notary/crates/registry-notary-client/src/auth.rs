// SPDX-License-Identifier: Apache-2.0
//! Authentication primitives for the Registry Notary client.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

use crate::error::NotaryClientError;

/// Static authentication material configured on a client.
///
/// `Debug` output redacts the underlying secret. The public builder exposes
/// this through [`crate::NotaryClientBuilder::bearer_token`] and
/// [`crate::NotaryClientBuilder::api_key`].
#[derive(Clone)]
pub enum Auth {
    /// Send an `Authorization: Bearer ...` header.
    Bearer(SecretString),
    /// Send an `X-Api-Key` header.
    ApiKey(SecretString),
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("Bearer(<redacted>)"),
            Self::ApiKey(_) => f.write_str("ApiKey(<redacted>)"),
        }
    }
}

/// One resolved authentication header for a single request.
///
/// Implementations of [`AuthProvider`] return this type when credentials are
/// minted or refreshed dynamically. `Debug` and `Display` never print the
/// secret value.
#[derive(Clone)]
pub enum AuthHeader {
    /// A complete `Authorization` header value, for example `Bearer <token>`.
    Authorization(SecretString),
    /// An `X-Api-Key` header value.
    ApiKey(SecretString),
}

impl std::fmt::Debug for AuthHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authorization(_) => f.write_str("Authorization(<redacted>)"),
            Self::ApiKey(_) => f.write_str("ApiKey(<redacted>)"),
        }
    }
}

impl std::fmt::Display for AuthHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Auth {
    pub(crate) fn header(&self) -> AuthHeader {
        match self {
            Self::Bearer(token) => AuthHeader::Authorization(SecretString::from(format!(
                "Bearer {}",
                token.expose_secret()
            ))),
            Self::ApiKey(token) => AuthHeader::ApiKey(token.clone()),
        }
    }
}

#[async_trait]
/// Dynamic per-request authentication provider.
///
/// Use this when a caller needs to refresh an access token, consult a secure
/// credential store, or mint short-lived credentials before each request. The
/// client awaits the provider before sending the request and still enforces the
/// single-auth-mode rule at build time.
pub trait AuthProvider: Send + Sync {
    /// Return the authentication header to attach to the next request.
    async fn auth_header(&self) -> Result<AuthHeader, NotaryClientError>;
}
