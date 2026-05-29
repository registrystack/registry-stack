// SPDX-License-Identifier: Apache-2.0
//! Authentication primitives for the Registry Notary client.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

use crate::error::NotaryClientError;

#[derive(Clone)]
pub enum Auth {
    Bearer(SecretString),
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

#[derive(Clone)]
pub enum AuthHeader {
    Authorization(SecretString),
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
pub trait AuthProvider: Send + Sync {
    async fn auth_header(&self) -> Result<AuthHeader, NotaryClientError>;
}
