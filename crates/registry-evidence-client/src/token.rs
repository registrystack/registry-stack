//! Bearer credential acquisition for the Evidence request.
//!
//! A token never reaches a log line, an error, a `Debug` rendering, or a
//! snapshot. It is held in a wrapper that wipes its buffer on drop and is
//! exposed only where the outbound request header is built.

use std::fmt;

use async_trait::async_trait;
use thiserror::Error;
use zeroize::Zeroizing;

/// Longest accepted credential. Access tokens are bounded well below this; the
/// limit keeps a hostile provider from handing over an unbounded header.
const MAXIMUM_TOKEN_BYTES: usize = 8 * 1024;

/// One bearer credential for one outbound request.
pub struct BearerToken(Zeroizing<String>);

impl BearerToken {
    /// Accept a credential that can be placed in an `Authorization` header
    /// without escaping or folding.
    ///
    /// The rejection carries no part of the value, so an invalid credential
    /// cannot reach a diagnostic through the error path.
    pub fn new(value: impl Into<String>) -> Result<Self, TokenError> {
        let value = Zeroizing::new(value.into());
        if value.is_empty() || value.len() > MAXIMUM_TOKEN_BYTES {
            return Err(TokenError::Invalid {
                reason: "a bearer credential must be non-empty and within the accepted length",
            });
        }
        // Visible ASCII only. This is the header-safe subset, so no credential
        // can inject a carriage return, a newline, or a byte the header
        // encoder would have to escape.
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(TokenError::Invalid {
                reason: "a bearer credential must contain only visible ASCII characters",
            });
        }
        Ok(Self(value))
    }

    /// The credential text, for building exactly one outbound header.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl Clone for BearerToken {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.0.as_str().to_owned()))
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BearerToken")
            .finish_non_exhaustive()
    }
}

/// Source of the bearer credential the client presents.
///
/// Implementations may cache, refresh, or mint a credential. The client calls
/// this once per outbound request and never stores what it returns.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError>;
}

/// A credential the integrator already holds.
///
/// This is the deployment where an operator, a supervisor, or an outer service
/// supplies the access token. Renewal is that caller's responsibility.
#[derive(Debug, Clone)]
pub struct StaticToken(BearerToken);

impl StaticToken {
    pub fn new(value: impl Into<String>) -> Result<Self, TokenError> {
        Ok(Self(BearerToken::new(value)?))
    }
}

#[async_trait]
impl TokenProvider for StaticToken {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        Ok(self.0.clone())
    }
}

/// Why a credential could not be supplied.
///
/// Every message is fixed text. A provider must not place a credential, a
/// response body, or a header value in this error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenError {
    #[error("the token provider could not supply a bearer credential")]
    Unavailable,
    #[error("the bearer credential is not usable: {reason}")]
    Invalid { reason: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_static_provider_returns_the_configured_credential() {
        let provider = StaticToken::new("header-safe-token").expect("the credential is accepted");
        let token = provider
            .bearer_token()
            .await
            .expect("a static provider always succeeds");
        assert_eq!(token.expose(), "header-safe-token");
    }

    #[test]
    fn unusable_credentials_are_refused_without_echoing_them() {
        for candidate in [
            "",
            "canary space",
            "canary\ttab",
            "canary\rcarriage-return",
            "canary\nnewline",
            "canary\u{00e9}-non-ascii",
        ] {
            let error = BearerToken::new(candidate).expect_err("the credential is refused");
            let rendered = error.to_string();
            assert!(
                !rendered.contains("canary"),
                "the error rendered part of the credential: {rendered}"
            );
        }
        assert!(BearerToken::new("A".repeat(MAXIMUM_TOKEN_BYTES + 1)).is_err());
    }

    #[test]
    fn debug_output_never_carries_the_credential() {
        let token = BearerToken::new("secret-canary-value").expect("the credential is accepted");
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("secret-canary-value"), "{rendered}");

        let provider = StaticToken::new("secret-canary-value").expect("the credential is accepted");
        let rendered = format!("{provider:?}");
        assert!(!rendered.contains("secret-canary-value"), "{rendered}");
    }
}
