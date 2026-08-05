//! Bearer credential acquisition for the Evidence request.
//!
//! A token never reaches a log line, an error, a `Debug` rendering, or a
//! snapshot. It is held in a wrapper that wipes its buffer on drop and is
//! exposed only where the outbound request header is built.

use std::fmt;

use async_trait::async_trait;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::error::TransportKind;

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

    /// The provider cannot be used as configured. The reason is fixed text
    /// chosen by the provider, never caller data and never key material.
    #[error("the token provider cannot be used as configured: {reason}")]
    Configuration { reason: &'static str },

    /// The exchange with the authorization server did not complete.
    #[error("the token request did not complete: {kind}")]
    Transport { kind: TransportKind },

    /// The authorization server declined to issue a token. The registered error
    /// code is the whole of what is reported.
    #[error("the authorization server declined to issue a token: {code}")]
    Refused { code: OAuthErrorCode },

    /// The answer was not a token response this crate can use: an unexpected
    /// status, an unexpected media type, an unreadable body, or a token type the
    /// Evidence request cannot present.
    #[error("the token response does not satisfy the OAuth 2.0 contract: status {status}")]
    Protocol { status: u16 },
}

impl TokenError {
    /// A stable, machine-readable name for which kind of token failure this is.
    ///
    /// It exists for callers that have to branch or aggregate without matching
    /// an enum this crate may extend: a metric label, a structured log field, or
    /// a language binding that carries the discriminant across a boundary. The
    /// rendered message is for people and may be reworded; these names are part
    /// of the crate's contract and will not be renamed. A variant added later
    /// brings a new name rather than reusing one of these.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Invalid { .. } => "invalid_credential",
            Self::Configuration { .. } => "configuration",
            Self::Transport { .. } => "transport",
            Self::Refused { .. } => "refused",
            Self::Protocol { .. } => "protocol",
        }
    }
}

/// The OAuth 2.0 error code an authorization server returned.
///
/// This code is all a refused token request reports. The accompanying
/// `error_description` is server-authored text about a failed authentication
/// attempt, so it is dropped where the body is parsed rather than carried into a
/// diagnostic, and the client assertion and the key that signed it are never part
/// of any of these values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    /// A code outside RFC 6749 section 5.2. The server's own spelling is
    /// deliberately not kept: it is unbounded text from the failed exchange, and
    /// the extension registry is open, so no closed variant could hold it.
    Other,
}

impl OAuthErrorCode {
    /// The registered spelling, or a fixed name for a code from outside the
    /// section 5.2 set.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::Other => "unregistered_error_code",
        }
    }

    /// Read a code off the wire, keeping only whether it is one this crate names.
    pub(crate) fn from_wire(code: &str) -> Self {
        match code {
            "invalid_request" => Self::InvalidRequest,
            "invalid_client" => Self::InvalidClient,
            "invalid_grant" => Self::InvalidGrant,
            "unauthorized_client" => Self::UnauthorizedClient,
            "unsupported_grant_type" => Self::UnsupportedGrantType,
            "invalid_scope" => Self::InvalidScope,
            _ => Self::Other,
        }
    }
}

impl fmt::Display for OAuthErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
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

    /// A refusal names the registered code and nothing else, and every acquisition
    /// failure renders as its own sentence so a support conversation can start
    /// from the message alone.
    #[test]
    fn acquisition_failures_render_their_own_fixed_text() {
        let cases = [
            (
                TokenError::Configuration {
                    reason: "the client identifier must not be empty",
                },
                "the token provider cannot be used as configured: the client identifier must not be empty",
            ),
            (
                TokenError::Transport {
                    kind: TransportKind::Connect,
                },
                "the token request did not complete: connection setup failed",
            ),
            (
                TokenError::Refused {
                    code: OAuthErrorCode::InvalidClient,
                },
                "the authorization server declined to issue a token: invalid_client",
            ),
            (
                TokenError::Refused {
                    code: OAuthErrorCode::Other,
                },
                "the authorization server declined to issue a token: unregistered_error_code",
            ),
            (
                TokenError::Protocol { status: 500 },
                "the token response does not satisfy the OAuth 2.0 contract: status 500",
            ),
        ];
        for (error, rendered) in &cases {
            assert_eq!(&error.to_string(), rendered);
        }
        let renderings: std::collections::BTreeSet<String> =
            cases.iter().map(|(error, _)| error.to_string()).collect();
        assert_eq!(
            renderings.len(),
            cases.len(),
            "two failures render the same text"
        );
    }

    /// The discriminant is what a binding, a metric label, or a caller's own
    /// branch reads, so every variant has one and no two share it.
    #[test]
    fn every_token_failure_reports_its_own_stable_kind() {
        let cases = [
            (TokenError::Unavailable, "unavailable"),
            (
                TokenError::Invalid {
                    reason: "a bearer credential must be non-empty and within the accepted length",
                },
                "invalid_credential",
            ),
            (
                TokenError::Configuration {
                    reason: "the client identifier must not be empty",
                },
                "configuration",
            ),
            (
                TokenError::Transport {
                    kind: TransportKind::Connect,
                },
                "transport",
            ),
            (
                TokenError::Refused {
                    code: OAuthErrorCode::InvalidClient,
                },
                "refused",
            ),
            (TokenError::Protocol { status: 500 }, "protocol"),
        ];
        for (error, kind) in &cases {
            assert_eq!(error.kind(), *kind, "{error}");
        }
        let kinds: std::collections::BTreeSet<&str> =
            cases.iter().map(|(error, _)| error.kind()).collect();
        assert_eq!(kinds.len(), cases.len(), "two variants share a kind");
    }

    /// A server may spell a code however it likes. Only the registered set is
    /// named, so an unbounded spelling cannot travel in the error.
    #[test]
    fn unregistered_error_codes_collapse_to_one_name() {
        assert_eq!(
            OAuthErrorCode::from_wire("invalid_request"),
            OAuthErrorCode::InvalidRequest
        );
        assert_eq!(
            OAuthErrorCode::from_wire("invalid_client"),
            OAuthErrorCode::InvalidClient
        );
        assert_eq!(
            OAuthErrorCode::from_wire("invalid_grant"),
            OAuthErrorCode::InvalidGrant
        );
        assert_eq!(
            OAuthErrorCode::from_wire("unauthorized_client"),
            OAuthErrorCode::UnauthorizedClient
        );
        assert_eq!(
            OAuthErrorCode::from_wire("unsupported_grant_type"),
            OAuthErrorCode::UnsupportedGrantType
        );
        assert_eq!(
            OAuthErrorCode::from_wire("invalid_scope"),
            OAuthErrorCode::InvalidScope
        );
        for candidate in ["", "Invalid_Client", "canary_extension_code"] {
            let code = OAuthErrorCode::from_wire(candidate);
            assert_eq!(code, OAuthErrorCode::Other, "{candidate}");
            assert!(!code.to_string().contains("canary"), "{candidate}");
        }
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
