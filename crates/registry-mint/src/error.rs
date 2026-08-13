//! OAuth 2.0 token endpoint errors.
//!
//! The public error code is deliberately coarse. Whether a client is unknown,
//! used the wrong authentication method, presented a bad signature or secret,
//! replayed a `jti`, or sent an expired assertion, the caller sees
//! `invalid_client`. Distinguishing those cases on the wire would turn the token
//! endpoint into an oracle for probing the client registry. The specific reason
//! is retained for operator logs only.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// RFC 6749 section 5.2 error codes, restricted to the ones Mint can return.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TokenErrorCode {
    InvalidRequest,
    InvalidClient,
    UnsupportedGrantType,
    ServerError,
}

impl TokenErrorCode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::ServerError => "server_error",
        }
    }

    #[must_use]
    pub fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest | Self::UnsupportedGrantType => StatusCode::BAD_REQUEST,
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Serialize)]
struct TokenErrorBody {
    error: &'static str,
}

/// A token endpoint failure carrying a public code and a private reason.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TokenError {
    code: TokenErrorCode,
    reason: &'static str,
}

impl TokenError {
    #[must_use]
    pub fn new(code: TokenErrorCode, reason: &'static str) -> Self {
        Self { code, reason }
    }

    #[must_use]
    pub fn invalid_request(reason: &'static str) -> Self {
        Self::new(TokenErrorCode::InvalidRequest, reason)
    }

    /// Every client authentication failure collapses to this variant.
    #[must_use]
    pub fn invalid_client(reason: &'static str) -> Self {
        Self::new(TokenErrorCode::InvalidClient, reason)
    }

    #[must_use]
    pub fn unsupported_grant_type(reason: &'static str) -> Self {
        Self::new(TokenErrorCode::UnsupportedGrantType, reason)
    }

    #[must_use]
    pub fn server_error(reason: &'static str) -> Self {
        Self::new(TokenErrorCode::ServerError, reason)
    }

    #[must_use]
    pub fn code(&self) -> TokenErrorCode {
        self.code
    }

    /// Operator-facing detail. Never sent to the caller.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        self.reason
    }

    /// Render a token-operation failure with its privacy-safe correlation id.
    #[must_use]
    pub fn into_operation_response(self, operation: &str) -> Response {
        self.respond(Some(operation))
    }

    fn respond(self, operation: Option<&str>) -> Response {
        tracing::warn!(
            target: "registry_mint::token",
            operation,
            error = self.code.as_str(),
            reason = self.reason,
            "token request rejected"
        );
        (
            self.code.status(),
            Json(TokenErrorBody {
                error: self.code.as_str(),
            }),
        )
            .into_response()
    }
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        self.respond(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_authentication_failures_share_one_public_code() {
        for reason in [
            "unknown client",
            "signature did not verify",
            "client secret did not verify",
            "assertion replayed",
            "assertion expired",
        ] {
            let error = TokenError::invalid_client(reason);
            assert_eq!(error.code().as_str(), "invalid_client");
            assert_eq!(error.code().status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn public_codes_match_the_oauth_registry() {
        assert_eq!(TokenErrorCode::InvalidRequest.as_str(), "invalid_request");
        assert_eq!(TokenErrorCode::InvalidClient.as_str(), "invalid_client");
        assert_eq!(
            TokenErrorCode::UnsupportedGrantType.as_str(),
            "unsupported_grant_type"
        );
        assert_eq!(TokenErrorCode::ServerError.as_str(), "server_error");
    }
}
