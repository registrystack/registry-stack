// SPDX-License-Identifier: Apache-2.0
//! OID4VCI wire-problem mappings.

use super::super::*;

/// OAuth 2.0 token-endpoint errors per RFC 6749 / OID4VCI.
#[derive(Debug, Clone, Copy)]
pub(in crate::api) enum TokenWireError {
    InvalidRequest,
    InvalidGrant,
    UnsupportedGrantType,
    SlowDown,
    ServerError,
}

pub(in crate::api) fn token_error_response(error: TokenWireError) -> Response {
    let (status, code, description) = match error {
        TokenWireError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token request is invalid",
        ),
        TokenWireError::InvalidGrant => (
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "pre-authorized code or tx_code is invalid",
        ),
        TokenWireError::UnsupportedGrantType => (
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only the pre-authorized_code grant is supported",
        ),
        TokenWireError::SlowDown => (
            StatusCode::TOO_MANY_REQUESTS,
            "slow_down",
            "too many token requests",
        ),
        TokenWireError::ServerError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "token issuance failed",
        ),
    };
    let mut response = (
        status,
        Json(WireError::new(code, Some(description.to_string()))),
    )
        .into_response();
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext(format!("oid4vci.token.{code}")));
    response
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::api) enum Oid4vciWireError {
    InvalidRequest,
    InvalidToken,
    InvalidProof,
    UnsupportedCredentialType,
    AccessDenied,
    RateLimited,
    ServerError,
}

pub(in crate::api) fn oid4vci_error_response(error: Oid4vciWireError) -> Response {
    let (status, code, description) = match error {
        Oid4vciWireError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "credential request is invalid",
        ),
        Oid4vciWireError::InvalidToken => (
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "credential access token is invalid",
        ),
        Oid4vciWireError::InvalidProof => (
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof is invalid",
        ),
        Oid4vciWireError::UnsupportedCredentialType => (
            StatusCode::BAD_REQUEST,
            "unsupported_credential_type",
            "credential request is not supported",
        ),
        Oid4vciWireError::AccessDenied => (
            StatusCode::FORBIDDEN,
            "access_denied",
            "credential request is denied",
        ),
        Oid4vciWireError::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "credential request is rate limited",
        ),
        Oid4vciWireError::ServerError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "credential issuer failed",
        ),
    };
    let mut response = (
        status,
        Json(WireError::new(code, Some(description.to_string()))),
    )
        .into_response();
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext(format!("oid4vci.{code}")));
    response
}

pub(in crate::api) fn oid4vci_error_from_evidence(error: &EvidenceError) -> Oid4vciWireError {
    match error {
        EvidenceError::SelfAttestationRateLimited => Oid4vciWireError::RateLimited,
        EvidenceError::HolderProofRequired | EvidenceError::HolderProofReplay => {
            Oid4vciWireError::InvalidProof
        }
        EvidenceError::SelfAttestationInvalidToken
        | EvidenceError::SelfAttestationAssuranceDenied => Oid4vciWireError::InvalidToken,
        EvidenceError::FormatUnsupported | EvidenceError::CredentialIssuerNotConfigured => {
            Oid4vciWireError::UnsupportedCredentialType
        }
        EvidenceError::CredentialIssuanceFailed | EvidenceError::SourceUnavailable => {
            Oid4vciWireError::ServerError
        }
        _ => Oid4vciWireError::AccessDenied,
    }
}
