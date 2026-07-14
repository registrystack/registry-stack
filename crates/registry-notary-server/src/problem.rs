// SPDX-License-Identifier: Apache-2.0
//! Stable problem metadata shared by Notary HTTP surfaces.

use axum::http::StatusCode;
use registry_notary_core::EvidenceError;

pub(crate) const PROBLEM_TYPE_BASE_URL: &str =
    "https://id.registrystack.org/problems/registry-notary";

pub(crate) fn evidence_status(error: &EvidenceError) -> StatusCode {
    match error {
        EvidenceError::ServerDisabled
        | EvidenceError::OperationUnsupported
        | EvidenceError::CredentialIssuerNotConfigured => StatusCode::NOT_IMPLEMENTED,
        EvidenceError::FormatUnsupported => StatusCode::NOT_ACCEPTABLE,
        EvidenceError::ClaimNotFound
        | EvidenceError::ClaimVersionNotFound
        | EvidenceError::EvaluationNotFound => StatusCode::NOT_FOUND,
        EvidenceError::MissingCredential => StatusCode::UNAUTHORIZED,
        EvidenceError::MultipleCredentials => StatusCode::BAD_REQUEST,
        EvidenceError::SubjectAccessInvalidToken => StatusCode::UNAUTHORIZED,
        EvidenceError::InvalidRequest
        | EvidenceError::ConsultationInvalidRequest
        | EvidenceError::ProfileUnsupported
        | EvidenceError::HolderProofRequired
        | EvidenceError::PurposeRequired => StatusCode::BAD_REQUEST,
        EvidenceError::DisclosureNotAllowed
        | EvidenceError::EvaluationBindingMismatch
        | EvidenceError::PurposeNotAllowed
        | EvidenceError::PolicyDenied { .. }
        | EvidenceError::ScopeDenied { .. }
        | EvidenceError::SubjectAccessDenied { .. }
        | EvidenceError::SubjectAccessAssuranceDenied => StatusCode::FORBIDDEN,
        EvidenceError::EvidenceNotAvailable
        | EvidenceError::IdempotencyConflict
        | EvidenceError::HolderProofReplay => StatusCode::CONFLICT,
        EvidenceError::SubjectAccessRateLimited | EvidenceError::MachineQuotaExceeded { .. } => {
            StatusCode::TOO_MANY_REQUESTS
        }
        EvidenceError::BatchTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        EvidenceError::CredentialIssuanceFailed | EvidenceError::RuleEvaluationFailed => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub(crate) fn evidence_title(error: &EvidenceError) -> &'static str {
    match error {
        EvidenceError::ServerDisabled => "Evidence server disabled",
        EvidenceError::ClaimNotFound => "Claim not found",
        EvidenceError::ClaimVersionNotFound => "Claim version not found",
        EvidenceError::OperationUnsupported => "Claim operation unsupported",
        EvidenceError::InvalidRequest => "Invalid evidence request",
        EvidenceError::ConsultationInvalidRequest => "Invalid consultation request",
        EvidenceError::DisclosureNotAllowed => "Disclosure not allowed",
        EvidenceError::PurposeNotAllowed => "Purpose not allowed",
        EvidenceError::PolicyDenied { .. } => "Policy decision denied",
        EvidenceError::ProfileUnsupported => "Profile unsupported",
        EvidenceError::EvidenceNotAvailable => "Evidence not available",
        EvidenceError::BatchTooLarge => "Batch too large",
        EvidenceError::EvaluationNotFound => "Evaluation not found",
        EvidenceError::EvaluationBindingMismatch => "Evaluation binding mismatch",
        EvidenceError::FormatUnsupported => "Claim format not supported",
        EvidenceError::CredentialIssuerNotConfigured => "Credential issuer not configured",
        EvidenceError::HolderProofRequired => "Holder proof required",
        EvidenceError::HolderProofReplay => "Holder proof replay",
        EvidenceError::CredentialIssuanceFailed => "Credential issuance failed",
        EvidenceError::RuleEvaluationFailed => "Claim rule evaluation failed",
        EvidenceError::IdempotencyConflict => "Idempotency conflict",
        EvidenceError::PurposeRequired => "Purpose required",
        EvidenceError::MissingCredential => "Missing credential",
        EvidenceError::MultipleCredentials => "Multiple credentials",
        EvidenceError::ScopeDenied { .. } => "Scope denied",
        EvidenceError::SubjectAccessDenied { .. } => "Self-attestation denied",
        EvidenceError::SubjectAccessRateLimited => "Self-attestation rate limited",
        EvidenceError::SubjectAccessInvalidToken | EvidenceError::SubjectAccessAssuranceDenied => {
            "Self-attestation denied"
        }
        EvidenceError::MachineQuotaExceeded { .. } => "Machine quota exceeded",
        _ => "Evidence error",
    }
}

pub(crate) fn evidence_detail(error: &EvidenceError) -> &'static str {
    match error {
        EvidenceError::ServerDisabled => "the evidence server is not enabled",
        EvidenceError::ClaimNotFound => "the requested claim is not available",
        EvidenceError::ClaimVersionNotFound => "the requested claim version is not available",
        EvidenceError::OperationUnsupported => "the requested operation is not enabled",
        EvidenceError::InvalidRequest => "the evidence request is invalid",
        EvidenceError::ConsultationInvalidRequest => {
            "the registry-backed batch consultation request is invalid"
        }
        EvidenceError::DisclosureNotAllowed => "the requested disclosure profile is not allowed",
        EvidenceError::PurposeNotAllowed => "the declared purpose is not allowed",
        EvidenceError::PolicyDenied { .. } => "the configured policy denied the evidence request",
        EvidenceError::ProfileUnsupported => "the requested profile is not supported",
        EvidenceError::EvidenceNotAvailable => "the evidence is not available",
        EvidenceError::BatchTooLarge => "the batch exceeds the configured inline limit",
        EvidenceError::EvaluationNotFound => "the evaluation id is unknown or expired",
        EvidenceError::EvaluationBindingMismatch => {
            "the request exceeds the original evaluation binding"
        }
        EvidenceError::FormatUnsupported => "the requested claim format is not supported",
        EvidenceError::CredentialIssuerNotConfigured => {
            "no credential issuer is configured for this claim and format"
        }
        EvidenceError::HolderProofRequired => "holder proof of possession is required",
        EvidenceError::HolderProofReplay => "holder proof of possession has already been used",
        EvidenceError::CredentialIssuanceFailed => "credential issuance failed",
        EvidenceError::RuleEvaluationFailed => "claim rule evaluation failed",
        EvidenceError::IdempotencyConflict => {
            "the idempotency key was reused with a different request"
        }
        EvidenceError::PurposeRequired => "a data purpose is required",
        EvidenceError::MissingCredential => "missing authentication credential",
        EvidenceError::MultipleCredentials => "provide exactly one authentication credential",
        EvidenceError::ScopeDenied { .. } => "missing required scope",
        EvidenceError::SubjectAccessDenied { .. } => "subject-access request was denied",
        EvidenceError::SubjectAccessRateLimited => "subject-access request was rate limited",
        EvidenceError::SubjectAccessInvalidToken | EvidenceError::SubjectAccessAssuranceDenied => {
            "subject-access request was denied"
        }
        EvidenceError::MachineQuotaExceeded { .. } => {
            "the machine evaluation quota was exceeded for this principal"
        }
        _ => "evidence request failed",
    }
}
