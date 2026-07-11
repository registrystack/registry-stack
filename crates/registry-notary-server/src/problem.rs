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
        | EvidenceError::SourceNotFound
        | EvidenceError::RequesterNotFound
        | EvidenceError::EvaluationNotFound => StatusCode::NOT_FOUND,
        EvidenceError::MissingCredential => StatusCode::UNAUTHORIZED,
        EvidenceError::MultipleCredentials => StatusCode::BAD_REQUEST,
        EvidenceError::SelfAttestationInvalidToken => StatusCode::UNAUTHORIZED,
        EvidenceError::InvalidRequest
        | EvidenceError::TargetIdentifierMissing
        | EvidenceError::TargetAttributesInsufficient
        | EvidenceError::RequesterIdentifierMissing
        | EvidenceError::RequesterAttributesInsufficient
        | EvidenceError::RelationshipAttributesInsufficient
        | EvidenceError::ProfileUnsupported
        | EvidenceError::HolderProofRequired
        | EvidenceError::PurposeRequired => StatusCode::BAD_REQUEST,
        EvidenceError::DisclosureNotAllowed
        | EvidenceError::EvaluationBindingMismatch
        | EvidenceError::PurposeNotAllowed
        | EvidenceError::PolicyDenied { .. }
        | EvidenceError::RequesterReauthenticationRequired
        | EvidenceError::RequesterMatchingPolicyRejected
        | EvidenceError::TargetMatchingPolicyRejected
        | EvidenceError::RelationshipNotEstablished
        | EvidenceError::RelationshipPurposeNotAllowed
        | EvidenceError::RelationshipPolicyRejected
        | EvidenceError::ScopeDenied { .. }
        | EvidenceError::SelfAttestationDenied { .. }
        | EvidenceError::SelfAttestationAssuranceDenied => StatusCode::FORBIDDEN,
        EvidenceError::SourceAmbiguous
        | EvidenceError::RequesterMatchAmbiguous
        | EvidenceError::RelationshipMatchAmbiguous
        | EvidenceError::TargetNotInValidState
        | EvidenceError::TargetMatchLowConfidence
        | EvidenceError::EvidenceNotAvailable
        | EvidenceError::MatchingEvidenceNotAvailable { .. }
        | EvidenceError::IdempotencyConflict
        | EvidenceError::HolderProofReplay => StatusCode::CONFLICT,
        EvidenceError::SourceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        EvidenceError::SelfAttestationRateLimited | EvidenceError::MachineQuotaExceeded { .. } => {
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
        EvidenceError::DisclosureNotAllowed => "Disclosure not allowed",
        EvidenceError::SourceNotFound => "Target not found",
        EvidenceError::SourceAmbiguous => "Target match ambiguous",
        EvidenceError::TargetIdentifierMissing => "Target identifier missing",
        EvidenceError::TargetAttributesInsufficient => "Target attributes insufficient",
        EvidenceError::TargetMatchingPolicyRejected => "Target matching policy rejected",
        EvidenceError::TargetNotInValidState => "Target not in valid state",
        EvidenceError::TargetMatchLowConfidence => "Target match confidence too low",
        EvidenceError::RequesterNotFound => "Requester not found",
        EvidenceError::RequesterMatchAmbiguous => "Requester match ambiguous",
        EvidenceError::RequesterIdentifierMissing => "Requester identifier missing",
        EvidenceError::RequesterAttributesInsufficient => "Requester attributes insufficient",
        EvidenceError::RequesterMatchingPolicyRejected => "Requester matching policy rejected",
        EvidenceError::RequesterReauthenticationRequired => "Requester reauthentication required",
        EvidenceError::RelationshipNotEstablished => "Relationship not established",
        EvidenceError::RelationshipMatchAmbiguous => "Relationship match ambiguous",
        EvidenceError::RelationshipAttributesInsufficient => "Relationship attributes insufficient",
        EvidenceError::RelationshipPolicyRejected => "Relationship policy rejected",
        EvidenceError::RelationshipPurposeNotAllowed => "Relationship purpose not allowed",
        EvidenceError::PurposeNotAllowed => "Purpose not allowed",
        EvidenceError::PolicyDenied { .. } => "Policy decision denied",
        EvidenceError::ProfileUnsupported => "Profile unsupported",
        EvidenceError::EvidenceNotAvailable
        | EvidenceError::MatchingEvidenceNotAvailable { .. } => "Evidence not available",
        EvidenceError::SourceUnavailable => "Source unavailable",
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
        EvidenceError::SelfAttestationDenied { .. } => "Self-attestation denied",
        EvidenceError::SelfAttestationRateLimited => "Self-attestation rate limited",
        EvidenceError::SelfAttestationInvalidToken
        | EvidenceError::SelfAttestationAssuranceDenied => "Self-attestation denied",
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
        EvidenceError::DisclosureNotAllowed => "the requested disclosure profile is not allowed",
        EvidenceError::SourceNotFound => "the target could not be uniquely matched",
        EvidenceError::SourceAmbiguous => "the target match is ambiguous",
        EvidenceError::TargetIdentifierMissing => {
            "a required target identifier is missing for the configured matching policy"
        }
        EvidenceError::TargetAttributesInsufficient => {
            "the target data is insufficient for the configured matching policy"
        }
        EvidenceError::TargetMatchingPolicyRejected => {
            "the target context is rejected by the configured matching policy"
        }
        EvidenceError::TargetNotInValidState => "the target is not in a valid state",
        EvidenceError::TargetMatchLowConfidence => {
            "the target match confidence is below the configured threshold"
        }
        EvidenceError::RequesterNotFound => "the requester could not be uniquely matched",
        EvidenceError::RequesterMatchAmbiguous => "the requester match is ambiguous",
        EvidenceError::RequesterIdentifierMissing => {
            "a required requester identifier is missing for the configured matching policy"
        }
        EvidenceError::RequesterAttributesInsufficient => {
            "the requester data is insufficient for the configured matching policy"
        }
        EvidenceError::RequesterMatchingPolicyRejected => {
            "the requester context is rejected by the configured matching policy"
        }
        EvidenceError::RequesterReauthenticationRequired => {
            "stronger requester authentication is required"
        }
        EvidenceError::RelationshipNotEstablished => {
            "the required requester-target relationship is missing"
        }
        EvidenceError::RelationshipMatchAmbiguous => {
            "the requester-target relationship match is ambiguous"
        }
        EvidenceError::RelationshipAttributesInsufficient => {
            "the relationship data is insufficient for the configured matching policy"
        }
        EvidenceError::RelationshipPolicyRejected => {
            "the requester-target relationship is not allowed"
        }
        EvidenceError::RelationshipPurposeNotAllowed => {
            "the requester-target relationship is not allowed for the declared purpose"
        }
        EvidenceError::PurposeNotAllowed => "the declared purpose is not allowed",
        EvidenceError::PolicyDenied { .. } => "the configured policy denied the evidence request",
        EvidenceError::ProfileUnsupported => "the requested profile is not supported",
        EvidenceError::EvidenceNotAvailable
        | EvidenceError::MatchingEvidenceNotAvailable { .. } => "the evidence is not available",
        EvidenceError::SourceUnavailable => "the source registry is unavailable",
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
        EvidenceError::SelfAttestationDenied { .. } => "self-attestation request was denied",
        EvidenceError::SelfAttestationRateLimited => "self-attestation request was rate limited",
        EvidenceError::SelfAttestationInvalidToken
        | EvidenceError::SelfAttestationAssuranceDenied => "self-attestation request was denied",
        EvidenceError::MachineQuotaExceeded { .. } => {
            "the machine evaluation quota was exceeded for this principal"
        }
        _ => "evidence request failed",
    }
}
