// SPDX-License-Identifier: Apache-2.0
//! Registry Witness stable error taxonomy.

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EvidenceError {
    #[error("evidence server is disabled")]
    ServerDisabled,
    #[error("claim was not found")]
    ClaimNotFound,
    #[error("claim operation is unsupported")]
    OperationUnsupported,
    #[error("evidence request is invalid")]
    InvalidRequest,
    #[error("requested disclosure is not allowed")]
    DisclosureNotAllowed,
    #[error("source record was not found")]
    SourceNotFound,
    #[error("source lookup returned more than one record")]
    SourceAmbiguous,
    #[error("source is unavailable")]
    SourceUnavailable,
    #[error("batch request is too large")]
    BatchTooLarge,
    #[error("evaluation was not found")]
    EvaluationNotFound,
    #[error("evaluation binding mismatch")]
    EvaluationBindingMismatch,
    #[error("format is unsupported")]
    FormatUnsupported,
    #[error("credential issuer is not configured")]
    CredentialIssuerNotConfigured,
    #[error("holder proof is required")]
    HolderProofRequired,
    #[error("holder proof has already been used")]
    HolderProofReplay,
    #[error("credential issuance failed")]
    CredentialIssuanceFailed,
    #[error("claim rule evaluation failed")]
    RuleEvaluationFailed,
    #[error("idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("purpose is required")]
    PurposeRequired,
    #[error("credential is missing")]
    MissingCredential,
    #[error("required scope is missing")]
    ScopeDenied { required: String },
}

impl EvidenceError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::ServerDisabled => "evidence.server_disabled",
            Self::ClaimNotFound => "claim.not_found",
            Self::OperationUnsupported => "claim.operation_unsupported",
            Self::InvalidRequest => "request.invalid",
            Self::DisclosureNotAllowed => "claim.disclosure_not_allowed",
            Self::SourceNotFound => "source.not_found",
            Self::SourceAmbiguous => "source.ambiguous",
            Self::SourceUnavailable => "source.unavailable",
            Self::BatchTooLarge => "batch.too_large",
            Self::EvaluationNotFound => "evaluation.not_found",
            Self::EvaluationBindingMismatch => "evaluation.binding_mismatch",
            Self::FormatUnsupported => "claim.format_not_supported",
            Self::CredentialIssuerNotConfigured => "credential.issuer_not_configured",
            Self::HolderProofRequired => "credential.holder_proof_required",
            Self::HolderProofReplay => "credential.holder_proof_replay",
            Self::CredentialIssuanceFailed => "credential.issuance_failed",
            Self::RuleEvaluationFailed => "claim.rule_evaluation_failed",
            Self::IdempotencyConflict => "idempotency.conflict",
            Self::PurposeRequired => "auth.purpose_required",
            Self::MissingCredential => "auth.missing_credential",
            Self::ScopeDenied { .. } => "auth.scope_denied",
        }
    }
}
