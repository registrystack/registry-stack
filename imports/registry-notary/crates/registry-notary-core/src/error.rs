// SPDX-License-Identifier: Apache-2.0
//! Registry Notary stable error taxonomy.

use crate::model::SelfAttestationDenialCode;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EvidenceError {
    #[error("evidence server is disabled")]
    ServerDisabled,
    #[error("claim was not found")]
    ClaimNotFound,
    #[error("claim version was not found")]
    ClaimVersionNotFound,
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
    #[error("self-attestation request is denied")]
    SelfAttestationDenied { reason: SelfAttestationDenialCode },
    #[error("self-attestation request is rate limited")]
    SelfAttestationRateLimited,
    #[error("self-attestation token is invalid")]
    SelfAttestationInvalidToken,
    #[error("self-attestation assurance policy denied the request")]
    SelfAttestationAssuranceDenied,
}

impl EvidenceError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::ServerDisabled => "evidence.server_disabled",
            Self::ClaimNotFound => "claim.not_found",
            Self::ClaimVersionNotFound => "claim.version_not_found",
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
            Self::SelfAttestationDenied { .. } => "self_attestation.denied",
            Self::SelfAttestationRateLimited => "self_attestation.rate_limited",
            Self::SelfAttestationInvalidToken | Self::SelfAttestationAssuranceDenied => {
                "self_attestation.denied"
            }
        }
    }

    #[must_use]
    pub fn audit_code(&self) -> &'static str {
        match self {
            Self::SelfAttestationDenied { reason } => reason.as_str(),
            Self::SelfAttestationInvalidToken => SelfAttestationDenialCode::InvalidToken.as_str(),
            Self::SelfAttestationAssuranceDenied => {
                SelfAttestationDenialCode::AssuranceDenied.as_str()
            }
            _ => self.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_attestation_denial_keeps_generic_public_code_and_specific_audit_code() {
        let error = EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::SubjectMismatch,
        };

        assert_eq!(error.code(), "self_attestation.denied");
        assert_eq!(error.audit_code(), "self_attestation.subject_mismatch");
    }

    #[test]
    fn self_attestation_specific_errors_have_stable_codes() {
        assert_eq!(
            EvidenceError::SelfAttestationRateLimited.code(),
            "self_attestation.rate_limited"
        );
        assert_eq!(
            EvidenceError::SelfAttestationInvalidToken.code(),
            "self_attestation.denied"
        );
        assert_eq!(
            EvidenceError::SelfAttestationInvalidToken.audit_code(),
            "self_attestation.invalid_token"
        );
        assert_eq!(
            EvidenceError::SelfAttestationAssuranceDenied.code(),
            "self_attestation.denied"
        );
        assert_eq!(
            EvidenceError::SelfAttestationAssuranceDenied.audit_code(),
            "self_attestation.assurance_denied"
        );
    }
}
