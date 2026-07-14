// SPDX-License-Identifier: Apache-2.0
//! Registry Notary stable error taxonomy.

use crate::model::SubjectAccessDenialCode;

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
    #[error("registry-backed batch consultation request is invalid")]
    ConsultationInvalidRequest,
    #[error("requested disclosure is not allowed")]
    DisclosureNotAllowed,
    #[error("purpose is not allowed")]
    PurposeNotAllowed,
    #[error("policy decision denied the request: {code}")]
    PolicyDenied {
        code: &'static str,
        policy_id: Option<String>,
        policy_hash: Option<String>,
        evaluated_rule_ids: Vec<String>,
    },
    #[error("evidence request profile is unsupported")]
    ProfileUnsupported,
    #[error("evidence is not available")]
    EvidenceNotAvailable,
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
    #[error("multiple authentication credentials were provided")]
    MultipleCredentials,
    #[error("required scope is missing")]
    ScopeDenied { required: String },
    #[error("subject-access request is denied")]
    SubjectAccessDenied { reason: SubjectAccessDenialCode },
    #[error("subject-access request is rate limited")]
    SubjectAccessRateLimited,
    #[error("subject-access token is invalid")]
    SubjectAccessInvalidToken,
    #[error("subject-access assurance policy denied the request")]
    SubjectAccessAssuranceDenied,
    #[error("machine evaluation quota was exceeded")]
    MachineQuotaExceeded { retry_after_seconds: u64 },
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
            Self::ConsultationInvalidRequest => "consultation.invalid_request",
            Self::DisclosureNotAllowed => "claim.disclosure_not_allowed",
            Self::PurposeNotAllowed => "purpose.not_allowed",
            Self::PolicyDenied { code, .. } => code,
            Self::ProfileUnsupported => "profile.unsupported",
            Self::EvidenceNotAvailable => "evidence.not_available",
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
            Self::MultipleCredentials => "auth.multiple_credentials",
            Self::ScopeDenied { .. } => "auth.scope_denied",
            Self::SubjectAccessDenied { .. } => "subject_access.denied",
            Self::SubjectAccessRateLimited => "subject_access.rate_limited",
            Self::SubjectAccessInvalidToken | Self::SubjectAccessAssuranceDenied => {
                "subject_access.denied"
            }
            Self::MachineQuotaExceeded { .. } => "evaluation.quota_exceeded",
        }
    }

    #[must_use]
    pub fn audit_code(&self) -> &'static str {
        match self {
            Self::SubjectAccessDenied { reason } => reason.as_str(),
            Self::SubjectAccessInvalidToken => SubjectAccessDenialCode::InvalidToken.as_str(),
            Self::SubjectAccessAssuranceDenied => SubjectAccessDenialCode::AssuranceDenied.as_str(),
            Self::PolicyDenied { code, .. } => code,
            _ => self.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_access_denial_keeps_generic_public_code_and_specific_audit_code() {
        let error = EvidenceError::SubjectAccessDenied {
            reason: SubjectAccessDenialCode::SubjectMismatch,
        };

        assert_eq!(error.code(), "subject_access.denied");
        assert_eq!(error.audit_code(), "subject_access.subject_mismatch");
    }

    #[test]
    fn subject_access_specific_errors_have_stable_codes() {
        assert_eq!(
            EvidenceError::SubjectAccessRateLimited.code(),
            "subject_access.rate_limited"
        );
        assert_eq!(
            EvidenceError::SubjectAccessInvalidToken.code(),
            "subject_access.denied"
        );
        assert_eq!(
            EvidenceError::SubjectAccessInvalidToken.audit_code(),
            "subject_access.invalid_token"
        );
        assert_eq!(
            EvidenceError::SubjectAccessAssuranceDenied.code(),
            "subject_access.denied"
        );
        assert_eq!(
            EvidenceError::SubjectAccessAssuranceDenied.audit_code(),
            "subject_access.assurance_denied"
        );
    }

    #[test]
    fn machine_quota_exceeded_has_stable_code() {
        let error = EvidenceError::MachineQuotaExceeded {
            retry_after_seconds: 42,
        };

        assert_eq!(error.code(), "evaluation.quota_exceeded");
        assert_eq!(error.audit_code(), "evaluation.quota_exceeded");
    }

    #[test]
    fn policy_denials_keep_stable_pdp_code() {
        let error = EvidenceError::PolicyDenied {
            code: "pdp.assurance_insufficient",
            policy_id: None,
            policy_hash: None,
            evaluated_rule_ids: Vec::new(),
        };

        assert_eq!(error.code(), "pdp.assurance_insufficient");
        assert_eq!(error.audit_code(), "pdp.assurance_insufficient");
    }
}
