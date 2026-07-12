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
    #[error("registry-backed batch consultation request is invalid")]
    ConsultationInvalidRequest,
    #[error("requested disclosure is not allowed")]
    DisclosureNotAllowed,
    #[error("source record was not found")]
    SourceNotFound,
    #[error("source lookup returned more than one record")]
    SourceAmbiguous,
    #[error("target identifier is missing")]
    TargetIdentifierMissing,
    #[error("target attributes are insufficient for matching")]
    TargetAttributesInsufficient,
    #[error("target matching policy rejected the request")]
    TargetMatchingPolicyRejected,
    #[error("target is not in a valid state")]
    TargetNotInValidState,
    #[error("target match confidence is too low")]
    TargetMatchLowConfidence,
    #[error("requester identifier is missing")]
    RequesterIdentifierMissing,
    #[error("requester attributes are insufficient for matching")]
    RequesterAttributesInsufficient,
    #[error("requester matching policy rejected the request")]
    RequesterMatchingPolicyRejected,
    #[error("requester record was not found")]
    RequesterNotFound,
    #[error("requester lookup returned more than one record")]
    RequesterMatchAmbiguous,
    #[error("requester must reauthenticate")]
    RequesterReauthenticationRequired,
    #[error("relationship was not established")]
    RelationshipNotEstablished,
    #[error("relationship match is ambiguous")]
    RelationshipMatchAmbiguous,
    #[error("relationship attributes are insufficient for matching")]
    RelationshipAttributesInsufficient,
    #[error("relationship policy rejected the request")]
    RelationshipPolicyRejected,
    #[error("relationship is not allowed for the requested purpose")]
    RelationshipPurposeNotAllowed,
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
    #[error("evidence is not available")]
    MatchingEvidenceNotAvailable { audit_code: &'static str },
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
    #[error("multiple authentication credentials were provided")]
    MultipleCredentials,
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
            Self::SourceNotFound => "target.not_found",
            Self::SourceAmbiguous => "target.match_ambiguous",
            Self::TargetIdentifierMissing => "target.identifier_missing",
            Self::TargetAttributesInsufficient => "target.attributes_insufficient",
            Self::TargetMatchingPolicyRejected => "target.matching_policy_rejected",
            Self::TargetNotInValidState => "target.not_in_valid_state",
            Self::TargetMatchLowConfidence => "target.match_low_confidence",
            Self::RequesterNotFound => "requester.not_found",
            Self::RequesterMatchAmbiguous => "requester.match_ambiguous",
            Self::RequesterIdentifierMissing => "requester.identifier_missing",
            Self::RequesterAttributesInsufficient => "requester.attributes_insufficient",
            Self::RequesterMatchingPolicyRejected => "requester.matching_policy_rejected",
            Self::RequesterReauthenticationRequired => "requester.reauthentication_required",
            Self::RelationshipNotEstablished => "relationship.not_established",
            Self::RelationshipMatchAmbiguous => "relationship.match_ambiguous",
            Self::RelationshipAttributesInsufficient => "relationship.attributes_insufficient",
            Self::RelationshipPolicyRejected => "relationship.policy_rejected",
            Self::RelationshipPurposeNotAllowed => "relationship.purpose_not_allowed",
            Self::PurposeNotAllowed => "purpose.not_allowed",
            Self::PolicyDenied { code, .. } => code,
            Self::ProfileUnsupported => "profile.unsupported",
            Self::EvidenceNotAvailable | Self::MatchingEvidenceNotAvailable { .. } => {
                "evidence.not_available"
            }
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
            Self::MultipleCredentials => "auth.multiple_credentials",
            Self::ScopeDenied { .. } => "auth.scope_denied",
            Self::SelfAttestationDenied { .. } => "self_attestation.denied",
            Self::SelfAttestationRateLimited => "self_attestation.rate_limited",
            Self::SelfAttestationInvalidToken | Self::SelfAttestationAssuranceDenied => {
                "self_attestation.denied"
            }
            Self::MachineQuotaExceeded { .. } => "evaluation.quota_exceeded",
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
            Self::PolicyDenied { code, .. } => code,
            Self::MatchingEvidenceNotAvailable { audit_code } => audit_code,
            _ => self.code(),
        }
    }
}

#[must_use]
pub fn missing_context_error(path: &str) -> EvidenceError {
    if path.starts_with("target.identifiers.") {
        EvidenceError::TargetIdentifierMissing
    } else if path.starts_with("requester.identifiers.") {
        EvidenceError::RequesterIdentifierMissing
    } else if path.starts_with("requester.attributes.") {
        EvidenceError::RequesterAttributesInsufficient
    } else if path.starts_with("relationship.attributes.") {
        EvidenceError::RelationshipAttributesInsufficient
    } else {
        EvidenceError::TargetAttributesInsufficient
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

    #[test]
    fn source_matching_errors_use_public_target_codes() {
        assert_eq!(EvidenceError::SourceNotFound.code(), "target.not_found");
        assert_eq!(
            EvidenceError::SourceAmbiguous.code(),
            "target.match_ambiguous"
        );
        assert_eq!(
            EvidenceError::TargetAttributesInsufficient.code(),
            "target.attributes_insufficient"
        );
        assert_eq!(
            EvidenceError::TargetIdentifierMissing.code(),
            "target.identifier_missing"
        );
        assert_eq!(
            EvidenceError::TargetMatchingPolicyRejected.code(),
            "target.matching_policy_rejected"
        );
        assert_eq!(
            EvidenceError::RequesterMatchingPolicyRejected.code(),
            "requester.matching_policy_rejected"
        );
        assert_eq!(
            EvidenceError::RelationshipNotEstablished.code(),
            "relationship.not_established"
        );
        assert_eq!(
            EvidenceError::RelationshipPolicyRejected.code(),
            "relationship.policy_rejected"
        );
        assert_eq!(
            EvidenceError::RelationshipPurposeNotAllowed.code(),
            "relationship.purpose_not_allowed"
        );
        let collapsed = EvidenceError::MatchingEvidenceNotAvailable {
            audit_code: EvidenceError::SourceAmbiguous.audit_code(),
        };
        assert_eq!(collapsed.code(), "evidence.not_available");
        assert_eq!(collapsed.audit_code(), "target.match_ambiguous");
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
