// SPDX-License-Identifier: Apache-2.0
//! Shared authorization_details enforcement for Notary transaction scopes.

use registry_notary_core::{
    AccessMode, ClaimRef, EvidenceAuthorizationDetails, EvidenceAuthorizationSubject,
    EvidenceAuthorizationTarget, EvidenceError,
};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopedAuthorizationError {
    DetailType,
    Action,
    Location,
    Claim,
    Disclosure,
    Format,
    Purpose,
    AccessMode,
    Subject,
    Target,
}

pub(crate) struct ScopedAuthorizationSubject {
    pub(crate) binding_claim: String,
    pub(crate) id_type: String,
}

pub(crate) struct ScopedAuthorizationTarget {
    pub(crate) id_type: String,
    pub(crate) id: String,
}

pub(crate) struct ScopedAuthorizationRequest<'a> {
    pub(crate) service_id: &'a str,
    pub(crate) action: &'a str,
    pub(crate) claims: &'a [ClaimRef],
    pub(crate) disclosure: &'a str,
    pub(crate) format: &'a str,
    pub(crate) purpose: &'a str,
    pub(crate) access_mode: AccessMode,
    pub(crate) subject: Option<ScopedAuthorizationSubject>,
    pub(crate) target: Option<ScopedAuthorizationTarget>,
    pub(crate) allow_subset_claims: bool,
    pub(crate) allowed_claims: Option<&'a [ClaimRef]>,
}

pub(crate) fn extract_notary_transaction_authorization_details(
    raw: &Value,
) -> Result<Option<EvidenceAuthorizationDetails>, EvidenceError> {
    let details = raw.as_array().ok_or(EvidenceError::MissingCredential)?;
    let mut matched = None;
    for detail in details {
        let Some(object) = detail.as_object() else {
            continue;
        };
        let type_matches = object.get("type").and_then(Value::as_str)
            == Some(registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE);
        let schema_matches = object.get("schema_version").and_then(Value::as_str)
            == Some(registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION);
        if !type_matches && !schema_matches {
            continue;
        }
        if !type_matches || !schema_matches || matched.is_some() {
            return Err(EvidenceError::MissingCredential);
        }
        matched = Some(
            serde_json::from_value::<EvidenceAuthorizationDetails>(detail.clone())
                .map_err(|_| EvidenceError::MissingCredential)?,
        );
    }
    Ok(matched)
}

pub(crate) fn has_transaction_scope(details: &EvidenceAuthorizationDetails) -> bool {
    !details.actions.is_empty()
        || !details.locations.is_empty()
        || !details.claims.is_empty()
        || details.disclosure.is_some()
        || details.format.is_some()
        || details.purpose.is_some()
        || details.subject.is_some()
        || details.target.is_some()
        || details.relationship.is_some()
        || details.access_mode.is_some()
        || details.assisted_access_context.is_some()
}

pub(crate) fn validate_scoped_authorization_details(
    details: &EvidenceAuthorizationDetails,
    expected: &ScopedAuthorizationRequest<'_>,
) -> Result<(), ScopedAuthorizationError> {
    if details.detail_type != registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE
        || details.schema_version
            != registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
    {
        return Err(ScopedAuthorizationError::DetailType);
    }
    if !exact_single(&details.actions, expected.action) {
        return Err(ScopedAuthorizationError::Action);
    }
    if !exact_single(&details.locations, expected.service_id) {
        return Err(ScopedAuthorizationError::Location);
    }
    let claims_match = if expected.allow_subset_claims {
        expected
            .claims
            .iter()
            .all(|expected_claim| details.claims.contains(expected_claim))
            && expected.allowed_claims.is_some_and(|allowed_claims| {
                details
                    .claims
                    .iter()
                    .all(|detail_claim| allowed_claims.contains(detail_claim))
            })
    } else {
        details.claims == expected.claims
    };
    if !claims_match {
        return Err(ScopedAuthorizationError::Claim);
    }
    if details.disclosure.as_deref() != Some(expected.disclosure) {
        return Err(ScopedAuthorizationError::Disclosure);
    }
    if details.format.as_deref() != Some(expected.format) {
        return Err(ScopedAuthorizationError::Format);
    }
    if details.purpose.as_deref() != Some(expected.purpose) {
        return Err(ScopedAuthorizationError::Purpose);
    }
    if details.access_mode != Some(expected.access_mode) {
        return Err(ScopedAuthorizationError::AccessMode);
    }
    if !subject_matches(details.subject.as_ref(), expected.subject.as_ref()) {
        return Err(ScopedAuthorizationError::Subject);
    }
    if !target_matches(details.target.as_ref(), expected.target.as_ref()) {
        return Err(ScopedAuthorizationError::Target);
    }
    Ok(())
}

fn exact_single(values: &[String], expected: &str) -> bool {
    values.len() == 1 && values[0] == expected
}

fn subject_matches(
    actual: Option<&EvidenceAuthorizationSubject>,
    expected: Option<&ScopedAuthorizationSubject>,
) -> bool {
    match (actual, expected) {
        (Some(actual), Some(expected)) => {
            actual.binding_claim == expected.binding_claim && actual.id_type == expected.id_type
        }
        (None, None) => true,
        _ => false,
    }
}

fn target_matches(
    actual: Option<&EvidenceAuthorizationTarget>,
    expected: Option<&ScopedAuthorizationTarget>,
) -> bool {
    match expected {
        Some(expected) => actual
            .is_some_and(|actual| actual.id_type == expected.id_type && actual.id == expected.id),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_notary_core::{EvidenceAssistedAccessContext, EvidenceAuthorizationRelationship};

    fn claim(id: &str) -> ClaimRef {
        ClaimRef::with_version(id, "1")
    }

    fn details(claims: Vec<ClaimRef>) -> EvidenceAuthorizationDetails {
        EvidenceAuthorizationDetails {
            detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE
                .to_string(),
            schema_version:
                registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
                    .to_string(),
            actions: vec!["evaluate".to_string()],
            locations: vec!["https://notary.example.test".to_string()],
            claims,
            disclosure: Some("predicate".to_string()),
            format: Some("application/vnd.registry-notary.claim-result+json".to_string()),
            purpose: Some("citizen_self_attestation".to_string()),
            legal_basis_ref: None,
            consent_ref: None,
            jurisdiction: None,
            assurance_level: None,
            subject: Some(EvidenceAuthorizationSubject {
                binding_claim: "national_id".to_string(),
                id_type: "national_id".to_string(),
            }),
            target: None,
            relationship: None,
            access_mode: Some(AccessMode::SelfAttestation),
            assisted_access_context: None,
        }
    }

    fn context_only_details() -> EvidenceAuthorizationDetails {
        EvidenceAuthorizationDetails {
            detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE
                .to_string(),
            schema_version:
                registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
                    .to_string(),
            legal_basis_ref: Some("demo:casework".to_string()),
            consent_ref: Some("demo:consent".to_string()),
            jurisdiction: Some("ZZ".to_string()),
            assurance_level: Some("substantial".to_string()),
            ..EvidenceAuthorizationDetails::default()
        }
    }

    fn request<'a>(
        claims: &'a [ClaimRef],
        allow_subset_claims: bool,
        allowed_claims: Option<&'a [ClaimRef]>,
    ) -> ScopedAuthorizationRequest<'a> {
        ScopedAuthorizationRequest {
            service_id: "https://notary.example.test",
            action: "evaluate",
            claims,
            disclosure: "predicate",
            format: "application/vnd.registry-notary.claim-result+json",
            purpose: "citizen_self_attestation",
            access_mode: AccessMode::SelfAttestation,
            subject: Some(ScopedAuthorizationSubject {
                binding_claim: "national_id".to_string(),
                id_type: "national_id".to_string(),
            }),
            target: None,
            allow_subset_claims,
            allowed_claims,
        }
    }

    #[test]
    fn context_only_authorization_details_are_not_transaction_scoped() {
        let mut details = context_only_details();

        assert!(!has_transaction_scope(&details));

        details.actions = vec!["evaluate".to_string()];
        assert!(has_transaction_scope(&details));
    }

    #[test]
    fn every_transaction_scope_field_marks_authorization_details_as_transaction_scoped() {
        let mut details = context_only_details();
        details.locations = vec!["https://notary.example.test".to_string()];
        assert!(has_transaction_scope(&details));

        let mut details = context_only_details();
        details.claims = vec![claim("person-is-alive")];
        assert!(has_transaction_scope(&details));

        let mut details = context_only_details();
        details.disclosure = Some("predicate".to_string());
        assert!(has_transaction_scope(&details));

        let mut details = context_only_details();
        details.format = Some("application/vnd.registry-notary.claim-result+json".to_string());
        assert!(has_transaction_scope(&details));

        let mut details = context_only_details();
        details.purpose = Some("citizen_self_attestation".to_string());
        assert!(has_transaction_scope(&details));

        let mut details = context_only_details();
        details.subject = Some(EvidenceAuthorizationSubject {
            binding_claim: "national_id".to_string(),
            id_type: "national_id".to_string(),
        });
        assert!(has_transaction_scope(&details));

        let mut details = context_only_details();
        details.target = Some(EvidenceAuthorizationTarget {
            id_type: "national_id".to_string(),
            id: "NID-1001".to_string(),
        });
        assert!(has_transaction_scope(&details));

        let mut details = context_only_details();
        details.relationship = Some(EvidenceAuthorizationRelationship {
            relationship_type: "parent_or_guardian".to_string(),
            proof_claim: "caregiver-link".to_string(),
        });
        assert!(has_transaction_scope(&details));

        let mut details = context_only_details();
        details.access_mode = Some(AccessMode::MachineClient);
        assert!(has_transaction_scope(&details));

        let mut details = context_only_details();
        details.assisted_access_context = Some(EvidenceAssistedAccessContext {
            channel: "assisted-service-desk".to_string(),
        });
        assert!(has_transaction_scope(&details));
    }

    #[test]
    fn subset_claims_allow_per_claim_validation_against_multi_claim_token() {
        let claim_a = claim("person-is-alive");
        let claim_b = claim("address-is-current");
        let token_details = details(vec![claim_a.clone(), claim_b]);
        let expected_claims = [claim_a];
        let allowed_claims = token_details.claims.clone();

        validate_scoped_authorization_details(
            &token_details,
            &request(&expected_claims, true, Some(&allowed_claims)),
        )
        .expect("single claim is covered by multi-claim transaction token");
    }

    #[test]
    fn exact_claim_validation_rejects_subset_and_subset_rejects_missing_claim() {
        let claim_a = claim("person-is-alive");
        let claim_b = claim("address-is-current");
        let token_details = details(vec![claim_a.clone(), claim_b]);
        let expected_claims = [claim_a];

        assert_eq!(
            validate_scoped_authorization_details(
                &token_details,
                &request(&expected_claims, false, None),
            ),
            Err(ScopedAuthorizationError::Claim)
        );

        let missing_claim = [claim("income-is-below-threshold")];
        assert_eq!(
            validate_scoped_authorization_details(
                &token_details,
                &request(&missing_claim, true, Some(&token_details.claims)),
            ),
            Err(ScopedAuthorizationError::Claim)
        );

        let request_claims = [expected_claims[0].clone()];
        assert_eq!(
            validate_scoped_authorization_details(
                &token_details,
                &request(&expected_claims, true, Some(&request_claims)),
            ),
            Err(ScopedAuthorizationError::Claim)
        );
    }

    #[test]
    fn target_validation_requires_exact_delegated_target() {
        let claim_a = claim("person-is-alive");
        let request_claims = [claim_a.clone()];
        let mut token_details = details(vec![claim_a]);
        token_details.target = Some(EvidenceAuthorizationTarget {
            id_type: "civil_registration_id".to_string(),
            id: "CHILD-123".to_string(),
        });
        let mut request = request(&request_claims, false, None);
        request.target = Some(ScopedAuthorizationTarget {
            id_type: "civil_registration_id".to_string(),
            id: "CHILD-123".to_string(),
        });

        validate_scoped_authorization_details(&token_details, &request)
            .expect("exact target is accepted");

        token_details.target.as_mut().expect("target is present").id = "OTHER-CHILD".to_string();
        assert_eq!(
            validate_scoped_authorization_details(&token_details, &request),
            Err(ScopedAuthorizationError::Target)
        );
    }
}
