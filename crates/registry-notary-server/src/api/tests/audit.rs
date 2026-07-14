// SPDX-License-Identifier: Apache-2.0
//! Audit API tests.

use super::*;

#[test]
fn pdp_pre_evaluation_denial_audit_records_zero_consultations_and_no_forward() {
    let mut response = StatusCode::FORBIDDEN.into_response();
    attach_evidence_audit(
        &mut response,
        "evaluate_denied",
        None,
        &["person-is-alive".to_string()],
        None,
    );
    attach_zero_source_no_forward_audit(&mut response);

    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("audit context is attached");
    assert_eq!(audit.source_read_count, Some(0));
    assert_eq!(audit.forwarded, Some(false));
}

#[test]
fn batch_audit_purposes_resolve_per_subject_overrides() {
    let purposes = resolved_batch_audit_purposes(
        None,
        Some("program-b"),
        &[
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "NAT-123".to_string(),
                    id_type: Some("national_id".to_string()),
                    purpose: Some("program-a".to_string()),
                },
            ),
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "NAT-456".to_string(),
                    id_type: Some("national_id".to_string()),
                    purpose: None,
                },
            ),
        ],
    )
    .expect("audit purposes resolve");

    assert_eq!(purposes, vec!["program-a", "program-b"]);
}

#[test]
fn redacted_fields_audit_unions_all_result_redactions() {
    let mut response = StatusCode::OK.into_response();
    attach_evidence_audit(
        &mut response,
        "evaluate",
        Some("eval-1".to_string()),
        &["opencrvs-age-band".to_string(), "opencrvs-sex".to_string()],
        Some(1),
    );
    let mut age_band = claim_result_view("eval-1", "opencrvs-age-band");
    age_band.disclosure = "redacted".to_string();
    age_band.redacted_fields = vec!["opencrvs-age-band".to_string()];
    let mut sex = claim_result_view("eval-1", "opencrvs-sex");
    sex.disclosure = "redacted".to_string();
    sex.redacted_fields = vec!["opencrvs-sex".to_string()];

    attach_redacted_fields_audit(&mut response, &[sex, age_band]);

    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("audit context is attached");
    assert_eq!(
        audit.redacted_fields.as_deref(),
        Some(&["opencrvs-age-band".to_string(), "opencrvs-sex".to_string()][..])
    );
}

#[test]
fn canonical_audit_identifier_input_sorts_identifiers_and_explicit_empty_fields() {
    let mut first = registry_notary_core::EvidenceIdentifier {
        scheme: "national_id".to_string(),
        value: "NID-1001".to_string(),
        issuer: None,
        country: Some("RW".to_string()),
    };
    let second = registry_notary_core::EvidenceIdentifier {
        scheme: "animal_ear_tag".to_string(),
        value: "EAR-77".to_string(),
        issuer: Some("vet-registry".to_string()),
        country: None,
    };
    let mut entity = EvidenceEntity::new("Person");
    entity.identifiers = vec![first.clone(), second.clone()];
    let canonical = canonical_audit_identifier_input("target", Some("program-a"), &entity)
        .expect("canonicalizes")
        .expect("identifier input is present");

    first.country = Some("RW".to_string());
    let mut reordered = EvidenceEntity::new("Person");
    reordered.identifiers = vec![second, first];
    let reordered_canonical =
        canonical_audit_identifier_input("target", Some("program-a"), &reordered)
            .expect("canonicalizes")
            .expect("identifier input is present");

    assert_eq!(canonical, reordered_canonical);
    assert!(canonical.contains(r#""issuer":"""#));
    assert!(canonical.contains(r#""country":"""#));
    assert!(canonical.find("animal_ear_tag") < canonical.find("national_id"));
}

#[test]
fn credential_audit_context_links_stored_target_and_requester_refs() {
    let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
    let mut result = claim_result_view("eval-1", "person-is-alive");
    result.requester_ref = Some(registry_notary_core::EvidenceEntityRef {
        entity_type: "Person".to_string(),
        handle: "rnref:v1:requester-handle".to_string(),
        identifier_schemes: vec!["national_id".to_string()],
        profile: None,
    });
    let mut response = StatusCode::OK.into_response();

    attach_self_attestation_credential_audit(
        &mut response,
        &keys,
        "eval-1",
        &["person-is-alive".to_string()],
        &[result],
        1,
        SelfAttestationCredentialAuditDetails {
            profile_id: "person_is_alive_sd_jwt",
            holder_binding_mode: "did",
            policy_hash: None,
            purposes: Some(vec!["citizen_self_attestation".to_string()]),
            protocol: Some("openid4vci"),
            credential_configuration_id: Some("person_is_alive_sd_jwt"),
        },
    )
    .expect("credential audit attaches");

    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("audit context is attached");
    assert_eq!(audit.target_type.as_deref(), Some("Person"));
    assert_eq!(audit.requester_type.as_deref(), Some("Person"));
    assert!(audit.target_ref_hash.is_some());
    assert!(audit.requester_ref_hash.is_some());
}
