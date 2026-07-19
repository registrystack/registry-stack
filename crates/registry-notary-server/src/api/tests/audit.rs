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
    attach_zero_relay_no_forward_audit(&mut response);

    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("audit context is attached");
    assert_eq!(audit.relay_consultation_count, Some(0));
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
fn failed_matching_attempts_receive_stable_purpose_scoped_keyed_pseudonyms() {
    let keys = SubjectAccessRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
    let entity = EvidenceEntity::with_identifier("Person", "national_id", "NID-1001");

    let first = hash_audit_matching_attempt(&keys, "target", Some("program-a"), &entity)
        .expect("matching attempt hashes")
        .expect("matching input produces a pseudonym");
    let repeated = hash_audit_matching_attempt(&keys, "target", Some("program-a"), &entity)
        .expect("matching attempt hashes")
        .expect("matching input produces a pseudonym");
    let other_purpose = hash_audit_matching_attempt(&keys, "target", Some("program-b"), &entity)
        .expect("matching attempt hashes")
        .expect("matching input produces a pseudonym");

    assert_eq!(first, repeated);
    assert_ne!(first, other_purpose);
    assert!(!serde_json::to_string(&first)
        .expect("pseudonym serializes")
        .contains("NID-1001"));
}

#[test]
fn failed_batch_member_audit_is_value_free_and_keeps_consultation_evidence() {
    let keys = SubjectAccessRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
    let request = registry_notary_core::BatchEvaluateRequest {
        items: vec![registry_notary_core::BatchEvaluateItemRequest {
            requester: Some(EvidenceEntity::with_identifier(
                "Organization",
                "organization_id",
                "ORG-SENSITIVE",
            )),
            target: EvidenceEntity::with_identifier("Person", "national_id", "NID-SENSITIVE"),
            relationship: None,
            on_behalf_of: None,
            purpose: Some("program-a".to_string()),
        }],
        claims: vec![ClaimRef::from("person-is-alive")],
        disclosure: Some("predicate".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("program-a".to_string()),
    };
    let result = registry_notary_core::BatchEvaluateResponse {
        batch_id: "batch-1".to_string(),
        status: registry_notary_core::BatchStatus::Completed,
        claims: vec!["person-is-alive".to_string()],
        items: vec![registry_notary_core::BatchItemResponse {
            input_index: 0,
            target_ref: registry_notary_core::TargetRefView {
                entity_type: "Person".to_string(),
                handle: "rnref:v1:failed-target".to_string(),
                identifier_schemes: vec!["national_id".to_string()],
                profile: None,
            },
            requester_ref: None,
            evaluation_id: None,
            status: registry_notary_core::BatchItemStatus::Failed,
            claim_results: Vec::new(),
            errors: vec![registry_notary_core::BatchItemError {
                code: "evidence.not_available".to_string(),
                title: "Evidence not available".to_string(),
                retryable: true,
                audit_code: Some("relay.transport_failed".to_string()),
            }],
            runtime_audit: registry_notary_core::BatchItemRuntimeAudit {
                relay_forwarded_count: 1,
                relay_consultation_ids: vec!["01JRELAYBATCHAUDIT".to_string()],
            },
        }],
        summary: registry_notary_core::BatchSummary {
            succeeded: 0,
            failed: 1,
        },
    };
    let mut response = StatusCode::OK.into_response();
    attach_evidence_audit_with_purposes(
        &mut response,
        "batch_evaluate",
        None,
        &["person-is-alive".to_string()],
        Some(1),
        Some(vec!["program-a".to_string()]),
    );

    attach_batch_evaluate_response_audit(
        &mut response,
        &keys,
        &evidence_config(),
        &request,
        &result,
        Some(&["program-a".to_string()]),
    )
    .expect("batch audit attaches");

    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("audit context is attached");
    let item = &audit.batch_items.as_ref().expect("batch items exist")[0];
    assert_eq!(item.outcome, "failed");
    assert_eq!(item.error_code.as_deref(), Some("relay.transport_failed"));
    assert_eq!(item.relay_consultation_count, 1);
    assert!(item.forwarded);
    assert!(item.target_ref_hash.is_some());
    assert!(item.requester_ref_hash.is_some());
    assert_eq!(audit.relay_consultation_count, Some(1));
    assert_eq!(audit.forwarded, Some(true));
    let serialized = serde_json::to_string(&audit.batch_items).expect("batch audit serializes");
    assert!(!serialized.contains("NID-SENSITIVE"));
    assert!(!serialized.contains("ORG-SENSITIVE"));
}

#[test]
fn credential_audit_context_links_stored_target_and_requester_refs() {
    let keys = SubjectAccessRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
    let mut result = claim_result_view("eval-1", "person-is-alive");
    result.requester_ref = Some(registry_notary_core::EvidenceEntityRef {
        entity_type: "Person".to_string(),
        handle: "rnref:v1:requester-handle".to_string(),
        identifier_schemes: vec!["national_id".to_string()],
        profile: None,
    });
    let mut response = StatusCode::OK.into_response();

    attach_subject_access_credential_audit(
        &mut response,
        &keys,
        "eval-1",
        &["person-is-alive".to_string()],
        &[result],
        1,
        SubjectAccessCredentialAuditDetails {
            profile_id: "person_is_alive_sd_jwt",
            holder_binding_mode: "did",
            policy_hash: None,
            purposes: Some(vec!["citizen_subject_access".to_string()]),
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
