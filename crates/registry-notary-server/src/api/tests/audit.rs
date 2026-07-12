// SPDX-License-Identifier: Apache-2.0
//! Audit API tests.

use super::*;

#[test]
fn pdp_pre_source_denial_audit_records_zero_source_and_no_forward() {
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
fn batch_audit_context_hashes_each_item_and_keeps_matching_audit_code() {
    let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
    let result = registry_notary_core::BatchEvaluateResponse {
        batch_id: "batch-1".to_string(),
        status: registry_notary_core::BatchStatus::Completed,
        claims: vec!["person-is-alive".to_string()],
        items: vec![
            registry_notary_core::BatchItemResponse {
                input_index: 0,
                target_ref: registry_notary_core::TargetRefView {
                    entity_type: "Person".to_string(),
                    handle: "rnref:v1:target-handle-1".to_string(),
                    identifier_schemes: vec!["national_id".to_string()],
                    profile: None,
                },
                requester_ref: Some(registry_notary_core::EvidenceEntityRef {
                    entity_type: "Person".to_string(),
                    handle: "rnref:v1:requester-handle".to_string(),
                    identifier_schemes: vec!["national_id".to_string()],
                    profile: None,
                }),
                matching: Some(registry_notary_core::MatchingMetadata {
                    policy_id: "policy-v1".to_string(),
                    method: "configured_lookup".to_string(),
                    confidence: "high".to_string(),
                    score: None,
                    policy_hash: Some(
                        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                    ),
                    evaluated_rule_ids: vec!["source-binding-policy:person".to_string()],
                    ecosystem_binding_id: Some("baseline-dpi/v1".to_string()),
                    ecosystem_binding_version: Some("2026-06-19".to_string()),
                    pack_id: Some("baseline-dpi/v1".to_string()),
                    pack_version: Some("2026-06-19".to_string()),
                }),
                evaluation_id: Some("eval-1".to_string()),
                status: registry_notary_core::BatchItemStatus::Succeeded,
                claim_results: Vec::new(),
                errors: Vec::new(),
            },
            registry_notary_core::BatchItemResponse {
                input_index: 1,
                target_ref: registry_notary_core::TargetRefView {
                    entity_type: "Person".to_string(),
                    handle: "rnref:v1:target-handle-2".to_string(),
                    identifier_schemes: vec!["national_id".to_string()],
                    profile: None,
                },
                requester_ref: None,
                matching: None,
                evaluation_id: None,
                status: registry_notary_core::BatchItemStatus::Failed,
                claim_results: Vec::new(),
                errors: vec![registry_notary_core::BatchItemError {
                    code: "evidence.not_available".to_string(),
                    title: "Evidence not available".to_string(),
                    retryable: false,
                    audit_code: Some("target.match_ambiguous".to_string()),
                }],
            },
        ],
        summary: registry_notary_core::BatchSummary {
            succeeded: 1,
            failed: 1,
        },
    };
    let mut response = StatusCode::OK.into_response();
    let audit_request = BatchEvaluateRequest {
        items: vec![
            BatchEvaluateItemRequest {
                requester: Some(EvidenceEntity::with_identifier(
                    "Person",
                    "national_id",
                    "NID-REQUESTER",
                )),
                target: EvidenceEntity::with_identifier("Person", "national_id", "NID-1"),
                relationship: None,
                on_behalf_of: None,
                purpose: None,
            },
            BatchEvaluateItemRequest {
                requester: None,
                target: EvidenceEntity::with_identifier("Person", "national_id", "NID-2"),
                relationship: None,
                on_behalf_of: None,
                purpose: None,
            },
        ],
        claims: vec![ClaimRef::from("person-is-alive")],
        disclosure: Some("predicate".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("program-a".to_string()),
    };
    let evidence = EvidenceConfig::default();
    attach_evidence_audit(
        &mut response,
        "batch_evaluate",
        None,
        &["person-is-alive".to_string()],
        Some(2),
    );

    attach_batch_evaluate_response_audit(
        &mut response,
        &keys,
        &evidence,
        &audit_request,
        &result,
        None,
    )
    .expect("batch audit context attaches");

    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("audit context is attached");
    let items = audit.batch_items.as_ref().expect("batch items captured");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].input_index, 0);
    assert_eq!(items[0].target_type.as_deref(), Some("Person"));
    assert_eq!(items[0].matching_outcome.as_deref(), Some("matched"));
    assert_eq!(items[0].matching_policy_id.as_deref(), Some("policy-v1"));
    assert_eq!(
        items[0].ecosystem_binding_id.as_deref(),
        Some("baseline-dpi/v1")
    );
    assert_eq!(
        items[0].ecosystem_binding_version.as_deref(),
        Some("2026-06-19")
    );
    assert!(items[0]
        .target_ref_hash
        .as_ref()
        .map(Hashed::as_str)
        .is_some_and(|hash| !hash.contains("target-handle-1")));
    assert!(items[0].requester_ref_hash.is_some());
    assert_eq!(items[1].input_index, 1);
    assert_eq!(items[1].matching_outcome.as_deref(), Some("error"));
    assert_eq!(
        items[1].matching_error_code.as_deref(),
        Some("target.match_ambiguous")
    );
    assert!(
        items[1].target_ref_hash.is_none(),
        "failed batch items must not emit durable matched-reference pseudonyms"
    );
}

#[test]
fn batch_audit_preserves_policy_identity_for_matching_policy_rejections() {
    let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
    let evidence: EvidenceConfig = serde_json::from_value(json!({
            "enabled": true,
            "ecosystem_bindings": {
                "baseline-dpi/v1": {
                    "profile": "odrl:v1",
                    "policy_id": "baseline-dpi-policy",
                    "policy_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                }
            },
            "claims": [{
                "id": "person-is-alive",
                "title": "Person is alive",
                "version": "2026-06",
                "subject_type": "person",
                "evidence_mode": { "type": "transitional_direct" },
                "source_bindings": {
                    "aa_wrong": {
                        "connector": "registry_data_api",
                        "dataset": "civil",
                        "entity": "person",
                        "lookup": {
                            "input": "sources.aa_wrong.alive",
                            "field": "alive",
                            "op": "eq",
                            "cardinality": "one"
                        },
                        "fields": {
                            "alive": {
                                "field": "alive",
                                "type": "boolean",
                                "required": true
                            }
                        },
                        "matching": {
                            "ecosystem_binding": {
                                "policy_id": "wrong-policy",
                                "policy_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                            }
                        }
                    },
                    "zz_civil": {
                        "connector": "registry_data_api",
                        "dataset": "civil",
                        "entity": "person",
                        "lookup": {
                            "input": "target.identifiers.national_id",
                            "field": "national_id",
                            "op": "eq",
                            "cardinality": "one"
                        },
                        "fields": {
                            "alive": {
                                "field": "alive",
                                "type": "boolean",
                                "required": true
                            }
                        },
                        "matching": {
                            "ecosystem_binding": { "id": "baseline-dpi/v1" }
                        }
                    }
                },
                "rule": { "type": "extract", "source": "zz_civil", "field": "alive" }
            }]
        }))
        .expect("evidence config parses");
    let request = BatchEvaluateRequest {
        items: vec![BatchEvaluateItemRequest {
            requester: None,
            target: EvidenceEntity::with_identifier("person", "national_id", "NID-TARGET"),
            relationship: None,
            on_behalf_of: None,
            purpose: Some("program-a".to_string()),
        }],
        claims: vec![ClaimRef::with_version("person-is-alive", "2026-06")],
        disclosure: Some("predicate".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: None,
    };
    let result = registry_notary_core::BatchEvaluateResponse {
        batch_id: "batch-1".to_string(),
        status: registry_notary_core::BatchStatus::Completed,
        claims: vec!["person-is-alive".to_string()],
        items: vec![registry_notary_core::BatchItemResponse {
            input_index: 0,
            target_ref: registry_notary_core::TargetRefView {
                entity_type: "person".to_string(),
                handle: "rnref:v1:target-handle".to_string(),
                identifier_schemes: vec!["national_id".to_string()],
                profile: None,
            },
            requester_ref: None,
            matching: None,
            evaluation_id: None,
            status: registry_notary_core::BatchItemStatus::Failed,
            claim_results: Vec::new(),
            errors: vec![registry_notary_core::BatchItemError {
                code: "target.matching_policy_rejected".to_string(),
                title: "Target matching policy rejected".to_string(),
                retryable: false,
                audit_code: None,
            }],
        }],
        summary: registry_notary_core::BatchSummary {
            succeeded: 0,
            failed: 1,
        },
    };
    let mut response = StatusCode::OK.into_response();
    attach_evidence_audit(
        &mut response,
        "batch_evaluate",
        None,
        &["person-is-alive".to_string()],
        Some(1),
    );

    attach_batch_evaluate_response_audit(&mut response, &keys, &evidence, &request, &result, None)
        .expect("batch audit context attaches");

    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("audit context is attached");
    let item = audit
        .batch_items
        .as_ref()
        .and_then(|items| items.first())
        .expect("batch item audit is captured");
    assert_eq!(item.matching_outcome.as_deref(), Some("error"));
    assert_eq!(
        item.matching_error_code.as_deref(),
        Some("target.matching_policy_rejected")
    );
    assert_eq!(
        item.matching_policy_id.as_deref(),
        Some("baseline-dpi-policy")
    );
    assert_eq!(
        item.matching_policy_hash.as_ref().map(Hashed::as_str),
        Some("sha256:3333333333333333333333333333333333333333333333333333333333333333")
    );
    assert_eq!(
        item.matching_evaluated_rule_ids.as_deref(),
        Some(&["source-binding-policy:person".to_string()][..])
    );
}

#[test]
fn evaluate_request_audit_context_hashes_entity_refs_and_matching_metadata() {
    let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
    let request = EvaluateRequest {
        requester: Some(EvidenceEntity::with_identifier(
            "person",
            "national_id",
            "NID-REQUESTER",
        )),
        target: Some({
            let mut target = EvidenceEntity::with_identifier("person", "national_id", "NID-TARGET");
            target
                .attributes
                .insert("given_name".to_string(), json!("Amina"));
            target
        }),
        relationship: None,
        on_behalf_of: None,
        variables: Default::default(),
        claims: vec![ClaimRef::from("person-is-alive")],
        disclosure: Some("predicate".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("program-a".to_string()),
    };
    let mut result = claim_result_view("eval-1", "person-is-alive");
    result.requester_ref = Some(registry_notary_core::EvidenceEntityRef {
        entity_type: "Person".to_string(),
        handle: "rnref:v1:requester-handle".to_string(),
        identifier_schemes: vec!["national_id".to_string()],
        profile: None,
    });
    result.matching = Some(registry_notary_core::MatchingMetadata {
        policy_id: "policy-v1".to_string(),
        method: "configured_lookup".to_string(),
        confidence: "high".to_string(),
        score: None,
        policy_hash: Some(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        ),
        evaluated_rule_ids: vec!["source-binding-policy:person".to_string()],
        ecosystem_binding_id: Some("baseline-dpi/v1".to_string()),
        ecosystem_binding_version: Some("2026-06-19".to_string()),
        pack_id: Some("baseline-dpi/v1".to_string()),
        pack_version: Some("2026-06-19".to_string()),
    });
    let mut response = StatusCode::OK.into_response();
    attach_evidence_audit(
        &mut response,
        "evaluate",
        Some("eval-1".to_string()),
        &["person-is-alive".to_string()],
        Some(1),
    );

    attach_evaluate_request_audit(&mut response, &keys, &request, Some(&result), None, None)
        .expect("audit context attaches");

    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("audit context is attached");
    assert_eq!(
        audit.purposes.as_deref(),
        Some(&["program-a".to_string()][..])
    );
    assert_eq!(audit.target_type.as_deref(), Some("Person"));
    assert_eq!(audit.requester_type.as_deref(), Some("Person"));
    assert_eq!(audit.matching_policy_id.as_deref(), Some("policy-v1"));
    assert_eq!(
        audit.matching_policy_hash.as_ref().map(Hashed::as_str),
        Some("sha256:1111111111111111111111111111111111111111111111111111111111111111")
    );
    assert_eq!(
        audit.matching_evaluated_rule_ids.as_deref(),
        Some(&["source-binding-policy:person".to_string()][..])
    );
    assert_eq!(
        audit.ecosystem_binding_id.as_deref(),
        Some("baseline-dpi/v1")
    );
    assert_eq!(
        audit.ecosystem_binding_version.as_deref(),
        Some("2026-06-19")
    );
    assert_eq!(audit.pack_id.as_deref(), Some("baseline-dpi/v1"));
    assert_eq!(audit.pack_version.as_deref(), Some("2026-06-19"));
    assert_eq!(audit.matching_method.as_deref(), Some("configured_lookup"));
    assert_eq!(audit.matching_outcome.as_deref(), Some("matched"));
    let target_hash = audit
        .target_ref_hash
        .as_ref()
        .map(Hashed::as_str)
        .expect("target ref hash is present");
    let requester_hash = audit
        .requester_ref_hash
        .as_ref()
        .map(Hashed::as_str)
        .expect("requester ref hash is present");
    assert!(!target_hash.contains("NID-TARGET"));
    assert!(!target_hash.contains("Amina"));
    assert!(!requester_hash.contains("NID-REQUESTER"));
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
    result.matching = Some(registry_notary_core::MatchingMetadata {
        policy_id: "policy-v1".to_string(),
        method: "configured_lookup".to_string(),
        confidence: "high".to_string(),
        score: None,
        policy_hash: None,
        evaluated_rule_ids: Vec::new(),
        ecosystem_binding_id: Some("baseline-dpi/v1".to_string()),
        ecosystem_binding_version: Some("2026-06-19".to_string()),
        pack_id: Some("baseline-dpi/v1".to_string()),
        pack_version: Some("2026-06-19".to_string()),
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
    assert_eq!(audit.matching_policy_id.as_deref(), Some("policy-v1"));
    assert_eq!(
        audit.ecosystem_binding_id.as_deref(),
        Some("baseline-dpi/v1")
    );
    assert_eq!(
        audit.ecosystem_binding_version.as_deref(),
        Some("2026-06-19")
    );
    assert_eq!(audit.pack_id.as_deref(), Some("baseline-dpi/v1"));
    assert_eq!(audit.pack_version.as_deref(), Some("2026-06-19"));
    assert_eq!(audit.matching_outcome.as_deref(), Some("matched"));
    assert!(audit.target_ref_hash.is_some());
    assert!(audit.requester_ref_hash.is_some());
}

#[test]
fn evaluate_request_audit_context_carries_matching_error_without_raw_inputs() {
    let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
    let mut target = EvidenceEntity::with_identifier("person", "national_id", "NID-TARGET");
    target
        .attributes
        .insert("date_of_birth".to_string(), json!("1984-02-10"));
    target
        .attributes
        .insert("given_name".to_string(), json!("Amina"));
    let request = EvaluateRequest {
        requester: None,
        target: Some(target),
        relationship: None,
        on_behalf_of: None,
        variables: Default::default(),
        claims: vec![ClaimRef::from("person-is-alive")],
        disclosure: Some("predicate".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("program-a".to_string()),
    };
    let mut response = StatusCode::FORBIDDEN.into_response();
    attach_evidence_audit(
        &mut response,
        "evaluate_denied",
        None,
        &["person-is-alive".to_string()],
        None,
    );

    attach_evaluate_request_audit(
        &mut response,
        &keys,
        &request,
        None,
        Some("target.matching_policy_rejected"),
        Some(&MatchingPolicyAuditIdentity {
            policy_id: "notary.source_binding.default.civil.person".to_string(),
            policy_hash: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            ecosystem_binding_id: None,
            ecosystem_binding_version: None,
            pack_id: None,
            pack_version: None,
            evaluated_rule_ids: vec!["source-binding-policy:person".to_string()],
        }),
    )
    .expect("audit context attaches");

    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("audit context is attached");
    assert_eq!(audit.target_type.as_deref(), Some("person"));
    assert_eq!(audit.matching_outcome.as_deref(), Some("error"));
    assert_eq!(
        audit.matching_error_code.as_deref(),
        Some("target.matching_policy_rejected")
    );
    assert_eq!(
        audit.matching_policy_id.as_deref(),
        Some("notary.source_binding.default.civil.person")
    );
    assert_eq!(
        audit.matching_policy_hash.as_ref().map(Hashed::as_str),
        Some("sha256:2222222222222222222222222222222222222222222222222222222222222222")
    );
    assert_eq!(
        audit.matching_evaluated_rule_ids.as_deref(),
        Some(&["source-binding-policy:person".to_string()][..])
    );
    assert!(
        audit.target_ref_hash.is_none(),
        "pre-match target errors must not create durable request-attribute pseudonyms"
    );
    let audit_value = json!({ "debug": format!("{audit:?}") });
    assert_json_absent_strings(&audit_value, ["NID-TARGET", "Amina", "1984-02-10"])
        .expect("raw matching inputs are absent from audit context");
    assert!(audit.requester_type.is_none());
    assert!(audit.requester_ref_hash.is_none());
}

#[test]
fn denied_matching_policy_audit_identity_uses_requested_claim_binding() {
    let evidence: EvidenceConfig = serde_json::from_value(json!({
            "enabled": true,
            "ecosystem_bindings": {
                "baseline-dpi/v1": {
                    "profile": "odrl:v1",
                    "policy_id": "baseline-dpi-policy",
                    "policy_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                }
            },
            "claims": [{
                "id": "person-is-alive",
                "title": "Person is alive",
                "version": "2026-06",
                "subject_type": "person",
                "evidence_mode": { "type": "transitional_direct" },
                "source_bindings": {
                    "aa_wrong": {
                        "connector": "registry_data_api",
                        "dataset": "civil",
                        "entity": "person",
                        "lookup": {
                            "input": "target.identifiers.national_id",
                            "field": "national_id",
                            "op": "eq",
                            "cardinality": "one"
                        },
                        "fields": {
                            "alive": {
                                "field": "alive",
                                "type": "boolean",
                                "required": true
                            }
                        },
                        "matching": {
                            "ecosystem_binding": {
                                "policy_id": "wrong-policy",
                                "policy_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                            }
                        }
                    },
                    "zz_civil": {
                        "connector": "registry_data_api",
                        "dataset": "civil",
                        "entity": "person",
                        "lookup": {
                            "input": "target.identifiers.national_id",
                            "field": "national_id",
                            "op": "eq",
                            "cardinality": "one"
                        },
                        "fields": {
                            "alive": {
                                "field": "alive",
                                "type": "boolean",
                                "required": true
                            }
                        },
                        "matching": {
                            "ecosystem_binding": { "id": "baseline-dpi/v1" }
                        }
                    }
                },
                "rule": { "type": "extract", "source": "zz_civil", "field": "alive" }
            }]
        }))
        .expect("evidence config parses");
    let request = EvaluateRequest {
        requester: None,
        target: Some(EvidenceEntity::with_identifier(
            "person",
            "national_id",
            "NID-TARGET",
        )),
        relationship: None,
        on_behalf_of: None,
        variables: Default::default(),
        claims: vec![ClaimRef::with_version("person-is-alive", "2026-06")],
        disclosure: None,
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("program-a".to_string()),
    };

    let policy = denied_matching_policy_audit_identity(
        &evidence,
        &request,
        Some("pdp.assurance_insufficient"),
    )
    .expect("matching policy identity is resolved");

    assert_eq!(policy.policy_id, "baseline-dpi-policy");
    assert_eq!(
        policy.policy_hash,
        "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    );
    assert_eq!(
        policy.evaluated_rule_ids,
        vec!["source-binding-policy:person".to_string()]
    );
    assert_eq!(
        policy.ecosystem_binding_id.as_deref(),
        Some("baseline-dpi/v1")
    );
    assert_eq!(policy.ecosystem_binding_version.as_deref(), Some("v1"));
    assert_eq!(policy.pack_id.as_deref(), Some("baseline-dpi/v1"));
    assert_eq!(policy.pack_version.as_deref(), Some("v1"));
    assert!(
        denied_matching_policy_audit_identity(
            &evidence,
            &request,
            Some("target.matching_policy_rejected")
        )
        .is_some(),
        "legacy matching policy denials still carry policy provenance"
    );
    assert!(
        denied_matching_policy_audit_identity(&evidence, &request, Some("auth.scope_denied"))
            .is_none(),
        "non-matching errors must not claim matching policy provenance"
    );
    assert!(
        denied_matching_policy_audit_identity(
            &evidence,
            &request,
            Some("target.attributes_insufficient")
        )
        .is_none(),
        "pre-policy input errors must not claim PDP provenance"
    );
    assert!(
        denied_matching_policy_audit_identity(&evidence, &request, Some("purpose.not_allowed"))
            .is_none(),
        "purpose denials happen before PDP matching policy evaluation"
    );
}

#[test]
fn matching_policy_audit_identity_from_error_uses_pdp_audit_payload() {
    let mut evidence = EvidenceConfig::default();
    evidence.ecosystem_bindings.insert(
        "baseline-dpi/v1".to_string(),
        registry_notary_core::EvidenceEcosystemBindingConfig {
            profile: Some("registry-notary/source-policy/v1".to_string()),
            policy_id: "actual-policy".to_string(),
            policy_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            unsupported_odrl_terms: Vec::new(),
        },
    );
    let error = EvidenceError::PolicyDenied {
        code: "pdp.assurance_insufficient",
        policy_id: Some("actual-policy".to_string()),
        policy_hash: Some(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        evaluated_rule_ids: vec!["actual-rule".to_string()],
    };

    let policy = matching_policy_audit_identity_from_error(&evidence, &error)
        .expect("PDP error audit identity is available");

    assert_eq!(policy.policy_id, "actual-policy");
    assert_eq!(
        policy.policy_hash,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(policy.evaluated_rule_ids, vec!["actual-rule".to_string()]);
    assert_eq!(
        policy.ecosystem_binding_id.as_deref(),
        Some("baseline-dpi/v1")
    );
    assert_eq!(policy.ecosystem_binding_version.as_deref(), Some("v1"));
    assert_eq!(policy.pack_id.as_deref(), Some("baseline-dpi/v1"));
    assert_eq!(policy.pack_version.as_deref(), Some("v1"));
}

#[test]
fn merge_matching_policy_audit_identity_preserves_pdp_rules_and_adds_binding() {
    let policy = merge_matching_policy_audit_identity(
        Some(MatchingPolicyAuditIdentity {
            policy_id: "actual-policy".to_string(),
            policy_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            ecosystem_binding_id: None,
            ecosystem_binding_version: None,
            pack_id: None,
            pack_version: None,
            evaluated_rule_ids: vec!["actual-rule".to_string()],
        }),
        Some(MatchingPolicyAuditIdentity {
            policy_id: "selected-policy".to_string(),
            policy_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            ecosystem_binding_id: Some("baseline-dpi/v1".to_string()),
            ecosystem_binding_version: Some("v1".to_string()),
            pack_id: Some("baseline-dpi/v1".to_string()),
            pack_version: Some("v1".to_string()),
            evaluated_rule_ids: vec!["selected-rule".to_string()],
        }),
    )
    .expect("merged policy exists");

    assert_eq!(policy.policy_id, "actual-policy");
    assert_eq!(
        policy.policy_hash,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(policy.evaluated_rule_ids, vec!["actual-rule".to_string()]);
    assert_eq!(
        policy.ecosystem_binding_id.as_deref(),
        Some("baseline-dpi/v1")
    );
    assert_eq!(policy.ecosystem_binding_version.as_deref(), Some("v1"));
}
