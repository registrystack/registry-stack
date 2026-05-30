// SPDX-License-Identifier: Apache-2.0

use registry_platform_audit::{
    verify_chain, verify_jsonl_lines, AuditChainHasher, ChainState, ChainVerificationError,
};
use registry_relay::audit::redact::{
    redact_query_with_sensitive_fields, sensitive_value_hash, QueryRedactionError, QueryRedactor,
};
use registry_relay::audit::{AuditRecord, EndpointKind, InMemorySink};

fn sample_record(request_id: usize) -> AuditRecord {
    AuditRecord {
        ts: "2026-05-15T10:00:00.123Z".to_string(),
        request_id: format!("REQ-{request_id:05}"),
        principal_id: Some("statistics_office".to_string()),
        auth_mode: Some("api_key".to_string()),
        remote_addr: "127.0.0.1".to_string(),
        method: "GET".to_string(),
        path: "/datasets/social_registry/individuals".to_string(),
        endpoint_kind: EndpointKind::Rows,
        dataset_id: Some("social_registry".to_string()),
        entity_name: Some("individuals".to_string()),
        table_id: Some("individuals".to_string()),
        relationship: None,
        aggregate_id: None,
        underlying_kind: None,
        collection_id: None,
        primary_key: None,
        offering_id: None,
        verification_id: None,
        verification_decision: None,
        claim_hash: None,
        evidence_hash: None,
        scopes_used: vec!["social_registry:read".to_string()],
        query_params: redact_query_with_sensitive_fields("id=IND-001234&limit=10", ["id"]),
        purpose: Some("benefit eligibility".to_string()),
        status_code: 200,
        row_count: Some(1),
        null_geometry_count: None,
        invalid_geometry_count: None,
        geometry_vertex_count: None,
        suppressed_groups: None,
        duration_ms: 3,
        error_code: None,
        provenance: None,
    }
}

#[test]
fn sensitive_value_hash_is_deterministic_and_field_bound() {
    let first = sensitive_value_hash("id", "IND-001234");
    let second = sensitive_value_hash("id", "IND-001234");
    let other_field = sensitive_value_hash("household_id", "IND-001234");

    assert_eq!(first, second);
    assert_ne!(first, other_field);
    assert!(first.starts_with("sha256:"));
}

#[test]
fn redaction_hashes_sensitive_values_without_leaking_raw_pii() {
    let redacted = redact_query_with_sensitive_fields(
        "id=IND-001234&name=Ana+Diaz&created_at.gte=2026-01-01&api_key=secret",
        ["id", "name"],
    );

    assert_eq!(redacted["id"]["op"], "eq");
    assert_eq!(
        redacted["id"]["value_hash"],
        sensitive_value_hash("id", "IND-001234")
    );
    assert_eq!(
        redacted["name"]["value_hash"],
        sensitive_value_hash("name", "Ana Diaz")
    );
    assert_eq!(redacted["created_at.gte"]["op"], "gte");
    assert_eq!(redacted["api_key"]["op"], "redacted");

    let dump = redacted.to_string();
    assert!(!dump.contains("IND-001234"), "{dump}");
    assert!(!dump.contains("Ana"));
    assert!(!dump.contains("2026-01-01"));
    assert!(!dump.contains("secret"));
}

#[test]
fn redaction_hashes_configured_sensitive_fields_case_insensitively() {
    let redacted = redact_query_with_sensitive_fields("ID=IND-001234&Name=Ana", ["id", "name"]);

    assert_eq!(
        redacted["ID"]["value_hash"],
        sensitive_value_hash("ID", "IND-001234")
    );
    assert_eq!(
        redacted["Name"]["value_hash"],
        sensitive_value_hash("Name", "Ana")
    );
}

#[test]
fn redaction_surfaces_invalid_utf8_query_encoding() {
    let redactor = QueryRedactor::new(["id"]);

    let err = redactor
        .try_redact_query("id=%FF")
        .expect_err("invalid UTF-8 is not silently lossy-decoded");
    assert_eq!(err, QueryRedactionError::InvalidUtf8);

    let redacted = redactor.redact_query("id=%FF");
    assert_eq!(redacted["_error"]["code"], "invalid_query_encoding");
    assert!(!redacted.to_string().contains('\u{fffd}'));
}

#[tokio::test]
async fn platform_chained_envelopes_verify_and_detect_tampering() {
    let sink = InMemorySink::new();
    let hasher = AuditChainHasher::unkeyed_dev_only();
    let state = ChainState::new(hasher.clone());
    let first = state
        .append(&sink, sample_record(1))
        .await
        .expect("first append");
    let mut second = state
        .append(&sink, sample_record(2))
        .await
        .expect("second append");

    let result = verify_chain(&[first.clone(), second.clone()], &hasher).expect("valid chain");
    assert_eq!(result.records, 2);
    assert!(result.start_prev_hash.is_none());
    assert!(result.last_hash.is_some());

    second.record["request_id"] = serde_json::json!("REQ-99999");
    let err = verify_chain(&[first, second], &hasher).expect_err("tampered chain");
    assert!(matches!(
        err,
        ChainVerificationError::RecordHashMismatch { line: 2 }
    ));
}

#[tokio::test]
async fn platform_verification_rejects_rotation_segment_without_genesis() {
    let sink = InMemorySink::new();
    let state = ChainState::unkeyed_dev_only();
    let first = state
        .append(&sink, sample_record(1))
        .await
        .expect("first append");

    let rotated = state
        .append(&sink, sample_record(2))
        .await
        .expect("second append")
        .to_jsonl()
        .expect("rotated jsonl");

    let err = verify_jsonl_lines([rotated.as_str()])
        .expect_err("public verification requires the retained genesis chain");
    assert!(matches!(
        err,
        ChainVerificationError::PrevHashMismatch {
            line: 1,
            expected: None,
            actual: Some(actual),
        } if actual == first.record_hash
    ));
}

#[tokio::test]
async fn ten_thousand_platform_record_chain_verification_smoke_is_quick() {
    let sink = InMemorySink::new();
    let state = ChainState::unkeyed_dev_only();

    for i in 0..10_000 {
        state.append(&sink, sample_record(i)).await.expect("append");
    }

    let lines = sink.snapshot();
    let result = verify_jsonl_lines(lines.iter().map(String::as_str)).expect("valid chain");
    assert_eq!(result.records, 10_000);
    assert!(result.last_hash.is_some());
}
