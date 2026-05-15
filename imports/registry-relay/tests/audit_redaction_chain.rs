// SPDX-License-Identifier: Apache-2.0

use data_gate::audit::chain::{
    verify_chain_lines, verify_chain_lines_from_prev_hash, ChainState, ChainVerificationError,
};
use data_gate::audit::redact::{redact_query_with_sensitive_fields, sensitive_value_hash};
use data_gate::audit::{AuditEnvelope, AuditRecord, EndpointKind};

fn sample_record(request_id: usize) -> AuditRecord {
    AuditRecord {
        ts: "2026-05-15T10:00:00.123Z".to_string(),
        request_id: format!("REQ-{request_id:05}"),
        api_key_id: Some("statistics_office".to_string()),
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
        scopes_used: vec!["social_registry:read".to_string()],
        query_params: redact_query_with_sensitive_fields("id=IND-001234&limit=10", ["id"]),
        purpose: Some("benefit eligibility".to_string()),
        status_code: 200,
        row_count: Some(1),
        suppressed_groups: None,
        duration_ms: 3,
        error_code: None,
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
fn chained_envelopes_verify_and_detect_tampering() {
    let mut state = ChainState::new();
    let first = state
        .wrap(AuditEnvelope::from(sample_record(1)))
        .to_jsonl()
        .expect("first jsonl");
    let second = state
        .wrap(AuditEnvelope::from(sample_record(2)))
        .to_jsonl()
        .expect("second jsonl");

    let result = verify_chain_lines([first.as_str(), second.as_str()]).expect("valid chain");
    assert_eq!(result.records, 2);
    assert!(result.start_prev_hash.is_none());
    assert!(result.last_hash.is_some());

    let tampered = second.replace("REQ-00002", "REQ-99999");
    let err = verify_chain_lines([first.as_str(), tampered.as_str()]).expect_err("tampered chain");
    assert!(matches!(
        err,
        ChainVerificationError::RecordHashMismatch { line: 2, .. }
    ));
}

#[test]
fn verification_accepts_rotation_boundary_records() {
    let mut state = ChainState::new();
    let first = state
        .wrap(AuditEnvelope::from(sample_record(1)))
        .to_jsonl()
        .expect("first jsonl");
    let boundary_prev_hash = verify_chain_lines([first.as_str()])
        .expect("first segment")
        .last_hash
        .expect("first hash");

    let rotated = state
        .wrap(AuditEnvelope::from(sample_record(2)))
        .to_jsonl()
        .expect("rotated jsonl");

    let standalone = verify_chain_lines([rotated.as_str()]).expect("rotated segment");
    assert_eq!(standalone.records, 1);
    assert_eq!(
        standalone.start_prev_hash.as_deref(),
        Some(boundary_prev_hash.as_str())
    );

    verify_chain_lines_from_prev_hash([rotated.as_str()], Some(boundary_prev_hash.as_str()))
        .expect("rotated segment with known predecessor");
}

#[test]
fn ten_thousand_record_chain_verification_smoke_is_quick() {
    let mut state = ChainState::new();
    let mut lines = Vec::with_capacity(10_000);

    for i in 0..10_000 {
        lines.push(
            state
                .wrap(AuditEnvelope::from(sample_record(i)))
                .to_jsonl()
                .expect("jsonl"),
        );
    }

    let result = verify_chain_lines(lines.iter().map(String::as_str)).expect("valid chain");
    assert_eq!(result.records, 10_000);
    assert!(result.last_hash.is_some());
}
