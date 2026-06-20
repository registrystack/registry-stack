// SPDX-License-Identifier: Apache-2.0
//! Integration tests for audit sinks.

use std::fs;
use std::path::Path;

use registry_platform_audit::{
    verify_jsonl_lines, verify_jsonl_lines_with_hasher, AuditChainProfile,
};
use registry_relay::audit::{AuditPipeline, AuditRecord, EndpointKind, FileSink, SyslogSink};
use serde_json::Value;
use tempfile::tempdir;
use tokio::time::{timeout, Duration};

fn sample_record(path: &str) -> AuditRecord {
    AuditRecord {
        ar_profile_id: None,
        ar_profile_version: None,
        ar_subject_id_type: None,
        ar_subject_id_hash: None,
        ar_requested_claims: None,
        ar_released_claims: None,
        ar_internal_outcome: None,
        ar_source_cardinality_outcome: None,
        ar_source_availability_class: None,
        ts: "2026-05-15T10:00:00.123Z".to_string(),
        request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
        principal_id: Some("statistics_office".to_string()),
        auth_mode: Some("api_key".to_string()),
        remote_addr: "127.0.0.1".to_string(),
        method: "GET".to_string(),
        path: path.to_string(),
        endpoint_kind: EndpointKind::Catalog,
        dataset_id: None,
        entity_name: None,
        table_id: None,
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
        pdp_policy_id: None,
        pdp_policy_hash: None,
        pdp_evaluated_rule_ids: None,
        pdp_stable_problem_code: None,
        pdp_ecosystem_binding_id: None,
        pdp_ecosystem_binding_version: None,
        pdp_route_identity: None,
        pdp_source_binding: None,
        pdp_checked_scopes: None,
        pdp_trust_provenance: None,
        scopes_used: vec!["catalog".to_string()],
        query_params: serde_json::json!({}),
        purpose: Some("ci-smoke".to_string()),
        status_code: 200,
        row_count: None,
        null_geometry_count: None,
        invalid_geometry_count: None,
        geometry_vertex_count: None,
        suppressed_groups: None,
        duration_ms: 7,
        error_code: None,
        provenance: None,
        config: None,
    }
}

#[tokio::test]
async fn file_sink_writes_jsonl_and_creates_parent_dir() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("nested").join("audit.jsonl");
    let sink = AuditPipeline::from_sink(FileSink::new(&path, 100, 14).expect("sink"));

    sink.write_record(sample_record("/v1/datasets"))
        .await
        .expect("write");
    sink.flush().await.expect("flush");

    let contents = fs::read_to_string(&path).expect("audit file");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 1);

    let value: Value = serde_json::from_str(lines[0]).expect("json line");
    assert!(value["envelope_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert!(value["timestamp_unix_ms"].as_i64().is_some());
    assert!(value["prev_hash"].is_null());
    assert_eq!(
        value["record_hash"].as_str().expect("record_hash").len(),
        64
    );
    assert_eq!(value["record"]["path"], "/v1/datasets");
    assert_eq!(value["record"]["endpoint_kind"], "catalog");
}

#[tokio::test]
async fn file_sink_rotates_when_next_record_exceeds_max_size() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let sink = AuditPipeline::from_sink(FileSink::new(&path, 1, 3).expect("sink"));

    let oversized_path = format!("/first/{}", "a".repeat(1024 * 1024));
    sink.write_record(sample_record(&oversized_path))
        .await
        .expect("first write");
    sink.write_record(sample_record("/second"))
        .await
        .expect("second write");

    let active = fs::read_to_string(&path).expect("active file");
    let rotated = fs::read_to_string(rotated_path(&path, 1)).expect("rotated file");

    assert!(active.contains("\"path\":\"/second\""));
    assert!(!active.contains("\"path\":\"/first\""));
    assert!(rotated.contains("\"path\":\"/first/"));
}

#[tokio::test]
async fn file_sink_bootstraps_chain_from_existing_tail() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let first_sink = AuditPipeline::from_sink(FileSink::new(&path, 100, 14).expect("first sink"));
    first_sink
        .write_record(sample_record("/first"))
        .await
        .expect("first write");

    let first_line = fs::read_to_string(&path).expect("audit file");
    let first_value: Value = serde_json::from_str(first_line.lines().next().expect("first line"))
        .expect("first platform envelope");
    let first_hash = first_value["record_hash"]
        .as_str()
        .expect("first record hash")
        .to_owned();

    let restarted_sink =
        AuditPipeline::from_sink(FileSink::new(&path, 100, 14).expect("restarted sink"));
    restarted_sink
        .write_record(sample_record("/second"))
        .await
        .expect("second write");

    let contents = fs::read_to_string(&path).expect("audit file");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 2);
    let second_value: Value = serde_json::from_str(lines[1]).expect("second platform envelope");
    assert_eq!(second_value["prev_hash"], first_hash);
}

#[tokio::test]
async fn file_sink_bootstraps_keyed_chain_from_existing_tail() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let env_name = "REGISTRY_RELAY_TEST_FILE_AUDIT_CHAIN_SECRET";
    std::env::set_var(env_name, "0123456789abcdef0123456789abcdef");
    let profile = AuditChainProfile::registry_relay_from_env(env_name)
        .expect("test audit chain secret loads");
    std::env::remove_var(env_name);
    let first_sink = AuditPipeline::new_with_chain_profile(
        std::sync::Arc::new(FileSink::new(&path, 100, 14).expect("first sink")),
        profile.clone(),
    );
    first_sink
        .write_record(sample_record("/first"))
        .await
        .expect("first write");

    let restarted_sink = AuditPipeline::new_with_chain_profile(
        std::sync::Arc::new(FileSink::new(&path, 100, 14).expect("restarted sink")),
        profile.clone(),
    );
    restarted_sink
        .write_record(sample_record("/second"))
        .await
        .expect("second write");

    let contents = fs::read_to_string(&path).expect("audit file");
    assert!(
        verify_jsonl_lines(contents.lines()).is_err(),
        "keyed audit chain must not verify with the dev-only unkeyed hasher"
    );
    verify_jsonl_lines_with_hasher(contents.lines(), &profile.hasher())
        .expect("keyed audit chain verifies");
}

#[tokio::test]
async fn file_sink_rejects_tampered_existing_jsonl_before_append() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let first_sink = AuditPipeline::from_sink(FileSink::new(&path, 100, 14).expect("first sink"));
    first_sink
        .write_record(sample_record("/first"))
        .await
        .expect("first write");

    let tampered = fs::read_to_string(&path)
        .expect("audit file")
        .replace("/first", "/tampered");
    fs::write(&path, tampered).expect("tamper audit file");

    let restarted_sink =
        AuditPipeline::from_sink(FileSink::new(&path, 100, 14).expect("restarted sink"));
    let error = restarted_sink
        .write_record(sample_record("/second"))
        .await
        .expect_err("tampered existing audit file must reject append");

    assert!(matches!(
        error,
        registry_relay::audit::AuditError::ChainVerification(_)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn syslog_sink_emits_jsonl_datagram() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("syslog.sock");
    let receiver = tokio::net::UnixDatagram::bind(&socket_path).expect("bind syslog socket");
    let sink = AuditPipeline::from_sink(SyslogSink::with_socket_path(&socket_path));

    sink.write_record(sample_record("/syslog"))
        .await
        .expect("write");

    let mut buf = vec![0_u8; 4096];
    let received = timeout(Duration::from_secs(1), receiver.recv(&mut buf))
        .await
        .expect("datagram")
        .expect("receive");
    let line = std::str::from_utf8(&buf[..received]).expect("utf8");

    let json_start = line.find('{').expect("json envelope suffix");
    assert!(line[..json_start].contains("registry-platform-audit"));
    let value: Value = serde_json::from_str(&line[json_start..]).expect("json envelope suffix");
    assert!(value["envelope_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert_eq!(value["record"]["path"], "/syslog");
}

#[cfg(unix)]
#[tokio::test]
async fn syslog_sink_returns_io_error_when_socket_unavailable() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("missing.sock");
    let sink = AuditPipeline::from_sink(SyslogSink::with_socket_path(socket_path));

    let error = sink
        .write_record(sample_record("/missing"))
        .await
        .expect_err("missing socket should be an audit error");

    assert!(matches!(error, registry_relay::audit::AuditError::Io(_)));
}

fn rotated_path(path: &Path, index: u32) -> String {
    format!("{}.{}", path.display(), index)
}
