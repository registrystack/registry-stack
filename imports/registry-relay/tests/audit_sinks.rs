// SPDX-License-Identifier: Apache-2.0
//! Integration tests for audit sinks.

use std::fs;
use std::path::Path;

use registry_relay::audit::{
    AuditEnvelope, AuditRecord, AuditSink, EndpointKind, FileSink, SyslogSink,
};
use serde_json::Value;
use tempfile::tempdir;
use tokio::time::{timeout, Duration};

fn sample_record(path: &str) -> AuditRecord {
    AuditRecord {
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
        scopes_used: vec!["catalog".to_string()],
        query_params: serde_json::json!({}),
        purpose: Some("ci-smoke".to_string()),
        status_code: 200,
        row_count: None,
        null_geometry_count: None,
        invalid_geometry_count: None,
        suppressed_groups: None,
        duration_ms: 7,
        error_code: None,
        provenance: None,
    }
}

#[tokio::test]
async fn file_sink_writes_jsonl_and_creates_parent_dir() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("nested").join("audit.jsonl");
    let sink = FileSink::new(&path, 100, 14).expect("sink");

    sink.write(AuditEnvelope::from(sample_record("/datasets")))
        .await
        .expect("write");
    sink.flush().await.expect("flush");

    let contents = fs::read_to_string(&path).expect("audit file");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 1);

    let value: Value = serde_json::from_str(lines[0]).expect("json line");
    assert_eq!(value["path"], "/datasets");
    assert_eq!(value["endpoint_kind"], "catalog");
}

#[tokio::test]
async fn file_sink_rotates_when_next_record_exceeds_max_size() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let first = AuditEnvelope::from(sample_record("/first"))
        .to_jsonl()
        .unwrap();
    let sink = FileSink::new(&path, 1, 3).expect("sink");

    fs::write(&path, "x".repeat((1024 * 1024) - first.len() + 1)).expect("seed oversized tail");

    sink.write(AuditEnvelope::from(sample_record("/first")))
        .await
        .expect("first write");
    let mut seeded_active = fs::read_to_string(&path).expect("active after first write");
    seeded_active.push_str(&"x".repeat(1024 * 1024));
    fs::write(&path, seeded_active).expect("force second rotation");
    sink.write(AuditEnvelope::from(sample_record("/second")))
        .await
        .expect("second write");

    let active = fs::read_to_string(&path).expect("active file");
    let rotated = fs::read_to_string(rotated_path(&path, 1)).expect("rotated file");

    assert!(active.contains("\"path\":\"/second\""));
    assert!(!active.contains("\"path\":\"/first\""));
    assert!(rotated.contains("\"path\":\"/first\""));
}

#[cfg(unix)]
#[tokio::test]
async fn syslog_sink_emits_jsonl_datagram() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("syslog.sock");
    let receiver = tokio::net::UnixDatagram::bind(&socket_path).expect("bind syslog socket");
    let sink = SyslogSink::with_socket_path(&socket_path);

    sink.write(AuditEnvelope::from(sample_record("/syslog")))
        .await
        .expect("write");

    let mut buf = vec![0_u8; 4096];
    let received = timeout(Duration::from_secs(1), receiver.recv(&mut buf))
        .await
        .expect("datagram")
        .expect("receive");
    let line = std::str::from_utf8(&buf[..received]).expect("utf8");

    assert!(line.ends_with('\n'));
    let value: Value = serde_json::from_str(line.trim_end()).expect("json line");
    assert_eq!(value["path"], "/syslog");
}

#[cfg(unix)]
#[tokio::test]
async fn syslog_sink_returns_io_error_when_socket_unavailable() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("missing.sock");
    let sink = SyslogSink::with_socket_path(socket_path);

    let error = sink
        .write(AuditEnvelope::from(sample_record("/missing")))
        .await
        .expect_err("missing socket should be an audit error");

    assert!(matches!(error, registry_relay::audit::AuditError::Io(_)));
}

fn rotated_path(path: &Path, index: u32) -> String {
    format!("{}.{}", path.display(), index)
}
