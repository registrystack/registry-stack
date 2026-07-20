// SPDX-License-Identifier: Apache-2.0

use super::support::*;
#[allow(unused_imports)]
use super::{
    admin::*, auth::*, credentials::*, federation::*, http_contracts::*, oid4vci::*, preauth::*,
};

#[tokio::test]
#[cfg(not(feature = "registry-notary-cel"))]
pub(super) async fn standalone_server_authenticates_and_audits_unsupported_access_mode() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let mut config = notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    add_admin_api_key(&mut config);
    add_metrics_read_api_key(&mut config);
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().mock_transport().build(app);

    let denied = server.get("/v1/claims").await;
    denied.assert_status(StatusCode::UNAUTHORIZED);

    let denied_openapi = server.get("/openapi.json").await;
    denied_openapi.assert_status(StatusCode::UNAUTHORIZED);

    let openapi = server
        .get("/openapi.json")
        .add_header("x-api-key", "api-token")
        .await;
    openapi.assert_status_ok();
    let openapi_body: Value = openapi.json();
    assert_eq!(openapi_body["openapi"], json!("3.1.0"));
    assert!(openapi_body["paths"]["/v1/evaluations"].is_object());

    let discovery = server
        .get("/.well-known/evidence-service")
        .add_header("x-api-key", "api-token")
        .await;
    discovery.assert_status_ok();
    let discovery_body: Value = discovery.json();
    assert_eq!(
        discovery_body["base_url"],
        json!("https://evidence.example.test")
    );

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("person-1"),
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    response.assert_status(StatusCode::NOT_IMPLEMENTED);

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    let envelopes = audit_envelopes(&audit_path);
    assert!(envelopes
        .iter()
        .any(|envelope| envelope.record.get("principal_id_hash").is_some()));
    assert!(envelopes
        .iter()
        .all(|envelope| envelope.record.get("principal_id").is_none()));
    assert!(audit.contains("\"decision\":\"evaluate_denied\""));
    assert!(audit.contains("\"claim_hash\":\"sha256:"));
    assert!(!audit.contains("api-token"));
    assert!(!audit.contains("person-1"));
    let metrics = server
        .get("/metrics")
        .add_header("x-api-key", "metrics-token")
        .await;
    metrics.assert_status_ok();
    let metrics_body = metrics.text();
    assert!(metrics_body.contains("registry_notary_http_requests_total"));
    assert!(metrics_body.contains(
        "registry_notary_http_requests_total{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"501\",status_class=\"5xx\",error_code=\"claim.operation_unsupported\"}"
    ));
    assert!(metrics_body.contains("# TYPE registry_notary_http_request_duration_seconds histogram"));
    assert!(metrics_body.contains(
        "registry_notary_http_request_duration_seconds_bucket{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"501\",status_class=\"5xx\",error_code=\"claim.operation_unsupported\",le=\"+Inf\"}"
    ));
    assert!(metrics_body.contains(
        "registry_notary_http_request_duration_seconds_sum{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"501\",status_class=\"5xx\",error_code=\"claim.operation_unsupported\"}"
    ));
    assert!(metrics_body.contains(
        "registry_notary_http_request_duration_seconds_count{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"501\",status_class=\"5xx\",error_code=\"claim.operation_unsupported\"}"
    ));
    assert!(!metrics_body.contains("registry_notary_http_request_duration_ms_total"));
    assert!(!metrics_body.contains("route="));
    assert!(metrics_body.contains("registry_notary_audit_events_total{outcome=\"success\"}"));
    assert!(!metrics_body.contains("api-token"));
    assert!(!metrics_body.contains("person-1"));
    assert!(!metrics_body.contains("farmer-under-4ha"));
    assert!(!metrics_body.contains("purpose.example.test"));
}

#[tokio::test]
pub(super) async fn audit_chain_bootstraps_from_sink_tail() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let config = notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );

    let first = TestServer::builder().mock_transport().build(
        standalone_router(config.clone())
            .await
            .expect("first router builds"),
    );
    first
        .get("/v1/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // A restart releases the single-writer audit lock: the first instance must
    // be fully torn down before the replacement acquires the lock (#211).
    drop(first);
    tokio::task::yield_now().await;

    let second = TestServer::builder().mock_transport().build(
        standalone_router(config)
            .await
            .expect("second router builds"),
    );
    second
        .get("/v1/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    let contents = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(
        verify_jsonl_lines_with_hasher(contents.lines(), &AuditChainHasher::unkeyed_dev_only())
            .is_err(),
        "runtime audit chain must not verify with the dev-only unkeyed hasher"
    );
    let hasher = AuditChainHasher::from_env_derived("REGISTRY_NOTARY_AUDIT_HASH_SECRET")
        .expect("configured audit chain secret loads");
    verify_jsonl_lines_with_hasher(contents.lines(), &hasher).expect("audit chain verifies");
    let envelopes = audit_envelopes(&audit_path);
    assert_eq!(envelopes.len(), 2);
    assert_eq!(envelopes[1].prev_hash, Some(envelopes[0].record_hash));
}

#[tokio::test]
pub(super) async fn audit_chain_detects_inserted_envelope() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let config = notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let first = TestServer::builder().mock_transport().build(
        standalone_router(config.clone())
            .await
            .expect("first router builds"),
    );
    first
        .get("/v1/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    first
        .get("/v1/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // A restart releases the single-writer audit lock before the replacement
    // instance acquires it (#211).
    drop(first);
    tokio::task::yield_now().await;

    let contents = std::fs::read_to_string(&audit_path).expect("audit was written");
    let mut lines = contents.lines().collect::<Vec<_>>();
    lines.insert(1, lines[0]);
    std::fs::write(&audit_path, format!("{}\n", lines.join("\n"))).expect("tampered audit write");

    let second = TestServer::builder().mock_transport().build(
        standalone_router(config)
            .await
            .expect("second router builds"),
    );
    let response = second
        .get("/v1/claims")
        .add_header("x-api-key", "api-token")
        .await;

    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("audit.write_failed"));
}

#[tokio::test]
pub(super) async fn standalone_router_verifies_audit_before_returning_readiness() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let config = notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let first = TestServer::builder().mock_transport().build(
        standalone_router(config.clone())
            .await
            .expect("first router builds"),
    );
    first
        .get("/v1/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    drop(first);
    tokio::task::yield_now().await;

    let contents = std::fs::read_to_string(&audit_path).expect("audit was written");
    std::fs::write(
        &audit_path,
        contents.replace("\"status\":401", "\"status\":402"),
    )
    .expect("audit is tampered");

    let app = standalone_router(config)
        .await
        .expect("public helper returns a router with integrity failure latched");
    let server = TestServer::builder().mock_transport().build(app);

    let ready = server.get("/ready").await;
    ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = ready.json();
    assert_eq!(body["code"], json!("audit.chain.inconsistent"));
    assert_eq!(body["status"], json!(503));
    assert!(body["request_id"].is_string());
    assert!(body.get("checks").is_none());
    assert!(body.get("readiness_status").is_none());
    let rendered = serde_json::to_string(&body).expect("readiness problem serializes");
    assert!(!rendered.contains("\"status\":402"));
    assert!(!rendered.contains(&audit_path.to_string_lossy().to_string()));
    server.get("/healthz").await.assert_status_ok();
}
