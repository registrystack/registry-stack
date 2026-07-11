// SPDX-License-Identifier: Apache-2.0

use super::support::*;
#[allow(unused_imports)]
use super::{
    admin::*, auth::*, credentials::*, federation::*, http_contracts::*, oid4vci::*, preauth::*,
    sources::*,
};

#[tokio::test]
pub(crate) async fn evaluate_policy_denial_records_zero_source_and_redacted_audit() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(
                move |headers: HeaderMap, query: Query<BTreeMap<String, String>>| {
                    let source_hits = Arc::clone(&source_hits_for_route);
                    async move {
                        source_hits.fetch_add(1, Ordering::SeqCst);
                        registry_data_api(headers, query).await
                    }
                },
            ),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let binding = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmed-land-size")
        .expect("farmed-land-size claim exists")
        .source_bindings
        .get_mut("farmer")
        .expect("farmer binding exists");
    binding.matching.permitted_jurisdictions = vec!["RW".to_string()];

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("person-1"),
            "claims": ["farmed-land-size"],
            "disclosure": "value"
        }))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let body: Value = response.json();
    assert_eq!(body["code"], json!("pdp.jurisdiction_not_permitted"));
    assert!(body.get("results").is_none());
    let body_text = serde_json::to_string(&body).expect("problem body serializes");
    assert!(!body_text.contains("api-token"));
    assert!(!body_text.contains("source-token"));
    assert!(!body_text.contains("person-1"));
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/evaluations",
        "evaluate_denied",
        StatusCode::FORBIDDEN,
        "pdp.jurisdiction_not_permitted",
    );
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    assert!(denied.get("principal_id").is_none());
    assert!(denied["principal_id_hash"]
        .as_str()
        .expect("principal id hash is present")
        .starts_with("hmac-sha256:"));
    assert!(denied["claim_hash"]
        .as_str()
        .expect("claim hash is present")
        .starts_with("sha256:"));
    assert!(denied.get("correlation_id").is_none());
    assert!(denied["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is present")
        .starts_with("hmac-sha256:"));
    assert_audit_records_do_not_contain(
        &records,
        &[
            "api-token",
            "source-token",
            "person-1",
            base_url.trim_end_matches('/'),
        ],
    );
}

#[tokio::test]
pub(crate) async fn standalone_server_authenticates_evaluates_over_http_and_writes_redacted_audit()
{
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let mut config = registry_data_api_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    add_admin_api_key(&mut config);
    add_metrics_read_api_key(&mut config);
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

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
            "claims": ["farmed-land-size"],
            "disclosure": "value"
        }))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(3.5));
    let provenance = &body["results"][0]["provenance"];
    assert_eq!(
        provenance["schema_version"],
        json!("registry-notary-claim-provenance/v1")
    );
    assert_eq!(
        provenance["generated_by"]["type"],
        json!("claim_evaluation")
    );
    assert_eq!(
        provenance["generated_by"]["service_id"],
        body["results"][0]["provenance"]["generated_by"]["service_id"]
    );
    assert!(provenance["generated_by"]["service_id"].is_string());
    assert_eq!(
        provenance["generated_by"]["claim_id"],
        json!("farmed-land-size")
    );
    assert_eq!(provenance["used"]["source_count"], json!(1));
    assert_eq!(provenance["derived_from"], json!([]));
    // computed_by must be gone from the wire entirely.
    assert!(
        !provenance.to_string().contains("computed_by"),
        "computed_by must not appear in claim provenance on the wire"
    );
    // Machine-client flow evaluates under no named policy: policy_* omitted.
    assert!(provenance["generated_by"].get("policy_id").is_none());
    // Requester-side identity must never appear in claim provenance.
    for forbidden in ["client", "actor", "subject"] {
        assert!(
            provenance.get(forbidden).is_none()
                && provenance["generated_by"].get(forbidden).is_none()
                && provenance["used"].get(forbidden).is_none(),
            "requester-side field {forbidden} must not appear in claim provenance"
        );
    }

    #[cfg(feature = "registry-notary-cel")]
    {
        let cel_response = server
            .post("/v1/evaluations")
            .add_header("x-api-key", "api-token")
            .add_header("data-purpose", "https://purpose.example.test/eligibility")
            .json(&json!({
                "target": person_target("person-1"),
                "claims": ["farmer-under-4ha"],
                "disclosure": "predicate"
            }))
            .await;
        cel_response.assert_status_ok();
        let cel_body: Value = cel_response.json();
        assert_eq!(cel_body["results"][0]["value"], json!(true));
        assert_eq!(
            cel_body["results"][0]["provenance"]["used"]["source_count"],
            json!(1)
        );
    }

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    let envelopes = audit_envelopes(&audit_path);
    assert!(envelopes
        .iter()
        .any(|envelope| envelope.record.get("principal_id_hash").is_some()));
    assert!(envelopes
        .iter()
        .all(|envelope| envelope.record.get("principal_id").is_none()));
    assert!(audit.contains("\"decision\":\"evaluate\""));
    assert!(audit.contains("\"claim_hash\":\"sha256:"));
    assert!(!audit.contains("api-token"));
    assert!(!audit.contains("source-token"));
    assert!(!audit.contains("person-1"));
    assert!(!envelopes
        .iter()
        .any(|envelope| audit_record_contains_text(&envelope.record, "3.5")));

    let metrics = server
        .get("/metrics")
        .add_header("x-api-key", "metrics-token")
        .await;
    metrics.assert_status_ok();
    let metrics_body = metrics.text();
    assert!(metrics_body.contains("registry_notary_http_requests_total"));
    assert!(metrics_body.contains(
        "registry_notary_http_requests_total{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"200\",status_class=\"2xx\",error_code=\"none\"}"
    ));
    assert!(metrics_body.contains("# TYPE registry_notary_http_request_duration_seconds histogram"));
    assert!(metrics_body.contains(
        "registry_notary_http_request_duration_seconds_bucket{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"200\",status_class=\"2xx\",error_code=\"none\",le=\"+Inf\"}"
    ));
    assert!(metrics_body.contains(
        "registry_notary_http_request_duration_seconds_sum{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"200\",status_class=\"2xx\",error_code=\"none\"}"
    ));
    assert!(metrics_body.contains(
        "registry_notary_http_request_duration_seconds_count{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"200\",status_class=\"2xx\",error_code=\"none\"}"
    ));
    assert!(!metrics_body.contains("registry_notary_http_request_duration_ms_total"));
    assert!(!metrics_body.contains("route="));
    assert!(metrics_body
        .contains("registry_notary_source_requests_total{connector=\"rda\",outcome=\"success\"}"));
    assert!(metrics_body.contains("registry_notary_audit_events_total{outcome=\"success\"}"));
    #[cfg(feature = "registry-notary-cel")]
    {
        assert!(
            metrics_body.contains("registry_notary_cel_evaluations_total{outcome=\"success\"} 1")
        );
        assert!(metrics_body.contains("registry_notary_cel_worker_pool{state=\"max\"}"));
        assert!(metrics_body.contains("registry_notary_cel_worker_pool{state=\"idle\"}"));
        assert!(metrics_body.contains("registry_notary_cel_worker_pool{state=\"in_flight\"}"));
        assert!(
            metrics_body.contains("registry_notary_cel_worker_pool{state=\"replacements_total\"}")
        );
        assert!(metrics_body.contains("registry_notary_cel_worker_pool{state=\"circuit_open\"}"));
    }
    assert!(!metrics_body.contains("api-token"));
    assert!(!metrics_body.contains("source-token"));
    assert!(!metrics_body.contains("person-1"));
    assert!(!metrics_body.contains("3.5"));
    assert!(!metrics_body.contains("farmed-land-size"));
    assert!(!metrics_body.contains("farmer-under-4ha"));
    assert!(!metrics_body.contains("purpose.example.test"));
    assert!(!metrics_body.contains(base_url.trim_end_matches('/')));
}

#[tokio::test]
pub(crate) async fn batch_evaluation_audit_records_per_item_target_model_context() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(registry_data_api_target_identifier_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "items": [
                { "target": person_identifier_target("national_id", "person-1") },
                { "target": person_identifier_target("national_id", "person-404") }
            ],
            "claims": ["farmed-land-size"],
            "disclosure": "value"
        }))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["summary"]["succeeded"], json!(1));
    assert_eq!(body["summary"]["failed"], json!(1));
    assert_eq!(
        body["items"][1]["errors"][0]["code"],
        json!("evidence.not_available")
    );

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(!audit.contains("person-1"));
    assert!(!audit.contains("person-404"));
    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    let batch_audit = records
        .iter()
        .find(|record| {
            record["path"] == json!("/v1/batch-evaluations")
                && record["decision"] == json!("batch_evaluate")
                && record["status"] == json!(200)
        })
        .expect("batch evaluation audit record exists");
    let items = batch_audit["batch_items"]
        .as_array()
        .expect("batch audit includes per-item metadata");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["input_index"], json!(0));
    assert_eq!(items[0]["target_type"], json!("Person"));
    assert!(items[0]["target_ref_hash"].as_str().is_some());
    assert_eq!(items[0]["matching_outcome"], json!("matched"));
    assert_eq!(
        items[0]["matching_policy_id"],
        json!("http-target-identifier-v1")
    );
    assert_eq!(items[0]["matching_method"], json!("exact_identifier"));
    assert_eq!(items[1]["input_index"], json!(1));
    assert_eq!(items[1]["matching_outcome"], json!("error"));
    assert_eq!(items[1]["matching_error_code"], json!("target.not_found"));
    assert!(items[1].get("target_ref_hash").is_none());
}

#[tokio::test]
pub(crate) async fn audit_chain_bootstraps_from_sink_tail() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );

    let first = TestServer::builder()
        .http_transport()
        .build(standalone_router(config.clone()).expect("first router builds"));
    first
        .get("/v1/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // A restart releases the single-writer audit lock: the first instance must
    // be fully torn down before the replacement acquires the lock (#211).
    drop(first);
    tokio::task::yield_now().await;

    let second = TestServer::builder()
        .http_transport()
        .build(standalone_router(config).expect("second router builds"));
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
pub(crate) async fn audit_chain_detects_inserted_envelope() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let first = TestServer::builder()
        .http_transport()
        .build(standalone_router(config.clone()).expect("first router builds"));
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

    let second = TestServer::builder()
        .http_transport()
        .build(standalone_router(config).expect("second router builds"));
    let response = second
        .get("/v1/claims")
        .add_header("x-api-key", "api-token")
        .await;

    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("audit.write_failed"));
}
