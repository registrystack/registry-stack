// SPDX-License-Identifier: Apache-2.0

use super::support::*;
#[allow(unused_imports)]
use super::{
    admin::*, audit::*, auth::*, credentials::*, federation::*, http_contracts::*, oid4vci::*,
    preauth::*,
};

#[test]
#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_worker_config_rejects_missing_command_without_path_leak() {
    let worker = CelWorker::lazy(CelWorkerConfig {
        command: "/registry-notary-test/missing-cel-worker".into(),
        ..CelWorkerConfig::for_current_exe_subcommand()
    });
    let error = worker
        .validate_config()
        .expect_err("worker rejects missing command path");

    let text = error.to_string();
    assert!(!text.contains("missing-cel-worker"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn standalone_startup_rejects_cel_expression_compile_error() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let bad_expression = "claims.farmed_land_size.value <";
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmer-under-4ha")
        .expect("CEL claim exists");
    let registry_notary_core::RuleConfig::Cel { expression, .. } = &mut claim.rule else {
        panic!("expected CEL claim");
    };
    *expression = bad_expression.to_string();

    let error = standalone_router(config).expect_err("router rejects invalid CEL expression");
    let text = error.to_string();
    assert!(text.contains("invalid CEL"));
    assert!(!text.contains(bad_expression));
    assert!(!text.contains("source-token"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn standalone_startup_rejects_cel_unknown_root_reference() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmer-under-4ha")
        .expect("CEL claim exists");
    let registry_notary_core::RuleConfig::Cel { expression, .. } = &mut claim.rule else {
        panic!("expected CEL claim");
    };
    *expression = "credential.level == 'gold'".to_string();

    let error = standalone_router(config).expect_err("router rejects unsupported CEL root");
    let text = error.to_string();
    assert!(text.contains("invalid CEL"));
    assert!(!text.contains("credential.level"));
    assert!(!text.contains("source-token"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn standalone_startup_rejects_disabled_cel_mode_when_claims_use_cel() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.cel.mode = "disabled".to_string();

    let error = standalone_router(config).expect_err("router rejects disabled CEL mode");
    let text = error.to_string();
    assert!(text.contains("CEL claims require cel.mode = worker"));
    assert!(!text.contains("source-token"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn standalone_startup_rejects_cel_regex_helpers_by_default() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let bad_expression = "text.regex_replace(source.farmer.total_farmed_area, '^3', '4') == '4.5'";
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmer-under-4ha")
        .expect("CEL claim exists");
    let registry_notary_core::RuleConfig::Cel { expression, .. } = &mut claim.rule else {
        panic!("expected CEL claim");
    };
    *expression = bad_expression.to_string();

    let error = standalone_router(config).expect_err("router rejects regex helper");
    let text = error.to_string();
    assert!(text.contains("invalid CEL"));
    assert!(!text.contains("text.regex_replace"));
    assert!(!text.contains("source-token"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn standalone_server_reads_dci_source_and_evaluates_cel_claim() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let observed = Arc::new(Mutex::new(None));
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/dci/fr/registry/sync/search", post(dci_source))
            .with_state(Arc::clone(&observed)),
    );
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(dci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

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

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(true));
    assert_eq!(
        body["results"][0]["provenance"]["used"]["source_count"],
        json!(1)
    );

    let observed = observed
        .lock()
        .expect("observed request lock")
        .clone()
        .expect("DCI request captured");
    assert_eq!(observed["header"]["action"], "search");
    assert_eq!(observed["header"]["receiver_id"], "upstream-registry");
    assert_eq!(observed["signature"], "");
    assert_eq!(
        observed["message"]["search_request"][0]["search_criteria"]["query_type"],
        "idtype-value"
    );
    assert_eq!(
        observed["message"]["search_request"][0]["search_criteria"]["reg_event_type"],
        "birth"
    );
    assert_eq!(
        observed["message"]["search_request"][0]["search_criteria"]["pagination"]["page_number"],
        1
    );
    assert_eq!(
        observed["message"]["search_request"][0]["search_criteria"]["query"]["type"],
        "id"
    );
    assert_eq!(
        observed["message"]["search_request"][0]["search_criteria"]["query"]["value"],
        "person-1"
    );
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn standalone_server_uses_dci_response_timestamp_for_source_freshness() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let observed = Arc::new(Mutex::new(None));
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/dci/fr/registry/sync/search", post(dci_source))
            .with_state(Arc::clone(&observed)),
    );
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let mut config = dci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let connection = config
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer registry source exists");
    connection.dci.field_paths.insert(
        "observed_at".to_string(),
        "$response:/message/search_response/0/timestamp".to_string(),
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
    binding.matching.max_source_age_seconds = Some(60);
    binding.matching.source_observed_at_field = Some("observed_at".to_string());

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

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(3.5));
    assert_eq!(
        body["results"][0]["provenance"]["used"]["source_count"],
        json!(1)
    );

    for target_id in ["stale-person", "missing-timestamp"] {
        let response = server
            .post("/v1/evaluations")
            .add_header("x-api-key", "api-token")
            .add_header("data-purpose", "https://purpose.example.test/eligibility")
            .json(&json!({
                "target": person_target(target_id),
                "claims": ["farmed-land-size"],
                "disclosure": "value"
            }))
            .await;

        response.assert_status(StatusCode::FORBIDDEN);
        let body: Value = response.json();
        assert_eq!(body["code"], json!("pdp.evidence_stale"));
    }
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn standalone_server_reads_dci_source_by_demographic_target_attributes() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let observed = Arc::new(Mutex::new(None));
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/dci/fr/registry/sync/search",
                post(civil_demographic_dci_source),
            )
            .with_state(Arc::clone(&observed)),
    );
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(civil_demographic_dci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": {
                "type": "Person",
                "attributes": {
                    "given_name": "Miguel",
                    "surname": "Santos",
                    "birth_date": "2016-01-15"
                }
            },
            "claims": ["civil-person-is-alive-by-demographics"],
            "disclosure": "predicate"
        }))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(true));
    assert_eq!(
        body["results"][0]["provenance"]["used"]["source_count"],
        json!(1)
    );

    let observed = observed
        .lock()
        .expect("observed request lock")
        .clone()
        .expect("DCI request captured");
    let criteria = &observed["message"]["search_request"][0]["search_criteria"];
    assert_eq!(criteria["query_type"], json!("predicate"));
    assert_eq!(criteria["reg_event_type"], json!("birth"));
    let query = criteria["query"]
        .as_array()
        .expect("predicate query is an array of expressions");
    assert_eq!(
        query[0]["expression1"]["attribute_name"],
        json!("given_name")
    );
    assert_eq!(query[0]["expression1"]["operator"], json!("eq"));
    assert_eq!(query[0]["expression1"]["attribute_value"], json!("Miguel"));
    assert_eq!(query[1]["expression2"]["attribute_name"], json!("surname"));
    assert_eq!(query[1]["expression2"]["attribute_value"], json!("Santos"));
    assert_eq!(
        query[2]["expression3"]["attribute_name"],
        json!("birth_date")
    );
    assert_eq!(
        query[2]["expression3"]["attribute_value"],
        json!("2016-01-15")
    );
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn standalone_server_rejects_cel_result_type_mismatch() {
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
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmer-under-4ha")
        .expect("CEL claim exists");
    let registry_notary_core::RuleConfig::Cel { expression, .. } = &mut claim.rule else {
        panic!("expected CEL claim");
    };
    *expression = "claims.farmed_land_size.value > 3.0 ? 'bad-type' : true".to_string();

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
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

    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("claim.rule_evaluation_failed"));
    assert!(body["results"].is_null());
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn standalone_server_maps_dci_register_not_found_to_source_not_found() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/dci/fr/registry/sync/search", post(dci_source))
            .with_state(Arc::new(Mutex::new(None))),
    );
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(dci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("openspp-missing"),
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("evidence.not_available"));
}

#[tokio::test]
pub(super) async fn standalone_server_extract_claim_works_without_default_features() {
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

    let app = standalone_router(no_cel_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
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

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(3.5));
}

#[cfg(not(feature = "registry-notary-cel"))]
#[tokio::test]
pub(super) async fn standalone_server_rejects_cel_claim_without_cel_feature() {
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
    let app = standalone_router(registry_data_api_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("person-1"),
            "claims": ["farmer-under-4ha"],
            "disclosure": "redacted"
        }))
        .await;

    response.assert_status(StatusCode::NOT_IMPLEMENTED);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("claim.operation_unsupported"));
}

#[test]
pub(super) fn standalone_router_rejects_unknown_audit_sink() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.audit.sink = "bogus".to_string();

    let error = standalone_router(config).expect_err("unknown audit sink is rejected");
    assert!(matches!(
        error,
        StandaloneServerError::InvalidAuditSink(sink) if sink == "bogus"
    ));
}

#[test]
pub(super) fn standalone_router_rejects_missing_redis_replay_url_env() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::remove_var("TEST_REPLAY_REDIS_URL_MISSING");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.replay = serde_norway::from_str(
        r#"
storage: redis
redis:
  url_env: TEST_REPLAY_REDIS_URL_MISSING
  key_prefix: registry-notary-test
  connect_timeout_ms: 1
  operation_timeout_ms: 1
"#,
    )
    .expect("redis replay config parses");

    let error = standalone_router(config).expect_err("missing redis URL env is rejected");
    assert!(
        error.to_string().contains("TEST_REPLAY_REDIS_URL_MISSING"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
pub(super) async fn ready_fails_closed_when_redis_replay_store_is_unavailable() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_REPLAY_REDIS_URL_UNAVAILABLE", "redis://127.0.0.1:1/");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.replay = serde_norway::from_str(
        r#"
storage: redis
redis:
  url_env: TEST_REPLAY_REDIS_URL_UNAVAILABLE
  key_prefix: registry-notary-test
  connect_timeout_ms: 10
  operation_timeout_ms: 10
"#,
    )
    .expect("redis replay config parses");

    let app = standalone_router(config).expect("router builds without opening Redis eagerly");
    let server = TestServer::builder().http_transport().build(app);

    let ready = server.get("/ready").await;

    ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
pub(super) async fn ready_accepts_available_redis_replay_store_when_env_is_set() {
    let Ok(redis_url) = std::env::var("REGISTRY_NOTARY_REDIS_TEST_URL") else {
        return;
    };
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_REPLAY_REDIS_URL_AVAILABLE", redis_url);

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.replay = serde_norway::from_str(
        r#"
storage: redis
redis:
  url_env: TEST_REPLAY_REDIS_URL_AVAILABLE
  key_prefix: registry-notary-live-test
  connect_timeout_ms: 500
  operation_timeout_ms: 500
"#,
    )
    .expect("redis replay config parses");

    let app = standalone_router(config).expect("router builds without opening Redis eagerly");
    let server = TestServer::builder().http_transport().build(app);

    let ready = server.get("/ready").await;

    ready.assert_status_ok();
}

#[test]
pub(super) fn audit_hasher_from_env_returns_err_when_unset() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::remove_var("TEST_UNSET_REGISTRY_NOTARY_AUDIT_HASH_SECRET");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.audit.hash_secret_env = Some("TEST_UNSET_REGISTRY_NOTARY_AUDIT_HASH_SECRET".to_string());

    let error = standalone_router(config).expect_err("unset audit hash secret fails closed");

    assert!(matches!(error, StandaloneServerError::Audit(_)));
    assert!(error
        .to_string()
        .contains("TEST_UNSET_REGISTRY_NOTARY_AUDIT_HASH_SECRET"));
}

#[test]
pub(super) fn audit_hash_secret_env_is_required_for_runtime_config() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.audit.hash_secret_env = None;

    let error = standalone_router(config).expect_err("missing audit hash secret fails closed");

    assert!(matches!(
        error,
        StandaloneServerError::MissingAuditHashSecretEnv
    ));
}

// ---------------------------------------------------------------------------
// Pre-authorized-code flow (PR3): offer/start, offer/callback, token endpoint,
// the second trust anchor, abuse controls, and audit redaction.
// ---------------------------------------------------------------------------

// Dedicated access-token signing key, distinct from the credential key
// (TEST_ISSUER_JWK). Config validation rejects reusing a credential key.
pub(super) const TEST_ACCESS_TOKEN_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"8jFBgUJxaaQimd4NjzxhvPYyNbcOnnZsqOntZbpP3Xk","x":"XvW-aWwJCWSYoYudTB9OZqNHURKElnnyGNa6DQNjzZk","alg":"EdDSA"}"#;
// eSignet RP client signing key (signs the private_key_jwt client assertion).
pub(super) const TEST_ESIGNET_RP_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"EOLPz23yGd5Ju5e-PYybLE-YyvjgXLhGzS6XgmszzXs","x":"3v5jZ5rAf7KGvcC3zuKh6-ujgtA0ABa4jqmAWXq-S_c","alg":"EdDSA"}"#;
// Test-only 2048-bit RSA private JWK (kty=RSA, alg=RS256) for the eSignet RP
// client when the lab registers the Notary's RP client with an RSA key.
// Generated once with openssl and converted to a JWK; not a production key.
#[cfg(feature = "registry-notary-cel")]
pub(super) const TEST_ESIGNET_RP_RSA_JWK: &str = r#"{"kty":"RSA","kid":"did:web:rp.example#esignet-rp-rsa-key","alg":"RS256","n":"uujuLM_PhTFXueBzTafeFW7O4kJgQnLIzuoHJQgaYDkCBbUYAznt-IZvGkyTTkg4mfolJj47HDlBsSNzzx7bYcFDKdBMoZQwukVX9bhkXVUPT9-fot1jfW0EPrvdJdDQ-5LjQYfk2a2OpKtV5hmBIxoHm_JRU3QOmKU0h1_vKjwStMO0ntaitIL7pSIE0X7Ht4P3edhBc5Vxf_-Ui7wSaN-jAjHCk6HYRY4BTODI-zo5K8yB5JERBqcawsuAIDPTjQ1eIOHxIQsTlsdbmSgqnMldoyZAkjxCyOm9Ad_rpbJ04WDaIhFxyaqHTVUD32cufcZFYxkSJ35zuIlJYgoebw","e":"AQAB","d":"EEvSyFFuFHzS2z_4jaK_ODsrCosi_WgonfHFobLtKcqOpJS_fTiFyQ9fjHl0tnSRistGhekTGkjbs2gV5s8X7ZP-GR0yMTxMa1E0dBYZmhGafipPLtICpKLmpdmXVH66WdTav5HroBcDwtO1b5R1r-vLEgu0j4Qk6aYtyEfTAGmKRzH9fk7crZwaM2MiklIWLaK6Gfior5KDrQhIMGfKZzu78naJ5FyFSHBUW0VvikTg0C8QbRgBuFbQCuOceu4UZhjySJUhugdgzlbnteVRc_VvSvusLL4i7fSeecRIXURSexUjraLifeh1lM_jrD8ZM-o_2Qop2ada12Asll4gkQ","p":"4QhhINnwbq_vuFTQL3Wx980l2eg8yocFS5hsmk7vbqAUbAZVSVOGW_y6ip-uG_c9xpYBvTyZAANUZHpqDyu0frPDdZplJZX2FTMkiHTg4RJQfj8OD0tmL370cGv3RRfO4md4-0E0wxl8Zsv4-PSVrMZCFyIk8TLgLZs1w7bpg0U","q":"1KGH6VP7TkA3hDXTlSL2GPShsGY0Y9P1Kn6mMA8aHIZ690QmeJU2j91oWcCP1AG6LnAp5pvxT0XJJu3OVsQs7OZPiUwAf_RoSdlMtm6xll1FkBKC3AtTLYn0vgHwFPeXa29wZM1khFv_vBdhk47ZgZT0G3f4Y88FHh5EM5EFPCM","dp":"0D332_WyWEu5c4QQ74pjuaP_XgpajzSpgs432ggn6-B5ZYnqzKNdl6xlV7jy3vBKG4Zfb6YvE-MA6saZdRaFviZOP3s0FLcUdYPRT_GQ1Nck498n_KFSm6tJOuu-dBLXIY6NVz19PPpNs7cX3BJCnBMPv-aZ9xaUe7_A3i9bIl0","dq":"gDDudp5aGSAgGEY3TGdqhTsfK_FCTpkf6sG2Qa0pKd9tzRs6MmKLJYrveYTdcYylCZA3wr9raUaCckTWrHrTNvPXKcg3WO0p3rPySt5LlIKhCK4QVMdDG2Zbth4G9y0aDfx-f1dQ7Xdlo6lY-5QYz8XUsabPiqTpyfGnXotk448","qi":"XlLiaiQDLYZXtyR1ixq3dJ1EqnBtHtx75VjpQydmb4yQMtzsQ1JS5xyRgv1gws8u5KVaF3h3CUo6wBrtKBFGIhL9WFnym_8DEECgVF7eLHZ6WNtnIv6Vs7vjO3CAPKG3TrIuaHhY5KXQf0za7criZ9Euai41_ky9_iU6j0Lw5CY"}"#;

pub(super) const NOTARY_ISSUER: &str = "http://127.0.0.1:4325";
pub(super) const NOTARY_AUDIENCE: &str = "registry-notary-citizen";
pub(super) const ESIGNET_RP_CLIENT_ID: &str = "registry-lab-live-client";

pub(super) fn set_preauth_env() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);
    std::env::set_var("TEST_ACCESS_TOKEN_JWK", TEST_ACCESS_TOKEN_JWK);
    std::env::set_var("TEST_ESIGNET_RP_JWK", TEST_ESIGNET_RP_JWK);
}

pub(super) fn local_jwk_signing_key(private_jwk_env: &str, kid: &str) -> SigningKeyConfig {
    SigningKeyConfig {
        provider: SigningKeyProviderConfig::LocalJwkEnv,
        alg: SD_JWT_VC_SIGNING_ALG.to_string(),
        kid: kid.to_string(),
        status: SigningKeyStatus::Active,
        publish_until_unix_seconds: None,
        private_jwk_env: private_jwk_env.to_string(),
        public_jwk_env: String::new(),
        module_path: String::new(),
        token_label: String::new(),
        pin_env: String::new(),
        key_label: String::new(),
        key_id_hex: String::new(),
        path: String::new(),
        password_env: String::new(),
    }
}

/// A pre-auth-enabled config. eSignet `issuer`/`jwks_uri` point at the MockIdp;
/// the token endpoint points at `token_url` (a wiremock upstream). The
/// access-token signing key is dedicated (distinct from the credential key).
pub(super) fn self_attestation_preauth_config(
    base_url: &str,
    audit_path: &str,
    esignet_issuer: &str,
    esignet_jwks_uri: &str,
    esignet_authorize_url: &str,
    esignet_token_url: &str,
) -> StandaloneRegistryNotaryConfig {
    // Reuse the eSignet issuer/jwks as the primary OIDC auth issuer so the
    // credential endpoint still accepts eSignet tokens on the unchanged path.
    let mut config =
        self_attestation_oid4vci_config(base_url, audit_path, esignet_issuer, esignet_jwks_uri);
    // The credential endpoint must be allowed to issue credentials for the
    // pre-auth happy path.
    config.self_attestation.allowed_operations.issue_credential = true;
    // The person-is-alive claim must support the SD-JWT VC format for OID4VCI
    // issuance (the base config only lists the claim-result format).
    for claim in config.evidence.claims.iter_mut() {
        if claim.id == "person-is-alive" {
            claim
                .formats
                .push(registry_notary_core::FORMAT_SD_JWT_VC.to_string());
        }
    }
    config
        .self_attestation
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 3;
    config
        .self_attestation
        .rate_limits
        .invalid_token_per_client_address_per_minute = 50;
    // The Notary RP client id must be an accepted citizen client + audience so a
    // Notary-minted token classifies as self-attestation.
    config
        .self_attestation
        .citizen_clients
        .allowed_client_ids
        .push(ESIGNET_RP_CLIENT_ID.to_string());
    config
        .oid4vci
        .accepted_token_audiences
        .push(NOTARY_AUDIENCE.to_string());
    if let Some(oidc) = config.auth.oidc.as_mut() {
        oidc.allowed_clients.push(ESIGNET_RP_CLIENT_ID.to_string());
    }

    // Dedicated access-token signing key.
    config.evidence.signing_keys.insert(
        "access-token-key".to_string(),
        local_jwk_signing_key(
            "TEST_ACCESS_TOKEN_JWK",
            "did:web:issuer.example#access-token-key",
        ),
    );
    // eSignet RP client signing key.
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        local_jwk_signing_key("TEST_ESIGNET_RP_JWK", "did:web:rp.example#esignet-rp-key"),
    );

    config.auth.access_token_signing = serde_norway::from_str(&format!(
        r#"
enabled: true
issuer: {NOTARY_ISSUER}
audiences:
  - {NOTARY_AUDIENCE}
allowed_algorithms:
  - EdDSA
token_typ: registry-notary-access+jwt
signing_key_id: access-token-key
access_token_ttl_seconds: 300
"#
    ))
    .expect("access-token signing config parses");

    config.oid4vci.pre_authorized_code = serde_norway::from_str(&format!(
        r#"
enabled: true
tx_code:
  required: true
  input_mode: numeric
  length: 6
esignet:
  client_id: {ESIGNET_RP_CLIENT_ID}
  client_signing_key_id: esignet-rp-key
  redirect_uri: http://127.0.0.1:4325/oid4vci/offer/callback
  authorize_url: {esignet_authorize_url}
  token_url: {esignet_token_url}
  issuer: {esignet_issuer}
  jwks_uri: {esignet_jwks_uri}
  scopes:
    - openid
  login_state_ttl_seconds: 300
  allow_insecure_localhost: true
pre_authorized_code_ttl_seconds: 300
"#
    ))
    .expect("pre-auth config parses");
    config
}

/// Extract a query parameter from a URL.
pub(super) fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

pub(super) fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Mint an eSignet id_token bound to the login nonce, with the civil-id claim.
pub(super) fn esignet_id_token(idp: &MockIdp, nonce: &str, national_id: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    idp.mint_token(json!({
        "sub": "esignet-citizen-subject",
        "aud": ESIGNET_RP_CLIENT_ID,
        "nonce": nonce,
        "national_id": national_id,
        "scope": "openid self_attestation",
        "acr": "urn:example:loa:substantial",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }))
}

pub(super) struct PreauthOfferPage {
    pub(super) code: String,
    pub(super) pin: Option<String>,
    pub(super) offer: Value,
    pub(super) html: String,
}

/// Drive offer/start + offer/callback, returning the rendered offer details.
pub(super) async fn drive_offer_to_page(
    server: &TestServer,
    token_upstream: &MockHttpUpstream,
    idp: &MockIdp,
    national_id: &str,
) -> PreauthOfferPage {
    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    start.assert_status(StatusCode::SEE_OTHER);
    let location = start
        .headers()
        .get("location")
        .expect("offer start redirects")
        .to_str()
        .expect("location is valid")
        .to_string();
    let state = query_param(&location, "state").expect("redirect carries state");
    let nonce = query_param(&location, "nonce").expect("redirect carries nonce");

    let id_token = esignet_id_token(idp, &nonce, national_id);
    token_upstream
        .expect("POST", "/token")
        .respond_json(
            200,
            json!({
                "access_token": "esignet-access-token",
                "token_type": "Bearer",
                "id_token": id_token,
                "expires_in": 300,
            }),
        )
        .await;

    let callback = server
        .get(&format!(
            "/oid4vci/offer/callback?code=esignet-code-123&state={state}"
        ))
        .await;
    callback.assert_status_ok();
    let html = callback.text();
    let offer_uri = extract_between(&html, "href=\"", "\"").expect("offer href present");
    let offer_json =
        query_param(&offer_uri, "credential_offer").expect("offer carries credential_offer");
    let offer: Value = serde_json::from_str(&offer_json).expect("offer is JSON");
    let code = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        ["pre-authorized_code"]
        .as_str()
        .expect("offer carries pre-authorized_code")
        .to_string();
    let pin = extract_between(&html, "id=\"tx-code\">", "<");
    PreauthOfferPage {
        code,
        pin,
        offer,
        html,
    }
}

/// Drive offer/start + offer/callback, returning (pre_authorized_code, tx_code).
pub(super) async fn drive_offer_to_code(
    server: &TestServer,
    token_upstream: &MockHttpUpstream,
    idp: &MockIdp,
    national_id: &str,
) -> (String, String) {
    let page = drive_offer_to_page(server, token_upstream, idp, national_id).await;
    let pin = page.pin.expect("offer page shows PIN");
    (page.code, pin)
}

pub(super) fn extract_between(haystack: &str, start: &str, end: &str) -> Option<String> {
    let after = haystack.split_once(start)?.1;
    let value = after.split_once(end)?.0;
    Some(value.to_string())
}

pub(super) async fn redeem_token(
    server: &TestServer,
    code: &str,
    pin: &str,
) -> axum_test::TestResponse {
    server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text(format!(
            "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code={}&tx_code={}",
            urlencode(code),
            urlencode(pin),
        ))
        .await
}

pub(super) async fn redeem_token_without_pin(
    server: &TestServer,
    code: &str,
) -> axum_test::TestResponse {
    server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text(format!(
            "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code={}",
            urlencode(code)
        ))
        .await
}

pub(super) fn urlencode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Decode (without verifying) the JSON claims of a compact JWT's payload.
pub(super) fn jwt_payload(jwt: &str) -> Value {
    let payload_b64 = jwt.split('.').nth(1).expect("jwt has a payload segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("payload is base64url");
    serde_json::from_slice(&bytes).expect("payload is JSON")
}

/// Decode (without verifying) the JOSE header of a compact JWT.
#[cfg(feature = "registry-notary-cel")]
pub(super) fn jwt_header(jwt: &str) -> Value {
    let header_b64 = jwt.split('.').next().expect("jwt has a header segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .expect("header is base64url");
    serde_json::from_slice(&bytes).expect("header is JSON")
}

/// Extract a field from an `application/x-www-form-urlencoded` body.
#[cfg(feature = "registry-notary-cel")]
pub(super) fn form_field(body: &str, name: &str) -> Option<String> {
    for pair in body.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}
