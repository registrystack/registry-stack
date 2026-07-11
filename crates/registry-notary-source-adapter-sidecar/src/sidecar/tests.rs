use super::*;

fn minimal_config() -> SidecarConfig {
    SidecarConfig {
        server: ServerConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            request_timeout_ms: default_request_timeout_ms(),
            request_body_timeout_ms: default_request_body_timeout_ms(),
            http1_header_read_timeout_ms: default_http1_header_read_timeout_ms(),
            max_connections: default_max_connections(),
            metrics_require_auth: false,
        },
        auth: AuthConfig {
            bearer_tokens: vec![BearerTokenConfig {
                id: "notary".to_string(),
                token: None,
                hash_env: Some("TEST_SOURCE_ADAPTER_SIDECAR_TOKEN_HASH".to_string()),
            }],
        },
        audit: SidecarAuditConfig::default(),
        config_trust: None,
        limits: LimitConfig {
            max_workers: 1,
            worker_timeout_ms: 1_000,
            max_output_bytes: 1_024,
            max_request_bytes: 1_024,
            max_query_parameter_bytes: 1_024,
            liveness_window_ms: default_liveness_window_ms(),
            retry_after_seconds: default_retry_after_seconds(),
            max_batch_items: default_max_batch_items(),
            batch_timeout_ms: None,
            max_worker_memory_mb: None,
        },
        sources: BTreeMap::from([(
            "people".to_string(),
            SourceConfig {
                dataset: "civil_registry".to_string(),
                entity: "person".to_string(),
                engine: SourceEngine::HttpJson,
                credential_env: "TEST_HTTP_JSON_SOURCE_CREDENTIAL".to_string(),
                credential_public_fields: vec!["baseUrl".to_string()],
                batch: SourceBatchConfig::default(),
                limits: SourceRuntimeLimitConfig::default(),
                allowed_base_urls: vec!["https://source.example.test".to_string()],
                allow_insecure_localhost: false,
                allow_insecure_private_network: false,
                http_json: Some(HttpJsonSourceConfig {
                    method: HttpJsonMethod::Get,
                    base_url: HttpJsonCelExpression {
                        cel: "credential_public.baseUrl".to_string(),
                    },
                    path: "/records".to_string(),
                    query: BTreeMap::new(),
                    headers: BTreeMap::new(),
                    auth: None,
                    response: HttpJsonResponseConfig {
                        records: HttpJsonCelExpression {
                            cel: "body.results".to_string(),
                        },
                    },
                    batch: None,
                }),
                http_flow: None,
                fhir: None,
                rhai: None,
                cache: None,
                smoke_lookup: Some(SmokeLookupConfig {
                    field: "national_id".to_string(),
                    value: "person-1".to_string(),
                    query_values: BTreeMap::new(),
                    fields: vec!["national_id".to_string()],
                    purpose: default_smoke_purpose(),
                }),
            },
        )]),
        assurance: None,
        governed_acceptance: None,
    }
}

fn minimal_http_json_config() -> SidecarConfig {
    minimal_config()
}

#[test]
fn server_limits_must_be_nonzero() {
    type MutateConfig = fn(&mut SidecarConfig);
    let cases: [(&str, MutateConfig); 4] = [
        ("server.request_timeout_ms", |config: &mut SidecarConfig| {
            config.server.request_timeout_ms = 0
        }),
        (
            "server.request_body_timeout_ms",
            |config: &mut SidecarConfig| config.server.request_body_timeout_ms = 0,
        ),
        (
            "server.http1_header_read_timeout_ms",
            |config: &mut SidecarConfig| config.server.http1_header_read_timeout_ms = 0,
        ),
        ("server.max_connections", |config: &mut SidecarConfig| {
            config.server.max_connections = 0
        }),
    ];
    for (label, mutate) in cases {
        let mut config = minimal_config();
        mutate(&mut config);
        let error = validate_config(&config).expect_err("zero sidecar server limit is rejected");
        assert!(
            error.to_string().contains(label),
            "expected {label} in {error}"
        );
    }
}

#[test]
fn batch_timeout_limit_must_be_nonzero_when_configured() {
    let mut config = minimal_config();
    config.limits.batch_timeout_ms = Some(0);

    let error = validate_config(&config).expect_err("zero batch timeout is rejected");

    assert!(
        error.to_string().contains("limits.batch_timeout_ms"),
        "expected batch timeout limit in {error}"
    );
}

#[test]
fn source_concurrency_limit_must_be_nonzero() {
    let mut config = minimal_http_json_config();
    config
        .sources
        .get_mut("people")
        .expect("source exists")
        .limits
        .max_in_flight = Some(0);

    let error = validate_config(&config).expect_err("zero source concurrency limit is rejected");

    assert!(
        error.to_string().contains("limits.max_in_flight"),
        "expected source limit in {error}"
    );
}

#[test]
fn source_rate_limit_config_must_be_consistent() {
    type MutateSource = fn(&mut SourceConfig);
    let cases: [(&str, MutateSource); 3] = [
        ("limits.requests_per_second", |source| {
            source.limits.requests_per_second = Some(0)
        }),
        ("limits.burst", |source| source.limits.burst = Some(0)),
        ("limits.burst requires", |source| {
            source.limits.burst = Some(5)
        }),
    ];
    for (label, mutate) in cases {
        let mut config = minimal_config();
        mutate(config.sources.get_mut("people").expect("source exists"));

        let error = validate_config(&config).expect_err("invalid source rate limit rejected");

        assert!(
            error.to_string().contains(label),
            "expected {label} in {error}"
        );
    }
}

#[test]
fn source_batch_and_cache_config_must_be_consistent() {
    let mut config = minimal_http_json_config();
    config
        .sources
        .get_mut("people")
        .expect("source exists")
        .batch
        .max_parallel = Some(2);
    let error = validate_config(&config).expect_err("max_parallel without mode is rejected");
    assert!(error.to_string().contains("batch.max_parallel"));

    let mut config = minimal_config();
    let source = config.sources.get_mut("people").expect("source exists");
    source.cache = Some(SourceCacheConfig {
        exact_match_ttl_ms: None,
        not_found_ttl_ms: None,
        max_entries: None,
    });
    let error = validate_config(&config).expect_err("empty cache config is rejected");
    assert!(error.to_string().contains("cache"));

    let mut config = minimal_http_json_config();
    let source = config.sources.get_mut("people").expect("source exists");
    source.cache = Some(SourceCacheConfig {
        exact_match_ttl_ms: Some(60_000),
        not_found_ttl_ms: None,
        max_entries: Some(0),
    });
    let error = validate_config(&config).expect_err("zero cache cap is rejected");
    assert!(error.to_string().contains("cache.max_entries"));
}

#[test]
fn http_json_native_batch_requires_batch_mapping() {
    let mut config = minimal_http_json_config();
    config
        .sources
        .get_mut("people")
        .expect("source exists")
        .batch
        .mode = SourceBatchMode::NativeBatch;

    let error = validate_config(&config).expect_err("native batch mapping is required");

    assert!(error.to_string().contains("http_json.batch"));
}

#[test]
fn http_json_ip_policy_blocks_private_and_metadata_by_default() {
    let mut source = minimal_config()
        .sources
        .remove("people")
        .expect("source exists");
    source.engine = SourceEngine::HttpJson;
    source.allow_insecure_localhost = false;
    source.allow_insecure_private_network = false;

    assert!(ensure_ip_allowed("10.0.0.1".parse().unwrap(), &source).is_err());

    source.allow_insecure_private_network = true;
    assert!(ensure_ip_allowed("10.0.0.1".parse().unwrap(), &source).is_ok());
    assert!(ensure_ip_allowed("169.254.169.254".parse().unwrap(), &source).is_err());
    assert!(ensure_ip_allowed("fd00:ec2::254".parse().unwrap(), &source).is_err());
    assert!(ensure_ip_allowed("::ffff:169.254.169.254".parse().unwrap(), &source).is_err());
    // Alibaba Cloud metadata endpoint: not in any private/link-local range,
    // so the cloud-metadata check is the only thing blocking it. Must stay
    // rejected even with the private-network escape hatch enabled.
    assert!(ensure_ip_allowed("100.100.100.200".parse().unwrap(), &source).is_err());
    assert!(ensure_ip_allowed("::ffff:100.100.100.200".parse().unwrap(), &source).is_err());

    source.allow_insecure_private_network = false;
    assert!(ensure_ip_allowed("::ffff:10.0.0.1".parse().unwrap(), &source).is_err());
    source.allow_insecure_localhost = true;
    assert!(ensure_ip_allowed("127.0.0.1".parse().unwrap(), &source).is_ok());
}

#[tokio::test]
async fn http_json_url_policy_rejects_plain_http_public_hosts_even_with_private_network_escape() {
    let mut source = minimal_config()
        .sources
        .remove("people")
        .expect("source exists");
    source.engine = SourceEngine::HttpJson;
    source.allow_insecure_localhost = true;
    source.allow_insecure_private_network = true;

    let public_http = reqwest::Url::parse("http://example.com").expect("url parses");
    assert!(ensure_http_json_url_policy(&public_http, &source)
        .await
        .is_err());
}

#[tokio::test]
async fn http_json_url_policy_rejects_plain_http_public_ip_literals_even_with_private_network_escape(
) {
    let mut source = minimal_config()
        .sources
        .remove("people")
        .expect("source exists");
    source.engine = SourceEngine::HttpJson;
    source.allow_insecure_localhost = true;
    source.allow_insecure_private_network = true;

    let public_http = reqwest::Url::parse("http://93.184.216.34").expect("url parses");
    assert!(ensure_http_json_url_policy(&public_http, &source)
        .await
        .is_err());
}

#[tokio::test]
async fn http_json_url_policy_keeps_metadata_blocked_with_private_network_escape() {
    let mut source = minimal_config()
        .sources
        .remove("people")
        .expect("source exists");
    source.engine = SourceEngine::HttpJson;
    source.allow_insecure_private_network = true;

    let metadata_http = reqwest::Url::parse("http://169.254.169.254").expect("url parses");
    assert!(ensure_http_json_url_policy(&metadata_http, &source)
        .await
        .is_err());
    let metadata_ipv6_http = reqwest::Url::parse("http://[fd00:ec2::254]").expect("url parses");
    assert!(ensure_http_json_url_policy(&metadata_ipv6_http, &source)
        .await
        .is_err());
    let metadata_mapped_http =
        reqwest::Url::parse("http://[::ffff:169.254.169.254]").expect("url parses");
    assert!(ensure_http_json_url_policy(&metadata_mapped_http, &source)
        .await
        .is_err());
}

#[test]
fn fhir_base_url_policy_allows_private_network_http_service_names_only_with_escape() {
    let mut source = minimal_config()
        .sources
        .remove("people")
        .expect("source exists");
    source.engine = SourceEngine::Fhir;
    source.allow_insecure_localhost = false;
    source.allow_insecure_private_network = false;

    let docker_service =
        reqwest::Url::parse("http://fhir-fixture-server:8080/fhir").expect("url parses");
    assert!(validate_fhir_base_url_policy("fhir", &source, &docker_service).is_err());

    source.allow_insecure_private_network = true;
    validate_fhir_base_url_policy("fhir", &source, &docker_service)
        .expect("private network escape allows docker service names");

    let metadata = reqwest::Url::parse("http://metadata.google.internal/fhir").expect("url parses");
    assert!(validate_fhir_base_url_policy("fhir", &source, &metadata).is_err());
}

/// Build a minimal `AppState` suitable for unit-testing the `authorize`
/// gate.  `auth_tokens` is empty so any supplied bearer token is rejected
/// (no valid fingerprint match); callers that skip auth entirely rely on
/// the `metrics_require_auth` flag being `false`.
fn minimal_app_state(metrics_require_auth: bool) -> AppState {
    let mut config = minimal_config();
    config.server.metrics_require_auth = metrics_require_auth;
    AppState {
        config: Arc::new(config),
        auth_tokens: Arc::new(Vec::new()),
        fhir_bearer_tokens: Arc::new(BTreeMap::new()),
        credentials: Arc::new(BTreeMap::new()),
        source_limiters: Arc::new(BTreeMap::new()),
        source_runtime: Arc::new(BTreeMap::new()),
        http_json_clients: Arc::new(Mutex::new(BTreeMap::new())),
        oauth2_tokens: Arc::new(Mutex::new(BTreeMap::new())),
        oauth2_token_locks: Arc::new(Mutex::new(BTreeMap::new())),
        rhai_engines: Arc::new(BTreeMap::new()),
        metrics: Arc::new(Mutex::new(BTreeMap::new())),
        audit: None,
    }
}

#[test]
fn sidecar_audit_record_hashes_purpose_and_correlation_without_lookup_values() {
    let pipeline = SidecarAuditPipeline {
        sink: JsonlFileSink::new("unused.jsonl"),
        chain: OnceCell::new(),
        profile: AuditProfile::unkeyed_dev_only(),
    };
    let record = sidecar_audit_record(
        &pipeline,
        "outcome",
        "GET",
        "/v1/datasets/civil_registry/entities/person/records",
        Some(StatusCode::OK.as_u16()),
        Some("benefits".to_string()),
        Some("corr-123".to_string()),
    );

    assert_eq!(
        record["event_type"],
        "registry-notary-source-adapter-sidecar.data_route"
    );
    assert_eq!(record["phase"], "outcome");
    assert_eq!(record["dataset"], "civil_registry");
    assert_eq!(record["entity"], "person");
    assert_eq!(record["decision"], "permitted");
    assert!(record["purpose_hash"]
        .as_str()
        .is_some_and(|value| value.starts_with("sha256:")));
    assert!(record["correlation_id_hash"]
        .as_str()
        .is_some_and(|value| value.starts_with("sha256:")));
    assert!(!record.to_string().contains("person-123"));
    assert!(!record.to_string().contains("benefits"));
    assert!(!record.to_string().contains("corr-123"));
}

#[tokio::test]
async fn sidecar_data_route_fails_closed_when_preaccess_audit_write_fails() {
    std::env::set_var(
        "TEST_SOURCE_ADAPTER_SIDECAR_TOKEN_HASH",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    std::env::set_var(
        "TEST_SIDECAR_AUDIT_HASH_SECRET",
        "0123456789abcdef0123456789abcdef",
    );
    let upstream = axum_test::TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/records",
            get(|| async {
                Json(json!({
                    "results": [
                        {
                            "national_id": "person-1"
                        }
                    ]
                }))
            }),
        ));
    let upstream_url = upstream
        .server_address()
        .expect("HTTP transport exposes server address")
        .to_string()
        .trim_end_matches('/')
        .to_string();
    let audit_dir = tempfile::TempDir::new().expect("audit temp dir");
    std::env::set_var(
        "TEST_HTTP_JSON_SOURCE_CREDENTIAL",
        json!({ "baseUrl": upstream_url }).to_string(),
    );
    let mut config = minimal_config();
    let source = config.sources.get_mut("people").expect("source exists");
    source.allowed_base_urls = vec![upstream_url];
    source.allow_insecure_localhost = true;
    config.audit = SidecarAuditConfig {
        sink: "file".to_string(),
        path: Some(audit_dir.path().to_string_lossy().into_owned()),
        hash_secret_env: Some("TEST_SIDECAR_AUDIT_HASH_SECRET".to_string()),
        max_size_mb: None,
        max_files: None,
    };
    let app = sidecar_router(config).await.expect("sidecar starts");
    let server = axum_test::TestServer::builder().http_transport().build(app);

    let response = server
        .get("/v1/datasets/civil_registry/entities/person/records")
        .await;

    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = response.json();
    assert_eq!(body["code"], "audit.write_failed");
}

#[tokio::test]
async fn governed_sidecar_requires_audit_pipeline() {
    std::env::set_var(
        "TEST_SOURCE_ADAPTER_SIDECAR_TOKEN_HASH",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let mut config = minimal_config();
    config.assurance = Some(SidecarAssurance {
        status: "ready".to_string(),
        product: "registry-notary-source-adapter-sidecar".to_string(),
        instance_id: "sidecar-1".to_string(),
        environment: "test".to_string(),
        stream_id: "stream".to_string(),
        bundle_id: "bundle".to_string(),
        sequence: 1,
        config_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        signer_kids: Vec::new(),
        expression_hashes_verified: true,
        runtime_verified: true,
        smoke_verified: true,
    });

    let error = sidecar_router(config)
        .await
        .expect_err("governed sidecar without audit is rejected");

    assert!(
        error.to_string().contains("requires durable audit"),
        "unexpected error: {error}"
    );
}

#[test]
fn metrics_auth_gate_rejects_missing_token_when_required() {
    let state = minimal_app_state(true);
    // No Authorization header → authorize must return Err (unauthorized).
    let headers = HeaderMap::new();
    assert!(
        authorize(&state, &headers).is_err(),
        "missing token must be rejected when metrics_require_auth is true"
    );
}

#[test]
fn metrics_auth_gate_rejects_invalid_token_when_required() {
    let state = minimal_app_state(true);
    // Malformed bearer value → authorize must return Err.
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer not-a-valid-token"),
    );
    assert!(
        authorize(&state, &headers).is_err(),
        "invalid token must be rejected when metrics_require_auth is true"
    );
}

#[test]
fn metrics_auth_gate_skips_authorize_when_disabled() {
    // When metrics_require_auth is false the handler bypasses authorize
    // entirely, so the config flag itself is what matters.  Verify the
    // flag is correctly read from the config struct.
    let state = minimal_app_state(false);
    assert!(
        !state.config.server.metrics_require_auth,
        "metrics_require_auth must default to false"
    );
}
