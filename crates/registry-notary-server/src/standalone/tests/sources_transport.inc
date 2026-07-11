    // SPDX-License-Identifier: Apache-2.0

    #[test]
    fn cached_source_token_debug_redacts_access_token() {
        let token = CachedSourceToken {
            access_token: "source-access-token-secret".to_string(),
            refresh_after: Instant::now(),
        };

        let debug = format!("{token:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("source-access-token-secret"));
    }

    #[tokio::test]
    async fn pinned_request_builder_sends_get_and_post_to_validated_target() {
        let app = Router::new()
            .route("/get", get(|| async { "pinned-get" }))
            .route("/post", post(|| async { "pinned-post" }));
        let server = TestServer::builder().http_transport().build(app);
        let base_url = server.server_address().expect("server address").to_string();
        let base_url = base_url.trim_end_matches('/');
        let get_url = format!("{base_url}/get").parse().expect("GET URL parses");
        let post_url = format!("{base_url}/post").parse().expect("POST URL parses");
        let policy = FetchUrlPolicy::dev();

        let validated_get = policy
            .validate_for_immediate_fetch_with_timeout(&get_url, Duration::from_secs(2))
            .await
            .expect("GET URL validates");
        let get_response =
            pinned_request_builder(&validated_get, reqwest::Method::GET, Duration::from_secs(2))
                .expect("GET request builds from validated URL")
                .send()
                .await
                .expect("GET request sends");
        assert_eq!(get_response.status(), reqwest::StatusCode::OK);
        let get_body = get_response.text().await.expect("GET response body reads");

        let validated_post = policy
            .validate_for_immediate_fetch_with_timeout(&post_url, Duration::from_secs(2))
            .await
            .expect("POST URL validates");
        let post_response = pinned_request_builder(
            &validated_post,
            reqwest::Method::POST,
            Duration::from_secs(2),
        )
        .expect("POST request builds from validated URL")
        .body("ignored")
        .send()
        .await
        .expect("POST request sends");
        assert_eq!(post_response.status(), reqwest::StatusCode::OK);
        let post_body = post_response
            .text()
            .await
            .expect("POST response body reads");

        assert_eq!(get_body, "pinned-get");
        assert_eq!(post_body, "pinned-post");
        assert!(!validated_get.resolved_ips().is_empty());
        assert!(!validated_post.resolved_ips().is_empty());
    }
    fn test_binding(dataset: &str, entity: &str) -> SourceBindingConfig {
        SourceBindingConfig {
            connector: SourceConnectorKind::RegistryDataApi,
            connection: Some("registry".to_string()),
            required_scope: None,
            dataset: dataset.to_string(),
            entity: entity.to_string(),
            lookup: SourceLookupConfig {
                input: "target.id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            query_fields: Vec::new(),
            fields: BTreeMap::new(),
            matching: registry_notary_core::SourceMatchingConfig::default(),
        }
    }

    fn test_source_config(base_url: &str, allow_insecure_localhost: bool) -> EvidenceConfig {
        EvidenceConfig {
            allowed_purposes: vec![SOURCE_ADAPTER_SPIKE_PURPOSE.to_string()],
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                SourceConnectionConfig {
                    base_url: base_url.to_string(),
                    allow_insecure_localhost,
                    allow_insecure_private_network: false,
                    token_env: "TEST_EVIDENCE_SOURCE_POLICY_TOKEN".to_string(),
                    source_auth: None,
                    expected_sidecar: None,
                    dci: DciSourceConnectionConfig::default(),
                    max_in_flight: 8,
                    retry_on_5xx: true,
                    bulk_mode: registry_notary_core::BulkMode::None,
                    bulk_mode_lookup_unique: false,
                    bulk_timeout_max_ms: 30_000,
                },
            )]),
            ..EvidenceConfig::default()
        }
    }

    fn source_adapter_sidecar_spike_config(base_url: &str) -> EvidenceConfig {
        let raw = format!(
            r#"
enabled: true
service_id: spike.registry-notary
allowed_purposes:
  - {SOURCE_ADAPTER_SPIKE_PURPOSE}
source_connections:
  source_adapter_crvs:
    base_url: "{base_url}"
    allow_insecure_localhost: true
    retry_on_5xx: false
    token_env: {SOURCE_ADAPTER_SIDECAR_TOKEN_ENV}
claims:
  - id: date-of-birth
    title: Date of birth
    version: 2026-05
    subject_type: person
    value:
      type: date
    inputs:
      - name: subject_id
        type: string
    source_bindings:
      crvs:
        connector: source_adapter_sidecar
        connection: source_adapter_crvs
        required_scope: civil_registry:evidence_verification
        dataset: civil_registry
        entity: civil_person
        lookup:
          input: target.id
          field: national_id
          op: eq
          cardinality: one
        fields:
          birth_date:
            field: birth_date
            type: date
            required: true
        matching:
          allowed_purposes:
            - "{SOURCE_ADAPTER_SPIKE_PURPOSE}"
    rule:
      type: extract
      source: crvs
      field: birth_date
    disclosure:
      default: value
      allowed:
        - value
        - redacted
    formats:
      - "{FORMAT_CLAIM_RESULT_JSON}"
"#
        );
        serde_norway::from_str(&raw).expect("spike config parses")
    }

    fn http_json_sidecar_test_manifest(upstream_url: &str) -> String {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_HASH_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN_HASH,
        );
        std::env::set_var(
            HTTP_JSON_CREDENTIAL_ENV,
            json!({
                "baseUrl": upstream_url,
                "clientId": "notary-test",
                "apiToken": "http-json-target-token"
            })
            .to_string(),
        );
        format!(
            r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary
      hash_env: "{SOURCE_ADAPTER_SIDECAR_TOKEN_HASH_ENV}"
limits:
  max_workers: 2
  worker_timeout_ms: 250
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
sources:
  source_adapter_crvs:
    engine: http_json
    dataset: civil_registry
    entity: civil_person
    credential_env: "{HTTP_JSON_CREDENTIAL_ENV}"
    credential_public_fields:
      - baseUrl
      - clientId
    allowed_base_urls:
      - "{upstream_url}"
    allow_insecure_localhost: true
    http_json:
      method: GET
      base_url:
        cel: credential_public.baseUrl
      path: "/people"
      query:
        id:
          cel: lookup.value
      headers:
        x-client-id:
          cel: credential_public.clientId
      auth:
        type: bearer
        token:
          secret: apiToken
      response:
        records:
          cel: body.results
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#
        )
    }

    async fn fixed_source_adapter_batch_response_handler(
        State(response): State<Value>,
        Json(_request): Json<Value>,
    ) -> Response {
        Json(response).into_response()
    }

    async fn http_json_people_handler(
        Query(query): Query<HashMap<String, String>>,
        headers: HeaderMap,
    ) -> Response {
        let authorized = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            == Some("Bearer http-json-target-token");
        let client_id = headers
            .get("x-client-id")
            .and_then(|value| value.to_str().ok());
        if !authorized || client_id != Some("notary-test") {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let id = query.get("id").cloned().unwrap_or_default();
        let results = match id.as_str() {
            "person-123" | "smoke-person" => json!([
                {
                    "national_id": id,
                    "birth_date": "1990-01-01",
                    "ignored_extra": "notary must not depend on this"
                }
            ]),
            _ => json!([]),
        };
        Json(json!({ "results": results })).into_response()
    }

    fn http_json_sidecar_test_config(upstream_url: &str) -> SidecarConfig {
        serde_norway::from_str(&http_json_sidecar_test_manifest(upstream_url))
            .expect("http_json sidecar test config parses")
    }

    async fn read_source_adapter_batch_from_fixed_response(
        response: Value,
    ) -> Vec<Result<Value, EvidenceError>> {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let upstream = TestServer::builder().http_transport().build(
            Router::new()
                .route(
                    "/v1/datasets/civil_registry/entities/civil_person/records:batchMatch",
                    post(fixed_source_adapter_batch_response_handler),
                )
                .with_state(response),
        );
        let evidence = source_adapter_sidecar_spike_config(
            upstream
                .server_address()
                .expect("HTTP transport exposes upstream address")
                .as_str(),
        );
        let source = HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
            .expect("source config resolves");
        let binding = evidence.claims[0].source_bindings["crvs"].clone();
        let connection = source
            .source_connection(&binding)
            .expect("source connection exists");
        let bindings = ["person-0", "person-1"]
            .into_iter()
            .map(|id| {
                (
                    binding.clone(),
                    EvidenceRequestContext {
                        requester: None,
                        target: registry_notary_core::EvidenceEntity::from_subject_request(
                            "Person",
                            SubjectRequest {
                                id: id.to_string(),
                                id_type: None,
                            },
                        ),
                        relationship: None,
                        on_behalf_of: None,
                    },
                )
            })
            .collect::<Vec<_>>();

        read_remote_source_adapter_sidecar_many_context(
            &source,
            connection,
            &bindings,
            SOURCE_ADAPTER_SPIKE_PURPOSE,
        )
        .await
    }

    #[derive(Clone)]
    struct SourceAdapterAssuranceFixture {
        assurance_count: Arc<AtomicUsize>,
        records_count: Arc<AtomicUsize>,
        config_hash: String,
    }

    async fn fixed_source_adapter_assurance_handler(
        State(fixture): State<SourceAdapterAssuranceFixture>,
    ) -> Response {
        fixture.assurance_count.fetch_add(1, Ordering::SeqCst);
        Json(json!({
            "status": "ready",
            "product": "registry-notary-source-adapter-sidecar",
            "instance_id": "demo",
            "environment": "staging",
            "stream_id": "source-adapter-sidecar-runtime",
            "bundle_id": "opencrvs-sidecar-test",
            "sequence": 12,
            "config_hash": fixture.config_hash,
            "signer_kids": ["kid"],
            "expression_hashes_verified": true,
            "runtime_verified": true,
            "smoke_verified": true
        }))
        .into_response()
    }

    async fn fixed_source_adapter_records_handler(
        State(fixture): State<SourceAdapterAssuranceFixture>,
    ) -> Response {
        fixture.records_count.fetch_add(1, Ordering::SeqCst);
        Json(json!({
            "data": [{
                "national_id": "person-123",
                "birth_date": "1990-01-01"
            }]
        }))
        .into_response()
    }

    fn expected_source_adapter_sidecar(config_hash: &str) -> ExpectedSidecarConfig {
        ExpectedSidecarConfig {
            product: SOURCE_ADAPTER_PRODUCT.to_string(),
            instance_id: SOURCE_ADAPTER_INSTANCE_ID.to_string(),
            environment: SOURCE_ADAPTER_ENVIRONMENT.to_string(),
            stream_id: SOURCE_ADAPTER_STREAM_ID.to_string(),
            config_hash: config_hash.to_string(),
            require_expression_hashes_verified: true,
            require_runtime_verified: true,
            require_smoke_verified: true,
            assurance_ttl_ms: 60_000,
        }
    }

    #[test]
    fn source_adapter_sidecar_assurance_url_preserves_base_path_prefix() {
        let url =
            source_adapter_sidecar_assurance_url("https://sidecar.example/api/source-adapter")
                .expect("assurance URL builds");

        assert_eq!(
            url.as_str(),
            "https://sidecar.example/api/source-adapter/v1/assurance"
        );
    }

    #[tokio::test]
    async fn source_adapter_sidecar_expected_assurance_is_cached_across_source_reads() {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let config_hash =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        let fixture = SourceAdapterAssuranceFixture {
            assurance_count: Arc::new(AtomicUsize::new(0)),
            records_count: Arc::new(AtomicUsize::new(0)),
            config_hash: config_hash.clone(),
        };
        let upstream = TestServer::builder().http_transport().build(
            Router::new()
                .route("/v1/assurance", get(fixed_source_adapter_assurance_handler))
                .route(
                    "/v1/datasets/civil_registry/entities/civil_person/records",
                    get(fixed_source_adapter_records_handler),
                )
                .with_state(fixture.clone()),
        );
        let mut evidence = source_adapter_sidecar_spike_config(
            upstream
                .server_address()
                .expect("HTTP transport exposes upstream address")
                .as_str(),
        );
        evidence
            .source_connections
            .get_mut("source_adapter_crvs")
            .expect("connection exists")
            .expected_sidecar = Some(expected_source_adapter_sidecar(&config_hash));
        let source = HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
            .expect("source config resolves");
        let binding = evidence.claims[0].source_bindings["crvs"].clone();
        let connection = source
            .source_connection(&binding)
            .expect("source connection exists");
        let subject = SubjectRequest {
            id: "person-123".to_string(),
            id_type: None,
        };

        assert!(source.has_readiness_check());
        assert!(source.check_ready().await);
        assert_eq!(fixture.assurance_count.load(Ordering::SeqCst), 1);
        read_remote_registry_data_api_one(
            &source,
            connection,
            &binding,
            &subject,
            SOURCE_ADAPTER_SPIKE_PURPOSE,
        )
        .await
        .expect("first source read succeeds");
        read_remote_registry_data_api_one(
            &source,
            connection,
            &binding,
            &subject,
            SOURCE_ADAPTER_SPIKE_PURPOSE,
        )
        .await
        .expect("second source read succeeds");

        assert_eq!(fixture.assurance_count.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.records_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            source
                .observed_sidecar_config_hashes(&evidence, &["date-of-birth".to_string()])
                .await,
            vec![config_hash]
        );
    }

    #[tokio::test]
    async fn source_adapter_sidecar_expected_assurance_mismatch_fails_before_source_read() {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let observed_hash =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        let expected_hash =
            "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_string();
        let fixture = SourceAdapterAssuranceFixture {
            assurance_count: Arc::new(AtomicUsize::new(0)),
            records_count: Arc::new(AtomicUsize::new(0)),
            config_hash: observed_hash,
        };
        let upstream = TestServer::builder().http_transport().build(
            Router::new()
                .route("/v1/assurance", get(fixed_source_adapter_assurance_handler))
                .route(
                    "/v1/datasets/civil_registry/entities/civil_person/records",
                    get(fixed_source_adapter_records_handler),
                )
                .with_state(fixture.clone()),
        );
        let mut evidence = source_adapter_sidecar_spike_config(
            upstream
                .server_address()
                .expect("HTTP transport exposes upstream address")
                .as_str(),
        );
        evidence
            .source_connections
            .get_mut("source_adapter_crvs")
            .expect("connection exists")
            .expected_sidecar = Some(expected_source_adapter_sidecar(&expected_hash));
        let source = HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
            .expect("source config resolves");
        let binding = evidence.claims[0].source_bindings["crvs"].clone();
        let connection = source
            .source_connection(&binding)
            .expect("source connection exists");
        let subject = SubjectRequest {
            id: "person-123".to_string(),
            id_type: None,
        };

        assert!(!source.check_ready().await);
        assert_eq!(fixture.assurance_count.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.records_count.load(Ordering::SeqCst), 0);
        let error = read_remote_registry_data_api_one(
            &source,
            connection,
            &binding,
            &subject,
            SOURCE_ADAPTER_SPIKE_PURPOSE,
        )
        .await
        .expect_err("mismatched assurance must fail");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
        assert_eq!(fixture.assurance_count.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.records_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn source_adapter_sidecar_missing_assurance_endpoint_fails_before_source_read() {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let expected_hash =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        let fixture = SourceAdapterAssuranceFixture {
            assurance_count: Arc::new(AtomicUsize::new(0)),
            records_count: Arc::new(AtomicUsize::new(0)),
            config_hash: expected_hash.clone(),
        };
        let upstream = TestServer::builder().http_transport().build(
            Router::new()
                .route(
                    "/v1/datasets/civil_registry/entities/civil_person/records",
                    get(fixed_source_adapter_records_handler),
                )
                .with_state(fixture.clone()),
        );
        let mut evidence = source_adapter_sidecar_spike_config(
            upstream
                .server_address()
                .expect("HTTP transport exposes upstream address")
                .as_str(),
        );
        evidence
            .source_connections
            .get_mut("source_adapter_crvs")
            .expect("connection exists")
            .expected_sidecar = Some(expected_source_adapter_sidecar(&expected_hash));
        let source = HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
            .expect("source config resolves");
        let binding = evidence.claims[0].source_bindings["crvs"].clone();
        let connection = source
            .source_connection(&binding)
            .expect("source connection exists");
        let subject = SubjectRequest {
            id: "person-123".to_string(),
            id_type: None,
        };

        assert!(!source.check_ready().await);
        let error = read_remote_registry_data_api_one(
            &source,
            connection,
            &binding,
            &subject,
            SOURCE_ADAPTER_SPIKE_PURPOSE,
        )
        .await
        .expect_err("missing assurance endpoint must fail");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
        assert_eq!(fixture.assurance_count.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.records_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn source_fetch_url_policy_private_network_escape_hatch_keeps_metadata_denial() {
        let config = test_source_config("http://registry-relay:8080", false);
        let mut connection = config
            .source_connections
            .get("registry")
            .expect("source connection")
            .clone();
        connection.allow_insecure_private_network = true;

        let policy = source_fetch_url_policy(&connection);

        assert_eq!(policy.allowed_schemes, ["http", "https"]);
        assert!(policy.allow_localhost);
        assert!(policy.allow_http_private_network);
        assert!(!policy.deny_private_ranges);
        assert!(policy.deny_cloud_metadata);
    }

    #[test]
    fn source_fetch_url_policy_defaults_to_strict() {
        let config = test_source_config("https://registry.example.test", false);
        let connection = config
            .source_connections
            .get("registry")
            .expect("source connection");

        assert_eq!(
            source_fetch_url_policy(connection),
            FetchUrlPolicy::strict()
        );
    }

    #[tokio::test]
    async fn http_json_sidecar_rda_facade_can_source_single_item_attestation() {
        let _env_guard = HTTP_JSON_SIDECAR_ENV_LOCK.lock().await;
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let upstream = TestServer::builder()
            .http_transport()
            .build(Router::new().route("/people", get(http_json_people_handler)));
        let upstream_url = upstream
            .server_address()
            .expect("HTTP transport exposes upstream address")
            .to_string()
            .trim_end_matches('/')
            .to_string();
        let sidecar = sidecar_router(http_json_sidecar_test_config(&upstream_url))
            .await
            .expect("http_json sidecar router builds");
        let server = TestServer::builder().http_transport().build(sidecar);
        let evidence = Arc::new(source_adapter_sidecar_spike_config(
            server
                .server_address()
                .expect("HTTP transport exposes sidecar address")
                .as_str(),
        ));
        let source = Arc::new(
            HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
                .expect("source config"),
        );
        let principal = EvidencePrincipal {
            principal_id: "caseworker".to_string(),
            scopes: vec!["civil_registry:evidence_verification".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };

        let results = crate::RegistryNotaryRuntime::new()
            .evaluate(
                Arc::clone(&evidence),
                source,
                &EvidenceStore::default(),
                &principal,
                EvaluateRequest {
                    requester: None,
                    target: Some(registry_notary_core::EvidenceEntity::from_subject_request(
                        "Person",
                        SubjectRequest {
                            id: "person-123".to_string(),
                            id_type: None,
                        },
                    )),
                    relationship: None,
                    on_behalf_of: None,
                    claims: vec![registry_notary_core::ClaimRef::from("date-of-birth")],
                    disclosure: Some("value".to_string()),
                    format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
                    purpose: Some(SOURCE_ADAPTER_SPIKE_PURPOSE.to_string()),
                },
                None,
            )
            .await
            .expect("http_json sidecar facade sources the claim");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].claim_id, "date-of-birth");
        assert_eq!(results[0].value, Some(json!("1990-01-01")));
        assert_eq!(results[0].provenance.used.source_count, 1);
        assert!(
            results[0].provenance.used.source_runtimes.is_empty(),
            "unsigned local sidecar has no pinned runtime summary"
        );
    }

    /// Mock upstream for the `script_rhai` sidecar. Returns a bare JSON array
    /// record (the script forwards `source.get(...).body` verbatim and the
    /// sidecar wraps it as `{ "data": [...] }`). Answers both the notary's lookup
    /// value (`person-123`) and the startup-smoke value (`smoke-person`); any
    /// other id yields an empty array. No auth is enforced (the target omits
    /// auth), so the script needs no credential.
    async fn rhai_lookup_handler(Query(query): Query<HashMap<String, String>>) -> Response {
        let id = query.get("id").cloned().unwrap_or_default();
        let records = match id.as_str() {
            "person-123" | "smoke-person" => json!([
                {
                    "national_id": id,
                    "birth_date": "1990-01-01",
                    "ignored_extra": "notary must not depend on this"
                }
            ]),
            _ => json!([]),
        };
        Json(records).into_response()
    }

    fn script_rhai_sidecar_test_manifest(upstream_url: &str) -> String {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_HASH_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN_HASH,
        );
        format!(
            r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary
      hash_env: "{SOURCE_ADAPTER_SIDECAR_TOKEN_HASH_ENV}"
limits:
  max_workers: 2
  worker_timeout_ms: 500
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
  max_worker_memory_mb: 256
sources:
  source_adapter_crvs:
    engine: script_rhai
    dataset: civil_registry
    entity: civil_person
    allowed_base_urls:
      - "{upstream_url}"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) {{
          source.get("primary", "/lookup", #{{ id: ctx.lookup.value }}).body
        }}
      targets:
        primary:
          base_url: "{upstream_url}"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#
        )
    }

    fn script_rhai_sidecar_test_config(upstream_url: &str) -> SidecarConfig {
        serde_norway::from_str(&script_rhai_sidecar_test_manifest(upstream_url))
            .expect("script_rhai sidecar test config parses")
    }

    /// End-to-end twin of `http_json_sidecar_rda_facade_can_source_single_item_attestation`,
    /// swapping only the sidecar engine to `script_rhai`. The notary connector
    /// (`source_adapter_sidecar`) and its spike config are identical: the
    /// protocol between notary and sidecar is engine-agnostic.
    #[tokio::test]
    async fn script_rhai_sidecar_rda_facade_can_source_single_item_attestation() {
        let _env_guard = HTTP_JSON_SIDECAR_ENV_LOCK.lock().await;
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let upstream = TestServer::builder()
            .http_transport()
            .build(Router::new().route("/lookup", get(rhai_lookup_handler)));
        let upstream_url = upstream
            .server_address()
            .expect("HTTP transport exposes upstream address")
            .to_string()
            .trim_end_matches('/')
            .to_string();
        let sidecar = sidecar_router(script_rhai_sidecar_test_config(&upstream_url))
            .await
            .expect("script_rhai sidecar router builds and passes startup smoke");
        let server = TestServer::builder().http_transport().build(sidecar);
        let evidence = Arc::new(source_adapter_sidecar_spike_config(
            server
                .server_address()
                .expect("HTTP transport exposes sidecar address")
                .as_str(),
        ));
        let source = Arc::new(
            HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
                .expect("source config"),
        );
        let principal = EvidencePrincipal {
            principal_id: "caseworker".to_string(),
            scopes: vec!["civil_registry:evidence_verification".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };

        let results = crate::RegistryNotaryRuntime::new()
            .evaluate(
                Arc::clone(&evidence),
                source,
                &EvidenceStore::default(),
                &principal,
                EvaluateRequest {
                    requester: None,
                    target: Some(registry_notary_core::EvidenceEntity::from_subject_request(
                        "Person",
                        SubjectRequest {
                            id: "person-123".to_string(),
                            id_type: None,
                        },
                    )),
                    relationship: None,
                    on_behalf_of: None,
                    claims: vec![registry_notary_core::ClaimRef::from("date-of-birth")],
                    disclosure: Some("value".to_string()),
                    format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
                    purpose: Some(SOURCE_ADAPTER_SPIKE_PURPOSE.to_string()),
                },
                None,
            )
            .await
            .expect("script_rhai sidecar facade sources the claim");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].claim_id, "date-of-birth");
        assert_eq!(results[0].value, Some(json!("1990-01-01")));
        assert_eq!(results[0].provenance.used.source_count, 1);
        assert!(
            results[0].provenance.used.source_runtimes.is_empty(),
            "unsigned local sidecar has no pinned runtime summary"
        );
    }

    #[tokio::test]
    async fn source_adapter_sidecar_batch_client_rejects_malformed_response_item_ids() {
        let cases = [
            json!({
                "items": [
                    { "id": "0", "data": [{ "national_id": "person-0", "birth_date": "1990-01-01" }] },
                    { "id": "1", "data": [{ "national_id": "person-1", "birth_date": "1991-01-01" }] },
                    { "id": "unexpected", "data": [] }
                ]
            }),
            json!({
                "items": [
                    { "id": "0", "data": [{ "national_id": "person-0", "birth_date": "1990-01-01" }] },
                    { "id": "0", "data": [] }
                ]
            }),
            json!({
                "items": [
                    { "id": "0", "data": [{ "national_id": "person-0", "birth_date": "1990-01-01" }] },
                    { "data": [] }
                ]
            }),
        ];

        for response in cases {
            let results = read_source_adapter_batch_from_fixed_response(response).await;

            assert_eq!(results.len(), 2);
            assert!(
                results
                    .iter()
                    .all(|result| matches!(result, Err(EvidenceError::SourceUnavailable))),
                "malformed batch response ids must reject the whole batch result: {results:?}"
            );
        }
    }

    #[tokio::test]
    async fn source_adapter_sidecar_batch_client_maps_missing_response_item_per_subject() {
        let results = read_source_adapter_batch_from_fixed_response(json!({
            "items": [
                { "id": "0", "data": [{ "national_id": "person-0", "birth_date": "1990-01-01" }] }
            ]
        }))
        .await;

        assert_eq!(results.len(), 2);
        assert!(results[0]
            .as_ref()
            .is_ok_and(|row| row.get("birth_date") == Some(&json!("1990-01-01"))));
        assert!(matches!(results[1], Err(EvidenceError::SourceUnavailable)));
    }

    #[test]
    fn registry_data_api_url_percent_encodes_dataset_and_entity_segments() {
        let binding = test_binding("farmer/registry", "farmer?active");

        let url = registry_data_api_url("https://registry.example.test/api", &binding)
            .expect("url builds");

        assert_eq!(
            url.as_str(),
            "https://registry.example.test/api/v1/datasets/farmer%2Fregistry/entities/farmer%3Factive/records"
        );
    }

    #[test]
    fn context_lookup_value_supports_requester_and_relationship_paths() {
        let mut binding = test_binding("people", "person");
        let mut requester =
            registry_notary_core::EvidenceEntity::with_identifier("Person", "national_id", "REQ-1");
        requester
            .attributes
            .insert("birthdate".to_string(), json!("1984-02-10"));
        let mut relationship = registry_notary_core::EvidenceRelationship {
            relationship_type: "guardian".to_string(),
            attributes: BTreeMap::new(),
        };
        relationship
            .attributes
            .insert("case_id".to_string(), json!("CASE-9"));
        let context = EvidenceRequestContext {
            requester: Some(requester),
            target: registry_notary_core::EvidenceEntity::with_identifier(
                "Person",
                "national_id",
                "NID-1",
            ),
            relationship: Some(relationship),
            on_behalf_of: None,
        };

        binding.lookup.input = "requester.identifiers.national_id".to_string();
        assert_eq!(
            lookup_value_for_context(&binding, &context).expect("requester id resolves"),
            json!("REQ-1")
        );
        binding.lookup.input = "requester.attributes.birthdate".to_string();
        assert_eq!(
            lookup_value_for_context(&binding, &context).expect("requester attr resolves"),
            json!("1984-02-10")
        );
        binding.lookup.input = "relationship.attributes.case_id".to_string();
        assert_eq!(
            lookup_value_for_context(&binding, &context).expect("relationship attr resolves"),
            json!("CASE-9")
        );
        binding.lookup.input = "requester.identifiers.missing".to_string();
        assert_eq!(
            lookup_value_for_context(&binding, &context)
                .expect_err("missing requester identifier is specific")
                .code(),
            "requester.identifier_missing"
        );
    }

    #[test]
    fn dci_query_fields_build_opencrvs_expression_query_from_target_attributes() {
        let mut binding = test_binding("civil_registry", "birth_registration");
        binding.query_fields = vec![
            SourceQueryFieldConfig {
                input: "target.attributes.given_name".to_string(),
                field: "given_name".to_string(),
                op: "eq".to_string(),
            },
            SourceQueryFieldConfig {
                input: "target.attributes.family_name".to_string(),
                field: "surname".to_string(),
                op: "eq".to_string(),
            },
            SourceQueryFieldConfig {
                input: "target.attributes.birthdate".to_string(),
                field: "birth_date".to_string(),
                op: "eq".to_string(),
            },
        ];
        let dci = DciSourceConnectionConfig {
            query_type: "expression".to_string(),
            registry_type: Some("ns:org:RegistryType:Civil".to_string()),
            registry_event_type: Some("birth".to_string()),
            ..DciSourceConnectionConfig::default()
        };
        let mut target = registry_notary_core::EvidenceEntity::new("Person");
        target
            .attributes
            .insert("given_name".to_string(), json!("Amina"));
        target
            .attributes
            .insert("family_name".to_string(), json!("Diallo"));
        target
            .attributes
            .insert("birthdate".to_string(), json!("2020-01-02"));
        let context = EvidenceRequestContext {
            requester: None,
            target,
            relationship: None,
            on_behalf_of: None,
        };

        let values = source_query_values_for_context(&binding, &context)
            .expect("query values resolve from target attributes");
        let criteria =
            dci_search_criteria_for_values(&dci, &binding, &values, 2).expect("criteria builds");

        assert_eq!(criteria["query_type"], json!("expression"));
        assert_eq!(
            criteria["query"],
            json!({
                "type": "ns:org:QueryType:expression",
                "value": {
                    "expression": {
                        "query": {
                            "given_name": { "type": "exact", "term": "Amina" },
                            "surname": { "type": "exact", "term": "Diallo" },
                            "birth_date": { "type": "exact", "term": "2020-01-02" }
                        }
                    }
                }
            })
        );
    }

    #[test]
    fn rda_query_fields_build_registry_relay_query_params_from_target_attributes() {
        let mut binding = test_binding("civil_registry", "civil_person");
        binding.query_fields = vec![
            SourceQueryFieldConfig {
                input: "target.attributes.given_name".to_string(),
                field: "given_name".to_string(),
                op: "eq".to_string(),
            },
            SourceQueryFieldConfig {
                input: "target.attributes.family_name".to_string(),
                field: "surname".to_string(),
                op: "eq".to_string(),
            },
            SourceQueryFieldConfig {
                input: "target.attributes.birthdate".to_string(),
                field: "birth_date".to_string(),
                op: "eq".to_string(),
            },
        ];
        let mut target = registry_notary_core::EvidenceEntity::new("Person");
        target
            .attributes
            .insert("given_name".to_string(), json!("Amina"));
        target
            .attributes
            .insert("family_name".to_string(), json!("Diallo"));
        target
            .attributes
            .insert("birthdate".to_string(), json!("2020-01-02"));
        let context = EvidenceRequestContext {
            requester: None,
            target,
            relationship: None,
            on_behalf_of: None,
        };

        let values = source_query_values_for_context(&binding, &context)
            .expect("query values resolve from target attributes");
        let pairs = values
            .iter()
            .map(registry_data_api_query_pair)
            .collect::<Result<Vec<_>, _>>()
            .expect("RDA query pairs build");

        assert_eq!(
            pairs,
            vec![
                ("given_name".to_string(), "Amina".to_string()),
                ("surname".to_string(), "Diallo".to_string()),
                ("birth_date".to_string(), "2020-01-02".to_string()),
            ]
        );
        assert_eq!(
            projected_source_fields_with_query_values(&binding, &values),
            vec![
                "birth_date".to_string(),
                "given_name".to_string(),
                "surname".to_string()
            ]
        );
        binding.matching.source_observed_at_field = Some("observed_at".to_string());
        assert_eq!(
            projected_source_fields_with_query_values(&binding, &values),
            vec![
                "birth_date".to_string(),
                "given_name".to_string(),
                "observed_at".to_string(),
                "surname".to_string()
            ]
        );
        assert_eq!(
            projected_source_fields_with_lookup(&binding, "national_id"),
            vec!["national_id".to_string(), "observed_at".to_string()]
        );
    }

    #[test]
    fn dci_expression_filter_accepts_gte_lte_aliases() {
        let gte = dci_expression_filter(&SourceQueryValue {
            field: "birth_date".to_string(),
            op: "gte".to_string(),
            value: json!("2020-01-01"),
        })
        .expect("gte maps to range filter");
        let lte = dci_expression_filter(&SourceQueryValue {
            field: "birth_date".to_string(),
            op: "lte".to_string(),
            value: json!("2020-12-31"),
        })
        .expect("lte maps to range filter");

        assert_eq!(gte, json!({ "type": "range", "gte": "2020-01-01" }));
        assert_eq!(lte, json!({ "type": "range", "lte": "2020-12-31" }));
    }

    #[test]
    fn parse_source_observed_at_trims_timestamp_before_parse() {
        let mut binding = test_binding("people", "person");
        binding.matching.source_observed_at_field = Some("observed_at".to_string());

        let observed_at =
            parse_source_observed_at(&binding, &json!({"observed_at": "\t2026-05-24T12:00:00Z "}))
                .expect("trimmed observed_at parses")
                .expect("observed_at is present");

        assert_eq!(
            observed_at
                .format(&Rfc3339)
                .expect("observed_at formats as RFC3339"),
            "2026-05-24T12:00:00Z"
        );
    }

    #[test]
    fn dci_source_url_rejects_absolute_search_paths() {
        assert!(source_url(
            "https://registry.example.test",
            "https://attacker.example.test/dci/search"
        )
        .is_err());
        assert!(source_url("https://registry.example.test", "file:///tmp/search").is_err());
        assert_eq!(
            source_url("https://registry.example.test/base", "/dci/search")
                .expect("relative path is accepted")
                .as_str(),
            "https://registry.example.test/base/dci/search"
        );
    }

    #[tokio::test]
    async fn source_json_reader_rejects_oversized_body() {
        let app = Router::new().route(
            "/too-large",
            get(|| async { "x".repeat(MAX_SOURCE_JSON_BYTES + 1) }),
        );
        let server = TestServer::builder().http_transport().build(app);
        let url = format!(
            "{}too-large",
            server
                .server_address()
                .expect("HTTP transport exposes upstream address")
        );
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client builds")
            .get(url)
            .send()
            .await
            .expect("request succeeds");

        let error = read_source_json(response)
            .await
            .expect_err("oversized body is rejected");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[tokio::test]
    async fn http_sources_do_not_follow_upstream_redirects() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_REDIRECT_TOKEN", "source-token");
        let app = Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(|| async { Redirect::temporary("/redirect-target") }),
            )
            .route(
                "/redirect-target",
                get(|| async {
                    Json(json!({
                        "data": [{
                            "id": "person-1",
                            "total_farmed_area": 3.5
                        }]
                    }))
                }),
            );
        let server = TestServer::builder().http_transport().build(app);
        let config = EvidenceConfig {
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                SourceConnectionConfig {
                    base_url: server
                        .server_address()
                        .expect("HTTP transport exposes upstream address")
                        .to_string(),
                    allow_insecure_localhost: true,
                    allow_insecure_private_network: false,
                    token_env: "TEST_EVIDENCE_SOURCE_REDIRECT_TOKEN".to_string(),
                    source_auth: None,
                    expected_sidecar: None,
                    dci: DciSourceConnectionConfig::default(),
                    max_in_flight: 8,
                    retry_on_5xx: true,
                    bulk_mode: registry_notary_core::BulkMode::None,
                    bulk_mode_lookup_unique: false,
                    bulk_timeout_max_ms: 30_000,
                },
            )]),
            ..EvidenceConfig::default()
        };
        let sources = HttpEvidenceSources::from_config(&config, Arc::new(AppMetrics::default()))
            .expect("source config resolves");
        let mut binding = test_binding("farmer_registry", "farmer");
        binding.fields.insert(
            "total_farmed_area".to_string(),
            registry_notary_core::SourceFieldConfig {
                field: "total_farmed_area".to_string(),
                field_type: Some("number".to_string()),
                unit: None,
                required: true,
                semantic_term: None,
            },
        );
        let subject = SubjectRequest {
            id: "person-1".to_string(),
            id_type: None,
        };

        let error = sources
            .read_one(
                &binding,
                &subject,
                "https://purpose.example.test/eligibility",
            )
            .await
            .expect_err("redirect response is not followed");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[tokio::test]
    async fn http_sources_reject_private_source_urls_before_fetch() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_POLICY_TOKEN", "source-token");
        let sources = HttpEvidenceSources::from_config(
            &test_source_config("https://10.0.0.1", false),
            Arc::new(AppMetrics::default()),
        )
        .expect("source config resolves");
        let binding = test_binding("farmer_registry", "farmer");
        let subject = SubjectRequest {
            id: "person-1".to_string(),
            id_type: None,
        };

        let error = sources
            .read_one(
                &binding,
                &subject,
                "https://purpose.example.test/eligibility",
            )
            .await
            .expect_err("private source URL is rejected");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[tokio::test]
    async fn http_sources_reject_cloud_metadata_source_urls_before_fetch() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_POLICY_TOKEN", "source-token");
        let sources = HttpEvidenceSources::from_config(
            &test_source_config("http://169.254.169.254", true),
            Arc::new(AppMetrics::default()),
        )
        .expect("source config resolves");
        let binding = test_binding("farmer_registry", "farmer");
        let subject = SubjectRequest {
            id: "person-1".to_string(),
            id_type: None,
        };

        let error = sources
            .read_one(
                &binding,
                &subject,
                "https://purpose.example.test/eligibility",
            )
            .await
            .expect_err("metadata source URL is rejected");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[test]
    fn http_sources_from_config_sets_finite_request_timeout() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_TIMEOUT_TOKEN", "source-token");
        let config = EvidenceConfig {
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                registry_notary_core::SourceConnectionConfig {
                    base_url: "https://registry.example.test".to_string(),
                    allow_insecure_localhost: false,
                    allow_insecure_private_network: false,
                    token_env: "TEST_EVIDENCE_SOURCE_TIMEOUT_TOKEN".to_string(),
                    source_auth: None,
                    expected_sidecar: None,
                    dci: DciSourceConnectionConfig::default(),
                    max_in_flight: 8,
                    retry_on_5xx: true,
                    bulk_mode: registry_notary_core::BulkMode::None,
                    bulk_mode_lookup_unique: false,
                    bulk_timeout_max_ms: 30_000,
                },
            )]),
            ..EvidenceConfig::default()
        };

        let sources = HttpEvidenceSources::from_config(&config, Arc::new(AppMetrics::default()))
            .expect("source config resolves");

        assert_eq!(sources.request_timeout, SOURCE_REQUEST_TIMEOUT);
        assert!(sources.request_timeout > Duration::ZERO);
    }
