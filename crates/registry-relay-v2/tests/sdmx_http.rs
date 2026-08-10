// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use http::header::{ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, VARY};
use http::{Request, StatusCode};
use registry_platform_audit::{
    AuditChainHasher, AuditEnvelope, AuditError, AuditSink, ChainState, JsonlFileSink,
};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier};
use registry_platform_sqlite::{
    inspect_schema, materialize_fixture, CapturedSnapshot, DatabaseProfile, InspectionLimits,
    SchemaObjectKind,
};
use registry_platform_testing::{
    fixtures, oidc_verifier_config, sign_ed25519_compact_jwt, MockIdp,
};
use registry_relay_v2::artifacts::generate_artifacts;
use registry_relay_v2::audit::RelayAudit;
use registry_relay_v2::auth::RelayAuthenticator;
use registry_relay_v2::compiler::{
    classification_inventory_digest, compile_contract, compile_contract_with_governed_files,
    GovernedFileSet,
};
use registry_relay_v2::contract::{ClassificationReviewDocument, RegistryContract, RelayRuntime};
use registry_relay_v2::model::{
    CompileProfile, ObservedColumn, ObservedSourceSchema, ObservedView,
};
use registry_relay_v2::server::{
    router, AlignmentMetadata, InstitutionMetadata, QuotaConfig, RelayService, ServiceMetadata,
};
use registry_relay_v2::sqlite_runtime::{RuntimeSourceBinding, SqliteRuntime, SqliteRuntimeLimits};
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt as _;

const PROJECT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../products/relay-v2/examples/labour-statistics"
);

struct Harness {
    app: axum::Router,
    audit_path: PathBuf,
    database: PathBuf,
    idp: MockIdp,
    audience: String,
    _temporary: TempDir,
}

struct ControlledAuditSink {
    fail_on_write: usize,
    writes: AtomicUsize,
}

impl ControlledAuditSink {
    fn new(fail_on_write: usize) -> Self {
        Self {
            fail_on_write,
            writes: AtomicUsize::new(0),
        }
    }

    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl AuditSink for ControlledAuditSink {
    async fn write(&self, _envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let write = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if write == self.fail_on_write {
            return Err(AuditError::Io(std::io::Error::other(
                "controlled audit failure",
            )));
        }
        Ok(())
    }

    #[allow(deprecated)]
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }

    async fn tail_hash_with_hasher(
        &self,
        _hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }
}

impl Harness {
    async fn open() -> Self {
        Self::open_with_options("", false, None, None).await
    }

    async fn open_with_fixture_suffix(suffix: &str) -> Self {
        Self::open_with_options(suffix, false, None, None).await
    }

    async fn open_with_audit(sink: Arc<dyn AuditSink>) -> Self {
        Self::open_with_options("", false, None, Some(sink)).await
    }

    async fn open_with_fixture_suffix_and_audit(suffix: &str, sink: Arc<dyn AuditSink>) -> Self {
        Self::open_with_options(suffix, false, None, Some(sink)).await
    }

    async fn open_with_options(
        suffix: &str,
        live_source: bool,
        quota: Option<QuotaConfig>,
        audit_sink: Option<Arc<dyn AuditSink>>,
    ) -> Self {
        let root = Path::new(PROJECT);
        let mut contract_yaml =
            fs::read_to_string(root.join("registry.yaml")).expect("SDMX contract reads");
        if live_source {
            contract_yaml = contract_yaml.replace("profile: snapshot", "profile: live-read-only");
        }
        let initial_contract =
            RegistryContract::parse_yaml(&contract_yaml).expect("SDMX contract parses");
        let runtime = RelayRuntime::parse_yaml(
            &fs::read_to_string(root.join("runtime.yaml")).expect("SDMX runtime reads"),
        )
        .expect("SDMX runtime parses");
        let temporary = tempfile::tempdir().expect("temporary project creates");
        let database = temporary.path().join("fixture.sqlite");
        let fixture = format!(
            "{}\n{suffix}",
            fs::read_to_string(root.join("fixture.sql")).expect("SDMX fixture reads")
        );
        materialize_fixture(&database, &fixture).expect("SDMX fixture materializes");
        let catalog = inspect_schema(
            &DatabaseProfile::Snapshot(
                CapturedSnapshot::capture(&database).expect("SDMX fixture captures"),
            ),
            &InspectionLimits {
                maximum_objects: 10_000,
                maximum_sql_bytes: 8 * 1024 * 1024,
                maximum_statement_steps: 1_000_000,
                timeout: Duration::from_secs(5),
            },
        )
        .expect("SDMX schema inspects");
        let source = initial_contract
            .sources
            .keys()
            .next()
            .expect("one source")
            .to_owned();
        let contract = RegistryContract::parse_yaml(
            &contract_yaml.replace(
                initial_contract
                    .sources
                    .get(&source)
                    .expect("source exists")
                    .expected_schema_fingerprint
                    .as_str(),
                &catalog.fingerprint,
            ),
        )
        .expect("SDMX contract parses with observed fixture fingerprint");
        let observed = [ObservedSourceSchema {
            source: source.clone(),
            fingerprint: catalog.fingerprint,
            views: catalog
                .objects
                .into_iter()
                .filter(|object| object.kind == SchemaObjectKind::View)
                .map(|object| ObservedView {
                    name: object.name,
                    columns: object
                        .columns
                        .into_iter()
                        .map(|column| ObservedColumn {
                            name: column.name,
                            declared_type: column.declared_type,
                            nullable: column.nullable,
                            primary_key: column.primary_key,
                        })
                        .collect(),
                })
                .collect(),
        }];
        let inventory_registry = compile_contract(&contract, &observed, CompileProfile::Production)
            .expect("SDMX inventory compiles");
        let inventory_digest =
            classification_inventory_digest(&inventory_registry).expect("SDMX inventory digests");
        let mut governed = governed_files(root, &contract);
        let review_path = &contract.classifications.provenance_ref;
        let review_bytes = governed
            .get(review_path)
            .expect("classification review is governed");
        let mut review = serde_norway::from_slice::<ClassificationReviewDocument>(review_bytes)
            .expect("classification review parses");
        review.classification_inventory_digest = inventory_digest;
        governed.insert(
            review_path.clone(),
            serde_norway::to_string(&review)
                .expect("classification review serializes")
                .into_bytes(),
        );
        let compiled = Arc::new(
            compile_contract_with_governed_files(
                &contract,
                &observed,
                CompileProfile::Production,
                &governed,
            )
            .unwrap_or_else(|report| panic!("SDMX project compiles: {report:?}")),
        );
        let artifacts = Arc::new(generate_artifacts(&compiled).expect("SDMX artifacts generate"));
        let sqlite = Arc::new(
            SqliteRuntime::open(
                &compiled,
                &BTreeMap::from([(
                    source,
                    RuntimeSourceBinding {
                        path: database.clone(),
                    },
                )]),
                SqliteRuntimeLimits {
                    request_timeout: Duration::from_millis(
                        runtime.limits.request_timeout_milliseconds,
                    ),
                    concurrent_queries: usize::try_from(runtime.limits.concurrent_queries)
                        .expect("concurrency fits"),
                },
            )
            .expect("SDMX runtime opens"),
        );
        let audit_path = temporary.path().join("audit.jsonl");
        let sink = audit_sink.unwrap_or_else(|| Arc::new(JsonlFileSink::new(audit_path.clone())));
        let chain = Arc::new(
            ChainState::bootstrap_unkeyed_dev_only(sink.as_ref())
                .await
                .expect("audit chain starts"),
        );
        let issuer = runtime
            .authentication
            .issuer
            .as_ref()
            .expect("SDMX example has a protected-dataflow issuer");
        let idp = MockIdp::start().await;
        let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        ));
        fetcher.ensure_key_set().await.expect("fixture JWKS loads");
        let mut verifier = oidc_verifier_config(idp.issuer(), vec![issuer.audience.clone()]);
        verifier.allowed_typ = vec!["at+jwt".into()];
        verifier.max_token_lifetime = Some(Duration::from_secs(3600));
        let authenticator = RelayAuthenticator::new(
            Arc::new(TokenVerifier::new(verifier, fetcher)),
            issuer.audience.clone(),
            Duration::from_secs(30),
        );
        let metadata = ServiceMetadata {
            authority: InstitutionMetadata {
                identifier: contract.registry.authority.identifier.clone(),
                name: contract.registry.authority.name.clone(),
            },
            operator: None,
            authoritative_scope: contract.registry.authoritative_scope.clone(),
            alignment_targets: compiled
                .alignment_targets
                .iter()
                .map(|target| AlignmentMetadata {
                    name: target.name.clone(),
                    version: target.version.clone(),
                    status: target.status.clone(),
                    cfr_target: target.cfr_target.clone(),
                })
                .collect(),
        };
        let quota = quota.or_else(|| {
            runtime.quotas.as_ref().map(|quota| QuotaConfig {
                requests_per_minute: quota.requests_per_minute,
                burst: quota.burst,
            })
        });
        let service = Arc::new(RelayService::new(
            compiled,
            Arc::clone(&artifacts),
            sqlite,
            Some(authenticator),
            RelayAudit::new(chain, sink),
            None,
            Duration::ZERO,
            Duration::from_millis(runtime.limits.request_timeout_milliseconds),
            quota,
            metadata,
        ));
        Self {
            app: router(service),
            audit_path,
            database,
            idp,
            audience: issuer.audience.clone(),
            _temporary: temporary,
        }
    }

    async fn get(
        &self,
        uri: &str,
        accept: Option<&str>,
        etag: Option<&str>,
    ) -> http::Response<Body> {
        self.get_with_token(uri, accept, etag, None).await
    }

    async fn get_with_token(
        &self,
        uri: &str,
        accept: Option<&str>,
        etag: Option<&str>,
        token: Option<&str>,
    ) -> http::Response<Body> {
        let mut request = Request::builder().uri(uri);
        if let Some(accept) = accept {
            request = request.header(ACCEPT, accept);
        }
        if let Some(etag) = etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(token) = token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        self.app
            .clone()
            .oneshot(request.body(Body::empty()).expect("request builds"))
            .await
            .expect("router responds")
    }

    fn token(&self, scope: &str, purpose: &str, authority: &str) -> String {
        self.token_with_claims(
            scope,
            Some(Value::String(purpose.to_owned())),
            Some(Value::String(authority.to_owned())),
        )
    }

    fn token_with_claims(
        &self,
        scope: &str,
        purpose: Option<Value>,
        authority: Option<Value>,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is valid")
            .as_secs();
        let mut claims = serde_json::json!({
            "iss": self.idp.issuer(),
            "aud": self.audience,
            "sub": "synthetic-statistics-client",
            "scope": scope,
            "iat": now,
            "nbf": now,
            "exp": now.saturating_add(900),
            "jti": format!("sdmx-{now}"),
        });
        let object = claims.as_object_mut().expect("claims are an object");
        if let Some(purpose) = purpose {
            object.insert("purpose".into(), purpose);
        }
        if let Some(authority) = authority {
            object.insert("area_authority".into(), authority);
        }
        sign_ed25519_compact_jwt(
            fixtures::ED25519_PRIVATE_JWK,
            "at+jwt",
            "registry-platform-testing-ed25519-1",
            claims,
        )
    }
}

#[tokio::test]
async fn governed_sdmx_refuses_an_unreviewed_source_code_without_disclosing_it() {
    let harness = Harness::open_with_fixture_suffix(
        "UPDATE source_labour_force_rates SET ref_area = 'UNREVIEWED-CANARY' WHERE ref_area = 'EX-A' AND sex = 'F' AND time_period = '2024-Q1';",
    )
    .await;
    let mut signatures = Vec::new();
    for uri in [
        "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/UNREVIEWED-CANARY.F?c%5BTIME_PERIOD%5D=2024-Q1",
        "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/ABSENT-CANARY.F?c%5BTIME_PERIOD%5D=2024-Q1",
        "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0?c%5BREF_AREA%5D=UNREVIEWED-CANARY&c%5BSEX%5D=F&c%5BTIME_PERIOD%5D=2024-Q1",
        "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0?c%5BREF_AREA%5D=ABSENT-CANARY&c%5BSEX%5D=F&c%5BTIME_PERIOD%5D=2024-Q1",
    ] {
        signatures.push(problem_signature(harness.get(uri, None, None).await).await);
    }
    assert!(signatures.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(signatures[0].0, StatusCode::BAD_REQUEST);
    assert_eq!(
        signatures[0].3.get("code").and_then(Value::as_str),
        Some("aggregate-data.invalid_request")
    );
    let audit = fs::read_to_string(&harness.audit_path).expect("audit reads");
    assert_eq!(audit.matches("\"phase\":\"refusal\"").count(), 4);
    assert!(!audit.contains("\"phase\":\"attempt\""));
    for value in ["UNREVIEWED-CANARY", "ABSENT-CANARY"] {
        assert!(!audit.contains(value));
    }
}

#[tokio::test]
async fn duplicate_observation_keys_fail_closed_across_page_boundaries() {
    let harness = Harness::open_with_fixture_suffix(
        r#"
DROP VIEW relay_labour_force_rates;
CREATE VIEW relay_labour_force_rates AS
SELECT ref_area, sex, time_period, obs_value, unit_measure
FROM source_labour_force_rates
UNION ALL
SELECT ref_area, sex, time_period, obs_value + 1.0, unit_measure
FROM source_labour_force_rates
WHERE ref_area = 'EX-A' AND sex = 'F' AND time_period = '2024-Q1';
"#,
    )
    .await;
    for uri in [
        "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?c%5BTIME_PERIOD%5D=2024-Q1&limit=1&offset=0".to_owned(),
        "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?c%5BTIME_PERIOD%5D=2024-Q1&limit=1&offset=1".to_owned(),
        "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0?limit=1&offset=2".to_owned(),
        "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0?limit=1&offset=100".to_owned(),
    ] {
        let response = harness
            .get(&uri, None, None)
            .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            json_body(response)
                .await
                .get("code")
                .and_then(Value::as_str),
            Some("internal.unhandled")
        );
    }
}

#[tokio::test]
async fn protected_structure_refusals_are_indistinguishable_and_value_free() {
    let harness = Harness::open().await;
    let protected = "/sdmx/v2/structure/dataflow/EXAMPLE_STAT/LABOUR_FORCE_AUTHORITY/1.0.0";
    let unknown = "/sdmx/v2/structure/dataflow/UNKNOWN/UNKNOWN/0.0.0";
    let authorized = harness.token(
        "statistics:labour-authority:read",
        "official-planning",
        "zone-a",
    );
    let expected = problem_signature(
        harness
            .get_with_token(unknown, None, None, Some(&authorized))
            .await,
    )
    .await;
    assert_eq!(expected.0, StatusCode::NOT_FOUND);

    let wrong_scope = harness.token("structure-scope-canary", "official-planning", "zone-a");
    let wrong_purpose = harness.token(
        "statistics:labour-authority:read",
        "structure-purpose-canary",
        "zone-a",
    );
    let missing_binding = harness.token_with_claims(
        "statistics:labour-authority:read",
        Some(Value::String("official-planning".into())),
        None,
    );
    for token in [&wrong_scope, &wrong_purpose, &missing_binding] {
        let actual = problem_signature(
            harness
                .get_with_token(protected, None, None, Some(token))
                .await,
        )
        .await;
        assert_eq!(actual, expected);
    }

    let audit = fs::read_to_string(&harness.audit_path).expect("audit reads");
    assert_eq!(audit.matches("\"phase\":\"refusal\"").count(), 4);
    for value in [
        "structure-scope-canary",
        "structure-purpose-canary",
        "UNKNOWN",
    ] {
        assert!(
            !audit.contains(value),
            "audit contains caller value {value}"
        );
    }
}

#[tokio::test]
async fn invalid_bearer_precedes_every_deferred_or_malformed_sdmx_surface() {
    let harness = Harness::open().await;
    let invalid = "invalid-bearer-canary";
    for path in [
        "/sdmx/v2/structure/unsupported/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0",
        "/sdmx/v2/structure/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0?unknown=true",
        "/sdmx/v2/schema/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0",
        "/sdmx/v2/availability/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/*/REF_AREA",
    ] {
        let response = harness
            .get_with_token(path, None, None, Some(invalid))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json_body(response).await.get("code").and_then(Value::as_str),
            Some("auth.invalid_credential")
        );
    }
    let audit = fs::read_to_string(&harness.audit_path).expect("audit reads");
    assert_eq!(audit.matches("\"phase\":\"refusal\"").count(), 4);
    assert!(!audit.contains(invalid));
}

#[tokio::test]
async fn sdmx_attempt_audit_failure_prevents_sqlite_execution() {
    let sink = Arc::new(ControlledAuditSink::new(1));
    let harness = Harness::open_with_audit(Arc::clone(&sink) as Arc<dyn AuditSink>).await;
    fs::remove_file(&harness.database).expect("bound source fixture removes");

    let response = harness
        .get(
            "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?c%5BTIME_PERIOD%5D=2024-Q1",
            None,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(response)
            .await
            .get("code")
            .and_then(Value::as_str),
        Some("audit.unavailable")
    );
    assert_eq!(
        sink.writes(),
        1,
        "the removed source is an execution tripwire: source access would trigger a terminal audit"
    );
}

#[tokio::test]
async fn sdmx_terminal_audit_failure_discards_held_representation_bytes() {
    const DATA_CANARY: &str = "987654.321";
    const DATA_URI: &str = "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?c%5BTIME_PERIOD%5D=2024-Q1";
    const STRUCTURE_URI: &str =
        "/sdmx/v2/structure/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0";

    for (uri, accept, canary, fixture_suffix) in [
        (
            DATA_URI,
            Some("application/vnd.sdmx.data+json;version=2.1.0"),
            DATA_CANARY,
            "UPDATE source_labour_force_rates SET obs_value = 987654.321 WHERE ref_area = 'EX-A' AND sex = 'F' AND time_period = '2024-Q1';",
        ),
        (
            DATA_URI,
            Some("application/vnd.sdmx.data+csv;version=2.1.0"),
            DATA_CANARY,
            "UPDATE source_labour_force_rates SET obs_value = 987654.321 WHERE ref_area = 'EX-A' AND sex = 'F' AND time_period = '2024-Q1';",
        ),
        (
            STRUCTURE_URI,
            None,
            "LABOUR_FORCE_PARTICIPATION",
            "",
        ),
    ] {
        let sink = Arc::new(ControlledAuditSink::new(2));
        let harness = Harness::open_with_fixture_suffix_and_audit(
            fixture_suffix,
            Arc::clone(&sink) as Arc<dyn AuditSink>,
        )
        .await;

        let response = harness.get(uri, accept, None).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = body_bytes(response).await;
        let problem: Value = serde_json::from_slice(&bytes).expect("audit problem is JSON");
        assert_eq!(
            problem.get("code").and_then(Value::as_str),
            Some("audit.unavailable")
        );
        let wire = String::from_utf8(bytes).expect("audit problem is UTF-8");
        assert!(
            !wire.contains(canary),
            "terminal audit failure must discard held SDMX bytes containing {canary}"
        );
        assert_eq!(
            sink.writes(),
            2,
            "the release gate must stop at the failed terminal audit"
        );
    }
}

#[tokio::test]
async fn governed_sdmx_data_structure_formats_and_bounds_use_the_real_router() {
    let harness = Harness::open().await;

    let discovery = harness.get("/v2", None, None).await;
    assert_eq!(discovery.status(), StatusCode::OK);
    let discovery = json_body(discovery).await;
    assert_eq!(
        discovery
            .pointer("/capabilities/0/family")
            .and_then(Value::as_str),
        Some("aggregate-data")
    );
    assert_eq!(
        discovery
            .pointer("/capabilities/0/structureReference")
            .and_then(Value::as_str),
        Some(
            "https://statistics.example.invalid/registry/sdmx/v2/structure/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0"
        )
    );
    assert_eq!(
        discovery["alignmentTargets"]
            .as_array()
            .expect("alignment targets")
            .iter()
            .map(|target| {
                (
                    target["name"].as_str().expect("target name"),
                    target["version"].as_str().expect("target version"),
                )
            })
            .collect::<Vec<_>>(),
        [
            ("sdmx-rest", "2.2.2"),
            ("sdmx-json", "2.1.0"),
            ("sdmx-csv", "2.1.0"),
        ]
    );
    assert_eq!(
        discovery.pointer("/capabilities/0/processingHandling"),
        Some(&serde_json::json!("public"))
    );
    assert_eq!(
        discovery.pointer("/capabilities/0/disclosureHandling"),
        Some(&serde_json::json!("public"))
    );

    let structure = harness
        .get(
            "/sdmx/v2/structure/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0",
            None,
            None,
        )
        .await;
    assert_eq!(structure.status(), StatusCode::OK);
    assert_eq!(
        structure
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/vnd.sdmx.structure+json;version=2.0.0")
    );
    let structure_etag = structure
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("public structure has ETag")
        .to_owned();
    assert_public_cache_headers(structure.headers(), &structure_etag);
    let structure = json_body(structure).await;
    assert_eq!(
        structure.pointer("/meta/schema").and_then(Value::as_str),
        Some("https://json.sdmx.org/2.0.0/sdmx-json-structure-schema.json")
    );
    assert_eq!(
        structure.pointer("/meta/sender/id").and_then(Value::as_str),
        Some("REGISTRY_RELAY")
    );
    assert_eq!(
        structure
            .pointer("/data/dataflows/0/id")
            .and_then(Value::as_str),
        Some("LABOUR_FORCE_PARTICIPATION")
    );
    assert!(structure.pointer("/data/dataStructures").is_none());
    let structure_not_modified = harness
        .get(
            "/sdmx/v2/structure/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0",
            None,
            Some(&structure_etag),
        )
        .await;
    assert_eq!(structure_not_modified.status(), StatusCode::NOT_MODIFIED);
    assert_public_cache_headers(structure_not_modified.headers(), &structure_etag);

    let data_structure = harness
        .get(
            "/sdmx/v2/structure/datastructure/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION_DSD/1.0.0?references=none",
            None,
            None,
        )
        .await;
    assert_eq!(data_structure.status(), StatusCode::OK);
    let data_structure = json_body(data_structure).await;
    assert!(data_structure.pointer("/data/dataflows").is_none());
    assert_eq!(
        data_structure
            .pointer("/data/dataStructures/0/dataStructureComponents/dimensionList/dimensions",)
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(
        data_structure
            .pointer("/data/dataStructures/0/dataStructureComponents/dimensionList/dimensions")
            .and_then(Value::as_array)
            .map(|dimensions| {
                dimensions
                    .iter()
                    .filter_map(|dimension| dimension.get("position").and_then(Value::as_u64))
                    .collect::<Vec<_>>()
            }),
        Some(vec![0, 1])
    );
    assert_eq!(
        data_structure
            .pointer(
                "/data/dataStructures/0/dataStructureComponents/dimensionList/timeDimension/id",
            )
            .and_then(Value::as_str),
        Some("TIME_PERIOD")
    );
    assert_eq!(
        data_structure
            .pointer("/data/dataStructures/0/dataStructureComponents/measureList/measures/0/id")
            .and_then(Value::as_str),
        Some("PARTICIPATION_RATE")
    );

    let structure_reader = harness.token(
        "statistics:labour-authority:read",
        "official-planning",
        "zone-a",
    );
    let protected_structure_path =
        "/sdmx/v2/structure/dataflow/EXAMPLE_STAT/LABOUR_FORCE_AUTHORITY/1.0.0";
    let protected_structure_missing = harness.get(protected_structure_path, None, None).await;
    assert_eq!(
        protected_structure_missing.status(),
        StatusCode::UNAUTHORIZED
    );
    let unrelated_structure_reader =
        harness.token("statistics:unrelated:read", "official-planning", "zone-a");
    let protected_structure_denied = harness
        .get_with_token(
            protected_structure_path,
            None,
            None,
            Some(&unrelated_structure_reader),
        )
        .await;
    assert_eq!(protected_structure_denied.status(), StatusCode::NOT_FOUND);
    let protected_structure = harness
        .get_with_token(
            protected_structure_path,
            None,
            None,
            Some(&structure_reader),
        )
        .await;
    assert_eq!(protected_structure.status(), StatusCode::OK);
    assert_eq!(
        protected_structure
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(protected_structure.headers().get(ETAG).is_none());
    let crossed_structure = harness
        .get_with_token(
            "/sdmx/v2/structure/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION_DSD/1.0.0",
            None,
            None,
            Some(&structure_reader),
        )
        .await;
    assert_eq!(crossed_structure.status(), StatusCode::NOT_FOUND);

    for path in [
        "/sdmx/v2/schema/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0",
        "/sdmx/v2/schema/dataflow/UNKNOWN/UNKNOWN/0.0.0",
        "/sdmx/v2/availability/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/*/REF_AREA",
    ] {
        let deferred = harness.get(path, None, None).await;
        assert_eq!(deferred.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            json_body(deferred)
                .await
                .get("code")
                .and_then(Value::as_str),
            Some("aggregate-data.not_implemented")
        );
    }

    let filtered_uri = "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?c%5BTIME_PERIOD%5D=ge%3A2024-Q1%2Ble%3A2024-Q2&dimensionAtObservation=AllDimensions";
    let first = harness.get(filtered_uri, None, None).await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        first
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/vnd.sdmx.data+json;version=2.1.0")
    );
    let etag = first
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("snapshot response has ETag")
        .to_owned();
    assert_public_cache_headers(first.headers(), &etag);
    let first = json_body(first).await;
    assert_eq!(
        first.get("$schema").and_then(Value::as_str),
        Some("https://json.sdmx.org/2.1/sdmx-json-data-schema.json")
    );
    assert_eq!(
        first.pointer("/meta/sender/id").and_then(Value::as_str),
        Some("REGISTRY_RELAY")
    );
    assert!(first
        .pointer("/meta/id")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.contains('.')));
    assert_eq!(
        first
            .pointer("/data/structures/0/links/0/urn")
            .and_then(Value::as_str),
        Some(
            "urn:sdmx:org.sdmx.infomodel.datastructure.Dataflow=LABOUR_STATISTICS:LABOUR_FORCE_PARTICIPATION(1.0.0)"
        )
    );
    assert_eq!(
        first
            .pointer("/data/structures/0/dataSets/0")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        first
            .pointer("/data/dataSets/0/observations")
            .and_then(Value::as_object)
            .map(serde_json::Map::len),
        Some(2)
    );
    assert_eq!(
        first
            .pointer("/data/structures/0/dimensions/observation")
            .and_then(Value::as_array)
            .map(|dimensions| {
                dimensions
                    .iter()
                    .map(|dimension| {
                        (
                            dimension.get("id").and_then(Value::as_str),
                            dimension.get("keyPosition").and_then(Value::as_u64),
                        )
                    })
                    .collect::<Vec<_>>()
            }),
        Some(vec![
            (Some("REF_AREA"), Some(0)),
            (Some("SEX"), Some(1)),
            (Some("TIME_PERIOD"), Some(2)),
        ])
    );
    let not_modified = harness.get(filtered_uri, None, Some(&etag)).await;
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert_public_cache_headers(not_modified.headers(), &etag);

    let preferred_json = harness
        .get(
            filtered_uri,
            Some("application/vnd.sdmx.data+csv;version=2.1.0;q=0.1, application/vnd.sdmx.data+json;version=2.1.0;q=1"),
            None,
        )
        .await;
    assert_eq!(
        preferred_json
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/vnd.sdmx.data+json;version=2.1.0")
    );
    let unacceptable = harness
        .get(
            filtered_uri,
            Some("application/vnd.sdmx.data+json;version=2.1.0;q=0.0"),
            None,
        )
        .await;
    assert_eq!(unacceptable.status(), StatusCode::NOT_ACCEPTABLE);
    let unsupported_csv_parameter = harness
        .get(
            filtered_uri,
            Some("application/vnd.sdmx.data+csv;version=2.1.0;labels=name"),
            None,
        )
        .await;
    assert_eq!(
        unsupported_csv_parameter.status(),
        StatusCode::NOT_ACCEPTABLE
    );

    let overlapping_constraint = harness
        .get(
            "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?c%5BREF_AREA%5D=EX-B&limit=1",
            None,
            None,
        )
        .await;
    assert_eq!(overlapping_constraint.status(), StatusCode::BAD_REQUEST);
    let time_in_positional_key = harness
        .get(
            "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F.2024-Q1",
            None,
            None,
        )
        .await;
    assert_eq!(time_in_positional_key.status(), StatusCode::BAD_REQUEST);
    let empty_internal_key = harness
        .get(
            "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.",
            None,
            None,
        )
        .await;
    assert_eq!(empty_internal_key.status(), StatusCode::BAD_REQUEST);
    let raw_plus = harness
        .get(
            "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?c%5BTIME_PERIOD%5D=ge%3A2024-Q1+le%3A2024-Q2&limit=2",
            None,
            None,
        )
        .await;
    assert_eq!(raw_plus.status(), StatusCode::OK);

    let omitted_key = harness
        .get(
            "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0?c%5BREF_AREA%5D=EX-A&c%5BSEX%5D=F&c%5BTIME_PERIOD%5D=2024-Q1",
            None,
            None,
        )
        .await;
    assert_eq!(omitted_key.status(), StatusCode::OK);
    let omitted_bytes = body_bytes(omitted_key).await;
    let omitted_key: Value =
        serde_json::from_slice(&omitted_bytes).expect("series response is JSON");
    assert_eq!(
        omitted_key
            .pointer("/data/dataSets/0/series")
            .and_then(Value::as_object)
            .map(serde_json::Map::len),
        Some(1)
    );

    let csv = harness
        .get(
            filtered_uri,
            Some("application/vnd.sdmx.data+csv;version=2.1.0"),
            None,
        )
        .await;
    assert_eq!(csv.status(), StatusCode::OK);
    let csv = String::from_utf8(body_bytes(csv).await).expect("CSV is UTF-8");
    assert!(csv.starts_with(
        "STRUCTURE,STRUCTURE_ID,ACTION,REF_AREA,SEX,TIME_PERIOD,PARTICIPATION_RATE,UNIT_MEASURE\n"
    ));
    assert!(csv.contains(
        "dataflow,LABOUR_STATISTICS:LABOUR_FORCE_PARTICIPATION(1.0.0),R,EX-A,F,2024-Q1,61.2,PERCENT"
    ));

    let too_broad = harness
        .get(
            "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/*",
            None,
            None,
        )
        .await;
    assert_eq!(too_broad.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        json_body(too_broad)
            .await
            .get("code")
            .and_then(Value::as_str),
        Some("aggregate-data.too_large")
    );

    let empty = harness
        .get(
            "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-B.F?c%5BTIME_PERIOD%5D=2024-Q2&limit=1",
            None,
            None,
        )
        .await;
    assert_eq!(empty.status(), StatusCode::NO_CONTENT);
    let empty_etag = empty
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("empty public snapshot response has ETag")
        .to_owned();
    assert_public_cache_headers(empty.headers(), &empty_etag);
    let empty_not_modified = harness
        .get(
            "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-B.F?c%5BTIME_PERIOD%5D=2024-Q2&limit=1",
            None,
            Some(&empty_etag),
        )
        .await;
    assert_eq!(empty_not_modified.status(), StatusCode::NOT_MODIFIED);
    assert_public_cache_headers(empty_not_modified.headers(), &empty_etag);

    let unsupported = harness
        .get(
            "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/*?updatedAfter=2024-01-01T00%3A00%3A00Z",
            None,
            None,
        )
        .await;
    assert_eq!(unsupported.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        json_body(unsupported)
            .await
            .get("code")
            .and_then(Value::as_str),
        Some("aggregate-data.not_implemented")
    );
    let unsupported_references = harness
        .get(
            "/sdmx/v2/structure/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0?references=all",
            None,
            None,
        )
        .await;
    assert_eq!(unsupported_references.status(), StatusCode::NOT_IMPLEMENTED);
    let malformed_structure_query = harness
        .get(
            "/sdmx/v2/structure/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0?unknown=true",
            None,
            None,
        )
        .await;
    assert_eq!(malformed_structure_query.status(), StatusCode::BAD_REQUEST);

    let protected_uri = "/sdmx/v2/data/dataflow/EXAMPLE_STAT/LABOUR_FORCE_AUTHORITY/1.0.0/*?limit=4&dimensionAtObservation=AllDimensions";
    let missing = harness.get(protected_uri, None, None).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let wrong_scope = harness.token("statistics:unrelated:read", "official-planning", "zone-a");
    let denied = harness
        .get_with_token(protected_uri, None, None, Some(&wrong_scope))
        .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let wrong_purpose = harness.token(
        "statistics:labour-authority:read",
        "commercial-profiling",
        "zone-a",
    );
    let denied = harness
        .get_with_token(protected_uri, None, None, Some(&wrong_purpose))
        .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let zone_a = harness.token(
        "statistics:labour-authority:read",
        "official-planning",
        "zone-a",
    );
    let confined = harness
        .get_with_token(protected_uri, None, None, Some(&zone_a))
        .await;
    assert_eq!(confined.status(), StatusCode::OK);
    assert_eq!(
        confined
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let confined_wire =
        String::from_utf8(body_bytes(confined).await).expect("protected JSON is UTF-8");
    assert!(confined_wire.contains("EX-A"));
    assert!(!confined_wire.contains("EX-B"));
    assert!(!confined_wire.contains("zone-a"));
    let protected_empty = harness
        .get_with_token(
            "/sdmx/v2/data/dataflow/EXAMPLE_STAT/LABOUR_FORCE_AUTHORITY/1.0.0/EX-B.F?limit=1",
            None,
            None,
            Some(&zone_a),
        )
        .await;
    assert_eq!(protected_empty.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        protected_empty
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(protected_empty.headers().get(ETAG).is_none());

    let audit = fs::read_to_string(&harness.audit_path).expect("audit reads");
    for value in ["EX-A", "2024-Q1", "61.2", "PERCENT", "zone-a"] {
        assert!(
            !audit.contains(value),
            "audit must not contain statistical value {value}"
        );
    }
    assert!(audit.contains("labour-force-participation.statistics.read"));
}

#[tokio::test]
async fn canonical_structure_uses_the_operation_quota_and_live_sources_are_never_cacheable() {
    let quota_harness = Harness::open_with_options(
        "",
        false,
        Some(QuotaConfig {
            requests_per_minute: 1,
            burst: 1,
        }),
        None,
    )
    .await;
    let structure_path =
        "/sdmx/v2/structure/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0";
    let structure = quota_harness.get(structure_path, None, None).await;
    assert_eq!(structure.status(), StatusCode::OK);
    let audit = fs::read_to_string(&quota_harness.audit_path).expect("structure audit reads");
    let phases = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| {
            event
                .pointer("/record/operationIdentifier")
                .and_then(Value::as_str)
                == Some("labour-force-participation.statistics.read")
        })
        .filter_map(|event| {
            event
                .pointer("/record/phase")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    assert_eq!(phases, ["attempt", "terminal"]);
    assert_eq!(
        quota_harness
            .get(
                "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F.2024-Q1?limit=1",
                None,
                None,
            )
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    let live_harness = Harness::open_with_options("", true, None, None).await;
    let live_structure = live_harness.get(structure_path, None, None).await;
    assert_eq!(live_structure.status(), StatusCode::OK);
    assert_eq!(
        live_structure
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(live_structure.headers().get(ETAG).is_none());
}

async fn json_body(response: http::Response<Body>) -> Value {
    let bytes = body_bytes(response).await;
    serde_json::from_slice(&bytes).expect("response is JSON")
}

async fn body_bytes(response: http::Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("body reads")
        .to_vec()
}

async fn problem_signature(
    response: http::Response<Body>,
) -> (StatusCode, Option<String>, Option<String>, Value) {
    let status = response.status();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let cache_control = response
        .headers()
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut body = json_body(response).await;
    body.as_object_mut()
        .expect("problem is an object")
        .remove("traceId");
    (status, content_type, cache_control, body)
}

fn assert_public_cache_headers(headers: &http::HeaderMap, etag: &str) {
    assert_eq!(
        headers.get(ETAG).and_then(|value| value.to_str().ok()),
        Some(etag)
    );
    assert_eq!(
        headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("public, no-cache")
    );
    assert_eq!(
        headers.get(VARY).and_then(|value| value.to_str().ok()),
        Some("Accept, Authorization")
    );
}

fn governed_files(root: &Path, contract: &RegistryContract) -> GovernedFileSet {
    let mut paths = BTreeSet::new();
    paths.insert(contract.registry.identifier_lifecycle_policy_ref.clone());
    paths.insert(contract.classifications.provenance_ref.clone());
    let review = serde_norway::from_slice::<ClassificationReviewDocument>(
        &fs::read(root.join(&contract.classifications.provenance_ref))
            .expect("classification review reads"),
    )
    .expect("classification review parses");
    paths.insert(review.rationale_ref);
    if let Some(generated) = review.generated_identification {
        paths.insert(generated.report_ref);
    }
    for dataset in &contract.statistical_datasets {
        for (_, dimension) in dataset.dimensions.iter() {
            if let Some(path) = &dimension.vocabulary {
                paths.insert(path.clone());
            }
        }
        for (_, attribute) in dataset.attributes.iter() {
            if let Some(path) = &attribute.vocabulary {
                paths.insert(path.clone());
            }
        }
        for processing in &dataset.processing_descriptions {
            paths.insert(processing.legal_basis_ref.clone());
            paths.insert(processing.dpv_profile_ref.clone());
        }
    }
    paths
        .into_iter()
        .map(|path| {
            let content = fs::read(root.join(&path))
                .unwrap_or_else(|error| panic!("governed file {path} reads: {error}"));
            (path, content)
        })
        .collect()
}
