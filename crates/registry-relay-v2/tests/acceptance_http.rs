// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use bytes::Bytes;
use futures::stream;
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG, VARY};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
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
use registry_relay_v2::compiler::{compile_contract_with_governed_files, GovernedFileSet};
use registry_relay_v2::contract::{RegistryContract, RelayRuntime};
use registry_relay_v2::identification::parse_classification_review_yaml;
use registry_relay_v2::model::{
    CompileProfile, ObservedColumn, ObservedSourceSchema, ObservedView,
};
use registry_relay_v2::server::{
    router, AlignmentMetadata, InstitutionMetadata, QuotaConfig, RelayService, ServiceMetadata,
};
use registry_relay_v2::sqlite_runtime::{RuntimeSourceBinding, SqliteRuntime, SqliteRuntimeLimits};
use serde::Deserialize;
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt as _;

const ACCEPTANCE_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../products/relay-v2/acceptance"
);
const PROJECTS: [&str; 3] = ["social-assistance", "business-registry", "civil-event"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Journey {
    schema_version: String,
    registry: String,
    #[serde(default)]
    authorizations: BTreeMap<String, AuthorizationFixture>,
    steps: Vec<JourneyStep>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuthorizationFixture {
    principal: String,
    scopes: BTreeSet<String>,
    #[serde(default)]
    claims: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct JourneyStep {
    id: String,
    #[serde(default)]
    authorization_fixture: Option<String>,
    request: JourneyRequest,
    expect: JourneyExpectation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct JourneyRequest {
    method: String,
    path: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    query: BTreeMap<String, Value>,
    #[serde(default)]
    body: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct JourneyExpectation {
    status: u16,
    #[serde(default)]
    capability_patterns: Vec<String>,
    #[serde(default)]
    absent_capability_patterns: Vec<String>,
    #[serde(default)]
    item_count: Option<usize>,
    #[serde(default)]
    next_cursor: Option<String>,
    #[serde(default)]
    registry_core_required: bool,
    #[serde(default)]
    domain_data_keys: Vec<String>,
    #[serde(default)]
    record_identifier: Option<String>,
    #[serde(default)]
    cache: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    route_absent: bool,
    #[serde(default)]
    equivalence_class: Option<String>,
    #[serde(default)]
    absent_everywhere: Vec<String>,
    #[serde(default)]
    records_equivalent_to: Option<String>,
    #[serde(default)]
    body_empty: bool,
    #[serde(default)]
    etag_same_as: Option<String>,
}

struct ProjectHarness {
    app: axum::Router,
    service: Arc<RelayService>,
    contract: RegistryContract,
    runtime: RelayRuntime,
    database: PathBuf,
    idp: Option<MockIdp>,
    _temp: TempDir,
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

#[tokio::test]
async fn all_three_registry_http_journeys_use_the_real_router() {
    let selected = std::env::var("RELAY_V2_ACCEPTANCE_PROJECT").ok();
    if let Some(selected) = &selected {
        assert!(
            PROJECTS.contains(&selected.as_str()),
            "selected acceptance project is unknown"
        );
    }
    for project in PROJECTS.into_iter().filter(|project| {
        selected
            .as_deref()
            .is_none_or(|selected| selected == *project)
    }) {
        let mut harness = ProjectHarness::open(project).await;
        let journey: Journey = serde_norway::from_slice(
            &fs::read(project_root(project).join("expected-http.yaml")).expect("journey reads"),
        )
        .expect("journey parses");
        assert_eq!(
            journey.schema_version,
            "relay.registrystack.org/http-journey/v1alpha1"
        );
        assert_eq!(
            journey.registry,
            harness.contract.registry.registry_identifier
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener binds");
        let address = listener.local_addr().expect("loopback address resolves");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let app = harness.app.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("loopback client builds");
        let mut equivalence_classes = BTreeMap::new();
        let mut response_documents = BTreeMap::new();
        let mut etags = BTreeMap::new();
        for step in journey.steps {
            let request = harness.request_with_observations(
                &step,
                &journey.authorizations,
                &response_documents,
                &etags,
            );
            let response = send_loopback_request(&client, address, request)
                .await
                .unwrap_or_else(|error| panic!("{project}/{} request failed: {error}", step.id));
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes().await.expect("response body reads");
            assert_eq!(
                status,
                StatusCode::from_u16(step.expect.status).expect("expected status is valid"),
                "{project}/{} returned the wrong status; response body withheld",
                step.id
            );
            if let Some(reference) = &step.expect.etag_same_as {
                assert_eq!(
                    headers.get(ETAG).and_then(|value| value.to_str().ok()),
                    etags.get(reference).map(String::as_str),
                    "{project}/{} ETag must match {reference}",
                    step.id
                );
            }
            if let Some(etag) = headers.get(ETAG).and_then(|value| value.to_str().ok()) {
                etags.insert(step.id.clone(), etag.to_owned());
            }
            assert_expectations(project, &step, &headers, &body, &mut equivalence_classes);
            if !body.is_empty() {
                let document: Value = serde_json::from_slice(&body).expect("response is JSON");
                if let Some(reference) = &step.expect.records_equivalent_to {
                    let expected = response_documents
                        .get(reference)
                        .unwrap_or_else(|| panic!("referenced response {reference} exists"));
                    assert_eq!(
                        normalized_records(&document),
                        normalized_records(expected),
                        "{project}/{} Record values must match {reference}",
                        step.id
                    );
                }
                response_documents.insert(step.id.clone(), document);
            }
        }
        shutdown_tx.send(()).expect("loopback server is running");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("loopback server shuts down before timeout")
            .expect("loopback server task completes")
            .expect("loopback server shuts down cleanly");
        if let Some(idp) = harness.idp.take() {
            idp.stop().await;
        }
    }
}

async fn send_loopback_request(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    request: Request<Body>,
) -> reqwest::Result<reqwest::Response> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 1024 * 1024)
        .await
        .expect("journey request body reads");
    client
        .request(
            reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
                .expect("journey method converts"),
            format!("http://{address}{}", parts.uri),
        )
        .headers(parts.headers)
        .body(body)
        .send()
        .await
}

#[tokio::test]
async fn readiness_fails_value_free_for_missing_replaced_and_drifted_sources() {
    for project in ["business-registry", "social-assistance"] {
        let harness = ProjectHarness::open(project).await;
        assert!(harness.service.is_ready().await, "{project} starts ready");
        fs::remove_file(&harness.database).expect("source removes");
        assert_unready(&harness, project, "missing").await;

        let harness = ProjectHarness::open(project).await;
        assert!(harness.service.is_ready().await, "{project} starts ready");
        let old = harness.database.with_extension("old.sqlite");
        fs::rename(&harness.database, &old).expect("bound source moves");
        materialize_fixture(
            &harness.database,
            &fs::read_to_string(project_root(project).join("fixture.sql"))
                .expect("fixture SQL reads"),
        )
        .expect("replacement materializes");
        assert_unready(&harness, project, "replaced").await;

        let harness = ProjectHarness::open(project).await;
        assert!(harness.service.is_ready().await, "{project} starts ready");
        let drift = harness.database.with_extension("drift.sqlite");
        let mut changed_sql = fs::read_to_string(project_root(project).join("fixture.sql"))
            .expect("fixture SQL reads");
        changed_sql.push_str("\nCREATE TABLE readiness_schema_drift (id TEXT);\n");
        materialize_fixture(&drift, &changed_sql).expect("drifted source materializes");
        make_writable(&harness.database);
        fs::copy(&drift, &harness.database).expect("source drifts in place");
        make_read_only(&harness.database);
        assert_unready(&harness, project, "drifted").await;
    }

    let harness = ProjectHarness::open("business-registry").await;
    fs::write(
        format!("{}-wal", harness.database.display()),
        b"synthetic uncheckpointed sidecar",
    )
    .expect("snapshot sidecar writes");
    assert_unready(&harness, "business-registry", "sidecar").await;
}

#[tokio::test]
async fn social_live_update_is_consistent_and_truthfully_unversioned() {
    let harness = ProjectHarness::open("social-assistance").await;
    let journey: Journey = serde_norway::from_slice(
        &fs::read(project_root("social-assistance").join("expected-http.yaml"))
            .expect("journey reads"),
    )
    .expect("journey parses");
    let step = journey
        .steps
        .iter()
        .find(|step| step.id == "lookup-default")
        .expect("default lookup exists");

    let before = harness
        .app
        .clone()
        .oneshot(harness.request(step, &journey.authorizations))
        .await
        .expect("router responds");
    assert_eq!(before.status(), StatusCode::OK);
    assert_eq!(
        before.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert!(!before.headers().contains_key(ETAG));
    let before = to_bytes(before.into_body(), 1024 * 1024)
        .await
        .expect("response reads");
    let before: Value = serde_json::from_slice(&before).expect("response parses");
    assert_eq!(
        before.pointer("/data/revisionIdentifier"),
        Some(&json!("3"))
    );
    assert_eq!(
        before.pointer("/data/domainData/enrolmentStatus"),
        Some(&json!("ELIGIBLE"))
    );

    make_writable(&harness.database);
    materialize_fixture(
        &harness.database,
        "UPDATE source_assistance_enrolments \
         SET record_revision = '4', enrolment_status = 'SUSPENDED', valid_through = NULL \
         WHERE enrolment_reference = 'ENROL-SYNTH-0001';",
    )
    .expect("trusted publisher update commits");

    let after = harness
        .app
        .clone()
        .oneshot(harness.request(step, &journey.authorizations))
        .await
        .expect("router responds");
    assert_eq!(after.status(), StatusCode::OK);
    assert_eq!(
        after.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert!(!after.headers().contains_key(ETAG));
    let after = to_bytes(after.into_body(), 1024 * 1024)
        .await
        .expect("response reads");
    let after: Value = serde_json::from_slice(&after).expect("response parses");
    assert_eq!(after.pointer("/data/revisionIdentifier"), Some(&json!("4")));
    assert_eq!(
        after.pointer("/data/domainData/enrolmentStatus"),
        Some(&json!("SUSPENDED"))
    );
    assert!(after.pointer("/data/domainData/validThrough").is_none());
    assert_eq!(
        after.pointer("/meta/sourceRevision"),
        Some(&json!({"profile": "live", "status": "unversioned", "value": null}))
    );
}

#[tokio::test]
async fn trusted_purpose_and_row_binding_refusals_use_only_verified_claims() {
    let harness = ProjectHarness::open("social-assistance").await;
    let journey: Journey = serde_norway::from_slice(
        &fs::read(project_root("social-assistance").join("expected-http.yaml"))
            .expect("journey reads"),
    )
    .expect("journey parses");
    for (step_id, status) in [
        ("missing-purpose", StatusCode::FORBIDDEN),
        ("wrong-purpose", StatusCode::FORBIDDEN),
        ("missing-binding", StatusCode::FORBIDDEN),
        ("wrong-binding", StatusCode::NOT_FOUND),
    ] {
        let step = journey
            .steps
            .iter()
            .find(|step| step.id == step_id)
            .unwrap_or_else(|| panic!("{step_id} journey exists"));
        let response = harness
            .app
            .clone()
            .oneshot(harness.request(step, &journey.authorizations))
            .await
            .expect("router responds");
        let expected_code = if status == StatusCode::FORBIDDEN {
            "consultation.denied"
        } else {
            "consultation.unresolved"
        };
        assert_problem_code(response, status, expected_code).await;
    }
}

#[tokio::test]
async fn audit_attempt_failure_prevents_source_access() {
    let sink = Arc::new(ControlledAuditSink::new(1));
    let harness = ProjectHarness::open_with_audit(
        "business-registry",
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
    )
    .await;
    let response = harness
        .app
        .oneshot(
            Request::builder()
                .uri("/v2/resources/registered-business/records/BIZ-SYNTH-0001")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    let body = response_body(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(
        body.get("code").and_then(Value::as_str),
        Some("audit.unavailable")
    );
    assert_eq!(
        sink.writes(),
        1,
        "source path must stop at failed attempt audit"
    );
}

#[tokio::test]
async fn audit_terminal_failure_discards_held_record_bytes() {
    let sink = Arc::new(ControlledAuditSink::new(2));
    let harness = ProjectHarness::open_with_audit(
        "business-registry",
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
    )
    .await;
    let response = harness
        .app
        .oneshot(
            Request::builder()
                .uri("/v2/resources/registered-business/records/BIZ-SYNTH-0001")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    let body = response_body(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(
        body.get("code").and_then(Value::as_str),
        Some("audit.unavailable")
    );
    let wire = serde_json::to_string(&body).expect("problem serializes");
    assert!(!wire.contains("BIZ-SYNTH-0001"));
    assert!(!wire.contains("Example Orchard Cooperative"));
    assert_eq!(
        sink.writes(),
        2,
        "release must stop at failed terminal audit"
    );
}

#[tokio::test]
async fn real_jwt_path_rejects_malformed_audience_time_and_expired_tokens() {
    let harness = ProjectHarness::open("social-assistance").await;
    let journey: Journey = serde_norway::from_slice(
        &fs::read(project_root("social-assistance").join("expected-http.yaml"))
            .expect("journey reads"),
    )
    .expect("journey parses");
    let step = journey
        .steps
        .iter()
        .find(|step| step.id == "lookup-success")
        .expect("protected lookup journey exists");
    let fixture_id = step
        .authorization_fixture
        .as_deref()
        .expect("lookup has authorization fixture");
    let fixture = journey
        .authorizations
        .get(fixture_id)
        .expect("authorization fixture resolves");

    let malformed = request_with_bearer(&harness, step, &journey.authorizations, "malformed");
    assert_problem_code(
        harness
            .app
            .clone()
            .oneshot(malformed)
            .await
            .expect("router responds"),
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is valid")
        .as_secs();
    let expected_audience = &harness
        .runtime
        .authentication
        .issuer
        .as_ref()
        .expect("issuer exists")
        .audience;
    let multiple_audiences = harness.signed_token_with_audience(
        fixture_id,
        fixture,
        json!([expected_audience, "urn:example:secondary-audience"]),
        now,
        now,
        now.saturating_add(900),
    );
    assert_problem_code(
        harness
            .app
            .clone()
            .oneshot(request_with_bearer(
                &harness,
                step,
                &journey.authorizations,
                &multiple_audiences,
            ))
            .await
            .expect("router responds"),
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;

    let future_issued_at = now.saturating_add(300);
    let future_issued = harness.signed_token(
        fixture_id,
        fixture,
        expected_audience,
        future_issued_at,
        now,
        future_issued_at.saturating_add(900),
    );
    assert_problem_code(
        harness
            .app
            .clone()
            .oneshot(request_with_bearer(
                &harness,
                step,
                &journey.authorizations,
                &future_issued,
            ))
            .await
            .expect("router responds"),
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;

    let wrong_audience = harness.signed_token(
        fixture_id,
        fixture,
        "urn:example:wrong-audience",
        now,
        now,
        now.saturating_add(900),
    );
    assert_problem_code(
        harness
            .app
            .clone()
            .oneshot(request_with_bearer(
                &harness,
                step,
                &journey.authorizations,
                &wrong_audience,
            ))
            .await
            .expect("router responds"),
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;

    let issued_at = now.saturating_sub(1_000);
    let expired = harness.signed_token(
        fixture_id,
        fixture,
        &harness
            .runtime
            .authentication
            .issuer
            .as_ref()
            .expect("issuer exists")
            .audience,
        issued_at,
        issued_at,
        now.saturating_sub(120),
    );
    assert_problem_code(
        harness
            .app
            .clone()
            .oneshot(request_with_bearer(
                &harness,
                step,
                &journey.authorizations,
                &expired,
            ))
            .await
            .expect("router responds"),
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;
}

#[tokio::test]
async fn operation_bound_metadata_is_no_store_and_links_only_visible_artifacts() {
    let harness = ProjectHarness::open("social-assistance").await;
    let journey: Journey = serde_norway::from_slice(
        &fs::read(project_root("social-assistance").join("expected-http.yaml"))
            .expect("journey reads"),
    )
    .expect("journey parses");
    let step = journey
        .steps
        .iter()
        .find(|step| step.id == "lookup-success")
        .expect("protected lookup journey exists");
    let fixture_id = step
        .authorization_fixture
        .as_deref()
        .expect("lookup has authorization fixture");
    let fixture = journey
        .authorizations
        .get(fixture_id)
        .expect("authorization fixture resolves");
    let token = harness.token(fixture_id, fixture);

    for (uri, capability_pointer) in [
        ("/v2", "/capabilities/0"),
        ("/v2/resources", "/items/0/capabilities/0"),
        ("/v2/resources/assistance-enrolment", "/data/capabilities/0"),
    ] {
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("metadata request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK, "{uri} status");
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "{uri} cache policy"
        );
        assert!(!response.headers().contains_key(ETAG), "{uri} omits ETag");
        let document: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("metadata body reads"),
        )
        .expect("metadata is JSON");
        let capability = document
            .pointer(capability_pointer)
            .and_then(Value::as_object)
            .expect("visible capability is linked");
        for reference in [
            "schemaReference",
            "semanticModelReference",
            "contextReference",
            "processingReference",
        ] {
            assert!(
                capability.get(reference).and_then(Value::as_str).is_some(),
                "{uri} exposes {reference}"
            );
        }
        assert!(
            !capability.contains_key("classificationReference"),
            "operator-only classification metadata stays undiscoverable"
        );
        assert!(
            capability["processingReference"]
                .as_str()
                .is_some_and(|reference| reference.ends_with(
                    "/v2/artifacts/assistance-enrolment--lookup-by-case-and-person--representation-limited-processing"
                )),
            "processing metadata link resolves to the mounted artifact identifier"
        );
    }
}

#[tokio::test]
async fn invalid_bearer_on_unknown_data_routes_is_audited_fail_closed() {
    let sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let harness = ProjectHarness::open_with_audit(
        "business-registry",
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
    )
    .await;
    for (method, uri) in [
        (Method::GET, "/v2/resources/unknown/records"),
        (Method::GET, "/v2/resources/unknown/records/record"),
        (Method::POST, "/v2/resources/unknown/lookups/unknown"),
    ] {
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(AUTHORIZATION, "Bearer malformed")
                    .body(Body::empty())
                    .expect("unknown request builds"),
            )
            .await
            .expect("router responds");
        assert_problem_code(
            response,
            StatusCode::UNAUTHORIZED,
            "auth.invalid_credential",
        )
        .await;
    }
    assert_eq!(
        sink.writes(),
        3,
        "each invalid credential is refused in audit"
    );

    let failing_sink = Arc::new(ControlledAuditSink::new(1));
    let harness = ProjectHarness::open_with_audit(
        "business-registry",
        Some(Arc::clone(&failing_sink) as Arc<dyn AuditSink>),
    )
    .await;
    assert_problem_code(
        harness
            .app
            .oneshot(
                Request::builder()
                    .uri("/v2/resources/unknown/records")
                    .header(AUTHORIZATION, "Bearer malformed")
                    .body(Body::empty())
                    .expect("unknown request builds"),
            )
            .await
            .expect("router responds"),
        StatusCode::SERVICE_UNAVAILABLE,
        "audit.unavailable",
    )
    .await;
    assert_eq!(failing_sink.writes(), 1);
}

#[tokio::test]
async fn lookup_body_collection_obeys_the_request_deadline() {
    let harness = ProjectHarness::open("social-assistance").await;
    let journey: Journey = serde_norway::from_slice(
        &fs::read(project_root("social-assistance").join("expected-http.yaml"))
            .expect("journey reads"),
    )
    .expect("journey parses");
    let step = journey
        .steps
        .iter()
        .find(|step| step.id == "lookup-success")
        .expect("protected lookup journey exists");
    let fixture_id = step
        .authorization_fixture
        .as_deref()
        .expect("lookup has authorization fixture");
    let fixture = journey
        .authorizations
        .get(fixture_id)
        .expect("authorization fixture resolves");
    let token = harness.token(fixture_id, fixture);
    let pending = stream::pending::<Result<Bytes, Infallible>>();
    let request = Request::builder()
        .method(Method::POST)
        .uri(&step.request.path)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from_stream(pending))
        .expect("pending lookup request builds");

    let response = tokio::time::timeout(
        Duration::from_millis(
            harness
                .runtime
                .limits
                .request_timeout_milliseconds
                .saturating_add(1_000),
        ),
        harness.app.oneshot(request),
    )
    .await
    .expect("router enforces its shorter request deadline")
    .expect("router responds");
    assert_problem_code(response, StatusCode::GATEWAY_TIMEOUT, "internal.timeout").await;
}

fn request_with_bearer(
    harness: &ProjectHarness,
    step: &JourneyStep,
    authorizations: &BTreeMap<String, AuthorizationFixture>,
    token: &str,
) -> Request<Body> {
    let mut request = harness.request(step, authorizations);
    request.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {token}").parse().expect("bearer header"),
    );
    request
}

async fn assert_problem_code(response: http::Response<Body>, status: StatusCode, code: &str) {
    let body = response_body(response, status).await;
    assert_eq!(body.get("code").and_then(Value::as_str), Some(code));
}

async fn response_body(response: http::Response<Body>, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body reads");
    serde_json::from_slice(&bytes).expect("response is JSON")
}

fn assert_expectations(
    project: &str,
    step: &JourneyStep,
    headers: &HeaderMap,
    body: &[u8],
    equivalence_classes: &mut BTreeMap<String, Value>,
) {
    let label = format!("{project}/{}", step.id);
    if step.expect.body_empty {
        assert!(body.is_empty(), "{label} body must be empty");
        return;
    }
    let document: Value = serde_json::from_slice(body)
        .unwrap_or_else(|error| panic!("{label} response must be JSON: {error}"));
    if let Some(code) = &step.expect.code {
        assert_eq!(
            document.get("code").and_then(Value::as_str),
            Some(code.as_str()),
            "{label} code"
        );
    }
    if step.expect.route_absent {
        assert_eq!(
            document.get("code").and_then(Value::as_str),
            Some("resource.not_found"),
            "{label} absent route must not disclose operation state"
        );
    }
    if !step.expect.capability_patterns.is_empty()
        || !step.expect.absent_capability_patterns.is_empty()
    {
        let patterns = document
            .get("capabilities")
            .and_then(Value::as_array)
            .expect("capabilities array")
            .iter()
            .filter_map(|capability| {
                Some(format!(
                    "{}.{}",
                    capability.get("family")?.as_str()?,
                    capability.get("pattern")?.as_str()?
                ))
            })
            .collect::<BTreeSet<_>>();
        for expected in &step.expect.capability_patterns {
            assert!(
                patterns.contains(expected),
                "{label} missing capability {expected}"
            );
        }
        for absent in &step.expect.absent_capability_patterns {
            assert!(
                !patterns.contains(absent),
                "{label} exposed forbidden capability {absent}"
            );
        }
    }
    if let Some(count) = step.expect.item_count {
        assert_eq!(
            document
                .get("items")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(count),
            "{label} item count"
        );
    }
    if let Some(expectation) = &step.expect.next_cursor {
        let cursor = document.pointer("/pageInfo/nextCursor");
        match expectation.as_str() {
            "non-null" => assert!(
                cursor.is_some_and(|value| !value.is_null()),
                "{label} cursor"
            ),
            "null" => assert!(cursor.is_some_and(Value::is_null), "{label} cursor"),
            value => panic!("{label} has unsupported nextCursor expectation {value}"),
        }
    }
    let records = response_records(&document);
    if step.expect.registry_core_required {
        assert!(!records.is_empty(), "{label} must contain a Record");
        for record in &records {
            for key in [
                "registryIdentifier",
                "recordIdentifier",
                "revisionIdentifier",
                "lifecycleState",
                "schemaReference",
                "semanticModelReference",
                "authorityIdentifier",
                "recordedAt",
                "domainData",
            ] {
                assert!(record.get(key).is_some(), "{label} Record is missing {key}");
            }
        }
    }
    if !step.expect.domain_data_keys.is_empty() {
        assert!(!records.is_empty(), "{label} must contain domain data");
        let expected = step
            .expect
            .domain_data_keys
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for record in &records {
            let actual = record
                .get("domainData")
                .and_then(Value::as_object)
                .expect("domainData object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            assert_eq!(actual, expected, "{label} disclosed domain properties");
        }
    }
    if let Some(identifier) = &step.expect.record_identifier {
        assert_eq!(
            document
                .pointer("/data/recordIdentifier")
                .and_then(Value::as_str),
            Some(identifier.as_str()),
            "{label} record identifier"
        );
    }
    if let Some(cache) = &step.expect.cache {
        match cache.as_str() {
            "public-snapshot-revalidation" => {
                assert_eq!(
                    headers
                        .get(CACHE_CONTROL)
                        .and_then(|value| value.to_str().ok()),
                    Some("public, no-cache"),
                    "{label} cache-control"
                );
                assert!(headers.contains_key(ETAG), "{label} requires an ETag");
                assert_eq!(
                    headers.get(VARY).and_then(|value| value.to_str().ok()),
                    Some("Accept, Authorization"),
                    "{label} vary"
                );
            }
            "no-store" => {
                assert_eq!(
                    headers
                        .get(CACHE_CONTROL)
                        .and_then(|value| value.to_str().ok()),
                    Some("no-store"),
                    "{label} cache-control"
                );
                assert!(!headers.contains_key(ETAG), "{label} omits an ETag");
            }
            unsupported => panic!("{label} has unsupported cache expectation {unsupported}"),
        }
    }
    let body_text = String::from_utf8_lossy(body);
    for absent in &step.expect.absent_everywhere {
        assert!(
            !body_text.contains(absent),
            "{label} disclosed forbidden term {absent}"
        );
    }
    if let Some(class) = &step.expect.equivalence_class {
        let mut normalized = document;
        normalized
            .as_object_mut()
            .expect("problem object")
            .remove("traceId");
        if let Some(existing) = equivalence_classes.get(class) {
            assert_eq!(
                &normalized, existing,
                "{label} changed equivalence-class problem"
            );
        } else {
            equivalence_classes.insert(class.clone(), normalized);
        }
    }
}

fn normalized_records(document: &Value) -> Vec<Value> {
    response_records(document)
        .into_iter()
        .map(|record| {
            let mut record = record.clone();
            if let Some(object) = record.as_object_mut() {
                object.remove("@id");
            }
            record
        })
        .collect()
}

fn response_records(document: &Value) -> Vec<&Value> {
    if let Some(record) = document.get("data") {
        vec![record]
    } else {
        document
            .get("items")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |items| items.iter().collect())
    }
}

impl ProjectHarness {
    async fn open(project: &str) -> Self {
        Self::open_with_audit(project, None).await
    }

    async fn open_with_audit(project: &str, sink: Option<Arc<dyn AuditSink>>) -> Self {
        let root = project_root(project);
        let contract = RegistryContract::parse_yaml(
            &fs::read_to_string(root.join("registry.yaml")).expect("contract reads"),
        )
        .expect("contract parses");
        let runtime = RelayRuntime::parse_yaml(
            &fs::read_to_string(root.join("runtime.yaml")).expect("runtime reads"),
        )
        .expect("runtime parses");
        let temp = tempfile::tempdir().expect("temporary project creates");
        let database = temp.path().join("fixture.sqlite");
        materialize_fixture(
            &database,
            &fs::read_to_string(root.join("fixture.sql")).expect("fixture SQL reads"),
        )
        .expect("fixture materializes");

        let captured = CapturedSnapshot::capture(&database).expect("fixture captures");
        let catalog = inspect_schema(
            &DatabaseProfile::Snapshot(captured),
            &InspectionLimits {
                maximum_objects: 10_000,
                maximum_sql_bytes: 8 * 1024 * 1024,
                maximum_statement_steps: 1_000_000,
                timeout: Duration::from_secs(5),
            },
        )
        .expect("schema inspects");
        let observed_fingerprint = catalog.fingerprint.clone();
        let source_id = contract
            .sources
            .keys()
            .next()
            .expect("one source")
            .to_owned();
        let observed = vec![ObservedSourceSchema {
            source: source_id.clone(),
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
        let governed = governed_files(&root, &contract);
        let compiled = Arc::new(
            compile_contract_with_governed_files(
                &contract,
                &observed,
                CompileProfile::Production,
                &governed,
            )
            .unwrap_or_else(|report| {
                panic!(
                    "{project} compilation failed (observed schema {observed_fingerprint}): {report:?}"
                )
            }),
        );
        let artifacts = Arc::new(generate_artifacts(&compiled).expect("artifacts generate"));
        let sqlite = Arc::new(
            SqliteRuntime::open(
                &compiled,
                &BTreeMap::from([(
                    source_id,
                    RuntimeSourceBinding {
                        path: database.clone(),
                    },
                )]),
                SqliteRuntimeLimits {
                    request_timeout: Duration::from_millis(
                        runtime.limits.request_timeout_milliseconds,
                    ),
                    concurrent_queries: usize::try_from(runtime.limits.concurrent_queries)
                        .expect("query limit fits"),
                },
            )
            .expect("SQLite runtime opens"),
        );
        let sink: Arc<dyn AuditSink> =
            sink.unwrap_or_else(|| Arc::new(JsonlFileSink::new(temp.path().join("audit.jsonl"))));
        let chain = Arc::new(
            ChainState::bootstrap_unkeyed_dev_only(sink.as_ref())
                .await
                .expect("test audit chain starts"),
        );
        let audit = RelayAudit::new(chain, sink);

        let (authenticator, idp) = if let Some(issuer) = runtime.authentication.issuer.as_ref() {
            let idp = MockIdp::start().await;
            let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
                idp.jwks_uri(),
                JwksFetcherConfig::defaults(),
                FetchUrlPolicy::dev(),
            ));
            fetcher.ensure_key_set().await.expect("fixture JWKS loads");
            let mut config = oidc_verifier_config(idp.issuer(), vec![issuer.audience.clone()]);
            config.allowed_typ = vec!["at+jwt".into()];
            config.max_token_lifetime = Some(Duration::from_secs(3600));
            (
                Some(RelayAuthenticator::new(
                    Arc::new(TokenVerifier::new(config, fetcher)),
                    issuer.audience.clone(),
                    Duration::from_secs(30),
                )),
                Some(idp),
            )
        } else {
            (None, None)
        };
        let metadata = ServiceMetadata {
            authority: InstitutionMetadata {
                identifier: contract.registry.authority.identifier.clone(),
                name: contract.registry.authority.name.clone(),
            },
            operator: contract
                .registry
                .operator
                .as_ref()
                .map(|operator| InstitutionMetadata {
                    identifier: operator.identifier.clone(),
                    name: operator.name.clone(),
                }),
            authoritative_scope: contract.registry.authoritative_scope.clone(),
            alignment_targets: contract
                .registry
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
        let service = Arc::new(RelayService::new(
            compiled,
            artifacts,
            sqlite,
            authenticator,
            audit,
            runtime.cursor.as_ref().map(|_| {
                Arc::new(
                    registry_relay_v2::cursor::CursorKey::new(vec![0x5a; 32])
                        .expect("cursor key is valid"),
                )
            }),
            Duration::from_secs(
                runtime
                    .cursor
                    .as_ref()
                    .map_or(300, |cursor| cursor.maximum_age_seconds),
            ),
            Duration::from_millis(runtime.limits.request_timeout_milliseconds),
            runtime.quotas.as_ref().map(|quota| QuotaConfig {
                requests_per_minute: quota.requests_per_minute,
                burst: quota.burst,
            }),
            metadata,
        ));
        Self {
            app: router(Arc::clone(&service)),
            service,
            contract,
            runtime,
            database,
            idp,
            _temp: temp,
        }
    }

    fn request(
        &self,
        step: &JourneyStep,
        authorizations: &BTreeMap<String, AuthorizationFixture>,
    ) -> Request<Body> {
        self.request_with_observations(step, authorizations, &BTreeMap::new(), &BTreeMap::new())
    }

    fn request_with_observations(
        &self,
        step: &JourneyStep,
        authorizations: &BTreeMap<String, AuthorizationFixture>,
        response_documents: &BTreeMap<String, Value>,
        etags: &BTreeMap<String, String>,
    ) -> Request<Body> {
        let mut url = step.request.path.clone();
        if !step.request.query.is_empty() {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in &step.request.query {
                let scalar = journey_query_value(value, response_documents).unwrap_or_else(|| {
                    panic!(
                        "journey {} query {name} must be scalar, got {value:?}",
                        step.id
                    )
                });
                serializer.append_pair(name, &scalar);
            }
            url.push('?');
            url.push_str(&serializer.finish());
        }
        let method = step
            .request
            .method
            .parse::<Method>()
            .expect("journey method is valid");
        let body = step
            .request
            .body
            .as_ref()
            .map(|selectors| {
                serde_json::to_vec(&json!({"selectors": selectors})).expect("body serializes")
            })
            .unwrap_or_default();
        let mut request = Request::builder()
            .method(method)
            .uri(url)
            .body(Body::from(body))
            .expect("request builds");
        if step.request.body.is_some() {
            request.headers_mut().insert(
                CONTENT_TYPE,
                "application/json".parse().expect("content type"),
            );
        }
        for (name, value) in &step.request.headers {
            let value = value
                .strip_prefix("$etag:")
                .map_or_else(
                    || value.as_str(),
                    |reference| {
                        etags
                            .get(reference)
                            .unwrap_or_else(|| panic!("referenced ETag {reference} exists"))
                    },
                )
                .parse::<HeaderValue>()
                .expect("journey header value");
            request.headers_mut().insert(
                name.parse::<HeaderName>().expect("journey header name"),
                value,
            );
        }
        if let Some(fixture) = step.authorization_fixture.as_deref() {
            let definition = authorizations
                .get(fixture)
                .unwrap_or_else(|| panic!("authorization fixture {fixture} is declared"));
            let token = self.token(fixture, definition);
            request.headers_mut().insert(
                AUTHORIZATION,
                format!("Bearer {token}")
                    .parse()
                    .expect("authorization header"),
            );
        }
        request
    }

    fn token(&self, fixture: &str, definition: &AuthorizationFixture) -> String {
        let audience = &self
            .runtime
            .authentication
            .issuer
            .as_ref()
            .expect("runtime has issuer")
            .audience;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is valid")
            .as_secs();
        self.signed_token(
            fixture,
            definition,
            audience,
            now,
            now,
            now.saturating_add(900),
        )
    }

    fn signed_token(
        &self,
        fixture: &str,
        definition: &AuthorizationFixture,
        audience: &str,
        issued_at: u64,
        not_before: u64,
        expires_at: u64,
    ) -> String {
        self.signed_token_with_audience(
            fixture,
            definition,
            json!(audience),
            issued_at,
            not_before,
            expires_at,
        )
    }

    fn signed_token_with_audience(
        &self,
        fixture: &str,
        definition: &AuthorizationFixture,
        audience: Value,
        issued_at: u64,
        not_before: u64,
        expires_at: u64,
    ) -> String {
        let issuer = self.idp.as_ref().expect("protected project has an IdP");
        let mut claims = serde_json::Map::new();
        claims.insert("iss".into(), json!(issuer.issuer()));
        claims.insert("aud".into(), audience);
        claims.insert("sub".into(), json!(definition.principal));
        claims.insert(
            "scope".into(),
            json!(definition
                .scopes
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(" ")),
        );
        claims.insert("iat".into(), json!(issued_at));
        claims.insert("nbf".into(), json!(not_before));
        claims.insert("exp".into(), json!(expires_at));
        claims.insert(
            "jti".into(),
            json!(format!("fixture-{fixture}-{issued_at}")),
        );
        for (name, value) in &definition.claims {
            claims.insert(name.clone(), json!(value));
        }
        sign_ed25519_compact_jwt(
            fixtures::ED25519_PRIVATE_JWK,
            "at+jwt",
            "registry-platform-testing-ed25519-1",
            Value::Object(claims),
        )
    }
}

async fn assert_unready(harness: &ProjectHarness, project: &str, condition: &str) {
    assert!(
        !harness.service.is_ready().await,
        "{project} must become unready when its source is {condition}"
    );
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    let document = response_body(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(
        document.get("code").and_then(Value::as_str),
        Some("service.not_ready")
    );
    let wire = serde_json::to_string(&document).expect("problem serializes");
    for protected in [
        project,
        condition,
        "fixture.sqlite",
        "readiness_schema_drift",
        harness.database.to_string_lossy().as_ref(),
    ] {
        assert!(
            !wire.contains(protected),
            "readiness failure disclosed protected detail"
        );
    }
}

#[cfg(unix)]
fn make_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("source becomes writable");
}

#[cfg(not(unix))]
fn make_writable(path: &Path) {
    let mut permissions = fs::metadata(path).expect("source metadata").permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).expect("source becomes writable");
}

fn make_read_only(path: &Path) {
    let mut permissions = fs::metadata(path).expect("source metadata").permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).expect("source becomes read-only");
}

fn governed_files(root: &Path, contract: &RegistryContract) -> GovernedFileSet {
    let mut paths = BTreeSet::new();
    paths.insert(contract.registry.identifier_lifecycle_policy_ref.clone());
    paths.insert(contract.classifications.provenance_ref.clone());
    let review_bytes = fs::read(root.join(&contract.classifications.provenance_ref))
        .expect("classification review reads");
    let review = parse_classification_review_yaml(&review_bytes)
        .expect("classification review strictly parses");
    paths.insert(review.rationale_ref);
    if let Some(generated) = review.generated_identification {
        paths.insert(generated.report_ref);
    }
    for alignment in &contract.semantics.alignments {
        paths.insert(alignment.profile_ref.clone());
    }
    for resource in &contract.resources {
        paths.insert(resource.record_context.lifecycle_state.codelist.clone());
        for (_, property) in resource.properties.iter() {
            if let Some(path) = &property.codelist {
                paths.insert(path.clone());
            }
        }
        for processing in &resource.processing_descriptions {
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

fn project_root(project: &str) -> PathBuf {
    Path::new(ACCEPTANCE_ROOT).join(project)
}

fn yaml_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn journey_query_value(
    value: &Value,
    response_documents: &BTreeMap<String, Value>,
) -> Option<String> {
    match value {
        Value::String(value) => value
            .strip_prefix("$nextCursor:")
            .map(|reference| {
                response_documents
                    .get(reference)?
                    .pointer("/pageInfo/nextCursor")?
                    .as_str()
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| Some(value.clone())),
        _ => yaml_scalar(value),
    }
}
