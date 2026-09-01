// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, LINK};
use http::{Method, Request, StatusCode};
use registry_platform_audit::{AuditChainHasher, AuditEnvelope, AuditError, AuditSink, ChainState};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier};
use registry_platform_sqlite::{
    inspect_schema, materialize_fixture, CapturedSnapshot, DatabaseProfile, InspectionLimits,
};
use registry_platform_testing::{
    fixtures, oidc_verifier_config, sign_ed25519_compact_jwt, MockIdp,
};
use registry_relay_v2::artifacts::{
    generate_artifacts, ArtifactSet, REGISTRY_RECORD_CONTEXT_ID, REGISTRY_RECORD_PROFILE_ID,
    RELAY_PROFILE_ID,
};
use registry_relay_v2::audit::RelayAudit;
use registry_relay_v2::auth::RelayAuthenticator;
use registry_relay_v2::contract::{
    DataType, DateInputType, DatePrecision, Handling, PartialStringReveal, ReviewStatus,
    SourceProfile, Visibility,
};
use registry_relay_v2::cursor::CursorKey;
use registry_relay_v2::model::{
    CapabilityFamily, CompiledAccess, CompiledAccessProfile, CompiledCodelist,
    CompiledDisclosureProfile, CompiledMetadataVisibility, CompiledOperation, CompiledPagination,
    CompiledProperty, CompiledPropertyBinding, CompiledPurpose, CompiledRecordContext,
    CompiledRegistry, CompiledResource, CompiledRowBinding, CompiledScalarPropertyBinding,
    CompiledSelector, CompiledSource, CompiledTransform, ConsultationPattern,
    EffectiveClassification, OperationKind, QueryPlan, RowAuthoritySource,
};
use registry_relay_v2::server::{
    router, InstitutionMetadata, QuotaConfig, RelayService, ServiceMetadata,
};
use registry_relay_v2::sqlite_runtime::{RuntimeSourceBinding, SqliteRuntime, SqliteRuntimeLimits};
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt as _;

const SOURCE: &str = "source";
const RESOURCE: &str = "record";
const AUDIENCE: &str = "urn:example:relay:access-profiles";
const ENCODED_REPRESENTATION_SELECTOR: &str = "%72%65%70%72%65%73%65%6e%74%61%74%69%6f%6e=limited";

const FIXTURE_SQL: &str = r#"
CREATE TABLE source_records (
    record_id TEXT PRIMARY KEY NOT NULL,
    revision TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    public_name TEXT NOT NULL,
    prederived_mask TEXT NOT NULL,
    secret_value ANY,
    event_date ANY NOT NULL,
    optional_value TEXT,
    lookup_key TEXT NOT NULL,
    authority TEXT NOT NULL
) STRICT;

INSERT INTO source_records VALUES
('record-1', '1', 'ACTIVE', '2026-08-01T00:00:00Z', 'Public one', 'PRE-1', 'SENSITIVE-SOURCE-VALUE-7341', '2042-09-17', NULL, 'lookup-1', 'area-a'),
('record-1a', '1', 'ACTIVE', 'not-a-core-date', 'Public invalid core', 'PRE-CORE', 'CORE', '2042-09-17', NULL, 'lookup-core', 'area-a'),
('record-2', '1', 'ACTIVE', '2026-08-02T00:00:00Z', 'Public two', 'PRE-2', 'ABCDEF', '2026-09-11', 'OPTIONAL-9', 'lookup-2', 'area-a'),
('record-bad-date', '1', 'ACTIVE', '2026-08-03T00:00:00Z', 'Public bad date', 'PRE-3', 'ABCDEFGH', 'not-a-date', NULL, 'lookup-3', 'area-a'),
('record-null', '1', 'ACTIVE', '2026-08-04T00:00:00Z', 'Public null', 'PRE-4', NULL, '2026-10-12', NULL, 'lookup-4', 'area-a'),
('record-wrong-secret-type', '1', 'ACTIVE', '2026-08-05T00:00:00Z', 'Public wrong secret type', 'PRE-5', 42, '2026-10-12', NULL, 'lookup-5', 'area-a'),
('record-wrong-date-type', '1', 'ACTIVE', '2026-08-06T00:00:00Z', 'Public wrong date type', 'PRE-6', 'ABCDEFGH', 42, NULL, 'lookup-6', 'area-a'),
('record-overlong-secret', '1', 'ACTIVE', '2026-08-07T00:00:00Z', 'Public overlong secret', 'PRE-7', replace(hex(zeroblob(2050)), '0', 'A'), '2026-10-12', NULL, 'lookup-7', 'area-a'),
('record-overlong-date', '1', 'ACTIVE', '2026-08-08T00:00:00Z', 'Public overlong date', 'PRE-8', 'ABCDEFGH', replace(hex(zeroblob(2050)), '0', 'A'), NULL, 'lookup-8', 'area-a');

CREATE VIEW relay_records AS
SELECT record_id, revision, lifecycle, recorded_at, public_name, prederived_mask,
       secret_value, event_date, optional_value, lookup_key, authority
FROM source_records;
"#;

#[derive(Default)]
struct RecordingSink {
    records: Mutex<Vec<AuditEnvelope>>,
    fail_after: Option<usize>,
}

impl RecordingSink {
    fn failing_after(successes: usize) -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            fail_after: Some(successes),
        }
    }

    fn values(&self) -> Vec<Value> {
        self.records
            .lock()
            .expect("audit lock")
            .iter()
            .map(|envelope| envelope.record.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl AuditSink for RecordingSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let mut records = self.records.lock().expect("audit lock");
        if self
            .fail_after
            .is_some_and(|maximum| records.len() >= maximum)
        {
            return Err(AuditError::Io(std::io::Error::other(
                "controlled audit failure",
            )));
        }
        records.push(envelope.clone());
        Ok(())
    }

    #[allow(deprecated)]
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(self
            .records
            .lock()
            .expect("audit lock")
            .last()
            .map(|envelope| envelope.record_hash))
    }

    async fn tail_hash_with_hasher(
        &self,
        _hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(self
            .records
            .lock()
            .expect("audit lock")
            .last()
            .map(|envelope| envelope.record_hash))
    }
}

struct Harness {
    app: axum::Router,
    database: std::path::PathBuf,
    artifacts: Arc<ArtifactSet>,
    idp: MockIdp,
    _temp: TempDir,
}

impl Harness {
    async fn open(quota: Option<QuotaConfig>, sink: Arc<RecordingSink>) -> Self {
        Self::open_with_fixture(quota, sink, FIXTURE_SQL).await
    }

    async fn open_with_fixture(
        quota: Option<QuotaConfig>,
        sink: Arc<RecordingSink>,
        fixture_sql: &str,
    ) -> Self {
        Self::open_with_fixture_and_list_order(quota, sink, fixture_sql, &["record_id"]).await
    }

    async fn open_with_fixture_and_list_order(
        quota: Option<QuotaConfig>,
        sink: Arc<RecordingSink>,
        fixture_sql: &str,
        list_order: &[&str],
    ) -> Self {
        let temp = tempfile::tempdir().expect("temporary fixture");
        let database = temp.path().join("fixture.sqlite");
        materialize_fixture(&database, fixture_sql).expect("fixture materializes");
        let captured = CapturedSnapshot::capture(&database).expect("fixture captures");
        let fingerprint = inspect_schema(
            &DatabaseProfile::Snapshot(captured),
            &InspectionLimits {
                maximum_objects: 100,
                maximum_sql_bytes: 1024 * 1024,
                maximum_statement_steps: 100_000,
                timeout: Duration::from_secs(2),
            },
        )
        .expect("fixture schema inspects")
        .fingerprint;
        let mut registry = compiled_registry(fingerprint);
        let list = registry.resources[0]
            .operations
            .iter_mut()
            .find(|operation| matches!(&operation.kind, OperationKind::List))
            .expect("list operation exists");
        list.query.order_by = list_order.iter().map(|column| (*column).into()).collect();
        let registry = Arc::new(registry);
        let artifacts = Arc::new(generate_artifacts(&registry).expect("artifacts generate"));
        let sqlite = Arc::new(
            SqliteRuntime::open(
                &registry,
                &BTreeMap::from([(
                    SOURCE.to_owned(),
                    RuntimeSourceBinding {
                        path: database.clone(),
                    },
                )]),
                SqliteRuntimeLimits {
                    request_timeout: Duration::from_secs(2),
                    concurrent_queries: 4,
                },
            )
            .expect("SQLite runtime opens"),
        );
        let idp = MockIdp::start().await;
        let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        ));
        fetcher.ensure_key_set().await.expect("fixture JWKS loads");
        let mut verifier = oidc_verifier_config(idp.issuer(), vec![AUDIENCE.into()]);
        verifier.allowed_typ = vec!["at+jwt".into()];
        verifier.max_token_lifetime = Some(Duration::from_secs(3600));
        let authenticator = RelayAuthenticator::new(
            Arc::new(TokenVerifier::new(verifier, fetcher)),
            AUDIENCE.into(),
            Duration::from_secs(30),
        );
        let sink_object: Arc<dyn AuditSink> = sink.clone();
        let chain = Arc::new(
            ChainState::bootstrap_unkeyed_dev_only(sink_object.as_ref())
                .await
                .expect("audit chain starts"),
        );
        let service = Arc::new(RelayService::new(
            registry,
            Arc::clone(&artifacts),
            sqlite,
            Some(authenticator),
            RelayAudit::new(chain, sink_object),
            Some(Arc::new(
                CursorKey::new(vec![0x5a; 32]).expect("cursor key"),
            )),
            Duration::from_secs(300),
            Duration::from_secs(2),
            quota,
            ServiceMetadata {
                authority: InstitutionMetadata {
                    identifier: "urn:example:authority".into(),
                    name: "Example Authority".into(),
                },
                operator: None,
                authoritative_scope: "Synthetic access profile tests".into(),
                alignment_targets: Vec::new(),
            },
        ));
        Self {
            app: router(service),
            database,
            artifacts,
            idp,
            _temp: temp,
        }
    }

    fn token(&self, scopes: &[&str], purpose: &str, authority: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        sign_ed25519_compact_jwt(
            fixtures::ED25519_PRIVATE_JWK,
            "at+jwt",
            "registry-platform-testing-ed25519-1",
            json!({
                "iss": self.idp.issuer(),
                "aud": AUDIENCE,
                "sub": "synthetic-client",
                "scope": scopes.join(" "),
                "purpose": purpose,
                "authority": authority,
                "iat": now,
                "nbf": now,
                "exp": now + 900,
                "jti": format!("fixture-{now}-{}", scopes.join("-")),
            }),
        )
    }

    async fn send(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, http::HeaderMap, Vec<u8>) {
        let has_body = body.is_some();
        let bytes = body
            .map(|value| serde_json::to_vec(&value).expect("body serializes"))
            .unwrap_or_default();
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(bytes))
            .expect("request builds");
        if has_body {
            request
                .headers_mut()
                .insert(CONTENT_TYPE, "application/json".parse().expect("header"));
        }
        if let Some(token) = token {
            request.headers_mut().insert(
                AUTHORIZATION,
                format!("Bearer {token}").parse().expect("bearer header"),
            );
        }
        for (name, value) in headers {
            request.headers_mut().append(
                name.parse::<http::HeaderName>().expect("header name"),
                value.parse().expect("header value"),
            );
        }
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("router responds");
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .expect("response body reads")
            .to_vec();
        (status, headers, body)
    }
}

#[tokio::test]
async fn access_profile_selection_authenticates_then_authorizes_the_exact_profile() {
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open(None, Arc::clone(&sink)).await;
    let limited = harness.token(&["registry:limited"], "review", "area-a");

    let (status, _, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1?accessProfile=missing",
            Some("not-a-jwt"),
            None,
            &[],
        )
        .await;
    assert_problem(
        status,
        &body,
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    );

    for (token, access_profile, expected_status, expected_code) in [
        (
            None,
            "caseworker",
            StatusCode::NOT_FOUND,
            "resource.not_found",
        ),
        (None, "missing", StatusCode::NOT_FOUND, "resource.not_found"),
        (
            Some(limited.as_str()),
            "caseworker",
            StatusCode::NOT_FOUND,
            "resource.not_found",
        ),
        (
            Some(limited.as_str()),
            "missing",
            StatusCode::NOT_FOUND,
            "resource.not_found",
        ),
    ] {
        let uri = format!("/v2/resources/record/records/record-1?accessProfile={access_profile}");
        let (status, _, body) = harness.send(Method::GET, &uri, token, None, &[]).await;
        assert_problem(status, &body, expected_status, expected_code);
    }

    let records = sink.values();
    assert!(records.iter().all(|event| event["phase"] == "refusal"));
    assert!(records
        .iter()
        .all(|event| event.get("accessProfile").is_none()));
    assert_eq!(
        records
            .iter()
            .filter(|event| event.get("accessProfile").is_none())
            .count(),
        5
    );
    let audit_wire = serde_json::to_string(&records).expect("audit serializes");
    assert!(!audit_wire.contains("not-a-jwt"));
}

#[tokio::test]
async fn anonymous_explicit_protected_access_profile_conceals_known_and_unknown_routes() {
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open(None, Arc::clone(&sink)).await;

    for (method, known, unknown) in [
        (
            Method::GET,
            "/v2/resources/record/records?accessProfile=caseworker",
            "/v2/resources/unknown/records?accessProfile=caseworker",
        ),
        (
            Method::GET,
            "/v2/resources/record/records/record-1?accessProfile=caseworker",
            "/v2/resources/unknown/records/record-1?accessProfile=caseworker",
        ),
        (
            Method::POST,
            "/v2/resources/record/lookups/by-key?accessProfile=caseworker",
            "/v2/resources/unknown/lookups/by-key?accessProfile=caseworker",
        ),
    ] {
        let mut normalized = None;
        for uri in [known, unknown] {
            let (status, _, body) = harness.send(method.clone(), uri, None, None, &[]).await;
            assert_problem(status, &body, StatusCode::NOT_FOUND, "resource.not_found");
            assert!(!String::from_utf8_lossy(&body).contains("caseworker"));
            let mut document: Value = serde_json::from_slice(&body).expect("problem JSON");
            document
                .as_object_mut()
                .expect("problem object")
                .remove("traceId");
            if let Some(expected) = &normalized {
                assert_eq!(&document, expected);
            } else {
                normalized = Some(document);
            }
        }
    }

    let records = sink.values();
    assert_eq!(records.len(), 6);
    assert!(records.iter().all(|event| {
        event["phase"] == "refusal"
            && event["outcome"] == "not-found"
            && event["principalKind"] == "anonymous"
            && event.get("resourceIdentifier").is_none()
            && event.get("operationIdentifier").is_none()
            && event.get("accessProfile").is_none()
    }));
    assert!(!serde_json::to_string(&records)
        .expect("audit serializes")
        .contains("caseworker"));
}

#[tokio::test]
async fn malformed_explicit_access_profile_is_identical_for_known_and_unknown_routes() {
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open(None, Arc::clone(&sink)).await;

    for (method, known, unknown) in [
        (
            Method::GET,
            "/v2/resources/record/records",
            "/v2/resources/unknown/records",
        ),
        (
            Method::GET,
            "/v2/resources/record/records/record-1",
            "/v2/resources/unknown/records/record-1",
        ),
        (
            Method::POST,
            "/v2/resources/record/lookups/by-key",
            "/v2/resources/unknown/lookups/by-key",
        ),
    ] {
        for selector in [
            "accessProfile=",
            "accessProfile=limited&accessProfile=caseworker",
            "accessProfile=%GG",
            "accessProfile=Caseworker",
        ] {
            let mut normalized = None;
            for route in [known, unknown] {
                let uri = format!("{route}?{selector}");
                let (status, _, body) = harness.send(method.clone(), &uri, None, None, &[]).await;
                assert_problem(
                    status,
                    &body,
                    StatusCode::BAD_REQUEST,
                    "request.access_profile_invalid",
                );
                let document = problem_without_trace(&body);
                if let Some(expected) = &normalized {
                    assert_eq!(&document, expected);
                } else {
                    normalized = Some(document);
                }
            }
        }
    }

    let records = sink.values();
    assert_eq!(records.len(), 24);
    for event in records.iter().skip(1).step_by(2) {
        assert_eq!(event["phase"], "refusal");
        assert_eq!(event["outcome"], "invalid-request");
        assert_eq!(event["principalKind"], "anonymous");
        assert!(event.get("resourceIdentifier").is_none());
        assert!(event.get("operationIdentifier").is_none());
        assert!(event.get("accessProfile").is_none());
    }
    let audit_wire = serde_json::to_string(&records).expect("audit serializes");
    for rejected in ["caseworker", "%GG", "Caseworker"] {
        assert!(!audit_wire.contains(rejected));
    }
}

#[tokio::test]
async fn retired_representation_selector_is_invalid_for_every_data_route() {
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open(None, Arc::clone(&sink)).await;

    for (method, known, unknown) in [
        (
            Method::GET,
            "/v2/resources/record/records",
            "/v2/resources/unknown/records",
        ),
        (
            Method::GET,
            "/v2/resources/record/records/record-1",
            "/v2/resources/unknown/records/record-1",
        ),
        (
            Method::POST,
            "/v2/resources/record/lookups/by-key",
            "/v2/resources/unknown/lookups/by-key",
        ),
    ] {
        for selector in ["representation=limited", ENCODED_REPRESENTATION_SELECTOR] {
            let mut normalized = None;
            for route in [known, unknown] {
                let uri = format!("{route}?{selector}");
                let (status, _, body) = harness.send(method.clone(), &uri, None, None, &[]).await;
                assert_problem(
                    status,
                    &body,
                    StatusCode::BAD_REQUEST,
                    "request.access_profile_invalid",
                );
                let document = problem_without_trace(&body);
                if let Some(expected) = &normalized {
                    assert_eq!(&document, expected);
                } else {
                    normalized = Some(document);
                }
            }
        }
    }

    let records = sink.values();
    assert_eq!(records.len(), 12);
    assert!(records.iter().all(|event| {
        event["phase"] == "refusal"
            && event["outcome"] == "invalid-request"
            && event.get("accessProfile").is_none()
    }));
    assert!(!records.iter().any(|event| event["phase"] == "attempt"));
    let audit_wire = serde_json::to_string(&records).expect("audit serializes");
    assert!(!audit_wire.contains("representation"));
    assert!(!audit_wire.contains("limited"));
}

#[tokio::test]
async fn unknown_route_access_profile_preflight_preserves_authentication_precedence() {
    let harness = Harness::open(None, Arc::new(RecordingSink::default())).await;

    for (method, known, unknown) in [
        (
            Method::GET,
            "/v2/resources/record/records",
            "/v2/resources/unknown/records",
        ),
        (
            Method::GET,
            "/v2/resources/record/records/record-1",
            "/v2/resources/unknown/records/record-1",
        ),
        (
            Method::POST,
            "/v2/resources/record/lookups/by-key",
            "/v2/resources/unknown/lookups/by-key",
        ),
    ] {
        let (status, _, body) = harness.send(method.clone(), unknown, None, None, &[]).await;
        assert_problem(
            status,
            &body,
            StatusCode::UNAUTHORIZED,
            "auth.missing_credential",
        );

        for selector in [
            "accessProfile=%GG",
            "representation=limited",
            ENCODED_REPRESENTATION_SELECTOR,
        ] {
            for route in [known, unknown] {
                let uri = format!("{route}?{selector}");
                let (status, _, body) = harness
                    .send(method.clone(), &uri, Some("not-a-jwt"), None, &[])
                    .await;
                assert_problem(
                    status,
                    &body,
                    StatusCode::UNAUTHORIZED,
                    "auth.invalid_credential",
                );
            }
        }
    }
}

#[tokio::test]
async fn oversized_uri_still_conceals_exact_access_profile_authorization() {
    let harness = Harness::open(None, Arc::new(RecordingSink::default())).await;
    let limited = harness.token(&["registry:limited"], "review", "area-a");
    let padding = "x".repeat(20_000);

    for access_profile in ["caseworker", "missing"] {
        let uri = format!(
            "/v2/resources/record/records/record-1?accessProfile={access_profile}&padding={padding}"
        );
        let (status, _, body) = harness
            .send(Method::GET, &uri, Some(&limited), None, &[])
            .await;
        assert_problem(status, &body, StatusCode::NOT_FOUND, "resource.not_found");
    }
}

#[tokio::test]
async fn oversized_unknown_route_preserves_access_profile_preflight_ordering() {
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open(None, Arc::clone(&sink)).await;
    let padding = "x".repeat(20_000);

    for (method, known, unknown) in [
        (
            Method::GET,
            "/v2/resources/record/records",
            "/v2/resources/unknown/records",
        ),
        (
            Method::GET,
            "/v2/resources/record/records/record-1",
            "/v2/resources/unknown/records/record-1",
        ),
        (
            Method::POST,
            "/v2/resources/record/lookups/by-key",
            "/v2/resources/unknown/lookups/by-key",
        ),
    ] {
        let mut normalized = None;
        for route in [known, unknown] {
            let uri = format!("{route}?padding={padding}&accessProfile=caseworker");
            let (status, _, body) = harness.send(method.clone(), &uri, None, None, &[]).await;
            assert_problem(status, &body, StatusCode::NOT_FOUND, "resource.not_found");
            let document = problem_without_trace(&body);
            if let Some(expected) = &normalized {
                assert_eq!(&document, expected);
            } else {
                normalized = Some(document);
            }
        }

        for selector in [
            "accessProfile=",
            "accessProfile=%GG",
            "representation=limited",
            ENCODED_REPRESENTATION_SELECTOR,
        ] {
            let mut normalized = None;
            for route in [known, unknown] {
                let uri = format!("{route}?padding={padding}&{selector}");
                let (status, _, body) = harness.send(method.clone(), &uri, None, None, &[]).await;
                assert_problem(
                    status,
                    &body,
                    StatusCode::BAD_REQUEST,
                    "request.access_profile_invalid",
                );
                let document = problem_without_trace(&body);
                if let Some(expected) = &normalized {
                    assert_eq!(&document, expected);
                } else {
                    normalized = Some(document);
                }
            }
        }

        let uri = format!("{unknown}?padding={padding}");
        let (status, _, body) = harness.send(method.clone(), &uri, None, None, &[]).await;
        assert_problem(
            status,
            &body,
            StatusCode::UNAUTHORIZED,
            "auth.missing_credential",
        );

        for route in [known, unknown] {
            let uri = format!("{route}?padding={padding}&accessProfile=%GG");
            let (status, _, body) = harness
                .send(method.clone(), &uri, Some("not-a-jwt"), None, &[])
                .await;
            assert_problem(
                status,
                &body,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credential",
            );
        }
    }

    let records = sink.values();
    assert_eq!(records.len(), 39);
    let audit_wire = serde_json::to_string(&records).expect("audit serializes");
    assert!(!audit_wire.contains(&padding));
    assert!(!audit_wire.contains("caseworker"));
    assert!(!audit_wire.contains("%GG"));
}

#[tokio::test]
async fn preflight_refusals_do_not_reach_source_and_attempt_audit_precedes_source_access() {
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open(None, Arc::clone(&sink)).await;
    let limited = harness.token(&["registry:limited"], "review", "area-a");

    std::fs::rename(&harness.database, harness.database.with_extension("moved"))
        .expect("test source moves after runtime open");
    for (uri, expected_status, code) in [
        (
            "/v2/resources/record/records?accessProfile=",
            StatusCode::BAD_REQUEST,
            "request.access_profile_invalid",
        ),
        (
            "/v2/resources/record/records?accessProfile=limited&accessProfile=caseworker",
            StatusCode::BAD_REQUEST,
            "request.access_profile_invalid",
        ),
        (
            "/v2/resources/record/records?accessProfile=missing",
            StatusCode::NOT_FOUND,
            "resource.not_found",
        ),
        (
            "/v2/resources/record/records?accessProfile=limited&fields=secretValue",
            StatusCode::BAD_REQUEST,
            "request.fields_invalid",
        ),
        (
            "/v2/resources/record/records?representation=limited",
            StatusCode::BAD_REQUEST,
            "request.access_profile_invalid",
        ),
        (
            "/v2/resources/record/records?%72%65%70%72%65%73%65%6e%74%61%74%69%6f%6e=limited",
            StatusCode::BAD_REQUEST,
            "request.access_profile_invalid",
        ),
    ] {
        let (status, _, body) = harness
            .send(Method::GET, uri, Some(&limited), None, &[])
            .await;
        assert_problem(status, &body, expected_status, code);
    }

    assert_eq!(
        sink.values()
            .iter()
            .filter(|event| event["phase"] == "attempt")
            .count(),
        0
    );

    let (status, _, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1?accessProfile=limited",
            Some(&limited),
            None,
            &[],
        )
        .await;
    assert_problem(
        status,
        &body,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );
    let correlated = sink
        .values()
        .into_iter()
        .filter(|event| event["operationIdentifier"] == "record.read")
        .collect::<Vec<_>>();
    assert_eq!(correlated.len(), 2);
    assert_eq!(correlated[0]["phase"], "attempt");
    assert_eq!(correlated[1]["phase"], "terminal");
    assert_eq!(correlated[1]["outcome"], "source-failed");
}

#[tokio::test]
async fn fields_only_minimize_the_selected_access_profile() {
    let harness = Harness::open(None, Arc::new(RecordingSink::default())).await;
    let limited = harness.token(&["registry:limited"], "review", "area-a");
    let (status, _, body) = harness
        .send(
            Method::POST,
            "/v2/resources/record/lookups/by-key?accessProfile=limited&fields=maskedSecret",
            Some(&limited),
            Some(json!({"selectors": {"lookupKey": "lookup-2"}})),
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let document: Value = serde_json::from_slice(&body).expect("JSON response");
    assert_eq!(
        document["data"]["domainData"],
        json!({"maskedSecret": "***CDEF"})
    );
    assert_eq!(document["meta"]["accessProfile"], "limited");
    assert_eq!(document["meta"]["selectedFields"], json!(["maskedSecret"]));

    let (status, _, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1?accessProfile=limited&fields=secretValue",
            Some(&limited),
            None,
            &[],
        )
        .await;
    assert_problem(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "request.fields_invalid",
    );
}

#[tokio::test]
async fn cursor_and_etag_are_bound_to_selected_access_profile() {
    let sink = Arc::new(RecordingSink::default());
    let valid_core_fixture = FIXTURE_SQL.replace("'not-a-core-date'", "'2026-08-01T12:00:00Z'");
    assert_ne!(valid_core_fixture, FIXTURE_SQL);
    let harness = Harness::open_with_fixture(None, Arc::clone(&sink), &valid_core_fixture).await;
    let all = harness.token(
        &["registry:limited", "registry:caseworker"],
        "review",
        "area-a",
    );
    let (status, headers, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1",
            None,
            None,
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let etag = headers
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("public profile has ETag")
        .to_owned();
    let document: Value = serde_json::from_slice(&body).expect("public JSON response");
    assert_eq!(
        document["meta"]["registryIdentifier"],
        "urn:example:registry:access-profiles"
    );
    assert_eq!(document["meta"]["datasetIdentifier"], "records");
    assert_eq!(document["meta"]["entityTypeIdentifier"], "record");
    assert!(document["data"].get("registryIdentifier").is_none());
    let (status, headers, _) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1?accessProfile=public",
            None,
            None,
            &[(IF_NONE_MATCH.as_str(), &etag)],
        )
        .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert_eq!(
        headers.get(ETAG).and_then(|value| value.to_str().ok()),
        Some(etag.as_str())
    );
    assert!(!body.is_empty());

    for value in ["*".to_owned(), format!("W/{etag}")] {
        let (status, _, body) = harness
            .send(
                Method::GET,
                "/v2/resources/record/records/record-1",
                None,
                None,
                &[(IF_NONE_MATCH.as_str(), &value)],
            )
            .await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
        assert!(body.is_empty());
    }
    let repeated = format!("\"absent\", W/{etag}");
    let (status, _, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1",
            None,
            None,
            &[
                (IF_NONE_MATCH.as_str(), "\"other\""),
                (IF_NONE_MATCH.as_str(), &repeated),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());

    let terminal = sink
        .values()
        .into_iter()
        .filter(|event| event["phase"] == "terminal")
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 5);
    assert_eq!(terminal[0]["outcome"], "released");
    assert!(terminal[1..]
        .iter()
        .all(|event| event["outcome"] == "not-modified"));
    let audit_wire = serde_json::to_string(&terminal).expect("audit serializes");
    for source_value in [
        "record-1",
        "Public one",
        "SENSITIVE-SOURCE-VALUE-7341",
        "2042-09-17",
    ] {
        assert!(!audit_wire.contains(source_value));
    }

    let (status, json_ld_headers, json_ld_body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1",
            None,
            None,
            &[
                (http::header::ACCEPT.as_str(), "application/ld+json"),
                (IF_NONE_MATCH.as_str(), &etag),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        json_ld_headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok()),
        Some(etag.as_str()),
        "the ETag must bind the selected representation"
    );
    let json_ld: Value = serde_json::from_slice(&json_ld_body).expect("JSON-LD response");
    assert_eq!(
        json_ld["@context"],
        json!([
            REGISTRY_RECORD_CONTEXT_ID,
            json_ld["meta"]["links"]["context"]
        ])
    );

    let (status, headers, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records?accessProfile=limited&pageSize=1",
            Some(&all),
            None,
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(headers.get(ETAG).is_none());
    let document: Value = serde_json::from_slice(&body).expect("JSON response");
    let cursor = document["pageInfo"]["nextCursor"]
        .as_str()
        .expect("limited cursor");
    let cursor_only_uri = format!("/v2/resources/record/records?cursor={cursor}");
    let (status, headers, body) = harness
        .send(Method::GET, &cursor_only_uri, Some(&all), None, &[])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(headers.get(ETAG).is_none());
    assert!(
        serde_json::from_slice::<Value>(&body).expect("cursor page JSON")["items"]
            .as_array()
            .is_some()
    );

    let caseworker_only = harness.token(&["registry:caseworker"], "review", "area-a");
    let (status, _, body) = harness
        .send(
            Method::GET,
            &cursor_only_uri,
            Some(&caseworker_only),
            None,
            &[],
        )
        .await;
    assert_problem(status, &body, StatusCode::NOT_FOUND, "resource.not_found");

    let uri = format!("/v2/resources/record/records?accessProfile=caseworker&cursor={cursor}");
    let (status, _, body) = harness.send(Method::GET, &uri, Some(&all), None, &[]).await;
    assert_problem(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "query.cursor_invalid",
    );
}

#[tokio::test]
async fn public_cursor_pages_are_not_cacheable() {
    let valid_core_fixture = FIXTURE_SQL.replace("'not-a-core-date'", "'2026-08-01T12:00:00Z'");
    let harness = Harness::open_with_fixture(
        None,
        Arc::new(RecordingSink::default()),
        &valid_core_fixture,
    )
    .await;
    let (status, headers, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records?pageSize=1",
            None,
            None,
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(headers.get(ETAG).is_none());
    let cursor = serde_json::from_slice::<Value>(&body).expect("first page JSON")["pageInfo"]
        ["nextCursor"]
        .as_str()
        .expect("first page cursor")
        .to_owned();
    let (status, headers, _) = harness
        .send(
            Method::GET,
            &format!("/v2/resources/record/records?cursor={cursor}"),
            None,
            None,
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(headers.get(ETAG).is_none());
}

#[tokio::test]
async fn malformed_list_lookahead_fails_atomically_without_value_disclosure() {
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open(None, Arc::clone(&sink)).await;

    let (status, _, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records?pageSize=1",
            None,
            None,
            &[],
        )
        .await;
    assert_problem(
        status,
        &body,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );

    let records = sink.values();
    let terminal = records
        .iter()
        .filter(|event| event["phase"] == "terminal")
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0]["outcome"], "source-failed");
    let response_and_audit = format!(
        "{}{}",
        String::from_utf8_lossy(&body),
        serde_json::to_string(&records).expect("audit serializes")
    );
    for source_value in [
        "record-1",
        "record-1a",
        "Public one",
        "Public invalid core",
        "not-a-core-date",
    ] {
        assert!(!response_and_audit.contains(source_value));
    }
}

#[tokio::test]
async fn accept_negotiation_uses_quality_and_json_tie_break_without_leaking_values() {
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open(None, Arc::clone(&sink)).await;

    for (accept, expected_type, expects_context) in [
        (
            "Application/LD+JSON ; Q = 0.5, application/json; q=0.4",
            "application/ld+json",
            true,
        ),
        (
            "application/ld+json;q=0.5, application/json;q=0.500",
            "application/json",
            false,
        ),
        (
            "application/ld+json;q=0.000, application/json;q=0.50",
            "application/json",
            false,
        ),
    ] {
        let (status, headers, body) = harness
            .send(
                Method::GET,
                "/v2/resources/record/records/record-1",
                None,
                None,
                &[(http::header::ACCEPT.as_str(), accept)],
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(expected_type)
        );
        let document: Value = serde_json::from_slice(&body).expect("response JSON");
        assert_eq!(document.get("@context").is_some(), expects_context);
        assert_eq!(
            document["meta"]["registryIdentifier"],
            "urn:example:registry:access-profiles"
        );
        assert_eq!(document["meta"]["datasetIdentifier"], "records");
        assert_eq!(document["meta"]["entityTypeIdentifier"], "record");
        for field in [
            "registryIdentifier",
            "datasetIdentifier",
            "entityTypeIdentifier",
        ] {
            assert!(document["data"].get(field).is_none());
        }
        let expected_link = format!(
            "<{REGISTRY_RECORD_PROFILE_ID}>; rel=\"profile\", <{RELAY_PROFILE_ID}>; rel=\"profile\""
        );
        assert_eq!(
            headers.get(LINK).and_then(|value| value.to_str().ok()),
            Some(expected_link.as_str())
        );
        if expects_context {
            assert_eq!(
                document["@context"],
                json!([
                    REGISTRY_RECORD_CONTEXT_ID,
                    document["meta"]["links"]["context"]
                ])
            );
        }
    }

    let (_, _, json_body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1",
            None,
            None,
            &[(http::header::ACCEPT.as_str(), "application/json")],
        )
        .await;
    let (_, _, json_ld_body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1",
            None,
            None,
            &[(http::header::ACCEPT.as_str(), "application/ld+json")],
        )
        .await;
    let json_document: Value = serde_json::from_slice(&json_body).expect("JSON response");
    let mut json_ld_document: Value =
        serde_json::from_slice(&json_ld_body).expect("JSON-LD response");
    json_ld_document
        .as_object_mut()
        .expect("JSON-LD envelope")
        .remove("@context");
    let record = json_ld_document["data"]
        .as_object_mut()
        .expect("JSON-LD Record");
    record.remove("@id");
    record.remove("@type");
    assert_eq!(json_ld_document, json_document);

    let (status, _, read_body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1",
            None,
            None,
            &[
                (http::header::ACCEPT.as_str(), "application/json;q=0.00"),
                (
                    http::header::ACCEPT.as_str(),
                    "application/ld+json; q=0.000",
                ),
            ],
        )
        .await;
    assert_problem(
        status,
        &read_body,
        StatusCode::NOT_ACCEPTABLE,
        "format.unsupported",
    );
    let records = sink.values();
    assert_eq!(records.last().expect("refusal exists")["phase"], "refusal");
    assert_eq!(
        records.last().expect("refusal exists")["outcome"],
        "invalid-request"
    );
    let audit_wire = serde_json::to_string(&records).expect("audit serializes");
    for source_value in [
        "record-1",
        "Public one",
        "SENSITIVE-SOURCE-VALUE-7341",
        "2042-09-17",
    ] {
        assert!(!audit_wire.contains(source_value));
    }
}

#[tokio::test]
async fn record_response_budget_refuses_oversized_json_and_json_ld_before_serialization() {
    let oversized_fixture = format!(
        "{FIXTURE_SQL}\n\
         DELETE FROM source_records\n\
         WHERE record_id NOT IN ('record-1', 'record-2', 'record-null', 'record-overlong-secret');\n\
         UPDATE source_records\n\
         SET public_name = replace(hex(zeroblob(480000)), '0', 'A'),\n\
             prederived_mask = replace(hex(zeroblob(480000)), '0', 'A');"
    );
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open_with_fixture(None, Arc::clone(&sink), &oversized_fixture).await;

    for accept in [None, Some("application/ld+json")] {
        let headers = accept
            .map(|value| vec![(http::header::ACCEPT.as_str(), value)])
            .unwrap_or_default();
        let (status, _, body) = harness
            .send(
                Method::GET,
                "/v2/resources/record/records?pageSize=4",
                None,
                None,
                &headers,
            )
            .await;
        assert_problem(
            status,
            &body,
            StatusCode::SERVICE_UNAVAILABLE,
            "source.unavailable",
        );
        assert!(
            !String::from_utf8_lossy(&body).contains(&"A".repeat(256)),
            "the bounded response refusal must not carry source values"
        );
    }

    let records = sink.values();
    assert_eq!(
        records
            .iter()
            .filter(|event| event["phase"] == "terminal")
            .count(),
        2
    );
    assert!(records
        .iter()
        .filter(|event| event["phase"] == "terminal")
        .all(|event| event["outcome"] == "source-failed"));
}

#[tokio::test]
async fn duplicate_identifier_fails_read_and_page_boundary_but_lookup_stays_unresolved() {
    let duplicate_fixture = FIXTURE_SQL.replace(
        "FROM source_records;",
        "FROM source_records\nUNION ALL\n\
         SELECT record_id, revision, lifecycle, '2026-08-01T12:00:00Z',\n\
                'DUPLICATE-LIST-CANARY-9073', prederived_mask, secret_value, event_date,\n\
                optional_value, lookup_key, authority\n\
         FROM source_records WHERE record_id = 'record-1';",
    );
    assert_ne!(duplicate_fixture, FIXTURE_SQL);
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open_with_fixture_and_list_order(
        None,
        Arc::clone(&sink),
        &duplicate_fixture,
        &["recorded_at", "record_id"],
    )
    .await;

    let (status, _, list_body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records?pageSize=1",
            None,
            None,
            &[],
        )
        .await;
    assert_problem(
        status,
        &list_body,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );
    let (status, _, read_body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1",
            None,
            None,
            &[],
        )
        .await;
    assert_problem(
        status,
        &read_body,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );
    let (status, _, lookup_body) = harness
        .send(
            Method::POST,
            "/v2/resources/record/lookups/by-key",
            None,
            Some(json!({"selectors": {"lookupKey": "lookup-1"}})),
            &[],
        )
        .await;
    assert_problem(
        status,
        &lookup_body,
        StatusCode::NOT_FOUND,
        "consultation.unresolved",
    );

    let records = sink.values();
    let terminal = records
        .iter()
        .filter(|event| event["phase"] == "terminal")
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 3);
    assert_eq!(terminal[0]["outcome"], "source-failed");
    assert_eq!(terminal[1]["outcome"], "source-failed");
    assert_eq!(terminal[2]["outcome"], "unresolved");
    let response_and_audit = format!(
        "{}{}{}{}",
        String::from_utf8_lossy(&list_body),
        String::from_utf8_lossy(&read_body),
        String::from_utf8_lossy(&lookup_body),
        serde_json::to_string(&records).expect("audit serializes")
    );
    for source_value in [
        "record-1",
        "lookup-1",
        "Public one",
        "DUPLICATE-LIST-CANARY-9073",
        "SENSITIVE-SOURCE-VALUE-7341",
        "2042-09-17",
    ] {
        assert!(!response_and_audit.contains(source_value));
    }
}

#[tokio::test]
async fn metadata_and_artifacts_authorize_each_access_profile_exactly() {
    let harness = Harness::open(None, Arc::new(RecordingSink::default())).await;
    let (status, _, body) = harness.send(Method::GET, "/v2", None, None, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body).expect("metadata is UTF-8");
    assert!(text.contains("public"));
    assert!(!text.contains("limited"));
    assert!(!text.contains("caseworker"));

    let limited_artifact = harness
        .artifacts
        .artifacts
        .iter()
        .find(|artifact| {
            matches!(
                &artifact.access_binding,
                Some(registry_relay_v2::artifacts::ArtifactAccessBinding::AccessProfile {
                    identifier
                }) if identifier == "limited"
            )
        })
        .expect("limited access profile artifact");
    let path = format!("/v2/artifacts/{}", limited_artifact.id);
    let caseworker = harness.token(&["registry:caseworker"], "review", "area-a");
    let (status, _, _) = harness
        .send(Method::GET, &path, Some(&caseworker), None, &[])
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let limited = harness.token(&["registry:limited"], "review", "area-a");
    let (status, _, body) = harness
        .send(Method::GET, &path, Some(&limited), None, &[])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, limited_artifact.content);
}

#[tokio::test]
async fn malformed_registry_core_fails_closed_and_list_release_is_atomic() {
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open(None, Arc::clone(&sink)).await;

    for uri in [
        "/v2/resources/record/records/record-1a",
        "/v2/resources/record/records?pageSize=2",
    ] {
        let (status, _, body) = harness.send(Method::GET, uri, None, None, &[]).await;
        assert_problem(
            status,
            &body,
            StatusCode::SERVICE_UNAVAILABLE,
            "source.unavailable",
        );
        let wire = String::from_utf8(body).expect("problem UTF-8");
        for source_value in [
            "record-1a",
            "not-a-core-date",
            "Public one",
            "Public invalid core",
        ] {
            assert!(!wire.contains(source_value));
        }
    }

    let (status, _, body) = harness
        .send(
            Method::POST,
            "/v2/resources/record/lookups/by-key",
            None,
            Some(json!({"selectors": {"lookupKey": "lookup-core"}})),
            &[],
        )
        .await;
    assert_problem(
        status,
        &body,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );

    let records = sink.values();
    let terminal = records
        .iter()
        .filter(|record| record["phase"] == "terminal")
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 3);
    assert_eq!(terminal[0]["outcome"], "source-failed");
    assert_eq!(terminal[1]["outcome"], "source-failed");
    assert_eq!(terminal[2]["outcome"], "source-failed");
    let audit_wire = serde_json::to_string(&records).expect("audit serializes");
    for source_value in [
        "record-1a",
        "not-a-core-date",
        "Public one",
        "Public invalid core",
        "lookup-core",
    ] {
        assert!(!audit_wire.contains(source_value));
    }
}

#[tokio::test]
async fn transforms_are_bounded_value_free_and_terminal_audit_gates_exact_bytes() {
    let sink = Arc::new(RecordingSink::default());
    let harness = Harness::open(None, Arc::clone(&sink)).await;
    let limited = harness.token(&["registry:limited"], "review", "area-a");
    let (status, _, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1?accessProfile=limited",
            Some(&limited),
            None,
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let document: Value = serde_json::from_slice(&body).expect("JSON response");
    assert_eq!(document["data"]["domainData"]["maskedSecret"], "***7341");
    assert_eq!(document["data"]["domainData"]["eventYear"], "2042");
    assert!(document["data"]["domainData"]
        .get("maskedOptional")
        .is_none());

    let records = sink.values();
    let correlated = records
        .iter()
        .filter(|record| record["operationIdentifier"] == "record.read")
        .collect::<Vec<_>>();
    assert_eq!(correlated.len(), 2);
    assert_eq!(correlated[0]["operationId"], correlated[1]["operationId"]);
    for record in &correlated {
        assert_eq!(record["accessProfile"], "limited");
        assert_eq!(record["disclosureProfile"], "limited-disclosure");
        assert_eq!(record["processingHandling"], "restricted");
        assert_eq!(record["disclosureHandling"], "confidential");
        assert_eq!(
            record["selectedProperties"],
            json!(["maskedSecret", "eventYear", "maskedOptional"])
        );
        assert_eq!(
            record["transformIdentifiers"],
            json!(["date-precision:date:year", "partial-string:suffix:4"])
        );
    }
    let audit_wire = serde_json::to_string(&records).expect("audit serializes");
    for canary in [
        "SENSITIVE-SOURCE-VALUE-7341",
        "***7341",
        "2042-09-17",
        "OPTIONAL-9",
    ] {
        assert!(!audit_wire.contains(canary), "audit disclosed value canary");
    }

    for record in [
        "record-bad-date",
        "record-null",
        "record-wrong-secret-type",
        "record-wrong-date-type",
        "record-overlong-secret",
        "record-overlong-date",
    ] {
        let uri = format!("/v2/resources/record/records/{record}?accessProfile=limited");
        let (status, _, body) = harness
            .send(Method::GET, &uri, Some(&limited), None, &[])
            .await;
        assert_problem(
            status,
            &body,
            StatusCode::SERVICE_UNAVAILABLE,
            "source.unavailable",
        );
        let problem = String::from_utf8(body).expect("problem UTF-8");
        assert!(!problem.contains(record));
        assert!(!problem.contains("not-a-date"));
        assert!(!problem.contains("AAAAAAAAAAAAAAAA"));
    }

    let (status, _, body) = harness
        .send(
            Method::POST,
            "/v2/resources/record/lookups/by-key?accessProfile=limited",
            Some(&limited),
            Some(json!({"selectors": {"lookupKey": "lookup-3"}})),
            &[],
        )
        .await;
    assert_problem(
        status,
        &body,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );
    assert!(!String::from_utf8(body)
        .expect("problem UTF-8")
        .contains("not-a-date"));

    let failing = Harness::open(None, Arc::new(RecordingSink::failing_after(1))).await;
    let token = failing.token(&["registry:limited"], "review", "area-a");
    let (status, _, body) = failing
        .send(
            Method::GET,
            "/v2/resources/record/records/record-2?accessProfile=limited",
            Some(&token),
            None,
            &[],
        )
        .await;
    assert_problem(
        status,
        &body,
        StatusCode::SERVICE_UNAVAILABLE,
        "audit.unavailable",
    );
    assert!(!String::from_utf8(body)
        .expect("problem UTF-8")
        .contains("***CDEF"));
}

#[tokio::test]
async fn quotas_remain_operation_scoped_across_access_profiles() {
    let harness = Harness::open(
        Some(QuotaConfig {
            requests_per_minute: 1,
            burst: 1,
        }),
        Arc::new(RecordingSink::default()),
    )
    .await;
    let all = harness.token(
        &["registry:limited", "registry:caseworker"],
        "review",
        "area-a",
    );
    let (status, _, _) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1?accessProfile=public",
            None,
            None,
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1?accessProfile=caseworker",
            Some(&all),
            None,
            &[],
        )
        .await;
    assert_problem(
        status,
        &body,
        StatusCode::TOO_MANY_REQUESTS,
        "consultation.rate_limited",
    );

    let (status, _, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1?accessProfile=public",
            None,
            None,
            &[],
        )
        .await;
    assert_problem(
        status,
        &body,
        StatusCode::TOO_MANY_REQUESTS,
        "consultation.rate_limited",
    );

    let (status, _, body) = harness
        .send(
            Method::GET,
            "/v2/resources/record/records/record-1?accessProfile=caseworker",
            Some(&all),
            None,
            &[],
        )
        .await;
    assert_problem(
        status,
        &body,
        StatusCode::TOO_MANY_REQUESTS,
        "consultation.rate_limited",
    );
}

fn assert_problem(actual: StatusCode, body: &[u8], expected: StatusCode, code: &str) {
    assert_eq!(actual, expected);
    let document: Value = serde_json::from_slice(body).expect("problem JSON");
    assert_eq!(document["code"], code);
    let wire = String::from_utf8_lossy(body);
    for value in [
        "ABCD",
        "ABCDEF",
        "not-a-date",
        "not-a-core-date",
        "OPTIONAL-9",
    ] {
        assert!(!wire.contains(value));
    }
}

fn problem_without_trace(body: &[u8]) -> Value {
    let mut document: Value = serde_json::from_slice(body).expect("problem JSON");
    document
        .as_object_mut()
        .expect("problem object")
        .remove("traceId");
    document
}

fn compiled_registry(fingerprint: String) -> CompiledRegistry {
    let core_columns = ["record_id", "revision", "lifecycle", "recorded_at"];
    let public = access_profile(
        "public",
        CompiledAccess::Public,
        "public-disclosure",
        &["publicName", "prederivedMask"],
        &core_columns
            .into_iter()
            .chain(["public_name", "prederived_mask"])
            .collect::<Vec<_>>(),
        Handling::Public,
        Handling::Public,
        &[],
    );
    let protected_access = |scope: &str| CompiledAccess::Protected {
        scope: scope.into(),
        purpose: Some(CompiledPurpose {
            claim: "purpose".into(),
            allowed: vec!["review".into()],
        }),
        row_binding: Some(CompiledRowBinding {
            source: RowAuthoritySource::Claim("authority".into()),
            source_column: "authority".into(),
        }),
    };
    let limited = access_profile(
        "limited",
        protected_access("registry:limited"),
        "limited-disclosure",
        &["maskedSecret", "eventYear", "maskedOptional"],
        &core_columns
            .into_iter()
            .chain(["secret_value", "event_date", "optional_value"])
            .collect::<Vec<_>>(),
        Handling::Restricted,
        Handling::Confidential,
        &[
            "maskedSecret=partial-string:suffix:4",
            "eventYear=date-precision:date:year",
            "maskedOptional=partial-string:suffix:4",
        ],
    );
    let caseworker = access_profile(
        "caseworker",
        protected_access("registry:caseworker"),
        "caseworker-disclosure",
        &["secretValue"],
        &core_columns
            .into_iter()
            .chain(["secret_value"])
            .collect::<Vec<_>>(),
        Handling::Restricted,
        Handling::Restricted,
        &[],
    );
    let access_profiles = vec![public.clone(), limited.clone(), caseworker.clone()];
    let list = CompiledOperation {
        identifier: "record.list".into(),
        family: CapabilityFamily::Consultation,
        pattern: ConsultationPattern::List,
        kind: OperationKind::List,
        default_access_profile: "public".into(),
        access_profiles: access_profiles.clone(),
        query: QueryPlan {
            source: SOURCE.into(),
            view: "relay_records".into(),
            filters: Vec::new(),
            spatial_bbox: None,
            selectors: Vec::new(),
            order_by: vec!["record_id".into()],
            allow_unfiltered: true,
            pagination: Some(CompiledPagination {
                default_page_size: 2,
                maximum_page_size: 4,
            }),
            maximum_request_body_bytes: None,
        },
    };
    let read = CompiledOperation {
        identifier: "record.read".into(),
        family: CapabilityFamily::Consultation,
        pattern: ConsultationPattern::Retrieve,
        kind: OperationKind::Read,
        default_access_profile: "public".into(),
        access_profiles: access_profiles.clone(),
        query: QueryPlan {
            source: SOURCE.into(),
            view: "relay_records".into(),
            filters: Vec::new(),
            spatial_bbox: None,
            selectors: Vec::new(),
            order_by: Vec::new(),
            allow_unfiltered: false,
            pagination: None,
            maximum_request_body_bytes: None,
        },
    };
    let lookup = CompiledOperation {
        identifier: "record.lookup.by-key".into(),
        family: CapabilityFamily::Consultation,
        pattern: ConsultationPattern::Search,
        kind: OperationKind::Lookup {
            name: "by-key".into(),
        },
        default_access_profile: "public".into(),
        access_profiles,
        query: QueryPlan {
            source: SOURCE.into(),
            view: "relay_records".into(),
            filters: Vec::new(),
            spatial_bbox: None,
            selectors: vec![CompiledSelector {
                name: "lookupKey".into(),
                source_column: "lookup_key".into(),
                data_type: DataType::String,
                minimum_bytes: Some(1),
                maximum_bytes: Some(32),
                codelist: None,
            }],
            order_by: Vec::new(),
            allow_unfiltered: false,
            pagination: None,
            maximum_request_body_bytes: Some(256),
        },
    };
    CompiledRegistry {
        contract_revision: "sha256:contract".into(),
        contract_id: "access-profile-tests".into(),
        contract_version: "1".into(),
        registry_identifier: "urn:example:registry:access-profiles".into(),
        registry_name: "Access profile test Registry".into(),
        authority_identifier: "urn:example:authority".into(),
        authority_name: "Example Authority".into(),
        operator_identifier: None,
        operator_name: None,
        authoritative_scope: "Synthetic access profile tests".into(),
        base_uri: "https://registry.example.invalid/".into(),
        identifier_lifecycle_policy_ref: "governance/lifecycle.yaml".into(),
        alignment_targets: Vec::new(),
        controller_identifier: "urn:example:authority".into(),
        publisher_identifier: "urn:example:authority".into(),
        audit_owner_identifier: "urn:example:audit".into(),
        publication: None,
        local_vocabulary: "https://registry.example.invalid/vocabulary/".into(),
        semantic_alignments: Vec::new(),
        governed_files: Vec::new(),
        classification_review: None,
        codelists: vec![CompiledCodelist {
            path: "codelists/lifecycle.yaml".into(),
            id: "lifecycle".into(),
            version: "1".into(),
            values: vec!["ACTIVE".into()],
        }],
        sources: vec![CompiledSource {
            id: SOURCE.into(),
            profile: SourceProfile::Snapshot,
            expected_schema_fingerprint: fingerprint,
            observed_schema: None,
        }],
        resources: vec![CompiledResource {
            id: RESOURCE.into(),
            dataset_identifier: "records".into(),
            entity_type_identifier: "record".into(),
            title: "Record".into(),
            description: "Synthetic record".into(),
            semantic_class: "https://registry.example.invalid/vocabulary/Record".into(),
            source: SOURCE.into(),
            view: "relay_records".into(),
            record_context: CompiledRecordContext {
                record_identifier_column: "record_id".into(),
                revision_identifier_column: "revision".into(),
                lifecycle_state_column: "lifecycle".into(),
                lifecycle_state_codelist: "codelists/lifecycle.yaml".into(),
                recorded_at_column: "recorded_at".into(),
                schema_reference: "https://registry.example.invalid/artifacts/full-schema".into(),
                semantic_model_reference: "https://registry.example.invalid/artifacts/full-model"
                    .into(),
            },
            properties: properties(),
            primary_geometry: None,
            disclosure_profiles: vec![
                disclosure(
                    "public-disclosure",
                    &["publicName", "prederivedMask"],
                    Handling::Public,
                ),
                disclosure(
                    "limited-disclosure",
                    &["maskedSecret", "eventYear", "maskedOptional"],
                    Handling::Confidential,
                ),
                disclosure(
                    "caseworker-disclosure",
                    &["secretValue"],
                    Handling::Restricted,
                ),
            ],
            operations: vec![list, read, lookup],
            column_accounting: Vec::new(),
            processing_descriptions: Vec::new(),
        }],
        statistical_datasets: Vec::new(),
        metadata_visibility: CompiledMetadataVisibility {
            service: Visibility::Public,
            resources: Visibility::Public,
            statistical_datasets: None,
            semantics: Visibility::Public,
            classifications: Visibility::OperatorOnly,
            processing: Visibility::OperatorOnly,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn access_profile(
    id: &str,
    access: CompiledAccess,
    disclosure_profile: &str,
    selectable: &[&str],
    projected: &[&str],
    processing: Handling,
    disclosure: Handling,
    transforms: &[&str],
) -> CompiledAccessProfile {
    let stem = format!("https://registry.example.invalid/artifacts/{id}");
    CompiledAccessProfile {
        id: id.into(),
        access,
        disclosure_profile: disclosure_profile.into(),
        selectable_properties: selectable.iter().map(|value| (*value).into()).collect(),
        projected_columns: projected.iter().map(|value| (*value).into()).collect(),
        processing_handling: processing,
        disclosure_handling: disclosure,
        transform_inventory: transforms.iter().map(|value| (*value).into()).collect(),
        schema_reference: format!("{stem}-schema"),
        semantic_model_reference: format!("{stem}-model"),
        context_reference: format!("{stem}-context"),
    }
}

fn disclosure(id: &str, properties: &[&str], handling: Handling) -> CompiledDisclosureProfile {
    CompiledDisclosureProfile {
        id: id.into(),
        properties: properties.iter().map(|value| (*value).into()).collect(),
        maximum_handling: handling,
    }
}

fn properties() -> Vec<CompiledProperty> {
    vec![
        property(
            "publicName",
            "public_name",
            DataType::String,
            true,
            Handling::Public,
            None,
        ),
        property(
            "prederivedMask",
            "prederived_mask",
            DataType::String,
            true,
            Handling::Public,
            None,
        ),
        property(
            "maskedSecret",
            "secret_value",
            DataType::String,
            true,
            Handling::Confidential,
            Some(CompiledTransform::PartialString {
                identifier: "partial-string:suffix:4".into(),
                reveal: PartialStringReveal::Suffix,
                characters: 4,
            }),
        ),
        property(
            "eventYear",
            "event_date",
            DataType::Year,
            true,
            Handling::Confidential,
            Some(CompiledTransform::DatePrecision {
                identifier: "date-precision:date:year".into(),
                source_type: DateInputType::Date,
                precision: DatePrecision::Year,
            }),
        ),
        property(
            "maskedOptional",
            "optional_value",
            DataType::String,
            false,
            Handling::Confidential,
            Some(CompiledTransform::PartialString {
                identifier: "partial-string:suffix:4".into(),
                reveal: PartialStringReveal::Suffix,
                characters: 4,
            }),
        ),
        property(
            "secretValue",
            "secret_value",
            DataType::String,
            true,
            Handling::Restricted,
            None,
        ),
    ]
}

fn property(
    name: &str,
    source_column: &str,
    data_type: DataType,
    source_required: bool,
    handling: Handling,
    transform: Option<CompiledTransform>,
) -> CompiledProperty {
    CompiledProperty {
        name: name.into(),
        label: name.into(),
        description: format!("Synthetic {name}"),
        source_required,
        semantic_iri: format!("https://registry.example.invalid/vocabulary/{name}"),
        classification: EffectiveClassification {
            privacy: "synthetic".into(),
            privacy_scheme: "https://example.invalid/privacy".into(),
            privacy_version: "1".into(),
            institutional: handling_label(handling).into(),
            institutional_scheme: "https://example.invalid/institutional".into(),
            institutional_version: "1".into(),
            handling,
            handling_scheme: "https://id.registrystack.org/vocab/handling".into(),
            handling_version: "1".into(),
            status: ReviewStatus::Reviewed,
            provenance_ref: "governance/review.yaml".into(),
        },
        binding: CompiledPropertyBinding::Scalar(CompiledScalarPropertyBinding {
            source_column: source_column.into(),
            transform,
            data_type,
            codelist: None,
        }),
    }
}

fn handling_label(handling: Handling) -> &'static str {
    match handling {
        Handling::Public => "public",
        Handling::Internal => "internal",
        Handling::Confidential => "confidential",
        Handling::Restricted => "restricted",
    }
}
