// SPDX-License-Identifier: Apache-2.0

//! Every concealed read refusal answers with the fixed 404 problem, counts
//! once under `breg_request_refusals_total{check}`, and writes one value-free
//! `request refused` line that names the check.
//!
//! The recorder is process-wide and admits five log lines per check per
//! minute, so this file drives every case from one test and keeps each check
//! under that bound.
//!
//! `tests/golden/concealment_refusals.json` freezes the status, the headers
//! that matter and the body (minus `traceId`) of each answer.
//! `REGISTRY_BREG_WRITE_GOLDEN=1` rewrites it. A change to the file in a
//! review is a change to a public response.

#![cfg(feature = "runtime")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderValue, Request};
use registry_breg::api::{
    authenticated_router, HeldReadResponse, HttpService, ReadRuntimeIdentity, ReadServiceError,
    ReadinessProbe, RecordReadRequest, RecordReadService, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::metrics::{metrics_app, Metrics};
use registry_breg::{compile_project, parse_project_yaml, CompileProfile, CompiledRegistry};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{ClaimNames, JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{
    fixtures, oidc_verifier_config, sign_ed25519_compact_jwt, MockIdp,
};
use serde_json::{json, Value};
use tower::ServiceExt as _;
use tracing::instrument::WithSubscriber;
use zeroize::Zeroizing;

const AUDIENCE: &str = "urn:example:breg";
const PRINCIPAL: &str = "principal-value-never-rendered";
const ACTOR_ID: &str = "00000000-0000-4000-8000-0000000000aa";
const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
const GOLDEN: &str = "tests/golden/concealment_refusals.json";

const PROJECT: &str = r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {id: concealment-recording, version: 0.1.0, defaultLanguage: en, canonicalBaseIri: https://authoring.example.test}
recordTypes:
  case:
    primaryDataset: test-dataset
    route: cases
    mutationMode: mutable
    tombstone: false
    classification: public
    fields:
      - {id: label, type: string, required: true, maximumLength: 100, classification: public}
      - {id: tenant, type: string, required: true, maximumLength: 100, classification: internal}
datasets:
  test-dataset: {}

accessProfiles:
  reader:
    default: true
    principalClaim: sub
    requiredScopes: [registry.read]
    permissions:
      records:
        - {recordType: case, operations: [get, list], readableFields: [label], rowBoundaries: unrestricted}
  purposeful:
    principalClaim: sub
    requiredScopes: unrestricted
    requiredPurposes: [record-review]
    permissions:
      records:
        - {recordType: case, operations: [get], readableFields: [label], rowBoundaries: unrestricted}
  human-only:
    principalClaim: sub
    requiredScopes: unrestricted
    actorKind: human
    requesterClients: [human-client]
    permissions:
      records:
        - {recordType: case, operations: [get], readableFields: [label], rowBoundaries: unrestricted}
  client-bound:
    principalClaim: sub
    requiredScopes: unrestricted
    actorKind: service
    requesterClients: [agent-client]
    permissions:
      records:
        - {recordType: case, operations: [get], readableFields: [label], rowBoundaries: unrestricted}
  tenant-bound:
    principalClaim: sub
    requiredScopes: unrestricted
    permissions:
      records:
        - recordType: case
          operations: [get]
          readableFields: [label]
          rowBoundaries:
            - {field: tenant, claim: tenant_claim, operator: equals}
  granted:
    principalClaim: sub
    requiredScopes: unrestricted
    actorKind: agent
    requesterClients: [agent-client]
    requiredPurposes: [record-review]
    taskGrant: {sourceIssuer: https://casework.example}
    permissions:
      records:
        - {recordType: case, operations: [get], readableFields: [label], rowBoundaries: unrestricted}
"#;

struct EmptyReads;

impl RecordReadService for EmptyReads {
    fn get(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
    }

    fn list(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        Box::pin(async {
            Ok(HeldReadResponse::from_json(&json!({"items": []})).expect("fixture serializes"))
        })
    }

    fn lookup(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
    }
}

struct Ready;

impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn compiled(source: &str) -> Arc<CompiledRegistry> {
    let project = parse_project_yaml(source.as_bytes()).expect("project parses");
    Arc::new(compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles"))
}

fn service(registry: Arc<CompiledRegistry>) -> HttpService {
    HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: "package-refusal-test".to_owned(),
            schema_fingerprint: "schema-refusal-test".to_owned(),
        },
        Arc::new(EmptyReads),
        Arc::new(Ready),
        Arc::new(
            CursorCodec::new(
                Zeroizing::new(vec![0x43; 32]),
                std::time::Duration::from_secs(300),
            )
            .expect("test cursor key is valid"),
        ),
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}

fn key_source(idp: &MockIdp) -> Arc<JwksFetcher> {
    Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ))
}

struct Harness {
    app: axum::Router,
    idp: MockIdp,
}

impl Harness {
    async fn start() -> Self {
        let registry = compiled(PROJECT);
        let idp = MockIdp::start().await;
        let mut verifier = oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]);
        verifier.allowed_clients = vec![
            "agent-client".to_owned(),
            "other-client".to_owned(),
            "human-client".to_owned(),
        ];
        let claims = AuthorityClaimConfig::new("sub", Some("registry_purpose".to_owned()))
            .with_contextual_claims(
                ClaimNames::default(),
                BTreeMap::from([("agent-client".to_owned(), ACTOR_ID.to_owned())]),
            );
        let authenticator =
            RegistryAuthenticator::new(&registry, verifier, key_source(&idp), claims)
                .expect("authentication config is valid");
        let app = authenticated_router(Arc::new(service(registry)), Arc::new(authenticator));
        Self { app, idp }
    }

    fn token(&self, mut claims: Value) -> String {
        let now = unix_now();
        let object = claims.as_object_mut().expect("claims are an object");
        object
            .entry("iss")
            .or_insert_with(|| json!(self.idp.issuer()));
        object.entry("iat").or_insert_with(|| json!(now));
        object.entry("nbf").or_insert_with(|| json!(now));
        object.entry("exp").or_insert_with(|| json!(now + 900));
        sign_ed25519_compact_jwt(
            fixtures::ED25519_PRIVATE_JWK,
            "JWT",
            "registry-platform-testing-ed25519-1",
            claims,
        )
    }
}

fn service_claims() -> Value {
    json!({
        "aud": AUDIENCE,
        "sub": PRINCIPAL,
        "azp": "agent-client",
        "registry_actor_kind": "service",
        "scope": "registry.read",
    })
}

fn with(mut claims: Value, key: &str, value: Value) -> Value {
    claims
        .as_object_mut()
        .expect("claims are an object")
        .insert(key.to_owned(), value);
    claims
}

fn without(mut claims: Value, key: &str) -> Value {
    claims
        .as_object_mut()
        .expect("claims are an object")
        .remove(key);
    claims
}

fn grant_claims(now: u64) -> Value {
    json!({
        "aud": AUDIENCE,
        "sub": PRINCIPAL,
        "registry_principal": PRINCIPAL,
        "azp": "agent-client",
        "registry_actor_kind": "agent",
        "registry_purpose": "record-review",
        "request_purpose": "record-review",
        "registry_grant_id": "00000000-0000-4000-8000-0000000000bf",
        "registry_approver": "h:synthetic-approver",
        "registry_grant_source_issuer": "https://casework.example",
        "registry_grant_client": "agent-client",
        "registry_grant_resource": AUDIENCE,
        "registry_grant_exp": now + 600,
        "registry_grant_bounds": {"type":"breg","permissions":[{"collection":"cases","operations":["get"]}]},
        "identity": {"tenant_claim": "tenant-from-approved-identity"},
    })
}

fn read_request(path: &str, token: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("request");
    if let Some(token) = token {
        request.headers_mut().append(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
        );
    }
    request
}

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("captured log buffer")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

impl CapturedLogs {
    fn subscriber(&self) -> tracing::Dispatch {
        let writer = self.clone();
        tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_ansi(false)
                .with_writer(writer)
                .finish(),
        )
    }

    fn events(&self) -> Vec<Value> {
        let bytes = self.0.lock().expect("captured log buffer").clone();
        String::from_utf8(bytes)
            .expect("log lines are UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON log line"))
            .collect()
    }
}

/// The counter, read the way an operator reads it: from the metrics listener.
async fn refusal_counts() -> BTreeMap<String, u64> {
    let response = metrics_app(Arc::new(Metrics::without_pool_for_test()))
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .expect("scrape request"),
        )
        .await
        .expect("metrics respond");
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("metrics body");
    let text = String::from_utf8(bytes.to_vec()).expect("metrics are UTF-8");
    let mut counts = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("breg_request_refusals_total{check=\"") {
            let (label, value) = rest.split_once("\"} ").expect("sample line");
            counts.insert(label.to_owned(), value.parse().expect("counter value"));
        }
    }
    counts
}

struct Observed {
    name: &'static str,
    expected_check: &'static str,
    answer: Value,
    counted: BTreeMap<String, u64>,
    refusal_lines: Vec<Value>,
    log_text: String,
}

async fn observe(
    name: &'static str,
    expected_check: &'static str,
    app: &axum::Router,
    request: Request<Body>,
) -> Observed {
    let captured = CapturedLogs::default();
    let before = refusal_counts().await;
    let response = app
        .clone()
        .oneshot(request)
        .with_subscriber(captured.subscriber())
        .await
        .expect("router responds");
    let after = refusal_counts().await;
    let status = response.status().as_u16();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .map(|value| value.to_str().expect("ASCII header").to_owned())
    };
    let content_type = header("content-type");
    let cache_control = header("cache-control");
    let www_authenticate = header("www-authenticate");
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    let mut body: Value = serde_json::from_slice(&bytes).expect("problem body is JSON");
    assert!(
        body.as_object_mut()
            .expect("problem body is an object")
            .remove("traceId")
            .is_some_and(|trace| trace.as_str().is_some_and(|id| id.len() == 32)),
        "{name}: the problem carries the request trace id"
    );
    let counted = after
        .iter()
        .filter_map(|(label, value)| {
            let delta = value - before.get(label).copied().unwrap_or(0);
            (delta > 0).then(|| (label.clone(), delta))
        })
        .collect();
    let events = captured.events();
    let log_text = events.iter().map(Value::to_string).collect::<String>();
    let refusal_lines = events
        .into_iter()
        .filter(|event| event["fields"]["message"] == "request refused")
        .collect();
    Observed {
        name,
        expected_check,
        answer: json!({
            "status": status,
            "contentType": content_type,
            "cacheControl": cache_control,
            "wwwAuthenticate": www_authenticate,
            "body": body,
        }),
        counted,
        refusal_lines,
        log_text,
    }
}

#[tokio::test]
async fn every_concealed_read_refusal_is_counted_logged_and_unchanged_on_the_wire() {
    let record = format!("/v1/records/cases/{RECORD_ID}");
    let now = unix_now();
    let harness = Harness::start().await;
    let token = |claims: Value| harness.token(claims);
    let mut observed = Vec::new();

    let ok = token(service_claims());
    let tenant_token = |tenant: Option<&str>| {
        let claims = service_claims();
        match tenant {
            Some(tenant) => token(with(claims, "tenant_claim", json!(tenant))),
            None => token(claims),
        }
    };
    let cases: Vec<(&'static str, &'static str, Request<Body>)> = vec![
        (
            "unknown-access-profile",
            "access-profile",
            read_request(&format!("{record}?accessProfile=nobody"), Some(&ok)),
        ),
        (
            "missing-scope",
            "scope",
            // The token carries another scope, so the line can be seen to name
            // the declared one and not the presented one.
            read_request(
                &record,
                Some(&token(with(
                    service_claims(),
                    "scope",
                    json!("token-held-canary-scope"),
                ))),
            ),
        ),
        (
            "purpose-not-declared",
            "purpose",
            read_request(&format!("{record}?accessProfile=purposeful"), Some(&ok)),
        ),
        (
            "actor-kind-mismatch",
            "actor-kind",
            read_request(&format!("{record}?accessProfile=human-only"), Some(&ok)),
        ),
        (
            "requester-client-not-admitted",
            "requester-client",
            read_request(
                &format!("{record}?accessProfile=client-bound"),
                Some(&token(with(service_claims(), "azp", json!("other-client")))),
            ),
        ),
        (
            "row-claim-missing",
            "row-boundary",
            read_request(
                &format!("{record}?accessProfile=tenant-bound"),
                Some(&tenant_token(None)),
            ),
        ),
        (
            "task-grant-missing",
            "task-grant-missing",
            read_request(
                &format!("{record}?accessProfile=granted"),
                Some(&token(with(
                    with(
                        with(service_claims(), "registry_actor_kind", json!("agent")),
                        "registry_purpose",
                        json!("record-review"),
                    ),
                    "act",
                    json!({"sub": ACTOR_ID, "iss": harness.idp.issuer()}),
                ))),
            ),
        ),
        (
            "task-grant-from-another-issuer",
            "task-grant-binding",
            read_request(
                &format!("{record}?accessProfile=granted"),
                Some(&token(with(
                    grant_claims(now),
                    "registry_grant_source_issuer",
                    json!("https://other.example"),
                ))),
            ),
        ),
        (
            "task-grant-bounds-do-not-cover-the-profile",
            "task-grant-scope",
            read_request(
                &format!("{record}?accessProfile=granted"),
                Some(&token(with(
                    grant_claims(now),
                    "registry_grant_bounds",
                    json!({"type":"breg","permissions":[{"collection":"cases","operations":["list"]}]}),
                ))),
            ),
        ),
        (
            "select-beyond-the-readable-fields",
            "disclosure",
            read_request(&format!("{record}?$select=tenant"), Some(&ok)),
        ),
        (
            "record-id-is-not-a-uuid",
            "visibility",
            read_request("/v1/records/cases/not-a-uuid", Some(&ok)),
        ),
        (
            "record-is-absent-or-outside-the-boundary",
            "visibility",
            read_request(&record, Some(&ok)),
        ),
        (
            "schema-of-a-record-type-the-caller-cannot-read",
            "visibility",
            read_request(
                "/v1/schemas/cases",
                Some(&token(without(service_claims(), "scope"))),
            ),
        ),
    ];
    for (name, check, request) in cases {
        observed.push(observe(name, check, &harness.app, request).await);
    }

    // The answers, frozen.
    let answers: BTreeMap<&str, &Value> = observed
        .iter()
        .map(|case| (case.name, &case.answer))
        .collect();
    let golden_path = format!("{}/{GOLDEN}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("REGISTRY_BREG_WRITE_GOLDEN").is_some() {
        let mut text = serde_json::to_string_pretty(&answers).expect("answers serialize");
        text.push('\n');
        std::fs::write(&golden_path, text).expect("golden file is writable");
    } else {
        let frozen: Value = serde_json::from_str(
            &std::fs::read_to_string(&golden_path).expect("golden file exists"),
        )
        .expect("golden file is JSON");
        assert_eq!(
            serde_json::to_value(&answers).expect("answers serialize"),
            frozen,
            "a concealed refusal changed on the wire"
        );
    }

    // The recording: one count, one line, no caller value.
    let mut used: BTreeSet<&str> = BTreeSet::new();
    for case in &observed {
        used.insert(case.expected_check);
        assert_eq!(
            case.counted,
            BTreeMap::from([(case.expected_check.to_owned(), 1)]),
            "{}: the refusal counts once under its check",
            case.name
        );
        assert_eq!(
            case.refusal_lines.len(),
            1,
            "{}: one refusal line",
            case.name
        );
        let line = &case.refusal_lines[0];
        assert_eq!(line["level"], "INFO", "{}", case.name);
        let fields = line["fields"].as_object().expect("line fields");
        assert_eq!(fields["decision"], "refused", "{}", case.name);
        assert_eq!(fields["failed_check"], case.expected_check, "{}", case.name);
        assert_eq!(fields["suppressed"], 0, "{}", case.name);
        let keys: BTreeSet<&str> = fields.keys().map(String::as_str).collect();
        let mut expected = BTreeSet::from([
            "decision",
            "failed_check",
            "message",
            "suppressed",
            "trace_id",
        ]);
        if case.expected_check == "scope" {
            // A scope refusal also names what the operator declared: the scope
            // claim, the scope the profile needs and the profile.
            expected.extend(["scope_claim", "required_scope", "access_profile"]);
            assert_eq!(fields["scope_claim"], "scope", "{}", case.name);
            assert_eq!(fields["required_scope"], "registry.read", "{}", case.name);
            assert_eq!(fields["access_profile"], "reader", "{}", case.name);
        }
        assert_eq!(
            keys, expected,
            "{}: the line carries only the fixed fields",
            case.name
        );
        for canary in [
            PRINCIPAL,
            "agent-client",
            "other-client",
            "token-held-canary-scope",
            "nobody",
            "not-a-uuid",
            "https://other.example",
            "Bearer",
        ] {
            assert!(
                !case.log_text.contains(canary),
                "{}: the log exposed {canary}",
                case.name
            );
        }
    }
    assert!(
        used.len() >= 11,
        "the cases cover every concealment check of the read routes"
    );
}
