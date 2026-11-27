// SPDX-License-Identifier: Apache-2.0

//! Every authentication refusal answers with the fixed 401 problem, counts
//! once under `breg_request_refusals_total{check}`, and writes one value-free
//! `request refused` line that names the check.
//!
//! The recorder is process-wide and admits five log lines per check per
//! minute, so this file drives every case from one test and keeps each check
//! under that bound.
//!
//! `tests/golden/authentication_refusals.json` freezes the status, the
//! headers that matter and the body (minus `traceId`) of each answer.
//! `REGISTRY_BREG_WRITE_GOLDEN=1` rewrites it. A change to the file in a
//! review is a change to a public response.

#![cfg(feature = "runtime")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderValue, Request};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::Algorithm;
use registry_breg::api::{
    authenticated_router, router, HeldReadResponse, HttpService, ReadRuntimeIdentity,
    ReadServiceError, ReadinessProbe, RecordReadRequest, RecordReadService, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::metrics::{metrics_app, Metrics};
use registry_breg::postgres::{ConnectionConfig, PoolBounds};
use registry_breg::review_store::{
    ReviewAuthorityClient, ReviewAuthorityRegistry, ReviewCompletionReceiver,
};
use registry_breg::{compile_project, parse_project_yaml, CompileProfile, CompiledRegistry};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{ClaimNames, JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use registry_platform_testing::{
    fixtures, oidc_verifier_config, sign_ed25519_compact_jwt, MockIdp,
};
use registry_review_client::{ReviewClient, ReviewClientConfig};
use serde_json::{json, Value};
use tower::ServiceExt as _;
use tracing::instrument::WithSubscriber;
use zeroize::Zeroizing;

const AUDIENCE: &str = "urn:example:breg";
const PRINCIPAL: &str = "principal-value-never-rendered";
const ACTOR_ID: &str = "00000000-0000-4000-8000-0000000000aa";
const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
const GOLDEN: &str = "tests/golden/authentication_refusals.json";

const PROJECT: &str = r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {id: refusal-recording, version: 0.1.0, defaultLanguage: en, canonicalBaseIri: https://authoring.example.test}
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
  public:
    default: true
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    permissions:
      records:
        - {recordType: case, operations: [get], readableFields: [label], rowBoundaries: unrestricted}
"#;

const CONTEXTUAL_PROJECT: &str = r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {id: refusal-recording-contextual, version: 0.1.0, defaultLanguage: en, canonicalBaseIri: https://authoring.example.test}
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
  standing-agent:
    principalClaim: sub
    requiredScopes: unrestricted
    actorKind: agent
    requesterClients: [agent-client]
    requiredPurposes: [citizen-self-service]
    permissions:
      records:
        - {recordType: case, operations: [get], readableFields: [label], rowBoundaries: unrestricted}
  delegated-agent:
    default: true
    principalClaim: sub
    requiredScopes: unrestricted
    actorKind: agent
    requesterClients: [agent-client]
    requiredPurposes: [record-review]
    taskGrant: {sourceIssuer: https://casework.example}
    permissions:
      records:
        - recordType: case
          operations: [get]
          readableFields: [label]
          rowBoundaries:
            - {field: tenant, claim: tenant_claim, operator: equals}
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
        FetchUrlPolicy::https_or_loopback(),
    ))
}

struct Harness {
    app: axum::Router,
    idp: MockIdp,
}

impl Harness {
    async fn plain() -> Self {
        let registry = compiled(PROJECT);
        let idp = MockIdp::start().await;
        let authenticator = RegistryAuthenticator::new(
            &registry,
            oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]),
            key_source(&idp),
            AuthorityClaimConfig::new("registry_principal", None),
        )
        .expect("authentication config is valid");
        let app = authenticated_router(Arc::new(service(registry)), Arc::new(authenticator));
        Self { app, idp }
    }

    /// A harness whose key source cannot be reached: the issuer's key set URL
    /// names a loopback port nothing listens on.
    async fn key_source_outage() -> Self {
        let registry = compiled(PROJECT);
        let idp = MockIdp::start().await;
        let unreachable = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            "http://127.0.0.1:9/jwks.json".to_owned(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::https_or_loopback(),
        ));
        let authenticator = RegistryAuthenticator::new(
            &registry,
            oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]),
            unreachable,
            AuthorityClaimConfig::new("registry_principal", None),
        )
        .expect("authentication config is valid");
        let app = authenticated_router(Arc::new(service(registry)), Arc::new(authenticator));
        Self { app, idp }
    }

    async fn contextual() -> Self {
        let registry = compiled(CONTEXTUAL_PROJECT);
        let idp = MockIdp::start().await;
        let mut verifier = oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]);
        verifier.allowed_clients = vec!["agent-client".to_owned()];
        let claims = AuthorityClaimConfig::new("sub", Some("registry_purpose".to_owned()))
            .with_contextual_claims(
                ClaimNames::default(),
                BTreeMap::from([("agent-client".to_owned(), ACTOR_ID.to_owned())]),
            );
        let authenticator =
            RegistryAuthenticator::new(&registry, verifier, key_source(&idp), claims)
                .expect("contextual authentication config is valid");
        let app = authenticated_router(Arc::new(service(registry)), Arc::new(authenticator));
        Self { app, idp }
    }

    fn signed(&self, mut claims: Value, kid: &str) -> String {
        let now = unix_now();
        let object = claims.as_object_mut().expect("claims are an object");
        object
            .entry("iss")
            .or_insert_with(|| json!(self.idp.issuer()));
        object.entry("iat").or_insert_with(|| json!(now));
        object.entry("nbf").or_insert_with(|| json!(now));
        object.entry("exp").or_insert_with(|| json!(now + 900));
        sign_ed25519_compact_jwt(fixtures::ED25519_PRIVATE_JWK, "JWT", kid, claims)
    }

    fn token(&self, claims: Value) -> String {
        self.signed(claims, "registry-platform-testing-ed25519-1")
    }
}

fn valid_claims() -> Value {
    json!({
        "aud": AUDIENCE,
        "registry_actor_kind": "service",
        "registry_principal": PRINCIPAL,
        "scope": "registry.read",
    })
}

fn delegated_grant_claims(now: u64) -> Value {
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
        "identity": {"tenant_claim": "tenant-from-approved-identity"}
    })
}

fn standing_agent_claims(act: Value) -> Value {
    json!({
        "aud": AUDIENCE,
        "sub": PRINCIPAL,
        "azp": "agent-client",
        "registry_actor_kind": "agent",
        "registry_purpose": "citizen-self-service",
        "act": act
    })
}

fn read_request(path: &str, authorization: &[&str]) -> Request<Body> {
    let mut request = Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("request");
    for value in authorization {
        request.headers_mut().append(
            AUTHORIZATION,
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    request
}

fn completion_keys(byte: u8) -> registry_platform_crypto::delivery_signature::DeliveryKeys {
    use registry_platform_crypto::delivery_signature::{DeliveryKey, DeliveryKeys};
    DeliveryKeys::new(DeliveryKey::new(&[byte; 32]).unwrap(), None).unwrap()
}

fn completion_request(key: Option<u8>, recipient: Option<&str>, offset: i64) -> Request<Body> {
    let event = "00000000-0000-4000-8000-000000000001";
    let timestamp = (chrono::Utc::now().timestamp() + offset) as u64;
    let body = b"{}";
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/review-completions")
        .header("webhook-id", event)
        .header("webhook-timestamp", timestamp.to_string());
    if let Some(recipient) = recipient {
        builder = builder.header("registry-recipient-binding", recipient);
    }
    if let Some(key) = key {
        let signature = registry_platform_crypto::delivery_signature::sign(
            &completion_keys(key),
            event,
            timestamp,
            body,
        )
        .unwrap();
        builder = builder.header("webhook-signature", signature);
    }
    builder
        .body(Body::from(body.as_slice()))
        .expect("completion request")
}

/// The review-completion router: a receiver with one authority and a pool
/// that never connects.
fn completion_app() -> axum::Router {
    let registry = compiled(PROJECT);
    let authenticator = Arc::new(
        RegistryAuthenticator::new(
            &registry,
            TokenVerifierConfig::access_token_profile(
                "https://issuer.example.test",
                vec![AUDIENCE.to_owned()],
                vec![Algorithm::EdDSA],
                vec!["at+jwt".to_owned()],
            ),
            Arc::new(JwksFetcher::new_static(
                JwkSet { keys: Vec::new() },
                JwksFetcherConfig::defaults(),
            )),
            AuthorityClaimConfig::new("registry_principal", None),
        )
        .expect("authentication config is valid"),
    );
    let bounds = PoolBounds::new(
        1,
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(50),
    )
    .expect("pool bounds are valid");
    let certificate = rcgen::generate_simple_self_signed(vec!["db.example.invalid".to_owned()])
        .expect("test CA is valid");
    let pool = ConnectionConfig::require_tls_with_custom_ca(
        "postgresql://registry_runtime@db.example.invalid/registry",
        certificate.cert.der(),
        bounds,
    )
    .expect("test connection configuration is valid")
    .build_pool()
    .expect("test pool builds");
    let review_client = ReviewClient::new(ReviewClientConfig::new(
        "https://review.example.invalid/"
            .parse()
            .expect("reserved HTTPS URL"),
    ))
    .expect("review client builds");
    let authority = Arc::new(
        ReviewAuthorityClient::new(
            "casework-a".to_owned(),
            review_client,
            Arc::new(
                registry_platform_httputil::StaticToken::new("outgoing-token".to_owned())
                    .expect("outgoing token is valid"),
            ),
            "producer-profile".to_owned(),
            "producer-a".to_owned(),
            7,
            Some(completion_keys(b'k')),
            Some("registry-a".to_owned()),
        )
        .expect("review authority is valid"),
    );
    let authorities = Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([("casework-a".to_owned(), authority)]))
            .expect("review authority registry is valid"),
    );
    let receiver = Arc::new(ReviewCompletionReceiver::new(pool, authorities));
    let service = Arc::new(service(registry).with_review_completions(receiver));
    authenticated_router(service, authenticator)
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
    let retry_after = header("retry-after");
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
            "retryAfter": retry_after,
            "body": body,
        }),
        counted,
        refusal_lines,
        log_text,
    }
}

#[tokio::test]
async fn every_authentication_refusal_is_counted_logged_and_unchanged_on_the_wire() {
    let record = format!("/v1/records/cases/{RECORD_ID}");
    let mut observed = Vec::new();

    let plain = Harness::plain().await;
    let valid = plain.idp.mint_token(valid_claims());
    // Change a character in the middle of the signature. The last character
    // of a base64url Ed25519 signature carries padding bits, so changing it
    // can make the token fail to decode instead of failing the signature.
    let mut tampered = valid.clone();
    let position = tampered.len() - 10;
    let replacement = if &valid[position..=position] == "A" {
        "B"
    } else {
        "A"
    };
    tampered.replace_range(position..=position, replacement);
    let now = unix_now();
    let mut wrong_audience = valid_claims();
    wrong_audience["aud"] = json!("urn:example:another-resource");
    let mut expired = valid_claims();
    expired["iat"] = json!(now - 7200);
    expired["nbf"] = json!(now - 7200);
    expired["exp"] = json!(now - 3600);
    let mut wrong_issuer = valid_claims();
    wrong_issuer["iss"] = json!("https://issuer-canary.example.test");
    let mut no_actor_kind = valid_claims();
    no_actor_kind
        .as_object_mut()
        .expect("claims are an object")
        .remove("registry_actor_kind");
    let mut object_principal = valid_claims();
    object_principal["registry_principal"] = json!({"value": PRINCIPAL});
    let mut malformed_actor_kind = valid_claims();
    malformed_actor_kind["registry_actor_kind"] = json!(["service"]);
    let bearer = |token: &str| format!("Bearer {token}");

    for (name, check, request) in [
        (
            "no-authorization-header",
            "credential-missing",
            read_request(&record, &[]),
        ),
        (
            "basic-scheme",
            "credential-missing",
            read_request(&record, &["Basic canary-basic-secret"]),
        ),
        (
            "repeated-authorization-header",
            "credential-malformed",
            read_request(
                &record,
                &["Bearer canary-one.two.three", "Bearer canary-four.five.six"],
            ),
        ),
        (
            "double-space-separator",
            "credential-malformed",
            read_request(&record, &["Bearer  canary-double-space"]),
        ),
        (
            "token-not-compact",
            "credential-malformed",
            read_request(&record, &["Bearer canary-not-compact"]),
        ),
        (
            "tampered-signature",
            "token-signature",
            read_request(&record, &[&bearer(&tampered)]),
        ),
        (
            "wrong-audience",
            "token-audience",
            read_request(&record, &[&bearer(&plain.token(wrong_audience))]),
        ),
        (
            "expired-token",
            "token-time",
            read_request(&record, &[&bearer(&plain.token(expired))]),
        ),
        (
            "unknown-key-id",
            "token-key",
            read_request(
                &record,
                &[&bearer(&plain.signed(valid_claims(), "kid-canary-unknown"))],
            ),
        ),
        (
            "wrong-issuer",
            "token-issuer",
            read_request(&record, &[&bearer(&plain.token(wrong_issuer))]),
        ),
        (
            "missing-actor-kind",
            "actor-kind",
            read_request(&record, &[&bearer(&plain.token(no_actor_kind))]),
        ),
        (
            "actor-kind-is-not-a-string",
            "actor-kind",
            read_request(&record, &[&bearer(&plain.token(malformed_actor_kind))]),
        ),
        (
            "token-type-is-not-admitted",
            "token-type",
            read_request(
                &record,
                &[&bearer(&sign_ed25519_compact_jwt(
                    fixtures::ED25519_PRIVATE_JWK,
                    "canary+type",
                    "registry-platform-testing-ed25519-1",
                    {
                        let mut claims = valid_claims();
                        claims["iss"] = json!(plain.idp.issuer());
                        claims["iat"] = json!(now);
                        claims["nbf"] = json!(now);
                        claims["exp"] = json!(now + 900);
                        claims
                    },
                ))],
            ),
        ),
        (
            "principal-claim-is-an-object",
            "token-claims",
            read_request(&record, &[&bearer(&plain.token(object_principal))]),
        ),
    ] {
        observed.push(observe(name, check, &plain.app, request).await);
    }

    // The low-level router has no bearer layer, so a route that reads claims
    // finds none.
    let unauthenticated = router(Arc::new(service(compiled(PROJECT))));
    observed.push(
        observe(
            "extractor-without-authentication-context",
            "credential-missing",
            &unauthenticated,
            read_request("/v1/registry", &[]),
        )
        .await,
    );

    let contextual = Harness::contextual().await;
    let agent_path = format!("{record}?accessProfile=standing-agent");
    let grant_path = format!("{record}?accessProfile=delegated-agent");
    let untrusted_actor = contextual.token(standing_agent_claims(
        json!({"sub": "00000000-0000-4000-8000-0000000000ff", "iss": contextual.idp.issuer()}),
    ));
    let mut actor_without_client =
        standing_agent_claims(json!({"sub": ACTOR_ID, "iss": contextual.idp.issuer()}));
    actor_without_client
        .as_object_mut()
        .expect("claims are an object")
        .remove("azp");
    let act_not_an_object = contextual.token(standing_agent_claims(json!("not-an-object")));
    let mut long_grant = delegated_grant_claims(now);
    long_grant["iat"] = json!(now);
    long_grant["exp"] = json!(now + 901);
    let mut partial_grant = delegated_grant_claims(now);
    partial_grant["iat"] = json!(now);
    partial_grant["exp"] = json!(now + 600);
    partial_grant["registry_grant_bounds"] = json!("not-an-object");
    let mut expired_grant = delegated_grant_claims(now);
    expired_grant["registry_grant_exp"] = json!(now - 1);
    let mut other_client_grant = delegated_grant_claims(now);
    other_client_grant["registry_grant_client"] = json!("other-client");
    let mut other_resource_grant = delegated_grant_claims(now);
    other_resource_grant["registry_grant_resource"] = json!("urn:example:other-resource");
    let mut future_issued_grant = delegated_grant_claims(now);
    future_issued_grant["iat"] = json!(now + 600);
    future_issued_grant["nbf"] = json!(now);
    future_issued_grant["exp"] = json!(now + 1200);
    for (name, check, request) in [
        (
            "actor-is-not-the-trusted-actor",
            "delegation",
            read_request(&agent_path, &[&bearer(&untrusted_actor)]),
        ),
        (
            "act-claim-is-not-an-object",
            "delegation",
            read_request(&agent_path, &[&bearer(&act_not_an_object)]),
        ),
        (
            "actor-without-a-matched-client",
            "token-client",
            read_request(
                &agent_path,
                &[&bearer(&contextual.token(actor_without_client))],
            ),
        ),
        (
            "task-grant-token-issued-for-too-long",
            "task-grant-lifetime",
            read_request(&grant_path, &[&bearer(&contextual.token(long_grant))]),
        ),
        (
            "task-grant-claims-malformed",
            "task-grant-claims",
            read_request(&grant_path, &[&bearer(&contextual.token(partial_grant))]),
        ),
        (
            "task-grant-expired",
            "task-grant-expired",
            read_request(&grant_path, &[&bearer(&contextual.token(expired_grant))]),
        ),
        (
            "task-grant-bound-to-another-client",
            "task-grant-binding",
            read_request(
                &grant_path,
                &[&bearer(&contextual.token(other_client_grant))],
            ),
        ),
        (
            "task-grant-bound-to-another-resource",
            "task-grant-binding",
            read_request(
                &grant_path,
                &[&bearer(&contextual.token(other_resource_grant))],
            ),
        ),
        (
            "task-grant-token-issued-in-the-future",
            "task-grant-claims",
            read_request(
                &grant_path,
                &[&bearer(&contextual.token(future_issued_grant))],
            ),
        ),
    ] {
        observed.push(observe(name, check, &contextual.app, request).await);
    }

    let outage = Harness::key_source_outage().await;
    let outage_token = outage.token(valid_claims());
    observed.push(
        observe(
            "key-source-unreachable",
            "key-source-unavailable",
            &outage.app,
            read_request(&record, &[&bearer(&outage_token)]),
        )
        .await,
    );

    let completions = completion_app();
    let mut repeated = completion_request(Some(b'k'), Some("registry-a"), 0);
    repeated.headers_mut().append(
        "webhook-signature",
        HeaderValue::from_static("v1,canary-second-header"),
    );
    let mut malformed = completion_request(Some(b'k'), Some("registry-a"), 0);
    malformed.headers_mut().insert(
        "webhook-timestamp",
        HeaderValue::from_static("malformed-timestamp-canary"),
    );
    for (name, check, request) in [
        (
            "review-completion-without-signature",
            "delivery-signature",
            completion_request(None, Some("registry-a"), 0),
        ),
        (
            "review-completion-with-two-signatures",
            "delivery-signature",
            repeated,
        ),
        (
            "review-completion-without-recipient",
            "delivery-signature",
            completion_request(Some(b'k'), None, 0),
        ),
        (
            "review-completion-wrong-key",
            "delivery-signature",
            completion_request(Some(b'x'), Some("registry-a"), 0),
        ),
        (
            "review-completion-wrong-recipient",
            "delivery-signature",
            completion_request(Some(b'k'), Some("wrong-recipient-canary"), 0),
        ),
        (
            "review-completion-expired-signature",
            "delivery-freshness",
            completion_request(Some(b'k'), Some("registry-a"), -301),
        ),
        (
            "review-completion-malformed-timestamp",
            "delivery-freshness",
            malformed,
        ),
    ] {
        observed.push(observe(name, check, &completions, request).await);
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
            "an authentication refusal changed on the wire"
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
        assert!(
            fields["trace_id"]
                .as_str()
                .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())),
            "{}: the line carries the request trace id",
            case.name
        );
        let keys: BTreeSet<&str> = fields.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            BTreeSet::from([
                "decision",
                "failed_check",
                "message",
                "suppressed",
                "trace_id"
            ]),
            "{}: the line carries only the fixed fields",
            case.name
        );
        for canary in [
            "canary",
            PRINCIPAL,
            "agent-client",
            "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "registry-a",
            "Bearer",
        ] {
            assert!(
                !case.log_text.contains(canary) && !case.answer.to_string().contains(canary),
                "{}: the refusal exposed {canary}",
                case.name
            );
        }
    }
    assert!(
        used.len() >= 14,
        "the cases cover every authentication check"
    );

    // The shared malformed-token corpus goes through the router. The counter
    // has no budget, so every token counts once under `credential-malformed`,
    // whatever the log line budget admits.
    let corpus = registry_platform_testing::malformed_access_token_fixtures();
    let captured = CapturedLogs::default();
    let before = refusal_counts().await;
    for token in &corpus {
        let response = plain
            .app
            .clone()
            .oneshot(read_request(&record, &[&bearer(token)]))
            .with_subscriber(captured.subscriber())
            .await
            .expect("router responds");
        assert_eq!(response.status().as_u16(), 401);
    }
    let after = refusal_counts().await;
    let counted = |label: &str| {
        after.get(label).copied().unwrap_or(0) - before.get(label).copied().unwrap_or(0)
    };
    assert_eq!(
        counted("credential-malformed"),
        u64::try_from(corpus.len()).expect("corpus length fits"),
        "each malformed token counts once"
    );
    // The line budget is shared with the cases above, so the corpus writes
    // exactly the lines they left: none once they have spent it. The log is
    // still searched, because anything else the corpus logged must be value-free.
    let spent = observed
        .iter()
        .filter(|case| case.expected_check == "credential-malformed")
        .count();
    let events = captured.events();
    let refusal_lines = events
        .iter()
        .filter(|event| event["fields"]["message"] == "request refused")
        .count();
    assert_eq!(
        refusal_lines,
        (registry_platform_authcommon::REFUSAL_LOG_LINES_PER_WINDOW as usize).saturating_sub(spent),
        "the corpus writes the refusal lines the budget admits"
    );
    let log_text = events.iter().map(Value::to_string).collect::<String>();
    assert!(!log_text.contains("canary"), "the corpus reached the log");
}
