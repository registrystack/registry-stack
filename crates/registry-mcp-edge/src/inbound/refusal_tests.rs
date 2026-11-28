// SPDX-License-Identifier: Apache-2.0

//! Every refusal the edge answers, driven through the real router. The golden
//! file freezes the status, the headers a client can read and the body of each
//! answer.

use std::{collections::BTreeMap, io, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{header, HeaderName, HeaderValue, Request, StatusCode},
    Router,
};
use registry_platform_audit::{AuditProfile, AuditWriter};
use registry_platform_authcommon::FailedCheck;
use registry_platform_httputil::{client::StaticToken, FetchUrlPolicy};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{TestAuthorizationServer, TestClient};
use rmcp::model::Tool;
use serde_json::{json, Value};
use tower::ServiceExt;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    router, token_verifier, AccessTokenAlgorithm, AuditOptions, EffectCertainty,
    FixedAuthorizationFactory, GatewayCore, GatewayInfo, Invocation, Provider,
    ProviderAuthorization, ProviderBinding, ProviderFailure, ProviderOutcome, RateLimitOptions,
    ResolvedTool, ResourceServer, ResourceServerOptions, ServerOptions, TokenBucketOptions,
    ToolAuditLog, VerifiedCaller,
};

const RESOURCE: &str = "https://gateway.example.test/mcp";
const HOST: &str = "gateway.example.test";
const CLIENT: &str = "chat-host";
const SCOPE: &str = "test:read";
const GOLDEN: &str = include_str!("../../tests/golden/refusals.json");
const GOLDEN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/refusals.json");

struct UnusedProvider;

#[async_trait]
impl Provider for UnusedProvider {
    fn resolve_tool(&self, name: &str) -> Option<ResolvedTool> {
        (name == "unused")
            .then(|| ResolvedTool::new("unused", "test", "unused", "v1").expect("identity"))
    }

    async fn list_tools(
        &self,
        _: &VerifiedCaller,
        _: ProviderAuthorization,
    ) -> Result<Vec<Tool>, ProviderFailure> {
        Ok(Vec::new())
    }

    async fn invoke(
        &self,
        _: &VerifiedCaller,
        _: ProviderAuthorization,
        _: Invocation<'_>,
    ) -> ProviderOutcome {
        ProviderOutcome::failure(ProviderFailure::new(
            "unused",
            "Unused.",
            EffectCertainty::NoEffect,
        ))
    }
}

fn gateway_core() -> Arc<GatewayCore> {
    let token = StaticToken::new("test-only-static-token").expect("token");
    let binding = ProviderBinding::new(
        Arc::new(UnusedProvider),
        Arc::new(FixedAuthorizationFactory::new(Arc::new(token))),
        ["unused".to_owned()],
    )
    .expect("binding");
    let audit = ToolAuditLog::new(AuditWriter::from_line_sink_without_posture(Box::new(
        io::sink(),
    )));
    Arc::new(
        GatewayCore::new(
            [binding],
            audit,
            AuditOptions::new("registry-test-mcp.tool-call/v1", "test_mcp.tool_call")
                .expect("audit"),
            GatewayInfo::new("test-mcp", "Test", "Test").expect("info"),
        )
        .expect("core"),
    )
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("time fits")
}

async fn authorization() -> TestAuthorizationServer {
    TestAuthorizationServer::builder()
        .client(TestClient::new(CLIENT))
        .client(TestClient::new("another-host"))
        .start()
        .await
}

/// The real edge router over a verifier that reads `jwks_uri`.
pub(super) fn application(
    authorization: &TestAuthorizationServer,
    jwks_uri: String,
    burst: u32,
) -> (Router, Arc<ResourceServer>) {
    let options = ResourceServerOptions {
        resource: RESOURCE.to_owned(),
        issuer: authorization.issuer(),
        allow_insecure_http: false,
        algorithms: vec![AccessTokenAlgorithm::EdDSA],
        allowed_clients: vec![CLIENT.to_owned()],
        required_scopes: vec![SCOPE.to_owned()],
        scope_claim: "scope".to_owned(),
        maximum_token_lifetime: Duration::from_secs(300),
        resource_name: "Test".to_owned(),
        principal_audit_namespace: "test-principal-v1".to_owned(),
        client_audit_namespace: "test-client-v1".to_owned(),
    };
    let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        jwks_uri,
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::https_or_loopback(),
    ));
    let profile =
        AuditProfile::production_from_secret_bytes(Zeroizing::new(vec![8; 32])).expect("profile");
    let bucket = TokenBucketOptions {
        requests_per_minute: 1,
        burst,
    };
    let resource_server = Arc::new(
        ResourceServer::new(
            &options,
            token_verifier(&options, fetcher),
            profile.key_hasher(),
            RateLimitOptions {
                per_principal: bucket,
                per_client: bucket,
            },
        )
        .expect("resource server"),
    );
    let app = router(
        gateway_core(),
        Arc::clone(&resource_server),
        &ServerOptions {
            resource: Url::parse(RESOURCE).expect("resource URL"),
            maximum_request_bytes: 4096,
            hsts: false,
        },
    );
    (app, resource_server)
}

pub(super) type Headers = Vec<(HeaderName, HeaderValue)>;

pub(super) fn request(headers: Headers) -> Request<Body> {
    let mut request = Request::post("/mcp")
        .header(header::HOST, HOST)
        .header(header::ACCEPT, "application/json, text/event-stream");
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request.body(Body::empty()).expect("request")
}

pub(super) fn authorization_header(value: &str) -> (HeaderName, HeaderValue) {
    (
        header::AUTHORIZATION,
        HeaderValue::from_str(value).expect("header value"),
    )
}

pub(super) fn bearer(token: &str) -> Headers {
    vec![authorization_header(&format!("Bearer {token}"))]
}

/// The answers and, per case, the checks its refusal counted.
#[derive(Default)]
struct Run {
    answers: BTreeMap<&'static str, Value>,
    counted: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
}

impl Run {
    /// Sends one request to a server that has served nothing else, so the
    /// counter holds this request's refusal alone.
    async fn observe(
        &mut self,
        name: &'static str,
        (app, server): &(Router, Arc<ResourceServer>),
        headers: Headers,
    ) {
        let mut answer = summarise(
            app.clone()
                .oneshot(request(headers))
                .await
                .expect("response"),
        )
        .await;
        settle_retry_after(&mut answer);
        self.record(name, server, answer);
    }

    fn record(&mut self, name: &'static str, server: &ResourceServer, answer: Value) {
        let counted = FailedCheck::ALL
            .iter()
            .filter_map(|check| {
                let count = server
                    .refusal_recorder()
                    .counter()
                    .get(&[check.as_str()])
                    .expect("every check is a declared series");
                (count > 0).then_some((check.as_str(), count))
            })
            .collect();
        self.answers.insert(name, answer);
        self.counted.insert(name, counted);
    }
}

/// The limiter holds one request per minute, so the delay it advertises is
/// the minute less however long the fixture took between its two requests,
/// rounded up. Any delay from one to sixty seconds is recorded as sixty so a
/// slow runner does not change the frozen answer.
fn settle_retry_after(answer: &mut Value) {
    let Some(header) = answer["headers"].get_mut("retry-after") else {
        return;
    };
    let seconds: u64 = header
        .as_str()
        .and_then(|text| text.parse().ok())
        .expect("retry-after is whole seconds");
    assert!((1..=60).contains(&seconds), "retry-after {seconds}");
    *header = Value::from("60");
}

/// One name per refusal the edge can answer, with the answer it gives.
async fn drive() -> Run {
    let auth = authorization().await;
    let fresh = || application(&auth, auth.jwks_uri(), 100);
    let issue = |client: &str, audience: &str, scope: &str, exp: i64| {
        auth.issue_access_token(client, "citizen-a", audience, scope, exp)
    };
    let mut run = Run::default();

    run.observe("no-authorization-header", &fresh(), vec![])
        .await;
    run.observe(
        "non-bearer-scheme",
        &fresh(),
        vec![authorization_header("Basic abc")],
    )
    .await;
    run.observe(
        "bearer-without-token",
        &fresh(),
        vec![authorization_header("Bearer")],
    )
    .await;
    run.observe(
        "bearer-with-two-spaces",
        &fresh(),
        vec![authorization_header("Bearer  a")],
    )
    .await;
    run.observe(
        "repeated-authorization-header",
        &fresh(),
        vec![
            authorization_header("Bearer a"),
            authorization_header("Bearer b"),
        ],
    )
    .await;
    run.observe(
        "unreadable-authorization-header",
        &fresh(),
        vec![(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff").expect("opaque header"),
        )],
    )
    .await;
    run.observe("not-a-jwt", &fresh(), bearer("not-a-compact-token"))
        .await;
    run.observe(
        "wrong-audience",
        &fresh(),
        bearer(&issue(CLIENT, "urn:elsewhere", SCOPE, now() + 300)),
    )
    .await;
    run.observe(
        "client-not-allowed",
        &fresh(),
        bearer(&issue("another-host", RESOURCE, SCOPE, now() + 300)),
    )
    .await;
    run.observe(
        "empty-subject",
        &fresh(),
        bearer(&auth.issue_access_token(CLIENT, "", RESOURCE, SCOPE, now() + 300)),
    )
    .await;
    run.observe(
        "expired",
        &fresh(),
        bearer(&issue(CLIENT, RESOURCE, SCOPE, now() - 120)),
    )
    .await;
    run.observe(
        "scope-missing",
        &fresh(),
        bearer(&issue(CLIENT, RESOURCE, "openid", now() + 300)),
    )
    .await;

    let (app, server) = fresh();
    let response = app
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header(header::HOST, "attacker.example.test")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    run.record("host-not-admitted", &server, summarise(response).await);
    run.observe(
        "origin-present",
        &fresh(),
        vec![(
            header::ORIGIN,
            HeaderValue::from_static("https://elsewhere.example.test"),
        )],
    )
    .await;

    let token = issue(CLIENT, RESOURCE, SCOPE, now() + 300);
    let limited = application(&auth, auth.jwks_uri(), 1);
    let first = limited
        .0
        .clone()
        .oneshot(request(bearer(&token)))
        .await
        .expect("response");
    assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);
    run.observe("rate-limited", &limited, bearer(&token)).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let closed = format!(
        "http://{}/jwks.json",
        listener.local_addr().expect("address")
    );
    drop(listener);
    run.observe(
        "key-set-unreachable",
        &application(&auth, closed, 100),
        bearer(&token),
    )
    .await;
    run
}

async fn summarise(response: axum::response::Response) -> Value {
    let status = response.status();
    let mut readable = BTreeMap::new();
    for name in [
        header::CONTENT_TYPE,
        header::CACHE_CONTROL,
        header::WWW_AUTHENTICATE,
        header::RETRY_AFTER,
    ] {
        if let Some(value) = response.headers().get(&name) {
            readable.insert(
                name.as_str().to_owned(),
                value.to_str().expect("ASCII header").to_owned(),
            );
        }
    }
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).expect("a problem document");
    json!({"status": status.as_u16(), "headers": readable, "body": body})
}

#[tokio::test(flavor = "current_thread")]
async fn every_refusal_answers_exactly_as_the_golden_file_records() {
    let answers = serde_json::to_value(drive().await.answers).expect("answers serialize");
    if std::env::var_os("REGISTRY_MCP_EDGE_WRITE_GOLDEN").is_some() {
        let mut text = serde_json::to_string_pretty(&answers).expect("golden text");
        text.push('\n');
        std::fs::write(GOLDEN_PATH, text).expect("the golden file is written");
    }
    let golden: Value = serde_json::from_str(GOLDEN).expect("the golden file is JSON");
    assert_eq!(answers, golden);
}

/// The check each refusal counts, one request each.
const COUNTED: [(&str, &str); 16] = [
    ("no-authorization-header", "credential-missing"),
    ("non-bearer-scheme", "credential-missing"),
    ("bearer-without-token", "credential-malformed"),
    ("bearer-with-two-spaces", "credential-malformed"),
    ("repeated-authorization-header", "credential-malformed"),
    ("unreadable-authorization-header", "credential-malformed"),
    ("not-a-jwt", "credential-malformed"),
    ("wrong-audience", "token-audience"),
    ("client-not-allowed", "token-client"),
    ("empty-subject", "token-claims"),
    ("expired", "token-time"),
    ("scope-missing", "scope"),
    ("host-not-admitted", "host-origin"),
    ("origin-present", "host-origin"),
    ("rate-limited", "rate-limit"),
    ("key-set-unreachable", "key-source-unavailable"),
];

#[tokio::test(flavor = "current_thread")]
async fn each_refusal_counts_once_under_its_check() {
    let run = drive().await;
    assert_eq!(run.counted.len(), COUNTED.len());
    for (name, check) in COUNTED {
        assert_eq!(run.counted[name], BTreeMap::from([(check, 1)]), "{name}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_refused_host_writes_one_line_with_its_check() {
    use registry_platform_testing::CapturedDiagnosticLogs;
    use tracing::instrument::WithSubscriber;

    let logs = CapturedDiagnosticLogs::default();
    let auth = authorization().await;
    let (app, _) = application(&auth, auth.jwks_uri(), 100);
    let response = app
        .oneshot(
            Request::post("/mcp")
                .header(header::HOST, "attacker.example.test")
                .body(Body::empty())
                .expect("request"),
        )
        .with_subscriber(logs.subscriber())
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let text = logs.text();
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("request refused"))
        .collect();
    assert_eq!(lines.len(), 1, "{text}");
    assert!(
        lines[0].contains("\"failed_check\":\"host-origin\""),
        "{text}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_refusal_writes_one_line_with_its_check_and_no_caller_value() {
    use registry_platform_testing::CapturedDiagnosticLogs;
    use tracing::instrument::WithSubscriber;

    let logs = CapturedDiagnosticLogs::default();
    let auth = authorization().await;
    let token = auth.issue_access_token(CLIENT, "citizen-canary", RESOURCE, "openid", now() + 300);
    let (app, _) = application(&auth, auth.jwks_uri(), 100);
    let response = app
        .oneshot(request(bearer(&token)))
        .with_subscriber(logs.subscriber())
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let text = logs.text();
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("request refused"))
        .collect();
    assert_eq!(lines.len(), 1, "{text}");
    assert!(lines[0].contains("\"failed_check\":\"scope\""), "{text}");
    // The line names what the operator declared, never the token's scopes.
    assert!(lines[0].contains("\"scope_claim\":\"scope\""), "{text}");
    assert!(
        lines[0].contains(&format!("\"required_scope\":\"{SCOPE}\"")),
        "{text}"
    );
    for canary in [token.as_str(), "citizen-canary", CLIENT, "openid"] {
        assert!(!text.contains(canary), "{canary} reached the log: {text}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_admit_fault_line_is_due_once_per_window() {
    let auth = authorization().await;
    let (_, server) = application(&auth, auth.jwks_uri(), 100);
    let start = std::time::Instant::now();
    assert_eq!(server.admit_fault_due(start), Some(0));
    assert_eq!(
        server.admit_fault_due(start + Duration::from_secs(30)),
        None
    );
    assert_eq!(
        server.admit_fault_due(start + Duration::from_secs(59)),
        None
    );
    assert_eq!(
        server.admit_fault_due(start + Duration::from_secs(61)),
        Some(2)
    );
    assert_eq!(
        server.admit_fault_due(start + Duration::from_secs(130)),
        Some(0)
    );
}

#[test]
fn a_retry_after_from_one_to_sixty_seconds_is_frozen_as_sixty() {
    for seconds in ["1", "59", "60"] {
        let mut answer = json!({"headers": {"retry-after": seconds}});
        settle_retry_after(&mut answer);
        assert_eq!(answer["headers"]["retry-after"], "60");
    }
    let mut none = json!({"headers": {}});
    settle_retry_after(&mut none);
    assert_eq!(none, json!({"headers": {}}));
}

#[test]
#[should_panic(expected = "retry-after 61")]
fn a_retry_after_beyond_the_refill_period_is_refused() {
    settle_retry_after(&mut json!({"headers": {"retry-after": "61"}}));
}
