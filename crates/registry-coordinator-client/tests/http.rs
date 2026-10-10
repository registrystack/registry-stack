// SPDX-License-Identifier: Apache-2.0
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
    Router,
};
use registry_coordinator_client::{
    BearerToken, CoordinatorClient, CoordinatorClientConfig, CoordinatorClientError,
    StartRunRequest, Uuid,
};
use serde_json::{json, Value};
use tokio::task::JoinHandle;
use url::Url;

const RUN: &str = "7e367d42-b001-4d44-b94c-9447bfa182aa";

fn status() -> Value {
    json!({"runId":RUN,"workflowId":"nursing-notice","workflowVersion":"1","definitionDigest":"sha256:definition","bindingDigest":"sha256:binding","step":"notify","state":"pending","outcome":null,"output":null,"failureCode":null,"admittedAt":"2026-10-10T12:00:00Z","deadlineAt":"2026-10-10T12:05:00Z","nextDueAt":null,"uncertain":false,"restoreReviewRequired":false,"cancelRequested":false})
}
fn inspection() -> Value {
    json!({"run":status(),"steps":[{"step":"notify","state":"unknown","generation":1,"attempt":1,"nextDueAt":null,"leaseExpiresAt":null,"commandPrepared":true,"uncertain":true,"receiptExpired":false,"failureCode":"response-lost"}],"recovery":{"retryAllowed":true,"reason":null,"operation":{"id":"submit-message","version":1,"product":"messaging","effect":"mutation","keyRequirement":"required","requiresPreparation":false,"recovery":"same-command-and-receipt","readReceipt":true}}})
}
type Seen = Arc<Mutex<Vec<(Method, String, Option<String>, Bytes)>>>;
#[derive(Clone)]
struct Fixture {
    seen: Seen,
    reply: Arc<Mutex<(u16, String, String)>>,
    wait: Duration,
}
async fn handle(
    State(f): State<Fixture>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    assert_eq!(
        headers.get("authorization").unwrap(),
        "Bearer fixture-token"
    );
    f.seen.lock().unwrap().push((
        method,
        uri.path().to_string(),
        headers
            .get("idempotency-key")
            .map(|v| v.to_str().unwrap().to_string()),
        body,
    ));
    tokio::time::sleep(f.wait).await;
    let (status, media, body) = f.reply.lock().unwrap().clone();
    (
        StatusCode::from_u16(status).unwrap(),
        [
            ("content-type", media),
            ("location", "/must-not-follow".to_string()),
        ],
        body,
    )
}
struct Server {
    url: Url,
    fixture: Fixture,
    task: JoinHandle<()>,
}
impl Server {
    async fn new(value: Value) -> Self {
        Self::with_wait(value, Duration::ZERO).await
    }
    async fn with_wait(value: Value, wait: Duration) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/deployment",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let fixture = Fixture {
            seen: Arc::default(),
            reply: Arc::new(Mutex::new((
                200,
                "application/json".into(),
                value.to_string(),
            ))),
            wait,
        };
        let app = Router::new().fallback(handle).with_state(fixture.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, fixture, task }
    }
    fn client(&self) -> CoordinatorClient {
        CoordinatorClient::new(CoordinatorClientConfig::new(self.url.clone())).unwrap()
    }
    fn answer(&self, code: u16, media: &str, bytes: &str) {
        *self.fixture.reply.lock().unwrap() = (code, media.into(), bytes.into());
    }
    fn count(&self) -> usize {
        self.fixture.seen.lock().unwrap().len()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn token() -> BearerToken {
    BearerToken::new("fixture-token".to_string()).unwrap()
}
fn request() -> StartRunRequest {
    StartRunRequest {
        flow: "nursing-notice".into(),
        input: json!({"requestId":"one", "values":[null,true,23]}),
    }
}

#[tokio::test]
async fn explicit_admission_preserves_prefix_key_input_and_single_exchange() {
    let server = Server::new(status()).await;
    let client = server.client();
    let outcome = client
        .start(&token(), "event start original", &request())
        .await
        .unwrap();
    assert_eq!(outcome.value.run_id.to_string(), RUN);
    assert_eq!(outcome.value.state, "pending");
    let seen = server.fixture.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, Method::POST);
    assert_eq!(seen[0].1, "/deployment/v1/runs");
    assert_eq!(seen[0].2.as_deref(), Some("event start original"));
    assert_eq!(
        serde_json::from_slice::<Value>(&seen[0].3).unwrap(),
        serde_json::to_value(request()).unwrap()
    );
}

#[tokio::test]
async fn status_inspection_and_receipt_reconciliation_use_only_their_exact_routes() {
    let server = Server::new(status()).await;
    let client = server.client();
    let run = Uuid::parse_str(RUN).unwrap();
    client.status(&token(), run).await.unwrap();
    server.answer(200, "application/json", &inspection().to_string());
    let inspected = client.inspect(&token(), run).await.unwrap();
    assert!(inspected.value.steps[0].uncertain);
    let recovered = client
        .reconcile(&token(), run, "lost-notice-response")
        .await
        .unwrap();
    assert!(recovered.value.recovery.operation.unwrap().read_receipt);
    let seen = server.fixture.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].0, Method::GET);
    assert_eq!(seen[1].1, format!("/deployment/v1/runs/{RUN}/inspect"));
    assert_eq!(seen[2].1, format!("/deployment/v1/runs/{RUN}/reconcile"));
    assert_eq!(
        serde_json::from_slice::<Value>(&seen[2].3).unwrap(),
        json!({"reason":"lost-notice-response"})
    );
    assert!(seen.iter().all(|s| s.2.is_none()));
}

#[tokio::test]
async fn invalid_admission_and_recovery_fail_before_io() {
    let server = Server::new(status()).await;
    let client = server.client();
    for key in [
        "",
        "contains\tcontrol",
        "injected\r\nheader",
        &"a".repeat(257),
    ] {
        assert!(matches!(
            client.start(&token(), key, &request()).await,
            Err(CoordinatorClientError::InvalidRequest { .. })
        ));
    }
    let mut input = request();
    input.flow = "../other".into();
    assert!(client.start(&token(), "key", &input).await.is_err());
    input = request();
    input.input = json!({"tooMuch":"x".repeat(65_536)});
    assert!(client.start(&token(), "key", &input).await.is_err());
    for reason in ["", "contains\ncontrol", &"é".repeat(129)] {
        assert!(matches!(
            client
                .reconcile(&token(), Uuid::parse_str(RUN).unwrap(), reason)
                .await,
            Err(CoordinatorClientError::InvalidRequest { .. })
        ));
    }
    assert_eq!(server.count(), 0);
}

#[tokio::test]
async fn problems_are_product_owned_and_prose_is_never_released() {
    let server = Server::new(status()).await;
    for (code, status) in [
        ("access.unauthenticated", 401),
        ("access.denied", 403),
        ("run-absent", 404),
        ("start-conflict", 409),
        ("store-unavailable", 503),
    ] {
        server.answer(status, "application/json", &json!({"code":code,"message":"sensitive-canary","suggestedAction":"secret-recovery-canary"}).to_string());
        let error = server
            .client()
            .start(&token(), "key", &request())
            .await
            .err()
            .unwrap();
        assert_eq!(error.is_outcome_unknown(), status >= 500);
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert!(
            matches!(error, CoordinatorClientError::Problem { status: s, code:c } if s == status && c == code)
        );
    }
    assert_eq!(server.count(), 5, "no automatic retry after even a 503");
}

#[tokio::test]
async fn malformed_ambiguous_redirected_or_wrong_run_answers_are_refused() {
    let server = Server::new(status()).await;
    let mut other = status();
    other["runId"] = json!(Uuid::nil());
    let mut duplicate = status().to_string();
    duplicate.insert_str(1, "\"state\":\"done\",");
    let cases = [
        (200, "application/json", duplicate),
        (200, "text/html", status().to_string()),
        (302, "application/json", status().to_string()),
        (200, "application/json", other.to_string()),
        (
            403,
            "application/json",
            json!({"code":"start-conflict","message":"refused"}).to_string(),
        ),
        (
            409,
            "application/json",
            json!({"code":"secret value","message":"refused"}).to_string(),
        ),
    ];
    for (code, media, bytes) in cases {
        server.answer(code, media, &bytes);
        assert!(matches!(
            server
                .client()
                .status(&token(), Uuid::parse_str(RUN).unwrap())
                .await,
            Err(CoordinatorClientError::Protocol { .. })
        ));
    }
    assert_eq!(server.count(), 6, "a redirect was never followed");
    server.answer(200, "application/json", &status().to_string());
    let bounded = CoordinatorClient::new(
        CoordinatorClientConfig::new(server.url.clone()).with_max_response_bytes(64),
    )
    .unwrap();
    assert!(matches!(
        bounded
            .status(&token(), Uuid::parse_str(RUN).unwrap())
            .await,
        Err(CoordinatorClientError::Transport { .. })
    ));
}

#[tokio::test]
async fn a_lost_admission_reply_is_unknown_and_is_not_resent() {
    let server = Server::with_wait(status(), Duration::from_millis(250)).await;
    let client = CoordinatorClient::new(
        CoordinatorClientConfig::new(server.url.clone())
            .with_request_timeout(Duration::from_millis(70)),
    )
    .unwrap();
    let error = client
        .start(&token(), "original", &request())
        .await
        .err()
        .unwrap();
    assert!(error.is_outcome_unknown());
    assert_eq!(server.count(), 1);
}

#[test]
fn config_bounds_and_debug_do_not_expose_configured_values() {
    let config = CoordinatorClientConfig::new(
        Url::parse("https://private-canary.example/secret-canary").unwrap(),
    )
    .with_user_agent("agent-canary")
    .with_trusted_root_certificates(b"certificate-canary".to_vec());
    assert!(!format!("{config:?}").contains("canary"));
    for url in [
        "http://remote.example",
        "https://user:secret@example.test",
        "https://example.test?token=secret",
        "https://example.test#secret",
    ] {
        assert!(
            CoordinatorClient::new(CoordinatorClientConfig::new(Url::parse(url).unwrap())).is_err()
        );
    }
    let url = Url::parse("https://example.test").unwrap();
    assert!(CoordinatorClient::new(
        CoordinatorClientConfig::new(url.clone()).with_request_timeout(Duration::ZERO)
    )
    .is_err());
    assert!(
        CoordinatorClient::new(CoordinatorClientConfig::new(url).with_max_response_bytes(0))
            .is_err()
    );
}

#[test]
fn dto_contract_tracks_the_runtime_generated_schema() {
    let api: Value = serde_json::from_str(include_str!(
        "../../../products/coordinator/generated/openapi/coordinator.openapi.json"
    ))
    .unwrap();
    let schemas = &api["components"]["schemas"];
    for (name, value) in [("RunStatus", status()), ("RunInspection", inspection())] {
        for field in schemas[name]["required"].as_array().unwrap() {
            assert!(
                value.get(field.as_str().unwrap()).is_some(),
                "missing {name} field {field}"
            );
        }
    }
    let _: registry_coordinator_client::RunStatus = serde_json::from_value(status()).unwrap();
    let _: registry_coordinator_client::RunInspection =
        serde_json::from_value(inspection()).unwrap();
}
