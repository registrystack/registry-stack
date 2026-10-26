// SPDX-License-Identifier: Apache-2.0
//! The bounded external command over a loopback provider: one POST to the
//! operator's configured path, carrying the frozen request id, with every
//! ambiguous exchange held as uncertain rather than reported as a failure.
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};

use registry_coordinator::{
    adapters::HttpAdapters,
    contracts::contract,
    external_http::{ExternalHttpConfig, ExternalHttpConnection},
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation},
    runtime::{RuntimeConfig, API_VERSION, KIND},
};
use registry_platform_httputil::client::{BearerToken, StaticToken, TokenError, TokenProvider};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

const REQUEST_ID: &str = "synthetic-request-id-canary";
const TOKEN: &str = "synthetic-command-token-canary";

fn response_schema() -> Value {
    json!({
        "type":"object", "required":["status","body"], "additionalProperties":false,
        "properties":{
            "status":{"type":"integer","minimum":100,"maximum":599},
            "body":{"anyOf":[{"type":"null"},{"type":"object","maxProperties":8}]}
        }
    })
}

fn config(base: &str) -> ExternalHttpConfig {
    serde_json::from_value(json!({
        "baseUrl":base,
        "paths":["bills/status"],
        "queryParameters":["reference"],
        "commandPath":"bills",
        "responseSchema":response_schema()
    }))
    .unwrap()
}

fn authorization() -> registry_coordinator::runtime::AuthorizationConfig {
    serde_json::from_value(json!({
        "tokenEndpoint":"http://127.0.0.1:9999/token", "clientId":"bill-issuer",
        "signingKeyRef":"secret:file/bill-issuer", "resource":"https://payments.example.test",
        "scopes":["bills.create"]
    }))
    .unwrap()
}

fn connection(config: &ExternalHttpConfig) -> ExternalHttpConnection {
    ExternalHttpConnection::new(config, None).unwrap()
}

fn authorized(config: &mut ExternalHttpConfig) -> ExternalHttpConnection {
    config.authorization = Some(authorization());
    let tokens = Arc::new(StaticToken::new(TOKEN).unwrap());
    ExternalHttpConnection::new(config, Some(tokens)).unwrap()
}

fn bill() -> Value {
    json!({"reference":"application-body-canary","amount":{"value":"25.00","currency":"XTS"}})
}

fn uncertain(outcome: &CallOutcome, expected: &str) -> bool {
    matches!(outcome, CallOutcome::Uncertain { code } if code == expected)
}

/// Renders everything an outcome carries, so a released value would show.
fn describe(outcome: &CallOutcome) -> String {
    match outcome {
        CallOutcome::Success(reply) => format!("success:{reply}"),
        CallOutcome::Retryable { code, retry_after } => format!(
            "retryable:{code}:{}",
            retry_after.map_or("-".into(), |wait| wait.as_secs().to_string())
        ),
        CallOutcome::Refused { code } => format!("refused:{code}"),
        CallOutcome::DeclaredRefusal(refusal) => format!("declared:{}", refusal.refusal_code()),
        CallOutcome::Uncertain { code } => format!("uncertain:{code}"),
        CallOutcome::ReceiptExpired => "receipt-expired".into(),
    }
}

#[tokio::test]
async fn a_command_posts_the_frozen_body_and_request_id_to_the_configured_path() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/payments/v1/bills"))
        .and(header("idempotency-key", REQUEST_ID))
        .and(header("content-type", "application/json"))
        .and(header("accept", "application/json"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(body_json(bill()))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"billId":"bill-001"})))
        .expect(1)
        .mount(&server)
        .await;
    let mut config = config(&format!("{}/payments/v1/", server.uri()));
    let connection = authorized(&mut config);
    match connection.command(&bill(), REQUEST_ID, false).await {
        CallOutcome::Success(reply) => {
            assert_eq!(reply, json!({"status":201,"body":{"billId":"bill-001"}}));
            assert_eq!(
                contract(Operation::ExternalCommand).check_output(&reply),
                Ok(())
            );
        }
        _ => panic!("the configured command is accepted"),
    }
    server.verify().await;
}

#[tokio::test]
async fn workflow_input_cannot_choose_destination_headers_or_credentials() {
    let server = MockServer::start().await;
    let input = json!({
        "path":"elsewhere", "url":"http://127.0.0.1:1/steal", "query":{"reference":"x"},
        "headers":{"authorization":"Bearer workflow-chosen","idempotency-key":"workflow-chosen"}
    });
    Mock::given(method("POST"))
        .and(path("/bills"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(header("idempotency-key", REQUEST_ID))
        .and(body_json(input.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    let mut config = config(&server.uri());
    let connection = authorized(&mut config);
    assert!(matches!(
        connection.command(&input, REQUEST_ID, false).await,
        CallOutcome::Success(reply) if reply == json!({"status":200,"body":{}})
    ));
    server.verify().await;
    server.reset().await;

    // Nothing is sent for a value the contract cannot carry.
    let oversized = json!({"padding":"x".repeat(65_536)});
    for (input, request_id, code) in [
        (
            json!(["not", "an", "object"]),
            REQUEST_ID,
            "external-invalid-command",
        ),
        (oversized, REQUEST_ID, "external-invalid-command"),
        (bill(), "", "invalid-command"),
        (bill(), "contains space", "invalid-command"),
    ] {
        assert!(
            matches!(connection.command(&input, request_id, false).await,
            CallOutcome::Refused { code: refused } if refused == code),
            "{code}"
        );
    }
    let mut read_only = self::config(&server.uri());
    read_only.command_path = None;
    assert!(matches!(
        self::connection(&read_only).command(&bill(), REQUEST_ID, false).await,
        CallOutcome::Refused { code } if code == "operation-unbound"
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// Reads one complete request, returning its head and body.
async fn read_request(socket: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        let read = socket.read(&mut chunk).await.unwrap();
        assert!(read > 0, "the client sends a complete request");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        assert!(buffer.len() < 65_536, "request headers stay bounded");
    };
    let head = String::from_utf8(buffer[..head_end].to_vec()).unwrap();
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .expect("the command declares its length");
    while buffer.len() < head_end + length {
        let read = socket.read(&mut chunk).await.unwrap();
        assert!(read > 0, "the client sends the complete body");
        buffer.extend_from_slice(&chunk[..read]);
    }
    (head, buffer[head_end..head_end + length].to_vec())
}

fn request_id(head: &str) -> String {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("idempotency-key")
                .then(|| value.trim().to_owned())
        })
        .expect("every command carries its request id")
}

/// A deduplicating provider that commits the first command, loses its
/// acknowledgement, and answers the repeated id with the original result.
async fn lossy_provider() -> (String, tokio::task::JoinHandle<Vec<(String, Vec<u8>)>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut seen = Vec::new();
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, body) = read_request(&mut socket).await;
            assert!(head.starts_with("POST /bills HTTP/1.1\r\n"));
            seen.push((request_id(&head), body));
            if attempt == 0 {
                // Committed, then the acknowledgement is lost.
                drop(socket);
                continue;
            }
            let reply = br#"{"billId":"bill-001"}"#;
            let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(reply).await.unwrap();
            socket.shutdown().await.unwrap();
        }
        seen
    });
    (format!("http://{address}"), server)
}

/// What the provider saw, without waiting forever for an attempt that failed.
async fn provided(
    server: tokio::task::JoinHandle<Vec<(String, Vec<u8>)>>,
) -> Vec<(String, Vec<u8>)> {
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the provider saw both attempts")
        .unwrap()
}

#[tokio::test]
async fn a_lost_acknowledgement_is_uncertain_and_the_same_request_id_is_sent_again() {
    let (base, server) = lossy_provider().await;
    let connection = connection(&config(&base));
    let first = connection.command(&bill(), REQUEST_ID, false).await;
    assert!(
        uncertain(&first, "transport-uncertain"),
        "{}",
        describe(&first)
    );
    assert!(matches!(
        connection.command(&bill(), REQUEST_ID, false).await,
        CallOutcome::Success(reply) if reply == json!({"status":201,"body":{"billId":"bill-001"}})
    ));
    let seen = provided(server).await;
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], seen[1], "the same id and bytes are sent again");
    assert_eq!(seen[0].0, REQUEST_ID);
    assert_eq!(serde_json::from_slice::<Value>(&seen[0].1).unwrap(), bill());
}

#[tokio::test]
async fn a_timeout_after_sending_is_uncertain_and_never_a_provider_failure() {
    // The provider reads the whole command and never answers.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (received, seen) = tokio::sync::oneshot::channel();
    let provider = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (head, _) = read_request(&mut socket).await;
        received.send(request_id(&head)).unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
    let mut config = config(&format!("http://{address}"));
    config.attempt_timeout_milliseconds = 1_500.try_into().unwrap();
    let started = std::time::Instant::now();
    let outcome = connection(&config)
        .command(&bill(), REQUEST_ID, false)
        .await;
    assert!(
        uncertain(&outcome, "attempt-timeout"),
        "{}",
        describe(&outcome)
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(seen.await.unwrap(), REQUEST_ID);
    provider.abort();
}

struct SlowTokens;

#[async_trait::async_trait]
impl TokenProvider for SlowTokens {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        tokio::time::sleep(Duration::from_secs(10)).await;
        BearerToken::new("synthetic-token")
    }
}

#[tokio::test]
async fn failures_before_anything_is_sent_stay_retryable_or_refused() {
    let server = MockServer::start().await;
    let mut slow = config(&server.uri());
    slow.authorization = Some(authorization());
    slow.attempt_timeout_milliseconds = 80.try_into().unwrap();
    let slow = ExternalHttpConnection::new(&slow, Some(Arc::new(SlowTokens))).unwrap();
    assert!(matches!(
        slow.command(&bill(), REQUEST_ID, false).await,
        CallOutcome::Retryable { code, .. } if code == "external-unavailable"
    ));
    assert!(server.received_requests().await.unwrap().is_empty());

    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    assert!(matches!(
        connection(&config(&format!("http://{address}"))).command(&bill(), REQUEST_ID, false).await,
        CallOutcome::Retryable { code, .. } if code == "external-unavailable"
    ));

    let mut metadata = config("https://169.254.169.254");
    metadata.authorization = Some(authorization());
    let metadata = ExternalHttpConnection::new(&metadata, Some(Arc::new(SlowTokens))).unwrap();
    assert!(matches!(
        metadata.command(&bill(), REQUEST_ID, false).await,
        CallOutcome::Refused { code } if code == "external-destination-refused"
    ));
}

#[tokio::test]
async fn an_oversize_or_unusable_response_is_held_without_releasing_its_body() {
    let server = MockServer::start().await;
    let mut config = config(&server.uri());
    config.maximum_response_bytes = 128.try_into().unwrap();
    let connection = connection(&config);
    for response in [
        ResponseTemplate::new(201).set_body_string(format!(
            "{{\"canary\":\"{}\"}}",
            "response-body-canary".repeat(8)
        )),
        ResponseTemplate::new(201).set_body_string("response-body-canary"),
        ResponseTemplate::new(201).set_body_string(r#"{"a":"response-body-canary","a":1}"#),
        ResponseTemplate::new(201).set_body_json(json!(["response-body-canary"])),
    ] {
        Mock::given(method("POST"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let outcome = connection.command(&bill(), REQUEST_ID, false).await;
        assert!(
            uncertain(&outcome, "external-invalid-response"),
            "{}",
            describe(&outcome)
        );
        assert!(!describe(&outcome).contains("canary"));
        server.verify().await;
        server.reset().await;
    }
}

#[tokio::test]
async fn a_redirect_is_not_followed_and_the_credential_stays_at_the_origin() {
    let server = MockServer::start().await;
    let target = MockServer::start().await;
    for status in [301, 303, 307, 308] {
        Mock::given(method("POST"))
            .and(path("/bills"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("location", format!("{}/bills", target.uri()).as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut config = config(&server.uri());
        let connection = authorized(&mut config);
        // A 303 may follow an accepted command, so the effect stays unknown.
        let outcome = connection.command(&bill(), REQUEST_ID, false).await;
        assert!(uncertain(&outcome, "external-redirect"), "{status}");
        server.verify().await;
        server.reset().await;
    }
    assert!(target.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn provider_statuses_are_classified_without_claiming_a_provider_failure() {
    let server = MockServer::start().await;
    let connection = connection(&config(&server.uri()));
    let cases = [
        (
            ResponseTemplate::new(429).insert_header("retry-after", "7"),
            "retryable:external-rate-limited:7",
        ),
        (
            ResponseTemplate::new(503),
            "retryable:external-unavailable:-",
        ),
        (
            ResponseTemplate::new(429).insert_header("retry-after", "86401"),
            "refused:external-unusable-retry-after",
        ),
        (ResponseTemplate::new(500), "uncertain:external-uncertain"),
        (ResponseTemplate::new(502), "uncertain:external-uncertain"),
        (ResponseTemplate::new(504), "uncertain:external-uncertain"),
        (
            ResponseTemplate::new(409).set_body_json(json!({"error":"duplicate"})),
            "success:409",
        ),
        (ResponseTemplate::new(204), "success:204"),
    ];
    for (response, expected) in cases {
        Mock::given(method("POST"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let outcome = connection.command(&bill(), REQUEST_ID, false).await;
        let observed = match &outcome {
            CallOutcome::Success(reply) => format!("success:{}", reply["status"]),
            other => describe(other),
        };
        assert_eq!(observed, expected);
        server.verify().await;
        server.reset().await;
    }
    // Once retries are spent, a busy provider leaves the effect unknown
    // rather than reporting a failure the provider never claimed.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    let outcome = connection.command(&bill(), REQUEST_ID, true).await;
    assert!(
        uncertain(&outcome, "external-uncertain"),
        "{}",
        describe(&outcome)
    );
    server.verify().await;
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn no_secret_body_or_request_id_reaches_logs_or_outcomes() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (base, server) = lossy_provider().await;
    let mut config = config(&base);
    let connection = authorized(&mut config);
    let outcomes = [
        connection.command(&bill(), REQUEST_ID, false).await,
        connection.command(&bill(), REQUEST_ID, false).await,
    ];
    assert!(uncertain(&outcomes[0], "transport-uncertain"));
    assert!(matches!(&outcomes[1], CallOutcome::Success(_)));
    provided(server).await;
    let rendered = format!(
        "{}{}",
        outcomes.iter().map(describe).collect::<String>(),
        String::from_utf8_lossy(&captured.0.lock().unwrap())
    );
    for canary in [TOKEN, REQUEST_ID, "application-body-canary"] {
        assert!(!rendered.contains(canary), "{canary} was released");
    }
}

fn runtime_document(base: &str) -> Value {
    json!({
        "apiVersion":API_VERSION,"kind":KIND,
        "secretProviders":{"environment":{}},
        "database":{
            "runtimeUrlRef":"secret:env/COORDINATOR_COMMAND_TEST_UNRESOLVED_DATABASE",
            "migrationUrlRef":"secret:env/COORDINATOR_COMMAND_TEST_UNRESOLVED_DATABASE"
        },
        "namespace":"coordinator_command_test",
        "connections":{
            "payments":{
                "type":"external-http", "baseUrl":base,
                "paths":["bills/status"], "commandPath":"bills",
                "responseSchema":response_schema()
            }
        }
    })
}

fn load(document: &Value) -> registry_coordinator::Result<RuntimeConfig> {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("runtime.yaml");
    std::fs::write(&path, serde_json::to_vec(document).unwrap()).unwrap();
    RuntimeConfig::load(&path)
}

#[tokio::test]
async fn the_runtime_routes_a_frozen_command_with_its_original_request_id() {
    let (base, server) = lossy_provider().await;
    let config = load(&runtime_document(&base)).unwrap();
    let adapters = HttpAdapters::new(&config).unwrap();
    let request = CallRequest {
        connection: "payments".into(),
        operation: Operation::ExternalCommand,
        input: bill(),
        idempotency_key: Some(REQUEST_ID.into()),
        operation_contract: None,
    };
    let first = adapters.call_attempt(&request, None, false).await;
    assert!(
        uncertain(&first, "transport-uncertain"),
        "{}",
        describe(&first)
    );
    // The prepared command survives a restart as its persisted bytes.
    let restored: CallRequest =
        serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap();
    assert!(matches!(
        adapters.call_attempt(&restored, None, true).await,
        CallOutcome::Success(reply) if reply["status"] == 201
    ));
    let seen = provided(server).await;
    assert_eq!(seen[0], seen[1]);

    let mut unkeyed = request.clone();
    unkeyed.idempotency_key = None;
    assert!(matches!(
        adapters.call(&unkeyed).await,
        CallOutcome::Refused { code } if code == "invalid-command"
    ));
}

#[test]
fn the_command_path_is_an_exact_operator_owned_relative_path() {
    let accepted = load(&runtime_document("https://payments.example.test/v1/")).unwrap();
    let binding = accepted.connections["payments"].external_http().unwrap();
    assert_eq!(binding.command_path.as_ref().unwrap().as_str(), "bills");
    let digest = accepted.binding_digest().unwrap();
    let mut changed = runtime_document("https://payments.example.test/v1/");
    changed["connections"]["payments"]["commandPath"] = json!("invoices");
    assert_ne!(load(&changed).unwrap().binding_digest().unwrap(), digest);

    for invalid in [
        "../bills",
        "bills/../admin",
        "bills?x=1",
        "bills#x",
        "a\\b",
        "",
        "/bills",
    ] {
        let mut document = runtime_document("https://payments.example.test/v1/");
        document["connections"]["payments"]["commandPath"] = json!(invalid);
        let error = load(&document)
            .err()
            .unwrap_or_else(|| panic!("{invalid} is refused"));
        assert!(
            error
                .field
                .as_deref()
                .unwrap_or_default()
                .contains("commandPath"),
            "{invalid}: {error:?}"
        );
    }
}
