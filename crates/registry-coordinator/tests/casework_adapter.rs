// SPDX-License-Identifier: Apache-2.0
//! The Casework review producer binding against a mock Casework: submission
//! recovery under one key, cancellation of a request that already ended, the
//! value-free outcome of every refusal, result reads, and the completion
//! sender each connection authenticates.
mod support;

use registry_casework_client::{submission_digest, ReviewCreateRequest};
use registry_coordinator::{
    adapters::{ConnectionConfig, HttpAdapters, RuntimeConfig},
    definition::{CompletionDefinition, CompletionKind, CompletionReference, Definition},
    protocol::{AdapterSet, CallOutcome, CallRequest, CompletionObservation, Operation},
    runtime::ReviewCompletionConfig,
};
use registry_platform_config::SecretReference;
use serde_json::{json, Value};
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

const REQUEST: &str = "00000000-0000-4000-8000-0000000000a1";
const RESULT: &str = "00000000-0000-4000-8000-0000000000a2";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const PRODUCER: &str = "coordinator";
const PROFILE: &str = "coordinator-producer";
const CANARY: &str = "private-review-canary";

fn create() -> Value {
    json!({
        "policy": {"id":"notice-review","version":"1","digest":format!("sha256:{}","b".repeat(64))},
        "subject": {"source": "applications", "type": "application",
            "id": support::RECORD, "version": "3",
            "digest": format!("sha256:{}", "a".repeat(64))},
        "requesterReference": "application-3",
        "context": {"mode": "submitted", "snapshot": {"summary": CANARY}}
    })
}

fn digest(producer: &str) -> String {
    let request: ReviewCreateRequest = serde_json::from_value(create()).unwrap();
    submission_digest(producer, "applications", &request)
        .unwrap()
        .to_string()
}

fn accepted(submission: &str) -> Value {
    json!({
        "requestId": REQUEST,
        "subject": create()["subject"],
        "policy": {"id": "notice-review", "version": "1",
            "digest": format!("sha256:{}", "b".repeat(64))},
        "submissionDigest": submission,
    })
}

fn result(status: &str) -> Value {
    let accepted = accepted(&digest(PRODUCER));
    json!({
        "resultId": RESULT,
        "requestId": REQUEST,
        "subject": accepted["subject"],
        "policy": accepted["policy"],
        "submissionDigest": accepted["submissionDigest"],
        "status": status,
        "completedAt": "2026-10-11T10:00:00Z",
        "availableUntil": "2026-11-11T10:00:00Z",
    })
}

fn json_answer(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("traceparent", support::TRACE)
        .set_body_raw(body.to_string(), "application/json")
}

fn problem(status: u16, code: &str, title: &str, detail: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("traceparent", support::TRACE)
        .set_body_raw(
            json!({
                "type": format!(
                    "https://id.registrystack.org/problems/registry-casework/{}",
                    code.replace('.', "/")
                ),
                "title": title,
                "status": status,
                "detail": detail,
                "code": code,
                "traceId": TRACE_ID,
            })
            .to_string(),
            "application/problem+json",
        )
}

/// The outcome's kind and code; a success shows no value.
fn describe(outcome: &CallOutcome) -> String {
    match outcome {
        CallOutcome::Success(_) => "success".into(),
        CallOutcome::Retryable { code, .. } => format!("retryable {code}"),
        CallOutcome::Refused { code } => format!("refused {code}"),
        CallOutcome::DeclaredRefusal(_) => "declared-refusal".into(),
        CallOutcome::Uncertain { code } => format!("uncertain {code}"),
        CallOutcome::ReceiptExpired => "receipt-expired".into(),
    }
}

fn submit(key: &str) -> CallRequest {
    CallRequest {
        operation_contract: None,
        connection: "review".into(),
        operation: Operation::SubmitReviewRequest,
        input: create(),
        idempotency_key: Some(key.into()),
    }
}

fn cancel(key: &str) -> CallRequest {
    CallRequest {
        operation_contract: None,
        connection: "review".into(),
        operation: Operation::CancelReviewRequest,
        input: json!({"request": accepted(&digest(PRODUCER)), "reason": "review-timed-out"}),
        idempotency_key: Some(key.into()),
    }
}

struct Fixture {
    adapters: HttpAdapters,
    token: MockServer,
    casework: MockServer,
    _root: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let token = MockServer::start().await;
    let casework = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let issuer = support::issuer().await;
    let mut config = support::config(root.path(), &issuer, &casework.uri(), &casework.uri());
    let mut authorization = config.connections["applications"]
        .authorization()
        .unwrap()
        .clone();
    authorization.token_endpoint = format!("{}/token", token.uri()).parse().unwrap();
    authorization.resource = "urn:example:casework".into();
    authorization.scopes = vec!["casework:review".into()];
    config.connections.insert(
        "review".into(),
        ConnectionConfig::CaseworkReviewProducer(
            registry_coordinator::runtime::CaseworkConnectionConfig {
                base_url: casework.uri().parse().unwrap(),
                authorization,
                profile: PROFILE.into(),
                producer: PRODUCER.into(),
                completion: None,
                result_check_seconds: None,
            },
        ),
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "fixture-token", "token_type": "Bearer", "expires_in": 40,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"})))
        .mount(&token)
        .await;
    let adapters = HttpAdapters::new(&config).unwrap();
    issuer.stop().await;
    Fixture {
        adapters,
        token,
        casework,
        _root: root,
    }
}

#[tokio::test]
async fn submit_review_request_recovers_the_accepted_request_under_the_same_key() {
    let fixture = fixture().await;
    Mock::given(method("POST"))
        .and(path("/v1/review-requests"))
        .and(header("authorization", "Bearer fixture-token"))
        .and(header("registry-review-profile", PROFILE))
        .and(header("idempotency-key", "review-key"))
        .and(body_json(create()))
        .respond_with(json_answer(200, accepted(&digest(PRODUCER))))
        .expect(2)
        .mount(&fixture.casework)
        .await;
    let first = fixture.adapters.call(&submit("review-key")).await;
    let recovered = fixture.adapters.call(&submit("review-key")).await;
    let CallOutcome::Success(first) = first else {
        panic!("the accepted review request is the step output");
    };
    let CallOutcome::Success(recovered) = recovered else {
        panic!("the same key recovers the accepted review request");
    };
    assert_eq!(first, accepted(&digest(PRODUCER)));
    assert_eq!(recovered, first);
    registry_coordinator::contracts::contract(Operation::SubmitReviewRequest)
        .check_output(&first)
        .unwrap();
    registry_coordinator::contracts::contract(Operation::SubmitReviewRequest)
        .check_input(&create())
        .unwrap();
}

#[tokio::test]
async fn submit_review_request_holds_an_acceptance_bound_to_another_producer() {
    let fixture = fixture().await;
    Mock::given(method("POST"))
        .and(path("/v1/review-requests"))
        .respond_with(json_answer(200, accepted(&digest("another-producer"))))
        .expect(1)
        .mount(&fixture.casework)
        .await;
    let outcome = fixture.adapters.call(&submit("review-key")).await;
    assert!(
        matches!(&outcome, CallOutcome::Uncertain { code } if code == "invalid-response"),
        "{}",
        describe(&outcome)
    );
}

#[tokio::test]
async fn accepted_policy_must_match_the_exact_requested_revision() {
    for (field, value) in [
        ("id", json!("other-policy")),
        ("version", json!("2")),
        ("digest", json!(format!("sha256:{}", "d".repeat(64)))),
    ] {
        let fixture = fixture().await;
        let mut response = accepted(&digest(PRODUCER));
        response["policy"][field] = value;
        Mock::given(method("POST"))
            .and(path("/v1/review-requests"))
            .respond_with(json_answer(201, response))
            .expect(1)
            .mount(&fixture.casework)
            .await;
        assert!(
            matches!(fixture.adapters.call(&submit("exact-policy")).await,CallOutcome::Uncertain {code} if code=="invalid-response")
        );
    }
}

#[tokio::test]
async fn cancel_review_request_counts_a_request_that_already_ended_as_done() {
    let fixture = fixture().await;
    for (outcome, status) in [("cancelled", "cancelled"), ("already-terminal", "approved")] {
        fixture.casework.reset().await;
        let answer = json!({"outcome": outcome, "result": result(status)});
        Mock::given(method("POST"))
            .and(path(format!("/v1/review-requests/{REQUEST}/cancel")))
            .and(header("authorization", "Bearer fixture-token"))
            .and(header("registry-review-profile", PROFILE))
            .and(header("idempotency-key", "cancel-key"))
            .and(body_json(
                json!({"subject": create()["subject"], "reason": "review-timed-out"}),
            ))
            .respond_with(json_answer(200, answer.clone()))
            .expect(1)
            .mount(&fixture.casework)
            .await;
        let CallOutcome::Success(value) = fixture.adapters.call(&cancel("cancel-key")).await else {
            panic!("a {outcome} answer completes the cancel step");
        };
        assert_eq!(value, answer);
        let contract = registry_coordinator::contracts::contract(Operation::CancelReviewRequest);
        contract.check_output(&value).unwrap();
        contract.check_input(&cancel("cancel-key").input).unwrap();
    }
}

#[tokio::test]
async fn review_refusals_are_value_free_and_ambiguous_submissions_are_held() {
    let cases: Vec<(ResponseTemplate, &str, &str)> = vec![
        (
            problem(
                410,
                "idempotency.expired",
                "Idempotency window expired",
                "The stored response for this idempotency key has expired. Reconcile the original operation before choosing a new key.",
            ),
            "receipt-expired",
            "",
        ),
        (
            problem(
                401,
                "authentication.refused",
                "Authentication refused",
                "The bearer credential is missing, invalid, or expired. Sign in again.",
            ),
            "refused",
            "product-forbidden",
        ),
        (
            problem(
                409,
                "review.submission-conflict",
                "Review submission conflict",
                "The same producer, source subject, version, and policy were already submitted with different canonical content.",
            ),
            "refused",
            "product-refused",
        ),
        (
            problem(429, "edge.rate-limited", "Slow down", CANARY),
            "retryable",
            "rate-limited",
        ),
        (
            problem(503, "edge.unavailable", "Unavailable", CANARY),
            "uncertain",
            "transport-uncertain",
        ),
        (
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_raw(CANARY, "application/json"),
            "uncertain",
            "invalid-response",
        ),
    ];
    for (answer, kind, code) in cases {
        let fixture = fixture().await;
        Mock::given(method("POST"))
            .and(path("/v1/review-requests"))
            .respond_with(answer)
            .expect(1)
            .mount(&fixture.casework)
            .await;
        let outcome = fixture.adapters.call(&submit("review-key")).await;
        assert!(!describe(&outcome).contains(CANARY));
        match (kind, &outcome) {
            ("receipt-expired", CallOutcome::ReceiptExpired) => {}
            ("refused", CallOutcome::Refused { code: observed })
            | ("retryable", CallOutcome::Retryable { code: observed, .. })
            | ("uncertain", CallOutcome::Uncertain { code: observed })
                if observed == code => {}
            _ => panic!("expected {kind} {code}, observed {}", describe(&outcome)),
        }
    }
}

#[tokio::test]
async fn invalid_review_commands_never_reach_casework() {
    let fixture = fixture().await;
    let mut unknown_member = submit("review-key");
    unknown_member.input["extra"] = json!(CANARY);
    let mut without_key = submit("review-key");
    without_key.idempotency_key = None;
    let mut spaced_key = submit("review-key");
    spaced_key.idempotency_key = Some("spaced key".into());
    let mut missing_reason = cancel("cancel-key");
    missing_reason
        .input
        .as_object_mut()
        .unwrap()
        .remove("reason");
    let mut retired_context = submit("review-key");
    retired_context.input["context"] =
        json!({"strategy":"submitted","snapshot":{"summary":CANARY}});
    let mut unbound_context = submit("review-key");
    unbound_context.input["context"] = json!({"mode":"current-source","reference":"application-3"});
    let mut wrong_connection = submit("review-key");
    wrong_connection.connection = "notices".into();
    let mut wrong_operation = submit("review-key");
    wrong_operation.operation = Operation::SubmitMessage;
    for (request, code) in [
        (unknown_member, "invalid-command"),
        (without_key, "invalid-command"),
        (spaced_key, "invalid-command"),
        (missing_reason, "invalid-command"),
        (retired_context, "invalid-command"),
        (unbound_context, "invalid-command"),
        (wrong_connection, "operation-unbound"),
        (wrong_operation, "operation-unbound"),
    ] {
        let outcome = fixture.adapters.call(&request).await;
        assert!(
            matches!(&outcome, CallOutcome::Refused { code: observed } if observed == code),
            "{}",
            describe(&outcome)
        );
    }
    assert!(fixture
        .casework
        .received_requests()
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_refused_producer_credential_sends_nothing_to_casework() {
    let fixture = fixture().await;
    fixture.token.reset().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&fixture.token)
        .await;
    let outcome = fixture.adapters.call(&submit("review-key")).await;
    assert!(
        matches!(&outcome, CallOutcome::Refused { code } if code == "credential-refused"),
        "{}",
        describe(&outcome)
    );
    assert!(fixture
        .casework
        .received_requests()
        .await
        .unwrap()
        .is_empty());
}

/// A result read's kind and code; a settled read shows no value.
fn describe_read(read: &CompletionObservation) -> String {
    match read {
        CompletionObservation::Settled(_) => "settled".into(),
        CompletionObservation::Pending { .. } => "pending".into(),
        CompletionObservation::Retryable { code, .. } => format!("retryable {code}"),
        CompletionObservation::Hold { code } => format!("hold {code}"),
    }
}

fn empty(status: u16) -> ResponseTemplate {
    ResponseTemplate::new(status).insert_header("traceparent", support::TRACE)
}

#[tokio::test]
async fn a_result_read_names_each_casework_answer_without_a_value() {
    let mut substituted = result("approved");
    substituted["subject"]["version"] = json!("4");
    let cases: Vec<(ResponseTemplate, &str)> = vec![
        (json_answer(200, result("approved")), "settled"),
        (empty(202), "pending"),
        (empty(404), "hold review-request-unknown"),
        (empty(410), "hold review-result-expired"),
        (json_answer(200, substituted), "hold invalid-response"),
        (
            problem(429, "edge.rate-limited", "Slow down", CANARY),
            "retryable rate-limited",
        ),
        (
            problem(
                401,
                "authentication.refused",
                "Authentication refused",
                "The bearer credential is missing, invalid, or expired. Sign in again.",
            ),
            "hold product-forbidden",
        ),
        (
            problem(503, "edge.unavailable", "Unavailable", CANARY),
            "retryable transport-unavailable",
        ),
        (
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_raw(CANARY, "application/json"),
            "hold invalid-response",
        ),
        // An intermediary's own page is outside Casework's catalogue, but its
        // status still says the read may be repeated.
        (
            empty(408).set_body_raw(CANARY, "text/html"),
            "retryable transport-unavailable",
        ),
        (
            empty(429).set_body_raw(CANARY, "text/html"),
            "retryable rate-limited",
        ),
        (
            empty(502).set_body_raw(CANARY, "text/html"),
            "retryable transport-unavailable",
        ),
    ];
    let definition = Definition::load(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/review-wait"),
    )
    .unwrap();
    let contract = definition
        .completion_contract(&CompletionReference {
            step: "submit-review".into(),
            name: "result".into(),
        })
        .unwrap();
    for (answer, expected) in cases {
        let fixture = fixture().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/review-requests/{REQUEST}/result")))
            .and(header("authorization", "Bearer fixture-token"))
            .and(header("registry-review-profile", PROFILE))
            .respond_with(answer)
            .expect(1)
            .mount(&fixture.casework)
            .await;
        let read = fixture
            .adapters
            .observe_completion(
                &review_read("review"),
                &accepted(&digest(PRODUCER)),
                &completion(),
            )
            .await;
        let observed = describe_read(&read);
        assert!(!observed.contains(CANARY));
        assert_eq!(observed, expected);
        if let CompletionObservation::Settled(value) = read {
            assert_eq!(value, result("approved"));
            contract.check(&value).unwrap();
        }
    }
}

#[tokio::test]
async fn a_result_read_without_an_accepted_request_or_casework_binding_sends_nothing() {
    let fixture = fixture().await;
    let mut unknown_member = accepted(&digest(PRODUCER));
    unknown_member["extra"] = json!(CANARY);
    for (connection, value, expected) in [
        ("review", unknown_member, "hold invalid-command"),
        ("review", json!(CANARY), "hold invalid-command"),
        (
            "notices",
            accepted(&digest(PRODUCER)),
            "hold operation-unbound",
        ),
        (
            "absent",
            accepted(&digest(PRODUCER)),
            "hold operation-unbound",
        ),
    ] {
        let read = fixture
            .adapters
            .observe_completion(&review_read(connection), &value, &completion())
            .await;
        assert_eq!(describe_read(&read), expected);
    }
    assert!(fixture
        .casework
        .received_requests()
        .await
        .unwrap()
        .is_empty());
}

fn with_completion(config: &mut RuntimeConfig, root: &std::path::Path, name: &str, token: &str) {
    let file = format!("{name}-completion-token");
    support::private_file(&root.join(&file), token.as_bytes());
    let mut connection = config.connections["review"].clone();
    let ConnectionConfig::CaseworkReviewProducer(ref mut binding) = connection else {
        panic!("Casework binding")
    };
    binding.result_check_seconds = None;
    binding.completion = Some(ReviewCompletionConfig {
        recipient_binding: format!("{name}-v1"),
        bearer_token_ref: SecretReference::parse(format!("secret:file/{file}")).unwrap(),
    });
    config.connections.insert(name.into(), connection);
}

async fn completion_fixture() -> (HttpAdapters, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let issuer = support::issuer().await;
    let mut config = support::config(
        root.path(),
        &issuer,
        "http://127.0.0.1:9",
        "http://127.0.0.1:9",
    );
    config.connections.insert(
        "review".into(),
        ConnectionConfig::CaseworkReviewProducer(
            registry_coordinator::runtime::CaseworkConnectionConfig {
                base_url: "http://127.0.0.1:9".parse().unwrap(),
                authorization: config.connections["applications"]
                    .authorization()
                    .unwrap()
                    .clone(),
                profile: PROFILE.into(),
                producer: PRODUCER.into(),
                completion: None,
                result_check_seconds: Some(registry_platform_yaml::BoundedU32::new(120).unwrap()),
            },
        ),
    );
    with_completion(
        &mut config,
        root.path(),
        "intake",
        "completion-token-intake",
    );
    with_completion(
        &mut config,
        root.path(),
        "appeals",
        "completion-token-shared",
    );
    with_completion(
        &mut config,
        root.path(),
        "renewals",
        "completion-token-shared",
    );
    let adapters = HttpAdapters::new(&config).unwrap();
    issuer.stop().await;
    (adapters, root)
}

#[tokio::test]
async fn a_completion_names_one_connection_only_for_its_own_token_and_binding() {
    let (adapters, _root) = completion_fixture().await;
    assert_eq!(
        adapters
            .review_completion("completion-token-intake", "intake-v1")
            .as_deref(),
        Some("intake")
    );
    // Two connections may share a token; the binding still names one.
    assert_eq!(
        adapters
            .review_completion("completion-token-shared", "appeals-v1")
            .as_deref(),
        Some("appeals")
    );
    assert_eq!(
        adapters
            .review_completion("completion-token-shared", "renewals-v1")
            .as_deref(),
        Some("renewals")
    );
    for (token, recipient) in [
        ("completion-token-intake", "appeals-v1"),
        ("completion-token-shared", "intake-v1"),
        ("completion-token-intak", "intake-v1"),
        ("completion-token-intakee", "intake-v1"),
        ("", "intake-v1"),
        ("completion-token-intake", ""),
        ("completion-token-intake", "intake-v2"),
    ] {
        assert!(adapters.review_completion(token, recipient).is_none());
    }
    // A connection without a completion block accepts no completion at all.
    assert!(adapters.review_completion("", "review-v1").is_none());
    assert_eq!(adapters.observation_interval("review", &completion()), 120);
    assert_eq!(
        adapters.observation_interval("intake", &completion()),
        registry_coordinator::runtime::DEFAULT_RESULT_CHECK_SECONDS
    );
}

#[tokio::test]
async fn a_completion_token_that_is_not_a_bearer_token_refuses_the_configuration() {
    let root = tempfile::tempdir().unwrap();
    let issuer = support::issuer().await;
    let mut config = support::config(
        root.path(),
        &issuer,
        "http://127.0.0.1:9",
        "http://127.0.0.1:9",
    );
    config.connections.insert(
        "review".into(),
        ConnectionConfig::CaseworkReviewProducer(
            registry_coordinator::runtime::CaseworkConnectionConfig {
                base_url: "http://127.0.0.1:9".parse().unwrap(),
                authorization: config.connections["applications"]
                    .authorization()
                    .unwrap()
                    .clone(),
                profile: PROFILE.into(),
                producer: PRODUCER.into(),
                completion: None,
                result_check_seconds: None,
            },
        ),
    );
    issuer.stop().await;
    for token in ["completion token\n", "", "token with space"] {
        with_completion(&mut config, root.path(), "intake", token);
        let Err(error) = HttpAdapters::new(&config) else {
            panic!("a completion token outside the bearer grammar is refused");
        };
        assert_eq!(error.code, "adapter.configuration");
        assert!(!error.to_string().contains("token with space"));
    }
}

fn completion() -> CompletionDefinition {
    CompletionDefinition {
        kind: CompletionKind::CaseworkResult {},
        output: registry_coordinator::contracts::casework_completion_schema().clone(),
        revision: format!("sha256:{}", "0".repeat(64)),
    }
}
fn review_read(connection: &str) -> CallRequest {
    CallRequest {
        connection: connection.into(),
        operation: Operation::SubmitReviewRequest,
        input: create(),
        idempotency_key: None,
        operation_contract: None,
    }
}
