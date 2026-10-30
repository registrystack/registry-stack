// SPDX-License-Identifier: Apache-2.0
//! `breg.read-in-force/v1` against a stub BReg: the request it sends and how
//! each answer maps to a step result.
mod support;

use registry_coordinator::{
    adapters::HttpAdapters,
    contracts::contract,
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation},
};
use serde_json::{json, Value};
use support::{config, issuer, TRACE};
use wiremock::{
    matchers::{header_exists, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

const ASSIGNMENT: &str = "00000000-0000-4000-8000-0000000000a1";
const OTHER_ASSIGNMENT: &str = "00000000-0000-4000-8000-0000000000a2";
const LINK: &str = "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/assignment>; rel=\"describedby\"";

fn row(identifier: &str, revision: &str) -> Value {
    json!({
        "recordIdentifier": identifier,
        "revisionIdentifier": revision,
        "domainData": {"district": "Colombo", "officer": "synthetic-officer"}
    })
}

fn collection(items: Vec<Value>) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("traceparent", TRACE)
        .insert_header("link", LINK)
        .set_body_json(json!({
            "items": items,
            "pageInfo": {"nextCursor": null},
            "meta": {
                "registryIdentifier": "registry",
                "datasetIdentifier": "dataset",
                "entityTypeIdentifier": "assignment"
            }
        }))
}

fn problem(status: u16, code: &str, title: &str, detail: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("traceparent", TRACE)
        .insert_header("cache-control", "no-store")
        .set_body_raw(
            json!({
                "type": format!("https://id.registrystack.org/problems/registry-breg/{}", code.replace('.', "/")),
                "title": title, "status": status, "code": code,
                "detail": detail,
                "traceId": "4bf92f3577b34da6a3ce929d0e0e4736"
            })
            .to_string(),
            "application/problem+json",
        )
}

fn command(subject: Value, date: &str) -> CallRequest {
    CallRequest {
        operation_contract: None,
        connection: "applications".into(),
        operation: Operation::ReadInForce,
        input: json!({"entity": "assignments", "subject": subject, "date": date}),
        idempotency_key: None,
    }
}

fn district() -> Value {
    json!({"district": "Colombo"})
}

/// Run one command against a BReg that answers every as-of read with
/// `answer`, returning the outcome and the number of requests received.
async fn run(answer: ResponseTemplate, request: CallRequest) -> (CallOutcome, usize) {
    let issuer = issuer().await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/records/assignments:as-of"))
        .respond_with(answer)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().unwrap();
    let adapters =
        HttpAdapters::new(&config(root.path(), &issuer, &server.uri(), &server.uri())).unwrap();
    let outcome = adapters.call(&request).await;
    let count = server.received_requests().await.unwrap().len();
    issuer.stop().await;
    (outcome, count)
}

fn refusal_code(outcome: &CallOutcome) -> String {
    match outcome {
        CallOutcome::Refused { code } => code.clone(),
        CallOutcome::DeclaredRefusal(_) => "declared-refusal".into(),
        CallOutcome::Success(_) => "success".into(),
        CallOutcome::Retryable { code, .. } => format!("retryable:{code}"),
        _ => "other".into(),
    }
}

#[tokio::test]
async fn one_row_in_force_is_the_step_output() {
    // observedAt is written to the second, so the lower bound is too.
    let before = chrono::SubsecRound::trunc_subsecs(chrono::Utc::now(), 0);
    let (outcome, count) = run(
        collection(vec![row(ASSIGNMENT, "3")]),
        command(district(), "2026-06-05"),
    )
    .await;
    let after = chrono::Utc::now();
    assert_eq!(count, 1);
    let CallOutcome::Success(value) = outcome else {
        panic!("one row in force succeeds, got {}", refusal_code(&outcome));
    };
    assert_eq!(value["recordIdentifier"], ASSIGNMENT);
    assert_eq!(value["revisionIdentifier"], "3");
    assert_eq!(
        value["domainData"],
        json!({"district": "Colombo", "officer": "synthetic-officer"})
    );
    assert_eq!(value["asOf"], "2026-06-05");
    let observed: chrono::DateTime<chrono::Utc> = value["observedAt"]
        .as_str()
        .expect("observedAt is text")
        .parse()
        .expect("observedAt is an RFC 3339 instant");
    assert!(before <= observed && observed <= after);
    contract(Operation::ReadInForce)
        .check_output(&value)
        .expect("the output satisfies the operation's output contract");
}

#[tokio::test]
async fn zero_rows_is_the_declared_refusal_none_in_force() {
    let (outcome, count) = run(collection(vec![]), command(district(), "2026-06-05")).await;
    assert_eq!(count, 1);
    let CallOutcome::DeclaredRefusal(refusal) = outcome else {
        panic!("an empty successful read is a declared refusal");
    };
    let refusal = serde_json::to_value(refusal).unwrap();
    assert_eq!(refusal, json!({"refusalCode": "none-in-force"}));
    contract(Operation::ReadInForce)
        .check_refusal(&refusal)
        .expect("the refusal satisfies the declared refusal schema");
}

#[tokio::test]
async fn two_rows_is_ambiguous_and_carries_only_the_identifiers_and_date() {
    let (outcome, count) = run(
        collection(vec![row(ASSIGNMENT, "3"), row(OTHER_ASSIGNMENT, "1")]),
        command(district(), "2026-06-05"),
    )
    .await;
    assert_eq!(count, 1);
    let CallOutcome::InForceAmbiguous(detail) = outcome else {
        panic!("two records in force hold the run with their identifiers");
    };
    assert_eq!(
        serde_json::to_value(detail).unwrap(),
        json!({"date": "2026-06-05", "recordIdentifiers": [ASSIGNMENT, OTHER_ASSIGNMENT]})
    );
}

#[tokio::test]
async fn more_rows_than_the_top_two_asked_for_is_an_invalid_response() {
    let (outcome, _) = run(
        collection(vec![
            row(ASSIGNMENT, "1"),
            row(OTHER_ASSIGNMENT, "1"),
            row("00000000-0000-4000-8000-0000000000a3", "1"),
        ]),
        command(district(), "2026-06-05"),
    )
    .await;
    assert_eq!(refusal_code(&outcome), "invalid-response");
}

#[tokio::test]
async fn a_refused_read_is_a_failure_never_none_in_force() {
    for (answer, expected) in [
        (
            problem(
                401,
                "authentication.refused",
                "Unauthorized",
                "The bearer credential is missing or refused.",
            ),
            "product-forbidden",
        ),
        (
            problem(
                403,
                "ingestion.profile_mismatch",
                "Forbidden",
                "The selected access profile does not match the run's bound profile.",
            ),
            "product-forbidden",
        ),
        (
            problem(
                404,
                "resource.not_found",
                "Not Found",
                "The requested resource was not found.",
            ),
            "product-not-found",
        ),
    ] {
        let (outcome, count) = run(answer, command(district(), "2026-06-05")).await;
        assert_eq!(count, 1);
        assert_eq!(refusal_code(&outcome), expected);
    }
}

#[tokio::test]
async fn a_temporary_failure_is_retryable() {
    let (outcome, _) = run(
        ResponseTemplate::new(503).set_body_string("private-upstream-canary"),
        command(district(), "2026-06-05"),
    )
    .await;
    assert_eq!(refusal_code(&outcome), "retryable:transport-unavailable");
}

#[tokio::test]
async fn the_request_is_one_as_of_read_with_an_equality_filter_and_top_two() {
    let issuer = issuer().await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/records/assignments:as-of"))
        .and(query_param("asOf", "2026-06-05"))
        .and(query_param(
            "$filter",
            "district eq 'O''Brien''s' and grade eq 7 and hours eq 7.5 and lead eq true",
        ))
        .and(query_param("$top", "2"))
        .and(query_param("accessProfile", "follow-up-reader"))
        .and(header_exists("authorization"))
        .respond_with(collection(vec![row(ASSIGNMENT, "1")]))
        .expect(1)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().unwrap();
    let adapters =
        HttpAdapters::new(&config(root.path(), &issuer, &server.uri(), &server.uri())).unwrap();
    let outcome = adapters
        .call(&command(
            json!({"district": "O'Brien's", "grade": 7, "hours": 7.5, "lead": true}),
            "2026-06-05",
        ))
        .await;
    assert_eq!(refusal_code(&outcome), "success");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "one durable attempt sends one read");
    assert_eq!(requests[0].method.as_str(), "GET");
    issuer.stop().await;
}

#[tokio::test]
async fn a_filter_never_comes_from_text_the_author_supplies() {
    let long = "x".repeat(1025);
    let cases = [
        (
            "a date that is not a calendar date",
            district(),
            "2026-02-30",
        ),
        ("a date with unpadded parts", district(), "2026-6-5"),
        (
            "a timestamp in place of a date",
            district(),
            "2026-06-05T00:00:00Z",
        ),
        ("an empty subject", json!({}), "2026-06-05"),
        ("a null value", json!({"district": null}), "2026-06-05"),
        ("an array value", json!({"district": ["a"]}), "2026-06-05"),
        (
            "an object value",
            json!({"district": {"a": 1}}),
            "2026-06-05",
        ),
        ("an exponent number", json!({"grade": 1e30}), "2026-06-05"),
        (
            "a control character",
            json!({"district": "a\u{0007}b"}),
            "2026-06-05",
        ),
        (
            "a literal over the bound",
            json!({"district": long}),
            "2026-06-05",
        ),
        (
            "a property name that is a filter fragment",
            json!({"district eq 'x' or id": "y"}),
            "2026-06-05",
        ),
        (
            "an upper-case property name",
            json!({"District": "Colombo"}),
            "2026-06-05",
        ),
    ];
    for (name, subject, date) in cases {
        let (outcome, count) = run(collection(vec![]), command(subject, date)).await;
        assert_eq!(refusal_code(&outcome), "invalid-command", "{name}");
        assert_eq!(count, 0, "{name} sends no request");
    }
}

#[tokio::test]
async fn an_entity_outside_the_route_grammar_is_refused_before_any_request() {
    let mut request = command(district(), "2026-06-05");
    request.input["entity"] = json!("assignments/../x");
    let (outcome, count) = run(collection(vec![]), request).await;
    assert_eq!(refusal_code(&outcome), "invalid-command");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn unknown_input_members_are_refused() {
    let mut request = command(district(), "2026-06-05");
    request.input["filter"] = json!("district eq 'x'");
    let (outcome, count) = run(collection(vec![]), request).await;
    assert_eq!(refusal_code(&outcome), "invalid-command");
    assert_eq!(count, 0);
}
