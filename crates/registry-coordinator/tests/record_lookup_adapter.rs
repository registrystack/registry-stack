// SPDX-License-Identifier: Apache-2.0
//! `breg.lookup-record/v1` and `breg.read-record/v2` against a stub BReg: the
//! request each sends, the provenance each returns, and how each answer maps to
//! a step result.
mod support;

use registry_breg_client::BRegProblemCode;
use registry_coordinator::{
    adapters::HttpAdapters,
    contracts::contract,
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation},
};
use serde_json::{json, Value};
use support::{config, issuer, RECORD, TRACE};
use wiremock::{
    matchers::{body_json, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

const LINK: &str = "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/registrant>; rel=\"describedby\"";
const ETAG: &str = "\"breg-record-000000000001\"";

fn envelope() -> Value {
    json!({
        "data": {
            "recordIdentifier": RECORD, "revisionIdentifier": "7",
            "domainData": {"name": "Synthetic Registrant"}
        },
        "meta": {
            "registryIdentifier": "registry", "datasetIdentifier": "dataset",
            "recordTypeIdentifier": "registrant"
        }
    })
}

fn found(with_etag: bool) -> ResponseTemplate {
    let template = ResponseTemplate::new(200)
        .insert_header("traceparent", TRACE)
        .insert_header("link", LINK)
        .set_body_json(envelope());
    if with_etag {
        template.insert_header("etag", ETAG)
    } else {
        template
    }
}

/// A problem document in exactly the shape the BReg client accepts for a
/// catalogued code: its own status, title, detail and type URI.
fn problem(status: u16, code: &str) -> ResponseTemplate {
    let known = BRegProblemCode::ALL
        .into_iter()
        .find(|candidate| candidate.code() == code)
        .expect("a catalogued problem code");
    assert_eq!(known.status(), status, "{code}");
    let title = match status {
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        503 => "Service Unavailable",
        other => panic!("no title for {other}"),
    };
    ResponseTemplate::new(status)
        .insert_header("traceparent", TRACE)
        .insert_header("cache-control", "no-store")
        .set_body_raw(
            json!({
                "type": format!("https://id.registrystack.org/problems/registry-breg/{}", code.replace('.', "/")),
                "title": title, "status": status, "code": code,
                "detail": known.detail(),
                "traceId": "4bf92f3577b34da6a3ce929d0e0e4736"
            })
            .to_string(),
            "application/problem+json",
        )
}

fn lookup_input() -> Value {
    json!({
        "entity": "registrants", "selector": "by-national-id",
        "values": {"nationalId": "synthetic-1", "birthYear": 1980, "active": true}
    })
}

fn request(operation: Operation, input: Value) -> CallRequest {
    CallRequest {
        operation_contract: None,
        connection: "applications".into(),
        operation,
        input,
        idempotency_key: None,
    }
}

/// Run one request against a BReg whose `mount` closure installs the mocks,
/// returning the outcome and the requests the stub received.
async fn run(
    mount: impl FnOnce(&MockServer) -> Mock,
    request: CallRequest,
) -> (CallOutcome, Vec<wiremock::Request>) {
    let issuer = issuer().await;
    let server = MockServer::start().await;
    mount(&server).mount(&server).await;
    let root = tempfile::tempdir().unwrap();
    let adapters =
        HttpAdapters::new(&config(root.path(), &issuer, &server.uri(), &server.uri())).unwrap();
    let outcome = adapters.call(&request).await;
    let received = server.received_requests().await.unwrap();
    issuer.stop().await;
    (outcome, received)
}

fn lookup_mock(answer: ResponseTemplate) -> impl FnOnce(&MockServer) -> Mock {
    move |_| {
        Mock::given(method("POST"))
            .and(path("/v1/records/registrants:lookup"))
            .respond_with(answer)
    }
}

fn read_mock(answer: ResponseTemplate) -> impl FnOnce(&MockServer) -> Mock {
    move |_| {
        Mock::given(method("GET"))
            .and(path(format!("/v1/records/registrants/{RECORD}")))
            .respond_with(answer)
    }
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

fn observed_between(
    value: &Value,
    before: chrono::DateTime<chrono::Utc>,
    after: chrono::DateTime<chrono::Utc>,
) {
    let observed: chrono::DateTime<chrono::Utc> = value
        .as_str()
        .expect("observedAt is text")
        .parse()
        .expect("observedAt is an RFC 3339 instant");
    assert!(before <= observed && observed <= after);
}

#[tokio::test]
async fn a_lookup_that_finds_one_record_returns_it_with_provenance() {
    // observedAt is written to the second, so the lower bound is too.
    let before = chrono::SubsecRound::trunc_subsecs(chrono::Utc::now(), 0);
    let (outcome, received) = run(
        |_| {
            Mock::given(method("POST"))
                .and(path("/v1/records/registrants:lookup"))
                .and(query_param("accessProfile", "follow-up-reader"))
                .and(body_json(json!({
                    "selector": "by-national-id",
                    "values": {"nationalId": "synthetic-1", "birthYear": 1980, "active": true}
                })))
                .respond_with(found(false))
        },
        request(Operation::LookupRecord, lookup_input()),
    )
    .await;
    let after = chrono::Utc::now();
    assert_eq!(received.len(), 1);
    assert!(
        received[0].headers.get("if-match").is_none()
            && received[0].headers.get("if-none-match").is_none(),
        "a lookup sends no ETag"
    );
    let CallOutcome::Success(value) = outcome else {
        panic!("one match succeeds, got {}", refusal_code(&outcome));
    };
    assert_eq!(value["recordIdentifier"], RECORD);
    assert_eq!(value["revisionIdentifier"], "7");
    assert_eq!(value["domainData"], json!({"name": "Synthetic Registrant"}));
    assert_eq!(value["provenance"]["recordIdentifier"], RECORD);
    assert_eq!(value["provenance"]["revisionIdentifier"], "7");
    assert!(value["provenance"].get("etag").is_none());
    observed_between(&value["provenance"]["observedAt"], before, after);
    contract(Operation::LookupRecord)
        .check_output(&value)
        .expect("the output satisfies the operation's output contract");
}

#[tokio::test]
async fn a_lookup_with_no_values_for_a_verified_claim_selector_is_not_sent() {
    // The service identity carries no verified claim, so a lookup without
    // values could never resolve; the step is refused before any request.
    let mut input = lookup_input();
    input.as_object_mut().unwrap().remove("values");
    let (outcome, received) = run(
        lookup_mock(found(false)),
        request(Operation::LookupRecord, input),
    )
    .await;
    assert_eq!(refusal_code(&outcome), "invalid-command");
    assert!(received.is_empty());
}

#[tokio::test]
async fn every_unresolved_cause_is_the_one_declared_refusal() {
    // BReg answers zero matches, two matches, a hidden row and a missing claim
    // with the same value-free problem, so the adapter sees one wire shape.
    for cause in ["no match", "two matches", "a hidden row"] {
        let (outcome, received) = run(
            lookup_mock(problem(404, "lookup.unresolved")),
            request(Operation::LookupRecord, lookup_input()),
        )
        .await;
        assert_eq!(received.len(), 1, "{cause}");
        let CallOutcome::DeclaredRefusal(refusal) = outcome else {
            panic!("{cause}: unresolved is a declared refusal");
        };
        assert_eq!(refusal.refusal_code(), "unresolved", "{cause}");
        let value = json!({"refusalCode": refusal.refusal_code()});
        contract(Operation::LookupRecord)
            .check_refusal(&value)
            .unwrap_or_else(|error| panic!("{cause}: {error:?}"));
    }
}

#[tokio::test]
async fn the_unresolved_refusal_admits_no_other_code() {
    let contract = contract(Operation::LookupRecord);
    assert!(contract
        .check_refusal(&json!({"refusalCode": "unresolved"}))
        .is_ok());
    assert!(contract
        .check_refusal(&json!({"refusalCode": "none-in-force"}))
        .is_err());
}

#[tokio::test]
async fn other_lookup_failures_are_failures_not_absences() {
    for (answer, expected) in [
        (problem(404, "resource.not_found"), "product-not-found"),
        (
            problem(403, "ingestion.profile_mismatch"),
            "product-forbidden",
        ),
        (problem(401, "authentication.refused"), "product-forbidden"),
        (
            problem(503, "service.unavailable"),
            "retryable:transport-unavailable",
        ),
        (
            ResponseTemplate::new(200)
                .insert_header("traceparent", TRACE)
                .insert_header("link", LINK)
                .set_body_json(json!({"private-upstream-canary": true})),
            "invalid-response",
        ),
        (
            // A lookup response must not carry an ETag.
            found(true),
            "invalid-response",
        ),
    ] {
        let (outcome, _) = run(
            lookup_mock(answer),
            request(Operation::LookupRecord, lookup_input()),
        )
        .await;
        assert_eq!(refusal_code(&outcome), expected);
    }
}

#[tokio::test]
async fn a_malformed_lookup_input_is_refused_before_any_request() {
    let mut cases: Vec<(&str, Value)> = Vec::new();
    for missing in ["entity", "selector"] {
        let mut input = lookup_input();
        input.as_object_mut().unwrap().remove(missing);
        cases.push((missing, input));
    }
    let mut upper = lookup_input();
    upper["selector"] = json!("By-National-Id");
    cases.push(("a selector that is not a compiled name", upper));
    let mut bad_name = lookup_input();
    bad_name["values"] = json!({"national id": "x"});
    cases.push(("a value name that is not an API name", bad_name));
    let mut nested = lookup_input();
    nested["values"] = json!({"nationalId": {"inner": "x"}});
    cases.push(("a nested value", nested));
    let mut list = lookup_input();
    list["values"] = json!({"nationalId": ["a"]});
    cases.push(("a list value", list));
    let mut null_value = lookup_input();
    null_value["values"] = json!({"nationalId": null});
    cases.push(("a null value", null_value));
    let mut fractional = lookup_input();
    fractional["values"] = json!({"nationalId": 1.5});
    cases.push(("a fractional number", fractional));
    let mut empty = lookup_input();
    empty["values"] = json!({});
    cases.push(("empty values", empty));
    let mut many = lookup_input();
    many["values"] = Value::Object(
        (0..17)
            .map(|index| (format!("f{index}"), json!("x")))
            .collect(),
    );
    cases.push(("more than sixteen values", many));
    let mut extra = lookup_input();
    extra["filter"] = json!("nationalId eq 'x'");
    cases.push(("a filter string", extra));
    let mut text = lookup_input();
    text["values"] = json!("nationalId=x");
    cases.push(("values given as text", text));

    for (case, input) in cases {
        let (outcome, received) = run(
            lookup_mock(found(false)),
            request(Operation::LookupRecord, input),
        )
        .await;
        assert_eq!(refusal_code(&outcome), "invalid-command", "{case}");
        assert!(received.is_empty(), "{case}: nothing is sent");
    }
}

#[tokio::test]
async fn read_record_v2_returns_the_record_with_provenance_and_the_etag() {
    // observedAt is written to the second, so the lower bound is too.
    let before = chrono::SubsecRound::trunc_subsecs(chrono::Utc::now(), 0);
    let (outcome, received) = run(
        read_mock(found(true)),
        request(
            Operation::ReadRecordV2,
            json!({"collection": "registrants", "recordId": RECORD}),
        ),
    )
    .await;
    let after = chrono::Utc::now();
    assert_eq!(received.len(), 1);
    let CallOutcome::Success(value) = outcome else {
        panic!("the read succeeds, got {}", refusal_code(&outcome));
    };
    assert_eq!(value["data"], envelope()["data"]);
    assert_eq!(value["meta"], envelope()["meta"]);
    assert_eq!(value["provenance"]["recordIdentifier"], RECORD);
    assert_eq!(value["provenance"]["revisionIdentifier"], "7");
    assert_eq!(value["provenance"]["etag"], ETAG);
    observed_between(&value["provenance"]["observedAt"], before, after);
    contract(Operation::ReadRecordV2)
        .check_output(&value)
        .expect("the output satisfies the operation's output contract");
}

#[tokio::test]
async fn read_record_v1_output_has_no_provenance() {
    let (outcome, _) = run(
        read_mock(found(true)),
        request(
            Operation::ReadRecord,
            json!({"collection": "registrants", "recordId": RECORD}),
        ),
    )
    .await;
    let CallOutcome::Success(value) = outcome else {
        panic!("the read succeeds");
    };
    assert!(value.get("provenance").is_none());
    assert_eq!(value["data"], envelope()["data"]);
}

#[tokio::test]
async fn read_record_v2_refuses_an_answer_that_already_carries_a_provenance_member() {
    let mut body = envelope();
    body["provenance"] = json!({"forged": true});
    let (outcome, _) = run(
        read_mock(
            ResponseTemplate::new(200)
                .insert_header("traceparent", TRACE)
                .insert_header("etag", ETAG)
                .insert_header("link", LINK)
                .set_body_json(body),
        ),
        request(
            Operation::ReadRecordV2,
            json!({"collection": "registrants", "recordId": RECORD}),
        ),
    )
    .await;
    assert_eq!(refusal_code(&outcome), "invalid-response");
}

#[tokio::test]
async fn read_record_v2_failures_map_like_version_one() {
    for (answer, expected) in [
        (problem(404, "resource.not_found"), "product-not-found"),
        (
            problem(403, "ingestion.profile_mismatch"),
            "product-forbidden",
        ),
        (
            problem(503, "service.unavailable"),
            "retryable:transport-unavailable",
        ),
    ] {
        let (outcome, _) = run(
            read_mock(answer),
            request(
                Operation::ReadRecordV2,
                json!({"collection": "registrants", "recordId": RECORD}),
            ),
        )
        .await;
        assert_eq!(refusal_code(&outcome), expected);
    }
}

#[tokio::test]
async fn read_record_v2_takes_the_same_input_as_version_one() {
    let (outcome, received) = run(
        read_mock(found(true)),
        request(
            Operation::ReadRecordV2,
            json!({"collection": "registrants", "recordId": RECORD, "unknown": 1}),
        ),
    )
    .await;
    assert_eq!(refusal_code(&outcome), "invalid-command");
    assert!(received.is_empty());
}
