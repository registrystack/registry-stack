// SPDX-License-Identifier: Apache-2.0
//! The BReg Proposal calls and the follow of one Proposal through the
//! configured adapters, against a stub BReg that serves one pinned Proposal
//! Action and one Proposal.
mod support;

use std::sync::{Arc, Mutex};

use registry_breg_client::{BRegActionMode, BRegProblemCode};
use registry_coordinator::{
    adapters::HttpAdapters,
    breg_action::ActionContract,
    definition::{CompletionDefinition, CompletionKind},
    protocol::{
        AdapterSet, CallOutcome, CallRequest, CompletionObservation, Operation, ProposalObservation,
    },
};
use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const ID: &str = "00000000-0000-4000-8000-000000000001";
const RECORD: &str = "00000000-0000-4000-8000-000000000002";
const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FINGERPRINT: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const EFFECT: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const KEY: &str = "durable-proposal-key";
const START: &str = "/tenant/base/v1/actions/update-item";
const GET: &str = "/tenant/base/v1/proposals/00000000-0000-4000-8000-000000000001";

fn metadata() -> Value {
    json!({
        "id":"fixture-registry", "version":"1", "revision":REVISION,
        "metadataVersion":"2", "recordTypes":[], "operations":[],
        "actions":[{
            "id":"update-item", "route":"/v1/actions/update-item", "conditionRoute":null,
            "apiName":"updateItem", "revision":FINGERPRINT, "display":{},
            "execution":{"mode":"proposal"}, "inputMode":"fixed", "maximumInputStringBytes":null,
            "inputs":[
                {"id":"target", "apiName":"targetId", "required":true,
                 "nullable":false, "classification":"internal",
                 "schema":{"type":"string", "format":"uuid"},
                 "fieldType":{"type":"reference", "target":"item", "onDelete":"restrict"}},
                {"id":"label", "apiName":"label", "required":true,
                 "nullable":false, "classification":"internal",
                 "schema":{"type":"string", "minLength":1, "maxLength":16},
                 "fieldType":{"type":"string", "minimumLength":1, "maximumLength":16}}
            ],
            "referenceInputs":[{"input":"target", "apiName":"targetId", "targetRecordType":"item"}],
            "requiredConditionKeys":[],
            "resultEffects":[{"effect":"item", "recordType":"item", "operation":"patch"}],
            "access":{"selectedProfile":"writer"},
            "routes":{
                "start":{"method":"POST", "path":"/v1/actions/update-item",
                    "operationId":"actions.update-item.start", "requiresIdempotencyKey":true,
                    "inputSchema":"action-update-item-invoke-input",
                    "responseSchema":"action-update-item-invoke-response"}
            },
            "bounds":{"maximumTargets":16, "maximumFieldMutations":128, "maximumSnapshotBytes":2097152}
        }],
        "proposals":{"method":"GET", "path":"/v1/proposals", "accessProfiles":["writer"],
            "get":{"method":"GET", "path":"/v1/proposals/{proposal_id}", "accessProfiles":["writer"]},
            "actions":[{"actionId":"update-item", "accessProfile":"writer", "readableInputs":["label"],
                "operations":["get", "submit", "cancel"]}]}
    })
}

fn link(operation: &str, revision: u64) -> Value {
    json!({"method":"POST", "path":format!("/v1/proposals/{ID}/{operation}"),
        "accessProfile":"writer", "operation":operation,
        "ifMatch":format!("\"proposal-revision-{revision}\"")})
}

/// One Proposal document as BReg serves it. The turn follows the state:
/// a draft is the party's, a terminal Proposal nobody's, and a submitted
/// one the official's unless the case says otherwise.
fn proposal(state: &str, version: u32, revision: u64) -> Value {
    let mut links = json!({"self":{"method":"GET", "path":format!("/v1/proposals/{ID}"),
        "accessProfile":"writer", "operation":"get"}});
    let turn = match state {
        "draft" => {
            links["submit"] = link("submit", revision);
            links["cancel"] = link("cancel", revision);
            "party"
        }
        "submitted" => {
            links["cancel"] = link("cancel", revision);
            "official"
        }
        _ => "nobody",
    };
    let mut value = json!({"id":ID, "actionId":"update-item", "actionRevision":FINGERPRINT,
        "input":{"label":"Original"}, "submissionVersion":version, "revision":revision,
        "state":state, "turn":turn, "links":links});
    if state != "draft" {
        value["effectDigest"] = json!(EFFECT);
    }
    if state == "applied" {
        value["application"] = json!({"applicationId":RECORD, "submissionVersion":version,
            "effectDigest":EFFECT,
            "resultLinks":[{"recordType":"item", "recordId":RECORD, "revision":2}]});
    }
    value
}

fn decided(mut value: Value, status: &str) -> Value {
    value["decision"] = json!({"status":status, "decidedAt":"2026-09-19T00:01:00.000001Z",
        "publicReason":"Synthetic public reason."});
    value
}

fn response(status: u16, value: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("traceparent", TRACE)
        .insert_header("cache-control", "no-store")
        .insert_header("vary", "authorization, accept")
        .set_body_json(value)
}

fn problem(code: BRegProblemCode) -> ResponseTemplate {
    ResponseTemplate::new(code.status())
        .insert_header("traceparent", TRACE)
        .insert_header("cache-control", "no-store")
        .set_body_raw(
            json!({"type":format!("https://id.registrystack.org/problems/registry-breg/{}",
                code.code().replace('.', "/")),
                "title":"Refused", "status":code.status(), "code":code.code(),
                "detail":code.detail(), "traceId":"4bf92f3577b34da6a3ce929d0e0e4736"})
            .to_string(),
            "application/problem+json",
        )
}

/// What the stub answers to a Proposal Get.
#[derive(Clone)]
enum Current {
    Proposal(Value),
    Problem(BRegProblemCode),
    Forbidden,
}

struct Fixture {
    server: MockServer,
    adapters: HttpAdapters,
    current: Arc<Mutex<Current>>,
    _root: tempfile::TempDir,
    issuer: registry_platform_testing::TestAuthorizationServer,
}

impl Fixture {
    async fn start() -> Self {
        Self::with_metadata(metadata()).await
    }

    async fn with_metadata(metadata: Value) -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/tenant/base/v1/registry"))
            .respond_with(response(200, metadata))
            .mount(&server)
            .await;
        let current = Arc::new(Mutex::new(Current::Proposal(proposal("draft", 1, 1))));
        let answer = current.clone();
        Mock::given(method("GET"))
            .and(path(GET))
            .respond_with(
                move |_: &wiremock::Request| match answer.lock().unwrap().clone() {
                    Current::Proposal(value) => response(200, value),
                    Current::Problem(code) => problem(code),
                    Current::Forbidden => ResponseTemplate::new(403)
                        .insert_header("traceparent", TRACE)
                        .insert_header("cache-control", "no-store"),
                },
            )
            .mount(&server)
            .await;
        let issuer = support::issuer().await;
        let root = tempfile::tempdir().unwrap();
        let mut config = support::config(root.path(), &issuer, &server.uri(), &server.uri());
        let registry_coordinator::runtime::ConnectionConfig::Breg(connection) =
            config.connections.get_mut("applications").unwrap()
        else {
            panic!("BReg connection")
        };
        connection.base_url = format!("{}/tenant/base/", server.uri()).parse().unwrap();
        connection.profile = "writer".into();
        connection.authorization.scopes = vec!["applications:act".into()];
        let adapters = HttpAdapters::new(&config).unwrap();
        Self {
            server,
            adapters,
            current,
            _root: root,
            issuer,
        }
    }

    fn answer(&self, current: Current) {
        *self.current.lock().unwrap() = current;
    }

    async fn posts(&self, to: &str) -> Vec<wiremock::Request> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method == "POST" && request.url.path() == to)
            .collect()
    }

    async fn run(&self, command: &CallRequest) -> CallOutcome {
        let prepared = self
            .adapters
            .prepare(command)
            .await
            .unwrap_or_else(|_| panic!("valid Proposal preparation"))
            .expect("a Proposal mutation is prepared");
        self.adapters.call_prepared(command, Some(&prepared)).await
    }
}

fn command(operation: Operation, input: Value, key: Option<&str>) -> CallRequest {
    CallRequest {
        connection: "applications".into(),
        operation,
        input,
        idempotency_key: key.map(Into::into),
        operation_contract: Some(ActionContract {
            action_id: "update-item".into(),
            action_revision: FINGERPRINT.into(),
            mode: BRegActionMode::Proposal,
        }),
    }
}

fn start_input() -> Value {
    json!({"input":{"targetId":RECORD, "label":"Original"}})
}

fn receipt(state: &str, version: u32) -> Value {
    json!({"proposalId":ID, "actionId":"update-item", "actionRevision":FINGERPRINT,
        "submissionVersion":version, "state":state})
}

fn success(outcome: CallOutcome) -> Value {
    match outcome {
        CallOutcome::Success(value) => value,
        CallOutcome::Refused { code } => panic!("refused: {code}"),
        CallOutcome::Uncertain { code } => panic!("uncertain: {code}"),
        _ => panic!("expected a Proposal receipt"),
    }
}

#[tokio::test]
async fn start_sends_one_frozen_start_and_replays_it_under_the_same_key() {
    let fixture = Fixture::start().await;
    Mock::given(method("POST"))
        .and(path(START))
        .respond_with(response(200, proposal("draft", 1, 1)))
        .expect(2)
        .mount(&fixture.server)
        .await;
    let start = command(Operation::StartProposal, start_input(), Some(KEY));
    for _ in 0..2 {
        assert_eq!(success(fixture.run(&start).await), receipt("draft", 1));
    }
    let starts = fixture.posts(START).await;
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[0].body, starts[1].body);
    assert!(starts
        .iter()
        .all(|request| request.headers["idempotency-key"] == KEY));
    assert_eq!(
        serde_json::from_slice::<Value>(&starts[0].body).unwrap(),
        start_input()
    );
    fixture.issuer.stop().await;
}

#[tokio::test]
async fn submit_sends_start_then_submit_as_two_frozen_commands_with_stable_keys() {
    let fixture = Fixture::start().await;
    Mock::given(method("POST"))
        .and(path(START))
        .respond_with(response(200, proposal("draft", 1, 1)))
        .expect(2)
        .mount(&fixture.server)
        .await;
    let submit = format!("/tenant/base/v1/proposals/{ID}/submit");
    Mock::given(method("POST"))
        .and(path(submit.as_str()))
        .respond_with(response(200, proposal("submitted", 1, 2)))
        .expect(2)
        .mount(&fixture.server)
        .await;
    let command = command(Operation::SubmitProposal, start_input(), Some(KEY));
    for _ in 0..2 {
        assert_eq!(
            success(fixture.run(&command).await),
            receipt("submitted", 1)
        );
    }
    let starts = fixture.posts(START).await;
    let submits = fixture.posts(&submit).await;
    assert_eq!((starts.len(), submits.len()), (2, 2));
    assert!(starts
        .iter()
        .all(|request| request.headers["idempotency-key"] == KEY));
    let submit_key = format!("{KEY}:submit");
    assert!(submits
        .iter()
        .all(|request| request.headers["idempotency-key"] == submit_key.as_str()));
    assert_eq!(submits[0].body, submits[1].body);
    assert!(submits
        .iter()
        .all(|request| request.headers["if-match"] == "\"proposal-revision-1\""));
    fixture.issuer.stop().await;
}

#[tokio::test]
async fn start_and_submit_refuse_an_immediate_action_pin_before_any_mutation() {
    let fixture = Fixture::start().await;
    for operation in [Operation::StartProposal, Operation::SubmitProposal] {
        let mut command = command(operation, start_input(), Some(KEY));
        command.operation_contract.as_mut().unwrap().mode = BRegActionMode::Immediate;
        assert!(matches!(
            fixture.adapters.prepare(&command).await,
            Err(CallOutcome::Refused { .. })
        ));
    }
    assert!(fixture
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|request| request.method == "GET"));
    fixture.issuer.stop().await;
}

#[tokio::test]
async fn cancel_rebinds_to_the_current_proposal_and_sends_nothing_once_cancelled() {
    let fixture = Fixture::start().await;
    let cancel = format!("/tenant/base/v1/proposals/{ID}/cancel");
    Mock::given(method("POST"))
        .and(path(cancel.as_str()))
        .respond_with(response(200, proposal("cancelled", 1, 3)))
        .expect(1)
        .mount(&fixture.server)
        .await;
    fixture.answer(Current::Proposal(proposal("submitted", 1, 2)));
    let command = command(
        Operation::CancelProposal,
        json!({"proposalId":ID}),
        Some(KEY),
    );
    let prepared = fixture
        .adapters
        .prepare(&command)
        .await
        .unwrap_or_else(|_| panic!("valid cancel preparation"))
        .expect("a cancel is prepared");
    assert!(fixture.posts(&cancel).await.is_empty());
    assert_eq!(
        success(
            fixture
                .adapters
                .call_prepared(&command, Some(&prepared))
                .await
        ),
        receipt("cancelled", 1)
    );
    let sent = fixture.posts(&cancel).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].headers["idempotency-key"], KEY);
    assert_eq!(sent[0].headers["if-match"], "\"proposal-revision-2\"");
    // The retry after an uncertain answer finds the Proposal cancelled.
    fixture.answer(Current::Proposal(proposal("cancelled", 1, 3)));
    assert_eq!(
        success(
            fixture
                .adapters
                .call_prepared(&command, Some(&prepared))
                .await
        ),
        receipt("cancelled", 1)
    );
    assert_eq!(fixture.posts(&cancel).await.len(), 1);
    fixture.issuer.stop().await;
}

#[tokio::test]
async fn read_returns_the_pinned_actions_proposal_and_refuses_another_actions() {
    let fixture = Fixture::start().await;
    let read = command(Operation::ReadProposal, json!({"proposalId":ID}), None);
    fixture.answer(Current::Proposal(proposal("submitted", 1, 2)));
    assert_eq!(
        success(fixture.adapters.call(&read).await),
        receipt("submitted", 1)
    );
    let mut other = proposal("submitted", 1, 2);
    other["actionId"] = json!("another-action");
    fixture.answer(Current::Proposal(other));
    match fixture.adapters.call(&read).await {
        CallOutcome::Refused { code } => assert_eq!(code, "invalid-command"),
        _ => panic!("a Proposal of another Action is not this read's"),
    }
    let mut extra = read.clone();
    extra.input["action"] = json!("another-action");
    match fixture.adapters.call(&extra).await {
        CallOutcome::Refused { code } => assert_eq!(code, "invalid-command"),
        _ => panic!("the read input names only a Proposal"),
    }
    assert!(fixture
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|request| request.method == "GET"));
    fixture.issuer.stop().await;
}

fn describe(read: &CompletionObservation) -> String {
    match read {
        CompletionObservation::Settled(value) => format!("settled {}", value["outcome"]),
        CompletionObservation::Pending { .. } => "pending".into(),
        CompletionObservation::Retryable { code, .. } => format!("retryable {code}"),
        CompletionObservation::Hold { code } => format!("hold {code}"),
        CompletionObservation::Followed { read, .. } => describe(read),
    }
}

fn completion() -> CompletionDefinition {
    CompletionDefinition {
        kind: CompletionKind::BregProposal {},
        output: json!({}),
        revision: format!("sha256:{}", "0".repeat(64)),
    }
}

/// The observation table of the product contract, for each operation that
/// follows a Proposal. The run's own submission is version 1.
#[tokio::test]
async fn each_follow_turns_the_current_proposal_into_the_contract_observation() {
    let fixture = Fixture::start().await;
    let returned_to_party = {
        let mut value = proposal("submitted", 1, 3);
        value["turn"] = json!("party");
        value
    };
    let unassigned = {
        let mut value = proposal("submitted", 1, 3);
        value["turn"] = json!("nobody");
        value
    };
    let refused_handoff = {
        let mut value = proposal("submitted", 1, 3);
        value["handoffRefusal"] = json!({"code":"review.initiator-required"});
        value
    };
    let another_actions = {
        let mut value = proposal("submitted", 1, 3);
        value["actionId"] = json!("another-action");
        value
    };
    let cases: Vec<(&str, Current, [&str; 3])> = vec![
        (
            "applied",
            Current::Proposal(decided(proposal("applied", 1, 4), "approved")),
            ["settled \"applied\""; 3],
        ),
        (
            "rejected",
            Current::Proposal(decided(proposal("rejected", 1, 4), "rejected")),
            ["settled \"rejected\""; 3],
        ),
        (
            "cancelled",
            Current::Proposal(proposal("cancelled", 1, 4)),
            ["settled \"cancelled\""; 3],
        ),
        (
            "official",
            Current::Proposal(proposal("submitted", 1, 3)),
            ["pending"; 3],
        ),
        ("nobody", Current::Proposal(unassigned), ["pending"; 3]),
        (
            "party",
            Current::Proposal(returned_to_party),
            ["pending", "pending", "settled \"returned\""],
        ),
        (
            "draft",
            Current::Proposal(proposal("draft", 1, 3)),
            ["pending", "pending", "settled \"returned\""],
        ),
        (
            "newer submission",
            Current::Proposal(proposal("submitted", 2, 5)),
            ["pending", "pending", "settled \"returned\""],
        ),
        (
            "hand-off refused",
            Current::Proposal(refused_handoff),
            ["pending", "pending", "hold proposal-handoff-refused"],
        ),
        (
            "401",
            Current::Problem(BRegProblemCode::AuthenticationRefused),
            ["hold proposal-unreadable"; 3],
        ),
        ("403", Current::Forbidden, ["hold proposal-unreadable"; 3]),
        (
            "404",
            Current::Problem(BRegProblemCode::ResourceNotFound),
            ["hold proposal-unreadable"; 3],
        ),
        (
            "503",
            Current::Problem(BRegProblemCode::ServiceUnavailable),
            ["retryable transport-unavailable"; 3],
        ),
        (
            "another Action's Proposal",
            Current::Proposal(another_actions),
            ["hold completion-invalid-response"; 3],
        ),
    ];
    let operations = [
        Operation::ReadProposal,
        Operation::StartProposal,
        Operation::SubmitProposal,
    ];
    let accepted = receipt("submitted", 1);
    let mut wrong = vec![];
    for (name, current, expected) in cases {
        fixture.answer(current);
        for (operation, expected) in operations.iter().zip(expected) {
            let request = command(*operation, json!({}), None);
            let read = fixture
                .adapters
                .observe_completion(&request, &accepted, &completion())
                .await;
            let observed = describe(&read);
            if observed != expected {
                wrong.push(format!(
                    "{name} under {}: {observed}, wanted {expected}",
                    operation.as_str()
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "misread: {wrong:#?}");
    assert!(fixture
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|request| request.method == "GET"));
    fixture.issuer.stop().await;
}

#[tokio::test]
async fn a_settled_follow_carries_the_decision_and_the_disclosed_input() {
    let fixture = Fixture::start().await;
    fixture.answer(Current::Proposal(decided(
        proposal("rejected", 1, 4),
        "rejected",
    )));
    let request = command(Operation::SubmitProposal, json!({}), None);
    match fixture
        .adapters
        .observe_completion(&request, &receipt("submitted", 1), &completion())
        .await
    {
        CompletionObservation::Followed { read, .. }
            if matches!(*read, CompletionObservation::Settled(_)) =>
        {
            let CompletionObservation::Settled(value) = *read else {
                unreachable!()
            };
            assert_eq!(
                value,
                json!({"outcome":"rejected", "proposalId":ID, "submissionVersion":1,
                "actionRevision":FINGERPRINT,
                "decision":{"status":"rejected", "decidedAt":"2026-09-19T00:01:00.000001Z",
                    "publicReason":"Synthetic public reason."},
                "input":{"label":"Original"}})
            )
        }
        read => panic!("a rejected Proposal settles, got {}", describe(&read)),
    }
    fixture.issuer.stop().await;
}

/// Every read BReg answers records what the Proposal showed, so the wait can
/// keep it; a read BReg refuses or conceals records nothing.
#[tokio::test]
async fn each_answered_follow_read_records_what_the_proposal_showed() {
    let fixture = Fixture::start().await;
    let refused_handoff = {
        let mut value = proposal("submitted", 1, 3);
        value["handoffRefusal"] = json!({"code":"review.initiator-required"});
        value
    };
    let seen = |state: &str, turn: &str, refusal: Option<&str>| ProposalObservation {
        state: state.into(),
        turn: Some(turn.into()),
        submission_version: 1,
        handoff_refusal: refusal.map(Into::into),
    };
    let cases: Vec<(Current, Operation, Option<ProposalObservation>, &str)> = vec![
        (
            Current::Proposal(proposal("submitted", 1, 3)),
            Operation::ReadProposal,
            Some(seen("submitted", "official", None)),
            "pending",
        ),
        (
            Current::Proposal(refused_handoff.clone()),
            Operation::ReadProposal,
            Some(seen(
                "submitted",
                "official",
                Some("review.initiator-required"),
            )),
            "pending",
        ),
        (
            Current::Proposal(refused_handoff),
            Operation::SubmitProposal,
            Some(seen(
                "submitted",
                "official",
                Some("review.initiator-required"),
            )),
            "hold proposal-handoff-refused",
        ),
        (
            Current::Proposal(proposal("cancelled", 1, 4)),
            Operation::StartProposal,
            Some(seen("cancelled", "nobody", None)),
            "settled \"cancelled\"",
        ),
        (
            Current::Forbidden,
            Operation::ReadProposal,
            None,
            "hold proposal-unreadable",
        ),
    ];
    for (current, operation, expected, meaning) in cases {
        fixture.answer(current);
        let request = command(operation, json!({}), None);
        let read = fixture
            .adapters
            .observe_completion(&request, &receipt("submitted", 1), &completion())
            .await;
        let recorded = match &read {
            CompletionObservation::Followed { proposal, .. } => Some(proposal.clone()),
            _ => None,
        };
        assert_eq!(recorded, expected, "{}", operation.as_str());
        assert_eq!(describe(&read), meaning, "{}", operation.as_str());
    }
    assert_eq!(
        serde_json::to_value(seen("submitted", "official", Some("review.refused"))).unwrap(),
        json!({"state":"submitted", "turn":"official", "submissionVersion":1,
            "handoffRefusal":"review.refused"})
    );
    fixture.issuer.stop().await;
}

#[tokio::test]
async fn proposal_get_uses_the_separate_metadata_budget_and_retains_its_business_body_limit() {
    let mut document = metadata();
    document["additionalDescriptions"] = json!(["m".repeat(40_000), "n".repeat(40_000)]);
    let fixture = Fixture::with_metadata(document).await;
    let read = command(Operation::ReadProposal, json!({"proposalId":ID}), None);
    assert_eq!(
        success(fixture.adapters.call(&read).await),
        receipt("draft", 1)
    );
    let mut oversized = proposal("draft", 1, 1);
    oversized["input"]["label"] = json!("x".repeat(65_536));
    fixture.answer(Current::Proposal(oversized));
    match fixture.adapters.call(&read).await {
        CallOutcome::Refused { code } => assert_eq!(code, "invalid-response"),
        _ => panic!("an oversized Proposal read is terminal and never enlarges its budget"),
    }
    assert!(fixture
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|request| request.method == "GET"));
    fixture.issuer.stop().await;
}
