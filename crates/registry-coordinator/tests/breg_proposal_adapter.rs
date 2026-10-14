// SPDX-License-Identifier: Apache-2.0
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use registry_breg_client::{
    BaseRegistryClient, BaseRegistryClientConfig, BearerToken, TokenError, TokenProvider,
};
use registry_coordinator::{
    breg_proposal::{self, ApplicationObservation, Transition},
    protocol::{CallOutcome, CallRequest, Operation},
};
use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

const PROPOSAL: &str = "00000000-0000-4000-8000-000000000001";
const APPLICATION: &str = "00000000-0000-4000-8000-000000000002";
const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

struct Token;
#[async_trait]
impl TokenProvider for Token {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        BearerToken::new("synthetic-proposal-token")
    }
}

fn client(server: &MockServer) -> BaseRegistryClient {
    BaseRegistryClient::new(
        BaseRegistryClientConfig::new(format!("{}/tenant/base/", server.uri()).parse().unwrap())
            .with_token_provider(Arc::new(Token))
            .with_max_mutation_retries(0),
    )
    .unwrap()
}

fn response(value: Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("traceparent", TRACE)
        .insert_header("cache-control", "no-store")
        .insert_header("vary", "authorization, accept")
        .set_body_json(value)
}

fn proposal(state: &str, revision: u64) -> Value {
    let mut value = json!({
        "id":PROPOSAL, "actionId":"correct-address", "actionRevision":REVISION,
        "submissionVersion":1, "revision":revision, "state":state,
        "links":{"self":{"method":"GET","path":format!("/v1/proposals/{PROPOSAL}"),"accessProfile":"writer","operation":"get"}}
    });
    if state != "draft" {
        value["effectDigest"] = json!(DIGEST);
    }
    for operation in ["submit", "apply", "cancel", "retry"] {
        let available = if operation == "submit" {
            state == "draft"
        } else {
            state == "submitted"
        };
        value["links"][operation] = json!({
            "method":"POST","path":format!("/v1/proposals/{PROPOSAL}/{operation}"),"accessProfile":"writer",
            "operation":operation,"ifMatch":format!("\"proposal-{revision}\""),
            "availability":{"available":available,"observedRevision":revision}
        });
        if !available {
            value["links"][operation]["availability"]["reason"] = json!("stale-revision");
            value["links"][operation]["availability"]["recovery"] = json!("receipt-only");
        }
    }
    if state == "applied" {
        value["application"] = json!({"applicationId":APPLICATION,"submissionVersion":1,"effectDigest":DIGEST,
            "resultLinks":[{"recordType":"facility","recordId":PROPOSAL,"revision":2}]});
    }
    value
}

fn request(input: Value, operation: Operation) -> CallRequest {
    CallRequest {
        connection: "facilities".into(),
        operation,
        input,
        idempotency_key: Some("exact-proposal-command".into()),
        operation_contract: None,
    }
}

async fn authority(server: &MockServer, value: Value) -> Arc<Mutex<Value>> {
    Mock::given(method("GET")).and(path("/tenant/base/v1/registry")).and(query_param("accessProfile", "writer"))
        .respond_with(response(json!({"id":"facilities","version":"1","revision":REVISION,
            "metadataVersion":"1","recordTypes":[],"operations":[],
            "proposals":{"get":{"method":"GET","path":"/v1/proposals/{proposal_id}","accessProfiles":["writer"]}}})))
        .mount(server).await;
    let current = Arc::new(Mutex::new(value));
    let observed = current.clone();
    Mock::given(method("GET"))
        .and(path(format!("/tenant/base/v1/proposals/{PROPOSAL}")))
        .and(query_param("accessProfile", "writer"))
        .respond_with(move |_: &wiremock::Request| response(observed.lock().unwrap().clone()))
        .mount(server)
        .await;
    current
}

fn refused(value: CallOutcome, expected: &str) {
    assert!(matches!(value,CallOutcome::Refused{code} if code == expected));
}

#[tokio::test]
async fn submit_plan_refusal_is_known_without_inventing_a_typed_route() {
    let server = MockServer::start().await;
    authority(&server, proposal("draft", 1)).await;
    Mock::given(method("POST"))
        .and(path(format!("/tenant/base/v1/proposals/{PROPOSAL}/submit")))
        .respond_with(
            ResponseTemplate::new(422)
                .insert_header("traceparent", TRACE)
                .insert_header("cache-control", "no-store")
                .set_body_raw(
                    json!({
                        "type":"https://id.registrystack.org/problems/registry-breg/action/refused",
                        "title":"Unprocessable Entity", "status":422, "code":"action.refused",
                        "traceId":"4bf92f3577b34da6a3ce929d0e0e4736",
                        "detail":"private-plan-value", "refusalCode":"invalid-postal-code"
                    })
                    .to_string(),
                    "application/problem+json",
                ),
        )
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server);
    let command = request(proposal("draft", 1), Operation::SubmitBregProposal);
    let prepared = breg_proposal::prepare(&client, "writer", &command, Transition::Submit)
        .await
        .unwrap_or_else(|_| panic!("prepare"));
    refused(
        breg_proposal::execute(&client, "writer", &command, &prepared, Transition::Submit).await,
        "action-refused",
    );
}

#[tokio::test]
async fn lost_submit_response_replays_original_frozen_command_after_restart() {
    let server = MockServer::start().await;
    let current = authority(&server, proposal("draft", 1)).await;
    let accepted = proposal("submitted", 2);
    let result = accepted.clone();
    let state = current.clone();
    let calls = Arc::new(Mutex::new(0));
    let counter = calls.clone();
    Mock::given(method("POST"))
        .and(path(format!("/tenant/base/v1/proposals/{PROPOSAL}/submit")))
        .respond_with(move |_: &wiremock::Request| {
            *state.lock().unwrap() = result.clone();
            let mut count = counter.lock().unwrap();
            *count += 1;
            if *count == 1 {
                response(json!({"malformed":true}))
            } else {
                response(result.clone())
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let first = client(&server);
    let command = request(proposal("draft", 1), Operation::SubmitBregProposal);
    let prepared = breg_proposal::prepare(&first, "writer", &command, Transition::Submit)
        .await
        .unwrap_or_else(|_| panic!("prepare"));
    assert_eq!(*calls.lock().unwrap(), 0);
    assert!(!String::from_utf8_lossy(&prepared).contains("synthetic-proposal-token"));
    assert!(matches!(
        breg_proposal::execute(&first, "writer", &command, &prepared, Transition::Submit).await,
        CallOutcome::Uncertain { .. }
    ));
    drop(first);
    match breg_proposal::execute(
        &client(&server),
        "writer",
        &command,
        &prepared,
        Transition::Submit,
    )
    .await
    {
        CallOutcome::Success(value) => assert_eq!(value, accepted),
        _ => panic!("exact submit recovery"),
    }
    let requests = server.received_requests().await.unwrap();
    let mutations = requests
        .iter()
        .filter(|request| request.method == "POST")
        .collect::<Vec<_>>();
    assert_eq!(mutations.len(), 2);
    assert_eq!(mutations[0].body, mutations[1].body);
    assert_eq!(
        mutations[0].headers["if-match"],
        mutations[1].headers["if-match"]
    );
    assert_eq!(
        mutations[0].headers["idempotency-key"],
        mutations[1].headers["idempotency-key"]
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&mutations[0].body).unwrap(),
        json!({})
    );
}

#[tokio::test]
async fn saved_transition_rejects_replaced_key_operation_input_and_submission() {
    let server = MockServer::start().await;
    let current = authority(&server, proposal("draft", 1)).await;
    let client = client(&server);
    let command = request(proposal("draft", 1), Operation::SubmitBregProposal);
    let prepared = breg_proposal::prepare(&client, "writer", &command, Transition::Submit)
        .await
        .unwrap_or_else(|_| panic!("prepare"));
    let mut replaced = command.clone();
    replaced.idempotency_key = Some("replacement-key".into());
    refused(
        breg_proposal::execute(&client, "writer", &replaced, &prepared, Transition::Submit).await,
        "prepared-command-mismatch",
    );
    refused(
        breg_proposal::execute(&client, "writer", &command, &prepared, Transition::Cancel).await,
        "prepared-command-mismatch",
    );
    let mut replaced = command.clone();
    replaced.input["revision"] = json!(7);
    refused(
        breg_proposal::execute(&client, "writer", &replaced, &prepared, Transition::Submit).await,
        "prepared-command-mismatch",
    );
    current.lock().unwrap()["submissionVersion"] = json!(2);
    refused(
        breg_proposal::execute(&client, "writer", &command, &prepared, Transition::Submit).await,
        "submission-stale",
    );
    assert!(server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|request| request.method == "GET"));
}

#[tokio::test]
async fn only_exact_applied_evidence_completes_application_observation() {
    let server = MockServer::start().await;
    let current = authority(&server, proposal("submitted", 2)).await;
    let client = client(&server);
    let accepted = proposal("submitted", 2);
    assert!(matches!(
        breg_proposal::observe_application(&client, "writer", &accepted).await,
        ApplicationObservation::Pending { .. }
    ));
    *current.lock().unwrap() = proposal("applied", 3);
    match breg_proposal::observe_application(&client, "writer", &accepted).await {
        ApplicationObservation::Complete(value) => {
            assert_eq!(value["outcome"], "applied");
            assert_eq!(
                value["proposal"]["application"]["applicationId"],
                APPLICATION
            );
        }
        _ => panic!("exact durable application"),
    }
    current
        .lock()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("application");
    assert!(matches!(
        breg_proposal::observe_application(&client, "writer", &accepted).await,
        ApplicationObservation::Hold { .. }
    ));
    *current.lock().unwrap() = proposal("submitted", 3);
    current.lock().unwrap()["submissionVersion"] = json!(2);
    assert!(
        matches!(breg_proposal::observe_application(&client,"writer",&accepted).await,ApplicationObservation::Hold{code} if code=="submission-stale")
    );
    *current.lock().unwrap() = proposal("submitted", 3);
    current.lock().unwrap()["blockedReason"] = json!("package-changed");
    assert!(
        matches!(breg_proposal::observe_application(&client,"writer",&accepted).await,ApplicationObservation::Hold{code} if code=="proposal-blocked")
    );
    *current.lock().unwrap() = proposal("submitted", 3);
    current.lock().unwrap()["applicationStatus"] = json!({"state":"blocked","mode":"automatic","reason":"dependency-outage","recovery":"retry","automaticRetry":{"scheduled":false,"attempts":1,"maximumAttempts":3}});
    assert!(
        matches!(breg_proposal::observe_application(&client, "writer", &accepted).await, ApplicationObservation::Hold { code } if code == "proposal-dependency-outage")
    );
    current.lock().unwrap()["applicationStatus"]["automaticRetry"]["scheduled"] = json!(true);
    assert!(matches!(
        breg_proposal::observe_application(&client, "writer", &accepted).await,
        ApplicationObservation::Hold { .. }
    ));
    assert!(
        matches!(breg_proposal::observe_application(&client,"writer",&proposal("draft",1)).await,ApplicationObservation::Hold{code} if code=="submission-missing")
    );
    assert!(server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|request| request.method == "GET"));
}

#[tokio::test]
async fn manual_apply_retains_exact_binding_and_current_promoted_grant() {
    let server = MockServer::start().await;
    let current = authority(&server, proposal("submitted", 2)).await;
    Mock::given(method("POST"))
        .and(path(format!("/tenant/base/v1/proposals/{PROPOSAL}/apply")))
        .respond_with(response(proposal("applied", 3)))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server);
    let command = request(proposal("submitted", 2), Operation::ApplyBregProposal);
    let prepared = breg_proposal::prepare(&client, "writer", &command, Transition::Apply)
        .await
        .unwrap_or_else(|_| panic!("prepare"));
    assert!(matches!(
        breg_proposal::execute(&client, "writer", &command, &prepared, Transition::Apply).await,
        CallOutcome::Success(_)
    ));
    let requests = server.received_requests().await.unwrap();
    let mutation = requests
        .iter()
        .find(|request| request.method == "POST")
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&mutation.body).unwrap(),
        json!({"submissionVersion":1,"effectDigest":DIGEST})
    );
    current.lock().unwrap()["links"]
        .as_object_mut()
        .unwrap()
        .remove("apply");
    refused(
        breg_proposal::execute(&client, "writer", &command, &prepared, Transition::Apply).await,
        "prepared-command-mismatch",
    );
}

#[tokio::test]
async fn cancellation_is_terminal_only_for_the_original_frozen_submission() {
    let server = MockServer::start().await;
    authority(&server, proposal("cancelled", 3)).await;
    let accepted = proposal("submitted", 2);
    match breg_proposal::observe_application(&client(&server), "writer", &accepted).await {
        ApplicationObservation::Complete(value) => assert_eq!(value["outcome"], "closed"),
        _ => panic!("exact cancellation is authoritative"),
    }
}

#[tokio::test]
async fn pending_observation_preserves_receiver_delay_and_never_echoes_unusable_headers() {
    let server = MockServer::start().await;
    let accepted = proposal("submitted", 2);
    authority(&server, accepted.clone()).await;
    let hint = Arc::new(Mutex::new("17".to_owned()));
    let current = hint.clone();
    let pending = accepted.clone();
    Mock::given(method("GET"))
        .and(path(format!("/tenant/base/v1/proposals/{PROPOSAL}")))
        .respond_with(move |_: &wiremock::Request| {
            response(pending.clone()).insert_header("retry-after", current.lock().unwrap().as_str())
        })
        .with_priority(1)
        .mount(&server)
        .await;
    let client = client(&server);
    match breg_proposal::observe_application(&client, "writer", &accepted).await {
        ApplicationObservation::Pending { retry_after } => {
            assert_eq!(retry_after, Some(std::time::Duration::from_secs(17)))
        }
        _ => panic!("receiver-requested delay on pending submission"),
    }
    *hint.lock().unwrap() = "private-header-canary".to_owned();
    assert!(
        matches!(breg_proposal::observe_application(&client, "writer", &accepted).await,
        ApplicationObservation::Hold { code } if code == "observation-backoff-unusable")
    );
}
