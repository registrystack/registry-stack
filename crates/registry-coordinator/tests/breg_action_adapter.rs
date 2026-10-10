// SPDX-License-Identifier: Apache-2.0
mod support;

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use async_trait::async_trait;
use registry_breg_client::{
    BRegProblemCode, BaseRegistryClient, BaseRegistryClientConfig, BearerToken, TokenError,
    TokenProvider,
};
use registry_coordinator::{
    adapters::HttpAdapters,
    breg_action::{execute, prepare},
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation, ReconciliationOutcome},
};
use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

const RECORD: &str = "00000000-0000-4000-8000-000000000001";
const APPLICATION: &str = "00000000-0000-4000-8000-000000000002";
const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FINGERPRINT: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const CONDITION: &str = "\"original-condition-canary\"";

#[derive(Default)]
struct CountingToken(AtomicUsize);

#[async_trait]
impl TokenProvider for CountingToken {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BearerToken::new("synthetic-action-token")
    }
}

fn client(server: &MockServer, token: Arc<CountingToken>) -> BaseRegistryClient {
    BaseRegistryClient::new(
        BaseRegistryClientConfig::new(format!("{}/tenant/base/", server.uri()).parse().unwrap())
            .with_token_provider(token)
            .with_max_mutation_retries(0),
    )
    .unwrap()
}

fn request() -> CallRequest {
    CallRequest {
        connection: "applications".into(),
        operation: Operation::InvokeBregAction,
        input: json!({"action":"update-item", "input":{"targetId": RECORD, "label":"Original"}}),
        idempotency_key: Some("durable-action-key".into()),
    }
}

fn metadata() -> Value {
    json!({
        "id":"fixture-registry", "version":"1", "revision":REVISION,
        "metadataVersion":"1", "entities":[], "operations":[],
        "actions":[{
            "id":"update-item", "route":"/v1/actions/update-item",
            "conditionRoute":"/v1/actions/update-item/target-conditions",
            "contractFingerprint":FINGERPRINT,
            "inputMode":"fixed", "maximumInputStringBytes":null,
            "inputs":[
                {"id":"target", "apiName":"targetId", "required":true,
                 "nullable":false, "classification":"internal",
                 "fieldType":{"type":"reference", "target":"item", "onDelete":"restrict"}},
                {"id":"label", "apiName":"label", "required":true,
                 "nullable":false, "classification":"internal",
                 "fieldType":{"type":"string", "minimumLength":1, "maximumLength":16}}
            ],
            "referenceInputs":[{"input":"target", "apiName":"targetId", "targetEntity":"item"}],
            "requiredConditionKeys":["targetId"],
            "resultEffects":[{"effect":"item", "entity":"item", "operation":"patch"}],
            "access":{"selectedProfile":"writer"},
            "routes":{
                "invoke":{"method":"POST", "path":"/v1/actions/update-item",
                    "operationId":"actions.update-item.invoke", "requiresIdempotencyKey":true,
                    "inputSchema":"action-update-item-invoke-input",
                    "responseSchema":"action-update-item-invoke-response"},
                "targetConditions":{"method":"POST", "path":"/v1/actions/update-item/target-conditions",
                    "operationId":"actions.update-item.target-conditions", "requiresIdempotencyKey":false,
                    "inputSchema":"action-update-item-target-conditions-input",
                    "responseSchema":"action-update-item-target-conditions-response"}
            },
            "bounds":{"maximumTargets":16, "maximumFieldMutations":128, "maximumSnapshotBytes":2097152}
        }]
    })
}

fn receipt() -> Value {
    json!({"action":"update-item", "applicationId":APPLICATION,
        "results":{"item":{"entity":"item", "recordId":RECORD, "revision":2}}})
}

fn response(value: Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("traceparent", TRACE)
        .insert_header("cache-control", "no-store")
        .insert_header("vary", "authorization, accept")
        .set_body_json(value)
}

async fn authority(server: &MockServer) -> Arc<Mutex<Value>> {
    let metadata = Arc::new(Mutex::new(metadata()));
    let current = metadata.clone();
    Mock::given(method("GET"))
        .and(path("/tenant/base/v1/registry"))
        .and(query_param("accessProfile", "writer"))
        .respond_with(move |_: &wiremock::Request| response(current.lock().unwrap().clone()))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/tenant/base/v1/actions/update-item/target-conditions",
        ))
        .and(query_param("accessProfile", "writer"))
        .respond_with(response(
            json!({"preconditions":{"targetId":{"ifMatch":CONDITION}}}),
        ))
        .expect(1)
        .mount(server)
        .await;
    metadata
}

fn refusal(outcome: CallOutcome, expected: &str) {
    match outcome {
        CallOutcome::Refused { code } => assert_eq!(code, expected),
        _ => panic!("expected a bounded refusal"),
    }
}

#[tokio::test]
async fn prepared_action_survives_client_restart_without_refreshing_conditions_or_retrying_inside_attempt(
) {
    let server = MockServer::start().await;
    authority(&server).await;
    let mutations = Arc::new(AtomicUsize::new(0));
    let count = mutations.clone();
    Mock::given(method("POST"))
        .and(path("/tenant/base/v1/actions/update-item"))
        .and(query_param("accessProfile", "writer"))
        .respond_with(move |_: &wiremock::Request| {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                // Acceptance could precede this corrupted reply. It must stay
                // uncertain and await an explicit durable retry.
                response(json!({"private-response-canary":true}))
            } else {
                response(receipt())
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let tokens = Arc::new(CountingToken::default());
    let first = client(&server, tokens.clone());
    let command = request();
    let prepared = prepare(&first, "writer", &command)
        .await
        .unwrap_or_else(|_| panic!("valid action preparation"));
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
    let saved: Value = serde_json::from_slice(&prepared).unwrap();
    assert_eq!(saved["idempotency_key"], "durable-action-key");
    assert!(!String::from_utf8_lossy(&prepared).contains("synthetic-action-token"));
    match execute(&first, "writer", &command, &prepared).await {
        CallOutcome::Uncertain { code } => assert_eq!(code, "transport-uncertain"),
        _ => panic!("malformed success must preserve uncertainty"),
    }
    assert_eq!(mutations.load(Ordering::SeqCst), 1);
    drop(first);
    let restarted = client(&server, tokens);
    match execute(&restarted, "writer", &command, &prepared).await {
        CallOutcome::Success(value) => assert_eq!(value, receipt()),
        _ => panic!("same original command must recover its receipt"),
    }
    let requests = server.received_requests().await.unwrap();
    let actions: Vec<_> = requests
        .iter()
        .filter(|request| request.url.path() == "/tenant/base/v1/actions/update-item")
        .collect();
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0].body, actions[1].body);
    assert_eq!(
        actions[0].headers["idempotency-key"],
        actions[1].headers["idempotency-key"]
    );
    assert_eq!(actions[0].headers["idempotency-key"], "durable-action-key");
    assert_eq!(
        serde_json::from_slice::<Value>(&actions[0].body).unwrap(),
        json!({"input":{"targetId":RECORD, "label":"Original"},
            "preconditions":{"targetId":{"ifMatch":CONDITION}}})
    );
    let conditions: Vec<_> = requests
        .iter()
        .filter(|request| request.url.path().ends_with("/target-conditions"))
        .collect();
    assert_eq!(conditions.len(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&conditions[0].body).unwrap(),
        json!({"input":{"targetId":RECORD}})
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        3
    );
}

#[tokio::test]
async fn changed_command_metadata_and_profile_never_send_a_mutation() {
    let server = MockServer::start().await;
    let current = authority(&server).await;
    let client = client(&server, Arc::new(CountingToken::default()));
    let original = request();
    let prepared = prepare(&client, "writer", &original)
        .await
        .unwrap_or_else(|_| panic!("valid preparation"));
    for changed in [
        json!({"action":"update-item", "input":{"targetId":RECORD, "label":"Changed"}}),
        json!({"action":"update-item", "input":{"targetId":APPLICATION, "label":"Original"}}),
    ] {
        let mut command = request();
        command.input = changed;
        refusal(
            execute(&client, "writer", &command, &prepared).await,
            "prepared-command-mismatch",
        );
    }
    let mut command = request();
    command.idempotency_key = Some("different-key".into());
    refusal(
        execute(&client, "writer", &command, &prepared).await,
        "prepared-command-mismatch",
    );
    for pointer in ["/revision", "/actions/0/contractFingerprint"] {
        let mut changed = metadata();
        *changed.pointer_mut(pointer).unwrap() =
            json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        *current.lock().unwrap() = changed;
        refusal(
            execute(&client, "writer", &original, &prepared).await,
            "prepared-command-mismatch",
        );
    }
    let mut changed = metadata();
    changed["actions"][0]["access"]["selectedProfile"] = json!("another-profile");
    *current.lock().unwrap() = changed;
    refusal(
        execute(&client, "writer", &original, &prepared).await,
        "action-unavailable",
    );
    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().all(
        |request| request.method == "GET" || request.url.path().ends_with("/target-conditions")
    ));
}

#[tokio::test]
async fn invalid_command_and_capsule_refuse_before_credentials_or_io() {
    let server = MockServer::start().await;
    let token = Arc::new(CountingToken::default());
    let client = client(&server, token.clone());
    let mut cases = Vec::new();
    let mut command = request();
    command.input["grant"] = json!({"id":APPLICATION, "expiresAt":1});
    cases.push(command);
    let mut command = request();
    command.idempotency_key = None;
    cases.push(command);
    let mut command = request();
    command.operation = Operation::ReadRecord;
    cases.push(command);
    for command in cases {
        match prepare(&client, "writer", &command).await {
            Err(outcome) => refusal(outcome, "invalid-command"),
            Ok(_) => panic!("invalid preparation must refuse"),
        }
    }
    refusal(
        execute(&client, "writer", &request(), b"invalid-capsule").await,
        "invalid-command",
    );
    assert_eq!(token.0.load(Ordering::SeqCst), 0);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn invalid_action_inputs_refuse_before_fetching_conditions() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/tenant/base/v1/registry"))
        .respond_with(response(metadata()))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server, Arc::new(CountingToken::default()));
    let mut command = request();
    command.input["input"]["label"] = json!("Too long for declared action input");
    match prepare(&client, "writer", &command).await {
        Err(outcome) => refusal(outcome, "invalid-command"),
        Ok(_) => panic!("invalid action inputs must refuse"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn expired_receipt_and_known_rollbacks_remain_distinct_from_unknown_effects() {
    for code in [
        BRegProblemCode::IdempotencyExpired,
        BRegProblemCode::ActionHandlerFailed,
        BRegProblemCode::PreconditionFailed,
    ] {
        let server = MockServer::start().await;
        authority(&server).await;
        let title = match code {
            BRegProblemCode::IdempotencyExpired => "Gone",
            BRegProblemCode::ActionHandlerFailed => "Internal Server Error",
            BRegProblemCode::PreconditionFailed => "Precondition Failed",
            _ => unreachable!(),
        };
        Mock::given(method("POST"))
            .and(path("/tenant/base/v1/actions/update-item"))
            .respond_with(
                ResponseTemplate::new(code.status())
                    .insert_header("traceparent", TRACE)
                    .insert_header("cache-control", "no-store")
                    .set_body_raw(
                        json!({"type":format!("https://id.registrystack.org/problems/registry-breg/{}",
                            code.code().replace('.', "/")),
                            "title":title, "status":code.status(), "code":code.code(),
                            "detail":code.detail(), "traceId":"4bf92f3577b34da6a3ce929d0e0e4736"})
                            .to_string(),
                        "application/problem+json",
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = client(&server, Arc::new(CountingToken::default()));
        let command = request();
        let prepared = prepare(&client, "writer", &command)
            .await
            .unwrap_or_else(|_| panic!("valid preparation"));
        let result = execute(&client, "writer", &command, &prepared).await;
        if code == BRegProblemCode::IdempotencyExpired {
            assert!(matches!(result, CallOutcome::ReceiptExpired));
        } else {
            refusal(result, "product-refused");
        }
    }
}

#[tokio::test]
async fn configured_adapter_requires_preparation_and_never_reconciles_by_sending_a_mutation() {
    let server = MockServer::start().await;
    authority(&server).await;
    Mock::given(method("POST"))
        .and(path("/tenant/base/v1/actions/update-item"))
        .respond_with(response(receipt()))
        .expect(1)
        .mount(&server)
        .await;
    let issuer = support::issuer().await;
    let root = tempfile::tempdir().unwrap();
    let mut config = support::config(root.path(), &issuer, &server.uri(), &server.uri());
    let connection = config.connections.get_mut("applications").unwrap();
    connection.base_url = format!("{}/tenant/base/", server.uri()).parse().unwrap();
    connection.profile = Some("writer".into());
    connection.authorization.scopes = vec!["applications:act".into()];
    let adapters = HttpAdapters::new(&config).unwrap();
    let command = request();
    assert!(matches!(
        adapters.call(&command).await,
        CallOutcome::Refused { .. }
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
    let prepared = adapters
        .prepare(&command)
        .await
        .unwrap_or_else(|_| panic!("configured action preparation"))
        .expect("BReg action evidence is required");
    match adapters.call_prepared(&command, Some(&prepared)).await {
        CallOutcome::Success(value) => assert_eq!(value, receipt()),
        _ => panic!("prepared action must reach its canonical client"),
    }
    let count = server.received_requests().await.unwrap().len();
    assert!(matches!(
        adapters.reconcile(&command, Some(&receipt())).await,
        ReconciliationOutcome::Unresolved { .. }
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), count);
    issuer.stop().await;
}
