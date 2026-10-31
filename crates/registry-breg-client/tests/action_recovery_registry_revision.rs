// SPDX-License-Identifier: Apache-2.0

//! A prepared action is bound to the Registry revision it was prepared under.
//! A registry that serves a different revision with an unchanged action
//! revision still refuses the saved command, so a stale command is never
//! replayed against changed registry configuration.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use registry_breg_client::{
    BRegActionInvocationRequest, BRegIdempotencyKey, BaseRegistryClient, BaseRegistryClientConfig,
    BaseRegistryClientError,
};
use registry_platform_httputil::client::{BearerToken, TokenError, TokenProvider};
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use url::Url;

const REVISION_A: &str = "sha256:00000000000000000000000000000000000000000000000000000000000000aa";
const REVISION_B: &str = "sha256:00000000000000000000000000000000000000000000000000000000000000ab";
const ACTION_REVISION: &str =
    "sha256:00000000000000000000000000000000000000000000000000000000000000bb";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

fn action_metadata(registry_revision: &str) -> Value {
    json!({
        "id": "fixture-registry", "version": "1", "revision": registry_revision,
        "metadataVersion": "2", "recordTypes": [], "operations": [],
        "actions": [{
            "id": "incorporate-company", "apiName": "incorporateCompany",
            "revision": ACTION_REVISION,
            "display": {}, "execution": {"mode": "immediate"},
            "route": "/v1/actions/incorporate-company", "conditionRoute": null,
            "inputMode": "fixed", "maximumInputStringBytes": null,
            "inputs": [{"id": "reference", "apiName": "reference", "required": true,
                "nullable": false, "classification": "internal",
                "schema": {"type": "string", "minLength": 1, "maxLength": 40},
                "fieldType": {"type": "string", "minimumLength": 1, "maximumLength": 40}}],
            "referenceInputs": [], "requiredConditionKeys": [],
            "resultEffects": [
                {"effect": "record-incorporation", "recordType": "incorporation", "operation": "create"}],
            "access": {"selectedProfile": "preparer"},
            "routes": {
                "invoke": {"method": "POST", "path": "/v1/actions/incorporate-company",
                    "operationId": "actions.incorporate-company.invoke", "requiresIdempotencyKey": true,
                    "inputSchema": "action-incorporate-company-invoke-input",
                    "responseSchema": "action-incorporate-company-invoke-response"},
                "targetConditions": null},
            "bounds": {"maximumTargets": 4, "maximumFieldMutations": 8, "maximumSnapshotBytes": 1024}
        }]
    })
}

#[derive(Debug)]
struct StaticToken(AtomicUsize);

#[async_trait]
impl TokenProvider for StaticToken {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BearerToken::new("recovery-test-token")
    }
}

#[derive(Clone)]
struct MockState {
    responses: Arc<Mutex<VecDeque<Value>>>,
    served: Arc<AtomicUsize>,
}

async fn handler(State(state): State<MockState>, _request: Request<Body>) -> Response<Body> {
    state.served.fetch_add(1, Ordering::SeqCst);
    let body = state
        .responses
        .lock()
        .expect("response queue lock")
        .pop_front()
        .expect("a queued metadata response");
    let mut response = Response::new(Body::from(serde_json::to_vec(&body).expect("body")));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert("content-type", "application/json".parse().expect("header"));
    response
        .headers_mut()
        .insert("traceparent", TRACEPARENT.parse().expect("header"));
    response
}

#[tokio::test]
async fn caller_metadata_vocabulary_codes_prepare_and_recover_exactly() {
    let mut metadata = action_metadata(REVISION_A);
    metadata["actions"][0]["inputs"][0]["fieldType"] = json!({
        "type": "vocabulary-code", "vocabulary": "report-type",
        "values": ["A-report", "B-report", "C-report"]
    });
    metadata["actions"][0]["inputs"][0]["schema"] = json!({
        "type": "string", "enum": ["A-report", "B-report", "C-report"]
    });
    let served = Arc::new(AtomicUsize::new(0));
    let state = MockState {
        responses: Arc::new(Mutex::new(VecDeque::from([metadata]))),
        served: served.clone(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(handler)).with_state(state),
        )
        .await
        .unwrap();
    });
    let tokens = Arc::new(StaticToken(AtomicUsize::new(0)));
    let client = BaseRegistryClient::new(
        BaseRegistryClientConfig::new(
            Url::parse(&format!("http://{address}/tenant/base")).unwrap(),
        )
        .with_token_provider(tokens.clone()),
    )
    .unwrap();
    let metadata = client
        .registry_contract(Some("preparer"))
        .await
        .unwrap()
        .value;
    assert!(metadata
        .select_action("incorporate-company", "other-profile")
        .is_err());
    let action = metadata
        .select_action("incorporate-company", "preparer")
        .unwrap();
    let key = BRegIdempotencyKey::parse("report-1").unwrap();
    for code in ["A-report", "B-report", "C-report"] {
        let inputs = Map::from_iter([("reference".to_owned(), json!(code))]);
        let request = BRegActionInvocationRequest::new(&action, inputs.clone(), None).unwrap();
        let prepared = client.prepare_action(&action, &request, &key).unwrap();
        let saved: Value = serde_json::from_slice(prepared.as_bytes()).unwrap();
        let body: Value = serde_json::from_str(saved["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["input"]["reference"], code);
        let recovered = client
            .recover_action(&action, &prepared, &inputs, &key)
            .unwrap();
        assert_eq!(
            client
                .prepare_action(&action, &recovered, &key)
                .unwrap()
                .as_bytes(),
            prepared.as_bytes()
        );
    }
    assert!(BRegActionInvocationRequest::new(
        &action,
        Map::from_iter([("reference".to_owned(), json!("a-report"))]),
        None,
    )
    .is_err());
    assert_eq!(served.load(Ordering::SeqCst), 1);
    assert_eq!(tokens.0.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn saved_command_refuses_after_registry_revision_change() {
    let served = Arc::new(AtomicUsize::new(0));
    let state = MockState {
        responses: Arc::new(Mutex::new(VecDeque::from([
            action_metadata(REVISION_A),
            action_metadata(REVISION_B),
        ]))),
        served: served.clone(),
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock registry");
    let address = listener.local_addr().expect("mock address");
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(handler)).with_state(state),
        )
        .await
        .expect("serve mock registry");
    });
    let config = BaseRegistryClientConfig::new(
        Url::parse(&format!("http://{address}/tenant/base")).expect("base URL"),
    )
    .with_token_provider(Arc::new(StaticToken(AtomicUsize::new(0))));
    let client = BaseRegistryClient::new(config).expect("client");

    let under_a = client
        .registry_contract(Some("preparer"))
        .await
        .expect("metadata under revision A")
        .value;
    let under_b = client
        .registry_contract(Some("preparer"))
        .await
        .expect("metadata under revision B")
        .value;
    assert_eq!(under_a.registry_revision(), REVISION_A);
    assert_eq!(under_b.registry_revision(), REVISION_B);
    let action_a = under_a
        .select_action("incorporate-company", "preparer")
        .expect("action under A");
    let action_b = under_b
        .select_action("incorporate-company", "preparer")
        .expect("action under B");
    assert_eq!(
        action_a.definition_revision(),
        action_b.definition_revision(),
        "only the Registry revision differs"
    );

    let inputs: Map<String, Value> =
        Map::from_iter([("reference".to_owned(), json!("APP-2026-0042"))]);
    let key = BRegIdempotencyKey::parse("incorporate-1").expect("key");
    let request =
        BRegActionInvocationRequest::new(&action_a, inputs.clone(), None).expect("request");
    let prepared = client
        .prepare_action(&action_a, &request, &key)
        .expect("prepared under A");
    let saved = prepared.as_bytes().to_vec();

    // Control: the same Registry revision recovers the identical command.
    let recovered = client
        .recover_action(&action_a, &prepared, &inputs, &key)
        .expect("recovery under the revision it was prepared under");
    assert_eq!(recovered.body_len(), request.body_len());

    let refusal = client
        .recover_action(&action_b, &prepared, &inputs, &key)
        .expect_err("a changed Registry revision refuses the saved command");
    assert!(
        matches!(refusal, BaseRegistryClientError::InvalidRequest { .. }),
        "{refusal}"
    );
    assert_eq!(
        prepared.as_bytes(),
        saved.as_slice(),
        "the saved command is unchanged"
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        2,
        "prepare and recover perform no exchange"
    );
}
