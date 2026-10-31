// SPDX-License-Identifier: Apache-2.0
use axum::{
    extract::State,
    http::{header::HeaderValue, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use registry_mcp::adapter::{
    contract_digest, AdapterContract, AdapterProvider, AdapterToolBinding, CONTRACT_PATH,
};
use registry_mcp_edge::{
    AuthorizationFactory, FixedAuthorizationFactory, Invocation, Provider, ProviderOutcome,
    VerifiedCaller,
};
use registry_platform_httputil::client::StaticToken;
use serde_json::{json, Map, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use url::Url;

const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

fn document(success_status: u16) -> Value {
    let empty = json!({"type":"object","additionalProperties":false,"properties":{}});
    let protocol_problem = |code: &str, status: u16, title: &str| {
        json!({
            "type":"object",
            "properties":{
                "code":{"const":code},
                "status":{"const":status},
                "title":{"const":title},
                "requestId":{"type":"string","minLength":32,"maxLength":32,"pattern":"^[0-9a-f]{32}$"}
            },
            "required":["code","status","title","requestId"],
            "additionalProperties":false
        })
    };
    let contract = json!({
        "schemaDialect":SCHEMA_DIALECT,
        "project":{"id":"fixture","version":"1"},
        "profileVersion":"1",
        "artifactDeploymentDigest":format!("sha256:{}", "a".repeat(64)),
        "authentication":{"scheme":"bearer","audience":"https://adapter.example.invalid/","clientAdmission":"allowlist"},
        "authority":{
            "callerMode":"trusted-machine",
            "representedSubject":"unsupported",
            "personalDelegation":"unsupported",
            "targetBinding":"unsupported",
            "rowDisclosureAuthority":"not-granted",
            "fieldDisclosureAuthority":"not-granted"
        },
        "operations":[{
            "id":"records.list","version":"1","bindingId":"read","profileOperationId":"list",
            "method":"GET","path":"/records","support":"served","effect":"read",
            "successStatus":success_status,
            "input":{"path":empty.clone(),"query":empty.clone()},"output":empty,
            "access":{"anyOf":[{"allScopes":["read"]}]}
        }],
        "unserved":[],
        "problemSchema":{
            "type":"object",
            "additionalProperties":false,
            "properties":{
                "code":{"type":"string"},
                "detail":{"type":"string"},
                "status":{"type":"integer"},
                "title":{"type":"string"}
            },
            "required":["code","status","title"]
        },
        "protocolProblems":{
            "schema":{"$schema":SCHEMA_DIALECT,"oneOf":[
                protocol_problem("adapter.contract.precondition-failed",412,"Effective contract precondition failed"),
                protocol_problem("adapter.contract.unavailable",503,"Effective contract unavailable")
            ]},
            "problems":[
                {"code":"adapter.contract.precondition-failed","status":412,"title":"Effective contract precondition failed"},
                {"code":"adapter.contract.unavailable","status":503,"title":"Effective contract unavailable"}
            ]
        }
    });
    json!({
        "apiVersion":"id.registrystack.org/formats/adapter/effective-contract/v1alpha1",
        "kind":"AdapterEffectiveContract",
        "digest":contract_digest(&contract).unwrap(),
        "contract":contract
    })
}

#[derive(Clone)]
struct AdapterState {
    runtime_contract: Value,
    runtime_contract_fetches: Arc<AtomicUsize>,
    operation_status: StatusCode,
    operation_body: Value,
    request_id: Option<String>,
    operation_headers: Arc<Mutex<Vec<HeaderMap>>>,
}

async fn runtime_contract(State(state): State<AdapterState>) -> Json<Value> {
    state
        .runtime_contract_fetches
        .fetch_add(1, Ordering::SeqCst);
    let mut document = state.runtime_contract;
    document["readiness"] = json!({"ready":true,"configuration":"ready","journal":"ready"});
    Json(document)
}

async fn operation(State(state): State<AdapterState>, headers: HeaderMap) -> Response {
    state.operation_headers.lock().unwrap().push(headers);
    let status = state.operation_status;
    let mut response = (status, Json(state.operation_body)).into_response();
    if !status.is_success() {
        response.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("application/problem+json"),
        );
    }
    if let Some(request_id) = state.request_id {
        response.headers_mut().insert(
            "x-registry-request-id",
            HeaderValue::from_str(&request_id).unwrap(),
        );
    }
    response
}

async fn invoke(
    success_status: u16,
    actual_status: StatusCode,
    operation_body: Value,
    request_id: Option<&str>,
) -> (ProviderOutcome, Vec<HeaderMap>, usize, String) {
    invoke_with_options(
        success_status,
        actual_status,
        operation_body,
        request_id,
        4096,
        Map::from_iter([
            ("path".to_owned(), json!({})),
            ("query".to_owned(), json!({})),
        ]),
    )
    .await
}

async fn invoke_with_options(
    success_status: u16,
    actual_status: StatusCode,
    operation_body: Value,
    request_id: Option<&str>,
    maximum_response_bytes: u64,
    arguments: Map<String, Value>,
) -> (ProviderOutcome, Vec<HeaderMap>, usize, String) {
    let document = document(success_status);
    let contract = AdapterContract::parse(
        &serde_json::to_vec(&document).unwrap(),
        document["digest"].as_str().unwrap(),
    )
    .unwrap();
    let operation_headers = Arc::new(Mutex::new(Vec::new()));
    let runtime_contract_fetches = Arc::new(AtomicUsize::new(0));
    let state = AdapterState {
        runtime_contract: document,
        runtime_contract_fetches: Arc::clone(&runtime_contract_fetches),
        operation_status: actual_status,
        operation_body,
        request_id: request_id.map(str::to_owned),
        operation_headers: Arc::clone(&operation_headers),
    };
    let app = Router::new()
        .route(&format!("/{CONTRACT_PATH}"), get(runtime_contract))
        .route("/records", get(operation))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut bindings = std::collections::BTreeMap::new();
    bindings.insert(
        "read_records".to_owned(),
        AdapterToolBinding {
            operation: "records.list".to_owned(),
            description: "List configured records.".to_owned(),
        },
    );
    let provider = AdapterProvider::new(
        Url::parse(&format!("http://{address}/")).unwrap(),
        contract,
        bindings,
        "https://adapter.example.invalid/",
        maximum_response_bytes,
    )
    .unwrap();
    let caller = VerifiedCaller::for_test(
        "https://issuer.example.invalid/",
        "machine",
        "gateway",
        "inbound-token",
        i64::MAX,
        "principal",
        "client",
    );
    let factory = FixedAuthorizationFactory::new(Arc::new(
        StaticToken::new("adapter-machine-token").unwrap(),
    ));
    let authorization = factory.authorization(&caller).unwrap();
    let tools = provider
        .list_tools(&caller, authorization.clone())
        .await
        .expect("the configured adapter catalog is available");
    let description = tools[0]
        .description
        .as_deref()
        .expect("configured tool description")
        .to_owned();
    let fetches_before_invocation = runtime_contract_fetches.load(Ordering::SeqCst);
    let tool = provider.resolve_tool("read_records").unwrap();
    let outcome = provider
        .invoke(
            &caller,
            authorization,
            Invocation {
                request_id: uuid::Uuid::new_v4(),
                tool: &tool,
                arguments: Some(&arguments),
            },
        )
        .await;
    task.abort();
    let headers = operation_headers.lock().unwrap().clone();
    (
        outcome,
        headers,
        runtime_contract_fetches.load(Ordering::SeqCst) - fetches_before_invocation,
        description,
    )
}

#[tokio::test]
async fn provider_sends_only_the_contract_pin_and_accepts_the_declared_success_status() {
    let (outcome, requests, contract_fetches, description) = invoke(
        201,
        StatusCode::CREATED,
        json!({}),
        Some("0123456789abcdef0123456789abcdef"),
    )
    .await;
    let ProviderOutcome::Success { value, .. } = outcome else {
        panic!("declared adapter success was refused");
    };
    assert_eq!(
        value["traceId"], "0123456789abcdef0123456789abcdef",
        "the public trace id preserves the Adapter's raw request id"
    );
    assert_eq!(requests.len(), 1);
    assert_eq!(
        contract_fetches, 0,
        "invocation relies on the Adapter's atomic contract pin, not a preflight fetch"
    );
    assert_eq!(description, "List configured records.");
    assert!(requests[0].contains_key("x-registry-adapter-contract"));
    assert!(!requests[0].contains_key("x-registry-correlation-id"));
}

#[tokio::test]
async fn provider_rejects_a_schema_valid_body_at_the_wrong_http_status() {
    let (outcome, requests, _, _) = invoke(
        204,
        StatusCode::OK,
        json!({}),
        Some("0123456789abcdef0123456789abcdef"),
    )
    .await;
    let ProviderOutcome::Failure(failure) = outcome else {
        panic!("wrong status was accepted");
    };
    assert_eq!(failure.code(), "adapter-protocol-invalid");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn provider_requires_the_exact_adapter_request_id_header_shape() {
    for request_id in [
        None,
        Some("01234567-89ab-cdef-0123-456789abcdef"),
        Some("0123456789ABCDEF0123456789ABCDEF"),
    ] {
        let (outcome, requests, _, _) = invoke(200, StatusCode::OK, json!({}), request_id).await;
        let ProviderOutcome::Failure(failure) = outcome else {
            panic!("invalid request identity was accepted");
        };
        assert_eq!(failure.code(), "adapter-protocol-invalid");
        assert_eq!(requests.len(), 1);
    }
}

#[tokio::test]
async fn ordinary_profile_503_is_not_misclassified_as_a_protocol_problem() {
    let (outcome, requests, _, _) = invoke(
        200,
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "code":"source.breaker",
            "status":503,
            "title":"Source temporarily unavailable"
        }),
        Some("0123456789abcdef0123456789abcdef"),
    )
    .await;
    let ProviderOutcome::Failure(failure) = outcome else {
        panic!("ordinary profile problem was accepted as data");
    };
    assert_eq!(failure.code(), "adapter-unavailable");
    assert!(format!("{failure:?}").contains("0123456789abcdef0123456789abcdef"));
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn malformed_reserved_protocol_tuple_is_protocol_invalid_not_profile_data() {
    let (outcome, requests, _, _) = invoke(
        200,
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "code":"adapter.contract.precondition-failed",
            "status":503,
            "title":"Effective contract precondition failed",
            "requestId":"0123456789abcdef0123456789abcdef"
        }),
        Some("0123456789abcdef0123456789abcdef"),
    )
    .await;
    let ProviderOutcome::Failure(failure) = outcome else {
        panic!("malformed protocol problem was accepted as data");
    };
    assert_eq!(failure.code(), "adapter-protocol-invalid");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn exact_typed_protocol_problems_are_refused_without_becoming_data() {
    for (status, code, title, expected_failure) in [
        (
            StatusCode::PRECONDITION_FAILED,
            "adapter.contract.precondition-failed",
            "Effective contract precondition failed",
            "adapter-contract-drift",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "adapter.contract.unavailable",
            "Effective contract unavailable",
            "adapter-unavailable",
        ),
    ] {
        let (outcome, requests, _, _) = invoke(
            200,
            status,
            json!({
                "code":code,
                "status":status.as_u16(),
                "title":title,
                "requestId":"0123456789abcdef0123456789abcdef"
            }),
            Some("0123456789abcdef0123456789abcdef"),
        )
        .await;
        let ProviderOutcome::Failure(failure) = outcome else {
            panic!("typed protocol problem was accepted as data");
        };
        assert_eq!(failure.code(), expected_failure);
        assert!(format!("{failure:?}").contains("0123456789abcdef0123456789abcdef"));
        assert_eq!(requests.len(), 1);
    }
}

#[tokio::test]
async fn protocol_body_request_id_must_equal_the_adapter_header() {
    let (outcome, requests, _, _) = invoke(
        200,
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "code":"adapter.contract.unavailable",
            "status":503,
            "title":"Effective contract unavailable",
            "requestId":"fedcba9876543210fedcba9876543210"
        }),
        Some("0123456789abcdef0123456789abcdef"),
    )
    .await;
    let ProviderOutcome::Failure(failure) = outcome else {
        panic!("protocol problem with split request identity was accepted as data");
    };
    assert_eq!(failure.code(), "adapter-protocol-invalid");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn provider_rejects_an_undeclared_output_member_after_accepting_request_identity() {
    let (outcome, requests, _, _) = invoke(
        200,
        StatusCode::OK,
        json!({"unknownOutput":"must not reach the model"}),
        Some("0123456789abcdef0123456789abcdef"),
    )
    .await;
    let ProviderOutcome::Failure(failure) = outcome else {
        panic!("an output member outside the closed producer schema was accepted");
    };
    assert_eq!(failure.code(), "adapter-protocol-invalid");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn profile_statuses_have_static_actionable_failure_classes_and_raw_trace() {
    for (status, expected) in [
        (StatusCode::BAD_REQUEST, "adapter-invalid-request"),
        (StatusCode::UNAUTHORIZED, "adapter-access-refused"),
        (StatusCode::FORBIDDEN, "adapter-access-refused"),
        (StatusCode::NOT_FOUND, "adapter-not-found"),
        (StatusCode::TOO_MANY_REQUESTS, "adapter-rate-limited"),
        (StatusCode::BAD_GATEWAY, "adapter-unavailable"),
    ] {
        let (outcome, requests, _, _) = invoke(
            200,
            status,
            json!({"code":"profile.problem","status":status.as_u16(),"title":"Static fixture"}),
            Some("0123456789abcdef0123456789abcdef"),
        )
        .await;
        let ProviderOutcome::Failure(failure) = outcome else {
            panic!("profile problem at {status} was accepted");
        };
        assert_eq!(failure.code(), expected, "status {status}");
        assert!(format!("{failure:?}").contains("0123456789abcdef0123456789abcdef"));
        assert_eq!(requests.len(), 1);
    }
}

#[tokio::test]
async fn bounded_response_and_omitted_empty_arguments_are_distinguished() {
    let (success, requests, _, _) = invoke_with_options(
        200,
        StatusCode::OK,
        json!({}),
        Some("0123456789abcdef0123456789abcdef"),
        4096,
        Map::new(),
    )
    .await;
    assert!(matches!(success, ProviderOutcome::Success { .. }));
    assert_eq!(requests.len(), 1);

    let (oversize, requests, _, _) = invoke_with_options(
        200,
        StatusCode::OK,
        json!({"padding":"x".repeat(256)}),
        Some("0123456789abcdef0123456789abcdef"),
        32,
        Map::new(),
    )
    .await;
    let ProviderOutcome::Failure(failure) = oversize else {
        panic!("oversize Adapter response was accepted");
    };
    assert_eq!(failure.code(), "adapter-response-too-large");
    assert!(format!("{failure:?}").contains("0123456789abcdef0123456789abcdef"));
    assert_eq!(requests.len(), 1);
}
