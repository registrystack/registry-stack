// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use registry_breg_client::{
    BRegCreateRequest, BRegDirectWrite, BRegEtag, BRegIdempotencyKey, BRegLifecycleOperation,
    BRegMetadataSelectionErrorKind, BRegPatchRequest, BRegPlanRefusal, BRegProblemCode,
    BRegProtocolFailure, BRegRecordFormat, BRegRecordOptions, BaseRegistryClient,
    BaseRegistryClientConfig, BaseRegistryClientError, RegistryRecordRepresentation,
    RegistryRecordResponse, REGISTRY_RECORD_CONTEXT_IDENTIFIER,
};
use registry_platform_httputil::client::{BearerToken, TokenError, TokenProvider};
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
const OTHER_RECORD_ID: &str = "00000000-0000-4000-8000-000000000002";
const SERVER_ETAG: &str = "\"breg-record-000000000001\"";
const ACTION_ETAG: &str =
    "\"breg-action-hmac-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"";
const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EFFECT_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PROFILE_LINK: &str = "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </tenant/base/v1/schemas/company>; rel=\"describedby\"";

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    uri: String,
    authorization: Option<String>,
    accept: Option<String>,
    content_type: Option<String>,
    idempotency_key: Option<String>,
    if_match: Option<String>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct MockResponse {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl MockResponse {
    fn json(status: StatusCode, body: Value) -> Self {
        Self {
            status,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("traceparent".into(), TRACEPARENT.into()),
            ],
            body: serde_json::to_vec(&body).expect("fixture serializes"),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    fn without_header(mut self, name: &str) -> Self {
        self.headers
            .retain(|(candidate, _)| !candidate.eq_ignore_ascii_case(name));
        self
    }
}

#[derive(Clone)]
struct MockState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
}

async fn handler(State(state): State<MockState>, request: Request<Body>) -> Response<Body> {
    let captured = CapturedRequest {
        method: request.method().to_string(),
        uri: request.uri().to_string(),
        authorization: header(&request, "authorization"),
        accept: header(&request, "accept"),
        content_type: header(&request, "content-type"),
        idempotency_key: header(&request, "idempotency-key"),
        if_match: header(&request, "if-match"),
        body: to_bytes(request.into_body(), 3 * 1024 * 1024)
            .await
            .expect("bounded request body")
            .to_vec(),
    };
    state
        .requests
        .lock()
        .expect("request capture lock")
        .push(captured);
    let spec = state
        .responses
        .lock()
        .expect("response queue lock")
        .pop_front()
        .unwrap_or_else(|| {
            MockResponse::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"unexpectedRequest": true}),
            )
        });
    let mut response = Response::new(Body::from(spec.body));
    *response.status_mut() = spec.status;
    for (name, value) in spec.headers {
        response.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("fixture header name"),
            HeaderValue::from_str(&value).expect("fixture header value"),
        );
    }
    response
}

fn header(request: &Request<Body>, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

#[derive(Debug)]
struct CountingToken(AtomicUsize);

#[async_trait]
impl TokenProvider for CountingToken {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BearerToken::new("write-boundary-token")
    }
}

struct TestClient {
    client: BaseRegistryClient,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    token: Arc<CountingToken>,
}

async fn test_client(responses: Vec<MockResponse>) -> TestClient {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
    let state = MockState {
        requests: requests.clone(),
        responses,
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock Base Registry Engine");
    let address = listener.local_addr().expect("mock address");
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(handler)).with_state(state),
        )
        .await
        .expect("serve mock Base Registry Engine");
    });
    let token = Arc::new(CountingToken(AtomicUsize::new(0)));
    let config = BaseRegistryClientConfig::new(
        Url::parse(&format!("http://{address}/tenant/base")).expect("base URL"),
    )
    .with_token_provider(token.clone());
    TestClient {
        client: BaseRegistryClient::new(config).expect("client"),
        requests,
        token,
    }
}

fn metadata_response() -> MockResponse {
    MockResponse::json(StatusCode::OK, metadata_fixture())
}

fn field() -> Value {
    json!({
        "id": "legal-name",
        "apiName": "legalName",
        "label": "Legal name",
        "schema": {"type": "string"},
        "required": true,
        "nullable": true,
        "readOnly": false,
        "removable": true
    })
}

#[allow(clippy::too_many_arguments)]
fn operation(
    identifier: &str,
    method: &str,
    path: &str,
    kind: &str,
    capabilities: Value,
    request: Value,
    create_writable: Value,
    patch_writable: Value,
) -> Value {
    json!({
        "id": identifier,
        "method": method,
        "path": path,
        "operation": kind,
        "sourceEntity": "company",
        "responseEntity": "company",
        "accessProfile": "company-writer",
        "requiredCapabilities": capabilities,
        "entityLabel": "Companies",
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": ["legal-name"],
        "fields": [field()],
        "readableFields": ["legal-name"],
        "createWritableFields": create_writable,
        "patchWritableFields": patch_writable,
        "selectors": [],
        "query": null,
        "request": request
    })
}

fn metadata_fixture() -> Value {
    let create = operation(
        "records.company.create",
        "POST",
        "/v1/records/companies",
        "create",
        json!([]),
        json!({
            "fieldNames": "api",
            "queryParameters": [],
            "body": "data_envelope",
            "contentType": "application/json",
            "idempotencyKeyRequired": true,
            "mutationSemantics": "direct",
            "schema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["data"],
                "properties": {"data": {"type": "object"}}
            }
        }),
        json!(["legal-name"]),
        json!([]),
    );
    let patch = operation(
        "records.company.patch",
        "PATCH",
        "/v1/records/companies/{record_id}",
        "patch",
        json!([]),
        json!({
            "fieldNames": "api",
            "queryParameters": [],
            "body": "json_patch",
            "contentType": "application/json-patch+json",
            "patchPathPrefix": "/data/",
            "patchOperations": ["add", "replace", "remove", "test"],
            "removeSemantics": "set_null",
            "ifMatchRequired": true,
            "idempotencyKeyRequired": true,
            "mutationSemantics": "direct",
            "schema": {"type": "array", "items": {"oneOf": [{"type": "object"}]}}
        }),
        json!([]),
        json!(["legal-name"]),
    );
    let submit = operation(
        "records.company.request.submit",
        "POST",
        "/v1/records/companies/{record_id}/actions/submit",
        "submit_request",
        json!(["change_request_lifecycle"]),
        json!({
            "fieldNames": "api",
            "queryParameters": [],
            "body": "change_request_action",
            "contentType": "application/json",
            "ifMatchRequired": true,
            "idempotencyKeyRequired": true,
            "mutationSemantics": "change_request_lifecycle",
            "schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": false,
                "properties": {}
            }
        }),
        json!([]),
        json!([]),
    );
    json!({
        "id": "business-registry",
        "version": "1.2.3",
        "revision": REVISION,
        "metadataVersion": "1",
        "entities": [{
            "id": "company",
            "datasetIdentifier": "legal-entities",
            "route": "companies",
            "operations": [
                {"operation": "create", "accessProfile": "company-writer"},
                {"operation": "patch", "accessProfile": "company-writer"},
                {"operation": "submit_request", "accessProfile": "company-writer"}
            ],
            "readableFields": ["legal-name"],
            "schema": "/v1/schemas/company"
        }],
        "operations": [create, patch, submit]
    })
}

fn record_body(format: BRegRecordFormat, record_identifier: &str) -> Value {
    let mut value = json!({
        "data": {
            "recordIdentifier": record_identifier,
            "revisionIdentifier": "1",
            "domainData": {"legalName": "Example Ltd"},
            "snapshot": format!("breg1_{record_identifier}")
        },
        "meta": {
            "registryIdentifier": "business-registry",
            "datasetIdentifier": "legal-entities",
            "entityTypeIdentifier": "company"
        }
    });
    if format == BRegRecordFormat::JsonLd {
        value["@context"] = Value::String(REGISTRY_RECORD_CONTEXT_IDENTIFIER.into());
    }
    value
}

fn mutation_response(
    status: StatusCode,
    format: BRegRecordFormat,
    record_identifier: &str,
    location: bool,
) -> MockResponse {
    let media_type = match format {
        BRegRecordFormat::Json => "application/json",
        BRegRecordFormat::JsonLd => "application/ld+json",
    };
    let mut response = MockResponse::json(status, record_body(format, record_identifier))
        .without_header("content-type")
        .with_header("content-type", media_type)
        .with_header("etag", SERVER_ETAG)
        .with_header("link", PROFILE_LINK)
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept");
    if location {
        response = response.with_header(
            "location",
            &format!("/tenant/base/v1/records/companies/{record_identifier}"),
        );
    }
    response
}

fn lifecycle_record_body() -> Value {
    json!({
        "data": {
            "recordIdentifier": RECORD_ID,
            "revisionIdentifier": "7",
            "domainData": {"legalName": "Example Ltd"},
            "request": {
                "bregState": "draft",
                "proposalVersion": 7,
                "effectDigest": EFFECT_DIGEST,
                "editable": true,
                "actions": [{
                    "operation": "submit_request",
                    "method": "POST",
                    "href": format!(
                        "/v1/records/companies/{RECORD_ID}/actions/submit?accessProfile=company-writer"
                    ),
                    "ifMatch": ACTION_ETAG
                }]
            }
        },
        "meta": {
            "registryIdentifier": "business-registry",
            "datasetIdentifier": "legal-entities",
            "entityTypeIdentifier": "company"
        }
    })
}

fn lifecycle_record_response() -> MockResponse {
    MockResponse::json(StatusCode::OK, lifecycle_record_body())
        .with_header("etag", SERVER_ETAG)
        .with_header("link", PROFILE_LINK)
}

fn receipt_body(record_identifier: &str, state: &str) -> Value {
    json!({
        "id": record_identifier,
        "revision": 8,
        "snapshot": format!("breg1_{record_identifier}"),
        "request": {
            "bregState": state,
            "proposalVersion": 7,
            "effectDigest": EFFECT_DIGEST,
            "application": null
        }
    })
}

fn lifecycle_response(body: Value) -> MockResponse {
    MockResponse::json(StatusCode::OK, body)
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept")
}

fn create_request() -> BRegCreateRequest {
    BRegCreateRequest::new(Map::from_iter([(
        "legalName".to_owned(),
        json!("Created Ltd"),
    )]))
    .expect("valid Create request")
}

fn patch_request() -> BRegPatchRequest {
    BRegPatchRequest::builder()
        .test("legalName", json!("Created Ltd"))
        .expect("valid test")
        .replace("legalName", json!("Patched Ltd"))
        .expect("valid replace")
        .build()
        .expect("valid PATCH request")
}

fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).expect("valid idempotency key")
}

fn create_binding(
    metadata: &registry_breg_client::BRegMetadata,
) -> registry_breg_client::BRegCreateBinding {
    let BRegDirectWrite::Create(binding) = metadata
        .select_direct_write("records.company.create", "company-writer")
        .expect("select exact Create contract")
    else {
        panic!("Create binding expected")
    };
    binding
}

fn patch_binding(
    metadata: &registry_breg_client::BRegMetadata,
) -> registry_breg_client::BRegPatchBinding {
    let BRegDirectWrite::Patch(binding) = metadata
        .select_direct_write("records.company.patch", "company-writer")
        .expect("select exact PATCH contract")
    else {
        panic!("PATCH binding expected")
    };
    binding
}

#[tokio::test]
async fn metadata_selected_create_and_patch_use_the_exact_http_contract() {
    let fixture = test_client(vec![
        metadata_response(),
        mutation_response(StatusCode::CREATED, BRegRecordFormat::Json, RECORD_ID, true),
        mutation_response(StatusCode::OK, BRegRecordFormat::JsonLd, RECORD_ID, false),
    ])
    .await;

    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .expect("runtime metadata")
        .value;
    assert_eq!(metadata.registry_revision(), REVISION);
    assert_eq!(
        metadata
            .select_direct_write("records.company.create", "other-profile")
            .expect_err("profile mismatch")
            .kind(),
        BRegMetadataSelectionErrorKind::ProfileMismatch
    );
    let create = create_binding(&metadata);
    let patch = patch_binding(&metadata);

    let created = fixture
        .client
        .create_record(
            &create,
            &create_request(),
            &key("create-exchange-1"),
            BRegRecordFormat::Json,
        )
        .await
        .expect("Create succeeds");
    assert_eq!(created.value.data.record_identifier, RECORD_ID);
    assert_eq!(created.metadata.etag().unwrap().as_str(), SERVER_ETAG);
    assert_eq!(
        created.metadata.location(),
        Some("/tenant/base/v1/records/companies/00000000-0000-4000-8000-000000000001")
    );

    let patched = fixture
        .client
        .patch_record(
            &patch,
            Uuid::parse_str(RECORD_ID).unwrap(),
            created.metadata.etag().unwrap(),
            &patch_request(),
            &key("patch-exchange-1"),
            BRegRecordFormat::JsonLd,
        )
        .await
        .expect("PATCH succeeds");
    assert!(patched.value.json_ld_context.is_some());
    assert!(patched.metadata.location().is_none());

    assert_eq!(fixture.token.0.load(Ordering::SeqCst), 3);
    let requests = fixture.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].uri,
        "/tenant/base/v1/registry?accessProfile=company-writer"
    );
    assert_eq!(requests[0].accept.as_deref(), Some("application/json"));
    assert!(requests[0].content_type.is_none());
    assert!(requests[0].idempotency_key.is_none());
    assert!(requests[0].if_match.is_none());

    assert_eq!(requests[1].method, "POST");
    assert_eq!(
        requests[1].uri,
        "/tenant/base/v1/records/companies?accessProfile=company-writer"
    );
    assert_eq!(requests[1].accept.as_deref(), Some("application/json"));
    assert_eq!(
        requests[1].content_type.as_deref(),
        Some("application/json")
    );
    assert_eq!(
        requests[1].idempotency_key.as_deref(),
        Some("create-exchange-1")
    );
    assert!(requests[1].if_match.is_none());
    assert_eq!(requests[1].body, br#"{"data":{"legalName":"Created Ltd"}}"#);

    assert_eq!(requests[2].method, "PATCH");
    assert_eq!(
        requests[2].uri,
        format!("/tenant/base/v1/records/companies/{RECORD_ID}?accessProfile=company-writer")
    );
    assert_eq!(requests[2].accept.as_deref(), Some("application/ld+json"));
    assert_eq!(
        requests[2].content_type.as_deref(),
        Some("application/json-patch+json")
    );
    assert_eq!(
        requests[2].idempotency_key.as_deref(),
        Some("patch-exchange-1")
    );
    assert_eq!(requests[2].if_match.as_deref(), Some(SERVER_ETAG));
    assert_eq!(
        requests[2].body,
        br#"[{"op":"test","path":"/data/legalName","value":"Created Ltd"},{"op":"replace","path":"/data/legalName","value":"Patched Ltd"}]"#
    );
    for request in requests {
        assert_eq!(
            request.authorization.as_deref(),
            Some("Bearer write-boundary-token")
        );
    }
}

#[tokio::test]
async fn promoted_lifecycle_action_uses_the_exact_route_headers_body_and_receipt() {
    let fixture = test_client(vec![
        metadata_response(),
        lifecycle_record_response(),
        lifecycle_response(receipt_body(RECORD_ID, "submitted")),
    ])
    .await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let authority = metadata
        .select_lifecycle("company", "company-writer")
        .expect("select lifecycle authority");
    let record = fixture
        .client
        .get_record(
            "companies",
            RECORD_ID,
            &BRegRecordOptions::default()
                .access_profile("company-writer")
                .unwrap(),
        )
        .await
        .expect("request record")
        .value;
    let actions = fixture
        .client
        .lifecycle_actions(&authority, &record)
        .expect("promote advertised action");
    assert_eq!(actions.len(), 1);
    assert_eq!(
        actions[0].operation(),
        BRegLifecycleOperation::SubmitRequest
    );

    let receipt = fixture
        .client
        .execute_lifecycle_action(&actions[0], &key("action-exchange-1"))
        .await
        .expect("execute action");
    assert_eq!(receipt.value.record_identifier(), RECORD_ID);
    assert_eq!(receipt.value.revision(), 8);
    assert!(receipt.metadata.etag().is_none());
    assert!(receipt.metadata.location().is_none());

    let requests = fixture.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[1].uri,
        format!("/tenant/base/v1/records/companies/{RECORD_ID}?accessProfile=company-writer")
    );
    assert_eq!(requests[2].method, "POST");
    assert_eq!(
        requests[2].uri,
        format!(
            "/tenant/base/v1/records/companies/{RECORD_ID}/actions/submit?accessProfile=company-writer"
        )
    );
    assert_eq!(requests[2].accept.as_deref(), Some("application/json"));
    assert_eq!(
        requests[2].content_type.as_deref(),
        Some("application/json")
    );
    assert_eq!(
        requests[2].idempotency_key.as_deref(),
        Some("action-exchange-1")
    );
    assert_eq!(requests[2].if_match.as_deref(), Some(ACTION_ETAG));
    assert_eq!(requests[2].body, br#"{}"#);
}

#[derive(Clone, Copy, Debug)]
enum DirectResponseCase {
    MissingEtag,
    WeakEtag,
    MissingLocation,
    WrongLocation,
    MissingLink,
    MissingCacheControl,
    WrongCacheControl,
    MissingVary,
    WrongVary,
    MissingTrace,
    WrongStatus,
    PatchWithLocation,
}

#[tokio::test]
async fn direct_write_success_headers_and_status_fail_closed() {
    for (case, expected) in [
        (
            DirectResponseCase::MissingEtag,
            BRegProtocolFailure::EntityTag,
        ),
        (DirectResponseCase::WeakEtag, BRegProtocolFailure::EntityTag),
        (
            DirectResponseCase::MissingLocation,
            BRegProtocolFailure::Location,
        ),
        (
            DirectResponseCase::WrongLocation,
            BRegProtocolFailure::Location,
        ),
        (
            DirectResponseCase::MissingLink,
            BRegProtocolFailure::ProfileLink,
        ),
        (
            DirectResponseCase::MissingCacheControl,
            BRegProtocolFailure::CachePolicy,
        ),
        (
            DirectResponseCase::WrongCacheControl,
            BRegProtocolFailure::CachePolicy,
        ),
        (
            DirectResponseCase::MissingVary,
            BRegProtocolFailure::CachePolicy,
        ),
        (
            DirectResponseCase::WrongVary,
            BRegProtocolFailure::CachePolicy,
        ),
        (
            DirectResponseCase::MissingTrace,
            BRegProtocolFailure::TraceContext,
        ),
        (DirectResponseCase::WrongStatus, BRegProtocolFailure::Status),
        (
            DirectResponseCase::PatchWithLocation,
            BRegProtocolFailure::Location,
        ),
    ] {
        let patch_case = matches!(case, DirectResponseCase::PatchWithLocation);
        let mut response = if patch_case {
            mutation_response(StatusCode::OK, BRegRecordFormat::Json, RECORD_ID, true)
        } else {
            mutation_response(StatusCode::CREATED, BRegRecordFormat::Json, RECORD_ID, true)
        };
        response = match case {
            DirectResponseCase::MissingEtag => response.without_header("etag"),
            DirectResponseCase::WeakEtag => response
                .without_header("etag")
                .with_header("etag", "W/\"breg-record-000000000001\""),
            DirectResponseCase::MissingLocation => response.without_header("location"),
            DirectResponseCase::WrongLocation => response.without_header("location").with_header(
                "location",
                &format!("/v1/records/companies/{OTHER_RECORD_ID}"),
            ),
            DirectResponseCase::MissingLink => response.without_header("link"),
            DirectResponseCase::MissingCacheControl => response.without_header("cache-control"),
            DirectResponseCase::WrongCacheControl => response
                .without_header("cache-control")
                .with_header("cache-control", "private"),
            DirectResponseCase::MissingVary => response.without_header("vary"),
            DirectResponseCase::WrongVary => response
                .without_header("vary")
                .with_header("vary", "accept, authorization"),
            DirectResponseCase::MissingTrace => response.without_header("traceparent"),
            DirectResponseCase::WrongStatus => {
                response.status = StatusCode::OK;
                response
            }
            DirectResponseCase::PatchWithLocation => response,
        };
        let fixture = test_client(vec![metadata_response(), response]).await;
        let metadata = fixture
            .client
            .registry_contract(Some("company-writer"))
            .await
            .unwrap()
            .value;
        let error = if patch_case {
            fixture
                .client
                .patch_record(
                    &patch_binding(&metadata),
                    Uuid::parse_str(RECORD_ID).unwrap(),
                    &BRegEtag::parse(SERVER_ETAG).unwrap(),
                    &patch_request(),
                    &key("header-case"),
                    BRegRecordFormat::Json,
                )
                .await
                .expect_err("invalid response is refused")
        } else {
            fixture
                .client
                .create_record(
                    &create_binding(&metadata),
                    &create_request(),
                    &key("header-case"),
                    BRegRecordFormat::Json,
                )
                .await
                .expect_err("invalid response is refused")
        };
        assert!(
            matches!(
                error,
                BaseRegistryClientError::Protocol { failure, .. } if failure == expected
            ),
            "{case:?}: {error:?}"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum LifecycleHeaderCase {
    Etag,
    Location,
    Link,
    Status,
}

#[tokio::test]
async fn lifecycle_success_forbids_record_response_headers() {
    for (case, expected) in [
        (LifecycleHeaderCase::Etag, BRegProtocolFailure::EntityTag),
        (LifecycleHeaderCase::Location, BRegProtocolFailure::Location),
        (LifecycleHeaderCase::Link, BRegProtocolFailure::ProfileLink),
        (LifecycleHeaderCase::Status, BRegProtocolFailure::Status),
    ] {
        let response = match case {
            LifecycleHeaderCase::Etag => lifecycle_response(receipt_body(RECORD_ID, "submitted"))
                .with_header("etag", SERVER_ETAG),
            LifecycleHeaderCase::Location => {
                lifecycle_response(receipt_body(RECORD_ID, "submitted"))
                    .with_header("location", &format!("/v1/records/companies/{RECORD_ID}"))
            }
            LifecycleHeaderCase::Link => lifecycle_response(receipt_body(RECORD_ID, "submitted"))
                .with_header("link", PROFILE_LINK),
            LifecycleHeaderCase::Status => {
                let mut response = lifecycle_response(receipt_body(RECORD_ID, "submitted"));
                response.status = StatusCode::CREATED;
                response
            }
        };
        let error = execute_submit(response)
            .await
            .expect_err("forbidden action header is refused");
        assert!(
            matches!(
                error,
                BaseRegistryClientError::Protocol { failure, .. } if failure == expected
            ),
            "{case:?}: {error:?}"
        );
    }
}

async fn execute_submit(
    response: MockResponse,
) -> Result<
    registry_breg_client::BRegComplete<registry_breg_client::BRegLifecycleActionReceipt>,
    BaseRegistryClientError,
> {
    let fixture = test_client(vec![
        metadata_response(),
        lifecycle_record_response(),
        response,
    ])
    .await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await?
        .value;
    let authority = metadata
        .select_lifecycle("company", "company-writer")
        .expect("lifecycle metadata");
    let record = fixture
        .client
        .get_record(
            "companies",
            RECORD_ID,
            &BRegRecordOptions::default()
                .access_profile("company-writer")
                .unwrap(),
        )
        .await?
        .value;
    let action = fixture
        .client
        .lifecycle_actions(&authority, &record)
        .expect("promote action")
        .remove(0);
    fixture
        .client
        .execute_lifecycle_action(&action, &key("action-response-case"))
        .await
}

#[tokio::test]
async fn mutation_records_and_action_receipts_are_validated_against_the_selected_operation() {
    for body in [
        {
            let mut body = record_body(BRegRecordFormat::Json, RECORD_ID);
            body["unexpected"] = json!(true);
            body
        },
        {
            let mut body = record_body(BRegRecordFormat::Json, RECORD_ID);
            body["meta"]["registryIdentifier"] = json!("other-registry");
            body
        },
        {
            let mut body = record_body(BRegRecordFormat::Json, RECORD_ID);
            body["meta"]["datasetIdentifier"] = json!("other-dataset");
            body
        },
        {
            let mut body = record_body(BRegRecordFormat::Json, RECORD_ID);
            body["data"]["snapshot"] = json!("not-a-snapshot");
            body
        },
    ] {
        let response =
            mutation_response(StatusCode::CREATED, BRegRecordFormat::Json, RECORD_ID, true);
        let response = MockResponse {
            body: serde_json::to_vec(&body).unwrap(),
            ..response
        };
        let fixture = test_client(vec![metadata_response(), response]).await;
        let metadata = fixture
            .client
            .registry_contract(Some("company-writer"))
            .await
            .unwrap()
            .value;
        let error = fixture
            .client
            .create_record(
                &create_binding(&metadata),
                &create_request(),
                &key("strict-record"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("inexact record is refused");
        assert!(matches!(
            error,
            BaseRegistryClientError::Protocol {
                failure: BRegProtocolFailure::Body,
                ..
            }
        ));
    }

    let response = mutation_response(
        StatusCode::OK,
        BRegRecordFormat::Json,
        OTHER_RECORD_ID,
        false,
    );
    let fixture = test_client(vec![metadata_response(), response]).await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let error = fixture
        .client
        .patch_record(
            &patch_binding(&metadata),
            Uuid::parse_str(RECORD_ID).unwrap(),
            &BRegEtag::parse(SERVER_ETAG).unwrap(),
            &patch_request(),
            &key("strict-patch-record"),
            BRegRecordFormat::Json,
        )
        .await
        .expect_err("PATCH cannot return another record");
    assert!(matches!(
        error,
        BaseRegistryClientError::Protocol {
            failure: BRegProtocolFailure::Body,
            ..
        }
    ));

    for receipt in [
        receipt_body(OTHER_RECORD_ID, "submitted"),
        receipt_body(RECORD_ID, "approved"),
        {
            let mut receipt = receipt_body(RECORD_ID, "submitted");
            receipt["unexpected"] = json!(true);
            receipt
        },
        {
            let mut receipt = receipt_body(RECORD_ID, "submitted");
            receipt["revision"] = json!(9);
            receipt
        },
    ] {
        let error = execute_submit(lifecycle_response(receipt))
            .await
            .expect_err("inexact action receipt is refused");
        assert!(matches!(
            error,
            BaseRegistryClientError::Protocol {
                failure: BRegProtocolFailure::Body,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn every_registered_problem_is_accepted_exactly_for_a_direct_write() {
    let responses = std::iter::once(metadata_response())
        .chain(BRegProblemCode::ALL.into_iter().map(problem_response))
        .collect();
    let fixture = test_client(responses).await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let binding = create_binding(&metadata);
    for code in BRegProblemCode::ALL {
        let error = fixture
            .client
            .create_record(
                &binding,
                &create_request(),
                &key("problem-exchange"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("registered problem is returned");
        assert_eq!(error.problem_code(), Some(code));
        assert_eq!(error.status(), Some(code.status()));
        assert_eq!(error.trace_id().unwrap().as_str(), TRACE_ID);
    }
    assert_eq!(
        fixture.requests.lock().unwrap().len(),
        1 + BRegProblemCode::ALL.len()
    );
}

fn problem_response(code: BRegProblemCode) -> MockResponse {
    MockResponse::json(
        StatusCode::from_u16(code.status()).expect("registered status"),
        json!({
            "type": format!("urn:breg:problem:{}", code.code()),
            "title": problem_title(code.status()),
            "status": code.status(),
            "detail": problem_detail(code),
            "code": code.code(),
            "traceId": TRACE_ID
        }),
    )
    .without_header("content-type")
    .with_header("content-type", "application/problem+json")
    .with_header("cache-control", "no-store")
}

fn problem_title(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        412 => "Precondition Failed",
        415 => "Unsupported Media Type",
        428 => "Precondition Required",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => panic!("unregistered problem status"),
    }
}

fn problem_detail(code: BRegProblemCode) -> &'static str {
    use BRegProblemCode as Code;

    match code {
        Code::AuthenticationRefused => "The bearer credential is missing or refused.",
        Code::IdempotencyConflict => "The idempotency key is bound to another request.",
        Code::LookupUnresolved => "The lookup did not resolve exactly one record.",
        Code::MutationConflict => "The mutation conflicts with current state.",
        Code::PreconditionFailed => "The mutation precondition failed.",
        Code::PreconditionRequired => "The mutation precondition is required.",
        Code::QueryCursorInvalid => "The query cursor is invalid.",
        Code::QueryInvalid => "The query request is invalid.",
        Code::RequestInvalid => "The request is invalid.",
        Code::RequestPlanRefused(refusal) => plan_refused_detail(refusal),
        Code::RequestTimeout => "The request timed out.",
        Code::ResourceNotFound => "The requested resource was not found.",
        Code::RuntimeNotReady => "Registry runtime is not ready.",
        Code::ServiceUnavailable => "The Registry mutation service is unavailable.",
        Code::SourceUnavailable => "The Registry data service is unavailable.",
        Code::UnsupportedMediaType => "The request media type is not supported.",
        _ => panic!("unregistered problem code"),
    }
}

fn plan_refused_detail(refusal: BRegPlanRefusal) -> &'static str {
    use BRegPlanRefusal as Refusal;

    match refusal {
        Refusal::Source => {
            "The change-request planner refused the submission: change_request.planner.source."
        }
        Refusal::Entrypoint => {
            "The change-request planner refused the submission: change_request.planner.entrypoint."
        }
        Refusal::Execution => {
            "The change-request planner refused the submission: change_request.planner.execution."
        }
        Refusal::Result => {
            "The change-request planner refused the submission: change_request.planner.result."
        }
        Refusal::Ceiling => {
            "The change-request planner refused the submission: change_request.planner.ceiling."
        }
        Refusal::Disposition => {
            "The change-request planner refused the submission: change_request.planner.disposition."
        }
        Refusal::Resource => {
            "The change-request planner refused the submission: change_request.planner.resource."
        }
        _ => panic!("unregistered plan refusal"),
    }
}

#[tokio::test]
async fn redirects_and_failures_are_never_followed_or_retried() {
    let redirect = MockResponse::json(
        StatusCode::FOUND,
        json!({
            "type": "urn:breg:problem:redirect",
            "title": "Redirect",
            "status": 302,
            "detail": "Do not follow this response.",
            "code": "redirect",
            "traceId": TRACE_ID
        }),
    )
    .without_header("content-type")
    .with_header("content-type", "application/problem+json")
    .with_header("cache-control", "no-store")
    .with_header("location", "/tenant/base/redirect-target");
    let fixture = test_client(vec![metadata_response(), redirect]).await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let error = fixture
        .client
        .create_record(
            &create_binding(&metadata),
            &create_request(),
            &key("redirect-exchange"),
            BRegRecordFormat::Json,
        )
        .await
        .expect_err("redirect is inert");
    assert!(matches!(
        error,
        BaseRegistryClientError::Protocol {
            failure: BRegProtocolFailure::Problem,
            ..
        }
    ));
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 2, "one metadata fetch and one Create only");
    assert!(!requests
        .iter()
        .any(|request| request.uri.contains("redirect-target")));
}

#[tokio::test]
async fn source_mismatch_and_invalid_bodies_are_refused_before_token_or_io() {
    let source = test_client(vec![metadata_response()]).await;
    let metadata = source
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let create = create_binding(&metadata);
    let patch = patch_binding(&metadata);
    let authority = metadata
        .select_lifecycle("company", "company-writer")
        .unwrap();
    let RegistryRecordResponse::Single(record) = RegistryRecordResponse::from_value(
        lifecycle_record_body(),
        RegistryRecordRepresentation::Json,
    )
    .unwrap() else {
        panic!("single record expected")
    };
    let action = source
        .client
        .lifecycle_actions(&authority, &record)
        .unwrap()
        .remove(0);

    let other = test_client(Vec::new()).await;
    let errors = [
        other
            .client
            .create_record(
                &create,
                &create_request(),
                &key("cross-source-create"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("cross-source Create refused"),
        other
            .client
            .patch_record(
                &patch,
                Uuid::parse_str(RECORD_ID).unwrap(),
                &BRegEtag::parse(SERVER_ETAG).unwrap(),
                &patch_request(),
                &key("cross-source-patch"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("cross-source PATCH refused"),
        other
            .client
            .execute_lifecycle_action(&action, &key("cross-source-action"))
            .await
            .expect_err("cross-source action refused"),
    ];
    assert!(errors
        .iter()
        .all(|error| matches!(error, BaseRegistryClientError::InvalidRequest { .. })));
    assert_eq!(other.token.0.load(Ordering::SeqCst), 0);
    assert!(other.requests.lock().unwrap().is_empty());

    let source_request_count = source.requests.lock().unwrap().len();
    let source_token_count = source.token.0.load(Ordering::SeqCst);
    let empty_create = BRegCreateRequest::new(Map::new()).unwrap();
    let invalid_patch = BRegPatchRequest::builder()
        .replace("unauthorizedField", json!("canary"))
        .unwrap()
        .build()
        .unwrap();
    for error in [
        source
            .client
            .create_record(
                &create,
                &empty_create,
                &key("invalid-create"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("missing required Create field"),
        source
            .client
            .patch_record(
                &patch,
                Uuid::parse_str(RECORD_ID).unwrap(),
                &BRegEtag::parse(SERVER_ETAG).unwrap(),
                &invalid_patch,
                &key("invalid-patch"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("ungranted PATCH field"),
    ] {
        assert!(matches!(
            error,
            BaseRegistryClientError::InvalidRequest { .. }
        ));
    }
    assert_eq!(source.token.0.load(Ordering::SeqCst), source_token_count);
    assert_eq!(source.requests.lock().unwrap().len(), source_request_count);
}
