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
    ingestion_chunk_digest, ingestion_prefix_digest, BRegBatchBuilder, BRegBatchError,
    BRegBatchOperation, BRegCreateRequest, BRegDirectWrite, BRegEtag, BRegIdempotencyKey,
    BRegIngestionChunk, BRegIngestionRunListQuery, BRegIngestionRunRequest, BRegIngestionRunStatus,
    BRegLifecycleOperation, BRegMetadataErrorKind, BRegMetadataSelectionErrorKind,
    BRegPatchRequest, BRegPlanRefusal, BRegProblemCode, BRegProtocolFailure, BRegRecordFormat,
    BRegRecordOptions, BRegRefusalCode, BaseRegistryClient, BaseRegistryClientConfig,
    BaseRegistryClientError, RegistryRecordRepresentation, RegistryRecordResponse,
    BREG_INGESTION_CHUNK_ALGORITHM_VERSION, REGISTRY_RECORD_CONTEXT_IDENTIFIER,
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
// A package declares its own refusal catalogue, so both the code and the label
// stand in for one declared entry rather than for fixed client-side text.
const REFUSAL_CODE: &str = "blank-name";
const REFUSAL_LABEL: &str = "At least one name part is required.";
const INGESTION_PROFILE: &str = "importer.v1";
const INGESTION_INPUT_DIGEST: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

fn metadata_fixture_with_create_batch() -> Value {
    let mut metadata = metadata_fixture();
    metadata["operations"]
        .as_array_mut()
        .unwrap()
        .push(operation(
            "records.company.batch",
            "POST",
            "/v1/records/companies:batch",
            "batch",
            json!([]),
            json!({
                "fieldNames": "api",
                "queryParameters": [],
                "body": "batch",
                "contentType": "application/json",
                "idempotencyKeyRequired": true,
                "mutationSemantics": "direct",
                "maximumItems": 20,
                "maximumBodyBytes": 4096,
                "allowCreate": true,
                "allowPatch": false,
                "schema": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["items"],
                    "properties": {
                        "items": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 20,
                            "items": {
                                "oneOf": [{
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["operation", "data"],
                                    "properties": {
                                        "operation": {"const": "create"},
                                        "data": {"type": "object"}
                                    }
                                }]
                            }
                        }
                    }
                }
            }),
            json!(["legal-name"]),
            json!([]),
        ));
    metadata["entities"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!({"operation": "batch", "accessProfile": "company-writer"}));
    metadata
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
    create_binding_for(metadata, "company-writer")
}

fn create_binding_for(
    metadata: &registry_breg_client::BRegMetadata,
    profile: &str,
) -> registry_breg_client::BRegCreateBinding {
    let BRegDirectWrite::Create(binding) = metadata
        .select_direct_write("records.company.create", profile)
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
async fn registry_contract_keeps_the_metadata_decode_reason_instead_of_discarding_it() {
    let mut fixture = metadata_fixture();
    fixture["entities"] = json!("not-an-array");
    let response = MockResponse::json(StatusCode::OK, fixture);
    let fixture = test_client(vec![response]).await;

    let error = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .expect_err("malformed registry metadata is refused");

    assert!(matches!(
        error,
        BaseRegistryClientError::Protocol {
            failure: BRegProtocolFailure::Body,
            ..
        }
    ));
    assert_eq!(
        error.metadata_error_kind(),
        Some(BRegMetadataErrorKind::Shape)
    );
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
    let receipt_value = receipt.value.to_value();
    assert_eq!(receipt_value, receipt_body(RECORD_ID, "submitted"));
    assert_eq!(
        registry_breg_client::BRegLifecycleActionReceipt::from_value(receipt_value).unwrap(),
        receipt.value
    );
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

#[tokio::test]
async fn pattern_conflicts_preserve_typed_conflicts_and_reject_inexact_metadata() {
    let generic = problem_response(BRegProblemCode::MutationConflict);
    let mut pattern: Value = serde_json::from_slice(&generic.body).unwrap();
    pattern["detail"] = json!("The field does not conform to its declared storage pattern.");
    let without_location = pattern.clone();
    pattern["entityId"] = json!("company");
    pattern["fieldId"] = json!("registration_number");
    let response_for = |value: Value| {
        let mut response = generic.clone();
        response.body = serde_json::to_vec(&value).unwrap();
        response
    };
    let mut bad = Vec::new();
    for member in ["entityId", "fieldId"] {
        let mut absent = pattern.clone();
        absent.as_object_mut().unwrap().remove(member);
        bad.push(response_for(absent));
        for value in [
            Value::Null,
            json!(17),
            json!(""),
            json!("x".repeat(129)),
            json!("id\ncanary"),
        ] {
            let mut malformed = pattern.clone();
            malformed[member] = value;
            bad.push(response_for(malformed));
        }
    }
    for (member, value) in [
        ("extra", json!("response-canary")),
        ("detail", json!("response-canary")),
        ("status", json!(400)),
        ("fieldPath", json!("/evidence/status")),
        ("refusalCode", json!("response-canary")),
        ("traceId", json!("0123456789abcdef0123456789abcdef")),
    ] {
        let mut malformed = pattern.clone();
        malformed[member] = value;
        bad.push(response_for(malformed));
    }
    let evidence = problem_response(BRegProblemCode::ActionEvidenceFailed);
    let mut misplaced: Value = serde_json::from_slice(&evidence.body).unwrap();
    misplaced["entityId"] = json!("company");
    misplaced["fieldId"] = json!("registration_number");
    bad.push(MockResponse {
        body: serde_json::to_vec(&misplaced).unwrap(),
        ..evidence
    });
    for member in ["entityId", "fieldId", "detail"] {
        let mut duplicate = generic.clone();
        duplicate.body = format!(
            "{{\"{member}\":\"duplicate-canary\",{}",
            &pattern.to_string()[1..]
        )
        .into_bytes();
        bad.push(duplicate);
    }
    let failures = bad.len();
    let responses = std::iter::once(metadata_response())
        .chain([
            generic.clone(),
            response_for(without_location),
            response_for(pattern),
        ])
        .chain(bad)
        .collect();
    let fixture = test_client(responses).await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let binding = create_binding(&metadata);
    for index in 0..3 + failures {
        let error = fixture
            .client
            .create_record(
                &binding,
                &create_request(),
                &key("pattern-conflict"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("conflict or protocol refusal");
        if index < 3 {
            assert_eq!(
                error.problem_code(),
                Some(BRegProblemCode::MutationConflict)
            );
            assert_eq!(error.status(), Some(409));
        } else {
            assert!(matches!(
                error,
                BaseRegistryClientError::Protocol {
                    failure: BRegProtocolFailure::Problem,
                    ..
                }
            ));
        }
        assert!(!format!("{error:?}: {error}").contains("canary"));
    }
    assert_eq!(
        fixture.requests.lock().unwrap().len(),
        1 + 3 + failures,
        "no retry after a conflict or malformed problem"
    );
}

#[tokio::test]
async fn evidence_failure_paths_are_closed_bounded_and_discarded() {
    let base = problem_response(BRegProblemCode::ActionEvidenceFailed);
    let document: Value = serde_json::from_slice(&base.body).unwrap();
    let response_for = |value: Value| {
        let mut response = base.clone();
        response.body = serde_json::to_vec(&value).unwrap();
        response
    };
    let mut accepted = vec![base.clone()];
    for path in [
        "/evidence/farmer-status".to_owned(),
        "/evidence/a".to_owned(),
        format!("/evidence/{}", "a".repeat(64)),
        "/evidence/evidence_canary-12".to_owned(),
    ] {
        let mut value = document.clone();
        value["fieldPath"] = json!(path);
        accepted.push(response_for(value));
    }
    let mut refused = Vec::new();
    for path in [
        Value::Null,
        json!(12),
        json!({}),
        json!(""),
        json!("/evidence/"),
        json!("/input/farmer-status"),
        json!("evidence/farmer-status"),
        json!("/evidence/Upper"),
        json!("/evidence/0status"),
        json!("/evidence/farmer.status"),
        json!("/evidence/farmer/status"),
        json!("/evidence/farmer~1status"),
        json!("/evidence/farmer%2fstatus"),
        json!("/evidence/farmer\ncanary"),
        json!("/evidence/é"),
        json!(format!("/evidence/{}", "a".repeat(65))),
    ] {
        let mut value = document.clone();
        value["fieldPath"] = path;
        refused.push(response_for(value));
    }
    let mut located = document.clone();
    located["fieldPath"] = json!("/evidence/evidence-canary");
    for (member, value) in [
        ("extra", json!("private-canary")),
        ("refusalCode", json!("private-canary")),
        ("entityId", json!("private-canary")),
        ("detail", json!("private-canary")),
        ("status", json!(409)),
        ("traceId", json!("0123456789abcdef0123456789abcdef")),
    ] {
        let mut invalid = located.clone();
        invalid[member] = value;
        refused.push(response_for(invalid));
    }
    let mut paired = located.clone();
    paired["entityId"] = json!("company");
    paired["fieldId"] = json!("registration_number");
    refused.push(response_for(paired));
    for code in [
        BRegProblemCode::MutationConflict,
        BRegProblemCode::ActionHandlerFailed,
        BRegProblemCode::RequestInvalid,
    ] {
        let mut misplaced = problem_response(code);
        let mut value: Value = serde_json::from_slice(&misplaced.body).unwrap();
        value["fieldPath"] = json!("/evidence/evidence-canary");
        misplaced.body = serde_json::to_vec(&value).unwrap();
        refused.push(misplaced);
    }
    let mut duplicate = base.clone();
    duplicate.body = format!(
        "{{\"fieldPath\":\"/evidence/duplicate-canary\",{}",
        &located.to_string()[1..]
    )
    .into_bytes();
    refused.push(duplicate);
    let accepted_count = accepted.len();
    let total = accepted_count + refused.len();
    let fixture = test_client(
        std::iter::once(metadata_response())
            .chain(accepted)
            .chain(refused)
            .collect(),
    )
    .await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let binding = create_binding(&metadata);
    for index in 0..total {
        let error = fixture
            .client
            .create_record(
                &binding,
                &create_request(),
                &key("evidence-failure"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("dependency or protocol refusal");
        if index < accepted_count {
            assert_eq!(
                error.problem_code(),
                Some(BRegProblemCode::ActionEvidenceFailed)
            );
            assert_eq!(error.status(), Some(503));
            assert_eq!(error.trace_id().unwrap().as_str(), TRACE_ID);
        } else {
            assert!(matches!(
                error,
                BaseRegistryClientError::Protocol {
                    failure: BRegProtocolFailure::Problem,
                    ..
                }
            ));
        }
        let rendered = format!("{error:?}: {error}");
        assert!(
            !rendered.contains("canary")
                && !rendered.contains("/evidence/")
                && !rendered.contains("farmer-status")
        );
    }
    assert_eq!(
        fixture.requests.lock().unwrap().len(),
        1 + total,
        "dependency and malformed responses are never retried"
    );
}

#[tokio::test]
async fn action_request_paths_are_closed_bounded_and_discarded() {
    let request_invalid = problem_response(BRegProblemCode::RequestInvalid);
    let request_document: Value = serde_json::from_slice(&request_invalid.body).unwrap();
    let response_for = |base: &MockResponse, mut value: Value, path: Value| {
        value["fieldPath"] = path;
        MockResponse {
            body: serde_json::to_vec(&value).unwrap(),
            ..base.clone()
        }
    };

    let accepted_request_paths = [
        "",
        "/input",
        "/input/legalName",
        "/preconditions",
        "/preconditions/legalName",
        "/preconditions/legalName/ifMatch",
    ];
    let mut accepted = accepted_request_paths
        .iter()
        .map(|path| response_for(&request_invalid, request_document.clone(), json!(path)))
        .collect::<Vec<_>>();
    accepted.push(response_for(
        &request_invalid,
        request_document.clone(),
        json!(format!("/input/a{}", "b".repeat(63))),
    ));

    let action_refused = problem_response(BRegProblemCode::ActionRefused);
    let action_document: Value = serde_json::from_slice(&action_refused.body).unwrap();
    accepted.push(response_for(
        &action_refused,
        action_document.clone(),
        json!("/input/legalName"),
    ));

    let mut refused = [
        Value::Null,
        json!(12),
        json!({}),
        json!("input/legalName"),
        json!("/input/"),
        json!("/input/LegalName"),
        json!("/input/0name"),
        json!("/input/legal-name"),
        json!("/input/legal.name"),
        json!("/input/legalName/extra"),
        json!("/input/legal~1name"),
        json!("/input/legal%2fname"),
        json!("/input/legal\ncanary"),
        json!("/input/é"),
        json!(format!("/input/a{}", "b".repeat(64))),
        json!("/preconditions/"),
        json!("/preconditions/LegalName"),
        json!("/preconditions/legal-name"),
        json!("/preconditions/legalName/ifmatch"),
        json!("/preconditions/legalName/ifMatch/extra"),
        json!("/preconditions/legal~1name/ifMatch"),
        json!("/preconditions/legal%2fname/ifMatch"),
        json!("/other/legalName"),
    ]
    .into_iter()
    .map(|path| response_for(&request_invalid, request_document.clone(), path))
    .collect::<Vec<_>>();

    for path in [
        "",
        "/input",
        "/preconditions",
        "/preconditions/legalName",
        "/preconditions/legalName/ifMatch",
    ] {
        refused.push(response_for(
            &action_refused,
            action_document.clone(),
            json!(path),
        ));
    }
    let mut duplicate = request_invalid.clone();
    duplicate.body = format!(
        "{{\"fieldPath\":\"/input/duplicateCanary\",{}",
        response_for(
            &request_invalid,
            request_document.clone(),
            json!("/input/legalName"),
        )
        .body
        .strip_prefix(b"{")
        .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
        .unwrap()
    )
    .into_bytes();
    refused.push(duplicate);

    let accepted_count = accepted.len();
    let total = accepted_count + refused.len();
    let fixture = test_client(
        std::iter::once(metadata_response())
            .chain(accepted)
            .chain(refused)
            .collect(),
    )
    .await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let binding = create_binding(&metadata);
    for index in 0..total {
        let error = fixture
            .client
            .create_record(
                &binding,
                &create_request(),
                &key("action-path-problem"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("problem or malformed problem is returned");
        if index < accepted_count {
            assert!(matches!(
                error.problem_code(),
                Some(BRegProblemCode::RequestInvalid | BRegProblemCode::ActionRefused)
            ));
            assert_eq!(error.trace_id().unwrap().as_str(), TRACE_ID);
        } else {
            assert!(matches!(
                error,
                BaseRegistryClientError::Protocol {
                    failure: BRegProtocolFailure::Problem,
                    ..
                }
            ));
        }
        let rendered = format!("{error:?}: {error}");
        assert!(!rendered.contains("legalName"));
        assert!(!rendered.contains("duplicateCanary"));
        assert!(!rendered.contains("/input"));
        assert!(!rendered.contains("/preconditions"));
    }
    assert_eq!(fixture.requests.lock().unwrap().len(), 1 + total);
}

fn problem_response(code: BRegProblemCode) -> MockResponse {
    let mut body = json!({
        "type": format!(
            "https://id.registrystack.org/problems/registry-breg/{}",
            code.code().replace('.', "/")
        ),
        "title": problem_title(code.status()),
        "status": code.status(),
        "detail": problem_detail(code),
        "code": code.code(),
        "traceId": TRACE_ID
    });
    if code == BRegProblemCode::ActionRefused {
        body["refusalCode"] = json!(REFUSAL_CODE);
    }
    MockResponse::json(
        StatusCode::from_u16(code.status()).expect("registered status"),
        body,
    )
    .without_header("content-type")
    .with_header("content-type", "application/problem+json")
    .with_header("cache-control", "no-store")
}

fn problem_title(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        412 => "Precondition Failed",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        428 => "Precondition Required",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => panic!("unregistered problem status"),
    }
}

fn problem_detail(code: BRegProblemCode) -> &'static str {
    use BRegProblemCode as Code;

    match code {
        Code::ActionEvidenceFailed => "The declared Evidence dependency could not be accepted.",
        Code::ActionHandlerFailed => "The action handler could not produce an accepted result.",
        Code::ActionRefused => REFUSAL_LABEL,
        Code::AuthenticationRefused => "The bearer credential is missing or refused.",
        Code::IdempotencyConflict => "The idempotency key is bound to another request.",
        Code::IngestionChunkMismatch => "The chunk does not match the expected next chunk.",
        Code::IngestionProfileMismatch => {
            "The selected access profile does not match the run's bound profile."
        }
        Code::IngestionReceiptErased => "The stored receipt of the chunk was erased.",
        Code::IngestionRunBlocked => "The active package no longer matches the run binding.",
        Code::IngestionRunNotOpen => "The ingestion run is not open for this transition.",
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
        Code::RuntimeFieldEncryptionUnavailable => {
            "The Registry field-encryption service is unavailable."
        }
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
            "type": "https://example.test/problems/redirect",
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

#[tokio::test]
async fn prepared_create_roundtrip_reuses_exact_request_and_refuses_changed_bindings() {
    use registry_breg_client::BRegPreparedCreate;

    let mut route_metadata = metadata_fixture();
    route_metadata["entities"][0]["route"] = json!("alternate-companies");
    route_metadata["operations"][0]["path"] = json!("/v1/records/alternate-companies");
    route_metadata["operations"][1]["path"] = json!("/v1/records/alternate-companies/{record_id}");
    route_metadata["operations"][2]["path"] =
        json!("/v1/records/alternate-companies/{record_id}/actions/submit");

    let mut profile_metadata = metadata_fixture();
    profile_metadata["operations"][0]["accessProfile"] = json!("recovery-writer");
    profile_metadata["entities"][0]["operations"][0]["accessProfile"] = json!("recovery-writer");

    let mut revision_metadata = metadata_fixture();
    revision_metadata["revision"] =
        json!("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    let fixture = test_client(vec![
        MockResponse::json(StatusCode::OK, metadata_fixture_with_create_batch()),
        mutation_response(
            StatusCode::CREATED,
            BRegRecordFormat::JsonLd,
            RECORD_ID,
            true,
        ),
        MockResponse::json(StatusCode::OK, metadata_fixture_with_create_batch()),
        MockResponse::json(StatusCode::OK, route_metadata),
        MockResponse::json(StatusCode::OK, profile_metadata),
        MockResponse::json(StatusCode::OK, revision_metadata),
        mutation_response(
            StatusCode::CREATED,
            BRegRecordFormat::JsonLd,
            RECORD_ID,
            true,
        ),
    ])
    .await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let binding = create_binding(&metadata);
    let batch_binding = metadata
        .select_batch("company", "company-writer")
        .expect("select exact batch contract");
    let prepared = fixture
        .client
        .prepare_create(
            &binding,
            &create_request(),
            &key("attempt-create"),
            BRegRecordFormat::JsonLd,
        )
        .unwrap();
    fixture
        .client
        .create_record(
            &binding,
            &create_request(),
            &key("attempt-create"),
            BRegRecordFormat::JsonLd,
        )
        .await
        .unwrap();
    let saved = prepared.as_bytes().to_vec();
    drop(prepared);
    let prepared = BRegPreparedCreate::from_slice(&saved).unwrap();
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let binding = create_binding(&metadata);
    let route_binding = create_binding(
        &fixture
            .client
            .registry_contract(Some("company-writer"))
            .await
            .unwrap()
            .value,
    );
    let profile_binding = create_binding_for(
        &fixture
            .client
            .registry_contract(Some("recovery-writer"))
            .await
            .unwrap()
            .value,
        "recovery-writer",
    );
    let revision_binding = create_binding(
        &fixture
            .client
            .registry_contract(Some("company-writer"))
            .await
            .unwrap()
            .value,
    );
    let (request, idempotency, format) =
        fixture.client.recover_create(&binding, &prepared).unwrap();
    assert!(!format!("{request:?}").contains("attempt-create"));

    let request_count = fixture.requests.lock().unwrap().len();
    let token_count = fixture.token.0.load(Ordering::SeqCst);
    for changed_binding in [&route_binding, &profile_binding, &revision_binding] {
        assert!(matches!(
            fixture
                .client
                .create_record(changed_binding, &request, &idempotency, format)
                .await,
            Err(BaseRegistryClientError::InvalidRequest { .. })
        ));
        assert!(fixture
            .client
            .prepare_create(changed_binding, &request, &idempotency, format)
            .is_err());
    }
    let changed_key = key("changed-recovery-key");
    assert!(fixture
        .client
        .create_record(&binding, &request, &changed_key, format)
        .await
        .is_err());
    assert!(fixture
        .client
        .prepare_create(&binding, &request, &changed_key, format)
        .is_err());
    assert!(fixture
        .client
        .create_record(&binding, &request, &idempotency, BRegRecordFormat::Json,)
        .await
        .is_err());
    assert!(fixture
        .client
        .prepare_create(&binding, &request, &idempotency, BRegRecordFormat::Json,)
        .is_err());
    assert!(matches!(
        BRegBatchBuilder::new(&batch_binding).create(&request),
        Err(BRegBatchError::ItemContractMismatch)
    ));

    let ordinary = create_request();
    for compatible_binding in [
        &binding,
        &route_binding,
        &profile_binding,
        &revision_binding,
    ] {
        fixture
            .client
            .prepare_create(
                compatible_binding,
                &ordinary,
                &key("new-explicit-attempt"),
                BRegRecordFormat::Json,
            )
            .expect("ordinary request remains reusable with compatible authority");
    }
    assert_eq!(fixture.requests.lock().unwrap().len(), request_count);
    assert_eq!(fixture.token.0.load(Ordering::SeqCst), token_count);

    fixture
        .client
        .create_record(&binding, &request, &idempotency, format)
        .await
        .unwrap();
    let requests = fixture.requests.lock().unwrap().clone();
    let replay = &requests[6];
    assert_eq!(requests[1].uri, replay.uri);
    assert_eq!(requests[1].body, replay.body);
    assert_eq!(requests[1].accept, replay.accept);
    assert_eq!(requests[1].idempotency_key, replay.idempotency_key);
    assert!(fixture
        .client
        .recover_create(&revision_binding, &prepared)
        .is_err());
    let other = test_client(vec![]).await;
    assert!(other.client.recover_create(&binding, &prepared).is_err());
    assert_eq!(other.token.0.load(Ordering::SeqCst), 0);
    let mut tampered: Value = serde_json::from_slice(&saved).unwrap();
    tampered["body"] = json!("{\"data\":{\"secret\":\"canary\"}}");
    let tampered = BRegPreparedCreate::from_slice(&serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(fixture.client.recover_create(&binding, &tampered).is_err());
    assert_eq!(fixture.token.0.load(Ordering::SeqCst), token_count + 1);
    assert!(!format!("{tampered:?}").contains("canary"));
    assert!(BRegPreparedCreate::from_slice(b"{\"version\":1,\"version\":1}").is_err());
}

fn apply_metadata_fixture() -> Value {
    let mut metadata = metadata_fixture();
    let operation = &mut metadata["operations"][2];
    operation["id"] = json!("records.company.request.apply");
    operation["path"] = json!("/v1/records/companies/{record_id}/actions/apply");
    operation["operation"] = json!("apply_request");
    operation["request"]["schema"] = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object", "additionalProperties": false,
        "required": ["proposalVersion", "effectDigest"],
        "properties": {
            "proposalVersion": {"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX},
            "effectDigest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$", "description": "Digest of the immutable proposal effects displayed to the actor."},
            "reason": {"type": "string", "maxLength": 4096, "pattern": "^[^\\u0000]*$", "description": "Optional application explanation, preserved unchanged. At most 4096 Unicode characters; NUL is refused."}
        }
    });
    metadata["entities"][0]["operations"][2]["operation"] = json!("apply_request");
    metadata
}

#[tokio::test]
async fn prepared_lifecycle_recovers_original_apply_after_action_disappears() {
    use registry_breg_client::BRegPreparedLifecycle;
    let metadata = apply_metadata_fixture();
    let mut record = lifecycle_record_body();
    record["data"]["request"]["bregState"] = json!("submitted");
    record["data"]["request"]["editable"] = json!(false);
    let action = &mut record["data"]["request"]["actions"][0];
    action["operation"] = json!("apply_request");
    action["href"] = json!(format!(
        "/v1/records/companies/{RECORD_ID}/actions/apply?accessProfile=company-writer"
    ));
    action["proposalVersion"] = json!(7);
    action["effectDigest"] = json!(EFFECT_DIGEST);
    let RegistryRecordResponse::Single(original_record) =
        RegistryRecordResponse::from_value(record.clone(), RegistryRecordRepresentation::Json)
            .unwrap()
    else {
        panic!("single")
    };
    record["data"]["request"]["actions"] = json!([]);
    let RegistryRecordResponse::Single(current_record) =
        RegistryRecordResponse::from_value(record, RegistryRecordRepresentation::Json).unwrap()
    else {
        panic!("single")
    };
    let mut receipt = receipt_body(RECORD_ID, "applied");
    receipt["request"]["application"] = json!({"applicationId": OTHER_RECORD_ID, "proposalVersion": 7, "effectDigest": EFFECT_DIGEST, "appliedAt": "2026-09-08T00:00:00Z"});
    let mut changed = metadata.clone();
    changed["revision"] =
        json!("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let fixture = test_client(vec![
        MockResponse::json(StatusCode::OK, metadata.clone()),
        lifecycle_response(receipt.clone()),
        MockResponse::json(StatusCode::OK, metadata),
        lifecycle_response(receipt),
        metadata_response(),
        MockResponse::json(StatusCode::OK, changed),
    ])
    .await;
    let contract = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let authority = contract
        .select_lifecycle("company", "company-writer")
        .unwrap();
    let action = fixture
        .client
        .lifecycle_actions(&authority, &original_record)
        .unwrap()
        .remove(0)
        .with_reason("Applied after the registrar's sign-off.")
        .unwrap();
    let prepared = fixture
        .client
        .prepare_lifecycle_action(&authority, &original_record, &action, &key("attempt-apply"))
        .unwrap();
    // The mock returns the retained receipt, exercising exact wire replay. Real
    // commit-before-checkpoint transaction proof belongs to the native journey.
    fixture
        .client
        .execute_lifecycle_action(&action, &key("attempt-apply"))
        .await
        .unwrap();
    let saved = prepared.as_bytes().to_vec();
    let minimal: Value = serde_json::from_slice(&saved).unwrap();
    let legacy_saved = serde_json::to_vec(&json!({
        "version": 1,
        "source": minimal["source"],
        "registry_revision": action.registry_revision(),
        "record": original_record,
        "href": action.href(),
        "body": serde_json::to_string(action.body()).unwrap(),
        "if_match": action.if_match().as_str(),
        "idempotency_key": "attempt-apply",
    }))
    .unwrap();
    drop(prepared);
    let prepared = BRegPreparedLifecycle::from_slice(&saved).unwrap();
    let contract = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let authority = contract
        .select_lifecycle("company", "company-writer")
        .unwrap();
    assert!(fixture
        .client
        .lifecycle_actions(&authority, &current_record)
        .unwrap()
        .is_empty());
    let (recovered, key) = fixture
        .client
        .recover_lifecycle_action(&authority, &prepared)
        .unwrap();
    assert_eq!(action.operation(), recovered.operation());
    assert_eq!(action.href(), recovered.href());
    assert_eq!(action.if_match(), recovered.if_match());
    assert_eq!(action.body(), recovered.body());
    let legacy = BRegPreparedLifecycle::from_slice(&legacy_saved).unwrap();
    let (legacy_recovered, legacy_key) = fixture
        .client
        .recover_lifecycle_action(&authority, &legacy)
        .unwrap();
    assert_eq!(legacy_recovered, action);
    assert_eq!(legacy_key.as_str(), "attempt-apply");
    fixture
        .client
        .execute_lifecycle_action(&recovered, &key)
        .await
        .unwrap();
    let requests = fixture.requests.lock().unwrap().clone();
    assert_eq!(requests[1].uri, requests[3].uri);
    assert_eq!(requests[1].body, requests[3].body);
    assert_eq!(requests[1].if_match, requests[3].if_match);
    assert_eq!(requests[1].idempotency_key, requests[3].idempotency_key);
    let contract = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let revoked_authority = contract
        .select_lifecycle("company", "company-writer")
        .unwrap();
    assert!(fixture
        .client
        .recover_lifecycle_action(&revoked_authority, &prepared)
        .is_err());
    let contract = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let changed_authority = contract
        .select_lifecycle("company", "company-writer")
        .unwrap();
    let token_count = fixture.token.0.load(Ordering::SeqCst);
    assert!(fixture
        .client
        .recover_lifecycle_action(&changed_authority, &prepared)
        .is_err());
    for (field, value) in [
        ("href", json!("https://attacker.invalid/")),
        ("body", json!("{}")),
        ("ifMatch", json!("\"changed\"")),
    ] {
        let mut tampered: Value = serde_json::from_slice(&saved).unwrap();
        if field == "body" {
            tampered[field] = value;
        } else {
            tampered["action"][field] = value;
        }
        let tampered =
            BRegPreparedLifecycle::from_slice(&serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(fixture
            .client
            .recover_lifecycle_action(&authority, &tampered)
            .is_err());
    }
    let mut tampered: Value = serde_json::from_slice(&saved).unwrap();
    tampered["authority"]["profile"] = json!("other-profile");
    let tampered =
        BRegPreparedLifecycle::from_slice(&serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(fixture
        .client
        .recover_lifecycle_action(&authority, &tampered)
        .is_err());
    assert_eq!(fixture.token.0.load(Ordering::SeqCst), token_count);
    let other = test_client(vec![]).await;
    assert!(other
        .client
        .recover_lifecycle_action(&authority, &prepared)
        .is_err());
    assert_eq!(other.token.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn record_revisions_uses_bounded_native_route_and_refuses_invalid_selectors_before_io() {
    let fixture = test_client(vec![MockResponse::json(
        StatusCode::OK,
        json!({"items": [], "pageInfo": {"hasNextPage": false}}),
    )])
    .await;
    let result = fixture
        .client
        .record_revisions("companies", RECORD_ID, Some("company-writer"))
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(result.value.as_bytes()).unwrap()["items"],
        json!([])
    );
    let requests = fixture.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].uri,
        format!(
            "/tenant/base/v1/records/companies/{RECORD_ID}/revisions?accessProfile=company-writer"
        )
    );
    for (route, id, profile) in [
        ("../companies", RECORD_ID, Some("company-writer")),
        ("companies", "arbitrary", Some("company-writer")),
        ("companies", RECORD_ID, Some("invalid?profile")),
    ] {
        assert!(fixture
            .client
            .record_revisions(route, id, profile)
            .await
            .is_err());
    }
    assert_eq!(fixture.token.0.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
}

fn ingestion_response(status: StatusCode, body: Value) -> MockResponse {
    MockResponse::json(status, body)
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept")
}

fn ingestion_run_wire(status: &str) -> Value {
    json!({
        "runId": RECORD_ID,
        "status": status,
        "blockedReason": null,
        "entityId": "company",
        "operation": "create",
        "profileId": INGESTION_PROFILE,
        "packageRevision": "revision-1",
        "schemaFingerprint": "fingerprint-1",
        "inputDigest": INGESTION_INPUT_DIGEST,
        "inputLength": 4321,
        "itemCount": 10,
        "chunkCount": 3,
        "chunkAlgorithmVersion": BREG_INGESTION_CHUNK_ALGORITHM_VERSION,
        "maximumItems": 100,
        "maximumBytes": 1048576,
        "nextChunkIndex": 1,
        "committedItems": 0,
        "committedPrefixDigest": ingestion_prefix_digest(&[]),
        "lastAttempt": null,
        "createdAt": "2026-09-19T00:00:00Z",
        "updatedAt": "2026-09-19T00:01:00Z",
        "complete": false
    })
}

fn ingestion_receipt_wire() -> Value {
    // The receipt digest is the digest of the exact canonical batch body the
    // tests' chunk submits, the way a run binds a committed receipt.
    json!({
        "chunkIndex": 0,
        "digest": ingestion_chunk_digest(&[json!(
            {"operation": "create", "data": {"legalName": "Example Ltd"}}
        )])
        .unwrap(),
        "replayed": false,
        "erased": false,
        "batch": {
            "snapshot": format!("breg1_{OTHER_RECORD_ID}"),
            "results": [
                {"operation": "create", "id": RECORD_ID, "revision": 1, "etag": "\"breg-record-v1-abcdef012345\"", "data": {"legalName": "Example Ltd"}}
            ]
        }
    })
}

fn ingestion_announcement(profile: &str) -> BRegIngestionRunRequest {
    BRegIngestionRunRequest::builder()
        .operation(BRegBatchOperation::Create)
        .profile(profile)
        .unwrap()
        .package_revision("revision-1")
        .unwrap()
        .schema_fingerprint("fingerprint-1")
        .unwrap()
        .input_digest(INGESTION_INPUT_DIGEST)
        .unwrap()
        .input_length(4321)
        .item_count(10)
        .unwrap()
        .chunk_count(3)
        .unwrap()
        .chunk_algorithm_version(BREG_INGESTION_CHUNK_ALGORITHM_VERSION)
        .unwrap()
        .build()
        .unwrap()
}

#[tokio::test]
async fn ingestion_exchanges_select_the_announced_run_access_profile() {
    let page = json!({"runs": [], "hasMore": false, "nextAfter": null});
    let fixture = test_client(vec![
        ingestion_response(
            StatusCode::CREATED,
            json!({"run": ingestion_run_wire("open")}),
        ),
        ingestion_response(
            StatusCode::OK,
            json!({"run": ingestion_run_wire("open"), "receipt": ingestion_receipt_wire()}),
        ),
        ingestion_response(StatusCode::OK, json!({"receipt": ingestion_receipt_wire()})),
        ingestion_response(StatusCode::OK, json!({"run": ingestion_run_wire("open")})),
        ingestion_response(StatusCode::OK, json!({"run": ingestion_run_wire("open")})),
        ingestion_response(
            StatusCode::OK,
            json!({"run": ingestion_run_wire("cancelled")}),
        ),
        ingestion_response(StatusCode::OK, page.clone()),
        ingestion_response(StatusCode::OK, page),
    ])
    .await;
    let client = &fixture.client;
    let run_id = client
        .create_ingestion_run("company", &ingestion_announcement(INGESTION_PROFILE))
        .await
        .unwrap()
        .value
        .run_id();
    let chunk = BRegIngestionChunk::new(
        0,
        vec![json!({"operation": "create", "data": {"legalName": "Example Ltd"}})],
        ingestion_prefix_digest(b"source-prefix"),
    )
    .unwrap();
    client
        .submit_ingestion_chunk("company", run_id, &chunk, INGESTION_PROFILE)
        .await
        .unwrap();
    client
        .ingestion_chunk_receipt("company", run_id, 0, INGESTION_PROFILE)
        .await
        .unwrap();
    client
        .read_ingestion_run("company", run_id, Some(INGESTION_PROFILE))
        .await
        .unwrap();
    client
        .read_ingestion_run("company", run_id, None)
        .await
        .unwrap();
    client
        .cancel_ingestion_run("company", run_id, Some(INGESTION_PROFILE))
        .await
        .unwrap();
    let queried = BRegIngestionRunListQuery::default()
        .access_profile(INGESTION_PROFILE)
        .unwrap()
        .limit(25)
        .unwrap()
        .status(BRegIngestionRunStatus::Open);
    client
        .list_ingestion_runs("company", &queried)
        .await
        .unwrap();
    client
        .list_ingestion_runs("company", &BRegIngestionRunListQuery::default())
        .await
        .unwrap();

    // Every run-scoped exchange selects the run's access profile; the reads
    // that accept one send it exactly when it is given.
    let requests = fixture.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 8);
    let expected = [
        "/tenant/base/v1/records/company/ingestion-runs?accessProfile=importer.v1".to_owned(),
        format!("/tenant/base/v1/records/company/ingestion-runs/{RECORD_ID}/chunks?accessProfile=importer.v1"),
        format!("/tenant/base/v1/records/company/ingestion-runs/{RECORD_ID}/chunks/0/receipt?accessProfile=importer.v1"),
        format!("/tenant/base/v1/records/company/ingestion-runs/{RECORD_ID}?accessProfile=importer.v1"),
        format!("/tenant/base/v1/records/company/ingestion-runs/{RECORD_ID}"),
        format!("/tenant/base/v1/records/company/ingestion-runs/{RECORD_ID}/cancel?accessProfile=importer.v1"),
        "/tenant/base/v1/records/company/ingestion-runs?accessProfile=importer.v1&limit=25&status=open".to_owned(),
        "/tenant/base/v1/records/company/ingestion-runs".to_owned(),
    ];
    for (request, uri) in requests.iter().zip(expected) {
        assert_eq!(request.uri, uri);
    }
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[1].method, "POST");
    assert_eq!(requests[2].method, "GET");
    assert_eq!(requests[3].method, "GET");
    assert_eq!(requests[4].method, "GET");
    assert_eq!(requests[5].method, "POST");
    assert_eq!(requests[6].method, "GET");
    assert_eq!(requests[7].method, "GET");

    // A profile identifier the wire grammar refuses is rejected before any
    // token acquisition or IO.
    let before = fixture.requests.lock().unwrap().len();
    let tokens = fixture.token.0.load(Ordering::SeqCst);
    assert!(client
        .submit_ingestion_chunk("company", run_id, &chunk, "Invalid Profile")
        .await
        .is_err());
    assert!(client
        .ingestion_chunk_receipt("company", run_id, 0, "UPPER")
        .await
        .is_err());
    assert!(client
        .create_ingestion_run("company", &ingestion_announcement("Invalid Profile"))
        .await
        .is_err());
    assert_eq!(fixture.requests.lock().unwrap().len(), before);
    assert_eq!(fixture.token.0.load(Ordering::SeqCst), tokens);
}

#[tokio::test]
async fn ingestion_answers_are_bound_to_the_requested_run_and_chunk() {
    // A structurally valid answer for another run or chunk would silently
    // corrupt the caller's checkpoint or retained receipt, so every
    // run-scoped exchange refuses a body that names another identity.
    enum Exchange {
        Submit,
        Read,
        Cancel,
        Receipt,
    }
    let chunk = BRegIngestionChunk::new(
        0,
        vec![json!({"operation": "create", "data": {"legalName": "Example Ltd"}})],
        ingestion_prefix_digest(b"source-prefix"),
    )
    .unwrap();
    let run_id = Uuid::parse_str(RECORD_ID).unwrap();
    let mut other_run = ingestion_run_wire("open");
    other_run["runId"] = json!(OTHER_RECORD_ID);
    let mut other_chunk_receipt = ingestion_receipt_wire();
    other_chunk_receipt["chunkIndex"] = json!(1);
    let mut other_digest_receipt = ingestion_receipt_wire();
    other_digest_receipt["digest"] = json!(INGESTION_INPUT_DIGEST);

    for (body, exchange) in [
        (
            json!({"run": other_run.clone(), "receipt": ingestion_receipt_wire()}),
            Exchange::Submit,
        ),
        (
            json!({"run": ingestion_run_wire("open"), "receipt": other_chunk_receipt.clone()}),
            Exchange::Submit,
        ),
        (
            json!({"run": ingestion_run_wire("open"), "receipt": other_digest_receipt.clone()}),
            Exchange::Submit,
        ),
        (json!({"run": other_run.clone()}), Exchange::Read),
        (json!({"run": other_run}), Exchange::Cancel),
        (json!({"receipt": other_chunk_receipt}), Exchange::Receipt),
    ] {
        let fixture = test_client(vec![ingestion_response(StatusCode::OK, body)]).await;
        let error = match exchange {
            Exchange::Submit => fixture
                .client
                .submit_ingestion_chunk("company", run_id, &chunk, INGESTION_PROFILE)
                .await
                .expect_err("a submission for another run or chunk is refused"),
            Exchange::Read => fixture
                .client
                .read_ingestion_run("company", run_id, None)
                .await
                .expect_err("a run answer naming another run is refused"),
            Exchange::Cancel => fixture
                .client
                .cancel_ingestion_run("company", run_id, None)
                .await
                .expect_err("a cancellation naming another run is refused"),
            Exchange::Receipt => fixture
                .client
                .ingestion_chunk_receipt("company", run_id, 0, INGESTION_PROFILE)
                .await
                .expect_err("a receipt for another chunk is refused"),
        };
        assert!(
            matches!(
                error,
                BaseRegistryClientError::Protocol {
                    failure: BRegProtocolFailure::Body,
                    ..
                }
            ),
            "the mismatched body is a protocol body failure"
        );
    }
}

#[tokio::test]
async fn immediate_action_refusals_carry_their_declared_reason_and_stay_bounded() {
    let base = problem_response(BRegProblemCode::ActionRefused);
    let document: Value = serde_json::from_slice(&base.body).unwrap();
    let response_for = |value: Value| {
        let mut response = base.clone();
        response.body = serde_json::to_vec(&value).unwrap();
        response
    };
    let mut accepted = vec![(base.clone(), REFUSAL_CODE.to_owned())];
    for (path, refusal) in [
        ("/input/givenName", REFUSAL_CODE),
        ("/input/a", "a"),
        ("/input/name9", "declared.reason_9-canary"),
    ] {
        let mut value = document.clone();
        value["fieldPath"] = json!(path);
        value["refusalCode"] = json!(refusal);
        value["detail"] = json!("A declared label canary.");
        accepted.push((response_for(value), refusal.to_owned()));
    }
    let mut long = document.clone();
    long["detail"] = json!("é".repeat(256));
    long["refusalCode"] = json!("z".repeat(128));
    accepted.push((response_for(long), "z".repeat(128)));
    let mut refused = Vec::new();
    for refusal in [
        Value::Null,
        json!(12),
        json!(""),
        json!("z".repeat(129)),
        json!("blank\nname"),
    ] {
        let mut value = document.clone();
        value["refusalCode"] = refusal;
        refused.push(response_for(value));
    }
    let mut absent = document.clone();
    absent.as_object_mut().unwrap().remove("refusalCode");
    refused.push(response_for(absent));
    for path in [
        json!("/input/"),
        json!("/input/Given"),
        json!("/input/9given"),
        json!("/input/given-name"),
        json!("/input/given.name"),
        json!("/input/givenName/raw"),
        json!("input/givenName"),
        json!("/evidence/status"),
        json!(format!("/input/a{}", "b".repeat(64))),
    ] {
        let mut value = document.clone();
        value["fieldPath"] = path;
        refused.push(response_for(value));
    }
    for detail in [json!(""), json!("é".repeat(257)), json!("label\ncanary")] {
        let mut value = document.clone();
        value["detail"] = detail;
        refused.push(response_for(value));
    }
    let mut paired = document.clone();
    paired["entityId"] = json!("company");
    paired["fieldId"] = json!("registration_number");
    refused.push(response_for(paired));
    for code in [
        BRegProblemCode::MutationConflict,
        BRegProblemCode::ActionHandlerFailed,
    ] {
        for (member, value) in [
            ("refusalCode", json!(REFUSAL_CODE)),
            ("fieldPath", json!("/input/givenName")),
        ] {
            let mut misplaced = problem_response(code);
            let mut body: Value = serde_json::from_slice(&misplaced.body).unwrap();
            body[member] = value;
            misplaced.body = serde_json::to_vec(&body).unwrap();
            refused.push(misplaced);
        }
    }
    let mut request_invalid = problem_response(BRegProblemCode::RequestInvalid);
    let mut request_invalid_body: Value = serde_json::from_slice(&request_invalid.body).unwrap();
    request_invalid_body["refusalCode"] = json!(REFUSAL_CODE);
    request_invalid.body = serde_json::to_vec(&request_invalid_body).unwrap();
    refused.push(request_invalid);
    let mut duplicate = base.clone();
    duplicate.body = format!(
        "{{\"refusalCode\":\"duplicate-canary\",{}",
        &document.to_string()[1..]
    )
    .into_bytes();
    refused.push(duplicate);
    // One entry per exchange, in order: the declared code an accepted refusal
    // must carry, and nothing for a document the client has to fail closed on.
    let expected: Vec<Option<String>> = accepted
        .iter()
        .map(|(_, code)| Some(code.clone()))
        .chain(refused.iter().map(|_| None))
        .collect();
    let total = expected.len();
    let fixture = test_client(
        std::iter::once(metadata_response())
            .chain(accepted.into_iter().map(|(response, _)| response))
            .chain(refused)
            .collect(),
    )
    .await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let binding = create_binding(&metadata);
    for declared in &expected {
        let error = fixture
            .client
            .create_record(
                &binding,
                &create_request(),
                &key("action-refusal"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("refusal or protocol failure");
        if let Some(code) = declared {
            assert_eq!(error.problem_code(), Some(BRegProblemCode::ActionRefused));
            assert_eq!(error.status(), Some(422));
            assert_eq!(
                error.refusal_code().map(BRegRefusalCode::as_str),
                Some(code.as_str())
            );
        } else {
            assert_eq!(error.refusal_code(), None);
            assert!(matches!(
                error,
                BaseRegistryClientError::Protocol {
                    failure: BRegProtocolFailure::Problem,
                    ..
                }
            ));
        }
        assert!(!format!("{error:?}: {error}").contains("canary"));
    }
    assert_eq!(fixture.requests.lock().unwrap().len(), 1 + total);
}
