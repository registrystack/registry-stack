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
    ingestion_chunk_digest, ingestion_prefix_digest, BRegActionAvailabilityRequest,
    BRegActionError, BRegActionInvocationRequest, BRegBatchBuilder, BRegBatchError,
    BRegBatchOperation, BRegCreateRequest, BRegDirectWrite, BRegEtag, BRegIdempotencyKey,
    BRegIngestionChunk, BRegIngestionRunListQuery, BRegIngestionRunRequest, BRegIngestionRunStatus,
    BRegMetadataErrorKind, BRegMetadataSelectionErrorKind, BRegPatchRequest, BRegProblemCode,
    BRegProblemFieldPath, BRegProtocolFailure, BRegRecordFormat, BRegRefusalCode,
    BaseRegistryClient, BaseRegistryClientConfig, BaseRegistryClientError,
    BREG_INGESTION_CHUNK_ALGORITHM_VERSION, REGISTRY_RECORD_CONTEXT_IDENTIFIER,
};
use registry_platform_httputil::client::{
    BearerToken, TokenError, TokenProvider, DEFAULT_MUTATION_RETRIES,
};
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
const OTHER_RECORD_ID: &str = "00000000-0000-4000-8000-000000000002";
const SERVER_ETAG: &str = "\"breg-record-000000000001\"";
const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
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
    serve_test_client(responses, DEFAULT_MUTATION_RETRIES).await
}

/// A client that reads each scripted answer exactly once: the same-key resend
/// of an unknown outcome is disabled, so a 5xx answer under test is decoded
/// once rather than resent.
async fn single_attempt_client(responses: Vec<MockResponse>) -> TestClient {
    serve_test_client(responses, 0).await
}

async fn serve_test_client(responses: Vec<MockResponse>, max_mutation_retries: u8) -> TestClient {
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
    .with_token_provider(token.clone())
    .with_maximum_mutation_retries(max_mutation_retries);
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
        "sourceRecordType": "company",
        "responseRecordType": "company",
        "accessProfile": "company-writer",
        "requiredCapabilities": capabilities,
        "recordTypeLabel": "Companies",
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": ["legal-name"],
        "fields": [field()],
        "readableFields": ["legal-name"],
        "readableRequestFields": [],
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
        "submit-request",
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
        "metadataVersion": "2",
        "recordTypes": [{
            "id": "company",
            "datasetIdentifier": "legal-entities",
            "route": "companies",
            "operations": [
                {"operation": "create", "accessProfile": "company-writer"},
                {"operation": "patch", "accessProfile": "company-writer"},
                {"operation": "submit-request", "accessProfile": "company-writer"}
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
    metadata["recordTypes"][0]["operations"]
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
            "domainData": {"legalName": "Example Ltd"}
        },
        "meta": {
            "registryIdentifier": "business-registry",
            "datasetIdentifier": "legal-entities",
            "recordTypeIdentifier": "company"
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
    fixture["recordTypes"] = json!("not-an-array");
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
async fn registry_contract_reports_the_engine_version_even_when_the_document_fails_to_decode() {
    let mut malformed = metadata_fixture();
    malformed["recordTypes"] = json!("not-an-array");
    let fixture = test_client(vec![
        metadata_response().with_header("registry-engine-version", "0.34.0"),
        MockResponse::json(StatusCode::OK, malformed)
            .with_header("registry-engine-version", "0.33.0"),
    ])
    .await;

    let (version, contract) = fixture
        .client
        .registry_contract_and_engine_version(Some("company-writer"))
        .await;
    assert_eq!(version.as_deref(), Some("0.34.0"));
    let contract = contract.expect("registry metadata decodes");
    assert_eq!(contract.metadata.engine_version(), Some("0.34.0"));

    let (version, contract) = fixture
        .client
        .registry_contract_and_engine_version(Some("company-writer"))
        .await;
    assert_eq!(version.as_deref(), Some("0.33.0"));
    assert_eq!(
        contract
            .expect_err("malformed registry metadata is refused")
            .metadata_error_kind(),
        Some(BRegMetadataErrorKind::Shape)
    );
}

#[tokio::test]
async fn registry_contract_reports_no_engine_version_for_an_absent_or_malformed_header() {
    let fixture = test_client(vec![
        metadata_response(),
        metadata_response().with_header("registry-engine-version", "0.34.0 (linux)"),
        metadata_response().with_header("registry-engine-version", &"9".repeat(65)),
    ])
    .await;

    for _ in 0..3 {
        let (version, contract) = fixture
            .client
            .registry_contract_and_engine_version(Some("company-writer"))
            .await;
        assert_eq!(version, None);
        assert_eq!(
            contract
                .expect("metadata decodes")
                .metadata
                .engine_version(),
            None
        );
    }
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
}

#[tokio::test]
async fn every_registered_problem_is_accepted_exactly_for_a_direct_write() {
    let responses = std::iter::once(metadata_response())
        .chain(BRegProblemCode::ALL.into_iter().map(problem_response))
        .collect();
    let fixture = single_attempt_client(responses).await;
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
async fn retired_plan_problems_have_only_generic_unknown_problem_semantics() {
    let retired = MockResponse::json(StatusCode::BAD_REQUEST, json!({
        "type": "https://id.registrystack.org/problems/registry-breg/request/plan_refused",
        "title": "Bad Request",
        "status": 400,
        "detail": "The change-request planner refused the submission: change_request.planner.disposition.",
        "code": "request.plan_refused",
        "traceId": TRACE_ID,
        "fieldPath": "/private/legacy-location",
        "refusalCode": "private-legacy-refusal",
        "constraintId": {"future": "private-legacy-constraint"},
        "constraintKind": null,
    }))
    .without_header("content-type")
    .with_header("content-type", "application/problem+json")
    .with_header("cache-control", "no-store");
    let fixture = single_attempt_client(vec![metadata_response(), retired]).await;
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
            &key("retired-plan"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), "problem");
    assert_eq!(error.status(), Some(400));
    assert_eq!(error.problem_code(), None);
    assert!(error.field_path().is_none());
    assert!(error.refusal_code().is_none());
    assert!(error.constraint().is_none());
    assert!(!error.is_outcome_unknown());
    assert!(!error.to_string().contains("planner"));
    assert!(!format!("{error:?}").contains("private-legacy"));
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn row_local_constraint_conflicts_remain_typed() {
    let generic = problem_response(BRegProblemCode::MutationConflict);
    let base: Value = serde_json::from_slice(&generic.body).unwrap();
    let compare = json!({
        "recordType": "company", "constraintId": "valid-period",
        "constraintKind": "compare", "left": "valid-from", "right": "valid-to",
    });
    let accepted = [
        compare.clone(),
        json!({"recordType": "company", "constraintId": "int-range-0123456789abcdef",
            "constraintKind": "int-range", "field": "quantity"}),
        json!({"recordType": "company", "constraintId": "allowed-status",
            "constraintKind": "vocabulary", "field": "status"}),
        json!({"recordType": "x".repeat(128), "constraintId": "y".repeat(128),
            "constraintKind": "compare", "left": "l".repeat(128), "right": "r".repeat(128)}),
    ];
    let response_for = |extension: &Value| {
        let mut body = base.clone();
        body.as_object_mut()
            .unwrap()
            .extend(extension.as_object().unwrap().clone());
        MockResponse {
            body: serde_json::to_vec(&body).unwrap(),
            ..generic.clone()
        }
    };
    let mut refused = Vec::new();
    for member in [
        "recordType",
        "constraintId",
        "constraintKind",
        "left",
        "right",
    ] {
        let mut incomplete = compare.clone();
        incomplete.as_object_mut().unwrap().remove(member);
        refused.push(response_for(&incomplete));
        for value in [
            Value::Null,
            json!(42),
            json!(""),
            json!("x".repeat(129)),
            json!("id\ncanary"),
        ] {
            let mut malformed = compare.clone();
            malformed[member] = value;
            refused.push(response_for(&malformed));
        }
        let response = response_for(&compare);
        refused.push(MockResponse {
            body: format!(
                "{{\"{member}\":\"duplicate-canary\",{}",
                &String::from_utf8(response.body.clone()).unwrap()[1..]
            )
            .into_bytes(),
            ..response
        });
    }
    for kind in ["unique", "temporal-non-overlap", "future-kind"] {
        let mut malformed = compare.clone();
        malformed["constraintKind"] = json!(kind);
        refused.push(response_for(&malformed));
    }
    for member in ["field", "fieldId"] {
        let mut mixed = compare.clone();
        mixed[member] = json!("extra-field");
        refused.push(response_for(&mixed));
    }
    for kind in ["int-range", "vocabulary"] {
        let mut malformed = compare.clone();
        malformed["constraintKind"] = json!(kind);
        malformed["field"] = json!("quantity");
        refused.push(response_for(&malformed));
        let mut incomplete = accepted[1].clone();
        incomplete["constraintKind"] = json!(kind);
        incomplete.as_object_mut().unwrap().remove("field");
        refused.push(response_for(&incomplete));
    }
    let mut misplaced: Value =
        serde_json::from_slice(&problem_response(BRegProblemCode::RequestInvalid).body).unwrap();
    misplaced
        .as_object_mut()
        .unwrap()
        .extend(compare.as_object().unwrap().clone());
    refused.push(MockResponse {
        body: serde_json::to_vec(&misplaced).unwrap(),
        ..problem_response(BRegProblemCode::RequestInvalid)
    });
    let refused_count = refused.len();
    let mut additive = compare.clone();
    additive["futureMember"] = json!({"ignored": true});
    let fixture = single_attempt_client(
        accepted
            .iter()
            .map(response_for)
            .chain([response_for(&additive), generic.clone()])
            .chain(refused)
            .collect(),
    )
    .await;
    for expected in accepted.iter().chain([&compare]) {
        let error = fixture
            .client
            .get_record("companies", RECORD_ID, &Default::default())
            .await
            .unwrap_err();
        assert_eq!(
            error.problem_code(),
            Some(BRegProblemCode::MutationConflict)
        );
        assert!(!error.is_outcome_unknown());
        let constraint = error.constraint().expect("declared constraint retained");
        assert_eq!(serde_json::to_value(constraint).unwrap(), *expected);
        assert_eq!(constraint.record_type(), expected["recordType"]);
        assert_eq!(constraint.id(), expected["constraintId"]);
        assert_eq!(constraint.kind(), expected["constraintKind"]);
        for value in [constraint.record_type(), constraint.id()] {
            assert!(!error.to_string().contains(value));
            assert!(!format!("{error:?}").contains(value));
        }
    }
    let generic = fixture
        .client
        .get_record("companies", RECORD_ID, &Default::default())
        .await
        .unwrap_err();
    assert_eq!(
        generic.problem_code(),
        Some(BRegProblemCode::MutationConflict)
    );
    assert!(generic.constraint().is_none());
    for _ in 0..refused_count {
        let error = fixture
            .client
            .get_record("companies", RECORD_ID, &Default::default())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BaseRegistryClientError::Protocol {
                failure: BRegProtocolFailure::Problem,
                ..
            }
        ));
        assert!(error.constraint().is_none());
        assert!(!format!("{error:?}").contains("canary"));
    }
}

#[tokio::test]
async fn action_guard_failures_reject_undeclared_constraint_and_field_extensions() {
    // A commit guard is not a row-local SQL constraint. Only the fixed
    // value-free Problem is admitted for this code.
    for extensions in [
        json!({}),
        json!({"recordType":"company", "constraintId":"canary-current-status",
            "constraintKind":"vocabulary", "field":"status"}),
        json!({"recordType":"company", "fieldId":"canary-status"}),
    ] {
        let generic = problem_response(BRegProblemCode::ActionGuardFailed);
        let mut body: Value = serde_json::from_slice(&generic.body).unwrap();
        body.as_object_mut()
            .unwrap()
            .extend(extensions.as_object().unwrap().clone());
        let response = MockResponse {
            body: serde_json::to_vec(&body).unwrap(),
            ..generic
        };
        let fixture = single_attempt_client(vec![metadata_response(), response]).await;
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
                &key("guard-failed"),
                BRegRecordFormat::Json,
            )
            .await
            .unwrap_err();
        if extensions.as_object().unwrap().is_empty() {
            assert_eq!(
                error.problem_code(),
                Some(BRegProblemCode::ActionGuardFailed)
            );
            assert!(!error.is_outcome_unknown());
        } else {
            assert!(matches!(
                error,
                BaseRegistryClientError::Protocol {
                    failure: BRegProtocolFailure::Problem,
                    ..
                }
            ));
        }
        assert!(error.constraint().is_none());
        assert!(!format!("{error:?}: {error}").contains("canary"));
    }
}

#[tokio::test]
async fn pattern_conflicts_preserve_typed_conflicts_and_reject_inexact_metadata() {
    let generic = problem_response(BRegProblemCode::MutationConflict);
    let mut pattern: Value = serde_json::from_slice(&generic.body).unwrap();
    pattern["detail"] = json!("The field does not conform to its declared storage pattern.");
    let without_location = pattern.clone();
    pattern["recordType"] = json!("company");
    pattern["fieldId"] = json!("registration_number");
    let response_for = |value: Value| {
        let mut response = generic.clone();
        response.body = serde_json::to_vec(&value).unwrap();
        response
    };
    let mut bad = Vec::new();
    let mut removed_location = pattern.clone();
    removed_location
        .as_object_mut()
        .unwrap()
        .remove("recordType");
    removed_location["entityId"] = json!("company");
    bad.push(response_for(removed_location));
    for member in ["recordType", "fieldId"] {
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
    misplaced["recordType"] = json!("company");
    misplaced["fieldId"] = json!("registration_number");
    bad.push(MockResponse {
        body: serde_json::to_vec(&misplaced).unwrap(),
        ..evidence
    });
    for member in ["recordType", "fieldId", "detail"] {
        let mut duplicate = generic.clone();
        duplicate.body = format!(
            "{{\"{member}\":\"duplicate-canary\",{}",
            &pattern.to_string()[1..]
        )
        .into_bytes();
        bad.push(duplicate);
    }
    let failures = bad.len();
    let mut additive = pattern.clone();
    additive["extra"] = json!({"future": "response-canary"});
    let accepted = [
        generic.clone(),
        response_for(without_location),
        response_for(pattern),
        response_for(additive),
    ];
    let accepted_count = accepted.len();
    let responses = std::iter::once(metadata_response())
        .chain(accepted)
        .chain(bad)
        .collect();
    let fixture = single_attempt_client(responses).await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let binding = create_binding(&metadata);
    for index in 0..accepted_count + failures {
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
        if index < accepted_count {
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
        1 + accepted_count + failures,
        "each scripted answer is read by exactly one exchange"
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
    let mut additive = located.clone();
    additive["extra"] = json!({"future": "private-canary"});
    accepted.push(response_for(additive));
    for (member, value) in [
        ("refusalCode", json!("private-canary")),
        ("recordType", json!("private-canary")),
        ("status", json!(409)),
        ("traceId", json!("0123456789abcdef0123456789abcdef")),
    ] {
        let mut invalid = located.clone();
        invalid[member] = value;
        refused.push(response_for(invalid));
    }
    let mut paired = located.clone();
    paired["recordType"] = json!("company");
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
    let fixture = single_attempt_client(
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
        "each scripted answer is read by exactly one exchange"
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

#[tokio::test]
async fn timer_window_problem_fields_are_paired_bounded_and_discarded() {
    let request_invalid = problem_response(BRegProblemCode::RequestInvalid);
    let document: Value = serde_json::from_slice(&request_invalid.body).unwrap();
    let response_for = |base: &MockResponse, value: Value| MockResponse {
        body: serde_json::to_vec(&value).unwrap(),
        ..base.clone()
    };
    let mut paired = document.clone();
    paired["atField"] = json!("activate-at");
    paired["notAfterField"] = json!("expires-at");

    let mut additive = paired.clone();
    additive["futureMember"] = json!({"private": "future-canary"});
    let mut future = paired.clone();
    future["type"] =
        json!("https://id.registrystack.org/problems/registry-breg/request/future_invalid");
    future["code"] = json!("request.future_invalid");
    future["atField"] = json!({"private": "future-at-canary"});
    future["notAfterField"] = Value::Null;
    let future_response = response_for(&request_invalid, future);
    let accepted = [
        response_for(&request_invalid, paired.clone()),
        response_for(&request_invalid, additive),
        future_response,
    ];

    let mut refused = Vec::new();
    for member in ["atField", "notAfterField"] {
        let mut partial = paired.clone();
        partial.as_object_mut().unwrap().remove(member);
        refused.push(response_for(&request_invalid, partial));
    }
    for (member, value) in [
        ("atField", Value::Null),
        ("atField", json!(12)),
        ("notAfterField", json!({})),
        ("notAfterField", json!("field\nprivate-canary")),
        ("atField", json!("")),
        ("notAfterField", json!("x".repeat(129))),
    ] {
        let mut malformed = paired.clone();
        malformed[member] = value;
        refused.push(response_for(&request_invalid, malformed));
    }
    let query_invalid = problem_response(BRegProblemCode::QueryInvalid);
    let mut misplaced: Value = serde_json::from_slice(&query_invalid.body).unwrap();
    misplaced["atField"] = json!("activate-at");
    misplaced["notAfterField"] = json!("expires-at");
    refused.push(response_for(&query_invalid, misplaced));
    for member in ["atField", "notAfterField"] {
        let mut duplicate = request_invalid.clone();
        duplicate.body = format!(
            "{{\"{member}\":\"duplicate-private-canary\",{}",
            &paired.to_string()[1..]
        )
        .into_bytes();
        refused.push(duplicate);
    }

    let accepted_count = accepted.len();
    let total = accepted_count + refused.len();
    let fixture = single_attempt_client(accepted.into_iter().chain(refused).collect()).await;
    for index in 0..total {
        let error = fixture
            .client
            .get_record("companies", RECORD_ID, &Default::default())
            .await
            .expect_err("problem or malformed problem is returned");
        if index < accepted_count {
            if index < 2 {
                assert_eq!(error.problem_code(), Some(BRegProblemCode::RequestInvalid));
            } else {
                assert_eq!(error.problem_code(), None);
            }
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
        assert!(!rendered.contains("activate-at"));
        assert!(!rendered.contains("expires-at"));
        assert!(!rendered.contains("private-canary"));
    }
    assert_eq!(fixture.requests.lock().unwrap().len(), total);
}

#[tokio::test]
async fn record_and_query_problem_paths_are_closed_bounded_and_retained_without_rendering() {
    let request_invalid = problem_response(BRegProblemCode::RequestInvalid);
    let request_document: Value = serde_json::from_slice(&request_invalid.body).unwrap();
    let query_invalid = problem_response(BRegProblemCode::QueryInvalid);
    let query_document: Value = serde_json::from_slice(&query_invalid.body).unwrap();
    let response_for = |base: &MockResponse, mut value: Value, path: Value| {
        value["fieldPath"] = path;
        MockResponse {
            body: serde_json::to_vec(&value).unwrap(),
            ..base.clone()
        }
    };

    let mut accepted = [
        "/data",
        "/data/householdCode",
        "/0",
        "/0/op",
        "/0/path",
        "/127/value",
        "/items",
        "/changeContext",
        "/items/3",
        "/items/3/operation",
        "/items/3/recordIdentifier",
        "/items/3/ifMatch",
        "/items/3/patch",
        "/items/3/data",
        "/items/3/data/householdCode",
        "/items/3/patch/0",
        "/items/3/patch/0/path",
        "/values",
        "Idempotency-Key",
        "If-Match",
    ]
    .iter()
    .map(|path| {
        (
            response_for(&request_invalid, request_document.clone(), json!(path)),
            (*path).to_owned(),
        )
    })
    .collect::<Vec<_>>();
    for parameter in [
        "$select",
        "$filter",
        "$orderby",
        "$top",
        "$count",
        "$skiptoken",
        "bbox",
        "accessProfile",
        "asOf",
        "snapshot",
        "validAt",
        "from",
        "to",
        "status",
        "limit",
        "action",
        "owner",
        "state",
        "turn",
        "pendingManualApplication",
        "target",
        "cursor",
        "top",
        "inputDigest",
        "after",
        "query",
    ] {
        accepted.push((
            response_for(&query_invalid, query_document.clone(), json!(parameter)),
            parameter.to_owned(),
        ));
    }

    let mut refused = [
        json!("/data/household-code"),
        json!("/data/HouseholdCode"),
        json!("/data/household~1code"),
        json!("/data/a/b"),
        json!(format!("/data/a{}", "b".repeat(64))),
        json!("/01/path"),
        json!("/0/from"),
        json!("/0/path/extra"),
        json!("/items/x"),
        json!("/items/03"),
        json!("/items/3/other"),
        json!("/items/3/data/a/b"),
        json!("/items/3/patch/0/from"),
        json!("/items/3/patch/x"),
        json!("/values/householdCode"),
        json!("/value"),
        json!("values"),
        json!("idempotency-key"),
        json!("if-match"),
        json!("$select"),
        json!("from"),
        json!("to"),
        json!("status"),
        json!("data"),
        json!(format!("/items/{}", "1".repeat(300))),
    ]
    .into_iter()
    .map(|path| response_for(&request_invalid, request_document.clone(), path))
    .collect::<Vec<_>>();
    for path in [
        "/data",
        "/data/householdCode",
        "/0/path",
        "/items/3",
        "/values",
        "Idempotency-Key",
        "If-Match",
        "$expand",
        "select",
        "fields",
        "noSuchField",
        "requestHistoryAfterProposalVersion",
    ] {
        refused.push(response_for(
            &query_invalid,
            query_document.clone(),
            json!(path),
        ));
    }

    let accepted_count = accepted.len();
    let accepted_paths = accepted
        .iter()
        .map(|(_, path)| path.clone())
        .collect::<Vec<_>>();
    let total = accepted_count + refused.len();
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
    for index in 0..total {
        let error = fixture
            .client
            .create_record(
                &binding,
                &create_request(),
                &key("record-path-problem"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("problem or malformed problem is returned");
        if index < accepted_count {
            assert!(matches!(
                error.problem_code(),
                Some(BRegProblemCode::RequestInvalid | BRegProblemCode::QueryInvalid)
            ));
            assert_eq!(error.status(), Some(400));
            assert_eq!(error.trace_id().unwrap().as_str(), TRACE_ID);
            assert_eq!(
                error.field_path().map(BRegProblemFieldPath::as_str),
                Some(accepted_paths[index].as_str())
            );
        } else {
            assert_eq!(error.field_path(), None);
            assert!(matches!(
                error,
                BaseRegistryClientError::Protocol {
                    failure: BRegProtocolFailure::Problem,
                    ..
                }
            ));
        }
        let rendered = format!("{error:?}: {error}");
        assert!(!rendered.contains("householdCode"));
        assert!(!rendered.contains("/data"));
        assert!(!rendered.contains("/items"));
        assert!(!rendered.contains("$select"));
        if let Some(path) = accepted_paths
            .get(index)
            .filter(|path| !matches!(path.as_str(), "from" | "to" | "status" | "query"))
        {
            assert!(!rendered.contains(path));
        }
    }
    assert_eq!(fixture.requests.lock().unwrap().len(), 1 + total);
}

#[tokio::test]
async fn registered_problem_identity_ignores_bounded_title_and_detail_prose() {
    let base = problem_response(BRegProblemCode::QueryInvalid);
    let base_document: Value = serde_json::from_slice(&base.body).unwrap();
    let cases = [
        (
            "query",
            "A different bounded title canary",
            "A different bounded detail canary.",
        ),
        (
            "limit",
            "Bad Request",
            "A record listing takes `$top` for its page size; `limit` is not accepted.",
        ),
        (
            "top",
            "Bad Request",
            "The Proposal list takes `limit` for its page size; `top` is not accepted.",
        ),
        (
            "after",
            "Bad Request",
            "An ingestion run listing takes `cursor` for its keyset cursor; `after` is not accepted.",
        ),
    ];
    let responses = cases.iter().map(|(path, title, detail)| {
        let mut document = base_document.clone();
        document["fieldPath"] = json!(path);
        document["title"] = json!(title);
        document["detail"] = json!(detail);
        MockResponse {
            body: serde_json::to_vec(&document).unwrap(),
            ..base.clone()
        }
    });
    let fixture = test_client(
        std::iter::once(metadata_response())
            .chain(responses)
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
    for (path, _, detail) in cases {
        let error = fixture
            .client
            .create_record(
                &binding,
                &create_request(),
                &key("query-guidance"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("the registered query problem is retained");
        assert_eq!(error.problem_code(), Some(BRegProblemCode::QueryInvalid));
        assert_eq!(
            error.field_path().map(BRegProblemFieldPath::as_str),
            Some(path)
        );
        let rendered = format!("{error:?}: {error}");
        assert!(!rendered.contains("canary"));
        assert!(!rendered.contains(detail));
    }
}

#[tokio::test]
async fn statistical_dimension_problem_paths_are_closed_code_bound_and_discarded() {
    let domain = problem_response(BRegProblemCode::StatisticalDatasetDomainViolation);
    let domain_document: Value = serde_json::from_slice(&domain.body).unwrap();
    let response_for = |base: &MockResponse, mut value: Value, path: Value| {
        value["fieldPath"] = path;
        MockResponse {
            body: serde_json::to_vec(&value).unwrap(),
            ..base.clone()
        }
    };
    let valid_path = "statisticalDatasets[id=records-by-category].dimensions[id=category_code]";
    let maximum_dataset_id = format!("d{}", "a".repeat(63));
    let maximum_dimension_id = format!("f{}", "b".repeat(63));
    let maximum_path = format!(
        "statisticalDatasets[id={maximum_dataset_id}].dimensions[id={maximum_dimension_id}]"
    );
    let accepted = [valid_path.to_owned(), maximum_path]
        .into_iter()
        .map(|path| response_for(&domain, domain_document.clone(), json!(path)))
        .collect::<Vec<_>>();

    let malformed = [
        String::new(),
        "statisticalDatasets[id=].dimensions[id=category]".to_owned(),
        "statisticalDatasets[id=records].dimensions[id=]".to_owned(),
        "statisticalDatasets[id=Records].dimensions[id=category]".to_owned(),
        "statisticalDatasets[id=records].dimensions[id=Category]".to_owned(),
        "statisticalDatasets[id=records].dimensions[id=category.secret]".to_owned(),
        "statisticalDatasets[id=records].dimensions[id=category/secret]".to_owned(),
        "statisticalDatasets[id=records].dimensions[id=category][id=secret]".to_owned(),
        "statisticalDatasets[id=records].dimensions[id=category].codes".to_owned(),
        "statisticalDatasets[id=records].dimensions[id=category".to_owned(),
        "statisticalDatasets[id=records].dimensions[id=category\nsecret]".to_owned(),
        format!(
            "statisticalDatasets[id=d{}].dimensions[id=category]",
            "a".repeat(64)
        ),
        format!(
            "statisticalDatasets[id=records].dimensions[id=f{}]",
            "b".repeat(64)
        ),
    ];
    let mut refused = malformed
        .into_iter()
        .map(|path| response_for(&domain, domain_document.clone(), json!(path)))
        .collect::<Vec<_>>();
    for code in [
        BRegProblemCode::RequestInvalid,
        BRegProblemCode::QueryInvalid,
        BRegProblemCode::StatisticalDatasetVersionConflict,
    ] {
        let base = problem_response(code);
        let document: Value = serde_json::from_slice(&base.body).unwrap();
        refused.push(response_for(&base, document, json!(valid_path)));
    }
    refused.push(response_for(&domain, domain_document, json!("from")));

    let accepted_count = accepted.len();
    let total = accepted_count + refused.len();
    let fixture = single_attempt_client(
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
                &key("statistical-path-problem"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("problem or malformed statistical location is returned");
        if index < accepted_count {
            assert_eq!(
                error.problem_code(),
                Some(BRegProblemCode::StatisticalDatasetDomainViolation)
            );
            assert_eq!(error.status(), Some(500));
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
        assert!(!rendered.contains("statisticalDatasets"));
        assert!(!rendered.contains("category"));
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
    } else if code == BRegProblemCode::StatisticalDatasetReleaseRefused {
        body["refusalCode"] = json!("period-not-ended");
    } else if code == BRegProblemCode::StatisticalDatasetVersionWithdrawn {
        body["reasonCode"] = json!("source-data-error");
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
        Code::ActionGuardFailed => "The action guard was not satisfied.",
        Code::ActionHandlerFailed => "The action handler could not produce an accepted result.",
        Code::ActionRefused => REFUSAL_LABEL,
        Code::AuthenticationRefused => "The bearer credential is missing or refused.",
        Code::IdempotencyConflict => "The idempotency key is bound to another request.",
        Code::IdempotencyExpired => {
            "The held response of the idempotency key expired; the key stays spent."
        }
        Code::IngestionChunkMismatch => "The chunk does not match the expected next chunk.",
        Code::IngestionProfileMismatch => {
            "The selected access profile does not match the run's bound profile."
        }
        Code::IngestionReceiptErased => "The stored receipt of the chunk was erased.",
        Code::IngestionRunBlocked => "The ingestion run is blocked and refuses further chunks.",
        Code::IngestionRunNotOpen => "The ingestion run is not open for this transition.",
        Code::LookupUnresolved => "The lookup did not resolve exactly one record.",
        Code::MutationConflict => "The mutation conflicts with current state.",
        Code::PreconditionFailed => "The mutation precondition failed.",
        Code::PreconditionRequired => "The mutation precondition is required.",
        Code::ProposalRejected => {
            "The review rejected this Proposal, and a rejection is final. A review result of changes-requested is what lets a Proposal be revised for another attempt."
        }
        Code::ProposalReviewResultMismatch => "The current review result does not match the retained approval.",
        Code::ProposalSubmissionExpired => {
            "The review result and application receipt of the submission are no longer retained."
        }
        Code::QueryCursorInvalid => "The query cursor is invalid.",
        Code::QueryInvalid => "The query request is invalid.",
        Code::RequestInvalid => "The request is invalid.",
        Code::RequestTimeout => "The request timed out.",
        Code::ResourceNotFound => "The requested resource was not found.",
        Code::RuntimeFieldEncryptionUnavailable => {
            "The Registry field-encryption service is unavailable."
        }
        Code::RuntimeNotReady => "Registry runtime is not ready.",
        Code::ServiceUnavailable => "The Registry mutation service is unavailable.",
        Code::SourceUnavailable => "The Registry data service is unavailable.",
        Code::StatisticalDatasetDomainViolation => {
            "A statistical dataset contains a code outside its declared domain."
        }
        Code::StatisticalDatasetReleaseRefused => {
            "The statistical dataset release operation is not eligible."
        }
        Code::StatisticalDatasetVersionConflict => {
            "The statistical dataset computation was superseded or its package changed."
        }
        Code::StatisticalDatasetVersionWithdrawn => {
            "The statistical dataset version was withdrawn."
        }
        Code::UnsupportedMediaType => "The request media type is not supported.",
        Code::WriteOutsideBoundary => {
            "The resulting record falls outside the selected access profile's row boundary."
        }
        _ => panic!("unregistered problem code"),
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
async fn a_create_answered_with_a_5xx_is_resent_byte_identically_under_the_same_key() {
    let fixture = test_client(vec![
        metadata_response(),
        problem_response(BRegProblemCode::ServiceUnavailable),
        mutation_response(StatusCode::CREATED, BRegRecordFormat::Json, RECORD_ID, true),
    ])
    .await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let created = fixture
        .client
        .create_record(
            &create_binding(&metadata),
            &create_request(),
            &key("create-resend-1"),
            BRegRecordFormat::Json,
        )
        .await
        .expect("the resent Create settles");
    assert_eq!(created.value.data.record_identifier, RECORD_ID);

    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 3, "one metadata fetch and two Create sends");
    let (first, second) = (&requests[1], &requests[2]);
    assert_eq!(first.method, "POST");
    assert_eq!(first.idempotency_key.as_deref(), Some("create-resend-1"));
    assert_eq!(first.method, second.method);
    assert_eq!(first.uri, second.uri);
    assert_eq!(first.authorization, second.authorization);
    assert_eq!(first.accept, second.accept);
    assert_eq!(first.content_type, second.content_type);
    assert_eq!(first.idempotency_key, second.idempotency_key);
    assert_eq!(first.if_match, second.if_match);
    assert_eq!(first.body, second.body);
}

/// Three unknown outcomes in a row: the first send and both default resends.
fn unavailable_sends() -> impl Iterator<Item = MockResponse> {
    std::iter::repeat_with(|| problem_response(BRegProblemCode::ServiceUnavailable))
        .take(1 + usize::from(DEFAULT_MUTATION_RETRIES))
}

/// Every resend repeats the first send exactly: the same method, route,
/// credential, media types, key, precondition, and body bytes.
fn assert_resent_identically(sends: &[CapturedRequest], idempotency_key: &str) {
    assert_eq!(sends.len(), 1 + usize::from(DEFAULT_MUTATION_RETRIES));
    let first = &sends[0];
    assert_eq!(first.idempotency_key.as_deref(), Some(idempotency_key));
    for send in &sends[1..] {
        assert_eq!(first.method, send.method);
        assert_eq!(first.uri, send.uri);
        assert_eq!(first.authorization, send.authorization);
        assert_eq!(first.accept, send.accept);
        assert_eq!(first.content_type, send.content_type);
        assert_eq!(first.idempotency_key, send.idempotency_key);
        assert_eq!(first.if_match, send.if_match);
        assert_eq!(first.body, send.body);
    }
}

#[tokio::test]
async fn a_patch_with_an_unknown_outcome_is_resent_byte_identically_under_the_same_key() {
    let fixture = test_client(
        std::iter::once(metadata_response())
            .chain(unavailable_sends())
            .collect(),
    )
    .await;
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
            &key("patch-resend-1"),
            BRegRecordFormat::Json,
        )
        .await
        .expect_err("no send settles the PATCH");
    assert!(error.is_outcome_unknown());

    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests[1].method, "PATCH");
    assert_eq!(requests[1].if_match.as_deref(), Some(SERVER_ETAG));
    assert_resent_identically(&requests[1..], "patch-resend-1");
}

#[tokio::test]
async fn a_batch_with_an_unknown_outcome_is_resent_byte_identically_under_the_same_key() {
    let fixture = test_client(
        std::iter::once(MockResponse::json(
            StatusCode::OK,
            metadata_fixture_with_create_batch(),
        ))
        .chain(unavailable_sends())
        .collect(),
    )
    .await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let binding = metadata
        .select_batch("company", "company-writer")
        .expect("select exact batch contract");
    let request = BRegBatchBuilder::new(&binding)
        .create(&create_request())
        .expect("a permitted Create item")
        .build()
        .expect("a bounded batch");
    let error = fixture
        .client
        .batch_records(&binding, &request, &key("batch-resend-1"))
        .await
        .expect_err("no send settles the batch");
    assert!(error.is_outcome_unknown());

    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests[1].method, "POST");
    assert_eq!(
        requests[1].uri,
        "/tenant/base/v1/records/companies:batch?accessProfile=company-writer"
    );
    assert_resent_identically(&requests[1..], "batch-resend-1");
}

#[tokio::test]
async fn an_action_invocation_with_an_unknown_outcome_is_resent_byte_identically_under_the_same_key(
) {
    let mut metadata = metadata_fixture();
    metadata["actions"] = json!([{
        "id": "register-company", "route": "/v1/actions/register-company",
        "conditionRoute": null,
        "apiName": "registerCompany", "revision": REVISION, "display": {}, "execution": {"mode":"immediate"},
        "inputMode": "fixed", "maximumInputStringBytes": null,
        "inputs": [{"id": "legal-name", "apiName": "legalName", "schema":{"type":"string","minLength":0,"maxLength":100}, "fieldType": {
            "type": "string", "minimumLength": 0, "maximumLength": 100},
            "required": true, "nullable": false, "classification": "internal"}],
        "referenceInputs": [], "requiredConditionKeys": [],
        "resultEffects": [{"effect": "company", "recordType": "company", "operation": "create"}],
        "access": {"selectedProfile": "company-writer"},
        "routes": {"invoke": {"method": "POST", "path": "/v1/actions/register-company",
            "operationId": "actions.register-company.invoke", "requiresIdempotencyKey": true,
            "inputSchema": "action-register-company-invoke-input",
            "responseSchema": "action-register-company-invoke-response"},
            "targetConditions": null},
        "bounds": {"maximumTargets": 4, "maximumFieldMutations": 8, "maximumSnapshotBytes": 1024}
    }]);
    let fixture = test_client(
        std::iter::once(MockResponse::json(StatusCode::OK, metadata))
            .chain(unavailable_sends())
            .collect(),
    )
    .await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let action = metadata
        .select_action("register-company", "company-writer")
        .expect("select exact immediate action");
    let request = BRegActionInvocationRequest::new(
        &action,
        Map::from_iter([("legalName".to_owned(), json!("Registered Ltd"))]),
        None,
    )
    .expect("valid invocation inputs");
    let error = fixture
        .client
        .invoke_action(&action, &request, &key("invoke-resend-1"))
        .await
        .expect_err("no send settles the invocation");
    assert!(error.is_outcome_unknown());

    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests[1].method, "POST");
    assert_eq!(
        requests[1].uri,
        "/tenant/base/v1/actions/register-company?accessProfile=company-writer"
    );
    assert_resent_identically(&requests[1..], "invoke-resend-1");
}

#[tokio::test]
async fn action_availability_is_metadata_bound_validated_and_sent_once() {
    let mut metadata = metadata_fixture();
    metadata["actions"] = json!([{
        "id": "rename-company", "route": "/v1/actions/rename-company",
        "conditionRoute": null,
        "apiName": "renameCompany", "revision": REVISION, "display": {}, "execution": {"mode":"immediate"},
        "inputMode": "fixed", "maximumInputStringBytes": null,
        "inputs": [
            {"id":"target","apiName":"targetId","schema":{"type":"string","format":"uuid"},
                "fieldType":{"type":"reference","target":"company","onDelete":"restrict"},
                "required":true,"nullable":false,"classification":"internal"},
            {"id":"legal-name","apiName":"legalName","schema":{"type":"string","minLength":1,"maxLength":100},
                "fieldType":{"type":"string","minimumLength":1,"maximumLength":100},
                "required":true,"nullable":false,"classification":"internal"}
        ],
        "referenceInputs": [{"input":"target","apiName":"targetId","targetRecordType":"company"}],
        "requiredConditionKeys": [],
        "resultEffects": [{"effect":"company","recordType":"company","operation":"patch"}],
        "access": {"selectedProfile":"company-writer"},
        "routes": {
            "invoke": {"method":"POST","path":"/v1/actions/rename-company",
                "operationId":"actions.rename-company.invoke","requiresIdempotencyKey":true,
                "inputSchema":"action-rename-company-invoke-input","responseSchema":"action-rename-company-invoke-response"},
            "targetConditions": null,
            "availability": {"method":"POST","path":"/v1/actions/rename-company/availability",
                "operationId":"actions.rename-company.availability","requiresIdempotencyKey":false,
                "inputSchema":"action-rename-company-availability-input","responseSchema":"action-rename-company-availability-response"}
        },
        "bounds": {"maximumTargets":4,"maximumFieldMutations":8,"maximumSnapshotBytes":1024}
    }]);
    let malformed = [
        json!({"availability":{"available":false,"observedRevision":7,
            "reason":"guard-not-satisfied","guardReason":"","recovery":"none"}}),
        json!({"availability":{"available":false,"observedRevision":7,
            "reason":"guard-not-satisfied","guardReason":"Uppercase","recovery":"none"}}),
        json!({"availability":{"available":false,"observedRevision":7,
            "reason":"guard-not-satisfied","guardReason":"has.dot","recovery":"none"}}),
        json!({"availability":{"available":false,"observedRevision":7,
            "reason":"guard-not-satisfied","guardReason":format!("a{}", "b".repeat(64)),"recovery":"none"}}),
        json!({"availability":{"available":true,"observedRevision":7,"guardReason":"misplaced"}}),
        json!({"availability":{"available":null,"observedRevision":7,
            "reason":"input-required","guardReason":"misplaced","recovery":"correct-input",
            "missingInputs":["legalName"]}}),
    ];
    let fixture = test_client(
        std::iter::once(MockResponse::json(StatusCode::OK, metadata))
        .chain(std::iter::once(MockResponse::json(
            StatusCode::OK,
            json!({"availability":{"available":null,"observedRevision":7,
                "reason":"input-required","recovery":"correct-input","missingInputs":["legalName"]}}),
        )
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept")))
        .chain(std::iter::once(MockResponse::json(
            StatusCode::OK,
            json!({"availability":{"available":false,"observedRevision":8,
                "reason":"guard-not-satisfied","guardReason":"legal_name_unchanged","recovery":"none"}}),
        )
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept")))
        .chain(malformed.into_iter().map(|body| MockResponse::json(StatusCode::OK, body)
            .with_header("cache-control", "no-store")
            .with_header("vary", "authorization, accept")))
        .collect(),
    )
    .await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let action = metadata
        .select_action("rename-company", "company-writer")
        .unwrap();
    let request = BRegActionAvailabilityRequest::new(
        &action,
        "targetId",
        Map::from_iter([("targetId".to_owned(), json!(RECORD_ID))]),
    )
    .unwrap();
    let result = fixture
        .client
        .action_availability(&action, &request)
        .await
        .unwrap();
    assert_eq!(result.value.available(), None);
    assert_eq!(result.value.observed_revision(), Some(7));
    assert_eq!(result.value.guard_reason(), None);
    assert_eq!(result.value.missing_inputs().unwrap(), ["legalName"]);
    {
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].method, "POST");
        assert_eq!(
            requests[1].uri,
            "/tenant/base/v1/actions/rename-company/availability?accessProfile=company-writer"
        );
        assert!(requests[1].idempotency_key.is_none());
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[1].body).unwrap(),
            json!({"targetInput":"targetId","input":{"targetId":RECORD_ID}})
        );
    }
    let unavailable = fixture
        .client
        .action_availability(&action, &request)
        .await
        .unwrap()
        .value;
    assert_eq!(unavailable.available(), Some(false));
    assert_eq!(unavailable.observed_revision(), Some(8));
    assert_eq!(unavailable.guard_reason(), Some("legal_name_unchanged"));
    for _ in 0..6 {
        let error = fixture
            .client
            .action_availability(&action, &request)
            .await
            .expect_err("malformed or misplaced guardReason is refused");
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
async fn proposal_action_drafts_may_omit_required_inputs_but_supplied_values_stay_typed() {
    let mut metadata = metadata_fixture();
    let input = json!({"id":"legal-name","apiName":"legalName",
        "schema":{"type":"string","minLength":1,"maxLength":100},
        "fieldType":{"type":"string","minimumLength":1,"maximumLength":100},
        "required":true,"nullable":false,"classification":"internal"});
    metadata["proposals"] = json!({"method":"GET","path":"/v1/proposals",
        "accessProfiles":["company-writer"],"actions":[]});
    metadata["actions"] = json!([
        {"id":"rename-now","route":"/v1/actions/rename-now","apiName":"renameNow",
            "revision":REVISION,"display":{},"execution":{"mode":"immediate"},"inputMode":"fixed",
            "inputs":[input.clone()],"referenceInputs":[],"requiredConditionKeys":[],"resultEffects":[],
            "access":{"selectedProfile":"company-writer"},
            "routes":{"invoke":{"method":"POST","path":"/v1/actions/rename-now",
                "operationId":"actions.rename-now.invoke","requiresIdempotencyKey":true,
                "inputSchema":"action-rename-now-invoke-input","responseSchema":"action-rename-now-invoke-response"},
                "targetConditions":null},
            "bounds":{"maximumTargets":4,"maximumFieldMutations":8,"maximumSnapshotBytes":1024}},
        {"id":"rename-draft","route":"/v1/actions/rename-draft/proposals","apiName":"renameDraft",
            "revision":REVISION,"display":{},"execution":{"mode":"proposal"},"inputMode":"fixed",
            "inputs":[input],"referenceInputs":[],"requiredConditionKeys":[],"resultEffects":[],
            "access":{"selectedProfile":"company-writer"},
            "routes":{"start":{"method":"POST","path":"/v1/actions/rename-draft/proposals",
                "operationId":"actions.rename-draft.start","requiresIdempotencyKey":true,
                "inputSchema":"action-rename-draft-invoke-input","responseSchema":"action-rename-draft-invoke-response"}},
            "bounds":{"maximumTargets":4,"maximumFieldMutations":8,"maximumSnapshotBytes":1024}}
    ]);
    let fixture = test_client(vec![MockResponse::json(StatusCode::OK, metadata)]).await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let immediate = metadata
        .select_action("rename-now", "company-writer")
        .unwrap();
    let proposal = metadata
        .select_action("rename-draft", "company-writer")
        .unwrap();
    assert_eq!(
        BRegActionInvocationRequest::new(&immediate, Map::new(), None).unwrap_err(),
        BRegActionError::MissingInput
    );
    BRegActionInvocationRequest::new(&proposal, Map::new(), None)
        .expect("a Proposal draft may omit a required input until Submit");
    for invalid in [Value::Null, json!(42), json!("")] {
        assert_eq!(
            BRegActionInvocationRequest::new(
                &proposal,
                Map::from_iter([("legalName".to_owned(), invalid)]),
                None,
            )
            .unwrap_err(),
            BRegActionError::InvalidInput
        );
    }
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert_eq!(fixture.token.0.load(Ordering::SeqCst), 1);
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
    route_metadata["recordTypes"][0]["route"] = json!("alternate-companies");
    route_metadata["operations"][0]["path"] = json!("/v1/records/alternate-companies");
    route_metadata["operations"][1]["path"] = json!("/v1/records/alternate-companies/{record_id}");

    let mut profile_metadata = metadata_fixture();
    profile_metadata["operations"][0]["accessProfile"] = json!("recovery-writer");
    profile_metadata["recordTypes"][0]["operations"][0]["accessProfile"] = json!("recovery-writer");

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
        "recordType": "company",
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
        "nextChunkIndex": 0,
        "committedItems": 0,
        "committedPrefixDigest": ingestion_prefix_digest(&[]),
        "lastAttempt": null,
        "createdAt": "2026-09-19T00:00:00Z",
        "updatedAt": "2026-09-19T00:01:00Z",
        "complete": false
    })
}

fn completed_ingestion_run_wire() -> Value {
    let mut run = ingestion_run_wire("complete");
    run["complete"] = json!(true);
    run["nextChunkIndex"] = run["chunkCount"].clone();
    run["committedItems"] = run["itemCount"].clone();
    run["committedPrefixDigest"] = run["inputDigest"].clone();
    run
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
                {"operation": "create", "recordIdentifier": RECORD_ID, "revisionIdentifier": "1", "etag": "\"breg-record-v1-abcdef012345\"", "domainData": {"legalName": "Example Ltd"}}
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
    let page = json!({"runs": [], "hasMore": false, "nextCursor": null});
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
async fn ingestion_creation_refuses_a_run_that_diverges_from_its_announcement() {
    let mut cases = Vec::new();
    for (case, member, value) in [
        ("operation", "operation", json!("patch")),
        ("profile", "profileId", json!("other-profile")),
        ("package revision", "packageRevision", json!("revision-2")),
        (
            "schema fingerprint",
            "schemaFingerprint",
            json!("fingerprint-2"),
        ),
        ("input digest", "inputDigest", json!("1".repeat(64))),
        ("input length", "inputLength", json!(4322)),
        ("item count", "itemCount", json!(11)),
        ("chunk count", "chunkCount", json!(4)),
        (
            "chunk algorithm",
            "chunkAlgorithmVersion",
            json!("another-bounded-algorithm"),
        ),
        ("initial status", "status", json!("cancelled")),
        ("next chunk", "nextChunkIndex", json!(1)),
        ("committed items", "committedItems", json!(1)),
        (
            "committed prefix",
            "committedPrefixDigest",
            json!("2".repeat(64)),
        ),
        (
            "last attempt",
            "lastAttempt",
            json!({"outcome": "unavailable", "chunkIndex": 0}),
        ),
    ] {
        let mut run = ingestion_run_wire("open");
        run[member] = value;
        cases.push((case, run));
    }

    for (case, run) in cases {
        let fixture = test_client(vec![ingestion_response(
            StatusCode::CREATED,
            json!({"run": run}),
        )])
        .await;
        let error = fixture
            .client
            .create_ingestion_run("company", &ingestion_announcement(INGESTION_PROFILE))
            .await
            .expect_err(case);
        let refusal = error.to_string();
        assert!(
            refusal.contains("verify the server URL")
                && refusal.contains("matching BReg runtime and client"),
            "{case}: the refusal must name the fix: {refusal}"
        );
        assert!(
            matches!(
                error,
                BaseRegistryClientError::Protocol {
                    failure: BRegProtocolFailure::Body,
                    ..
                }
            ),
            "{case}: a creation answer that diverges from its announcement is a protocol body failure"
        );
    }
}

#[tokio::test]
async fn completed_ingestion_runs_require_the_announced_totals_and_digest() {
    let mut cases = Vec::new();
    for (case, member, value) in [
        ("chunk total", "nextChunkIndex", json!(2)),
        ("item total", "committedItems", json!(9)),
        (
            "whole-input digest",
            "committedPrefixDigest",
            json!("3".repeat(64)),
        ),
    ] {
        let mut run = completed_ingestion_run_wire();
        run[member] = value;
        cases.push((case, run));
    }

    for (case, run) in cases {
        let fixture = test_client(vec![ingestion_response(
            StatusCode::OK,
            json!({"run": run}),
        )])
        .await;
        let error = fixture
            .client
            .read_ingestion_run("company", Uuid::parse_str(RECORD_ID).unwrap(), None)
            .await
            .expect_err(case);
        let refusal = error.to_string();
        assert!(
            refusal.contains("verify the server URL")
                && refusal.contains("matching BReg runtime and client"),
            "{case}: the refusal must name the fix: {refusal}"
        );
        assert!(
            matches!(
                error,
                BaseRegistryClientError::Protocol {
                    failure: BRegProtocolFailure::Body,
                    ..
                }
            ),
            "{case}: a complete run without exact totals and digest is a protocol body failure"
        );
    }
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
    let mut accepted = vec![(base.clone(), REFUSAL_CODE.to_owned(), None)];
    for (path, refusal) in [
        ("/input/givenName", REFUSAL_CODE),
        ("/input/a", "a"),
        ("/input/name9", "declared.reason_9-canary"),
    ] {
        let mut value = document.clone();
        value["fieldPath"] = json!(path);
        value["refusalCode"] = json!(refusal);
        value["detail"] = json!("A declared label canary.");
        accepted.push((
            response_for(value),
            refusal.to_owned(),
            Some(path.to_owned()),
        ));
    }
    let mut long = document.clone();
    long["detail"] = json!("é".repeat(256));
    long["refusalCode"] = json!("z".repeat(128));
    accepted.push((response_for(long), "z".repeat(128), None));
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
    paired["recordType"] = json!("company");
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
    let expected: Vec<Option<(String, Option<String>)>> = accepted
        .iter()
        .map(|(_, code, path)| Some((code.clone(), path.clone())))
        .chain(refused.iter().map(|_| None))
        .collect();
    let total = expected.len();
    let fixture = single_attempt_client(
        std::iter::once(metadata_response())
            .chain(accepted.into_iter().map(|(response, _, _)| response))
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
        if let Some((code, path)) = declared {
            assert_eq!(error.problem_code(), Some(BRegProblemCode::ActionRefused));
            assert_eq!(error.status(), Some(422));
            assert_eq!(
                error.refusal_code().map(BRegRefusalCode::as_str),
                Some(code.as_str())
            );
            assert_eq!(
                error.field_path().map(BRegProblemFieldPath::as_str),
                path.as_deref()
            );
        } else {
            assert_eq!(error.refusal_code(), None);
            assert_eq!(error.field_path(), None);
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

#[tokio::test]
async fn guard_failures_expose_only_bounded_authored_copy_keys() {
    let base = problem_response(BRegProblemCode::ActionGuardFailed);
    let document: Value = serde_json::from_slice(&base.body).unwrap();
    let response_for = |mut value: Value, guard_reason: Value| {
        value["guardReason"] = guard_reason;
        let mut response = base.clone();
        response.body = serde_json::to_vec(&value).unwrap();
        response
    };
    let accepted = [
        "a".to_owned(),
        "legal_name_unchanged".to_owned(),
        format!("a{}", "b".repeat(63)),
    ];
    let mut refused = [
        json!(""),
        json!("Uppercase"),
        json!("has.dot"),
        json!(format!("a{}", "b".repeat(64))),
        Value::Null,
    ]
    .into_iter()
    .map(|reason| response_for(document.clone(), reason))
    .collect::<Vec<_>>();
    for (code, member, value) in [
        (
            BRegProblemCode::ActionRefused,
            "guardReason",
            json!("misplaced"),
        ),
        (
            BRegProblemCode::ActionGuardFailed,
            "refusalCode",
            json!(REFUSAL_CODE),
        ),
        (
            BRegProblemCode::ActionGuardFailed,
            "reasonCode",
            json!("source-data-error"),
        ),
    ] {
        let mut response = problem_response(code);
        let mut body: Value = serde_json::from_slice(&response.body).unwrap();
        body[member] = value;
        response.body = serde_json::to_vec(&body).unwrap();
        refused.push(response);
    }
    let fixture = single_attempt_client(
        std::iter::once(metadata_response())
            .chain(
                accepted
                    .iter()
                    .map(|reason| response_for(document.clone(), json!(reason))),
            )
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
    for expected in &accepted {
        let error = fixture
            .client
            .create_record(
                &binding,
                &create_request(),
                &key("guard-failure"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("guard failure is returned");
        assert_eq!(
            error.problem_code(),
            Some(BRegProblemCode::ActionGuardFailed)
        );
        assert_eq!(error.guard_reason(), Some(expected.as_str()));
        assert_eq!(error.refusal_code(), None);
        assert_eq!(error.reason_code(), None);
        let rendered = format!("{error:?}: {error}");
        assert!(rendered.contains("BRegRefusalCode(<undisclosed>)"));
        if expected.len() > 1 {
            assert!(!rendered.contains(expected));
        }
    }
    for _ in 0..8 {
        let error = fixture
            .client
            .create_record(
                &binding,
                &create_request(),
                &key("malformed-guard-failure"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("malformed or misplaced guard reason is refused");
        assert!(matches!(
            error,
            BaseRegistryClientError::Protocol {
                failure: BRegProtocolFailure::Problem,
                ..
            }
        ));
        assert_eq!(error.guard_reason(), None);
    }
}

#[tokio::test]
async fn idempotency_key_reuse_uses_the_current_wire_code() {
    let current = problem_response(BRegProblemCode::IdempotencyConflict);
    let mut retired = current.clone();
    let mut retired_body: Value = serde_json::from_slice(&retired.body).unwrap();
    retired_body["type"] =
        json!("https://id.registrystack.org/problems/registry-breg/idempotency/conflict");
    retired_body["code"] = json!("idempotency.conflict");
    retired.body = serde_json::to_vec(&retired_body).unwrap();
    let fixture = single_attempt_client(vec![metadata_response(), current, retired]).await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .unwrap()
        .value;
    let binding = create_binding(&metadata);
    let current = fixture
        .client
        .create_record(
            &binding,
            &create_request(),
            &key("current-idempotency-code"),
            BRegRecordFormat::Json,
        )
        .await
        .expect_err("key reuse is refused");
    assert_eq!(
        current.problem_code().map(BRegProblemCode::code),
        Some("idempotency.key-reused")
    );
    assert!(!current.is_outcome_unknown());

    let retired = fixture
        .client
        .create_record(
            &binding,
            &create_request(),
            &key("retired-idempotency-code"),
            BRegRecordFormat::Json,
        )
        .await
        .expect_err("the retired code is not treated as the typed refusal");
    assert_eq!(retired.problem_code(), None);
    assert!(!retired.is_outcome_unknown());
}
