// SPDX-License-Identifier: Apache-2.0

//! The three attachment exchanges are exact: one request each, the engine's own
//! route, and a response shape the client refuses to relax.

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
    BRegAttachmentSlot, BRegAttachmentUpload, BRegEtag, BRegIdempotencyKey, BRegMetadata,
    BRegProblemCode, BRegProtocolFailure, BRegRecordFormat, BaseRegistryClient,
    BaseRegistryClientConfig, BaseRegistryClientError, REGISTRY_RECORD_CONTEXT_IDENTIFIER,
};
use registry_platform_httputil::client::{BearerToken, TokenError, TokenProvider};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
const SERVER_ETAG: &str = "\"breg-record-000000000001\"";
const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROFILE_LINK: &str = "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </tenant/base/v1/schemas/company>; rel=\"describedby\"";
const SLOT: &str = "supporting-file";
const SLOT_PATH: &str = "/v1/records/companies/{record_id}/attachments/supporting-file";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PDF: &[u8] = b"%PDF-1.7 governed bytes";

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

    fn bytes(status: StatusCode, content_type: &str, body: &[u8]) -> Self {
        Self {
            status,
            headers: vec![
                ("content-type".into(), content_type.into()),
                ("traceparent".into(), TRACEPARENT.into()),
            ],
            body: body.to_vec(),
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
        BearerToken::new("attachment-boundary-token")
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

fn attachment_capability() -> Value {
    json!({
        "requiredForSubmit": true,
        "maximumBytes": 1024,
        "contentTypes": ["application/pdf"],
        "verification": {
            "statusField": "verificationStatus",
            "allowedStatuses": ["notRequired", "approved"],
            "pendingOrRejectedBlocks": ["download", "submit"]
        },
        "download": {"method": "GET", "path": SLOT_PATH, "accessProfile": "company-writer",
            "authorizationOperation": "get", "queryParameters": ["proposalVersion"],
            "body": "none", "ifMatchRequired": false, "idempotencyKeyRequired": false,
            "proposalVersionRequired": true},
        "upload": {"method": "PATCH", "path": SLOT_PATH, "accessProfile": "company-writer",
            "authorizationOperation": "patch", "queryParameters": [], "body": "binary",
            "ifMatchRequired": true, "idempotencyKeyRequired": true, "requiredState": "draft"},
        "remove": {"method": "DELETE", "path": SLOT_PATH, "accessProfile": "company-writer",
            "authorizationOperation": "patch", "queryParameters": [], "body": "none",
            "ifMatchRequired": true, "idempotencyKeyRequired": true, "requiredState": "draft"}
    })
}

fn fields() -> Value {
    json!([
        {"id": "legal-name", "apiName": "legalName", "label": "Legal name",
         "schema": {"type": "string"}, "required": true, "nullable": true,
         "readOnly": false, "removable": true},
        {"id": SLOT, "apiName": SLOT, "label": "Supporting file",
         "schema": {"anyOf": [{"type": "null"}, {"type": "object"}], "readOnly": true,
             "x-registry-fieldKind": "attachment", "x-registry-attachment": attachment_capability()},
         "required": false, "nullable": true, "readOnly": true, "removable": false}
    ])
}

fn operation(identifier: &str, method: &str, path: &str, kind: &str, request: Value) -> Value {
    json!({
        "id": identifier,
        "method": method,
        "path": path,
        "operation": kind,
        "sourceEntity": "company",
        "responseEntity": "company",
        "accessProfile": "company-writer",
        "requiredCapabilities": [],
        "entityLabel": "Companies",
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": ["legal-name"],
        "fields": fields(),
        "readableFields": ["legal-name", SLOT],
        "createWritableFields": [],
        "patchWritableFields": ["legal-name"],
        "selectors": [],
        "query": null,
        "request": request
    })
}

fn metadata_fixture() -> Value {
    let patch = operation(
        "records.company.patch",
        "PATCH",
        "/v1/records/companies/{record_id}",
        "patch",
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
    );
    let get = operation(
        "records.company.get",
        "GET",
        "/v1/records/companies/{record_id}",
        "get",
        json!({"fieldNames": "api", "queryParameters": ["$select"]}),
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
                {"operation": "patch", "accessProfile": "company-writer"},
                {"operation": "get", "accessProfile": "company-writer"}
            ],
            "readableFields": ["legal-name", SLOT],
            "schema": "/v1/schemas/company"
        }],
        "operations": [patch, get]
    })
}

fn metadata_response() -> MockResponse {
    MockResponse::json(StatusCode::OK, metadata_fixture())
}

fn record_body(format: BRegRecordFormat, slot_value: Value) -> Value {
    let mut value = json!({
        "data": {
            "recordIdentifier": RECORD_ID,
            "revisionIdentifier": "2",
            "domainData": {"legalName": "Example Ltd", SLOT: slot_value},
            "snapshot": format!("breg1_{RECORD_ID}")
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

fn filled_slot() -> Value {
    json!({
        "slotId": SLOT,
        "proposalVersion": 2,
        "filled": true,
        "sha256": DIGEST,
        "byteSize": PDF.len(),
        "erased": false,
        "contentType": "application/pdf",
        "uploadedAt": "2026-01-02T03:04:05.000000Z",
        "uploadedBy": "urn:registry:actor:filer",
        "verificationStatus": "approved"
    })
}

fn mutation_response(format: BRegRecordFormat, slot_value: Value) -> MockResponse {
    let media_type = match format {
        BRegRecordFormat::Json => "application/json",
        BRegRecordFormat::JsonLd => "application/ld+json",
    };
    MockResponse::json(StatusCode::OK, record_body(format, slot_value))
        .without_header("content-type")
        .with_header("content-type", media_type)
        .with_header("etag", SERVER_ETAG)
        .with_header("link", PROFILE_LINK)
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept")
}

/// The engine's own download response: the stored content type, no entity tag,
/// and a narrower `vary` than any record route.
fn download_response() -> MockResponse {
    MockResponse::bytes(StatusCode::OK, "application/pdf", PDF)
        .with_header("content-disposition", "attachment")
        .with_header("x-content-type-options", "nosniff")
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization")
}

fn problem_response(code: BRegProblemCode, detail: &str) -> MockResponse {
    MockResponse::json(
        StatusCode::from_u16(code.status()).expect("registered status"),
        json!({
            "type": format!("https://id.registrystack.org/problems/registry-breg/{}",
                code.code().replace('.', "/")),
            "title": problem_title(code.status()),
            "status": code.status(),
            "detail": detail,
            "code": code.code(),
            "traceId": "4bf92f3577b34da6a3ce929d0e0e4736"
        }),
    )
    .without_header("content-type")
    .with_header("content-type", "application/problem+json")
    .with_header("cache-control", "no-store")
}

fn problem_title(status: u16) -> &'static str {
    match status {
        404 => "Not Found",
        409 => "Conflict",
        412 => "Precondition Failed",
        415 => "Unsupported Media Type",
        428 => "Precondition Required",
        _ => panic!("unregistered problem status"),
    }
}

fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).expect("valid idempotency key")
}

fn etag() -> BRegEtag {
    BRegEtag::parse(SERVER_ETAG).expect("valid strong entity tag")
}

fn record_id() -> Uuid {
    Uuid::parse_str(RECORD_ID).expect("canonical record identifier")
}

fn slot(metadata: &BRegMetadata) -> BRegAttachmentSlot {
    metadata
        .select_attachments("company", "company-writer")
        .expect("the served slot contract is complete")
        .remove(0)
}

async fn selected(responses: Vec<MockResponse>) -> (TestClient, BRegAttachmentSlot) {
    let mut queue = vec![metadata_response()];
    queue.extend(responses);
    let fixture = test_client(queue).await;
    let metadata = fixture
        .client
        .registry_contract(Some("company-writer"))
        .await
        .expect("runtime metadata")
        .value;
    let slot = slot(&metadata);
    (fixture, slot)
}

#[tokio::test]
async fn upload_download_and_delete_use_the_exact_slot_routes() {
    let (fixture, slot) = selected(vec![
        mutation_response(BRegRecordFormat::Json, filled_slot()),
        download_response(),
        mutation_response(BRegRecordFormat::JsonLd, Value::Null),
    ])
    .await;

    let upload = BRegAttachmentUpload::new(&slot, "application/pdf", PDF.to_vec())
        .expect("the slot accepts these bytes");
    let uploaded = fixture
        .client
        .upload_attachment(
            &slot,
            record_id(),
            &etag(),
            &upload,
            &key("upload-exchange-1"),
            BRegRecordFormat::Json,
        )
        .await
        .expect("upload succeeds");
    assert_eq!(uploaded.value.data.record_identifier, RECORD_ID);
    assert_eq!(uploaded.metadata.etag().unwrap().as_str(), SERVER_ETAG);
    let state = slot
        .value_in(&uploaded.value.data)
        .expect("the response carries a conforming slot value");
    assert_eq!(state.filled().unwrap().sha256(), DIGEST);

    let downloaded = fixture
        .client
        .download_attachment(&slot, record_id(), 2)
        .await
        .expect("download succeeds");
    assert_eq!(downloaded.value.media_type(), "application/pdf");
    assert_eq!(downloaded.value.as_bytes(), PDF);
    assert!(downloaded.metadata.etag().is_none());

    let removed = fixture
        .client
        .delete_attachment(
            &slot,
            record_id(),
            &etag(),
            &key("remove-exchange-1"),
            BRegRecordFormat::JsonLd,
        )
        .await
        .expect("removal succeeds");
    assert!(removed.value.json_ld_context.is_some());
    assert_eq!(
        slot.value_in(&removed.value.data).unwrap(),
        registry_breg_client::BRegAttachmentSlotValue::Empty
    );

    assert_eq!(fixture.token.0.load(Ordering::SeqCst), 4);
    let requests = fixture.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 4, "one request per explicit exchange");

    assert_eq!(requests[1].method, "PATCH");
    assert_eq!(
        requests[1].uri,
        format!(
            "/tenant/base/v1/records/companies/{RECORD_ID}/attachments/{SLOT}?accessProfile=company-writer"
        )
    );
    assert_eq!(requests[1].accept.as_deref(), Some("application/json"));
    assert_eq!(requests[1].content_type.as_deref(), Some("application/pdf"));
    assert_eq!(
        requests[1].idempotency_key.as_deref(),
        Some("upload-exchange-1")
    );
    assert_eq!(requests[1].if_match.as_deref(), Some(SERVER_ETAG));
    assert_eq!(requests[1].body, PDF);
    assert_eq!(
        requests[1].authorization.as_deref(),
        Some("Bearer attachment-boundary-token")
    );

    assert_eq!(requests[2].method, "GET");
    assert_eq!(
        requests[2].uri,
        format!(
            "/tenant/base/v1/records/companies/{RECORD_ID}/attachments/{SLOT}?proposalVersion=2&accessProfile=company-writer"
        )
    );
    assert_eq!(
        requests[2].accept.as_deref(),
        Some("*/*"),
        "a binary read is not negotiated"
    );
    assert!(requests[2].if_match.is_none());
    assert!(requests[2].idempotency_key.is_none());
    assert!(requests[2].body.is_empty());

    assert_eq!(requests[3].method, "DELETE");
    assert_eq!(
        requests[3].uri,
        format!(
            "/tenant/base/v1/records/companies/{RECORD_ID}/attachments/{SLOT}?accessProfile=company-writer"
        )
    );
    assert_eq!(requests[3].accept.as_deref(), Some("application/ld+json"));
    assert!(requests[3].content_type.is_none());
    assert_eq!(
        requests[3].idempotency_key.as_deref(),
        Some("remove-exchange-1")
    );
    assert_eq!(requests[3].if_match.as_deref(), Some(SERVER_ETAG));
    assert!(requests[3].body.is_empty());
}

#[tokio::test]
async fn a_slot_from_another_client_source_is_refused_without_a_request() {
    let (fixture, slot) = selected(Vec::new()).await;
    let other = test_client(vec![metadata_response()]).await;
    let other_metadata = other
        .client
        .registry_contract(Some("company-writer"))
        .await
        .expect("runtime metadata")
        .value;
    let other_slot = self::slot(&other_metadata);
    let upload = BRegAttachmentUpload::new(&slot, "application/pdf", PDF.to_vec())
        .expect("the slot accepts these bytes");

    for refusal in [
        fixture
            .client
            .upload_attachment(
                &other_slot,
                record_id(),
                &etag(),
                &upload,
                &key("foreign-1"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("a foreign slot is refused"),
        fixture
            .client
            .download_attachment(&other_slot, record_id(), 1)
            .await
            .expect_err("a foreign slot is refused"),
        fixture
            .client
            .delete_attachment(
                &other_slot,
                record_id(),
                &etag(),
                &key("foreign-2"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("a foreign slot is refused"),
    ] {
        assert!(matches!(
            refusal,
            BaseRegistryClientError::InvalidRequest { .. }
        ));
    }
    assert_eq!(
        fixture.requests.lock().unwrap().len(),
        1,
        "only the metadata fetch reached the engine"
    );
}

#[tokio::test]
async fn an_upload_prepared_for_another_slot_never_reaches_the_engine() {
    let (fixture, slot) = selected(Vec::new()).await;
    let mut other = metadata_fixture();
    for operation in other["operations"].as_array_mut().unwrap() {
        operation["fields"][1]["id"] = json!("cover-letter");
        operation["fields"][1]["apiName"] = json!("cover-letter");
        operation["fields"][1]["schema"]["x-registry-attachment"]["download"]["path"] =
            json!("/v1/records/companies/{record_id}/attachments/cover-letter");
        operation["fields"][1]["schema"]["x-registry-attachment"]["upload"]["path"] =
            json!("/v1/records/companies/{record_id}/attachments/cover-letter");
        operation["fields"][1]["schema"]["x-registry-attachment"]["remove"]["path"] =
            json!("/v1/records/companies/{record_id}/attachments/cover-letter");
        operation["readableFields"] = json!(["legal-name", "cover-letter"]);
    }
    other["entities"][0]["readableFields"] = json!(["legal-name", "cover-letter"]);
    let second = test_client(vec![MockResponse::json(StatusCode::OK, other)]).await;
    let other_slot = self::slot(
        &second
            .client
            .registry_contract(Some("company-writer"))
            .await
            .expect("runtime metadata")
            .value,
    );
    // Both slots come from the same source, so only the slot binding differs.
    let upload = BRegAttachmentUpload::new(&other_slot, "application/pdf", PDF.to_vec())
        .expect("the other slot accepts these bytes");
    let refusal = fixture
        .client
        .upload_attachment(
            &slot,
            record_id(),
            &etag(),
            &upload,
            &key("mismatched-1"),
            BRegRecordFormat::Json,
        )
        .await
        .expect_err("bytes prepared for another slot are refused");
    assert!(matches!(
        refusal,
        BaseRegistryClientError::InvalidRequest { .. }
    ));
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_download_response_missing_its_governing_headers_is_refused() {
    for (label, response, expected) in [
        (
            "a missing content disposition",
            download_response().without_header("content-disposition"),
            BRegProtocolFailure::CachePolicy,
        ),
        (
            "a sniffable download",
            download_response().without_header("x-content-type-options"),
            BRegProtocolFailure::CachePolicy,
        ),
        (
            "a storable download",
            download_response().without_header("cache-control"),
            BRegProtocolFailure::CachePolicy,
        ),
        (
            "a download that varies on Accept",
            download_response()
                .without_header("vary")
                .with_header("vary", "authorization, accept"),
            BRegProtocolFailure::CachePolicy,
        ),
        (
            "an entity tag on a binary read",
            download_response().with_header("etag", SERVER_ETAG),
            BRegProtocolFailure::EntityTag,
        ),
        (
            "a profile link on a binary read",
            download_response().with_header("link", PROFILE_LINK),
            BRegProtocolFailure::ProfileLink,
        ),
        (
            "a content type that is not a concrete media type",
            download_response()
                .without_header("content-type")
                .with_header("content-type", "application/pdf; charset=utf-8"),
            BRegProtocolFailure::MediaType,
        ),
        (
            "a missing content type",
            download_response().without_header("content-type"),
            BRegProtocolFailure::MediaType,
        ),
    ] {
        let (fixture, slot) = selected(vec![response]).await;
        let refusal = fixture
            .client
            .download_attachment(&slot, record_id(), 2)
            .await
            .expect_err("the client refuses the response");
        let BaseRegistryClientError::Protocol { failure, .. } = refusal else {
            panic!("{label} must be a protocol refusal")
        };
        assert_eq!(failure, expected, "{label}");
    }
}

#[tokio::test]
async fn attachment_problems_keep_the_closed_problem_vocabulary() {
    for (expected, detail) in [
        (
            BRegProblemCode::PreconditionRequired,
            "The mutation precondition is required.",
        ),
        (
            BRegProblemCode::PreconditionFailed,
            "The mutation precondition failed.",
        ),
        (
            BRegProblemCode::UnsupportedMediaType,
            "The request media type is not supported.",
        ),
        (
            BRegProblemCode::ResourceNotFound,
            "The requested resource was not found.",
        ),
        (
            BRegProblemCode::IdempotencyConflict,
            "The idempotency key is bound to another request.",
        ),
    ] {
        let (fixture, slot) = selected(vec![problem_response(expected, detail)]).await;
        let upload = BRegAttachmentUpload::new(&slot, "application/pdf", PDF.to_vec())
            .expect("the slot accepts these bytes");
        let refusal = fixture
            .client
            .upload_attachment(
                &slot,
                record_id(),
                &etag(),
                &upload,
                &key("problem-1"),
                BRegRecordFormat::Json,
            )
            .await
            .expect_err("the engine refused");
        let BaseRegistryClientError::Problem { code, .. } = refusal else {
            panic!("{detail} must surface as a Base Registry Engine problem")
        };
        assert_eq!(code, expected);
    }
}

#[tokio::test]
async fn a_download_refuses_a_proposal_version_the_engine_cannot_parse() {
    let (fixture, slot) = selected(Vec::new()).await;
    let refusal = fixture
        .client
        .download_attachment(&slot, record_id(), 0)
        .await
        .expect_err("a zero proposal version is not canonical");
    assert!(matches!(
        refusal,
        BaseRegistryClientError::InvalidRequest { .. }
    ));
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_mutation_response_for_another_record_is_refused() {
    let mut body = record_body(BRegRecordFormat::Json, filled_slot());
    body["data"]["recordIdentifier"] = json!("00000000-0000-4000-8000-000000000002");
    let response = MockResponse::json(StatusCode::OK, body)
        .with_header("etag", SERVER_ETAG)
        .with_header("link", PROFILE_LINK)
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept");
    let (fixture, slot) = selected(vec![response]).await;
    let refusal = fixture
        .client
        .delete_attachment(
            &slot,
            record_id(),
            &etag(),
            &key("other-record-1"),
            BRegRecordFormat::Json,
        )
        .await
        .expect_err("another record's response is refused");
    assert!(matches!(refusal, BaseRegistryClientError::Protocol { .. }));
}
