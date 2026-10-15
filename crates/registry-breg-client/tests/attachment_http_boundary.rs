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
    BRegActionInvocationRequest, BRegIdempotencyKey, BRegProblemCode, BRegProposal,
    BRegProtocolFailure, BaseRegistryClient, BaseRegistryClientConfig, BaseRegistryClientError,
};
use registry_platform_httputil::client::{BearerToken, TokenError, TokenProvider};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use url::Url;

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
const SERVER_ETAG: &str = "\"breg-record-000000000001\"";
const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SLOT: &str = "supporting-file";
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
    BRegIdempotencyKey::parse(value).unwrap()
}
fn proposal_document() -> Value {
    let path = format!("/v1/proposals/{RECORD_ID}/attachments/{SLOT}");
    json!({"id":RECORD_ID,"actionId":"correct","actionRevision":REVISION,"submissionVersion":2,"revision":3,"state":"draft","links":{},
        "attachments":{SLOT:{"id":SLOT,"required":false,"maximumBytes":1024,"contentTypes":["application/pdf"],"classification":"restricted","links":{
            "download":{"method":"GET","path":format!("{path}?submissionVersion=2"),"accessProfile":"writer","operation":"download"},
            "upload":{"method":"PATCH","path":path,"accessProfile":"writer","operation":"upload","ifMatch":SERVER_ETAG},
            "remove":{"method":"DELETE","path":path,"accessProfile":"writer","operation":"remove","ifMatch":SERVER_ETAG}}}}})
}
fn proposal_response() -> MockResponse {
    let mut receipt = proposal_document();
    receipt["revision"] = json!(4);
    MockResponse::json(StatusCode::OK, receipt)
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept")
}
async fn selected(responses: Vec<MockResponse>) -> (TestClient, BRegProposal) {
    selected_with_document(proposal_document(), responses).await
}
async fn selected_with_document(
    document: Value,
    responses: Vec<MockResponse>,
) -> (TestClient, BRegProposal) {
    let metadata = json!({"id":"attachment-test","version":"1","revision":REVISION,"metadataVersion":"1","recordTypes":[],"operations":[],"actions":[{
        "id":"correct","apiName":"correct","revision":REVISION,"display":{},"execution":{"mode":"proposal"},"route":"/v1/actions/correct/proposals","inputMode":"fixed","inputs":[],"referenceInputs":[],"requiredConditionKeys":[],"resultEffects":[],"access":{"selectedProfile":"writer"},
        "routes":{"start":{"method":"POST","path":"/v1/actions/correct/proposals","operationId":"actions.correct.start","requiresIdempotencyKey":true,"inputSchema":"action-correct-invoke-input","responseSchema":"action-correct-invoke-response"}},
        "bounds":{"maximumTargets":16,"maximumFieldMutations":128,"maximumSnapshotBytes":2097152}}]});
    let mut queue = vec![
        MockResponse::json(StatusCode::OK, metadata)
            .with_header("cache-control", "no-store")
            .with_header("vary", "authorization, accept"),
        MockResponse::json(StatusCode::OK, document)
            .with_header("cache-control", "no-store")
            .with_header("vary", "authorization, accept"),
    ];
    queue.extend(responses);
    let fixture = test_client(queue).await;
    let metadata = fixture
        .client
        .registry_contract(Some("writer"))
        .await
        .unwrap();
    let action = metadata.value.select_action("correct", "writer").unwrap();
    let input = BRegActionInvocationRequest::new(&action, serde_json::Map::new(), None).unwrap();
    let proposal = fixture
        .client
        .start_proposal(&action, &input, &key("start"))
        .await
        .unwrap()
        .value;
    (fixture, proposal)
}
#[tokio::test]
async fn upload_download_and_delete_use_exact_promoted_proposal_routes() {
    let (fixture, proposal) = selected(vec![
        proposal_response(),
        download_response(),
        proposal_response(),
    ])
    .await;
    fixture
        .client
        .upload_proposal_attachment(&proposal, SLOT, "application/pdf", PDF, &key("upload"))
        .await
        .unwrap();
    let bytes = fixture
        .client
        .download_proposal_attachment(&proposal, SLOT)
        .await
        .unwrap();
    assert_eq!(bytes.value.as_bytes(), PDF);
    assert!(bytes.metadata.etag().is_none());
    fixture
        .client
        .delete_proposal_attachment(&proposal, SLOT, &key("remove"))
        .await
        .unwrap();
    assert_eq!(fixture.token.0.load(Ordering::SeqCst), 5);
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    for (request, method) in requests[2..].iter().zip(["PATCH", "GET", "DELETE"]) {
        assert_eq!(request.method, method);
        assert_eq!(
            request.authorization.as_deref(),
            Some("Bearer attachment-boundary-token")
        );
    }
    let path = format!("/tenant/base/v1/proposals/{RECORD_ID}/attachments/{SLOT}");
    assert_eq!(requests[2].uri, format!("{path}?accessProfile=writer"));
    assert_eq!(requests[2].body, PDF);
    assert_eq!(requests[2].content_type.as_deref(), Some("application/pdf"));
    assert_eq!(requests[2].accept.as_deref(), Some("application/json"));
    assert_eq!(requests[2].if_match.as_deref(), Some(SERVER_ETAG));
    assert_eq!(requests[2].idempotency_key.as_deref(), Some("upload"));
    assert_eq!(
        requests[3].uri,
        format!("{path}?accessProfile=writer&submissionVersion=2")
    );
    assert_eq!(requests[3].accept.as_deref(), Some("*/*"));
    assert!(requests[3].if_match.is_none());
    assert!(requests[3].idempotency_key.is_none());
    assert_eq!(requests[4].uri, format!("{path}?accessProfile=writer"));
    assert_eq!(requests[4].if_match.as_deref(), Some(SERVER_ETAG));
    assert_eq!(requests[4].idempotency_key.as_deref(), Some("remove"));
    assert!(requests[4].body.is_empty());
}
#[tokio::test]
async fn retained_attachment_download_uses_its_value_bound_and_current_upload_policy() {
    let mut retained = proposal_document();
    retained["attachments"][SLOT]["maximumBytes"] = json!(4);
    retained["attachments"][SLOT]["contentTypes"] = json!(["text/plain"]);
    retained["attachments"][SLOT]["value"] = json!({
        "submissionVersion":2,"sha256":"a".repeat(64),"contentType":"application/pdf",
        "byteSize":PDF.len(),"uploadedAt":"2026-09-19T00:01:00Z","verificationStatus":"notRequired"
    });
    let too_large = [PDF, b"x"].concat();
    let oversized = MockResponse::bytes(StatusCode::OK, "application/pdf", &too_large)
        .with_header("content-disposition", "attachment")
        .with_header("x-content-type-options", "nosniff")
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization");
    let (fixture, proposal) =
        selected_with_document(retained.clone(), vec![download_response(), oversized]).await;
    let downloaded = fixture
        .client
        .download_proposal_attachment(&proposal, SLOT)
        .await
        .unwrap();
    assert_eq!(downloaded.value.as_bytes(), PDF);
    assert_eq!(downloaded.value.media_type(), "application/pdf");
    assert!(matches!(
        fixture
            .client
            .download_proposal_attachment(&proposal, SLOT)
            .await,
        Err(BaseRegistryClientError::Transport {
            kind: registry_breg_client::TransportKind::ResponseTooLarge
        })
    ));
    for (media, bytes) in [
        ("application/pdf", PDF),
        ("text/plain", b"12345".as_slice()),
    ] {
        assert!(fixture
            .client
            .upload_proposal_attachment(&proposal, SLOT, media, bytes, &key("current-upload"))
            .await
            .is_err());
    }
    assert_eq!(fixture.requests.lock().unwrap().len(), 4);
    retained["attachments"][SLOT]["value"]["byteSize"] =
        json!(registry_breg_client::MAX_BREG_ATTACHMENT_BYTES + 1);
    assert!(BRegProposal::from_slice(&serde_json::to_vec(&retained).unwrap()).is_err());
}

#[tokio::test]
async fn foreign_sources_missing_slots_and_disallowed_bytes_are_refused_before_io() {
    let (fixture, proposal) = selected(vec![]).await;
    for (mime, bytes) in [
        ("text/plain", PDF),
        ("application/pdf", b"".as_slice()),
        ("application/pdf", &vec![1; 1025]),
    ] {
        assert!(fixture
            .client
            .upload_proposal_attachment(&proposal, SLOT, mime, bytes, &key("bad"))
            .await
            .is_err());
    }
    assert!(fixture
        .client
        .delete_proposal_attachment(&proposal, "missing", &key("bad"))
        .await
        .is_err());
    let other = test_client(vec![]).await;
    assert!(other
        .client
        .download_proposal_attachment(&proposal, SLOT)
        .await
        .is_err());
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    assert!(other.requests.lock().unwrap().is_empty());
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
            download_response().with_header("link", "<https://example.test>; rel=\"profile\""),
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
            .download_proposal_attachment(&slot, SLOT)
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
    for (code, detail) in [
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
    ] {
        let (fixture, proposal) = selected(vec![problem_response(code, detail)]).await;
        let error = fixture
            .client
            .upload_proposal_attachment(&proposal, SLOT, "application/pdf", PDF, &key("upload"))
            .await
            .unwrap_err();
        assert_eq!(error.problem_code(), Some(code));
    }
}
#[test]
fn inert_attachment_descriptors_refuse_another_submission_or_proposal() {
    for path in [
        format!("/v1/proposals/{RECORD_ID}/attachments/{SLOT}?submissionVersion=1"),
        format!("/v1/records/companies/{RECORD_ID}/attachments/{SLOT}?submissionVersion=2"),
    ] {
        let mut document = proposal_document();
        document["attachments"][SLOT]["links"]["download"]["path"] = json!(path);
        assert!(BRegProposal::from_slice(&serde_json::to_vec(&document).unwrap()).is_err());
    }
}
#[tokio::test]
async fn a_mutation_response_for_another_proposal_is_refused() {
    let mut document = proposal_document();
    document["id"] = json!("00000000-0000-4000-8000-000000000002");
    document["attachments"] = json!({});
    let response = MockResponse::json(StatusCode::OK, document)
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept");
    let (fixture, proposal) = selected(vec![response]).await;
    assert!(fixture
        .client
        .delete_proposal_attachment(&proposal, SLOT, &key("remove"))
        .await
        .is_err());
}
