use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use registry_breg_client::{
    BRegListRequest, BRegLookupRequest, BRegProblemCode, BRegProtocolFailure, BRegRecordFormat,
    BRegRecordOptions, BaseRegistryClient, BaseRegistryClientConfig, BaseRegistryClientError,
    TransportKind, REGISTRY_RECORD_CONTEXT_IDENTIFIER,
};
use registry_platform_httputil::client::{BearerToken, TokenError, TokenProvider};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use url::Url;

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
const SERVER_ETAG: &str = "\"breg-record-000000000001\"";
const PROFILE_LINK: &str = "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </tenant/prefix/v1/schemas/company>; rel=\"describedby\"";

#[derive(Clone)]
struct TestState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    mode: Mode,
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    uri: String,
    authorization: Option<String>,
    accept: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Mode {
    Happy,
    MissingLink,
    BadLink,
    DuplicateLink,
    MissingEtag,
    BadEtag,
    DuplicateEtag,
    CollectionEtag,
    MismatchedContinuation,
    CursorBytes(usize),
    WrongMedia,
    DuplicateMedia,
    TraceMissing,
    TraceUppercase,
    TraceDuplicate,
    BadProblem,
    UnknownProblem(u16, Option<ProblemChange>),
    Redirect,
    ConcealedNotFound,
    HugeBody,
}

#[derive(Clone, Copy)]
enum ProblemChange {
    Status,
    Trace,
    Type,
    CodeType,
    KnownCode,
    FieldPath,
    RefusalCode,
    DuplicateCode,
    DuplicateExtension,
    OpaqueExtensions,
    KnownExtraMember,
    LongTitle,
    LongDetail,
    HugeBody,
}

async fn handler(State(state): State<TestState>, request: Request<Body>) -> Response<Body> {
    let captured = CapturedRequest {
        method: request.method().to_string(),
        uri: request.uri().to_string(),
        authorization: header(&request, "authorization"),
        accept: header(&request, "accept"),
        content_type: header(&request, "content-type"),
        body: to_bytes(request.into_body(), 32 * 1024)
            .await
            .expect("bounded test request body")
            .to_vec(),
    };
    state
        .requests
        .lock()
        .expect("request capture lock")
        .push(captured.clone());

    match state.mode {
        Mode::Redirect => redirect_response(),
        Mode::BadProblem => malformed_problem(),
        Mode::UnknownProblem(status, change) => unknown_problem(status, change),
        Mode::ConcealedNotFound => registered_problem(BRegProblemCode::ResourceNotFound),
        Mode::TraceMissing => response(
            StatusCode::OK,
            "application/json",
            br#"{"status":"alive"}"#,
            None,
        ),
        Mode::TraceDuplicate => {
            let mut response = response(
                StatusCode::OK,
                "application/json",
                br#"{"status":"alive"}"#,
                Some(TRACEPARENT),
            );
            response
                .headers_mut()
                .append("traceparent", TRACEPARENT.parse().expect("traceparent"));
            response
        }
        Mode::TraceUppercase => response(
            StatusCode::OK,
            "application/json",
            br#"{"status":"alive"}"#,
            Some("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"),
        ),
        Mode::HugeBody => response(
            StatusCode::OK,
            "application/json",
            &vec![b'x'; 4096],
            Some(TRACEPARENT),
        ),
        mode => happy_response(&captured, mode),
    }
}

fn header(request: &Request<Body>, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn happy_response(request: &CapturedRequest, mode: Mode) -> Response<Body> {
    let path = request.uri.split('?').next().expect("request path");
    if path.ends_with("/health") {
        return response(
            StatusCode::OK,
            "application/json",
            br#"{"status":"alive"}"#,
            Some(TRACEPARENT),
        );
    }
    if path.ends_with("/ready") {
        return response(
            StatusCode::OK,
            "application/json",
            br#"{"status":"ready"}"#,
            Some(TRACEPARENT),
        );
    }
    if path.ends_with("/openapi.json") {
        return response(
            StatusCode::OK,
            "application/json",
            br#"{"openapi":"3.1.0"}"#,
            Some(TRACEPARENT),
        );
    }
    if path.ends_with("/v1/registry") || path.contains("/v1/schemas/") {
        return response(
            StatusCode::OK,
            "application/json",
            br#"{"document":"inert"}"#,
            Some(TRACEPARENT),
        );
    }

    let collection = request.method == "GET" && path.ends_with("/v1/records/companies");
    let json_ld = request.accept.as_deref() == Some("application/ld+json");
    let mut document = if collection {
        json!({
            "items": [record()],
            "pageInfo": {"nextCursor": "next-token"},
            "meta": meta(),
        })
    } else {
        json!({"data": record(), "meta": meta()})
    };
    if collection {
        if let Mode::CursorBytes(bytes) = mode {
            document["pageInfo"]["nextCursor"] = if request.uri.contains("$skiptoken=") {
                Value::Null
            } else {
                Value::String("A".repeat(bytes))
            };
        }
    }
    if collection
        && matches!(mode, Mode::MismatchedContinuation)
        && request.uri.contains("$skiptoken=")
    {
        document["meta"]["registryIdentifier"] = Value::String("other-registry".into());
    }
    if json_ld {
        document["@context"] = Value::String(REGISTRY_RECORD_CONTEXT_IDENTIFIER.into());
    }
    let media = if json_ld {
        "application/ld+json"
    } else {
        "application/json"
    };
    let mut wire = response(
        StatusCode::OK,
        media,
        &serde_json::to_vec(&document).expect("record serializes"),
        Some(TRACEPARENT),
    );
    match mode {
        Mode::WrongMedia => {
            wire = response(
                StatusCode::OK,
                "text/plain",
                &serde_json::to_vec(&document).expect("record serializes"),
                Some(TRACEPARENT),
            )
        }
        Mode::DuplicateMedia => {
            wire.headers_mut().append(
                "content-type",
                "application/json".parse().expect("content type"),
            );
        }
        _ => {}
    }
    match mode {
        Mode::MissingLink => {}
        Mode::BadLink => {
            wire.headers_mut().insert(
                "link",
                "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/wrong>; rel=\"describedby\""
                    .parse()
                    .expect("profile link"),
            );
        }
        Mode::DuplicateLink => {
            wire.headers_mut()
                .append("link", PROFILE_LINK.parse().expect("profile link"));
            wire.headers_mut()
                .append("link", PROFILE_LINK.parse().expect("profile link"));
        }
        _ => {
            wire.headers_mut()
                .insert("link", PROFILE_LINK.parse().expect("profile link"));
        }
    }
    let is_get = path.ends_with(RECORD_ID);
    if is_get && !matches!(mode, Mode::MissingEtag | Mode::BadEtag) {
        wire.headers_mut()
            .insert("etag", SERVER_ETAG.parse().expect("server etag"));
    }
    if matches!(mode, Mode::DuplicateEtag) {
        wire.headers_mut()
            .append("etag", SERVER_ETAG.parse().expect("server etag"));
    }
    if matches!(mode, Mode::BadEtag) {
        wire.headers_mut()
            .insert("etag", "\"not-a-server-etag\"".parse().expect("bad etag"));
    }
    if collection && matches!(mode, Mode::CollectionEtag) {
        wire.headers_mut()
            .insert("etag", SERVER_ETAG.parse().expect("server etag"));
    }
    wire
}

fn record() -> Value {
    json!({
        "recordIdentifier": RECORD_ID,
        "revisionIdentifier": "1",
        "domainData": {"legalName": "Example Ltd"},
    })
}

fn meta() -> Value {
    json!({
        "registryIdentifier": "business-registry",
        "datasetIdentifier": "legal-entities",
        "entityTypeIdentifier": "company",
    })
}

fn registered_problem(code: BRegProblemCode) -> Response<Body> {
    let body = serde_json::to_vec(&json!({
        "type": format!(
            "https://id.registrystack.org/problems/registry-breg/{}",
            code.code().replace('.', "/")
        ),
        "title": match code.status() {
            400 => "Bad Request", 401 => "Unauthorized", 404 => "Not Found",
            415 => "Unsupported Media Type", 503 => "Service Unavailable", _ => "Gateway Timeout",
        },
        "status": code.status(),
        "detail": match code {
            BRegProblemCode::ResourceNotFound => "The requested resource was not found.",
            _ => panic!("test only registers resource-not-found"),
        },
        "code": code.code(),
        "traceId": TRACE_ID,
    }))
    .expect("problem serializes");
    let mut response = response(
        StatusCode::from_u16(code.status()).expect("status"),
        "application/problem+json",
        &body,
        Some(TRACEPARENT),
    );
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().expect("cache policy"));
    response
}

fn malformed_problem() -> Response<Body> {
    let mut response = response(
        StatusCode::NOT_FOUND,
        "application/problem+json",
        br#"{"type":"https://id.registrystack.org/problems/registry-breg/resource/not_found","title":"Wrong known title","status":404,"detail":"The requested resource was not found.","code":"resource.not_found","traceId":"4bf92f3577b34da6a3ce929d0e0e4736"}"#,
        Some(TRACEPARENT),
    );
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().expect("cache policy"));
    response
}

fn unknown_problem(status: u16, change: Option<ProblemChange>) -> Response<Body> {
    let mut document = json!({
        "type": "https://id.registrystack.org/problems/registry-breg/future/refused",
        "title": "Future refusal",
        "status": status,
        "detail": "canary future detail",
        "code": "future.refused",
        "traceId": TRACE_ID,
    });
    match change {
        Some(ProblemChange::Status) => document["status"] = json!(409),
        Some(ProblemChange::Trace) => {
            document["traceId"] = json!("11111111111111111111111111111111")
        }
        Some(ProblemChange::Type) => document["type"] = json!("https://example.test/other"),
        Some(ProblemChange::CodeType) => document["code"] = json!(42),
        Some(ProblemChange::KnownCode) => {
            document["code"] = json!("action.refused");
            document["type"] =
                json!("https://id.registrystack.org/problems/registry-breg/action/refused");
            document["refusalCode"] = json!("declared-refusal");
        }
        Some(ProblemChange::FieldPath) => document["fieldPath"] = json!("/input/name"),
        Some(ProblemChange::RefusalCode) => document["refusalCode"] = json!("declared-refusal"),
        Some(ProblemChange::OpaqueExtensions) => {
            document["fieldPath"] = json!({"future": true});
            document["refusalCode"] = json!(null);
            document["reasonCode"] = json!(["future"]);
            document["entityId"] = json!(42);
            document["future"] = json!({"annotation": true});
        }
        Some(ProblemChange::KnownExtraMember) => {
            document["type"] =
                json!("https://id.registrystack.org/problems/registry-breg/resource/not_found");
            document["title"] = json!("Not Found");
            document["detail"] = json!("The requested resource was not found.");
            document["code"] = json!("resource.not_found");
            document["future"] = json!({"annotation": true});
        }
        Some(ProblemChange::LongTitle) => document["title"] = json!("x".repeat(129)),
        Some(ProblemChange::LongDetail) => document["detail"] = json!("x".repeat(257)),
        Some(ProblemChange::HugeBody) => document["detail"] = json!("x".repeat(5000)),
        _ => {}
    }
    let mut body = serde_json::to_string(&document).unwrap();
    if matches!(change, Some(ProblemChange::DuplicateCode)) {
        body.insert_str(1, "\"code\":\"future.other\",");
    }
    if matches!(change, Some(ProblemChange::DuplicateExtension)) {
        body.insert_str(1, "\"future\":{\"flag\":true,\"flag\":false},");
    }
    let mut response = response(
        StatusCode::from_u16(status).unwrap(),
        "application/problem+json",
        body.as_bytes(),
        Some(TRACEPARENT),
    );
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}

fn redirect_response() -> Response<Body> {
    let mut response = response(
        StatusCode::FOUND,
        "text/plain",
        b"redirect",
        Some(TRACEPARENT),
    );
    response.headers_mut().insert(
        "location",
        "/tenant/prefix/health".parse().expect("location"),
    );
    response
}

fn response(
    status: StatusCode,
    media_type: &str,
    body: &[u8],
    traceparent: Option<&str>,
) -> Response<Body> {
    let mut response = Response::new(Body::from(body.to_vec()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", media_type.parse().expect("media type"));
    if let Some(traceparent) = traceparent {
        response
            .headers_mut()
            .insert("traceparent", traceparent.parse().expect("traceparent"));
    }
    response
}

async fn test_client(
    mode: Mode,
    provider: Option<Arc<dyn TokenProvider>>,
    maximum: u64,
) -> (BaseRegistryClient, Arc<Mutex<Vec<CapturedRequest>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let address = listener.local_addr().expect("server address");
    let state = TestState {
        requests: requests.clone(),
        mode,
    };
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(handler)).with_state(state),
        )
        .await
        .expect("test server");
    });
    let mut config = BaseRegistryClientConfig::new(
        Url::parse(&format!("http://{address}/tenant/prefix")).expect("base URL"),
    )
    .with_max_response_bytes(maximum);
    if let Some(provider) = provider {
        config = config.with_token_provider(provider);
    }
    (BaseRegistryClient::new(config).expect("client"), requests)
}

#[tokio::test]
async fn caller_scoped_tokens_are_isolated_across_concurrent_requests() {
    let configured = Arc::new(CountingToken(AtomicUsize::new(0)));
    let (client, captured) =
        test_client(Mode::Happy, Some(configured.clone()), 8 * 1024 * 1024).await;
    let first = client.with_bearer_token(BearerToken::new("human-token-one").unwrap());
    let second = client.with_bearer_token(BearerToken::new("human-token-two").unwrap());

    let (first_result, second_result) = tokio::join!(
        first.registry_metadata(Some("reviewer")),
        second.registry_metadata(Some("reviewer")),
    );
    first_result.expect("first caller metadata");
    second_result.expect("second caller metadata");

    assert_eq!(configured.0.load(Ordering::SeqCst), 0);
    let mut credentials = captured
        .lock()
        .unwrap()
        .iter()
        .map(|request| request.authorization.clone().unwrap())
        .collect::<Vec<_>>();
    credentials.sort();
    assert_eq!(
        credentials,
        vec!["Bearer human-token-one", "Bearer human-token-two"]
    );
    let rendered = format!("{first:?} {second:?}");
    assert!(!rendered.contains("human-token-one"));
    assert!(!rendered.contains("human-token-two"));
}

#[derive(Debug)]
struct CountingToken(AtomicUsize);

#[async_trait]
impl TokenProvider for CountingToken {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BearerToken::new("secret-token")
    }
}

fn json_ld_options() -> BRegRecordOptions {
    BRegRecordOptions::default()
        .access_profile("public")
        .expect("access profile")
        .select(["legalName"])
        .expect("select")
        .format(BRegRecordFormat::JsonLd)
}

#[tokio::test]
async fn breg_paths_queries_credentials_and_record_representations_are_product_exact() {
    let provider = Arc::new(CountingToken(AtomicUsize::new(0)));
    let (client, captured) =
        test_client(Mode::Happy, Some(provider.clone()), 8 * 1024 * 1024).await;

    client.health().await.expect("health");
    client.ready().await.expect("ready");
    client.openapi(Some("public")).await.expect("openapi");
    client
        .registry_metadata(Some("public"))
        .await
        .expect("metadata");
    client
        .entity_schema("company", Some("public"))
        .await
        .expect("schema");

    let ordinary = client
        .get_record("companies", RECORD_ID, &BRegRecordOptions::default())
        .await
        .expect("ordinary JSON record");
    assert_eq!(
        ordinary.metadata.etag().expect("read etag").as_str(),
        SERVER_ETAG
    );

    let list = BRegListRequest::default()
        .options(json_ld_options())
        .filter("status eq 'active'")
        .expect("filter")
        .orderby("legalName asc")
        .expect("ordering")
        .top(10)
        .expect("top")
        .count(false);
    let first_page = client
        .list_records("companies", &list)
        .await
        .expect("list page");
    assert!(first_page.metadata.etag().is_none());
    let continuation = first_page.value.continuation.expect("continuation");
    client
        .continue_list(&continuation)
        .await
        .expect("next page");
    let lookup = BRegLookupRequest::new("by-number")
        .expect("selector")
        .options(json_ld_options())
        .value("number", json!(42))
        .expect("value");
    client
        .lookup_record("companies", &lookup)
        .await
        .expect("lookup");

    assert_eq!(provider.0.load(Ordering::SeqCst), 7);
    let captured = captured.lock().expect("captured requests").clone();
    assert_eq!(captured.len(), 9);
    for request in &captured {
        assert!(request.uri.starts_with("/tenant/prefix/"), "{request:?}");
    }
    assert_eq!(captured[0].uri, "/tenant/prefix/health");
    assert_eq!(captured[1].uri, "/tenant/prefix/ready");
    assert_eq!(captured[0].authorization, None);
    assert_eq!(captured[1].authorization, None);
    for request in &captured[2..] {
        assert_eq!(
            request.authorization.as_deref(),
            Some("Bearer secret-token")
        );
    }
    assert_eq!(
        captured[2].uri,
        "/tenant/prefix/openapi.json?accessProfile=public"
    );
    assert_eq!(
        captured[3].uri,
        "/tenant/prefix/v1/registry?accessProfile=public"
    );
    assert_eq!(
        captured[4].uri,
        "/tenant/prefix/v1/schemas/company?accessProfile=public"
    );
    assert_eq!(
        captured[5].uri,
        format!("/tenant/prefix/v1/records/companies/{RECORD_ID}")
    );
    assert_eq!(captured[5].accept.as_deref(), Some("application/json"));
    assert_eq!(
        captured[6].uri,
        "/tenant/prefix/v1/records/companies?accessProfile=public&$select=legalName&$filter=status%20eq%20%27active%27&$orderby=legalName%20asc&$top=10&$count=false"
    );
    assert_eq!(captured[6].accept.as_deref(), Some("application/ld+json"));
    assert_eq!(
        captured[7].uri,
        "/tenant/prefix/v1/records/companies?accessProfile=public&$skiptoken=next-token"
    );
    assert!(!captured[7].uri.contains("$select"));
    assert_eq!(captured[8].method, "POST");
    assert_eq!(
        captured[8].uri,
        "/tenant/prefix/v1/records/companies:lookup?accessProfile=public&$select=legalName"
    );
    assert_eq!(
        captured[8].content_type.as_deref(),
        Some("application/json")
    );
    assert_eq!(
        captured[8].body,
        br#"{"selector":"by-number","values":{"number":42}}"#
    );
}

#[tokio::test]
async fn invalid_breg_record_identifiers_are_rejected_before_authentication_or_io() {
    let provider = Arc::new(CountingToken(AtomicUsize::new(0)));
    let (client, captured) = test_client(Mode::Happy, Some(provider.clone()), 1024).await;
    let error = client
        .get_record(
            "companies",
            "not-a-canonical-uuid",
            &BRegRecordOptions::default(),
        )
        .await
        .expect_err("invalid UUID is refused locally");
    assert!(matches!(
        error,
        BaseRegistryClientError::InvalidRequest { .. }
    ));
    assert_eq!(provider.0.load(Ordering::SeqCst), 0);
    assert!(captured.lock().expect("captured requests").is_empty());
}

#[tokio::test]
async fn issued_cursor_envelope_bound_survives_typed_http_continuation() {
    // The filtered read regression returned 4,720 bytes; the v3 codec can issue
    // up to 10,978. Both must survive response decoding and request construction.
    for bytes in [4_720, 10_978] {
        let provider = Arc::new(CountingToken(AtomicUsize::new(0)));
        let (client, captured) =
            test_client(Mode::CursorBytes(bytes), Some(provider.clone()), 32 * 1024).await;
        let request = BRegListRequest::default()
            .options(json_ld_options())
            .filter("status eq 'active'")
            .expect("filter")
            .top(1)
            .expect("small page")
            .count(true);
        let first = client
            .list_records("companies", &request)
            .await
            .expect("first page");
        let continuation = first.value.continuation.expect("issued continuation");
        assert_eq!(continuation.projection().skiptoken.len(), bytes);
        let last = client
            .continue_list(&continuation)
            .await
            .expect("continuation page");
        assert!(last.value.continuation.is_none());
        assert_eq!(provider.0.load(Ordering::SeqCst), 2);
        let captured = captured.lock().expect("captured requests");
        assert_eq!(captured.len(), 2);
        let (_, query) = captured[1].uri.split_once('?').expect("continuation query");
        let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, "accessProfile");
        assert_eq!(pairs[0].1, "public");
        assert_eq!(pairs[1].0, "$skiptoken");
        assert_eq!(pairs[1].1.len(), bytes);
        assert_eq!(captured[1].accept.as_deref(), Some("application/ld+json"));
    }
}

#[tokio::test]
async fn response_cursor_above_the_codec_envelope_is_refused() {
    let (client, captured) = test_client(Mode::CursorBytes(10_979), None, 32 * 1024).await;
    let error = client
        .list_records("companies", &BRegListRequest::default())
        .await
        .expect_err("oversized cursor is refused");
    assert!(matches!(
        error,
        BaseRegistryClientError::Protocol {
            failure: BRegProtocolFailure::Body,
            ..
        }
    ));
    assert_eq!(captured.lock().expect("captured requests").len(), 1);
}

#[tokio::test]
async fn continuation_pages_must_preserve_the_first_page_collection_identity() {
    let (client, _) = test_client(Mode::MismatchedContinuation, None, 1024 * 1024).await;
    let first = client
        .list_records("companies", &BRegListRequest::default())
        .await
        .expect("first page");
    let continuation = first.value.continuation.expect("continuation");

    let error = client
        .continue_list(&continuation)
        .await
        .expect_err("mixed collection metadata is refused");
    assert!(matches!(
        error,
        BaseRegistryClientError::Protocol {
            failure: BRegProtocolFailure::Body,
            ..
        }
    ));
}

#[tokio::test]
async fn record_header_and_media_contracts_fail_closed() {
    for (mode, call, expected) in [
        (
            Mode::MissingLink,
            Call::Read,
            BRegProtocolFailure::ProfileLink,
        ),
        (Mode::BadLink, Call::Read, BRegProtocolFailure::ProfileLink),
        (
            Mode::DuplicateLink,
            Call::Read,
            BRegProtocolFailure::ProfileLink,
        ),
        (
            Mode::MissingEtag,
            Call::Read,
            BRegProtocolFailure::EntityTag,
        ),
        (Mode::BadEtag, Call::Read, BRegProtocolFailure::EntityTag),
        (
            Mode::DuplicateEtag,
            Call::Read,
            BRegProtocolFailure::EntityTag,
        ),
        (
            Mode::CollectionEtag,
            Call::List,
            BRegProtocolFailure::EntityTag,
        ),
        (Mode::WrongMedia, Call::Read, BRegProtocolFailure::MediaType),
        (
            Mode::DuplicateMedia,
            Call::Read,
            BRegProtocolFailure::MediaType,
        ),
    ] {
        let (client, _) = test_client(mode, None, 1024 * 1024).await;
        let error = match call {
            Call::Read => client
                .get_record("companies", RECORD_ID, &BRegRecordOptions::default())
                .await
                .expect_err("invalid record response"),
            Call::List => client
                .list_records("companies", &BRegListRequest::default())
                .await
                .expect_err("invalid list response"),
        };
        assert!(matches!(
            error,
            BaseRegistryClientError::Protocol { failure, .. } if failure == expected
        ));
    }
}

#[derive(Clone, Copy)]
enum Call {
    Read,
    List,
}

#[tokio::test]
async fn trace_and_problem_contracts_are_exact_and_concealment_has_no_fallback() {
    for mode in [
        Mode::TraceMissing,
        Mode::TraceUppercase,
        Mode::TraceDuplicate,
    ] {
        let (client, _) = test_client(mode, None, 1024).await;
        let error = client.health().await.expect_err("invalid trace refused");
        assert!(matches!(
            error,
            BaseRegistryClientError::Protocol {
                failure: BRegProtocolFailure::TraceContext,
                ..
            }
        ));
    }

    let (client, _) = test_client(Mode::BadProblem, None, 1024).await;
    let error = client
        .health()
        .await
        .expect_err("malformed problem refused");
    assert!(matches!(
        error,
        BaseRegistryClientError::Protocol {
            failure: BRegProtocolFailure::Problem,
            ..
        }
    ));

    let (client, captured) = test_client(Mode::ConcealedNotFound, None, 1024).await;
    let error = client
        .get_record("companies", RECORD_ID, &BRegRecordOptions::default())
        .await
        .expect_err("concealed not-found");
    assert_eq!(
        error.problem_code(),
        Some(BRegProblemCode::ResourceNotFound)
    );
    // app-developer-22: a missing record is its own error kind, not a generic
    // `"problem"` a caller must also check `status == 404` to recognize.
    assert_eq!(error.kind(), "not-found");
    assert_eq!(captured.lock().expect("captured requests").len(), 1);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(RECORD_ID));
    assert!(!rendered.contains("companies"));
}

#[tokio::test]
async fn unknown_problem_codes_fall_back_to_http_status_without_retaining_service_values() {
    for status in [400, 404, 422, 429, 500, 503] {
        let (client, captured) = test_client(Mode::UnknownProblem(status, None), None, 8192).await;
        let error = client
            .health()
            .await
            .expect_err("unknown code is still an HTTP error");
        assert_eq!(error.status(), Some(status));
        assert_eq!(error.kind(), "problem");
        assert_eq!(error.problem_code(), None);
        assert_eq!(error.trace_id().unwrap().as_str(), TRACE_ID);
        assert!(error.field_path().is_none());
        assert!(error.refusal_code().is_none());
        assert!(error.reason_code().is_none());
        assert_eq!(error.is_outcome_unknown(), status >= 500);
        assert_eq!(captured.lock().unwrap().len(), 1);
        let rendered = format!("{error:?} {error}");
        for value in [
            "future.refused",
            "Future refusal",
            "canary future detail",
            "https://",
        ] {
            assert!(!rendered.contains(value));
        }
    }
}

#[tokio::test]
async fn problem_extensions_are_ignored_without_inventing_unknown_code_semantics() {
    for change in [
        ProblemChange::FieldPath,
        ProblemChange::RefusalCode,
        ProblemChange::OpaqueExtensions,
    ] {
        let (client, _) = test_client(Mode::UnknownProblem(422, Some(change)), None, 8192).await;
        let error = client
            .health()
            .await
            .expect_err("unknown code stays an error");
        assert_eq!(error.kind(), "problem");
        assert_eq!(error.status(), Some(422));
        assert!(error.problem_code().is_none());
        assert!(error.field_path().is_none());
        assert!(error.refusal_code().is_none());
        assert!(error.reason_code().is_none());
    }
    let (client, _) = test_client(
        Mode::UnknownProblem(404, Some(ProblemChange::KnownExtraMember)),
        None,
        8192,
    )
    .await;
    let error = client
        .health()
        .await
        .expect_err("known code stays an error");
    assert_eq!(error.kind(), "not-found");
    assert_eq!(
        error.problem_code(),
        Some(BRegProblemCode::ResourceNotFound)
    );
}

#[tokio::test]
async fn unknown_problem_fallback_preserves_envelope_and_known_code_validation() {
    for change in [
        ProblemChange::Status,
        ProblemChange::Trace,
        ProblemChange::Type,
        ProblemChange::CodeType,
        ProblemChange::KnownCode,
        ProblemChange::DuplicateCode,
        ProblemChange::DuplicateExtension,
        ProblemChange::LongTitle,
        ProblemChange::LongDetail,
    ] {
        let (client, _) = test_client(Mode::UnknownProblem(422, Some(change)), None, 8192).await;
        let error = client
            .health()
            .await
            .expect_err("invalid Problem remains a protocol error");
        assert!(matches!(
            error,
            BaseRegistryClientError::Protocol {
                failure: BRegProtocolFailure::Problem,
                ..
            }
        ));
    }
    let (client, _) = test_client(
        Mode::UnknownProblem(422, Some(ProblemChange::HugeBody)),
        None,
        8192,
    )
    .await;
    assert!(matches!(
        client.health().await,
        Err(BaseRegistryClientError::Transport {
            kind: TransportKind::ResponseTooLarge
        })
    ));
}

#[tokio::test]
async fn redirects_with_bearer_and_oversize_bodies_are_refused_without_retry() {
    let provider = Arc::new(CountingToken(AtomicUsize::new(0)));
    let (client, captured) = test_client(Mode::Redirect, Some(provider.clone()), 1024).await;
    let error = client
        .openapi(Some("public"))
        .await
        .expect_err("redirect refused");
    assert!(matches!(error, BaseRegistryClientError::Protocol { .. }));
    assert_eq!(provider.0.load(Ordering::SeqCst), 1);
    let captured = captured.lock().expect("captured requests").clone();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].authorization.as_deref(),
        Some("Bearer secret-token")
    );

    let (client, _) = test_client(Mode::HugeBody, None, 32).await;
    let error = client.health().await.expect_err("oversize body refused");
    assert!(matches!(
        error,
        BaseRegistryClientError::Transport {
            kind: TransportKind::ResponseTooLarge
        }
    ));
}
