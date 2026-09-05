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
    WrongMedia,
    DuplicateMedia,
    TraceMissing,
    TraceUppercase,
    TraceDuplicate,
    BadProblem,
    Redirect,
    ConcealedNotFound,
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
        br#"{"type":"https://id.registrystack.org/problems/registry-breg/resource/not_found","title":"Not Found","status":404,"detail":"The requested resource was not found.","code":"resource.not_found","traceId":"4bf92f3577b34da6a3ce929d0e0e4736","extra":true}"#,
        Some(TRACEPARENT),
    );
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().expect("cache policy"));
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
    assert_eq!(error.kind(), "not_found");
    assert_eq!(captured.lock().expect("captured requests").len(), 1);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(RECORD_ID));
    assert!(!rendered.contains("companies"));
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
