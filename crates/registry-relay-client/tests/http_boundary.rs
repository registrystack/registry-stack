use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use registry_platform_httputil::client::{BearerToken, TokenError, TokenProvider};
use registry_relay_client::{
    BoundingBox, CollectionContinuation, CollectionContinuationProjection,
    CollectionRouteProjection, Conditional, ListRequest, LookupRequest, ProblemCode,
    ProtocolFailure, RecordFormat, RecordOptions, RecordResponse, RelayClient, RelayClientConfig,
    RelayClientError, ResourceContinuation, ResourceListRequest, SdmxDataRequest,
    SdmxStructureKind, SdmxStructureRequest, SearchRequest, StrongEtag,
};
use serde_json::json;
use tokio::net::TcpListener;
use url::Url;

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const ETAG: &str = "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"";

#[derive(Clone)]
struct TestState {
    paths: Arc<Mutex<Vec<String>>>,
    mode: Mode,
}

#[derive(Clone, Copy)]
enum Mode {
    Routes,
    TraceMissing,
    TraceDuplicate,
    TraceUppercase,
    ProblemTraceMismatch,
    ProblemExtraMember,
    ProblemTraceMissing,
    ProblemTraceDuplicate,
    ProblemTraceUppercase,
    NotModified,
    NotModifiedMissingEtag,
    NotModifiedWrongEtag,
    Redirect,
    RateLimited,
    RateLimitedOverBound,
    ServiceRetry,
    Artifact,
    ArtifactInvalidMedia,
    ArtifactDuplicateMedia,
    TooManyHeaders,
    WrongMedia,
    RecordJson,
    RecordJsonLd,
    RecordJsonLdNonHttpsContext,
    RecordJsonLdMissingContext,
    RecordJsonLdMismatchedContext,
    RecordJsonLegacyContextPlacement,
    RecordJsonWithId,
    RecordJsonWithType,
    RecordJsonLdMissingId,
    RecordJsonLdMissingType,
}

#[derive(Clone, Copy)]
enum RecordIdentity {
    None,
    Complete,
    IdOnly,
    TypeOnly,
}

async fn handler(State(state): State<TestState>, request: Request<Body>) -> Response<Body> {
    state
        .paths
        .lock()
        .expect("path capture lock")
        .push(request.uri().to_string());
    match state.mode {
        Mode::TraceMissing => wire_response(
            StatusCode::OK,
            "application/json",
            br#"{"status":"ok"}"#,
            None,
        ),
        Mode::TraceDuplicate => {
            let mut response = wire_response(
                StatusCode::OK,
                "application/json",
                br#"{"status":"ok"}"#,
                Some(TRACEPARENT),
            );
            response
                .headers_mut()
                .append("traceparent", TRACEPARENT.parse().expect("traceparent"));
            response
        }
        Mode::TraceUppercase => wire_response(
            StatusCode::OK,
            "application/json",
            br#"{"status":"ok"}"#,
            Some("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"),
        ),
        Mode::ProblemTraceMismatch => {
            let code = ProblemCode::ResourceNotFound;
            let body = serde_json::to_vec(&json!({
                "type": code.type_uri(), "title": code.title(), "status": code.status(),
                "detail": code.detail(), "code": code.code(),
                "traceId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }))
            .expect("problem serializes");
            wire_response(
                StatusCode::NOT_FOUND,
                "application/problem+json",
                &body,
                Some(TRACEPARENT),
            )
        }
        Mode::ProblemExtraMember => {
            let code = ProblemCode::ResourceNotFound;
            let body = serde_json::to_vec(&json!({
                "type": code.type_uri(), "title": code.title(), "status": code.status(),
                "detail": code.detail(), "code": code.code(), "traceId": TRACE_ID,
                "unregistered": "must be refused",
            }))
            .expect("problem serializes");
            wire_response(
                StatusCode::NOT_FOUND,
                "application/problem+json",
                &body,
                Some(TRACEPARENT),
            )
        }
        Mode::ProblemTraceMissing => {
            let mut response = registered_problem(ProblemCode::ResourceNotFound);
            response.headers_mut().remove("traceparent");
            response
        }
        Mode::ProblemTraceDuplicate => {
            let mut response = registered_problem(ProblemCode::ResourceNotFound);
            response
                .headers_mut()
                .append("traceparent", TRACEPARENT.parse().expect("traceparent"));
            response
        }
        Mode::ProblemTraceUppercase => {
            let mut response = registered_problem(ProblemCode::ResourceNotFound);
            response.headers_mut().insert(
                "traceparent",
                "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"
                    .parse()
                    .expect("traceparent"),
            );
            response
        }
        Mode::NotModified => {
            let mut response = wire_response(
                StatusCode::NOT_MODIFIED,
                "application/json",
                b"",
                Some(TRACEPARENT),
            );
            response
                .headers_mut()
                .insert("etag", ETAG.parse().expect("etag"));
            response.headers_mut().insert(
                "content-length",
                "4096".parse().expect("representation content length"),
            );
            response
        }
        Mode::NotModifiedMissingEtag => wire_response(
            StatusCode::NOT_MODIFIED,
            "application/json",
            b"",
            Some(TRACEPARENT),
        ),
        Mode::NotModifiedWrongEtag => {
            let mut response = wire_response(
                StatusCode::NOT_MODIFIED,
                "application/json",
                b"",
                Some(TRACEPARENT),
            );
            response.headers_mut().insert(
                "etag",
                "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
                    .parse()
                    .expect("etag"),
            );
            response
        }
        Mode::Redirect => {
            let mut response = wire_response(
                StatusCode::FOUND,
                "text/plain",
                b"redirect",
                Some(TRACEPARENT),
            );
            response.headers_mut().insert(
                "location",
                "/tenant/prefix/ready".parse().expect("location"),
            );
            response
        }
        Mode::RateLimited => problem_with_retry(ProblemCode::RateLimited),
        Mode::RateLimitedOverBound => {
            let mut response = registered_problem(ProblemCode::RateLimited);
            response
                .headers_mut()
                .insert("retry-after", "61".parse().expect("retry-after"));
            response
        }
        Mode::ServiceRetry => problem_with_retry(ProblemCode::ServiceNotReady),
        Mode::Artifact => wire_response(
            StatusCode::OK,
            "application/yaml; charset=utf-8",
            b"openapi: 3.1.0\n",
            Some(TRACEPARENT),
        ),
        Mode::ArtifactInvalidMedia => wire_response(
            StatusCode::OK,
            "application/yaml; broken",
            b"untrusted",
            Some(TRACEPARENT),
        ),
        Mode::ArtifactDuplicateMedia => {
            let mut response = wire_response(
                StatusCode::OK,
                "application/yaml",
                b"untrusted",
                Some(TRACEPARENT),
            );
            response.headers_mut().append(
                "content-type",
                "application/json".parse().expect("content type"),
            );
            response
        }
        Mode::TooManyHeaders => {
            let mut response = wire_response(
                StatusCode::OK,
                "application/json",
                br#"{"status":"ok"}"#,
                Some(TRACEPARENT),
            );
            for index in 0..65 {
                response.headers_mut().insert(
                    format!("x-bound-{index}")
                        .parse::<axum::http::HeaderName>()
                        .expect("header name"),
                    "value".parse().expect("header value"),
                );
            }
            response
        }
        Mode::WrongMedia => wire_response(
            StatusCode::OK,
            "text/plain",
            br#"{"status":"ok"}"#,
            Some(TRACEPARENT),
        ),
        Mode::RecordJson => record_response(
            request.uri().path(),
            "application/json",
            None,
            false,
            RecordIdentity::None,
        ),
        Mode::RecordJsonLd => record_response(
            request.uri().path(),
            "application/ld+json",
            Some(json!([
                "https://id.registrystack.org/contexts/registry-record/v1",
                "https://relay.example.invalid/contexts/record.jsonld"
            ])),
            false,
            RecordIdentity::Complete,
        ),
        Mode::RecordJsonLdNonHttpsContext => record_response_with_meta_context(
            request.uri().path(),
            "application/ld+json",
            Some(json!([
                "https://id.registrystack.org/contexts/registry-record/v1",
                "file:///private/relay-context.jsonld"
            ])),
            false,
            RecordIdentity::Complete,
            "file:///private/relay-context.jsonld",
        ),
        Mode::RecordJsonLdMissingContext => record_response(
            request.uri().path(),
            "application/ld+json",
            None,
            false,
            RecordIdentity::Complete,
        ),
        Mode::RecordJsonLdMismatchedContext => record_response(
            request.uri().path(),
            "application/ld+json",
            Some(json!([
                "https://id.registrystack.org/contexts/registry-record/v1",
                "https://relay.example.invalid/contexts/not-the-metadata-context.jsonld"
            ])),
            false,
            RecordIdentity::Complete,
        ),
        Mode::RecordJsonLegacyContextPlacement => record_response(
            request.uri().path(),
            "application/json",
            None,
            true,
            RecordIdentity::None,
        ),
        Mode::RecordJsonWithId => record_response(
            request.uri().path(),
            "application/json",
            None,
            false,
            RecordIdentity::IdOnly,
        ),
        Mode::RecordJsonWithType => record_response(
            request.uri().path(),
            "application/json",
            None,
            false,
            RecordIdentity::TypeOnly,
        ),
        Mode::RecordJsonLdMissingId => record_response(
            request.uri().path(),
            "application/ld+json",
            Some(json!([
                "https://id.registrystack.org/contexts/registry-record/v1",
                "https://relay.example.invalid/contexts/record.jsonld"
            ])),
            false,
            RecordIdentity::TypeOnly,
        ),
        Mode::RecordJsonLdMissingType => record_response(
            request.uri().path(),
            "application/ld+json",
            Some(json!([
                "https://id.registrystack.org/contexts/registry-record/v1",
                "https://relay.example.invalid/contexts/record.jsonld"
            ])),
            false,
            RecordIdentity::IdOnly,
        ),
        Mode::Routes => route_response(request.uri().path()),
    }
}

fn record_response(
    path: &str,
    media_type: &str,
    json_ld_context: Option<serde_json::Value>,
    legacy_context_placement: bool,
    identity: RecordIdentity,
) -> Response<Body> {
    record_response_with_meta_context(
        path,
        media_type,
        json_ld_context,
        legacy_context_placement,
        identity,
        "https://relay.example.invalid/contexts/record.jsonld",
    )
}

fn record_response_with_meta_context(
    path: &str,
    media_type: &str,
    json_ld_context: Option<serde_json::Value>,
    legacy_context_placement: bool,
    identity: RecordIdentity,
    meta_context: &str,
) -> Response<Body> {
    let mut record = json!({
        "recordIdentifier": "record-1",
        "revisionIdentifier": "revision-1",
        "lifecycleState": "active",
        "schemaReference": "https://relay.example.invalid/schemas/record",
        "semanticModelReference": "https://relay.example.invalid/models/record",
        "authorityIdentifier": "authority",
        "recordedAt": "2026-09-01T00:00:00Z",
        "domainData": {"name": "Example"}
    });
    if legacy_context_placement {
        record["registryIdentifier"] = json!("legacy-registry");
    }
    if matches!(identity, RecordIdentity::Complete | RecordIdentity::IdOnly) {
        record["@id"] = json!("https://relay.example.invalid/v2/resources/people/records/record-1");
    }
    if matches!(
        identity,
        RecordIdentity::Complete | RecordIdentity::TypeOnly
    ) {
        record["@type"] = json!("https://relay.example.invalid/vocabulary/Person");
    }
    let meta = json!({
        "registryIdentifier": "registry",
        "datasetIdentifier": "dataset",
        "entityTypeIdentifier": "entity-type",
        "operationIdentifier": "record.read",
        "accessProfile": "public",
        "family": "consultation",
        "pattern": "retrieve",
        "disclosureProfile": "public",
        "contractRevision": "1",
        "sourceRevision": {"profile": "snapshot", "status": "versioned", "value": "1"},
        "selectedFields": ["name"],
        "links": {
            "self": "https://relay.example.invalid/v2/resources/records/record-1",
            "context": meta_context,
            "schema": "https://relay.example.invalid/schemas/record",
            "semanticModel": "https://relay.example.invalid/models/record"
        }
    });
    let mut document = if path.ends_with("/records") {
        json!({"items": [record], "pageInfo": {"nextCursor": null}, "meta": meta})
    } else {
        json!({"data": record, "meta": meta})
    };
    if let Some(context) = json_ld_context {
        document["@context"] = context;
    }
    let body = serde_json::to_vec(&document).expect("record response serializes");
    wire_response(StatusCode::OK, media_type, &body, Some(TRACEPARENT))
}

fn route_response(path: &str) -> Response<Body> {
    if path.ends_with("/health") {
        return wire_response(
            StatusCode::OK,
            "application/json",
            br#"{"status":"ok"}"#,
            Some(TRACEPARENT),
        );
    }
    if path.ends_with("/ready") {
        return wire_response(
            StatusCode::OK,
            "application/json",
            br#"{"status":"ready"}"#,
            Some(TRACEPARENT),
        );
    }
    if path.ends_with("/openapi.json") {
        return wire_response(
            StatusCode::OK,
            "application/json",
            br#"{"openapi":"3.1.0"}"#,
            Some(TRACEPARENT),
        );
    }
    registered_problem(ProblemCode::ResourceNotFound)
}

fn registered_problem(code: ProblemCode) -> Response<Body> {
    let body = serde_json::to_vec(&json!({
        "type": code.type_uri(), "title": code.title(), "status": code.status(),
        "detail": code.detail(), "code": code.code(), "traceId": TRACE_ID,
    }))
    .expect("problem serializes");
    wire_response(
        StatusCode::from_u16(code.status()).expect("problem status"),
        "application/problem+json",
        &body,
        Some(TRACEPARENT),
    )
}

fn problem_with_retry(code: ProblemCode) -> Response<Body> {
    let mut response = registered_problem(code);
    response
        .headers_mut()
        .insert("retry-after", "60".parse().expect("retry-after"));
    response
}

fn wire_response(
    status: StatusCode,
    media: &str,
    body: &[u8],
    traceparent: Option<&str>,
) -> Response<Body> {
    let mut response = Response::new(Body::from(body.to_vec()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", media.parse().expect("response media type"));
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
) -> (RelayClient, Arc<Mutex<Vec<String>>>) {
    test_client_with_max(mode, provider, 8 * 1024 * 1024).await
}

async fn test_client_with_max(
    mode: Mode,
    provider: Option<Arc<dyn TokenProvider>>,
    max_response_bytes: u64,
) -> (RelayClient, Arc<Mutex<Vec<String>>>) {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let state = TestState {
        paths: paths.clone(),
        mode,
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let address = listener.local_addr().expect("test address");
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(handler)).with_state(state),
        )
        .await
        .expect("test server");
    });
    let mut config = RelayClientConfig::new(
        Url::parse(&format!("http://{address}/tenant/prefix")).expect("base URL"),
    )
    .with_max_response_bytes(max_response_bytes);
    if let Some(provider) = provider {
        config = config.with_token_provider(provider);
    }
    (RelayClient::new(config).expect("client"), paths)
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

#[tokio::test]
async fn probes_and_openapi_never_acquire_a_token() {
    let provider = Arc::new(CountingToken(AtomicUsize::new(0)));
    let (client, _) = test_client(Mode::Routes, Some(provider.clone())).await;
    client.health().await.expect("health");
    client.ready().await.expect("ready");
    client.openapi(None).await.expect("openapi");
    assert_eq!(provider.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_access_profiles_are_rejected_before_auth_or_io() {
    let provider = Arc::new(CountingToken(AtomicUsize::new(0)));
    let (_client, paths) = test_client(Mode::Routes, Some(provider.clone())).await;

    for invalid in ["Public", "public_profile", "public--profile"] {
        assert!(matches!(
            RecordOptions::default().access_profile(invalid),
            Err(RelayClientError::InvalidRequest { .. })
        ));
    }
    assert!(
        CollectionContinuation::try_from_projection(CollectionContinuationProjection {
            route: CollectionRouteProjection::Records {
                resource: "people".into(),
            },
            cursor: "opaque_cursor-123".into(),
            format: RecordFormat::Json,
            access_profile: Some("Public_Profile".into()),
        })
        .is_err()
    );

    assert_eq!(provider.0.load(Ordering::SeqCst), 0);
    assert!(paths.lock().expect("paths").is_empty());
}

#[tokio::test]
async fn base_prefix_is_preserved_for_every_route_family() {
    let (client, paths) = test_client(Mode::Routes, None).await;
    let _ = client.health().await;
    let _ = client.ready().await;
    let _ = client.openapi(None).await;
    let _ = client.service_metadata(None).await;
    let _ = client.resources(ResourceListRequest::default(), None).await;
    let _ = client.resource("people", None).await;
    let _ = client
        .list_records("people", &ListRequest::default(), None)
        .await;
    let search_request =
        SearchRequest::new(BoundingBox::new(100.0, 13.0, 101.0, 14.0).expect("search bbox"));
    let _ = client
        .search_records("people", "by-name", &search_request, None)
        .await;
    let _ = client
        .read_record("people", "person-1", &RecordOptions::default(), None)
        .await;
    let lookup = LookupRequest::default()
        .selector("number", json!(42))
        .expect("lookup request");
    let _ = client
        .lookup_record("people", "by-number", &lookup, None)
        .await;
    let _ = client.artifact("schema", None).await;
    let data = SdmxDataRequest::new("AGENCY", "FLOW", "1.0.0")
        .expect("data request")
        .constraint("TIME_PERIOD", "ge:2020+le:2024")
        .expect("time constraint");
    let _ = client.sdmx_data(&data, None).await;
    let keyed = SdmxDataRequest::new("AGENCY", "FLOW", "1.0.0")
        .expect("data request")
        .keyed("South East,กรุงเทพ.*")
        .expect("non-code key");
    let _ = client.sdmx_data(&keyed, None).await;
    let structure =
        SdmxStructureRequest::new(SdmxStructureKind::Dataflow, "AGENCY", "FLOW", "1.0.0")
            .expect("structure request");
    let _ = client.sdmx_structure(&structure, None).await;
    let paths = paths.lock().expect("captured paths").clone();
    assert!(
        paths.iter().all(|path| path.starts_with("/tenant/prefix/")),
        "{paths:?}"
    );
    for expected in [
        "/tenant/prefix/health",
        "/tenant/prefix/ready",
        "/tenant/prefix/openapi.json",
        "/tenant/prefix/v2",
        "/tenant/prefix/v2/resources",
        "/tenant/prefix/v2/resources/people",
        "/tenant/prefix/v2/resources/people/records",
        "/tenant/prefix/v2/resources/people/searches/by-name",
        "/tenant/prefix/v2/resources/people/records/person-1",
        "/tenant/prefix/v2/resources/people/lookups/by-number",
        "/tenant/prefix/v2/artifacts/schema",
    ] {
        assert!(
            paths
                .iter()
                .any(|path| path.split('?').next() == Some(expected)),
            "missing {expected} in {paths:?}"
        );
    }
    assert!(paths
        .iter()
        .any(|path| path.starts_with("/tenant/prefix/sdmx/v2/data/dataflow/AGENCY/FLOW/1.0.0")));
    assert!(paths
        .iter()
        .any(|path| path.contains("ge%3A2020%2Ble%3A2024")));
    assert!(paths
        .iter()
        .any(|path| path.contains("South%20East,") && path.contains("%E0%B8%81")));
}

#[tokio::test]
async fn continuation_preserves_access_profile_and_representation_without_first_page_facts() {
    let (client, paths) = test_client(Mode::Routes, None).await;
    let continuation =
        CollectionContinuation::try_from_projection(CollectionContinuationProjection {
            route: CollectionRouteProjection::Records {
                resource: "people".into(),
            },
            cursor: "opaque_cursor-123".into(),
            format: RecordFormat::JsonFg,
            access_profile: Some("public".into()),
        })
        .expect("continuation");
    let _ = client.continue_collection(&continuation, None).await;
    let paths = paths.lock().expect("captured paths");
    let path = paths.last().expect("continuation request");
    assert!(path.contains("cursor=opaque_cursor-123"), "{path}");
    assert!(path.contains("accessProfile=public"), "{path}");
    assert!(!path.contains("formatProfile="), "{path}");
    assert!(!path.contains("fields="), "{path}");
    assert!(!path.contains("pageSize="), "{path}");
}

#[tokio::test]
async fn response_trace_requires_one_canonical_lowercase_v0_traceparent() {
    for mode in [
        Mode::TraceMissing,
        Mode::TraceDuplicate,
        Mode::TraceUppercase,
    ] {
        let (client, _) = test_client(mode, None).await;
        let error = client.health().await.expect_err("invalid trace refused");
        assert!(matches!(error, RelayClientError::Protocol { .. }));
    }
    let (client, _) = test_client(Mode::Routes, None).await;
    assert_eq!(
        client
            .health()
            .await
            .expect("canonical trace")
            .metadata
            .trace_id()
            .as_str(),
        TRACE_ID
    );
}

#[tokio::test]
async fn problem_requires_exact_registered_six_member_body_and_trace_equality() {
    for mode in [
        Mode::ProblemTraceMismatch,
        Mode::ProblemExtraMember,
        Mode::ProblemTraceMissing,
        Mode::ProblemTraceDuplicate,
        Mode::ProblemTraceUppercase,
    ] {
        let (client, _) = test_client(mode, None).await;
        let error = client
            .resource("people", None)
            .await
            .expect_err("malformed problem refused");
        assert!(matches!(error, RelayClientError::Protocol { .. }));
    }
    let (client, _) = test_client(Mode::Routes, None).await;
    let error = client
        .resource("people", None)
        .await
        .expect_err("registered problem");
    assert_eq!(error.problem_code(), Some(ProblemCode::ResourceNotFound));
}

#[tokio::test]
async fn not_modified_http_requires_matching_strong_sha256_etag() {
    let (client, _) = test_client(Mode::NotModified, None).await;
    let etag = StrongEtag::parse(ETAG).expect("strong etag");
    let result = client.openapi(Some(&etag)).await.expect("valid 304");
    assert!(matches!(result, Conditional::NotModified(_)));
    for mode in [Mode::NotModifiedWrongEtag, Mode::NotModifiedMissingEtag] {
        let (client, _) = test_client(mode, None).await;
        let error = client
            .openapi(Some(&etag))
            .await
            .expect_err("invalid not-modified response refused");
        assert!(matches!(error, RelayClientError::Protocol { .. }));
    }
}

#[tokio::test]
async fn redirects_are_reported_without_following_the_location() {
    let (client, paths) = test_client(Mode::Redirect, None).await;
    let error = client.health().await.expect_err("redirect refused");
    assert!(matches!(error, RelayClientError::Protocol { .. }));
    assert_eq!(paths.lock().expect("paths").len(), 1);
}

#[tokio::test]
async fn only_registered_429_exposes_bounded_retry_after() {
    let (client, paths) = test_client(Mode::RateLimited, None).await;
    let error = client
        .resource("people", None)
        .await
        .expect_err("rate limit problem");
    assert_eq!(error.problem_code(), Some(ProblemCode::RateLimited));
    assert_eq!(error.retry_after_seconds(), Some(60));
    assert_eq!(paths.lock().expect("paths").len(), 1);

    let (client, _) = test_client(Mode::RateLimitedOverBound, None).await;
    let error = client
        .resource("people", None)
        .await
        .expect_err("over-bound retry guidance");
    assert_eq!(error.problem_code(), Some(ProblemCode::RateLimited));
    assert_eq!(error.retry_after_seconds(), None);

    let (client, _) = test_client(Mode::ServiceRetry, None).await;
    let error = client
        .resource("people", None)
        .await
        .expect_err("service problem");
    assert_eq!(error.problem_code(), Some(ProblemCode::ServiceNotReady));
    assert_eq!(error.retry_after_seconds(), None);
}

#[tokio::test]
async fn artifact_preserves_one_syntactically_valid_server_media_type() {
    let (client, _) = test_client(Mode::Artifact, None).await;
    let response = client
        .artifact("openapi-full", None)
        .await
        .expect("artifact");
    let Conditional::Complete(complete) = response else {
        panic!("artifact unexpectedly not modified");
    };
    assert_eq!(
        complete.value.media_type(),
        "application/yaml; charset=utf-8"
    );
    assert_eq!(complete.value.as_bytes(), b"openapi: 3.1.0\n");
    assert!(!format!("{:?}", complete.value).contains("openapi: 3.1.0"));

    for mode in [Mode::ArtifactInvalidMedia, Mode::ArtifactDuplicateMedia] {
        let (client, _) = test_client(mode, None).await;
        assert!(matches!(
            client
                .artifact("openapi-full", None)
                .await
                .expect_err("invalid artifact media refused"),
            RelayClientError::Protocol { .. }
        ));
    }
}

#[tokio::test]
async fn response_headers_media_and_bodies_are_bounded_before_exposure() {
    let (client, _) = test_client(Mode::TooManyHeaders, None).await;
    let error = client.health().await.expect_err("header count refused");
    assert_eq!(error.status(), Some(200));

    let (client, _) = test_client(Mode::WrongMedia, None).await;
    assert!(matches!(
        client.health().await.expect_err("media type refused"),
        RelayClientError::Protocol { .. }
    ));

    let (client, _) = test_client_with_max(Mode::Routes, None, 4).await;
    assert!(matches!(
        client.health().await.expect_err("body bound refused"),
        RelayClientError::Transport { .. }
    ));
}

#[tokio::test]
async fn registry_record_context_is_response_metadata_and_json_ld_context_is_governed() {
    let (client, _) = test_client(Mode::RecordJson, None).await;
    let json = client
        .read_record("people", "record-1", &RecordOptions::default(), None)
        .await
        .expect("JSON Registry Record response");
    let Conditional::Complete(complete) = json else {
        panic!("record unexpectedly not modified");
    };
    let RecordResponse::Json(record) = complete.value else {
        panic!("ordinary JSON unexpectedly decoded as GeoJSON");
    };
    assert_eq!(record.meta.registry_identifier, "registry");
    assert_eq!(record.meta.dataset_identifier, "dataset");
    assert_eq!(record.meta.entity_type_identifier, "entity-type");
    assert!(record.json_ld_context.is_none());
    client
        .list_records("people", &ListRequest::default(), None)
        .await
        .expect("JSON Registry Record collection response");

    let (client, _) = test_client(Mode::RecordJsonLd, None).await;
    let json_ld = client
        .read_record(
            "people",
            "record-1",
            &RecordOptions::default().format(RecordFormat::JsonLd),
            None,
        )
        .await
        .expect("governed JSON-LD Registry Record response");
    let Conditional::Complete(complete) = json_ld else {
        panic!("JSON-LD record unexpectedly not modified");
    };
    let RecordResponse::Json(record) = complete.value else {
        panic!("JSON-LD unexpectedly decoded as GeoJSON");
    };
    assert_eq!(
        record
            .json_ld_context
            .as_ref()
            .expect("JSON-LD context")
            .relay_context(),
        record.meta.links.context
    );
    assert!(record.data.json_ld_id.is_some());
    assert!(record.data.json_ld_type.is_some());
    let json_ld_list =
        ListRequest::default().options(RecordOptions::default().format(RecordFormat::JsonLd));
    client
        .list_records("people", &json_ld_list, None)
        .await
        .expect("JSON-LD Registry Record collection response");

    for mode in [
        Mode::RecordJsonLdMissingContext,
        Mode::RecordJsonLdMismatchedContext,
        Mode::RecordJsonLdNonHttpsContext,
        Mode::RecordJsonLegacyContextPlacement,
    ] {
        let (client, _) = test_client(mode, None).await;
        let options = match mode {
            Mode::RecordJsonLegacyContextPlacement => RecordOptions::default(),
            _ => RecordOptions::default().format(RecordFormat::JsonLd),
        };
        let error = client
            .read_record("people", "record-1", &options, None)
            .await
            .expect_err("malformed Registry Record response refused");
        assert!(matches!(
            error,
            RelayClientError::Protocol {
                failure: ProtocolFailure::Body,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn registry_record_identity_is_media_specific_for_single_and_collection_responses() {
    for (mode, format, malformed_member) in [
        (Mode::RecordJsonWithId, RecordFormat::Json, "JSON @id"),
        (Mode::RecordJsonWithType, RecordFormat::Json, "JSON @type"),
        (
            Mode::RecordJsonLdMissingId,
            RecordFormat::JsonLd,
            "JSON-LD missing @id",
        ),
        (
            Mode::RecordJsonLdMissingType,
            RecordFormat::JsonLd,
            "JSON-LD missing @type",
        ),
    ] {
        let (client, _) = test_client(mode, None).await;
        let options = RecordOptions::default().format(format);
        let error = client
            .read_record("people", "record-1", &options, None)
            .await
            .expect_err("media-specific record identity violation refused");
        assert!(
            matches!(
                error,
                RelayClientError::Protocol {
                    failure: ProtocolFailure::Body,
                    ..
                }
            ),
            "single response with {malformed_member} must fail at the protocol boundary"
        );

        let request = ListRequest::default().options(options);
        let error = client
            .list_records("people", &request, None)
            .await
            .expect_err("media-specific collection item identity violation refused");
        assert!(
            matches!(
                error,
                RelayClientError::Protocol {
                    failure: ProtocolFailure::Body,
                    ..
                }
            ),
            "collection item with {malformed_member} must fail at the protocol boundary"
        );
    }
}

#[test]
fn continuations_cannot_mix_first_page_facts() {
    assert!(ResourceContinuation::try_from_cursor("bad+cursor").is_err());
    let resource = ResourceContinuation::try_from_cursor("opaque_resource-123")
        .expect("resource continuation");
    let projection = resource.projection();
    assert_eq!(projection.cursor, "opaque_resource-123");
    assert_eq!(
        ResourceContinuation::try_from_projection(projection)
            .expect("rehydrated resource continuation")
            .cursor(),
        "opaque_resource-123"
    );
    let projection = CollectionContinuationProjection {
        route: CollectionRouteProjection::Search {
            resource: "people".into(),
            search: "by-name".into(),
        },
        cursor: "opaque_cursor-123".into(),
        format: RecordFormat::JsonFg,
        access_profile: Some("caseworker".into()),
    };
    let continuation =
        CollectionContinuation::try_from_projection(projection.clone()).expect("continuation");
    assert_eq!(continuation.projection(), projection);
    let serialized = serde_json::to_value(&continuation).expect("serializes");
    assert!(serialized.get("pageSize").is_none());
    assert!(serialized.get("fields").is_none());
    assert!(serialized.get("filters").is_none());
    assert!(serialized.get("bbox").is_none());
}
