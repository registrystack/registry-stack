// SPDX-License-Identifier: Apache-2.0
//! Fixed five-route read-only Registry Discovery HTTP service.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{RawQuery, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, Request, Response};
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httpsec::{security_headers, CspBuilder};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::Semaphore;
use tower_http::trace::TraceLayer;

use crate::model::{
    EvidenceTypeResolveRequest, MAXIMUM_HTTP_BODY_BYTES, MINIMUM_HTTP_RESPONSE_BYTES,
};
pub use crate::openapi::{
    EVIDENCE_TYPES_ROUTE, HEALTH_ROUTE, OPENAPI_BYTES, OPENAPI_ROUTE, READY_ROUTE, SERVICES_ROUTE,
};
use crate::problem::ProblemCode;
use crate::query::{parse_service_filters, Directory};

const JSON: &str = "application/json";
const OPENAPI_JSON: &str = "application/vnd.oai.openapi+json;version=3.1";
const HEALTH_BYTES: &[u8] = br#"{"status":"ok"}"#;
const READY_BYTES: &[u8] = br#"{"status":"ready"}"#;
const BLOCKING_QUERY_CAPACITY: usize = 4;

pub struct DiscoveryService {
    directory: Directory,
    maximum_response_bytes: usize,
    blocking_queries: BlockingQueryExecutor,
}

#[derive(Clone)]
struct BlockingQueryExecutor {
    permits: Arc<Semaphore>,
}

impl BlockingQueryExecutor {
    fn new(capacity: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(capacity)),
        }
    }

    async fn run<T, F>(&self, operation: F) -> Result<T, ProblemCode>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, ProblemCode> + Send + 'static,
    {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| ProblemCode::Unavailable)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation()
        })
        .await
        .map_err(|_| ProblemCode::Unavailable)?
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("the Discovery HTTP limits are invalid")]
pub struct ServiceConfigError;

impl DiscoveryService {
    pub fn new(
        directory: Directory,
        maximum_response_bytes: usize,
    ) -> Result<Self, ServiceConfigError> {
        if !(MINIMUM_HTTP_RESPONSE_BYTES..=MAXIMUM_HTTP_BODY_BYTES)
            .contains(&maximum_response_bytes)
        {
            return Err(ServiceConfigError);
        }
        Ok(Self {
            directory,
            maximum_response_bytes,
            blocking_queries: BlockingQueryExecutor::new(BLOCKING_QUERY_CAPACITY),
        })
    }
}

#[derive(Clone, Copy)]
struct HttpLimits {
    maximum_request_bytes: usize,
    request_timeout: Duration,
}

pub fn router(
    service: Arc<DiscoveryService>,
    maximum_request_bytes: usize,
    request_timeout: Duration,
) -> Result<Router, ServiceConfigError> {
    if maximum_request_bytes == 0
        || maximum_request_bytes > MAXIMUM_HTTP_BODY_BYTES
        || request_timeout.is_zero()
        || request_timeout > Duration::from_secs(300)
    {
        return Err(ServiceConfigError);
    }
    Ok(Router::new()
        .route(HEALTH_ROUTE, get(health).head(not_found))
        .route(READY_ROUTE, get(ready).head(not_found))
        .route(OPENAPI_ROUTE, get(openapi).head(not_found))
        .route(SERVICES_ROUTE, get(search_services).head(not_found))
        .route(EVIDENCE_TYPES_ROUTE, post(resolve_evidence_types))
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        .with_state(service)
        .layer(middleware::from_fn_with_state(
            HttpLimits {
                maximum_request_bytes,
                request_timeout,
            },
            enforce_http_limits,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<Body>| {
                    tracing::info_span!(
                        target: "registry_discovery::http",
                        "http.request",
                        method = operational_method(request.method()),
                        route = operational_route(request.uri().path()),
                    )
                })
                .on_response(
                    |response: &Response<Body>, latency: Duration, span: &tracing::Span| {
                        tracing::info!(
                            parent: span,
                            status = response.status().as_u16(),
                            latency_milliseconds = latency.as_millis().min(u128::from(u32::MAX)) as u32,
                            "request completed"
                        );
                    },
                ),
        )
        .layer(security_headers(CspBuilder::restrictive())))
}

async fn enforce_http_limits(
    State(limits): State<HttpLimits>,
    request: Request<Body>,
    next: middleware::Next,
) -> Response<Body> {
    let exchange = async move {
        let (parts, body) = request.into_parts();
        let bytes = match to_bytes(body, limits.maximum_request_bytes).await {
            Ok(bytes) => bytes,
            Err(_) => return ProblemCode::InvalidRequest.response(),
        };
        next.run(Request::from_parts(parts, Body::from(bytes)))
            .await
    };
    match tokio::time::timeout(limits.request_timeout, exchange).await {
        Ok(response) => response,
        Err(_) => ProblemCode::Unavailable.response(),
    }
}

async fn health() -> Response<Body> {
    static_json(HEALTH_BYTES, JSON)
}

async fn ready() -> Response<Body> {
    static_json(READY_BYTES, JSON)
}

async fn openapi() -> Response<Body> {
    cacheable_static_json(OPENAPI_BYTES, OPENAPI_JSON)
}

async fn search_services(
    State(service): State<Arc<DiscoveryService>>,
    RawQuery(query): RawQuery,
) -> Response<Body> {
    let directory = service.directory.clone();
    let maximum_response_bytes = service.maximum_response_bytes;
    let operation = move || {
        let filters =
            parse_service_filters(query.as_deref().unwrap_or("")).map_err(ProblemCode::from)?;
        let response = directory
            .search_services(&filters)
            .map_err(ProblemCode::from)?;
        bounded_json_bytes(maximum_response_bytes, &response)
    };
    match service.blocking_queries.run(operation).await {
        Ok(bytes) => static_json(&bytes, JSON),
        Err(error) => error.response(),
    }
}

async fn resolve_evidence_types(
    State(service): State<Arc<DiscoveryService>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if !json_media_type(&headers) {
        return ProblemCode::InvalidRequest.response();
    }
    let directory = service.directory.clone();
    let maximum_response_bytes = service.maximum_response_bytes;
    let operation = move || {
        let request = strict_body::<EvidenceTypeResolveRequest>(&body)?;
        let response = directory
            .resolve_evidence_types(&request)
            .map_err(ProblemCode::from)?;
        bounded_json_bytes(maximum_response_bytes, &response)
    };
    match service.blocking_queries.run(operation).await {
        Ok(bytes) => static_json(&bytes, JSON),
        Err(error) => error.response(),
    }
}

async fn not_found() -> Response<Body> {
    ProblemCode::NotFound.response()
}

fn strict_body<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProblemCode> {
    let value = parse_json_strict(bytes).map_err(|_| ProblemCode::InvalidRequest)?;
    serde_json::from_value(value).map_err(|_| ProblemCode::InvalidRequest)
}

fn json_media_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(JSON))
}

fn bounded_json_bytes<T: Serialize>(
    maximum_response_bytes: usize,
    value: &T,
) -> Result<Vec<u8>, ProblemCode> {
    let bytes = serde_json::to_vec(value).map_err(|_| ProblemCode::Unavailable)?;
    if bytes.len() > maximum_response_bytes {
        return Err(ProblemCode::ResultBoundExceeded);
    }
    Ok(bytes)
}

fn static_json(bytes: &[u8], content_type: &'static str) -> Response<Body> {
    let mut response = Response::new(Body::from(bytes.to_vec()));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn cacheable_static_json(bytes: &[u8], content_type: &'static str) -> Response<Body> {
    let mut response = static_json(bytes, content_type);
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );
    response
}

fn operational_method(method: &http::Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        _ => "OTHER",
    }
}

fn operational_route(path: &str) -> &'static str {
    match path {
        HEALTH_ROUTE => HEALTH_ROUTE,
        READY_ROUTE => READY_ROUTE,
        OPENAPI_ROUTE => OPENAPI_ROUTE,
        SERVICES_ROUTE => SERVICES_ROUTE,
        EVIDENCE_TYPES_ROUTE => EVIDENCE_TYPES_ROUTE,
        _ => "unmatched",
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{mpsc, Mutex};

    use axum::body::to_bytes;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::model::tests::example_index;

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log capture").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedLogWriter(Arc::clone(&self.0))
        }
    }

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("log capture").clone())
                .expect("JSON logs are UTF-8")
        }
    }

    fn app(maximum_result_records: usize) -> Router {
        let directory = Directory::new(example_index(), maximum_result_records, 10).unwrap();
        let service = Arc::new(DiscoveryService::new(directory, 1024 * 1024).unwrap());
        router(service, 64 * 1024, Duration::from_secs(5)).unwrap()
    }

    #[tokio::test]
    async fn real_router_exposes_only_the_fixed_read_only_surface() {
        let app = app(10);
        for route in [HEALTH_ROUTE, READY_ROUTE, OPENAPI_ROUTE, SERVICES_ROUTE] {
            let response = app
                .clone()
                .oneshot(Request::get(route).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{route}");
        }
        let response = app
            .clone()
            .oneshot(
                Request::post(EVIDENCE_TYPES_ROUTE)
                    .header(CONTENT_TYPE, JSON)
                    .body(Body::from(
                        br#"{"requirementId":"urn:example:requirement","jurisdiction":"urn:example:jurisdiction"}"#
                            .as_slice(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        for (method, route) in [
            ("GET", "/v1/services/record-a"),
            ("POST", "/v1/services"),
            ("POST", "/v1/evidence-providers/resolve"),
            ("POST", "/reload"),
            ("GET", "/metrics"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(route)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {route}");
        }
    }

    #[tokio::test]
    async fn head_is_explicitly_concealed_on_every_get_route() {
        let app = app(10);
        for route in [HEALTH_ROUTE, READY_ROUTE, OPENAPI_ROUTE, SERVICES_ROUTE] {
            let response = app
                .clone()
                .oneshot(Request::head(route).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "HEAD {route}");
            assert_eq!(
                response.headers()[CONTENT_TYPE],
                "application/problem+json",
                "HEAD {route}"
            );
            assert_eq!(
                response.headers()[CACHE_CONTROL],
                "no-store",
                "HEAD {route}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_blocking_query_keeps_its_permit_and_capacity_recovers() {
        let executor = BlockingQueryExecutor::new(1);
        let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first_executor = executor.clone();
        let first = tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_millis(25),
                first_executor.run(move || {
                    let _ = first_started_tx.send(());
                    release_first_rx
                        .recv()
                        .map_err(|_| ProblemCode::Unavailable)?;
                    Ok::<_, ProblemCode>(())
                }),
            )
            .await
        });
        first_started_rx.await.expect("the first worker started");
        assert!(first.await.expect("the first caller joined").is_err());

        let (second_started_tx, mut second_started_rx) = tokio::sync::oneshot::channel();
        let second_executor = executor.clone();
        let second = tokio::spawn(async move {
            second_executor
                .run(move || {
                    let _ = second_started_tx.send(());
                    Ok::<_, ProblemCode>(7usize)
                })
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut second_started_rx)
                .await
                .is_err(),
            "the detached first worker must retain the only permit"
        );

        release_first_tx
            .send(())
            .expect("the detached worker can be released");
        tokio::time::timeout(Duration::from_secs(1), &mut second_started_rx)
            .await
            .expect("the second worker starts after capacity returns")
            .expect("the second worker reports startup");
        assert_eq!(second.await.expect("the second caller joined"), Ok(7));
        assert_eq!(
            executor
                .run(|| Ok::<_, ProblemCode>(8usize))
                .await
                .expect("the executor remains available"),
            8
        );
    }

    #[tokio::test]
    async fn openapi_route_serves_the_exact_embedded_bytes() {
        let response = app(10)
            .oneshot(Request::get(OPENAPI_ROUTE).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()[CACHE_CONTROL], "public, max-age=60");
        let bytes = to_bytes(response.into_body(), OPENAPI_BYTES.len() + 1)
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), OPENAPI_BYTES);
    }

    #[tokio::test]
    async fn probes_and_dynamic_query_results_are_never_cacheable() {
        let app = app(10);
        for route in [HEALTH_ROUTE, READY_ROUTE, SERVICES_ROUTE] {
            let response = app
                .clone()
                .oneshot(Request::get(route).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{route}");
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store", "{route}");
        }
        let response = app
            .oneshot(
                Request::post(EVIDENCE_TYPES_ROUTE)
                    .header(CONTENT_TYPE, JSON)
                    .body(Body::from(
                        br#"{"requirementId":"urn:example:requirement","jurisdiction":"urn:example:jurisdiction"}"#
                            .as_slice(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    }

    #[test]
    fn openapi_contract_matches_the_fixed_surface_and_repeated_filter_semantics() {
        let value = registry_platform_canonical_json::parse_json_strict(OPENAPI_BYTES).unwrap();
        let paths = value["paths"].as_object().unwrap();
        assert_eq!(
            paths.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                HEALTH_ROUTE,
                OPENAPI_ROUTE,
                READY_ROUTE,
                EVIDENCE_TYPES_ROUTE,
                SERVICES_ROUTE,
            ]
        );
        for (path, method) in [
            (HEALTH_ROUTE, "get"),
            (OPENAPI_ROUTE, "get"),
            (READY_ROUTE, "get"),
            (EVIDENCE_TYPES_ROUTE, "post"),
            (SERVICES_ROUTE, "get"),
        ] {
            let operations = paths[path].as_object().unwrap();
            assert_eq!(
                operations.keys().map(String::as_str).collect::<Vec<_>>(),
                [method]
            );
            assert!(operations[method]["responses"].get("400").is_some());
            assert!(operations[method]["responses"].get("503").is_some());
        }

        let parameters = paths[SERVICES_ROUTE]["get"]["parameters"]
            .as_array()
            .unwrap();
        assert_eq!(parameters.len(), 8);
        let expected = [
            "recordId",
            "serviceId",
            "serviceKind",
            "jurisdiction",
            "conformsTo",
            "evidenceType",
            "semanticClass",
            "operationFamily",
        ];
        assert_eq!(
            parameters
                .iter()
                .map(|parameter| parameter["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            expected
        );
        for parameter in parameters {
            assert_eq!(parameter["style"], "form");
            assert_eq!(parameter["explode"], true);
            assert_eq!(parameter["schema"]["type"], "array");
            assert!(parameter["schema"]["items"]["type"].is_string());
        }
        for removed in [
            "/v1/services/{recordId}",
            "/v1/evidence-providers/resolve",
            "/reload",
            "/federation",
            "/metrics",
        ] {
            assert!(paths.get(removed).is_none(), "{removed}");
        }
    }

    #[tokio::test]
    async fn duplicate_request_members_are_refused_by_the_real_router() {
        let response = app(10)
            .oneshot(
                Request::post(EVIDENCE_TYPES_ROUTE)
                    .header(CONTENT_TYPE, JSON)
                    .body(Body::from(
                        br#"{"requirementId":"urn:a","requirementId":"urn:b"}"#.as_slice(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn duplicate_request_media_type_headers_are_refused_by_the_real_router() {
        let response = app(10)
            .oneshot(
                Request::post(EVIDENCE_TYPES_ROUTE)
                    .header(CONTENT_TYPE, JSON)
                    .header(CONTENT_TYPE, JSON)
                    .body(Body::from(
                        br#"{"requirementId":"urn:example:requirement"}"#.as_slice(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_trace_and_problem_output_exclude_request_canaries() {
        let query_canary = "secret-query-canary";
        let body_canary = "secret-requirement-canary";
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::INFO)
            .with_writer(logs.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("the Discovery unit-test process installs one tracing subscriber");

        let response = app(10)
            .clone()
            .oneshot(
                Request::get(format!("{SERVICES_ROUTE}?unknown={query_canary}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains(query_canary));

        let response = app(10)
            .oneshot(
                Request::post(EVIDENCE_TYPES_ROUTE)
                    .header(CONTENT_TYPE, JSON)
                    .body(Body::from(format!(
                        r#"{{"requirementId":"urn:example:requirement","unexpected":"{body_canary}"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains(body_canary));

        let rendered = logs.text();
        assert!(rendered.contains(SERVICES_ROUTE), "{rendered}");
        assert!(rendered.contains(EVIDENCE_TYPES_ROUTE), "{rendered}");
        assert!(rendered.contains("request completed"), "{rendered}");
        assert!(rendered.contains("latency_milliseconds"), "{rendered}");
        for canary in [query_canary, body_canary] {
            assert!(!rendered.contains(canary));
        }
    }
}
