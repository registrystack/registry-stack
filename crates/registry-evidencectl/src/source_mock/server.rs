use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderValue, Method, Request, Response, StatusCode},
    response::IntoResponse,
    routing::any,
    Router,
};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");
const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const ALLOW_GET: HeaderValue = HeaderValue::from_static("GET");
const MAX_CONCURRENT_REQUESTS: usize = 64;
const MAX_REQUEST_TARGET_BYTES: usize = 8 * 1024;

const NOT_FOUND_PROBLEM: &[u8] =
    br#"{"type":"about:blank","title":"not found","status":404,"code":"source_mock.not_found"}
"#;
const METHOD_NOT_ALLOWED_PROBLEM: &[u8] =
    br#"{"type":"about:blank","title":"method not allowed","status":405,"code":"source_mock.method_not_allowed"}
"#;
const UNSUPPORTED_PROBLEM: &[u8] =
    br#"{"type":"about:blank","title":"route not implemented","status":501,"code":"source_mock.unsupported_route"}
"#;
const GENERATION_FAILED_PROBLEM: &[u8] =
    br#"{"type":"about:blank","title":"response generation failed","status":500,"code":"source_mock.generation_failed"}
"#;
const BUSY_PROBLEM: &[u8] =
    br#"{"type":"about:blank","title":"server busy","status":503,"code":"source_mock.busy"}
"#;

type ResponseGenerator = dyn Fn(&BTreeMap<String, String>) -> Result<Option<Vec<u8>>> + Send + Sync;

#[derive(Clone)]
pub struct RouteSnapshot {
    routes: Arc<[CompiledRoute]>,
}

impl fmt::Debug for RouteSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteSnapshot")
            .field("route_count", &self.routes.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct RouteSpec {
    pub method: Method,
    pub path_template: String,
    pub outcome: RouteOutcome,
}

#[derive(Clone)]
pub enum RouteOutcome {
    Json { body: Vec<u8> },
    Generated { generate: Arc<ResponseGenerator> },
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Readiness {
    pub local_addr: SocketAddr,
    pub route_count: usize,
    pub unsupported_route_count: usize,
}

#[derive(Clone)]
struct CompiledRoute {
    segments: Arc<[Segment]>,
    specificity: Arc<[bool]>,
    index: usize,
    outcome: CompiledOutcome,
}

struct ServerState {
    snapshot: RouteSnapshot,
    permits: Arc<Semaphore>,
}

#[derive(Clone)]
enum CompiledOutcome {
    Json { body: Arc<[u8]> },
    Generated { generate: Arc<ResponseGenerator> },
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Segment {
    Literal(String),
    Parameter(String),
}

#[derive(Debug, Eq, PartialEq)]
enum Match {
    Found(usize, BTreeMap<String, String>),
    NoRoute,
    WrongMethod,
}

impl RouteSpec {
    pub fn json(path_template: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method: Method::GET,
            path_template: path_template.into(),
            outcome: RouteOutcome::Json { body: body.into() },
        }
    }

    pub fn generated<F>(path_template: impl Into<String>, generate: F) -> Self
    where
        F: Fn(&BTreeMap<String, String>) -> Result<Option<Vec<u8>>> + Send + Sync + 'static,
    {
        Self {
            method: Method::GET,
            path_template: path_template.into(),
            outcome: RouteOutcome::Generated {
                generate: Arc::new(generate),
            },
        }
    }

    pub fn unsupported_get(path_template: impl Into<String>) -> Self {
        Self {
            method: Method::GET,
            path_template: path_template.into(),
            outcome: RouteOutcome::Unsupported,
        }
    }
}

impl RouteSnapshot {
    pub fn new(routes: Vec<RouteSpec>) -> Result<Self> {
        if routes.is_empty() {
            bail!("source mock server needs at least one route");
        }

        let mut seen_shapes = BTreeSet::new();
        let mut compiled = Vec::with_capacity(routes.len());
        for (index, route) in routes.into_iter().enumerate() {
            if route.method != Method::GET {
                bail!("source mock server only serves GET routes");
            }
            let segments = parse_template(&route.path_template).with_context(|| {
                format!(
                    "invalid source mock route template `{}`",
                    route.path_template
                )
            })?;
            let shape = shape_key(&segments);
            if !seen_shapes.insert(shape) {
                bail!("source mock server route templates must be structurally distinct");
            }
            let specificity = segments
                .iter()
                .map(|segment| matches!(segment, Segment::Literal(_)))
                .collect::<Vec<_>>()
                .into();
            let outcome = match route.outcome {
                RouteOutcome::Json { body } => CompiledOutcome::Json { body: body.into() },
                RouteOutcome::Generated { generate } => CompiledOutcome::Generated { generate },
                RouteOutcome::Unsupported => CompiledOutcome::Unsupported,
            };
            compiled.push(CompiledRoute {
                segments: segments.into(),
                specificity,
                index,
                outcome,
            });
        }

        compiled.sort_by(compare_routes);
        Ok(Self {
            routes: compiled.into(),
        })
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    pub fn unsupported_route_count(&self) -> usize {
        self.routes
            .iter()
            .filter(|route| matches!(route.outcome, CompiledOutcome::Unsupported))
            .count()
    }

    fn match_request(&self, method: &Method, raw_path: &str) -> Match {
        let Some(path_segments) = split_raw_path(raw_path) else {
            return Match::NoRoute;
        };
        let matched = self.routes.iter().enumerate().find_map(|(index, route)| {
            route
                .match_parameters(&path_segments)
                .map(|parameters| (index, parameters))
        });
        match (method == Method::GET, matched) {
            (true, Some((index, parameters))) => Match::Found(index, parameters),
            (true, None) => Match::NoRoute,
            (false, Some(_)) => Match::WrongMethod,
            (false, None) => Match::NoRoute,
        }
    }
}

impl CompiledRoute {
    fn match_parameters(&self, path_segments: &[&str]) -> Option<BTreeMap<String, String>> {
        if self.segments.len() != path_segments.len() {
            return None;
        }
        let mut parameters = BTreeMap::new();
        for (template, actual) in self.segments.iter().zip(path_segments) {
            match template {
                Segment::Literal(literal) if literal == actual => {}
                Segment::Literal(_) => return None,
                Segment::Parameter(name) => {
                    let decoded = decode_parameter(actual)?;
                    parameters.insert(name.clone(), decoded);
                }
            }
        }
        Some(parameters)
    }
}

pub fn router(snapshot: RouteSnapshot) -> Router {
    Router::new()
        .route("/", any(handle))
        .fallback(handle)
        .with_state(Arc::new(ServerState {
            snapshot,
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        }))
}

pub fn validate_numeric_loopback_addr(addr: SocketAddr) -> Result<SocketAddr> {
    if addr.port() == 0 {
        bail!("source mock bind address needs an explicit non-zero port");
    }
    if !is_numeric_loopback(addr.ip()) {
        bail!("source mock bind address must be a numeric loopback address");
    }
    Ok(addr)
}

pub async fn bind_validated_listener(addr: SocketAddr) -> Result<TcpListener> {
    let addr = validate_numeric_loopback_addr(addr)?;
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding source mock listener at {addr}"))
}

pub async fn serve_foreground<F>(
    snapshot: RouteSnapshot,
    bind_addr: SocketAddr,
    on_ready: F,
) -> Result<()>
where
    F: FnOnce(&Readiness),
{
    serve_with_shutdown(snapshot, bind_addr, on_ready, shutdown_signal()).await
}

pub async fn serve_with_shutdown<F, S>(
    snapshot: RouteSnapshot,
    bind_addr: SocketAddr,
    on_ready: F,
    shutdown: S,
) -> Result<()>
where
    F: FnOnce(&Readiness),
    S: Future<Output = ()> + Send + 'static,
{
    let listener = bind_validated_listener(bind_addr).await?;
    let readiness = Readiness {
        local_addr: listener
            .local_addr()
            .context("reading source mock listener address")?,
        route_count: snapshot.route_count(),
        unsupported_route_count: snapshot.unsupported_route_count(),
    };
    on_ready(&readiness);

    axum::serve(listener, router(snapshot))
        .with_graceful_shutdown(shutdown)
        .await
        .context("serving source mock")
}

async fn handle(State(state): State<Arc<ServerState>>, request: Request<Body>) -> Response<Body> {
    let Ok(_permit) = Arc::clone(&state.permits).try_acquire_owned() else {
        return fixed_problem(StatusCode::SERVICE_UNAVAILABLE);
    };
    if request
        .uri()
        .path_and_query()
        .is_some_and(|target| target.as_str().len() > MAX_REQUEST_TARGET_BYTES)
    {
        return fixed_problem(StatusCode::NOT_FOUND);
    }
    match state
        .snapshot
        .match_request(request.method(), request.uri().path())
    {
        Match::Found(index, parameters) => match &state.snapshot.routes[index].outcome {
            CompiledOutcome::Json { body } => json_response(body.clone()),
            CompiledOutcome::Generated { generate } => match generate(&parameters) {
                Ok(Some(body)) => json_response(body.into()),
                Ok(None) => fixed_problem(StatusCode::NOT_FOUND),
                Err(_) => fixed_problem(StatusCode::INTERNAL_SERVER_ERROR),
            },
            CompiledOutcome::Unsupported => fixed_problem(StatusCode::NOT_IMPLEMENTED),
        },
        Match::WrongMethod => fixed_problem(StatusCode::METHOD_NOT_ALLOWED),
        Match::NoRoute => fixed_problem(StatusCode::NOT_FOUND),
    }
}

fn json_response(body: Arc<[u8]>) -> Response<Body> {
    let mut response = (StatusCode::OK, Body::from(body.to_vec())).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, APPLICATION_JSON);
    response
}

fn fixed_problem(status: StatusCode) -> Response<Body> {
    let body = match status {
        StatusCode::NOT_FOUND => NOT_FOUND_PROBLEM,
        StatusCode::METHOD_NOT_ALLOWED => METHOD_NOT_ALLOWED_PROBLEM,
        StatusCode::NOT_IMPLEMENTED => UNSUPPORTED_PROBLEM,
        StatusCode::INTERNAL_SERVER_ERROR => GENERATION_FAILED_PROBLEM,
        StatusCode::SERVICE_UNAVAILABLE => BUSY_PROBLEM,
        _ => NOT_FOUND_PROBLEM,
    };
    let mut response = (status, Body::from(body.to_vec())).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    if status == StatusCode::METHOD_NOT_ALLOWED {
        response.headers_mut().insert(header::ALLOW, ALLOW_GET);
    }
    response
}

fn is_numeric_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip == Ipv6Addr::LOCALHOST,
    }
}

fn parse_template(template: &str) -> Result<Vec<Segment>> {
    if !template.starts_with('/') {
        bail!("route template must start with `/`");
    }
    if template.contains('?') || template.contains('#') {
        bail!("route template must contain only a path");
    }
    if template == "/" {
        return Ok(Vec::new());
    }
    let mut parameter_names = BTreeSet::new();
    template
        .strip_prefix('/')
        .ok_or_else(|| anyhow!("route template must start with `/`"))?
        .split('/')
        .map(|segment| {
            if segment.is_empty() {
                bail!("route template cannot contain empty path segments");
            }
            if segment.starts_with('{') || segment.ends_with('}') {
                let name = segment
                    .strip_prefix('{')
                    .and_then(|name| name.strip_suffix('}'))
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| anyhow!("path parameters must occupy a whole segment"))?;
                if !parameter_names.insert(name.to_owned()) {
                    bail!("route template cannot repeat a path parameter");
                }
                Ok(Segment::Parameter(name.to_owned()))
            } else {
                Ok(Segment::Literal(segment.to_owned()))
            }
        })
        .collect()
}

fn split_raw_path(path: &str) -> Option<Vec<&str>> {
    if !path.starts_with('/') {
        return None;
    }
    if path == "/" {
        return Some(Vec::new());
    }
    Some(path.strip_prefix('/')?.split('/').collect())
}

fn shape_key(segments: &[Segment]) -> Vec<Option<String>> {
    segments
        .iter()
        .map(|segment| match segment {
            Segment::Literal(literal) => Some(literal.clone()),
            Segment::Parameter(_) => None,
        })
        .collect()
}

fn decode_parameter(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = decode_hex(*bytes.get(index + 1)?)?;
            let low = decode_hex(*bytes.get(index + 2)?)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let decoded = String::from_utf8(decoded).ok()?;
    if decoded.is_empty() || decoded.contains(['/', '\\']) || decoded.chars().any(char::is_control)
    {
        return None;
    }
    Some(decoded)
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn compare_routes(left: &CompiledRoute, right: &CompiledRoute) -> Ordering {
    compare_specificity(&left.specificity, &right.specificity)
        .then_with(|| right.segments.len().cmp(&left.segments.len()))
        .then_with(|| left.index.cmp(&right.index))
}

fn compare_specificity(left: &[bool], right: &[bool]) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        match (*left, *right) {
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            _ => {}
        }
    }
    right.len().cmp(&left.len())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(_) => ctrl_c.await,
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use axum::{
        body::{to_bytes, Body},
        http::{header, Method, Request, StatusCode},
    };
    use tokio::sync::oneshot;
    use tower::ServiceExt;

    use super::*;

    fn app() -> Router {
        router(
            RouteSnapshot::new(vec![
                RouteSpec::json("/pets/{pet_id}", br#"{"kind":"template"}"#.to_vec()),
                RouteSpec::json("/pets/special", br#"{"kind":"literal"}"#.to_vec()),
                RouteSpec::generated("/numbers/{id}", |parameters| {
                    Ok((parameters.get("id").map(String::as_str) == Some("1"))
                        .then(|| br#"{"id":1}"#.to_vec()))
                }),
                RouteSpec::unsupported_get("/skipped/{id}"),
            ])
            .expect("snapshot"),
        )
    }

    async fn body_text(response: Response<Body>) -> String {
        String::from_utf8(
            to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body")
                .to_vec(),
        )
        .expect("utf8")
    }

    #[tokio::test]
    async fn literal_routes_win_before_template_routes() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/pets/special?selector=secret-canary")
                    .header("x-selector", "secret-canary")
                    .body(Body::from("secret-canary"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&APPLICATION_JSON)
        );
        assert_eq!(body_text(response).await, r#"{"kind":"literal"}"#);
    }

    #[tokio::test]
    async fn query_headers_and_body_do_not_change_selected_bytes() {
        let baseline = app()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/pets/123")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let controlled = app()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/pets/123?__dynamic=secret-canary")
                    .header("prefer", "secret-canary")
                    .body(Body::from("secret-canary"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(baseline.status(), StatusCode::OK);
        assert_eq!(controlled.status(), StatusCode::OK);
        assert_eq!(body_text(baseline).await, body_text(controlled).await);
    }

    #[tokio::test]
    async fn fixed_problems_are_value_free() {
        let cases = [
            (Method::GET, "/absent/secret-canary", StatusCode::NOT_FOUND),
            (
                Method::POST,
                "/pets/secret-canary",
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                Method::GET,
                "/skipped/secret-canary",
                StatusCode::NOT_IMPLEMENTED,
            ),
        ];

        for (method, uri, status) in cases {
            let response = app()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("cookie", "secret-canary")
                        .body(Body::from("secret-canary"))
                        .expect("request"),
                )
                .await
                .expect("response");

            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE),
                Some(&PROBLEM_JSON)
            );
            if status == StatusCode::METHOD_NOT_ALLOWED {
                assert_eq!(response.headers().get(header::ALLOW), Some(&ALLOW_GET));
            }
            let body = body_text(response).await;
            assert!(!body.contains("secret-canary"), "problem leaked: {body}");
        }
    }

    #[tokio::test]
    async fn a_template_value_rejected_by_its_schema_is_not_a_route_match() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/numbers/not-an-integer")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn bind_validation_accepts_only_explicit_numeric_loopback() {
        assert!(
            validate_numeric_loopback_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 4010))).is_ok()
        );
        assert!(
            validate_numeric_loopback_addr(SocketAddr::from((Ipv6Addr::LOCALHOST, 4010))).is_ok()
        );
        assert!(
            validate_numeric_loopback_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).is_err()
        );
        assert!(validate_numeric_loopback_addr(SocketAddr::from(([0, 0, 0, 0], 4010))).is_err());
        assert!(validate_numeric_loopback_addr(SocketAddr::from(([192, 0, 2, 1], 4010))).is_err());
    }

    #[test]
    fn structurally_indistinguishable_templates_are_rejected() {
        let error = RouteSnapshot::new(vec![
            RouteSpec::json("/people/{person_id}", b"{}".to_vec()),
            RouteSpec::json("/people/{other}", b"{}".to_vec()),
        ])
        .expect_err("ambiguous");

        assert!(format!("{error:#}").contains("structurally distinct"));
    }

    #[tokio::test]
    async fn serve_reports_readiness_after_bind_and_stops_gracefully() {
        let holder = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
        let addr = holder.local_addr().expect("reserved address");
        drop(holder);

        let snapshot =
            RouteSnapshot::new(vec![RouteSpec::json("/ready", br#"{"ok":true}"#.to_vec())])
                .expect("snapshot");
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();

        let task = tokio::spawn(serve_with_shutdown(
            snapshot,
            addr,
            move |readiness| {
                ready_tx
                    .send(readiness.clone())
                    .expect("readiness receiver is alive");
            },
            async move {
                let _ = stop_rx.await;
            },
        ));

        let readiness = tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .expect("ready timeout")
            .expect("ready");
        assert_eq!(readiness.local_addr, addr);
        assert_eq!(readiness.route_count, 1);

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connects");
        drop(stream);
        stop_tx.send(()).expect("server still running");
        task.await.expect("join").expect("server result");
    }

    #[tokio::test]
    async fn an_occupied_port_fails_without_readiness_or_disturbing_its_owner() {
        let holder = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("hold port");
        let addr = holder.local_addr().expect("held address");
        holder.set_nonblocking(true).expect("nonblocking holder");
        let snapshot =
            RouteSnapshot::new(vec![RouteSpec::json("/ready", br#"{"ok":true}"#.to_vec())])
                .expect("snapshot");
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&ready);
        let error = serve_with_shutdown(
            snapshot,
            addr,
            move |_| observed.store(true, std::sync::atomic::Ordering::SeqCst),
            std::future::pending(),
        )
        .await
        .expect_err("occupied port");
        assert!(format!("{error:#}").contains("binding source mock listener"));
        assert!(!ready.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(holder.local_addr().unwrap(), addr);
    }
}
