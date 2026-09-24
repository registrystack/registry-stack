// SPDX-License-Identifier: Apache-2.0

//! A stateful stand-in for the Base Registry Engine the gateway calls.
//!
//! It serves the captured agent-profile metadata and answers the record
//! routes with the exact envelopes, headers, and problem documents a real
//! engine returns for the citizen agent profile. It reads the caller's
//! principal from the bearer token's `sub` claim without verifying it: the
//! gateway's delegation is proven against the real engine elsewhere. Every
//! request is recorded so a test can prove what the gateway did and did not
//! send.

// The unit tests and each integration target use different parts of it.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine as _;
use registry_breg_client::BRegProblemCode;
use serde_json::{json, Map, Value};
use tokio::task::JoinHandle;
use uuid::Uuid;

pub const METADATA: &[u8] = include_bytes!("../fixtures/citizen-agent-metadata.json");
pub const PROFILE: &str = "citizen-agent";
const REGISTRY: &str = "citizen-address-correction";
const DETAILS_ENTITY: &str = "person-address";
const APPLICATION_ENTITY: &str = "address-correction-request";
const APPLICATIONS: &str = "address-correction-requests";

/// One request the gateway sent.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: Method,
    pub path: String,
    pub query: Option<String>,
    pub body: Option<Value>,
    pub authorization: Option<String>,
    pub idempotency_key: Option<String>,
    pub if_match: Option<String>,
}

/// One application record the stand-in holds.
#[derive(Clone, Debug)]
pub struct Application {
    pub data: Map<String, Value>,
    pub revision: u64,
    pub request: Value,
}

#[derive(Default)]
struct Registry {
    addresses: BTreeMap<String, Vec<(String, Value)>>,
    applications: BTreeMap<Uuid, Application>,
    seen: Vec<Seen>,
    next_problem: Option<(Method, BRegProblemCode)>,
}

#[derive(Clone)]
struct Shared(Arc<Mutex<Registry>>);

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.0.lock().expect("mock registry state is not poisoned")
    }
}

pub struct MockRegistry {
    pub base_url: String,
    state: Shared,
    task: JoinHandle<()>,
}

impl MockRegistry {
    pub async fn start() -> Self {
        let state = Shared(Arc::new(Mutex::new(Registry::default())));
        let app = Router::new()
            .route("/v1/registry", get(metadata))
            .route("/v1/records/person-addresses", get(list_addresses))
            .route(
                "/v1/records/address-correction-requests",
                axum::routing::post(create_application),
            )
            .route(
                "/v1/records/address-correction-requests/{id}",
                get(get_application).patch(patch_application),
            )
            .fallback(unexpected)
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock registry listens");
        let base_url = format!(
            "http://{}/",
            listener.local_addr().expect("mock registry address")
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock registry serves");
        });
        Self {
            base_url,
            state,
            task,
        }
    }

    /// Link one address record to `principal`.
    pub fn add_address(&self, principal: &str, identifier: &str, line: &str) {
        self.state
            .lock()
            .addresses
            .entry(principal.to_owned())
            .or_default()
            .push((
                identifier.to_owned(),
                json!({"addressLine": line, "locality": "Port Selene", "postalCode": "PS-100"}),
            ));
    }

    /// Hold an application with the given domain data and request extension.
    pub fn add_application(&self, data: Value, request: Value) -> Uuid {
        let identifier = Uuid::new_v4();
        self.state.lock().applications.insert(
            identifier,
            Application {
                data: data.as_object().expect("application data").clone(),
                revision: 1,
                request,
            },
        );
        identifier
    }

    pub fn applications(&self) -> BTreeMap<Uuid, Application> {
        self.state.lock().applications.clone()
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().seen.clone()
    }

    /// Answer the next request with this method with this problem.
    pub fn fail_next(&self, method: Method, code: BRegProblemCode) {
        self.state.lock().next_problem = Some((method, code));
    }

    pub fn stop(self) {
        self.task.abort();
    }
}

pub fn draft_request() -> Value {
    json!({"bregState": "draft", "editable": true, "effectDigest": null, "proposalVersion": 1})
}

pub fn etag(revision: u64) -> String {
    format!("\"breg-hmac-sha256:{revision:064x}\"")
}

fn record(
    state: &Shared,
    method: Method,
    path: String,
    query: Option<String>,
    headers: &HeaderMap,
    body: Option<Value>,
) -> Option<BRegProblemCode> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let mut registry = state.lock();
    let fails = registry
        .next_problem
        .as_ref()
        .is_some_and(|(expected, _)| *expected == method);
    registry.seen.push(Seen {
        method,
        path,
        query,
        body,
        authorization: header("authorization"),
        idempotency_key: header("idempotency-key"),
        if_match: header("if-match"),
    });
    if fails {
        registry.next_problem.take().map(|(_, code)| code)
    } else {
        None
    }
}

fn principal(headers: &HeaderMap) -> Option<String> {
    let token = headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    let payload = token.split('.').nth(1)?;
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?,
    )
    .ok()?;
    claims["sub"].as_str().map(str::to_owned)
}

fn profile_selected(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        query
            .split('&')
            .any(|pair| pair == format!("accessProfile={PROFILE}"))
    })
}

fn trace() -> (String, String) {
    let trace_id = Uuid::new_v4().simple().to_string();
    let parent = format!(
        "00-{trace_id}-{}-01",
        &Uuid::new_v4().simple().to_string()[..16]
    );
    (trace_id, parent)
}

fn meta(entity: &str) -> Value {
    json!({
        "datasetIdentifier": REGISTRY,
        "entityTypeIdentifier": entity,
        "registryIdentifier": REGISTRY,
    })
}

fn json_response(status: StatusCode, body: &Value, entity: Option<&str>) -> Response {
    let (_, parent) = trace();
    let mut response = (status, serde_json::to_vec(body).expect("body serializes")).into_response();
    let headers = response.headers_mut();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("traceparent", parent.parse().expect("traceparent"));
    if let Some(entity) = entity {
        headers.insert(
            "link",
            format!(
                "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/{entity}>; rel=\"describedby\""
            )
            .parse()
            .expect("link"),
        );
    }
    response
}

pub fn problem(code: BRegProblemCode) -> Response {
    let (trace_id, parent) = trace();
    let status = StatusCode::from_u16(code.status()).expect("problem status");
    let body = json!({
        "code": code.code(),
        "detail": code.detail(),
        "status": status.as_u16(),
        "title": status.canonical_reason().unwrap_or("Error"),
        "traceId": trace_id,
        "type": format!(
            "https://id.registrystack.org/problems/registry-breg/{}",
            code.code().replace('.', "/")
        ),
    });
    let mut response = (
        status,
        serde_json::to_vec(&body).expect("problem serializes"),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/problem+json"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("traceparent", parent.parse().expect("traceparent"));
    response
}

fn with_etag(mut response: Response, revision: u64) -> Response {
    response
        .headers_mut()
        .insert("etag", etag(revision).parse().expect("etag"));
    response
}

/// A mutation answer varies by credential and representation.
fn mutation(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert("vary", HeaderValue::from_static("authorization, accept"));
    response
}

fn application_record(identifier: Uuid, application: &Application, with_request: bool) -> Value {
    let mut data = json!({
        "domainData": application.data,
        "recordIdentifier": identifier.to_string(),
        "revisionIdentifier": application.revision.to_string(),
    });
    if with_request {
        data["request"] = application.request.clone();
    } else {
        data["snapshot"] = json!(format!("breg1_{}", Uuid::new_v4()));
    }
    json!({"data": data, "meta": meta(APPLICATION_ENTITY)})
}

async fn metadata(
    State(state): State<Shared>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    record(
        &state,
        Method::GET,
        "/v1/registry".to_owned(),
        query.clone(),
        &headers,
        None,
    );
    if !profile_selected(query.as_deref()) {
        return problem(BRegProblemCode::ResourceNotFound);
    }
    let body: Value = serde_json::from_slice(METADATA).expect("fixture metadata is JSON");
    json_response(StatusCode::OK, &body, None)
}

async fn list_addresses(
    State(state): State<Shared>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Some(code) = record(
        &state,
        Method::GET,
        "/v1/records/person-addresses".to_owned(),
        query.clone(),
        &headers,
        None,
    ) {
        return problem(code);
    }
    if !profile_selected(query.as_deref()) {
        return problem(BRegProblemCode::ResourceNotFound);
    }
    let items: Vec<Value> = principal(&headers)
        .and_then(|principal| state.lock().addresses.get(&principal).cloned())
        .unwrap_or_default()
        .into_iter()
        .map(|(identifier, data)| {
            json!({"domainData": data, "recordIdentifier": identifier, "revisionIdentifier": "1"})
        })
        .collect();
    json_response(
        StatusCode::OK,
        &json!({"items": items, "meta": meta(DETAILS_ENTITY), "pageInfo": {"nextCursor": null}}),
        Some(DETAILS_ENTITY),
    )
}

async fn create_application(
    State(state): State<Shared>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if let Some(code) = record(
        &state,
        Method::POST,
        format!("/v1/records/{APPLICATIONS}"),
        query.clone(),
        &headers,
        Some(body.clone()),
    ) {
        return problem(code);
    }
    if !profile_selected(query.as_deref()) || headers.get("idempotency-key").is_none() {
        return problem(BRegProblemCode::RequestInvalid);
    }
    let Some(data) = body["data"].as_object().cloned() else {
        return problem(BRegProblemCode::RequestInvalid);
    };
    let identifier = Uuid::new_v4();
    let application = Application {
        data: data.into_iter().filter(|(key, _)| key != "owner").collect(),
        revision: 1,
        request: draft_request(),
    };
    let response = json_response(
        StatusCode::CREATED,
        &application_record(identifier, &application, false),
        Some(APPLICATION_ENTITY),
    );
    state
        .lock()
        .applications
        .insert(identifier, application.clone());
    let mut response = mutation(with_etag(response, 1));
    response.headers_mut().insert(
        "location",
        format!("/v1/records/{APPLICATIONS}/{identifier}")
            .parse()
            .expect("location"),
    );
    response
}

async fn get_application(
    State(state): State<Shared>,
    Path(identifier): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let path = format!("/v1/records/{APPLICATIONS}/{identifier}");
    let identifier = Uuid::parse_str(&identifier).unwrap_or_default();
    if let Some(code) = record(&state, Method::GET, path, query.clone(), &headers, None) {
        return problem(code);
    }
    if !profile_selected(query.as_deref()) {
        return problem(BRegProblemCode::ResourceNotFound);
    }
    let Some(application) = state.lock().applications.get(&identifier).cloned() else {
        return problem(BRegProblemCode::ResourceNotFound);
    };
    with_etag(
        json_response(
            StatusCode::OK,
            &application_record(identifier, &application, true),
            Some(APPLICATION_ENTITY),
        ),
        application.revision,
    )
}

async fn patch_application(
    State(state): State<Shared>,
    Path(identifier): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let path = format!("/v1/records/{APPLICATIONS}/{identifier}");
    let identifier = Uuid::parse_str(&identifier).unwrap_or_default();
    if let Some(code) = record(
        &state,
        Method::PATCH,
        path,
        query.clone(),
        &headers,
        Some(body.clone()),
    ) {
        return problem(code);
    }
    if !profile_selected(query.as_deref()) {
        return problem(BRegProblemCode::ResourceNotFound);
    }
    let mut registry = state.lock();
    let Some(application) = registry.applications.get_mut(&identifier) else {
        return problem(BRegProblemCode::ResourceNotFound);
    };
    let if_match = headers
        .get("if-match")
        .and_then(|value| value.to_str().ok());
    if if_match != Some(etag(application.revision).as_str()) {
        return problem(BRegProblemCode::PreconditionFailed);
    }
    let Some(operations) = body.as_array() else {
        return problem(BRegProblemCode::RequestInvalid);
    };
    let mut data = application.data.clone();
    for operation in operations {
        let Some(field) = operation["path"]
            .as_str()
            .and_then(|path| path.strip_prefix("/data/"))
        else {
            return problem(BRegProblemCode::RequestInvalid);
        };
        match operation["op"].as_str() {
            Some("test") => {
                if data.get(field) != Some(&operation["value"]) {
                    return problem(BRegProblemCode::MutationConflict);
                }
            }
            Some("add" | "replace") => {
                data.insert(field.to_owned(), operation["value"].clone());
            }
            Some("remove") => {
                data.insert(field.to_owned(), Value::Null);
            }
            _ => return problem(BRegProblemCode::RequestInvalid),
        }
    }
    application.data = data;
    application.revision += 1;
    let revision = application.revision;
    let body = application_record(identifier, application, false);
    drop(registry);
    mutation(with_etag(
        json_response(StatusCode::OK, &body, Some(APPLICATION_ENTITY)),
        revision,
    ))
}

async fn unexpected(
    State(state): State<Shared>,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    record(
        &state,
        method,
        uri.path().to_owned(),
        uri.query().map(str::to_owned),
        &headers,
        None,
    );
    problem(BRegProblemCode::ResourceNotFound)
}
