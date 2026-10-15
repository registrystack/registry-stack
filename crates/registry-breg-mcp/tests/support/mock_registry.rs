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

use std::collections::{BTreeMap, BTreeSet};
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
    pub owner: String,
}

#[derive(Default)]
struct Registry {
    addresses: BTreeMap<String, Vec<(String, Value)>>,
    applications: BTreeMap<Uuid, Application>,
    /// Each idempotency key the stand-in has answered, with the package
    /// revision it was bound under, the application it created, and the
    /// creation record it replays.
    created: BTreeMap<String, (u64, Uuid, Value)>,
    /// The consumed keys whose held response has passed the receipt
    /// horizon. A real engine keeps such a key spent and refuses to replay
    /// it.
    expired: BTreeSet<String>,
    /// The active package revision. A real engine binds every idempotency
    /// key to it, so a key first answered under another revision conflicts.
    package_revision: u64,
    allowed_operations: Option<BTreeSet<String>>,
    seen: Vec<Seen>,
    next_problem: Option<(Method, String, BRegProblemCode)>,
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
                "/v1/actions/correct-address/proposals",
                axum::routing::post(create_application),
            )
            .route("/v1/proposals/{id}", get(get_application))
            .route(
                "/v1/proposals/{id}/edit",
                axum::routing::post(patch_application),
            )
            .route("/v1/proposals", get(list_applications))
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
        let mut input = data.as_object().expect("application input").clone();
        let owner = input
            .remove("owner")
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "synthetic-citizen-a".to_owned());
        self.state.lock().applications.insert(
            identifier,
            Application {
                data: input,
                revision: 1,
                request,
                owner,
            },
        );
        identifier
    }

    /// Move an application to another request state, as a review page or
    /// a reviewer would.
    pub fn set_request(&self, identifier: Uuid, request: Value) {
        self.state
            .lock()
            .applications
            .get_mut(&identifier)
            .expect("application exists")
            .request = request;
    }

    /// Activate another package revision, as an operator upgrade would.
    pub fn activate_package(&self) {
        self.state.lock().package_revision += 1;
    }

    /// Pass the receipt horizon of every key answered so far, as time does.
    pub fn expire_receipts(&self) {
        let mut registry = self.state.lock();
        let consumed: Vec<String> = registry.created.keys().cloned().collect();
        registry.expired.extend(consumed);
    }

    pub fn grant_issuer(&self) -> GrantIssuer {
        GrantIssuer(self.state.clone())
    }
    pub fn restrict_operations(&self, operations: &[&str]) {
        self.state.lock().allowed_operations =
            Some(operations.iter().map(|value| (*value).to_owned()).collect());
    }
    pub fn applications(&self) -> BTreeMap<Uuid, Application> {
        self.state.lock().applications.clone()
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().seen.clone()
    }

    /// Answer the next request with this method with this problem.
    pub fn fail_next(&self, method: Method, code: BRegProblemCode) {
        self.fail_next_at(method, "/", code);
    }

    /// Answer the next request with this method whose path starts with
    /// `path_prefix` with this problem.
    pub fn fail_next_at(&self, method: Method, path_prefix: &str, code: BRegProblemCode) {
        self.state.lock().next_problem = Some((method, path_prefix.to_owned(), code));
    }

    pub fn stop(self) {
        self.task.abort();
    }
}

pub fn draft_request() -> Value {
    json!({"state": "draft"})
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
        .is_some_and(|(expected, prefix, _)| *expected == method && path.starts_with(prefix));
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
        registry.next_problem.take().map(|(_, _, code)| code)
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
    headers.insert("vary", HeaderValue::from_static("authorization, accept"));
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
    headers.insert("vary", HeaderValue::from_static("authorization, accept"));
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

fn application_record(identifier: Uuid, application: &Application, headers: &HeaderMap) -> Value {
    let state = application.request["state"].as_str().unwrap_or("draft");
    let revision: Value = serde_json::from_slice(METADATA).unwrap();
    let mut links = json!({"self":{"method":"GET","path":format!("/v1/proposals/{identifier}"),"operation":"get","accessProfile":PROFILE}});
    if !grant_allows(headers, "get", Some(identifier)) {
        links.as_object_mut().unwrap().remove("self");
    }
    if state == "draft" && grant_allows(headers, "edit", Some(identifier)) {
        links["edit"] = json!({"method":"POST","path":format!("/v1/proposals/{identifier}/edit"),"operation":"edit","accessProfile":PROFILE,
            "ifMatch":etag(application.revision),"availability":{"available":true,"observedRevision":application.revision}});
    }
    let mut value = json!({"id":identifier,"actionId":"correct-address","actionRevision":revision["revision"],"revision":application.revision,
        "submissionVersion":1,"state":state,"input":application.data,"links":links});
    if state != "draft" {
        if let Some(digest) = application.request.get("effectDigest") {
            value["effectDigest"] = digest.clone();
        }
    }
    value
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
    let mut body: Value = serde_json::from_slice(METADATA).expect("fixture metadata is JSON");
    if !grant_allows(&headers, "start", None) {
        body["actions"][0].as_object_mut().unwrap().remove("route");
        body["actions"][0]["routes"] = json!({});
        body["actions"][0]["resultEffects"] = json!([]);
    }
    if !grant_has_operation(&headers, "get") {
        body["proposals"]["get"]["accessProfiles"] = json!([]);
    }
    if !grant_has_operation(&headers, "list") {
        body["proposals"]["accessProfiles"] = json!([]);
    }
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
        "/v1/actions/correct-address/proposals".to_owned(),
        query.clone(),
        &headers,
        Some(body.clone()),
    ) {
        return problem(code);
    }
    if !profile_selected(query.as_deref())
        || headers.get("idempotency-key").is_none()
        || !grant_allows(&headers, "start", None)
    {
        return problem(BRegProblemCode::RequestInvalid);
    }
    let Some(data) = body["input"].as_object().cloned() else {
        return problem(BRegProblemCode::RequestInvalid);
    };
    let key = header_text(&headers, "idempotency-key");
    // A consumed key replays the response recorded when it was first
    // answered, whatever state the application has reached since, but only
    // under the package revision it was bound to and within its receipt
    // horizon.
    let (package_revision, consumed, expired) = {
        let registry = state.lock();
        (
            registry.package_revision,
            registry.created.get(&key).cloned(),
            registry.expired.contains(&key),
        )
    };
    if let Some((bound_revision, identifier, created)) = consumed {
        if bound_revision != package_revision {
            return problem(BRegProblemCode::IdempotencyConflict);
        }
        if expired {
            return problem(BRegProblemCode::IdempotencyExpired);
        }
        return created_response(identifier, &created);
    }
    let identifier = Uuid::new_v4();
    let application = Application {
        owner: principal(&headers).unwrap_or_default(),
        data,
        revision: 1,
        request: draft_request(),
    };
    let created = application_record(identifier, &application, &headers);
    let mut registry = state.lock();
    registry.applications.insert(identifier, application);
    registry
        .created
        .insert(key, (package_revision, identifier, created.clone()));
    drop(registry);
    created_response(identifier, &created)
}

fn created_response(identifier: Uuid, created: &Value) -> Response {
    let response = json_response(StatusCode::CREATED, created, None);
    let mut response = mutation(with_etag(response, 1));
    response.headers_mut().insert(
        "location",
        format!("/v1/proposals/{identifier}")
            .parse()
            .expect("location"),
    );
    response
}

fn header_text(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

async fn get_application(
    State(state): State<Shared>,
    Path(identifier): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let path = format!("/v1/proposals/{identifier}");
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
    if principal(&headers).as_deref() != Some(&application.owner)
        || !grant_allows(&headers, "get", Some(identifier))
    {
        return problem(BRegProblemCode::ResourceNotFound);
    }
    with_etag(
        json_response(
            StatusCode::OK,
            &application_record(identifier, &application, &headers),
            None,
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
    let path = format!("/v1/proposals/{identifier}/edit");
    let identifier = Uuid::parse_str(&identifier).unwrap_or_default();
    if let Some(code) = record(
        &state,
        Method::POST,
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
    if principal(&headers).as_deref() != Some(&application.owner)
        || !grant_allows(&headers, "edit", Some(identifier))
    {
        return problem(BRegProblemCode::ResourceNotFound);
    }
    let Some(input) = body["input"].as_object() else {
        return problem(BRegProblemCode::RequestInvalid);
    };
    if input.get("address") != application.data.get("address") {
        return problem(BRegProblemCode::MutationConflict);
    }
    application.data = input.clone();
    application.revision += 1;
    let revision = application.revision;
    let body = application_record(identifier, application, &headers);
    drop(registry);
    mutation(with_etag(
        json_response(StatusCode::OK, &body, None),
        revision,
    ))
}

async fn list_applications(
    State(state): State<Shared>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Some(code) = record(
        &state,
        Method::GET,
        "/v1/proposals".into(),
        query.clone(),
        &headers,
        None,
    ) {
        return problem(code);
    }
    if !profile_selected(query.as_deref()) || !grant_has_operation(&headers, "list") {
        return problem(BRegProblemCode::ResourceNotFound);
    }
    let pairs = url::form_urlencoded::parse(query.as_deref().unwrap_or("").as_bytes())
        .collect::<BTreeMap<_, _>>();
    let owner = principal(&headers).unwrap_or_default();
    let registry = state.lock();
    let items: Vec<_> = registry
        .applications
        .iter()
        .filter(|(id, app)| app.owner == owner && grant_allows(&headers, "list", Some(**id)))
        .filter(|(_, app)| {
            pairs
                .get("target")
                .is_none_or(|target| app.data["address"].as_str() == Some(target.as_ref()))
        })
        .map(|(id, app)| application_record(*id, app, &headers))
        .collect();
    json_response(StatusCode::OK, &json!({"items":items}), None)
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

/// A source-owned grant issuer for protocol tests. It augments only an already
/// exchanged token, using the platform server's public synthetic signing key.
/// Instance bounds come from current source ownership, never tool arguments.
#[derive(Clone)]
pub struct GrantIssuer(Shared);
impl GrantIssuer {
    pub fn token(&self, token: &str) -> String {
        let mut claims = token_claims(token).expect("issued token claims");
        if claims.get("act").is_none() {
            return token.to_owned();
        }
        let principal = claims["sub"].as_str().unwrap().to_owned();
        let registry = self.0.lock();
        let allows = |operation: &str| {
            registry
                .allowed_operations
                .as_ref()
                .is_none_or(|operations| operations.contains(operation))
        };
        let mut permissions = vec![json!({"collection":"person-addresses","operations":["list"]})];
        if allows("start") {
            permissions.push(json!({"collection":"action:correct-address","operations":["start"]}));
        }
        let operations: Vec<_> = ["get", "edit", "list"]
            .into_iter()
            .filter(|operation| allows(operation))
            .collect();
        for (id, application) in &registry.applications {
            if application.owner == principal && !operations.is_empty() {
                permissions
                    .push(json!({"collection":format!("proposal:{id}"),"operations":operations}));
            }
        }
        let target = registry
            .addresses
            .get(&principal)
            .and_then(|addresses| addresses.first())
            .map(|(id, _)| id.clone());
        claims["registry_grant_id"] = json!(if principal.ends_with('b') {
            "00000000-0000-4000-8000-000000000002"
        } else {
            "00000000-0000-4000-8000-000000000001"
        });
        claims["registry_grant_source_issuer"] = json!("https://tasks.example.test");
        claims["registry_grant_client"] = claims["azp"].clone();
        claims["registry_grant_resource"] = claims["aud"].clone();
        claims["registry_grant_exp"] = claims["exp"].clone();
        claims["registry_purpose"] = json!("address-correction");
        claims["registry_actor_kind"] = json!("agent");
        claims["registry_approver"] = json!("h:synthetic-task-owner");
        claims["registry_grant_bounds"] = json!({"type":"breg","permissions":permissions});
        claims["identity"] = json!({"address":target});
        let (private, _) = registry_platform_testing::fixtures::ed25519_pair();
        let kid = private.kid.as_deref().expect("fixture key identifier");
        registry_platform_testing::sign_ed25519_compact_jwt_with_key(
            &private, "at+jwt", kid, claims,
        )
    }
}
fn token_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?,
    )
    .ok()
}
fn grant_permissions(headers: &HeaderMap) -> Vec<Value> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(token_claims)
        .and_then(|claims| {
            claims
                .pointer("/registry_grant_bounds/permissions")
                .and_then(Value::as_array)
                .cloned()
        })
        .unwrap_or_default()
}
fn grant_has_operation(headers: &HeaderMap, operation: &str) -> bool {
    grant_permissions(headers).iter().any(|permission| {
        permission["collection"]
            .as_str()
            .is_some_and(|collection| collection.starts_with("proposal:"))
            && permission["operations"]
                .as_array()
                .is_some_and(|operations| operations.iter().any(|candidate| candidate == operation))
    })
}
fn grant_allows(headers: &HeaderMap, operation: &str, id: Option<Uuid>) -> bool {
    let collection = id.map_or_else(
        || "action:correct-address".to_owned(),
        |id| format!("proposal:{id}"),
    );
    grant_permissions(headers).iter().any(|permission| {
        permission["collection"] == collection
            && permission["operations"]
                .as_array()
                .is_some_and(|operations| operations.iter().any(|candidate| candidate == operation))
    })
}
#[derive(Clone)]
struct GrantExchange {
    upstream: String,
    issuer: GrantIssuer,
}
pub async fn grant_exchange(upstream: String, issuer: GrantIssuer) -> String {
    let app = Router::new()
        .route("/token", axum::routing::post(exchange_grant))
        .with_state(GrantExchange { upstream, issuer });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    endpoint
}
async fn exchange_grant(
    State(exchange): State<GrantExchange>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut request = reqwest::Client::new().post(exchange.upstream).body(body);
    if let Some(content_type) = headers.get("content-type") {
        request = request.header("content-type", content_type);
    }
    let Ok(response) = request.send().await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let status = response.status();
    let Ok(mut value): Result<Value, _> = response.json().await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    if status.is_success() {
        if let Some(token) = value["access_token"].as_str() {
            value["access_token"] = json!(exchange.issuer.token(token));
        }
    }
    let mut response = (
        StatusCode::from_u16(status.as_u16()).unwrap(),
        axum::Json(value),
    )
        .into_response();
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("pragma", HeaderValue::from_static("no-cache"));
    response
}
