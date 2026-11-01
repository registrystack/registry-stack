// SPDX-License-Identifier: Apache-2.0
//! The in-process scripted BReg the connector mock tests run against, in
//! the fixture style of `registry-breg-client`'s own HTTP boundary tests.
//! Every answer is scripted; requests are captured for assertion. The
//! fixture serves one deployment prefix and never inspects credentials.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use registry_adapter_connectors::breg::{BregConnector, BregConnectorConfig};
use registry_breg_client::{
    ingestion_chunk_digest, ingestion_prefix_digest, BaseRegistryClient, BaseRegistryClientConfig,
    StaticToken,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use url::Url;

pub const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
pub const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
pub const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
pub const OTHER_RECORD_ID: &str = "00000000-0000-4000-8000-000000000002";
pub const PROPOSAL_ID: &str = "10000000-0000-4000-8000-00000000000a";
pub const RUN_ID: &str = "20000000-0000-4000-8000-00000000000b";
pub const APPLICATION_ID: &str = "30000000-0000-4000-8000-00000000000c";
pub const SERVER_ETAG: &str = "\"breg-record-000000000001\"";
pub const REVISION: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const ACTION_REVISION: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const PROFILE: &str = "writer";
pub const IMMEDIATE_ACTION: &str = "register-company";
pub const PROPOSAL_ACTION: &str = "correct-company";
pub const TOKEN: &str = "mock-connector-token";
pub const INPUT_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
pub const PACKAGE_REVISION: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
pub const SCHEMA_FINGERPRINT: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

/// One JSON mutation/Proposal/ingestion answer: the exact cache policy
/// the client enforces on these exchanges, with no entity tag and no
/// profile link.
pub fn mutation_json(status: StatusCode, body: Value) -> MockResponse {
    MockResponse::json(status, body)
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept")
}

/// One scripted answer.
#[derive(Clone)]
pub struct MockResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Never answer; hold the exchange until the client's attempt timeout.
    pub hang: bool,
}

impl MockResponse {
    pub fn json(status: StatusCode, body: Value) -> Self {
        Self {
            status,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("traceparent".into(), TRACEPARENT.into()),
            ],
            body: serde_json::to_vec(&body).expect("fixture serializes"),
            hang: false,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Hold this answer past the client's attempt timeout.
    pub fn hanging(mut self) -> Self {
        self.hang = true;
        self
    }
}

/// One registered problem answer in the exact envelope the client maps:
/// the problem media type, the registry's own title for the status, the
/// code's published sentence, and the resolving type URI.
pub fn problem(code: registry_breg_client::BRegProblemCode) -> MockResponse {
    let title = match code.status() {
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
        _ => "Request failed",
    };
    let body = json!({
        "type": format!(
            "https://id.registrystack.org/problems/registry-breg/{}",
            code.code().replace('.', "/")
        ),
        "title": title,
        "status": code.status(),
        "detail": code.detail(),
        "code": code.code(),
        "traceId": TRACE_ID,
    });
    let mut answer = MockResponse::json(
        StatusCode::from_u16(code.status()).expect("problem status"),
        body,
    );
    answer.headers.retain(|(name, _)| name != "content-type");
    answer
        .with_header("content-type", "application/problem+json")
        .with_header("cache-control", "no-store")
}

#[derive(Clone, Debug)]
pub struct Captured {
    pub method: String,
    pub uri: String,
    pub authorization: Option<String>,
    pub idempotency_key: Option<String>,
    pub if_match: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Clone)]
struct MockState {
    requests: Arc<Mutex<Vec<Captured>>>,
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
}

async fn handler(State(state): State<MockState>, request: Request<Body>) -> Response<Body> {
    let captured = Captured {
        method: request.method().to_string(),
        uri: request.uri().to_string(),
        authorization: header(&request, "authorization"),
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
    if spec.hang {
        // Hold until the client's attempt timeout ends the exchange.
        std::future::pending::<()>().await;
    }
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

/// The scripted deployment: one server, its captured requests, and the
/// connector resolved against it.
pub struct Mock {
    pub requests: Arc<Mutex<Vec<Captured>>>,
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
    pub connector: Arc<BregConnector>,
    server: tokio::task::JoinHandle<()>,
}

impl Mock {
    /// Start a scripted deployment whose first answer is the metadata the
    /// connector resolves. `action_mode` is `"immediate"` or `"proposal"`;
    /// `tombstone` adds the tombstone operation to the served metadata.
    pub async fn start(action_mode: &str, tombstone: bool) -> Self {
        Self::start_with(action_mode, tombstone, Vec::new()).await
    }

    /// Start a deployment whose connector runs with the import authority
    /// closed: the ingestion family stays unadvertised.
    pub async fn start_closed_import() -> Self {
        let requests = Arc::new(Mutex::new(VecDeque::from(vec![MockResponse::json(
            StatusCode::OK,
            metadata("immediate", false),
        )])));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            requests: Arc::clone(&captured),
            responses: requests,
        };
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Base Registry Engine");
        let address = listener.local_addr().expect("mock address");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(any(handler)).with_state(state),
            )
            .await
            .expect("serve mock Base Registry Engine");
        });
        let token = Arc::new(StaticToken::new(TOKEN).expect("static token"));
        let connector = BregConnector::connect(
            BregConnectorConfig::new(
                format!("http://{address}/tenant/prefix"),
                token,
                PROFILE,
                IMMEDIATE_ACTION,
                "company",
                "companies",
            )
            .with_attempt_timeout(std::time::Duration::from_millis(150)),
        )
        .await
        .expect("connector resolves against the scripted metadata");
        Self {
            requests: captured,
            responses: Arc::new(Mutex::new(VecDeque::new())),
            connector: Arc::new(connector),
            server,
        }
    }

    /// Start with extra scripted answers queued after the metadata.
    pub async fn start_with(
        action_mode: &str,
        tombstone: bool,
        responses: Vec<MockResponse>,
    ) -> Self {
        Self::start_serving(
            metadata(action_mode, tombstone),
            action_mode,
            tombstone,
            responses,
        )
        .await
    }

    /// Start an immediate-mode deployment whose metadata names another
    /// registry revision, so every binding it resolves differs in identity.
    pub async fn start_at_revision(revision: &str) -> Self {
        let mut served = metadata("immediate", false);
        served["revision"] = json!(revision);
        Self::start_serving(served, "immediate", false, Vec::new()).await
    }

    async fn start_serving(
        served: Value,
        action_mode: &str,
        tombstone: bool,
        responses: Vec<MockResponse>,
    ) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut queue = VecDeque::from(responses);
        queue.push_front(MockResponse::json(StatusCode::OK, served));
        let responses = Arc::new(Mutex::new(queue));
        let state = MockState {
            requests: requests.clone(),
            responses: Arc::clone(&responses),
        };
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Base Registry Engine");
        let address = listener.local_addr().expect("mock address");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(any(handler)).with_state(state),
            )
            .await
            .expect("serve mock Base Registry Engine");
        });
        let token = Arc::new(StaticToken::new(TOKEN).expect("static token"));
        let connector = BregConnector::connect(
            BregConnectorConfig::new(
                format!("http://{address}/tenant/prefix"),
                token,
                PROFILE,
                if action_mode == "proposal" {
                    PROPOSAL_ACTION
                } else {
                    IMMEDIATE_ACTION
                },
                "company",
                "companies",
            )
            .with_tombstone(tombstone)
            .with_import_profile(true)
            // A short attempt timeout keeps the unknown-outcome tests fast.
            .with_attempt_timeout(std::time::Duration::from_millis(150)),
        )
        .await
        .expect("connector resolves against the scripted metadata");
        Self {
            requests,
            responses,
            connector: Arc::new(connector),
            server,
        }
    }

    /// The exchanges after the connect-time metadata fetch.
    pub fn exchanges(&self) -> Vec<Captured> {
        self.requests.lock().unwrap()[1..].to_vec()
    }

    /// Queue one more scripted answer.
    pub fn push(&self, response: MockResponse) {
        self.responses
            .lock()
            .expect("response queue lock")
            .push_back(response);
    }

    /// Run one blocking connector call off the async test workers.
    pub fn call<T>(&self, f: impl FnOnce() -> T + Send + 'static) -> T
    where
        T: Send + 'static,
    {
        std::thread::spawn(f).join().expect("blocking call joins")
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.server.abort();
    }
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
        "accessProfile": PROFILE,
        "requiredCapabilities": [],
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

fn create_request() -> Value {
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
    })
}

fn patch_request() -> Value {
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
    })
}

fn tombstone_request() -> Value {
    json!({
        "fieldNames": "api",
        "queryParameters": [],
        "body": "none",
        "idempotencyKeyRequired": true,
        "ifMatchRequired": true,
        "mutationSemantics": "direct"
    })
}

fn batch_request() -> Value {
    json!({
        "fieldNames": "api",
        "queryParameters": [],
        "body": "batch",
        "contentType": "application/json",
        "idempotencyKeyRequired": true,
        "mutationSemantics": "direct",
        "maximumItems": 2,
        "maximumBodyBytes": 4096,
        "allowCreate": true,
        "allowPatch": true,
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["items"],
            "properties": {
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 2,
                    "items": {
                        "oneOf": [
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["operation", "data"],
                                "properties": {
                                    "operation": {"const": "create"},
                                    "data": {"type": "object"}
                                }
                            },
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["operation", "recordId", "ifMatch", "patch"],
                                "properties": {
                                    "operation": {"const": "patch"},
                                    "recordId": {"type": "string"},
                                    "ifMatch": {"type": "string"},
                                    "patch": {"type": "array"}
                                }
                            }
                        ]
                    }
                }
            }
        }
    })
}

fn action(action_mode: &str) -> Value {
    let proposal = action_mode == "proposal";
    let action_id = if proposal {
        PROPOSAL_ACTION
    } else {
        IMMEDIATE_ACTION
    };
    json!({
        "id": action_id,
        "apiName": "registerCompany",
        "revision": ACTION_REVISION,
        "display": {},
        "execution": {"mode": action_mode},
        "route": format!("/v1/actions/{action_id}"),
        "conditionRoute": null,
        "inputMode": "fixed",
        "maximumInputStringBytes": null,
        "inputs": [{"id": "label", "apiName": "legalName", "required": true,
            "nullable": false, "classification": "internal",
            "schema": {"type": "string", "minLength": 1, "maxLength": 40},
            "fieldType": {"type": "string", "minimumLength": 1, "maximumLength": 40}}],
        "referenceInputs": [],
        "requiredConditionKeys": [],
        "resultEffects": [
            {"effect": "record-created", "recordType": "company", "operation": "create"}],
        "access": {"selectedProfile": PROFILE},
        "routes": {
            (if proposal { "start" } else { "invoke" }): {
                "method": "POST",
                "path": format!("/v1/actions/{action_id}"),
                "operationId": format!("actions.{action_id}.{}",
                    if proposal { "start" } else { "invoke" }),
                "requiresIdempotencyKey": true,
                "inputSchema": format!("action-{action_id}-invoke-input"),
                "responseSchema": format!("action-{action_id}-invoke-response")
            },
            "targetConditions": null},
        "bounds": {"maximumTargets": 4, "maximumFieldMutations": 8, "maximumSnapshotBytes": 1024}
    })
}

/// The caller-filtered Registry Metadata v2 document the connector
/// resolves: record operations, the batch, an optional tombstone, one
/// action in the requested mode, and the Proposal grants.
pub fn metadata(action_mode: &str, tombstone: bool) -> Value {
    let mut operations = vec![
        operation(
            "records.company.create",
            "POST",
            "/v1/records/companies",
            "create",
            create_request(),
            json!(["legal-name"]),
            json!([]),
        ),
        operation(
            "records.company.patch",
            "PATCH",
            "/v1/records/companies/{record_id}",
            "patch",
            patch_request(),
            json!([]),
            json!(["legal-name"]),
        ),
        operation(
            "records.company.batch",
            "POST",
            "/v1/records/companies:batch",
            "batch",
            batch_request(),
            json!(["legal-name"]),
            json!(["legal-name"]),
        ),
    ];
    let mut entity_operations = vec![
        json!({"operation": "create", "accessProfile": PROFILE}),
        json!({"operation": "patch", "accessProfile": PROFILE}),
        json!({"operation": "batch", "accessProfile": PROFILE}),
    ];
    if tombstone {
        operations.push(operation(
            "records.company.tombstone",
            "DELETE",
            "/v1/records/companies/{record_id}",
            "tombstone",
            tombstone_request(),
            json!([]),
            json!([]),
        ));
        entity_operations.push(json!({"operation": "tombstone", "accessProfile": PROFILE}));
    }
    json!({
        "id": "business-registry",
        "version": "1.2.3",
        "revision": REVISION,
        "metadataVersion": "2",
        "recordTypes": [{
            "id": "company",
            "datasetIdentifier": "legal-entities",
            "route": "companies",
            "operations": entity_operations,
            "readableFields": ["legal-name"],
            "schema": "/v1/schemas/company"
        }],
        "operations": operations,
        "actions": [action(action_mode)],
        "proposals": {
            "method": "GET",
            "path": "/v1/proposals",
            "accessProfiles": [PROFILE],
            "get": {"method": "GET", "path": "/v1/proposals/{proposal_id}",
                "accessProfiles": [PROFILE]},
            "actions": [{"actionId": if action_mode == "proposal" { PROPOSAL_ACTION } else { IMMEDIATE_ACTION },
                "accessProfile": PROFILE, "readableInputs": [],
                "operations": ["get"]}]
        }
    })
}

/// The Registry Record single envelope the reads answer.
pub fn record_body() -> Value {
    json!({
        "data": {
            "recordIdentifier": RECORD_ID,
            "revisionIdentifier": "3",
            "domainData": {"legalName": "Example Ltd"}
        },
        "meta": {
            "registryIdentifier": "business-registry",
            "datasetIdentifier": "legal-entities",
            "recordTypeIdentifier": "company"
        }
    })
}

/// One created-record answer with the location header the client checks.
pub fn created_record(record_identifier: &str) -> MockResponse {
    let mut body = record_body();
    body["data"]["recordIdentifier"] = json!(record_identifier);
    body["data"]["revisionIdentifier"] = json!("1");
    MockResponse::json(StatusCode::CREATED, body)
        .with_header("etag", SERVER_ETAG)
        .with_header(
            "link",
            "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </tenant/prefix/v1/schemas/company>; rel=\"describedby\"",
        )
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept")
        .with_header(
            "location",
            &format!("/tenant/prefix/v1/records/companies/{record_identifier}"),
        )
}

/// One patched or tombstoned-record answer.
pub fn mutated_record() -> MockResponse {
    MockResponse::json(StatusCode::OK, record_body())
        .with_header("etag", SERVER_ETAG)
        .with_header(
            "link",
            "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </tenant/prefix/v1/schemas/company>; rel=\"describedby\"",
        )
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept")
}

/// One Proposal document in the state the fixture names; `revision` 2 is
/// the fresh draft the submit attempts transition from.
pub fn proposal(state: &str, revision: u64) -> Value {
    let mut value = json!({
        "id": PROPOSAL_ID,
        "actionId": PROPOSAL_ACTION,
        "actionRevision": ACTION_REVISION,
        "submissionVersion": 1,
        "revision": revision,
        "state": state,
        "links": {
            "self": {"method": "GET", "path": format!("/v1/proposals/{PROPOSAL_ID}"),
                "accessProfile": PROFILE, "operation": "get"},
            "submit": {"method": "POST", "path": format!("/v1/proposals/{PROPOSAL_ID}/submit"),
                "accessProfile": PROFILE, "operation": "submit", "ifMatch": "\"condition\""}
        }
    });
    if state != "draft" {
        value["effectDigest"] = json!(REVISION);
    }
    value
}

/// The immediate Action receipt for the fixture's one result effect.
pub fn action_receipt() -> Value {
    json!({
        "action": IMMEDIATE_ACTION,
        "applicationId": APPLICATION_ID,
        "results": {
            "record-created": {"recordType": "company", "recordId": RECORD_ID, "revision": 7}
        }
    })
}

/// The durable run document the fixture announces, in the state the
/// committed chunk leaves behind.
pub fn ingestion_run(status: &str, next_chunk: u64, committed: u64, prefix: &str) -> Value {
    let complete = status == "complete";
    json!({
        "runId": RUN_ID,
        "status": status,
        "blockedReason": null,
        "recordType": "company",
        "operation": "create",
        "profileId": PROFILE,
        "packageRevision": PACKAGE_REVISION,
        "schemaFingerprint": SCHEMA_FINGERPRINT,
        "inputDigest": INPUT_DIGEST,
        "inputLength": 64,
        "itemCount": 2,
        "chunkCount": 1,
        "chunkAlgorithmVersion": "greedy-canonical-http-batch-v1",
        "maximumItems": 100,
        "maximumBytes": 1000,
        "nextChunkIndex": next_chunk,
        "committedItems": committed,
        "committedPrefixDigest": prefix,
        "lastAttempt": null,
        "createdAt": "2026-10-31T00:00:00.000000Z",
        "updatedAt": "2026-10-31T00:01:00.000000Z",
        "complete": complete
    })
}

/// The committed chunk receipt beside the run state. The fixture run
/// announces two items, so a two-item chunk completes it.
pub fn chunk_submission(items: &[Value], replayed: bool) -> Value {
    let complete = items.len() == 2;
    let empty_prefix = ingestion_prefix_digest(&[]);
    let run = ingestion_run(
        if complete { "complete" } else { "open" },
        if complete { 1 } else { items.len() as u64 },
        items.len() as u64,
        if complete {
            INPUT_DIGEST
        } else {
            &empty_prefix
        },
    );
    json!({
        "run": run,
        "receipt": {
            "chunkIndex": 0,
            "digest": ingestion_chunk_digest(items).expect("fixture chunk digest"),
            "replayed": replayed,
            "erased": false,
            "batch": {"snapshot": format!("breg1_{RUN_ID}"), "results": []}
        }
    })
}

/// The empty-prefix digest a fresh run publishes.
pub fn empty_prefix_digest() -> String {
    ingestion_prefix_digest(&[])
}

/// The client the reads use directly in assertions.
pub fn direct_client(base_url: &str) -> BaseRegistryClient {
    let token = Arc::new(StaticToken::new(TOKEN).expect("static token"));
    BaseRegistryClient::new(
        BaseRegistryClientConfig::new(Url::parse(base_url).expect("base url"))
            .with_token_provider(token)
            .with_maximum_mutation_retries(0),
    )
    .expect("direct client")
}
