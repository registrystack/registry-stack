// SPDX-License-Identifier: Apache-2.0
//! A review page wired to an in-process authorization server and a stateful
//! mock Base Registry Engine, driven over loopback HTTP like a browser would.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path as RoutePath, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_breg_client::BRegProblemCode;
use registry_platform_testing::fixtures;
use registry_platform_testing::{TestAuthorizationServer, TestClient};
use serde_json::{json, Value};
use tempfile::TempDir;

pub const CLIENT_ID: &str = "citizen-review-page";
pub const RESOURCE: &str = "https://registry.example/base";
pub const SCOPE: &str = "address-correction:self";
pub const ENTITY: &str = "address-correction-request";
pub const ROUTE: &str = "address-correction-requests";
pub const TARGET_ENTITY: &str = "person-address";
pub const TARGET_ROUTE: &str = "person-addresses";
pub const TARGET_FIELD: &str = "address";
pub const PROFILE: &str = "citizen-review";
pub const CITIZEN_A: &str = "citizen-a";
pub const CITIZEN_B: &str = "citizen-b";
/// Citizen A's draft, naming citizen A's own address.
pub const REQUEST_ID: &str = "3f6c8a3e-0b8e-4c52-9d0e-6a4f1c2b7d10";
/// Citizen B's draft, naming citizen B's own address.
pub const B_REQUEST_ID: &str = "5e2b9c41-7d3a-4f68-a1b0-c2d3e4f50617";
/// Citizen B's draft naming citizen A's address: the registry accepts it.
pub const FOREIGN_TARGET_REQUEST_ID: &str = "9b8a7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
/// A request identifier nobody holds.
pub const OTHER_REQUEST_ID: &str = "7a1d2e3f-4b5c-4d6e-8f70-8192a3b4c5d6";
pub const ADDRESS_A: &str = "0d1e2f30-4152-4637-8899-aabbccddeeff";
pub const ADDRESS_B: &str = "1a2b3c4d-5e6f-4a0b-9c1d-2e3f4a5b6c7d";
pub const CURRENT_LINE_A: &str = "1 Harbour Road";
pub const CURRENT_LINE_B: &str = "40 Mill Street";
pub const PROPOSED_LOCALITY: &str = "Selene Heights";
pub const AUDIT_KEY_VARIABLE: &str = "BREG_REVIEW_TEST_AUDIT_KEY";
pub const HOSTILE_STREET: &str = "<script>alert('x')</script> 2 Quarry Lane";
pub const EXPECTED_CSP: &str =
    "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'";

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const METADATA_REVISION: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EFFECT_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TARGET_GET: &str = "records.person-address.get";
const TARGET_LIST: &str = "records.person-address.list";

/// One draft the mock registry holds.
#[derive(Debug)]
pub struct Draft {
    pub owner: &'static str,
    pub target: &'static str,
    pub revision: u64,
    pub proposal_version: u64,
    pub action_generation: u64,
    pub submitted: bool,
}

/// One registered address the mock registry holds.
#[derive(Debug)]
pub struct Address {
    /// The only citizen who may read it; `None` once the link is withdrawn.
    pub reader: Option<&'static str>,
    pub line: &'static str,
    pub locality: &'static str,
    pub postal_code: &'static str,
    /// The record revision, advanced by every change to the record.
    pub revision: u64,
}

/// A stateful stand-in for the registry. Like the real one it conceals every
/// record from everyone but its reader, rotates the action ETag on each agent
/// edit, replays a submit that reuses an idempotency key, and does not tie a
/// request's target to the requester: citizen B may hold a draft naming
/// citizen A's address.
pub struct MockRegistry {
    pub drafts: Mutex<BTreeMap<&'static str, Draft>>,
    pub addresses: Mutex<BTreeMap<&'static str, Address>>,
    /// Every request the registry received, as `METHOD /path`.
    log: Mutex<Vec<String>>,
    submit_effects: Mutex<u64>,
    replays: Mutex<HashMap<String, (String, Value)>>,
    bearers: Mutex<Vec<String>>,
    /// Whether the registry refuses every bearer token, as it does once a
    /// person's access token is revoked.
    refusing_tokens: Mutex<bool>,
    /// An address whose reader the next submit conflict this registry
    /// answers also withdraws, taking effect strictly after that submit's
    /// own read of the draft.
    withdraw_reader_on_next_conflict: Mutex<Option<&'static str>>,
    /// Whether the next successful submit commits but loses its answer.
    lose_next_submit_response: AtomicBool,
    /// A deterministic pause after the next metadata call reaches the mock,
    /// before it releases the protected response.
    pause_next_metadata_response: AtomicBool,
    metadata_response_paused: tokio::sync::Semaphore,
    release_metadata_response: tokio::sync::Semaphore,
    /// Whether the metadata also publishes a list of the target entity,
    /// named first among the target field's reference operations.
    target_list_first: AtomicBool,
    /// How the registry answers the next draft read instead of the draft.
    next_draft_read: Mutex<Option<Injected>>,
    /// A problem the registry answers the next submit with, before any effect.
    next_submit_problem: Mutex<Option<BRegProblemCode>>,
    /// Whether every held submit response has passed the receipt horizon, so
    /// a replay of its key is refused as expired while the key stays spent.
    receipts_expired: AtomicBool,
}

/// An answer injected in place of the one the mock would give.
#[derive(Clone, Copy)]
enum Injected {
    /// A bare 503, as a registry that cannot answer returns.
    Unavailable,
    /// A definite registry problem.
    Problem(BRegProblemCode),
}

impl MockRegistry {
    fn new() -> Self {
        let draft = |owner, target| Draft {
            owner,
            target,
            revision: 7,
            proposal_version: 7,
            action_generation: 1,
            submitted: false,
        };
        let drafts = BTreeMap::from([
            (REQUEST_ID, draft(CITIZEN_A, ADDRESS_A)),
            (B_REQUEST_ID, draft(CITIZEN_B, ADDRESS_B)),
            (FOREIGN_TARGET_REQUEST_ID, draft(CITIZEN_B, ADDRESS_A)),
        ]);
        let addresses = BTreeMap::from([
            (
                ADDRESS_A,
                Address {
                    reader: Some(CITIZEN_A),
                    line: CURRENT_LINE_A,
                    locality: "Solmara",
                    postal_code: "PS-100",
                    revision: 3,
                },
            ),
            (
                ADDRESS_B,
                Address {
                    reader: Some(CITIZEN_B),
                    line: CURRENT_LINE_B,
                    locality: "Solmara",
                    postal_code: "PS-200",
                    revision: 3,
                },
            ),
        ]);
        Self {
            drafts: Mutex::new(drafts),
            addresses: Mutex::new(addresses),
            log: Mutex::new(Vec::new()),
            submit_effects: Mutex::new(0),
            replays: Mutex::new(HashMap::new()),
            bearers: Mutex::new(Vec::new()),
            refusing_tokens: Mutex::new(false),
            withdraw_reader_on_next_conflict: Mutex::new(None),
            lose_next_submit_response: AtomicBool::new(false),
            pause_next_metadata_response: AtomicBool::new(false),
            metadata_response_paused: tokio::sync::Semaphore::new(0),
            release_metadata_response: tokio::sync::Semaphore::new(0),
            target_list_first: AtomicBool::new(false),
            next_draft_read: Mutex::new(None),
            next_submit_problem: Mutex::new(None),
            receipts_expired: AtomicBool::new(false),
        }
    }

    /// The registry stops accepting every access token it was issued.
    pub fn refuse_tokens(&self) {
        *self.refusing_tokens.lock().unwrap() = true;
    }

    /// The metadata publishes a list of the target entity for the review
    /// profile ahead of its get, as a registry exposing both reads does.
    pub fn publish_target_list_first(&self) {
        self.target_list_first.store(true, Ordering::SeqCst);
    }

    /// Someone else changes `address` itself, leaving every draft naming it
    /// untouched.
    pub fn change_address(&self, address: &str, line: &'static str) {
        let mut addresses = self.addresses.lock().unwrap();
        let address = addresses.get_mut(address).unwrap();
        address.line = line;
        address.revision += 1;
    }

    /// An agent edits citizen A's draft between the render and the submit.
    pub fn agent_patch(&self) {
        let mut drafts = self.drafts.lock().unwrap();
        let draft = drafts.get_mut(REQUEST_ID).unwrap();
        draft.revision += 1;
        draft.proposal_version += 1;
        draft.action_generation += 1;
    }

    /// The steward withdraws the self-service link behind an address.
    pub fn withdraw_reader(&self, address: &str) {
        self.addresses
            .lock()
            .unwrap()
            .get_mut(address)
            .unwrap()
            .reader = None;
    }

    /// The steward withdraws the self-service link behind `address`, but not
    /// until the next submit this registry answers with a conflict: that
    /// submit's own read of the draft still sees the reader in place, so a
    /// caller can prove a conflict re-render reads again rather than reusing
    /// what that read returned.
    pub fn withdraw_reader_on_next_conflict(&self, address: &'static str) {
        *self.withdraw_reader_on_next_conflict.lock().unwrap() = Some(address);
    }

    /// Make the next successful submit take effect while its caller receives
    /// only an unavailable response, as when an acknowledgment is lost.
    pub fn lose_next_submit_response_after_commit(&self) {
        self.lose_next_submit_response
            .store(true, Ordering::Release);
    }

    /// The registry answers the next draft read with a bare 503.
    pub fn fail_next_draft_read(&self) {
        *self.next_draft_read.lock().unwrap() = Some(Injected::Unavailable);
    }

    /// The registry answers the next draft read with the problem `code`.
    pub fn refuse_next_draft_read(&self, code: BRegProblemCode) {
        *self.next_draft_read.lock().unwrap() = Some(Injected::Problem(code));
    }

    /// The registry declines the next submit with the problem `code`, before
    /// the submit takes any effect.
    pub fn refuse_next_submit(&self, code: BRegProblemCode) {
        *self.next_submit_problem.lock().unwrap() = Some(code);
    }

    /// Every held submit response passes the receipt horizon: a replay of
    /// its key is answered `idempotency.expired` and runs nothing again.
    pub fn expire_receipts(&self) {
        self.receipts_expired.store(true, Ordering::Release);
    }

    pub fn pause_next_metadata_response(&self) {
        self.pause_next_metadata_response
            .store(true, Ordering::Release);
    }

    pub async fn wait_until_metadata_response_is_paused(&self) {
        self.metadata_response_paused
            .acquire()
            .await
            .unwrap()
            .forget();
    }

    pub fn release_metadata_response(&self) {
        self.release_metadata_response.add_permits(1);
    }

    async fn pause_metadata_response_if_requested(&self) {
        if self
            .pause_next_metadata_response
            .swap(false, Ordering::AcqRel)
        {
            self.metadata_response_paused.add_permits(1);
            self.release_metadata_response
                .acquire()
                .await
                .unwrap()
                .forget();
        }
    }

    fn apply_deferred_withdrawal(&self) {
        if let Some(address) = self.withdraw_reader_on_next_conflict.lock().unwrap().take() {
            self.addresses
                .lock()
                .unwrap()
                .get_mut(address)
                .unwrap()
                .reader = None;
        }
    }

    pub fn submitted(&self, request: &str) -> bool {
        self.drafts.lock().unwrap()[request].submitted
    }

    pub fn calls(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    pub fn total_calls(&self) -> u64 {
        self.log.lock().unwrap().len() as u64
    }

    /// Every submit call, whatever the registry answered.
    pub fn submits(&self) -> u64 {
        self.count(|call| call.starts_with("POST ") && call.ends_with("/actions/submit"))
    }

    pub fn submits_for(&self, request: &str) -> u64 {
        let path = format!("POST /v1/records/{ROUTE}/{request}/actions/submit");
        self.count(|call| call == path)
    }

    pub fn target_reads(&self, address: &str) -> u64 {
        let path = format!("GET /v1/records/{TARGET_ROUTE}/{address}");
        self.count(|call| call == path)
    }

    pub fn submit_effects(&self) -> u64 {
        *self.submit_effects.lock().unwrap()
    }

    fn count(&self, matches: impl Fn(&str) -> bool) -> u64 {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|call| matches(call))
            .count() as u64
    }

    /// Every distinct bearer token the registry was presented, so a test can
    /// look for it where it must never appear.
    pub fn bearer_tokens(&self) -> Vec<String> {
        self.bearers.lock().unwrap().clone()
    }

    fn record_call(&self, method: &str, path: String, headers: &HeaderMap) {
        self.log.lock().unwrap().push(format!("{method} {path}"));
        if let Some(token) = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        {
            let mut bearers = self.bearers.lock().unwrap();
            if !bearers.iter().any(|seen| seen == token) {
                bearers.push(token.to_owned());
            }
        }
    }
}

fn action_etag(generation: u64) -> String {
    format!("\"breg-action-hmac-sha256:{generation:064x}\"")
}

fn subject(headers: &HeaderMap) -> Option<String> {
    let token = headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    let payload = token.split('.').nth(1)?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    claims.get("sub")?.as_str().map(str::to_owned)
}

/// A request from another profile is authorized against the entity's default
/// profile, which the review page's client does not hold.
fn selects_profile(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .any(|(name, value)| name == "accessProfile" && value == PROFILE)
    })
}

fn json_response(status: StatusCode, body: &Value, extra: &[(&str, String)]) -> Response {
    let mut response = (status, serde_json::to_vec(body).unwrap()).into_response();
    let headers = response.headers_mut();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("traceparent", TRACEPARENT.parse().unwrap());
    for (name, value) in extra {
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    response
}

fn problem(code: BRegProblemCode) -> Response {
    let status = code.status();
    let title = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        412 => "Precondition Failed",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        428 => "Precondition Required",
        _ => panic!("unregistered mock problem status"),
    };
    let body = json!({
        "type": format!(
            "https://id.registrystack.org/problems/registry-breg/{}",
            code.code().replace('.', "/")
        ),
        "title": title,
        "status": status,
        "detail": code.detail(),
        "code": code.code(),
        "traceId": TRACE_ID
    });
    let mut response = json_response(
        StatusCode::from_u16(status).unwrap(),
        &body,
        &[("cache-control", "no-store".to_owned())],
    );
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    response
}

fn field(id: &str, api_name: &str, label: &str) -> Value {
    json!({
        "id": id,
        "apiName": api_name,
        "label": label,
        "schema": {"type": "string"},
        "required": false,
        "nullable": true,
        "readOnly": false,
        "removable": true
    })
}

/// The request's fields as the real acceptance project declares them, plus a
/// coded field and an empty one so label and absence rendering are exercised.
fn request_fields() -> Value {
    let mut address = field(TARGET_FIELD, TARGET_FIELD, "Registered address");
    address["schema"] = json!({"type": "string", "format": "uuid"});
    address["reference"] = json!({
        "manualEntry": true,
        "targetEntity": TARGET_ENTITY,
        "operations": [{
            "operationId": TARGET_GET,
            "accessProfile": PROFILE,
            "labelFields": ["address-line"]
        }]
    });
    let mut reason = field("reason", "reason", "Reason for the change");
    reason["codeLabels"] = json!({"relocation": "Moved house"});
    json!([
        address,
        field("new-address-line", "newAddressLine", "New address line"),
        field("new-locality", "newLocality", "New town"),
        field("new-postal-code", "newPostalCode", "New postal code"),
        reason,
        field("unit", "unit", "Flat or unit")
    ])
}

const REQUEST_READABLE: [&str; 6] = [
    TARGET_FIELD,
    "new-address-line",
    "new-locality",
    "new-postal-code",
    "reason",
    "unit",
];

const TARGET_READABLE: [&str; 3] = ["address-line", "locality", "postal-code"];

fn operation(identifier: &str, method: &str, path: &str, kind: &str, request: Value) -> Value {
    let capabilities = if kind == "get" {
        json!([])
    } else {
        json!(["change_request_lifecycle"])
    };
    json!({
        "id": identifier,
        "method": method,
        "path": path,
        "operation": kind,
        "sourceEntity": ENTITY,
        "responseEntity": ENTITY,
        "accessProfile": PROFILE,
        "requiredCapabilities": capabilities,
        "entityLabel": "Address correction requests",
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": ["new-address-line"],
        "fields": request_fields(),
        "readableFields": REQUEST_READABLE,
        "readableRequestFields": [],
        "createWritableFields": [],
        "patchWritableFields": [],
        "selectors": [],
        "query": null,
        "request": request
    })
}

fn target_operation() -> Value {
    json!({
        "id": TARGET_GET,
        "method": "GET",
        "path": format!("/v1/records/{TARGET_ROUTE}/{{record_id}}"),
        "operation": "get",
        "sourceEntity": TARGET_ENTITY,
        "responseEntity": TARGET_ENTITY,
        "accessProfile": PROFILE,
        "requiredCapabilities": [],
        "entityLabel": "Registered addresses",
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": ["address-line"],
        "fields": [
            field("address-line", "addressLine", "Address line"),
            field("locality", "locality", "Town"),
            field("postal-code", "postalCode", "Postal code")
        ],
        "readableFields": TARGET_READABLE,
        "readableRequestFields": [],
        "createWritableFields": [],
        "patchWritableFields": [],
        "selectors": [],
        "query": null,
        "request": {"fieldNames": "api", "queryParameters": ["$select"]}
    })
}

/// [`metadata`], also publishing a list of the target entity for the review
/// profile and naming it before the get among the target field's reference
/// operations.
pub fn metadata_with_target_list_first() -> Value {
    let mut document = metadata();
    let list_reference = json!({
        "operationId": TARGET_LIST,
        "accessProfile": PROFILE,
        "labelFields": ["address-line"]
    });
    let operations = document["operations"].as_array_mut().unwrap();
    for operation in operations.iter_mut() {
        for field in operation["fields"].as_array_mut().unwrap() {
            if let Some(references) = field.pointer_mut("/reference/operations") {
                references
                    .as_array_mut()
                    .unwrap()
                    .insert(0, list_reference.clone());
            }
        }
    }
    operations.push(target_list_operation());
    let target = document["entities"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entity| entity["id"] == TARGET_ENTITY)
        .unwrap();
    target["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!({"operation": "list", "accessProfile": PROFILE}));
    document
}

fn target_list_operation() -> Value {
    let mut list = target_operation();
    list["id"] = json!(TARGET_LIST);
    list["path"] = json!(format!("/v1/records/{TARGET_ROUTE}"));
    list["operation"] = json!("list");
    list["request"] = json!({
        "fieldNames": "api",
        "queryParameters": ["$select", "$skiptoken", "$top"]
    });
    list["query"] = json!({
        "kind": "list",
        "allowCount": false,
        "defaultPageSize": 100,
        "maxPageSize": 100,
        "maxFilterClauses": 32,
        "maxInValues": 100,
        "filterableFields": [],
        "sortableFields": [],
        "selectableFields": [
            {"id": "address-line", "apiName": "addressLine"},
            {"id": "locality", "apiName": "locality"},
            {"id": "postal-code", "apiName": "postalCode"}
        ],
        "pagination": {
            "exclusive": true,
            "parameter": "$skiptoken",
            "responsePath": "pageInfo.nextCursor"
        },
        "temporal": null
    });
    list
}

/// The caller-filtered metadata the registry answers for `citizen-review`.
pub fn metadata() -> Value {
    let get = operation(
        "records.address-correction-request.get",
        "GET",
        &format!("/v1/records/{ROUTE}/{{record_id}}"),
        "get",
        json!({"fieldNames": "api", "queryParameters": ["$select"]}),
    );
    let submit = operation(
        "records.address-correction-request.request.submit",
        "POST",
        &format!("/v1/records/{ROUTE}/{{record_id}}/actions/submit"),
        "submit_request",
        json!({
            "fieldNames": "api",
            "queryParameters": [],
            "body": "change_request_action",
            "contentType": "application/json",
            "ifMatchRequired": true,
            "idempotencyKeyRequired": true,
            "mutationSemantics": "change_request_lifecycle",
            "schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": false,
                "properties": {}
            }
        }),
    );
    json!({
        "id": "citizen-address-correction",
        "version": "0.1.0",
        "revision": METADATA_REVISION,
        "metadataVersion": "1",
        "entities": [
            {
                "id": ENTITY,
                "datasetIdentifier": "citizen-address-correction",
                "route": ROUTE,
                "operations": [
                    {"operation": "get", "accessProfile": PROFILE},
                    {"operation": "submit_request", "accessProfile": PROFILE}
                ],
                "readableFields": REQUEST_READABLE,
                "schema": format!("/v1/schemas/{ENTITY}")
            },
            {
                "id": TARGET_ENTITY,
                "datasetIdentifier": "citizen-address-correction",
                "route": TARGET_ROUTE,
                "operations": [{"operation": "get", "accessProfile": PROFILE}],
                "readableFields": TARGET_READABLE,
                "schema": format!("/v1/schemas/{TARGET_ENTITY}")
            }
        ],
        "operations": [get, submit, target_operation()]
    })
}

fn draft_record(identifier: &str, draft: &Draft) -> Value {
    let actions = if draft.submitted {
        json!([])
    } else {
        json!([{
            "operation": "submit_request",
            "method": "POST",
            "href": format!(
                "/v1/records/{ROUTE}/{identifier}/actions/submit?accessProfile={PROFILE}"
            ),
            "ifMatch": action_etag(draft.action_generation)
        }])
    };
    json!({
        "data": {
            "recordIdentifier": identifier,
            "revisionIdentifier": draft.revision.to_string(),
            "domainData": {
                "address": draft.target,
                "newAddressLine": HOSTILE_STREET,
                "newLocality": PROPOSED_LOCALITY,
                "newPostalCode": "PS-205",
                "reason": "relocation",
                "unit": null
            },
            "request": {
                "bregState": if draft.submitted { "submitted" } else { "draft" },
                "proposalVersion": draft.proposal_version,
                "effectDigest": EFFECT_DIGEST,
                "editable": !draft.submitted,
                "actions": actions
            }
        },
        "meta": {
            "registryIdentifier": "citizen-address-correction",
            "datasetIdentifier": "citizen-address-correction",
            "entityTypeIdentifier": ENTITY
        }
    })
}

fn address_record(identifier: &str, address: &Address) -> Value {
    json!({
        "data": {
            "recordIdentifier": identifier,
            "revisionIdentifier": address.revision.to_string(),
            "domainData": {
                "addressLine": address.line,
                "locality": address.locality,
                "postalCode": address.postal_code
            }
        },
        "meta": {
            "registryIdentifier": "citizen-address-correction",
            "datasetIdentifier": "citizen-address-correction",
            "entityTypeIdentifier": TARGET_ENTITY
        }
    })
}

fn record_response(entity: &str, body: &Value, revision: u64) -> Response {
    json_response(
        StatusCode::OK,
        body,
        &[
            ("etag", format!("\"breg-record-{revision:012}\"")),
            (
                "link",
                format!(
                    "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </tenant/base/v1/schemas/{entity}>; rel=\"describedby\""
                ),
            ),
        ],
    )
}

async fn registry_metadata(
    State(registry): State<Arc<MockRegistry>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    registry.record_call("GET", "/v1/registry".to_owned(), &headers);
    if subject(&headers).is_none() {
        return problem(BRegProblemCode::AuthenticationRefused);
    }
    if !selects_profile(query.as_deref()) {
        return problem(BRegProblemCode::ResourceNotFound);
    }
    registry.pause_metadata_response_if_requested().await;
    let metadata = if registry.target_list_first.load(Ordering::SeqCst) {
        metadata_with_target_list_first()
    } else {
        metadata()
    };
    json_response(StatusCode::OK, &metadata, &[])
}

async fn read_draft(
    State(registry): State<Arc<MockRegistry>>,
    RoutePath(identifier): RoutePath<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    registry.record_call("GET", format!("/v1/records/{ROUTE}/{identifier}"), &headers);
    if *registry.refusing_tokens.lock().unwrap() {
        return problem(BRegProblemCode::AuthenticationRefused);
    }
    match registry.next_draft_read.lock().unwrap().take() {
        Some(Injected::Unavailable) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Some(Injected::Problem(code)) => return problem(code),
        None => {}
    }
    let caller = subject(&headers);
    let drafts = registry.drafts.lock().unwrap();
    let Some(draft) = drafts.get(identifier.as_str()) else {
        return problem(BRegProblemCode::ResourceNotFound);
    };
    if caller.as_deref() != Some(draft.owner) || !selects_profile(query.as_deref()) {
        return problem(BRegProblemCode::ResourceNotFound);
    }
    record_response(ENTITY, &draft_record(&identifier, draft), draft.revision)
}

async fn read_address(
    State(registry): State<Arc<MockRegistry>>,
    RoutePath(identifier): RoutePath<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    registry.record_call(
        "GET",
        format!("/v1/records/{TARGET_ROUTE}/{identifier}"),
        &headers,
    );
    let caller = subject(&headers);
    let addresses = registry.addresses.lock().unwrap();
    let Some(address) = addresses.get(identifier.as_str()) else {
        return problem(BRegProblemCode::ResourceNotFound);
    };
    if caller.is_none() || caller.as_deref() != address.reader || !selects_profile(query.as_deref())
    {
        return problem(BRegProblemCode::ResourceNotFound);
    }
    record_response(
        TARGET_ENTITY,
        &address_record(&identifier, address),
        address.revision,
    )
}

async fn submit_draft(
    State(registry): State<Arc<MockRegistry>>,
    RoutePath(identifier): RoutePath<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    _body: Bytes,
) -> Response {
    registry.record_call(
        "POST",
        format!("/v1/records/{ROUTE}/{identifier}/actions/submit"),
        &headers,
    );
    let caller = subject(&headers);
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    // One lock order for the whole decision keeps a concurrent pair serial.
    let mut replays = registry.replays.lock().unwrap();
    let mut drafts = registry.drafts.lock().unwrap();
    let Some(draft) = drafts.get_mut(identifier.as_str()) else {
        return problem(BRegProblemCode::ResourceNotFound);
    };
    if caller.as_deref() != Some(draft.owner) || !selects_profile(query.as_deref()) {
        return problem(BRegProblemCode::ResourceNotFound);
    }
    let (Some(key), Some(if_match)) = (header("idempotency-key"), header("if-match")) else {
        return problem(BRegProblemCode::PreconditionRequired);
    };
    if let Some((bound, receipt)) = replays.get(&key) {
        if *bound != if_match {
            return problem(BRegProblemCode::IdempotencyConflict);
        }
        if registry.receipts_expired.load(Ordering::Acquire) {
            return problem(BRegProblemCode::IdempotencyExpired);
        }
        return receipt_response(receipt);
    }
    if let Some(code) = registry.next_submit_problem.lock().unwrap().take() {
        return problem(code);
    }
    if if_match != action_etag(draft.action_generation) {
        registry.apply_deferred_withdrawal();
        return problem(BRegProblemCode::PreconditionFailed);
    }
    if draft.submitted {
        registry.apply_deferred_withdrawal();
        return problem(BRegProblemCode::MutationConflict);
    }
    draft.submitted = true;
    draft.revision += 1;
    *registry.submit_effects.lock().unwrap() += 1;
    let receipt = json!({
        "id": identifier,
        "revision": draft.revision,
        "snapshot": format!("breg1_{identifier}"),
        "request": {
            "bregState": "submitted",
            "proposalVersion": draft.proposal_version,
            "effectDigest": EFFECT_DIGEST,
            "application": null
        }
    });
    replays.insert(key, (if_match, receipt.clone()));
    if registry
        .lose_next_submit_response
        .swap(false, Ordering::AcqRel)
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    receipt_response(&receipt)
}

fn receipt_response(receipt: &Value) -> Response {
    json_response(
        StatusCode::OK,
        receipt,
        &[
            ("cache-control", "no-store".to_owned()),
            ("vary", "authorization, accept".to_owned()),
        ],
    )
}

async fn start_registry() -> (Arc<MockRegistry>, String) {
    let registry = Arc::new(MockRegistry::new());
    let app = Router::new()
        .route("/tenant/base/v1/registry", get(registry_metadata))
        .route(
            &format!("/tenant/base/v1/records/{ROUTE}/{{id}}"),
            get(read_draft),
        )
        .route(
            &format!("/tenant/base/v1/records/{TARGET_ROUTE}/{{id}}"),
            get(read_address),
        )
        .route(
            &format!("/tenant/base/v1/records/{ROUTE}/{{id}}/actions/submit"),
            post(submit_draft),
        )
        .with_state(registry.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (registry, format!("http://{address}/tenant/base"))
}

/// Write a secret file the way the runtime requires: owner-only, one link.
pub fn write_secret(directory: &Path, name: &str, value: &[u8]) {
    let path = directory.join(name);
    std::fs::write(&path, value).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A one-shot authorization code the narrow-scope provider issued.
struct NarrowScopeCode {
    subject: String,
    nonce: Option<String>,
    redirect_uri: String,
}

/// A minimal single-origin OpenID Connect provider whose token response
/// always states a scope narrower than the one the request asked for.
///
/// The shared `TestAuthorizationServer` always echoes back exactly the scope
/// a request asked for, so it cannot produce this response; this provider
/// exists only to prove the sign-in client refuses a narrowed grant.
struct NarrowScopeState {
    issuer: String,
    signing_key: registry_platform_crypto::PrivateJwk,
    codes: Mutex<HashMap<String, NarrowScopeCode>>,
    token_calls: Arc<AtomicU64>,
}

pub struct NarrowScopeProvider {
    pub issuer: String,
    token_calls: Arc<AtomicU64>,
}

impl NarrowScopeProvider {
    pub fn token_calls(&self) -> u64 {
        self.token_calls.load(Ordering::Acquire)
    }
}

fn narrow_scope_unix_now() -> i64 {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after Unix epoch")
        .as_secs();
    i64::try_from(seconds).expect("the clock fits in i64")
}

/// Start the narrow-scope provider and return its issuer: a bare origin with
/// no path, so discovery's `.well-known` suffix lands where the provider
/// serves it.
pub async fn start_narrow_scope_provider() -> NarrowScopeProvider {
    let (signing_key, _) = fixtures::ed25519_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let issuer = format!("http://{address}");
    let token_calls = Arc::new(AtomicU64::new(0));
    let state = Arc::new(NarrowScopeState {
        issuer: issuer.clone(),
        signing_key,
        codes: Mutex::new(HashMap::new()),
        token_calls: Arc::clone(&token_calls),
    });
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(narrow_scope_metadata),
        )
        .route("/jwks.json", get(narrow_scope_jwks))
        .route("/authorize", get(narrow_scope_authorize))
        .route("/token", post(narrow_scope_token))
        .with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    NarrowScopeProvider {
        issuer,
        token_calls,
    }
}

async fn narrow_scope_metadata(State(state): State<Arc<NarrowScopeState>>) -> Response {
    json_response(
        StatusCode::OK,
        &json!({
            "issuer": state.issuer,
            "authorization_endpoint": format!("{}/authorize", state.issuer),
            "token_endpoint": format!("{}/token", state.issuer),
            "jwks_uri": format!("{}/jwks.json", state.issuer),
        }),
        &[],
    )
}

async fn narrow_scope_jwks(State(state): State<Arc<NarrowScopeState>>) -> Response {
    json_response(
        StatusCode::OK,
        &registry_platform_testing::jwks_from_private_jwk(&state.signing_key),
        &[],
    )
}

async fn narrow_scope_authorize(
    State(state): State<Arc<NarrowScopeState>>,
    RawQuery(query): RawQuery,
) -> Response {
    let pairs: HashMap<String, String> = query
        .as_deref()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default();
    let Some(redirect_uri) = pairs.get("redirect_uri") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let request_state = pairs.get("state").cloned().unwrap_or_default();
    let code = uuid::Uuid::new_v4().to_string();
    state.codes.lock().unwrap().insert(
        code.clone(),
        NarrowScopeCode {
            subject: pairs
                .get("login_hint")
                .cloned()
                .unwrap_or_else(|| CITIZEN_A.to_owned()),
            nonce: pairs.get("nonce").cloned(),
            redirect_uri: redirect_uri.clone(),
        },
    );
    let mut location = url::Url::parse(redirect_uri).unwrap();
    location
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &request_state);
    (
        StatusCode::FOUND,
        [(axum::http::header::LOCATION, location.to_string())],
    )
        .into_response()
}

async fn narrow_scope_token(State(state): State<Arc<NarrowScopeState>>, body: Bytes) -> Response {
    state.token_calls.fetch_add(1, Ordering::AcqRel);
    let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    let Some(code) = form.get("code") else {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({ "error": "invalid_request" }),
            &[],
        );
    };
    let Some(pending) = state.codes.lock().unwrap().remove(code) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({ "error": "invalid_grant" }),
            &[],
        );
    };
    let now = narrow_scope_unix_now();
    let expires_at = now + 300;
    let mut id_claims = serde_json::Map::new();
    id_claims.insert("iss".to_owned(), json!(state.issuer));
    id_claims.insert("sub".to_owned(), json!(pending.subject));
    id_claims.insert("aud".to_owned(), json!(CLIENT_ID));
    id_claims.insert("azp".to_owned(), json!(CLIENT_ID));
    id_claims.insert("exp".to_owned(), json!(expires_at));
    id_claims.insert("iat".to_owned(), json!(now));
    if let Some(nonce) = &pending.nonce {
        id_claims.insert("nonce".to_owned(), json!(nonce));
    }
    let id_token = registry_platform_testing::sign_ed25519_compact_jwt_with_key(
        &state.signing_key,
        "JWT",
        "registry-platform-testing-ed25519-1",
        Value::Object(id_claims),
    );
    json_response(
        StatusCode::OK,
        &json!({
            "access_token": "narrow-scope-access-token",
            "token_type": "Bearer",
            "expires_in": 300,
            // Deliberately narrower than the "address-correction:self" the
            // request asked for: this response is the whole point of the
            // provider, proving the sign-in client refuses it.
            "scope": "citizen:profile",
            "id_token": id_token,
        }),
        &[],
    )
}

pub struct Options {
    pub token_lifetime: Duration,
    /// Top-level blocks appended to the runtime document, such as `rateLimits`.
    pub extra_document: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            token_lifetime: Duration::from_secs(300),
            extra_document: String::new(),
        }
    }
}

/// Everything the page needs besides itself: an authorization server, a mock
/// registry, and an owner-only directory holding the runtime document, the
/// client key, and the audit journal.
pub struct Environment {
    pub origin: String,
    pub address: SocketAddr,
    pub registry: Arc<MockRegistry>,
    pub authorization_server: TestAuthorizationServer,
    pub directory: TempDir,
    pub config_path: PathBuf,
    pub audit_path: PathBuf,
}

impl Environment {
    /// Prepare the page's surroundings for an origin whose port is `address`.
    pub async fn prepare(address: SocketAddr, options: &Options) -> Self {
        let origin = format!("http://{address}");
        let (_, public_key) = fixtures::ed25519_pair();
        let authorization_server = TestAuthorizationServer::builder()
            .client(
                TestClient::new(CLIENT_ID)
                    .with_public_jwk(public_key)
                    .with_redirect_uri(format!("{origin}/signin/callback"))
                    .with_resource(RESOURCE)
                    .with_token_lifetime(options.token_lifetime),
            )
            .logged_in_subject(CITIZEN_A)
            .start()
            .await;
        let (registry, base_url) = start_registry().await;

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let secrets = root.join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
        write_secret(
            &secrets,
            "client-key.jwk",
            fixtures::ED25519_PRIVATE_JWK.as_bytes(),
        );
        write_secret(&secrets, "audit-key", &[0x5a; 32]);
        let audit_directory = root.join("audit");
        std::fs::create_dir(&audit_directory).unwrap();
        std::fs::set_permissions(&audit_directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let audit_path = audit_directory.join("audit.jsonl");
        let config_path = root.join("runtime.yaml");
        let document = format!(
            "apiVersion: id.registrystack.org/formats/breg/review-runtime/v1alpha1\n\
             kind: BRegReviewRuntimeConfig\n\
             listener:\n  bind: \"{address}\"\n  tlsTermination: development-loopback\n\
             publicOrigin: {origin}\n\
             secretProviders:\n  file:\n    root: {secrets}\n\
             signIn:\n  issuer: {issuer}\n  clientId: {CLIENT_ID}\n  clientKeyRef: secret:file/client-key.jwk\n  scopes: [\"{SCOPE}\"]\n\
             registry:\n  baseUrl: {base_url}\n  resource: {RESOURCE}\n  entity: {ENTITY}\n  targetField: {TARGET_FIELD}\n  accessProfile: {PROFILE}\n\
             audit:\n  path: {audit}\n  hashKeyRef: secret:file/audit-key\n\
             {extra}",
            secrets = secrets.display(),
            issuer = authorization_server.issuer(),
            audit = audit_path.display(),
            extra = options.extra_document,
        );
        std::fs::write(&config_path, document).unwrap();
        Self {
            origin,
            address,
            registry,
            authorization_server,
            directory,
            config_path,
            audit_path,
        }
    }

    pub fn audit_text(&self) -> String {
        let mut text = String::new();
        let directory = self.audit_path.parent().unwrap();
        let mut entries: Vec<_> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_file() {
                text.push_str(&std::fs::read_to_string(path).unwrap());
            }
        }
        text
    }
}

/// An audit destination a test controls: it keeps every line the page writes
/// and refuses every write once its budget of accepted writes is spent.
#[derive(Clone, Default)]
pub struct AuditSink {
    lines: Arc<Mutex<Vec<u8>>>,
    /// Writes still accepted; `None` accepts every write.
    budget: Arc<Mutex<Option<u64>>>,
}

impl AuditSink {
    /// Accept `writes` more writes, then refuse every later one.
    pub fn fail_after(&self, writes: u64) {
        *self.budget.lock().unwrap() = Some(writes);
    }

    pub fn text(&self) -> String {
        String::from_utf8(self.lines.lock().unwrap().clone()).unwrap()
    }
}

impl std::io::Write for AuditSink {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let mut budget = self.budget.lock().unwrap();
        match budget.as_mut() {
            Some(0) => return Err(std::io::Error::other("the test audit sink refuses")),
            Some(remaining) => *remaining -= 1,
            None => {}
        }
        self.lines.lock().unwrap().extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A running page and the browser that drives it.
pub struct Harness {
    pub environment: Environment,
    pub http: reqwest::Client,
}

pub struct Page {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Page {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    pub fn location(&self) -> &str {
        self.header("location").expect("a location header")
    }

    /// The `name=value` pair of the cookie this response sets under `name`.
    pub fn set_cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with(&format!("{name}=")))
            .map(str::to_owned)
    }

    pub fn error_code(&self) -> Option<&str> {
        let start = self.body.find("data-error-code=\"")? + "data-error-code=\"".len();
        let end = self.body[start..].find('"')? + start;
        Some(&self.body[start..end])
    }

    /// The value of the hidden form input `name`, if the page renders one.
    pub fn input(&self, name: &str) -> Option<String> {
        let marker = format!("name=\"{name}\" value=\"");
        let start = self.body.find(&marker)? + marker.len();
        let end = self.body[start..].find('"')? + start;
        Some(self.body[start..end].to_owned())
    }
}

impl Harness {
    pub async fn start() -> Self {
        Self::start_with(Options::default()).await
    }

    pub async fn start_with(options: Options) -> Self {
        Self::start_over(options, None).await
    }

    /// Start a page whose audit stream is `sink` instead of its journal file.
    pub async fn start_with_audit_sink(sink: &AuditSink) -> Self {
        Self::start_over(Options::default(), Some(sink.clone())).await
    }

    async fn start_over(options: Options, sink: Option<AuditSink>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let environment = Environment::prepare(address, &options).await;
        let config = registry_breg_review::RuntimeConfig::load(&environment.config_path)
            .expect("runtime document loads");
        let router = match sink {
            Some(sink) => {
                let writer = registry_platform_audit::AuditWriter::from_line_sink(Box::new(sink));
                registry_breg_review::router_with_audit_writer(config, writer).await
            }
            None => registry_breg_review::router(config).await,
        }
        .expect("review page starts");
        tokio::spawn(async move {
            registry_breg_review::serve_until(listener, router, std::future::pending())
                .await
                .expect("review page serves");
        });
        Self {
            environment,
            http: browser(),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.environment.origin)
    }

    pub async fn get(&self, path: &str, cookie: Option<&str>) -> Page {
        let mut request = self.http.get(self.url(path));
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        page(request.send().await.unwrap()).await
    }

    pub async fn post(&self, path: &str, cookie: Option<&str>, form: &[(&str, &str)]) -> Page {
        let body = form
            .iter()
            .map(|(name, value)| format!("{name}={}", encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let mut request = self
            .http
            .post(self.url(path))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body);
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        page(request.send().await.unwrap()).await
    }

    /// Sign `subject` in through the whole redirect dance and return the
    /// session cookie pair.
    pub async fn sign_in(&self, subject: &str) -> String {
        self.sign_in_page(subject)
            .await
            .set_cookie("breg-review-session")
            .expect("the callback sets a session cookie")
    }

    /// Sign `subject` in and return the callback response.
    pub async fn sign_in_page(&self, subject: &str) -> Page {
        sign_in_to(&self.http, &self.environment.origin, subject, REQUEST_ID).await
    }

    /// Sign citizen A in and open their draft, returning the cookie and page.
    pub async fn review(&self) -> (String, Page) {
        self.review_as(CITIZEN_A, REQUEST_ID).await
    }

    /// Sign `subject` in and open `request`, which must render a form.
    pub async fn review_as(&self, subject: &str, request: &str) -> (String, Page) {
        let cookie = cookie_pair(&self.sign_in(subject).await);
        let page = self
            .get(&format!("/requests/{request}"), Some(&cookie))
            .await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        (cookie, page)
    }
}

/// Sign `subject` in to the page at `origin` through the whole redirect
/// dance, returning to `request`, and return the callback response.
pub async fn sign_in_to(
    http: &reqwest::Client,
    origin: &str,
    subject: &str,
    request: &str,
) -> Page {
    let start = page(
        http.get(format!("{origin}/signin?return=%2Frequests%2F{request}"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(start.status, StatusCode::SEE_OTHER, "{}", start.body);
    let sign_in_cookie = cookie_pair(
        &start
            .set_cookie("breg-review-signin")
            .expect("sign-in cookie"),
    );
    let authorize = format!("{}&login_hint={subject}", start.location());
    let redirected = http.get(authorize).send().await.unwrap();
    assert_eq!(redirected.status(), StatusCode::FOUND);
    let callback = redirected
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(callback.starts_with(&format!("{origin}/signin/callback?")));
    let response = http
        .get(callback)
        .header("cookie", sign_in_cookie)
        .send()
        .await
        .unwrap();
    page(response).await
}

/// Reduce a `Set-Cookie` value to the `name=value` a browser sends back.
pub fn cookie_pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_owned()
}

pub fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

pub async fn page(response: reqwest::Response) -> Page {
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    let mut headers = HeaderMap::new();
    for (name, value) in response.headers() {
        headers.append(
            axum::http::HeaderName::from_bytes(name.as_str().as_bytes()).unwrap(),
            axum::http::HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );
    }
    let body = response.text().await.unwrap();
    Page {
        status,
        headers,
        body,
    }
}

pub fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
