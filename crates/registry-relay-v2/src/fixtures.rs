// SPDX-License-Identifier: Apache-2.0
//! Strict, value-free offline acceptance journeys over the real Relay router.

use std::collections::{BTreeMap, BTreeSet};

use axum::body::{to_bytes, Body};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG, VARY};
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tower::ServiceExt as _;

use crate::auth::{FixturePrincipal, RelayAuthenticator};
use crate::model::{CompiledAccess, CompiledRegistry, OperationKind};

const JOURNEY_VERSION: &str = "relay.registrystack.org/http-journey/v1alpha1";
const MAXIMUM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureJourney {
    pub schema_version: String,
    pub registry: String,
    #[serde(default)]
    pub authorizations: BTreeMap<String, FixtureAuthorization>,
    pub steps: Vec<FixtureStep>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureAuthorization {
    pub principal: String,
    pub scopes: BTreeSet<String>,
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureStep {
    pub id: String,
    #[serde(default)]
    pub authorization_fixture: Option<String>,
    pub request: FixtureRequest,
    pub expect: FixtureExpectation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureRequest {
    pub method: FixtureMethod,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub query: BTreeMap<String, Value>,
    #[serde(default)]
    pub body: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FixtureMethod {
    Get,
    Post,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureExpectation {
    pub status: u16,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub capability_patterns: Vec<String>,
    #[serde(default)]
    pub absent_capability_patterns: Vec<String>,
    #[serde(default)]
    pub item_count: Option<u32>,
    #[serde(default)]
    pub next_cursor: Option<Value>,
    #[serde(default)]
    pub registry_core_required: Option<bool>,
    #[serde(default)]
    pub domain_data_keys: Vec<String>,
    #[serde(default)]
    pub record_identifier: Option<String>,
    #[serde(default)]
    pub cache: Option<String>,
    #[serde(default)]
    pub route_absent: Option<bool>,
    #[serde(default)]
    pub equivalence_class: Option<String>,
    #[serde(default)]
    pub absent_everywhere: Vec<String>,
    #[serde(default)]
    pub records_equivalent_to: Option<String>,
    #[serde(default)]
    pub body_empty: Option<bool>,
    #[serde(default)]
    pub etag_same_as: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FixturePlanReport {
    pub registry_identifier: String,
    pub selected_fixture: Option<String>,
    pub steps: Vec<FixturePlanStep>,
    pub diagnostics: Vec<FixtureDiagnostic>,
}

impl FixturePlanReport {
    pub fn is_success(&self) -> bool {
        self.diagnostics.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FixturePlanStep {
    pub id: String,
    pub operation_identifier: Option<String>,
    pub expected_status: u16,
    pub actual_status: Option<u16>,
    pub actual_code: Option<String>,
    pub passed: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FixtureDiagnostic {
    pub code: String,
    pub location: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum FixtureError {
    #[error("fixture YAML is not valid")]
    InvalidYaml,
}

pub fn parse_journey(yaml: &str) -> Result<FixtureJourney, FixtureError> {
    serde_norway::from_str(yaml).map_err(|_| FixtureError::InvalidYaml)
}

/// Compile a journey against the exact runtime operation inventory without
/// opening the source. This is the structural preflight used before execution.
pub fn compile_fixture_plan(
    registry: &CompiledRegistry,
    journey: &FixtureJourney,
    selected_fixture: Option<&str>,
) -> FixturePlanReport {
    let mut diagnostics = Vec::new();
    if journey.schema_version != JOURNEY_VERSION {
        diagnostic(
            &mut diagnostics,
            "fixture.schema_version_unsupported",
            "schemaVersion",
            "the fixture journey version is unsupported",
        );
    }
    if journey.registry != registry.registry_identifier {
        diagnostic(
            &mut diagnostics,
            "fixture.registry_mismatch",
            "registry",
            "the fixture journey belongs to another Registry",
        );
    }
    validate_authorizations(journey, &mut diagnostics);

    let mut ids = BTreeSet::new();
    let mut steps = Vec::new();
    for (index, step) in journey.steps.iter().enumerate() {
        if !ids.insert(step.id.as_str()) {
            diagnostic(
                &mut diagnostics,
                "fixture.id_duplicate",
                &format!("steps[{index}].id"),
                "fixture step identifiers must be unique",
            );
        }
        if let Some(reference) = step.authorization_fixture.as_deref() {
            if !journey.authorizations.contains_key(reference) {
                diagnostic(
                    &mut diagnostics,
                    "fixture.authorization_unknown",
                    &format!("steps[{index}].authorizationFixture"),
                    "the authorization fixture identifier is unknown",
                );
            }
        }
        if selected_fixture.is_some_and(|selected| selected != step.id) {
            continue;
        }
        if !step.request.path.starts_with('/') || step.request.path.contains(['?', '#']) {
            diagnostic(
                &mut diagnostics,
                "fixture.path_invalid",
                &format!("steps[{index}].request.path"),
                "fixture paths must be absolute URI paths without a query or fragment",
            );
        }
        if !matches!(
            step.expect.status,
            200 | 304 | 400 | 401 | 403 | 404 | 406 | 413 | 414 | 415 | 429 | 500 | 503 | 504
        ) {
            diagnostic(
                &mut diagnostics,
                "fixture.status_unsupported",
                &format!("steps[{index}].expect.status"),
                "the expected status is outside the Relay problem contract",
            );
        }
        let operation = resolve_operation(registry, &step.request);
        if step.expect.status == 200 && is_data_path(&step.request.path) && operation.is_none() {
            diagnostic(
                &mut diagnostics,
                "fixture.operation_unknown",
                &format!("steps[{index}].request"),
                "a successful fixture names no compiled operation",
            );
        }
        if let Some(operation) = operation {
            if matches!(operation.access, CompiledAccess::Protected { .. })
                && step.expect.status == 200
                && step.authorization_fixture.is_none()
            {
                diagnostic(
                    &mut diagnostics,
                    "fixture.authorization_missing",
                    &format!("steps[{index}].authorizationFixture"),
                    "a protected successful fixture requires an authorization fixture",
                );
            }
        }
        steps.push(FixturePlanStep {
            id: step.id.clone(),
            operation_identifier: operation.map(|operation| operation.identifier.clone()),
            expected_status: step.expect.status,
            actual_status: None,
            actual_code: None,
            passed: None,
        });
    }
    if let Some(selected) = selected_fixture {
        if !journey.steps.iter().any(|step| step.id == selected) {
            diagnostic(
                &mut diagnostics,
                "fixture.id_unknown",
                "fixture",
                "the selected fixture identifier is unknown",
            );
        }
    }
    FixturePlanReport {
        registry_identifier: registry.registry_identifier.clone(),
        selected_fixture: selected_fixture.map(str::to_owned),
        steps,
        diagnostics,
    }
}

/// Execute each preflighted step against the real in-process Relay router.
/// Response bytes are inspected in memory and never copied into the report.
pub async fn execute_fixture_journey(
    registry: &CompiledRegistry,
    app: Router,
    journey: &FixtureJourney,
    selected_fixture: Option<&str>,
) -> FixturePlanReport {
    let mut report = compile_fixture_plan(registry, journey, selected_fixture);
    if !report.is_success() {
        return report;
    }
    let mut equivalence_classes = BTreeMap::<String, Value>::new();
    let mut observations = BTreeMap::<String, FixtureObservation>::new();
    for planned in &mut report.steps {
        let Some((index, step)) = journey
            .steps
            .iter()
            .enumerate()
            .find(|(_, step)| step.id == planned.id)
        else {
            diagnostic(
                &mut report.diagnostics,
                "fixture.execution_failed",
                "steps",
                "the fixture step could not be executed",
            );
            continue;
        };
        let request = match fixture_request(step, &observations) {
            Ok(request) => request,
            Err(()) => {
                diagnostic(
                    &mut report.diagnostics,
                    "fixture.request_invalid",
                    &format!("steps[{index}].request"),
                    "the fixture request could not be constructed",
                );
                planned.passed = Some(false);
                continue;
            }
        };
        let response = match app.clone().oneshot(request).await {
            Ok(response) => response,
            Err(error) => match error {},
        };
        let status = response.status();
        let headers = response.headers().clone();
        let body = match to_bytes(response.into_body(), MAXIMUM_RESPONSE_BYTES).await {
            Ok(body) => body,
            Err(_) => {
                diagnostic(
                    &mut report.diagnostics,
                    "fixture.response_invalid",
                    &format!("steps[{index}].expect"),
                    "the fixture response exceeded the offline evaluation bound",
                );
                planned.passed = Some(false);
                continue;
            }
        };
        let document = serde_json::from_slice::<Value>(&body).ok();
        let actual_code = document
            .as_ref()
            .and_then(|value| value.get("code"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        planned.actual_status = Some(status.as_u16());
        planned.actual_code.clone_from(&actual_code);
        planned.passed = Some(assert_expectations(
            step,
            &ObservedResponse {
                status,
                headers: &headers,
                body: &body,
                document: document.as_ref(),
                code: actual_code.as_deref(),
            },
            &mut equivalence_classes,
            &observations,
            index,
            &mut report.diagnostics,
        ));
        observations.insert(
            step.id.clone(),
            FixtureObservation {
                document,
                etag: headers
                    .get(ETAG)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
            },
        );
    }
    report
}

/// Build the only non-production authenticator used by `relayctl test`.
/// Its already-verified principals come solely from the strict journey input.
pub(crate) fn fixture_authenticator(journey: &FixtureJourney) -> Option<RelayAuthenticator> {
    (!journey.authorizations.is_empty()).then(|| {
        RelayAuthenticator::for_offline_fixtures(
            journey
                .authorizations
                .iter()
                .map(|(identifier, fixture)| {
                    (
                        fixture_token(identifier),
                        FixturePrincipal {
                            identifier: fixture.principal.clone(),
                            scopes: fixture.scopes.clone(),
                            claims: Value::Object(
                                fixture
                                    .claims
                                    .iter()
                                    .map(|(name, value)| {
                                        (name.clone(), Value::String(value.clone()))
                                    })
                                    .collect(),
                            ),
                        },
                    )
                })
                .collect(),
        )
    })
}

fn fixture_request(
    step: &FixtureStep,
    observations: &BTreeMap<String, FixtureObservation>,
) -> Result<Request<Body>, ()> {
    let mut url = step.request.path.clone();
    if !step.request.query.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in &step.request.query {
            let value = query_value(value, observations).ok_or(())?;
            serializer.append_pair(name, &value);
        }
        url.push('?');
        url.push_str(&serializer.finish());
    }
    let method = match step.request.method {
        FixtureMethod::Get => "GET",
        FixtureMethod::Post => "POST",
    };
    let body = if step.request.body.is_empty() {
        Body::empty()
    } else {
        Body::from(serde_json::to_vec(&json!({"selectors": step.request.body})).map_err(|_| ())?)
    };
    let mut request = Request::builder()
        .method(method)
        .uri(url)
        .body(body)
        .map_err(|_| ())?;
    if !step.request.body.is_empty() {
        request
            .headers_mut()
            .insert(CONTENT_TYPE, "application/json".parse().map_err(|_| ())?);
    }
    if let Some(identifier) = step.authorization_fixture.as_deref() {
        request.headers_mut().insert(
            AUTHORIZATION,
            format!("Bearer {}", fixture_token(identifier))
                .parse()
                .map_err(|_| ())?,
        );
    }
    for (name, value) in &step.request.headers {
        if !matches!(name.as_str(), "accept" | "if-none-match") {
            return Err(());
        }
        let value = if let Some(reference) = value.strip_prefix("$etag:") {
            observations
                .get(reference)
                .ok_or(())?
                .etag
                .as_deref()
                .ok_or(())?
        } else {
            value
        };
        request.headers_mut().insert(
            http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?,
            http::header::HeaderValue::from_str(value).map_err(|_| ())?,
        );
    }
    Ok(request)
}

#[derive(Clone)]
struct FixtureObservation {
    document: Option<Value>,
    etag: Option<String>,
}

struct ObservedResponse<'a> {
    status: StatusCode,
    headers: &'a http::HeaderMap,
    body: &'a [u8],
    document: Option<&'a Value>,
    code: Option<&'a str>,
}

fn assert_expectations(
    step: &FixtureStep,
    response: &ObservedResponse<'_>,
    equivalence_classes: &mut BTreeMap<String, Value>,
    observations: &BTreeMap<String, FixtureObservation>,
    index: usize,
    diagnostics: &mut Vec<FixtureDiagnostic>,
) -> bool {
    let before = diagnostics.len();
    let location = format!("steps[{index}].expect");
    if response.status.as_u16() != step.expect.status {
        mismatch(diagnostics, "fixture.status_mismatch", &location, "status");
    }
    if step.expect.code.is_some() && step.expect.code.as_deref() != response.code {
        mismatch(
            diagnostics,
            "fixture.code_mismatch",
            &location,
            "problem code",
        );
    }
    if step.expect.route_absent == Some(true) && response.code != Some("resource.not_found") {
        mismatch(
            diagnostics,
            "fixture.route_mismatch",
            &location,
            "route posture",
        );
    }
    let records = response.document.map(response_records).unwrap_or_default();
    if let Some(expected) = step.expect.item_count {
        let actual = response
            .document
            .and_then(|value| value.get("items"))
            .and_then(Value::as_array)
            .map(Vec::len);
        if actual != usize::try_from(expected).ok() {
            mismatch(
                diagnostics,
                "fixture.item_count_mismatch",
                &location,
                "record count",
            );
        }
    }
    if let Some(expected) = step.expect.next_cursor.as_ref().and_then(Value::as_str) {
        let cursor = response
            .document
            .and_then(|value| value.pointer("/pageInfo/nextCursor"));
        let matches = match expected {
            "non-null" => cursor.is_some_and(|value| !value.is_null()),
            "null" => cursor.is_some_and(Value::is_null),
            _ => false,
        };
        if !matches {
            mismatch(
                diagnostics,
                "fixture.cursor_mismatch",
                &location,
                "cursor posture",
            );
        }
    }
    if step.expect.registry_core_required == Some(true)
        && (records.is_empty() || records.iter().any(|record| !has_registry_core(record)))
    {
        mismatch(
            diagnostics,
            "fixture.registry_core_mismatch",
            &location,
            "Registry Core context",
        );
    }
    if !step.expect.domain_data_keys.is_empty() {
        let expected = step
            .expect
            .domain_data_keys
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if records.is_empty()
            || records.iter().any(|record| {
                record
                    .get("domainData")
                    .and_then(Value::as_object)
                    .map(|object| object.keys().map(String::as_str).collect::<BTreeSet<_>>())
                    .as_ref()
                    != Some(&expected)
            })
        {
            mismatch(
                diagnostics,
                "fixture.disclosure_mismatch",
                &location,
                "governed property set",
            );
        }
    }
    if let Some(expected) = step.expect.record_identifier.as_deref() {
        let actual = response
            .document
            .and_then(|value| value.pointer("/data/recordIdentifier"))
            .and_then(Value::as_str);
        if actual != Some(expected) {
            mismatch(
                diagnostics,
                "fixture.record_mismatch",
                &location,
                "Record identity",
            );
        }
    }
    assert_capabilities(step, response.document, &location, diagnostics);
    if step.expect.cache.as_deref() == Some("public-snapshot-revalidation")
        && (response
            .headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            != Some("public, no-cache")
            || !response.headers.contains_key(ETAG)
            || response
                .headers
                .get(VARY)
                .and_then(|value| value.to_str().ok())
                != Some("Accept, Authorization"))
    {
        mismatch(
            diagnostics,
            "fixture.cache_mismatch",
            &location,
            "cache posture",
        );
    }
    if step
        .expect
        .absent_everywhere
        .iter()
        .any(|value| contains_bytes(response.body, value.as_bytes()))
    {
        diagnostic(
            diagnostics,
            "fixture.disclosure_leak",
            &location,
            "the fixture disclosed a prohibited value or source binding",
        );
    }
    if let Some(class) = step.expect.equivalence_class.as_ref() {
        let mut normalized = response.document.cloned().unwrap_or(Value::Null);
        if let Some(object) = normalized.as_object_mut() {
            object.remove("traceId");
        }
        if equivalence_classes
            .get(class)
            .is_some_and(|previous| previous != &normalized)
        {
            mismatch(
                diagnostics,
                "fixture.equivalence_mismatch",
                &location,
                "outcome equivalence class",
            );
        } else {
            equivalence_classes.insert(class.clone(), normalized);
        }
    }
    if let Some(reference) = step.expect.records_equivalent_to.as_ref() {
        let previous = observations
            .get(reference)
            .and_then(|observation| observation.document.as_ref())
            .map(normalized_records);
        let current = response.document.map(normalized_records);
        if previous.is_none() || current != previous {
            mismatch(
                diagnostics,
                "fixture.representation_mismatch",
                &location,
                "JSON and JSON-LD Record equivalence",
            );
        }
    }
    if step.expect.body_empty == Some(true) && !response.body.is_empty() {
        mismatch(
            diagnostics,
            "fixture.body_mismatch",
            &location,
            "empty response body",
        );
    }
    if let Some(reference) = step.expect.etag_same_as.as_ref() {
        let previous = observations
            .get(reference)
            .and_then(|observation| observation.etag.as_deref());
        let current = response
            .headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok());
        if previous.is_none() || current != previous {
            mismatch(
                diagnostics,
                "fixture.etag_mismatch",
                &location,
                "revalidation entity tag",
            );
        }
    }
    before == diagnostics.len()
}

fn assert_capabilities(
    step: &FixtureStep,
    document: Option<&Value>,
    location: &str,
    diagnostics: &mut Vec<FixtureDiagnostic>,
) {
    if step.expect.capability_patterns.is_empty()
        && step.expect.absent_capability_patterns.is_empty()
    {
        return;
    }
    let patterns = document
        .and_then(|value| value.get("capabilities"))
        .and_then(Value::as_array)
        .map(|capabilities| {
            capabilities
                .iter()
                .filter_map(|capability| {
                    Some(format!(
                        "{}.{}",
                        capability.get("family")?.as_str()?,
                        capability.get("pattern")?.as_str()?
                    ))
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    if step
        .expect
        .capability_patterns
        .iter()
        .any(|expected| !patterns.contains(expected))
        || step
            .expect
            .absent_capability_patterns
            .iter()
            .any(|absent| patterns.contains(absent))
    {
        mismatch(
            diagnostics,
            "fixture.capability_mismatch",
            location,
            "capability inventory",
        );
    }
}

fn validate_authorizations(journey: &FixtureJourney, diagnostics: &mut Vec<FixtureDiagnostic>) {
    for (index, fixture) in journey.authorizations.values().enumerate() {
        if fixture.principal.is_empty()
            || fixture.scopes.is_empty()
            || fixture.scopes.iter().any(String::is_empty)
            || fixture
                .claims
                .iter()
                .any(|(name, value)| name.is_empty() || value.is_empty())
        {
            diagnostic(
                diagnostics,
                "fixture.authorization_invalid",
                &format!("authorizations[{index}]"),
                "authorization fixtures require a principal, scopes, and direct string claims",
            );
        }
    }
}

fn resolve_operation<'a>(
    registry: &'a CompiledRegistry,
    request: &FixtureRequest,
) -> Option<&'a crate::model::CompiledOperation> {
    registry.resources.iter().find_map(|resource| {
        resource
            .operations
            .iter()
            .find(|operation| match &operation.kind {
                OperationKind::List => {
                    request.method == FixtureMethod::Get
                        && request.path == format!("/v2/resources/{}/records", resource.id)
                }
                OperationKind::Read => {
                    request.method == FixtureMethod::Get
                        && request
                            .path
                            .starts_with(&format!("/v2/resources/{}/records/", resource.id))
                }
                OperationKind::Lookup { name } => {
                    request.method == FixtureMethod::Post
                        && request.path == format!("/v2/resources/{}/lookups/{name}", resource.id)
                }
            })
    })
}

fn query_value(
    value: &Value,
    observations: &BTreeMap<String, FixtureObservation>,
) -> Option<String> {
    match value {
        Value::String(value) => value
            .strip_prefix("$nextCursor:")
            .map(|reference| {
                observations
                    .get(reference)?
                    .document
                    .as_ref()?
                    .pointer("/pageInfo/nextCursor")?
                    .as_str()
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| Some(value.clone())),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn normalized_records(document: &Value) -> Value {
    let mut records = response_records(document)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    for record in &mut records {
        if let Some(object) = record.as_object_mut() {
            object.remove("@context");
            object.remove("@id");
        }
    }
    Value::Array(records)
}

fn fixture_token(identifier: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({"fixture": identifier}))
            .expect("fixture token claims are canonical JSON"),
    );
    let signature = URL_SAFE_NO_PAD.encode(b"offline-fixture");
    format!("{header}.{claims}.{signature}")
}

fn response_records(document: &Value) -> Vec<&Value> {
    if let Some(record) = document.get("data") {
        vec![record]
    } else {
        document
            .get("items")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |items| items.iter().collect())
    }
}

fn has_registry_core(record: &Value) -> bool {
    [
        "registryIdentifier",
        "recordIdentifier",
        "revisionIdentifier",
        "lifecycleState",
        "schemaReference",
        "semanticModelReference",
        "authorityIdentifier",
        "recordedAt",
        "domainData",
    ]
    .iter()
    .all(|key| record.get(key).is_some())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn is_data_path(path: &str) -> bool {
    path.contains("/records") || path.contains("/lookups/")
}

fn mismatch(diagnostics: &mut Vec<FixtureDiagnostic>, code: &str, location: &str, subject: &str) {
    diagnostic(
        diagnostics,
        code,
        location,
        &format!("the fixture returned a different {subject}"),
    );
}

fn diagnostic(diagnostics: &mut Vec<FixtureDiagnostic>, code: &str, location: &str, message: &str) {
    diagnostics.push(FixtureDiagnostic {
        code: code.into(),
        location: location.into(),
        message: message.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_yaml_rejects_unknown_request_fields() {
        let yaml = r#"
schemaVersion: relay.registrystack.org/http-journey/v1alpha1
registry: urn:example:registry
authorizations: {}
steps:
  - id: one
    request: {method: GET, path: /health, sql: SELECT 1}
    expect: {status: 200}
"#;
        assert!(parse_journey(yaml).is_err());
    }

    #[test]
    fn fixture_tokens_have_a_bounded_jwt_shape_without_exposing_claims() {
        let token = fixture_token("fixture-a");
        assert_eq!(token.split('.').count(), 3);
        assert!(!token.contains("principal"));
    }
}
