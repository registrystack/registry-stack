// SPDX-License-Identifier: Apache-2.0
//! Strict, value-free offline acceptance journeys over the real Relay router.

use std::collections::{BTreeMap, BTreeSet};

use axum::body::{to_bytes, Body};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG, LINK, VARY};
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower::ServiceExt as _;

use crate::auth::{FixturePrincipal, RelayAuthenticator};
pub use crate::fixture_contract::{
    parse_journey, FixtureAuthorization, FixtureError, FixtureExpectation, FixtureFormatProfile,
    FixtureGeoJsonRoot, FixtureGeometryType, FixtureJourney, FixtureMethod, FixtureRequest,
    FixtureStep,
};
use crate::model::{CompiledAccess, CompiledRegistry, OperationKind};

const JOURNEY_VERSION: &str = "relay.registrystack.org/http-journey/v1alpha1";
const MAXIMUM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_DOMAIN_VALUE_EXPECTATIONS: usize = 64;
const MAXIMUM_DOMAIN_PROPERTY_NAME_BYTES: usize = 128;

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
    for (index, step) in journey.steps.iter().enumerate() {
        if !ids.insert(step.id.as_str()) {
            diagnostic(
                &mut diagnostics,
                "fixture.id_duplicate",
                &format!("steps[{index}].id"),
                "fixture step identifiers must be unique",
            );
        }
    }
    let dependencies = fixture_dependencies(journey, &mut diagnostics);
    let selected_steps = selected_step_closure(journey, &dependencies, selected_fixture);

    let mut steps = Vec::new();
    for (index, step) in journey.steps.iter().enumerate() {
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
        if !selected_steps.contains(&index) {
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
        validate_domain_data_expectations(
            &step.expect,
            &format!("steps[{index}].expect.domainDataValues"),
            &mut diagnostics,
        );
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
            let access_profile_identifier = step
                .request
                .query
                .get("accessProfile")
                .and_then(Value::as_str)
                .unwrap_or(&operation.default_access_profile);
            let protected = operation
                .access_profiles
                .iter()
                .find(|access_profile| access_profile.id == access_profile_identifier)
                .is_some_and(|access_profile| {
                    matches!(access_profile.access, CompiledAccess::Protected { .. })
                });
            if protected && step.expect.status == 200 && step.authorization_fixture.is_none() {
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

#[derive(Clone, Debug)]
struct FixtureDependency {
    target: String,
    location: String,
}

fn fixture_dependencies(
    journey: &FixtureJourney,
    diagnostics: &mut Vec<FixtureDiagnostic>,
) -> Vec<Vec<usize>> {
    let identifiers =
        journey
            .steps
            .iter()
            .enumerate()
            .fold(BTreeMap::new(), |mut identifiers, (index, step)| {
                identifiers.entry(step.id.as_str()).or_insert(index);
                identifiers
            });
    let mut equivalence_classes = BTreeMap::<&str, &str>::new();
    let references = journey
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let mut references = step_dependencies(step, index);
            if let Some(class) = step.expect.equivalence_class.as_deref() {
                if let Some(target) = equivalence_classes.get(class) {
                    references.push(FixtureDependency {
                        target: (*target).into(),
                        location: format!("steps[{index}].expect.equivalenceClass"),
                    });
                } else {
                    equivalence_classes.insert(class, step.id.as_str());
                }
            }
            references
        })
        .collect::<Vec<_>>();
    let mut dependencies = vec![Vec::new(); journey.steps.len()];

    for (index, step_references) in references.iter().enumerate() {
        for reference in step_references {
            let Some(target) = identifiers.get(reference.target.as_str()).copied() else {
                diagnostic(
                    diagnostics,
                    "fixture.dependency_unknown",
                    &reference.location,
                    "the fixture step dependency is unknown",
                );
                continue;
            };
            if !dependencies[index].contains(&target) {
                dependencies[index].push(target);
            }
        }
    }

    for (index, step_references) in references.iter().enumerate() {
        for reference in step_references {
            let Some(target) = identifiers.get(reference.target.as_str()).copied() else {
                continue;
            };
            if dependency_reaches(&dependencies, target, index) {
                diagnostic(
                    diagnostics,
                    "fixture.dependency_cycle",
                    &reference.location,
                    "fixture step dependencies must be acyclic",
                );
            } else if target > index {
                diagnostic(
                    diagnostics,
                    "fixture.dependency_forward",
                    &reference.location,
                    "fixture steps may depend only on preceding steps",
                );
            }
        }
    }
    dependencies
}

fn step_dependencies(step: &FixtureStep, index: usize) -> Vec<FixtureDependency> {
    let mut dependencies = Vec::new();
    for (name, value) in &step.request.query {
        if let Some(target) = value
            .as_str()
            .and_then(|value| value.strip_prefix("$nextCursor:"))
        {
            dependencies.push(FixtureDependency {
                target: target.into(),
                location: format!("steps[{index}].request.query.{name}"),
            });
        }
    }
    for (name, value) in &step.request.headers {
        if let Some(target) = value.strip_prefix("$etag:") {
            dependencies.push(FixtureDependency {
                target: target.into(),
                location: format!("steps[{index}].request.headers.{name}"),
            });
        }
    }
    if let Some(target) = step.expect.records_equivalent_to.as_ref() {
        dependencies.push(FixtureDependency {
            target: target.clone(),
            location: format!("steps[{index}].expect.recordsEquivalentTo"),
        });
    }
    if let Some(target) = step.expect.etag_same_as.as_ref() {
        dependencies.push(FixtureDependency {
            target: target.clone(),
            location: format!("steps[{index}].expect.etagSameAs"),
        });
    }
    dependencies
}

fn dependency_reaches(dependencies: &[Vec<usize>], start: usize, target: usize) -> bool {
    let mut pending = vec![start];
    let mut visited = BTreeSet::new();
    while let Some(index) = pending.pop() {
        if index == target {
            return true;
        }
        if visited.insert(index) {
            pending.extend(dependencies[index].iter().copied());
        }
    }
    false
}

fn selected_step_closure(
    journey: &FixtureJourney,
    dependencies: &[Vec<usize>],
    selected_fixture: Option<&str>,
) -> BTreeSet<usize> {
    let Some(selected_fixture) = selected_fixture else {
        return (0..journey.steps.len()).collect();
    };
    let Some(selected) = journey
        .steps
        .iter()
        .position(|step| step.id == selected_fixture)
    else {
        return BTreeSet::new();
    };
    let mut selected_steps = BTreeSet::new();
    let mut pending = vec![selected];
    while let Some(index) = pending.pop() {
        if selected_steps.insert(index) {
            pending.extend(dependencies[index].iter().copied());
        }
    }
    selected_steps
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
        let actual = response.document.and_then(response_item_count);
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
    if !step.expect.domain_data_values.is_empty()
        && (records.is_empty()
            || records.iter().any(|record| {
                step.expect
                    .domain_data_values
                    .iter()
                    .any(|(property, expected)| {
                        record
                            .get("domainData")
                            .and_then(Value::as_object)
                            .and_then(|domain| domain.get(property))
                            != Some(expected)
                    })
            }))
    {
        mismatch(
            diagnostics,
            "fixture.domain_value_mismatch",
            &location,
            "governed domain value",
        );
    }
    if let Some(expected) = step.expect.record_identifier.as_deref() {
        let actual = records
            .first()
            .and_then(|record| record.get("recordIdentifier"))
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
    assert_geojson_expectations(step, response, &location, diagnostics);
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
                "fixture.format_mismatch",
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

fn assert_geojson_expectations(
    step: &FixtureStep,
    response: &ObservedResponse<'_>,
    location: &str,
    diagnostics: &mut Vec<FixtureDiagnostic>,
) {
    let Some(document) = response.document else {
        if step.expect.geo_json_root.is_some()
            || step.expect.geometry_type.is_some()
            || step.expect.format_profile.is_some()
        {
            mismatch(
                diagnostics,
                "fixture.geojson_mismatch",
                location,
                "GeoJSON response",
            );
        }
        return;
    };
    if let Some(expected) = step.expect.geo_json_root {
        let expected = match expected {
            FixtureGeoJsonRoot::Feature => "Feature",
            FixtureGeoJsonRoot::FeatureCollection => "FeatureCollection",
        };
        if document.get("type").and_then(Value::as_str) != Some(expected) {
            mismatch(
                diagnostics,
                "fixture.geojson_root_mismatch",
                location,
                "GeoJSON root",
            );
        }
    }
    if let Some(expected) = step.expect.geometry_type {
        let features = response_features(document);
        let mismatch_found = features.is_empty()
            || features.iter().any(|feature| match expected {
                FixtureGeometryType::Point => {
                    feature
                        .get("geometry")
                        .and_then(|geometry| geometry.get("type"))
                        .and_then(Value::as_str)
                        != Some("Point")
                }
                FixtureGeometryType::Null => !feature.get("geometry").is_some_and(Value::is_null),
            });
        if mismatch_found {
            mismatch(
                diagnostics,
                "fixture.geometry_mismatch",
                location,
                "GeoJSON geometry type",
            );
        }
    }
    let Some(profile) = step.expect.format_profile else {
        return;
    };
    if response
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/geo+json")
    {
        mismatch(
            diagnostics,
            "fixture.format_profile_mismatch",
            location,
            "GeoJSON content type",
        );
    }
    let (profile_uri, conformance) = match profile {
        FixtureFormatProfile::Rfc7946 => ("http://www.opengis.net/def/profile/OGC/0/rfc7946", None),
        FixtureFormatProfile::JsonFg => (
            "http://www.opengis.net/def/profile/OGC/0/jsonfg",
            Some([
                "http://www.opengis.net/spec/json-fg-1/1.0/conf/core",
                "http://www.opengis.net/spec/json-fg-1/1.0/conf/types-schemas",
            ]),
        ),
    };
    let expected_link = format!("<{profile_uri}>; rel=\"profile\"");
    if response
        .headers
        .get(LINK)
        .and_then(|value| value.to_str().ok())
        != Some(expected_link.as_str())
    {
        mismatch(
            diagnostics,
            "fixture.format_profile_mismatch",
            location,
            "GeoJSON profile link",
        );
    }
    if let Some(expected) = conformance {
        let actual = document
            .get("conformsTo")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
            });
        if actual != Some(expected.into_iter().collect()) {
            mismatch(
                diagnostics,
                "fixture.format_profile_mismatch",
                location,
                "JSON-FG conformance",
            );
        }
    } else if document.get("conformsTo").is_some() || document.get("featureType").is_some() {
        mismatch(
            diagnostics,
            "fixture.format_profile_mismatch",
            location,
            "RFC 7946 profile members",
        );
    }
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
                OperationKind::Search { name } => {
                    request.method == FixtureMethod::Get
                        && request.path == format!("/v2/resources/{}/searches/{name}", resource.id)
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
    let geometries = response_geometries(document);
    let mut records = response_records(document)
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let mut record = record.clone();
            let mut geometry = geometries
                .get(index)
                .and_then(|geometry| *geometry)
                .cloned()
                .unwrap_or(Value::Null);
            if geometry.is_null() {
                if let Some(domain) = record.get_mut("domainData").and_then(Value::as_object_mut) {
                    let geometry_name = domain.iter().find_map(|(name, value)| {
                        (value.get("type").and_then(Value::as_str) == Some("Point")
                            && value.get("coordinates").is_some())
                        .then(|| name.clone())
                    });
                    if let Some(name) = geometry_name {
                        geometry = domain.remove(&name).unwrap_or(Value::Null);
                    }
                }
            }
            json!({"record": record, "geometry": geometry})
        })
        .collect::<Vec<_>>();
    for normalized in &mut records {
        let Some(record) = normalized.get_mut("record") else {
            continue;
        };
        if let Some(object) = record.as_object_mut() {
            object.remove("@context");
            object.remove("@id");
            object.remove("@type");
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
    if document.get("type").and_then(Value::as_str) == Some("Feature") {
        document
            .get("properties")
            .map_or_else(Vec::new, |record| vec![record])
    } else if document.get("type").and_then(Value::as_str) == Some("FeatureCollection") {
        document
            .get("features")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |features| {
                features
                    .iter()
                    .filter_map(|feature| feature.get("properties"))
                    .collect()
            })
    } else if let Some(record) = document.get("data") {
        vec![record]
    } else {
        document
            .get("items")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |items| items.iter().collect())
    }
}

fn response_item_count(document: &Value) -> Option<usize> {
    document
        .get("items")
        .or_else(|| document.get("features"))
        .and_then(Value::as_array)
        .map(Vec::len)
}

fn response_geometries(document: &Value) -> Vec<Option<&Value>> {
    if document.get("type").and_then(Value::as_str) == Some("Feature") {
        vec![document
            .get("geometry")
            .filter(|geometry| !geometry.is_null())]
    } else if document.get("type").and_then(Value::as_str) == Some("FeatureCollection") {
        document
            .get("features")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |features| {
                features
                    .iter()
                    .map(|feature| {
                        feature
                            .get("geometry")
                            .filter(|geometry| !geometry.is_null())
                    })
                    .collect()
            })
    } else {
        Vec::new()
    }
}

fn response_features(document: &Value) -> Vec<&Value> {
    if document.get("type").and_then(Value::as_str) == Some("Feature") {
        vec![document]
    } else if document.get("type").and_then(Value::as_str) == Some("FeatureCollection") {
        document
            .get("features")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |features| features.iter().collect())
    } else {
        Vec::new()
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

fn validate_domain_data_expectations(
    expectation: &FixtureExpectation,
    location: &str,
    diagnostics: &mut Vec<FixtureDiagnostic>,
) {
    if expectation.domain_data_values.len() > MAXIMUM_DOMAIN_VALUE_EXPECTATIONS {
        diagnostic(
            diagnostics,
            "fixture.domain_values_invalid",
            location,
            "exact domain-value expectations exceed the fixture bound",
        );
    }
    for (property, expected) in &expectation.domain_data_values {
        if property.len() > MAXIMUM_DOMAIN_PROPERTY_NAME_BYTES {
            diagnostic(
                diagnostics,
                "fixture.domain_values_invalid",
                location,
                "an exact domain-value expectation name exceeds the fixture bound",
            );
        }
        if !matches!(
            expected,
            Value::Bool(_) | Value::Number(_) | Value::String(_)
        ) {
            diagnostic(
                diagnostics,
                "fixture.domain_values_invalid",
                location,
                "exact domain-value expectations must be non-null JSON scalars",
            );
        }
        if !expectation.domain_data_keys.contains(property) {
            diagnostic(
                diagnostics,
                "fixture.domain_values_invalid",
                location,
                "every exact domain-value expectation must be closed by domainDataKeys",
            );
        }
    }
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
    fn fixture_yaml_accepts_closed_scalar_domain_value_expectations() {
        let yaml = r#"
schemaVersion: relay.registrystack.org/http-journey/v1alpha1
registry: urn:example:registry
authorizations: {}
steps:
  - id: one
    request: {method: GET, path: /health}
    expect:
      status: 200
      domainDataKeys: [maskedReference, registrationYear]
      domainDataValues: {maskedReference: "***0001", registrationYear: "2026"}
"#;
        let journey = parse_journey(yaml).expect("fixture parses");
        assert_eq!(
            journey.steps[0].expect.domain_data_values,
            BTreeMap::from([
                ("maskedReference".into(), Value::String("***0001".into())),
                ("registrationYear".into(), Value::String("2026".into())),
            ])
        );
    }

    #[test]
    fn domain_value_expectations_are_bounded_scalar_and_closed() {
        let mut expectation = FixtureExpectation {
            status: 200,
            domain_data_keys: vec!["allowed".into()],
            domain_data_values: BTreeMap::from([
                ("notClosed".into(), Value::String("safe".into())),
                ("overlong".repeat(17), Value::String("safe".into())),
                ("structured".into(), json!(["not", "scalar"])),
            ]),
            ..FixtureExpectation::default()
        };
        for index in 0..=MAXIMUM_DOMAIN_VALUE_EXPECTATIONS {
            expectation
                .domain_data_values
                .insert(format!("extra{index}"), Value::Bool(true));
        }
        let mut diagnostics = Vec::new();
        validate_domain_data_expectations(&expectation, "expect", &mut diagnostics);
        assert!(diagnostics.len() >= 4);
        assert!(diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code == "fixture.domain_values_invalid"));
        let rendered = serde_json::to_string(&diagnostics).expect("diagnostics serialize");
        assert!(!rendered.contains("safe"));
        assert!(!rendered.contains("not scalar"));
    }

    #[test]
    fn exact_domain_value_assertion_is_value_free_on_mismatch() {
        let yaml = r#"
schemaVersion: relay.registrystack.org/http-journey/v1alpha1
registry: urn:example:registry
authorizations: {}
steps:
  - id: one
    request: {method: GET, path: /health}
    expect:
      status: 200
      domainDataKeys: [maskedReference]
      domainDataValues: {maskedReference: "***0001"}
"#;
        let journey = parse_journey(yaml).expect("fixture parses");
        let step = &journey.steps[0];
        let headers = http::HeaderMap::new();
        let mut equivalence_classes = BTreeMap::new();
        let observations = BTreeMap::new();
        let matching = json!({"data": {"domainData": {"maskedReference": "***0001"}}});
        let mut diagnostics = Vec::new();
        assert!(assert_expectations(
            step,
            &ObservedResponse {
                status: StatusCode::OK,
                headers: &headers,
                body: b"",
                document: Some(&matching),
                code: None,
            },
            &mut equivalence_classes,
            &observations,
            0,
            &mut diagnostics,
        ));

        let mismatching = json!({"data": {"domainData": {"maskedReference": "SOURCE-SECRET"}}});
        assert!(!assert_expectations(
            step,
            &ObservedResponse {
                status: StatusCode::OK,
                headers: &headers,
                body: b"",
                document: Some(&mismatching),
                code: None,
            },
            &mut equivalence_classes,
            &observations,
            0,
            &mut diagnostics,
        ));
        let rendered = serde_json::to_string(&diagnostics).expect("diagnostics serialize");
        assert!(!rendered.contains("SOURCE-SECRET"));
        assert!(!rendered.contains("***0001"));
        assert!(diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "fixture.domain_value_mismatch"));
    }

    #[test]
    fn fixture_tokens_have_a_bounded_jwt_shape_without_exposing_claims() {
        let token = fixture_token("fixture-a");
        assert_eq!(token.split('.').count(), 3);
        assert!(!token.contains("principal"));
    }

    #[test]
    fn selected_step_closure_includes_every_transitive_reference_and_nothing_else() {
        let journey = parse_journey(
            r#"
schemaVersion: relay.registrystack.org/http-journey/v1alpha1
registry: urn:example:registry
authorizations: {}
steps:
  - id: cursor-source
    request: {method: GET, path: /health}
    expect: {status: 200}
  - id: cursor-consumer
    request:
      method: GET
      path: /health
      query: {cursor: "$nextCursor:cursor-source"}
    expect: {status: 200}
  - id: etag-consumer
    request:
      method: GET
      path: /health
      headers: {if-none-match: "$etag:cursor-consumer"}
    expect: {status: 200}
  - id: format-consumer
    request: {method: GET, path: /health}
    expect:
      status: 200
      recordsEquivalentTo: etag-consumer
      etagSameAs: etag-consumer
      equivalenceClass: selected-equivalence
  - id: selected
    request: {method: GET, path: /health}
    expect: {status: 200, equivalenceClass: selected-equivalence}
  - id: unrelated
    request: {method: GET, path: /health}
    expect: {status: 200}
"#,
        )
        .expect("fixture parses");
        let mut diagnostics = Vec::new();
        let dependencies = fixture_dependencies(&journey, &mut diagnostics);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(
            selected_step_closure(&journey, &dependencies, Some("selected")),
            BTreeSet::from([0, 1, 2, 3, 4])
        );
    }

    #[test]
    fn unknown_forward_and_cyclic_step_dependencies_are_distinct_refusals() {
        for (steps, expected) in [
            (
                r#"
  - id: one
    request: {method: GET, path: /health}
    expect: {status: 200, recordsEquivalentTo: missing}
"#,
                "fixture.dependency_unknown",
            ),
            (
                r#"
  - id: one
    request: {method: GET, path: /health}
    expect: {status: 200, recordsEquivalentTo: two}
  - id: two
    request: {method: GET, path: /health}
    expect: {status: 200}
"#,
                "fixture.dependency_forward",
            ),
            (
                r#"
  - id: one
    request: {method: GET, path: /health}
    expect: {status: 200, recordsEquivalentTo: two}
  - id: two
    request: {method: GET, path: /health}
    expect: {status: 200, recordsEquivalentTo: one}
"#,
                "fixture.dependency_cycle",
            ),
        ] {
            let journey = parse_journey(&format!(
                "schemaVersion: {JOURNEY_VERSION}\nregistry: urn:example:registry\nauthorizations: {{}}\nsteps:{steps}"
            ))
            .expect("fixture parses");
            let mut diagnostics = Vec::new();
            fixture_dependencies(&journey, &mut diagnostics);
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected),
                "{diagnostics:?}"
            );
        }
    }

    #[test]
    fn fixture_yaml_accepts_only_the_closed_geojson_expectations() {
        let yaml = r#"
schemaVersion: relay.registrystack.org/http-journey/v1alpha1
registry: urn:example:registry
authorizations: {}
steps:
  - id: feature
    request: {method: GET, path: /v2/resources/places/records/one}
    expect:
      status: 200
      geoJsonRoot: feature
      geometryType: Point
      formatProfile: jsonfg
"#;
        let journey = parse_journey(yaml).expect("closed GeoJSON expectations parse");
        assert_eq!(
            journey.steps[0].expect.geo_json_root,
            Some(FixtureGeoJsonRoot::Feature)
        );
        assert_eq!(
            journey.steps[0].expect.geometry_type,
            Some(FixtureGeometryType::Point)
        );
        assert_eq!(
            journey.steps[0].expect.format_profile,
            Some(FixtureFormatProfile::JsonFg)
        );

        assert!(parse_journey(&yaml.replace("jsonfg", "draft-profile")).is_err());
    }

    #[test]
    fn rfc7946_fixture_requires_explicit_null_geometry_and_no_json_fg_members() {
        let journey = parse_journey(
            r#"
schemaVersion: relay.registrystack.org/http-journey/v1alpha1
registry: urn:example:registry
authorizations: {}
steps:
  - id: feature
    request: {method: GET, path: /v2/resources/places/records/one}
    expect:
      status: 200
      geoJsonRoot: feature
      geometryType: "null"
      formatProfile: rfc7946
"#,
        )
        .expect("fixture parses");
        let step = &journey.steps[0];
        let mut headers = http::HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            "application/geo+json".parse().expect("header"),
        );
        headers.insert(
            LINK,
            "<http://www.opengis.net/def/profile/OGC/0/rfc7946>; rel=\"profile\""
                .parse()
                .expect("header"),
        );

        for document in [
            json!({"type": "Feature", "properties": {}}),
            json!({
                "type": "Feature",
                "geometry": null,
                "properties": {},
                "featureType": "places",
            }),
        ] {
            let bytes = serde_json::to_vec(&document).expect("document serializes");
            let mut diagnostics = Vec::new();
            assert!(!assert_expectations(
                step,
                &ObservedResponse {
                    status: StatusCode::OK,
                    headers: &headers,
                    body: &bytes,
                    document: Some(&document),
                    code: None,
                },
                &mut BTreeMap::new(),
                &BTreeMap::new(),
                0,
                &mut diagnostics,
            ));
            assert!(!diagnostics.is_empty());
        }

        let document = json!({"type": "Feature", "geometry": null, "properties": {}});
        let bytes = serde_json::to_vec(&document).expect("document serializes");
        assert!(assert_expectations(
            step,
            &ObservedResponse {
                status: StatusCode::OK,
                headers: &headers,
                body: &bytes,
                document: Some(&document),
                code: None,
            },
            &mut BTreeMap::new(),
            &BTreeMap::new(),
            0,
            &mut Vec::new(),
        ));
    }
}
