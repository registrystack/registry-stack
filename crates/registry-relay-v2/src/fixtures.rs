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
    FixtureGeoJsonRoot, FixtureGeometryType, FixtureJourney, FixtureJsonScalarType, FixtureMethod,
    FixtureRequest, FixtureSdmxJsonTypes, FixtureStep,
};
use crate::format_capabilities::{CRS84_URI, JSON_FG_PROFILE_URI, RFC7946_PROFILE_URI};
use crate::model::{
    CompiledAccess, CompiledOperation, CompiledRegistry, CompiledStatisticalDataset, OperationKind,
};

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
            let protected = operation.protected(&step.request);
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
            operation_identifier: operation.map(ResolvedOperation::identifier),
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
        let equivalent_records = normalized_response_records(&headers, document.as_ref(), &body);
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
                equivalent_records: equivalent_records.as_ref(),
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
                equivalent_records,
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
    equivalent_records: Option<Value>,
}

struct ObservedResponse<'a> {
    status: StatusCode,
    headers: &'a http::HeaderMap,
    body: &'a [u8],
    document: Option<&'a Value>,
    code: Option<&'a str>,
    equivalent_records: Option<&'a Value>,
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
    if let Some(expected) = step.expect.media_type.as_deref() {
        let actual = response
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        if actual != Some(expected) {
            mismatch(
                diagnostics,
                "fixture.media_type_mismatch",
                &location,
                "media type",
            );
        }
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
            .and_then(|value| value.get("items").or_else(|| value.get("features")))
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
    if let Some(expected) = step.expect.observation_count {
        let actual = sdmx_observation_count(response.headers, response.document, response.body);
        if actual != usize::try_from(expected).ok() {
            mismatch(
                diagnostics,
                "fixture.observation_count_mismatch",
                &location,
                "observation count",
            );
        }
    }
    if let Some(expected) = step.expect.sdmx_json_types.as_ref() {
        if response
            .document
            .and_then(sdmx_json_rows)
            .is_none_or(|rows| !sdmx_rows_match_types(&rows, expected))
        {
            mismatch(
                diagnostics,
                "fixture.sdmx_type_mismatch",
                &location,
                "SDMX JSON scalar types",
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
    if step.expect.registry_core_required == Some(true) {
        let registry_record_envelope = response
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.starts_with("application/json") || value.starts_with("application/ld+json")
            });
        let record_context_matches = if registry_record_envelope {
            response.document.is_some_and(has_registry_record_context)
                && records.iter().all(|record| {
                    has_record_core(record)
                        && [
                            "registryIdentifier",
                            "datasetIdentifier",
                            "entityTypeIdentifier",
                        ]
                        .iter()
                        .all(|key| record.get(key).is_none())
                })
        } else {
            records.iter().all(|record| has_registry_core(record))
        };
        if records.is_empty() || !record_context_matches {
            mismatch(
                diagnostics,
                "fixture.registry_core_mismatch",
                &location,
                "Registry Core context",
            );
        }
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
        let actual = response.document.map(response_records).and_then(|records| {
            records
                .first()
                .and_then(|record| record.get("recordIdentifier"))
                .and_then(Value::as_str)
        });
        if actual != Some(expected) {
            mismatch(
                diagnostics,
                "fixture.record_mismatch",
                &location,
                "Record identity",
            );
        }
    }
    assert_spatial_expectations(step, response, &location, diagnostics);
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
    if step.expect.cache.as_deref() == Some("no-store")
        && (response
            .headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            != Some("no-store")
            || response.headers.contains_key(ETAG))
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
            .and_then(|observation| observation.equivalent_records.as_ref());
        let current = response.equivalent_records;
        if previous.is_none() || current != previous {
            mismatch(
                diagnostics,
                "fixture.representation_mismatch",
                &location,
                "cross-format record equivalence",
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

fn assert_spatial_expectations(
    step: &FixtureStep,
    response: &ObservedResponse<'_>,
    location: &str,
    diagnostics: &mut Vec<FixtureDiagnostic>,
) {
    if let Some(expected) = step.expect.geo_json_root {
        let expected = match expected {
            FixtureGeoJsonRoot::Feature => "Feature",
            FixtureGeoJsonRoot::FeatureCollection => "FeatureCollection",
        };
        let actual = response
            .document
            .and_then(|document| document.get("type"))
            .and_then(Value::as_str);
        if actual != Some(expected) {
            mismatch(
                diagnostics,
                "fixture.geojson_root_mismatch",
                location,
                "GeoJSON root",
            );
        }
    }

    if let Some(expected) = step.expect.geometry_type {
        let features = response.document.map(geojson_features).unwrap_or_default();
        let matches = !features.is_empty()
            && features.iter().all(|feature| {
                let Some(geometry) = feature.get("geometry") else {
                    return false;
                };
                match expected {
                    FixtureGeometryType::Point => {
                        geometry.get("type").and_then(Value::as_str) == Some("Point")
                            && geometry
                                .get("coordinates")
                                .and_then(Value::as_array)
                                .is_some_and(|coordinates| coordinates.len() == 2)
                    }
                    FixtureGeometryType::Null => geometry.is_null(),
                }
            });
        if !matches {
            mismatch(
                diagnostics,
                "fixture.geometry_mismatch",
                location,
                "geometry type",
            );
        }
    }

    if let Some(expected) = step.expect.format_profile {
        let (profile_uri, json_fg) = match expected {
            FixtureFormatProfile::Rfc7946 => (RFC7946_PROFILE_URI, false),
            FixtureFormatProfile::Jsonfg => (JSON_FG_PROFILE_URI, true),
        };
        let expected_link = format!("<{profile_uri}>; rel=\"profile\"");
        let media_and_link_match = response
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            == Some("application/geo+json")
            && response
                .headers
                .get(LINK)
                .and_then(|value| value.to_str().ok())
                == Some(expected_link.as_str());
        let document_matches = response.document.is_some_and(|document| {
            let members_match = ["conformsTo", "featureType", "coordRefSys"]
                .into_iter()
                .all(|member| document.get(member).is_some() == json_fg);
            if !members_match {
                return false;
            }
            if !json_fg {
                return true;
            }
            document.get("coordRefSys").and_then(Value::as_str) == Some(CRS84_URI)
                && (document.get("type").and_then(Value::as_str) != Some("FeatureCollection")
                    || geojson_features(document).iter().all(|feature| {
                        ["conformsTo", "featureType", "coordRefSys"]
                            .into_iter()
                            .all(|member| feature.get(member).is_none())
                    }))
        });
        if !media_and_link_match || !document_matches {
            mismatch(
                diagnostics,
                "fixture.format_profile_mismatch",
                location,
                "spatial format profile",
            );
        }
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

#[derive(Clone, Copy)]
enum ResolvedOperation<'a> {
    Record(&'a CompiledOperation),
    Statistical(&'a CompiledStatisticalDataset),
}

impl ResolvedOperation<'_> {
    fn identifier(self) -> String {
        match self {
            Self::Record(operation) => operation.identifier.clone(),
            Self::Statistical(dataset) => dataset.operation_identifier(),
        }
    }

    fn protected(self, request: &FixtureRequest) -> bool {
        let access = match self {
            Self::Record(operation) => {
                let identifier = request
                    .query
                    .get("accessProfile")
                    .and_then(Value::as_str)
                    .unwrap_or(&operation.default_access_profile);
                operation
                    .access_profiles
                    .iter()
                    .find(|profile| profile.id == identifier)
                    .map(|profile| &profile.access)
            }
            Self::Statistical(dataset) => Some(&dataset.access),
        };
        access.is_some_and(|access| matches!(access, CompiledAccess::Protected { .. }))
    }
}

fn resolve_operation<'a>(
    registry: &'a CompiledRegistry,
    request: &FixtureRequest,
) -> Option<ResolvedOperation<'a>> {
    let record = registry.resources.iter().find_map(|resource| {
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
    });
    if let Some(operation) = record {
        return Some(ResolvedOperation::Record(operation));
    }
    if request.method != FixtureMethod::Get {
        return None;
    }
    registry
        .statistical_datasets
        .iter()
        .find(|dataset| statistical_path_matches(dataset, &request.path))
        .map(ResolvedOperation::Statistical)
}

fn statistical_path_matches(dataset: &CompiledStatisticalDataset, path: &str) -> bool {
    let data = format!(
        "/sdmx/v2/data/dataflow/{}/{}/{}",
        dataset.sdmx.agency_id, dataset.sdmx.dataflow_id, dataset.sdmx.version
    );
    if path == data
        || path.strip_prefix(&data).is_some_and(|suffix| {
            suffix.starts_with('/') && suffix.len() > 1 && !suffix[1..].contains('/')
        })
    {
        return true;
    }
    path == format!(
        "/sdmx/v2/structure/dataflow/{}/{}/{}",
        dataset.sdmx.agency_id, dataset.sdmx.dataflow_id, dataset.sdmx.version
    ) || path
        == format!(
            "/sdmx/v2/structure/datastructure/{}/{}/{}",
            dataset.sdmx.agency_id, dataset.sdmx.data_structure_id, dataset.sdmx.version
        )
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

fn normalized_response_records(
    headers: &http::HeaderMap,
    document: Option<&Value>,
    body: &[u8],
) -> Option<Value> {
    let media_type = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    let rows = if media_type.starts_with("application/vnd.sdmx.data+json") {
        sdmx_json_rows(document?)?
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|(name, value)| (name, stable_fixture_scalar(&value)))
                    .collect::<BTreeMap<_, _>>()
            })
            .collect::<Vec<_>>()
    } else if media_type.starts_with("application/vnd.sdmx.data+csv") {
        sdmx_csv_rows(body)?
    } else {
        return document.map(normalized_records);
    };
    let mut documents = rows
        .into_iter()
        .map(|row| serde_json::to_value(row).ok())
        .collect::<Option<Vec<_>>>()?;
    documents.sort_by_key(|row| serde_json::to_string(row).unwrap_or_default());
    Some(Value::Array(documents))
}

fn stable_fixture_scalar(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(_) | Value::Object(_) => String::new(),
    }
}

fn sdmx_csv_rows(body: &[u8]) -> Option<Vec<BTreeMap<String, String>>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(body);
    let headers = reader.headers().ok()?.clone();
    if headers.len() < 4
        || headers.get(0) != Some("STRUCTURE")
        || headers.get(1) != Some("STRUCTURE_ID")
        || headers.get(2) != Some("ACTION")
    {
        return None;
    }
    reader
        .records()
        .map(|record| {
            let record = record.ok()?;
            (3..headers.len())
                .map(|index| {
                    Some((
                        headers.get(index)?.to_owned(),
                        record.get(index)?.to_owned(),
                    ))
                })
                .collect::<Option<BTreeMap<_, _>>>()
        })
        .collect()
}

fn sdmx_observation_count(
    headers: &http::HeaderMap,
    document: Option<&Value>,
    body: &[u8],
) -> Option<usize> {
    let media_type = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    if media_type.starts_with("application/vnd.sdmx.data+json") {
        sdmx_json_rows(document?).map(|rows| rows.len())
    } else if media_type.starts_with("application/vnd.sdmx.data+csv") {
        sdmx_csv_rows(body).map(|rows| rows.len())
    } else {
        None
    }
}

#[derive(Clone)]
struct SdmxComponentDecoder {
    id: String,
    values: Vec<Value>,
}

fn sdmx_json_rows(document: &Value) -> Option<Vec<BTreeMap<String, Value>>> {
    let structure = document.pointer("/data/structures/0")?;
    let series_dimensions = sdmx_component_decoders(
        structure
            .pointer("/dimensions/series")
            .and_then(Value::as_array),
    )?;
    let observation_dimensions = sdmx_component_decoders(
        structure
            .pointer("/dimensions/observation")
            .and_then(Value::as_array),
    )?;
    let measures = structure
        .pointer("/measures/observation")
        .and_then(Value::as_array)?
        .iter()
        .map(|item| item.get("id")?.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    let attributes = sdmx_component_decoders(
        structure
            .pointer("/attributes/observation")
            .and_then(Value::as_array),
    )?;
    let data_set = document.pointer("/data/dataSets/0")?;
    let mut rows = Vec::new();

    if let Some(observations) = data_set.get("observations").and_then(Value::as_object) {
        for (key, values) in observations {
            let mut row = sdmx_decode_key(key, &observation_dimensions)?;
            sdmx_decode_values(&mut row, values, &measures, &attributes)?;
            rows.push(row);
        }
    } else {
        let series = data_set.get("series").and_then(Value::as_object)?;
        for (series_key, series_document) in series {
            let series_values = sdmx_decode_key(series_key, &series_dimensions)?;
            let observations = series_document.get("observations")?.as_object()?;
            for (observation_key, values) in observations {
                let mut row = series_values.clone();
                for (name, value) in sdmx_decode_key(observation_key, &observation_dimensions)? {
                    if row.insert(name, value).is_some() {
                        return None;
                    }
                }
                sdmx_decode_values(&mut row, values, &measures, &attributes)?;
                rows.push(row);
            }
        }
    }
    Some(rows)
}

fn sdmx_component_decoders(components: Option<&Vec<Value>>) -> Option<Vec<SdmxComponentDecoder>> {
    let Some(components) = components else {
        return Some(Vec::new());
    };
    components
        .iter()
        .map(|component| {
            let values = match component.get("values") {
                Some(values) => values
                    .as_array()?
                    .iter()
                    .map(|value| value.get("id").or_else(|| value.get("value")).cloned())
                    .collect::<Option<Vec<_>>>()?,
                None => Vec::new(),
            };
            Some(SdmxComponentDecoder {
                id: component.get("id")?.as_str()?.to_owned(),
                values,
            })
        })
        .collect()
}

fn sdmx_decode_key(
    key: &str,
    components: &[SdmxComponentDecoder],
) -> Option<BTreeMap<String, Value>> {
    let indexes = if components.is_empty() && key.is_empty() {
        Vec::new()
    } else {
        key.split(':')
            .map(str::parse::<usize>)
            .collect::<Result<Vec<_>, _>>()
            .ok()?
    };
    if indexes.len() != components.len() {
        return None;
    }
    components
        .iter()
        .zip(indexes)
        .map(|(component, index)| {
            Some((component.id.clone(), component.values.get(index)?.clone()))
        })
        .collect()
}

fn sdmx_decode_values(
    row: &mut BTreeMap<String, Value>,
    values: &Value,
    measures: &[String],
    attributes: &[SdmxComponentDecoder],
) -> Option<()> {
    let values = values.as_array()?;
    if values.len() != measures.len() + attributes.len() {
        return None;
    }
    for (index, measure) in measures.iter().enumerate() {
        if row.insert(measure.clone(), values[index].clone()).is_some() {
            return None;
        }
    }
    for (offset, attribute) in attributes.iter().enumerate() {
        let value = &values[measures.len() + offset];
        let decoded = if attribute.values.is_empty() || value.is_null() {
            value.clone()
        } else {
            attribute
                .values
                .get(usize::try_from(value.as_u64()?).ok()?)?
                .clone()
        };
        if row.insert(attribute.id.clone(), decoded).is_some() {
            return None;
        }
    }
    Some(())
}

fn sdmx_rows_match_types(
    rows: &[BTreeMap<String, Value>],
    expected: &FixtureSdmxJsonTypes,
) -> bool {
    let types = expected
        .dimensions
        .iter()
        .chain(&expected.measures)
        .chain(&expected.attributes)
        .collect::<Vec<_>>();
    !rows.is_empty()
        && !types.is_empty()
        && rows.iter().all(|row| {
            types.iter().all(|(name, expected)| {
                row.get(*name).is_some_and(|value| match expected {
                    FixtureJsonScalarType::String => value.is_string(),
                    FixtureJsonScalarType::Number => value.is_number(),
                    FixtureJsonScalarType::Boolean => value.is_boolean(),
                })
            })
        })
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
            object.remove("@type");
            object.remove("registryIdentifier");
            if let Some(domain) = object.get_mut("domainData").and_then(Value::as_object_mut) {
                domain.retain(|_, value| {
                    value.get("type").and_then(Value::as_str) != Some("Point")
                        || value.get("coordinates").and_then(Value::as_array).is_none()
                });
            }
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
    } else if let Some(items) = document.get("items").and_then(Value::as_array) {
        items.iter().collect()
    } else {
        geojson_features(document)
            .into_iter()
            .filter_map(|feature| feature.get("properties"))
            .collect()
    }
}

fn geojson_features(document: &Value) -> Vec<&Value> {
    if document.get("type").and_then(Value::as_str) == Some("Feature") {
        vec![document]
    } else {
        document
            .get("features")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |items| items.iter().collect())
    }
}

fn has_registry_core(record: &Value) -> bool {
    record.get("registryIdentifier").is_some() && has_record_core(record)
}

fn has_record_core(record: &Value) -> bool {
    [
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

fn has_registry_record_context(document: &Value) -> bool {
    [
        "registryIdentifier",
        "datasetIdentifier",
        "entityTypeIdentifier",
    ]
    .iter()
    .all(|key| {
        document
            .get("meta")
            .and_then(|meta| meta.get(key))
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    })
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
    path.contains("/records")
        || path.contains("/lookups/")
        || path.starts_with("/sdmx/v2/data/")
        || path.starts_with("/sdmx/v2/structure/")
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
                equivalent_records: None,
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
                equivalent_records: None,
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
    fn json_and_json_ld_record_mismatch_keeps_the_wire_representation_code() {
        let yaml = r#"
schemaVersion: relay.registrystack.org/http-journey/v1alpha1
registry: urn:example:registry
authorizations: {}
steps:
  - id: jsonld
    request: {method: GET, path: /health}
    expect: {status: 200, recordsEquivalentTo: json}
"#;
        let journey = parse_journey(yaml).expect("fixture parses");
        let step = &journey.steps[0];
        let headers = http::HeaderMap::new();
        let previous = json!({"data": {"recordIdentifier": "record-1"}});
        let current = json!({"data": {"recordIdentifier": "record-2"}});
        let previous_equivalent = normalized_records(&previous);
        let current_equivalent = normalized_records(&current);
        let observations = BTreeMap::from([(
            "json".into(),
            FixtureObservation {
                document: Some(previous),
                etag: None,
                equivalent_records: Some(previous_equivalent),
            },
        )]);
        let mut diagnostics = Vec::new();

        assert!(!assert_expectations(
            step,
            &ObservedResponse {
                status: StatusCode::OK,
                headers: &headers,
                body: b"",
                document: Some(&current),
                code: None,
                equivalent_records: Some(&current_equivalent),
            },
            &mut BTreeMap::new(),
            &observations,
            0,
            &mut diagnostics,
        ));
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "fixture.representation_mismatch");
    }

    #[test]
    fn spatial_fixture_expectations_are_enforced() {
        let yaml = r#"
schemaVersion: relay.registrystack.org/http-journey/v1alpha1
registry: urn:example:registry
authorizations: {}
steps:
  - id: spatial
    request: {method: GET, path: /health}
    expect:
      status: 200
      geoJsonRoot: feature-collection
      geometryType: Point
      formatProfile: jsonfg
"#;
        let journey = parse_journey(yaml).expect("spatial fixture parses");
        let step = &journey.steps[0];
        let mut headers = http::HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/geo+json".parse().unwrap());
        headers.insert(
            LINK,
            format!("<{JSON_FG_PROFILE_URI}>; rel=\"profile\"")
                .parse()
                .unwrap(),
        );
        let document = json!({
            "type": "FeatureCollection",
            "conformsTo": ["https://www.opengis.net/spec/json-fg-1/1.0/conf/core"],
            "featureType": "example",
            "coordRefSys": CRS84_URI,
            "features": [{
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [100.0, 13.0]},
                "properties": {"recordIdentifier": "record-1", "domainData": {}}
            }]
        });
        let evaluate = |step: &FixtureStep, document: &Value, headers: &http::HeaderMap| {
            let mut diagnostics = Vec::new();
            let passed = assert_expectations(
                step,
                &ObservedResponse {
                    status: StatusCode::OK,
                    headers,
                    body: b"",
                    document: Some(document),
                    code: None,
                    equivalent_records: None,
                },
                &mut BTreeMap::new(),
                &BTreeMap::new(),
                0,
                &mut diagnostics,
            );
            (passed, diagnostics)
        };

        let (passed, diagnostics) = evaluate(step, &document, &headers);
        assert!(passed);
        assert!(diagnostics.is_empty());

        let mut wrong_root = step.clone();
        wrong_root.expect.geo_json_root = Some(FixtureGeoJsonRoot::Feature);
        let (passed, diagnostics) = evaluate(&wrong_root, &document, &headers);
        assert!(!passed);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "fixture.geojson_root_mismatch");

        let mut wrong_geometry = step.clone();
        wrong_geometry.expect.geometry_type = Some(FixtureGeometryType::Null);
        let (passed, diagnostics) = evaluate(&wrong_geometry, &document, &headers);
        assert!(!passed);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "fixture.geometry_mismatch");

        let mut invalid_profile = document.clone();
        invalid_profile["features"][0]["coordRefSys"] = Value::String(CRS84_URI.into());
        let (passed, diagnostics) = evaluate(step, &invalid_profile, &headers);
        assert!(!passed);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "fixture.format_profile_mismatch");
    }

    #[test]
    fn fixture_yaml_accepts_closed_sdmx_expectations() {
        let yaml = r#"
schemaVersion: relay.registrystack.org/http-journey/v1alpha1
registry: urn:example:registry
authorizations: {}
steps:
  - id: data
    request: {method: GET, path: /sdmx/v2/data/dataflow/EXAMPLE/RATES/1.0.0/*}
    expect:
      status: 200
      mediaType: application/vnd.sdmx.data+json;version=2.1.0
      observationCount: 1
      sdmxJsonTypes:
        dimensions: {REF_AREA: string, TIME_PERIOD: string}
        measures: {OBS_VALUE: number}
        attributes: {UNIT_MEASURE: string}
"#;
        let journey = parse_journey(yaml).expect("SDMX fixture parses");
        let expectation = &journey.steps[0].expect;
        assert_eq!(expectation.observation_count, Some(1));
        assert_eq!(
            expectation
                .sdmx_json_types
                .as_ref()
                .and_then(|types| types.measures.get("OBS_VALUE")),
            Some(&FixtureJsonScalarType::Number)
        );
    }

    #[test]
    fn sdmx_json_and_csv_fixture_rows_are_typed_and_equivalent() {
        let document = json!({
            "data": {
                "dataSets": [{"series": {"0": {"observations": {"0": [65.5, 0]}}}}],
                "structures": [{
                    "dimensions": {
                        "series": [{"id": "REF_AREA", "values": [{"id": "EX-A"}]}],
                        "observation": [{"id": "TIME_PERIOD", "values": [{"value": "2024-Q1"}]}]
                    },
                    "measures": {"observation": [{"id": "OBS_VALUE"}]},
                    "attributes": {"observation": [{
                        "id": "UNIT_MEASURE", "values": [{"id": "PERCENT"}]
                    }]}
                }]
            }
        });
        let csv = b"STRUCTURE,STRUCTURE_ID,ACTION,REF_AREA,TIME_PERIOD,OBS_VALUE,UNIT_MEASURE\n\
dataflow,EXAMPLE:RATES(1.0.0),R,EX-A,2024-Q1,65.5,PERCENT\n";
        let mut json_headers = http::HeaderMap::new();
        json_headers.insert(
            CONTENT_TYPE,
            "application/vnd.sdmx.data+json;version=2.1.0"
                .parse()
                .unwrap(),
        );
        let mut csv_headers = http::HeaderMap::new();
        csv_headers.insert(
            CONTENT_TYPE,
            "application/vnd.sdmx.data+csv;version=2.1.0"
                .parse()
                .unwrap(),
        );

        let rows = sdmx_json_rows(&document).expect("JSON rows decode");
        assert!(sdmx_rows_match_types(
            &rows,
            &FixtureSdmxJsonTypes {
                dimensions: BTreeMap::from([
                    ("REF_AREA".into(), FixtureJsonScalarType::String),
                    ("TIME_PERIOD".into(), FixtureJsonScalarType::String),
                ]),
                measures: BTreeMap::from([("OBS_VALUE".into(), FixtureJsonScalarType::Number,)]),
                attributes: BTreeMap::from([(
                    "UNIT_MEASURE".into(),
                    FixtureJsonScalarType::String,
                )]),
            }
        ));
        assert_eq!(
            sdmx_observation_count(&json_headers, Some(&document), b""),
            Some(1)
        );
        assert_eq!(sdmx_observation_count(&csv_headers, None, csv), Some(1));
        assert_eq!(
            normalized_response_records(&json_headers, Some(&document), b""),
            normalized_response_records(&csv_headers, None, csv)
        );
    }

    #[test]
    fn sdmx_json_rows_refuse_a_data_set_without_observations_or_series() {
        let structures = json!([{
            "dimensions": {
                "series": [{"id": "REF_AREA", "values": [{"id": "EX-A"}]}],
                "observation": [{"id": "TIME_PERIOD", "values": [{"value": "2024-Q1"}]}]
            },
            "measures": {"observation": [{"id": "OBS_VALUE"}]},
            "attributes": {"observation": [{
                "id": "UNIT_MEASURE", "values": [{"id": "PERCENT"}]
            }]}
        }]);

        let neither = json!({"data": {"dataSets": [{}], "structures": structures}});
        assert_eq!(sdmx_json_rows(&neither), None);

        let unusable_series =
            json!({"data": {"dataSets": [{"series": []}], "structures": structures}});
        assert_eq!(sdmx_json_rows(&unusable_series), None);
    }

    #[test]
    fn fixture_tokens_have_a_bounded_jwt_shape_without_exposing_claims() {
        let token = fixture_token("fixture-a");
        assert_eq!(token.split('.').count(), 3);
        assert!(!token.contains("principal"));
    }
}
