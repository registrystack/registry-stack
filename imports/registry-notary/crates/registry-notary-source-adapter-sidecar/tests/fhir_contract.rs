// SPDX-License-Identifier: Apache-2.0

use axum::{extract::Query, http::HeaderMap, Json, Router};
use axum_test::TestServer;
use registry_notary_source_adapter_sidecar::{sidecar_router, SidecarConfig};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

const TOKEN: &str = "fhir-sidecar-token";
const TOKEN_HASH_ENV: &str = "FHIR_CONTRACT_SIDECAR_TOKEN_HASH";
const TOKEN_HASH: &str = "sha256:4ca64b39d0e234b213559bb21d7821678bc38338f9ceda9c480fd55c63bfb518";
const UPSTREAM_TOKEN_ENV: &str = "FHIR_CONTRACT_UPSTREAM_TOKEN";
const UPSTREAM_TOKEN: &str = "fhir-upstream-token";
const PURPOSE: &str = "https://purpose.example.test/coverage";

#[tokio::test]
async fn fhir_lookup_projects_patient_coverage_graph_to_rda_rows() {
    let upstream = fhir_fixture_server();
    let sidecar = fhir_sidecar(upstream.server_address().unwrap().as_str()).await;

    let response = sidecar
        .get("/v1/datasets/health_registry/entities/coverage/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,coverage_status,coverage_id")
        .add_query_param("limit", "2")
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(
        body,
        json!({
            "data": [{
                "national_id": "person-123",
                "coverage_status": "active",
                "coverage_id": "cov-active"
            }]
        })
    );
    assert!(
        !body.to_string().contains("resourceType"),
        "raw FHIR resources must not be returned"
    );
}

#[tokio::test]
async fn fhir_lookup_preserves_inactive_coverage_as_false_ready_fact() {
    let upstream = fhir_fixture_server();
    let sidecar = fhir_sidecar(upstream.server_address().unwrap().as_str()).await;

    let response = sidecar
        .get("/v1/datasets/health_registry/entities/coverage/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("national_id", "inactive-person")
        .add_query_param("fields", "national_id,coverage_status")
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({ "data": [{ "national_id": "inactive-person", "coverage_status": "inactive" }] })
    );
}

#[tokio::test]
async fn fhir_lookup_maps_missing_and_ambiguous_graphs_to_rda_cardinality() {
    let upstream = fhir_fixture_server();
    let sidecar = fhir_sidecar(upstream.server_address().unwrap().as_str()).await;

    let missing = sidecar
        .get("/v1/datasets/health_registry/entities/coverage/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("national_id", "missing-person")
        .add_query_param("fields", "national_id,coverage_status")
        .await;
    missing.assert_status_ok();
    assert_eq!(missing.json::<Value>(), json!({ "data": [] }));

    let ambiguous = sidecar
        .get("/v1/datasets/health_registry/entities/coverage/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("national_id", "ambiguous-coverage")
        .add_query_param("fields", "national_id,coverage_status,coverage_id")
        .await;
    ambiguous.assert_status_ok();
    assert_eq!(
        ambiguous.json::<Value>(),
        json!({
            "data": [
                {
                    "national_id": "ambiguous-coverage",
                    "coverage_status": "active",
                    "coverage_id": "cov-a"
                },
                {
                    "national_id": "ambiguous-coverage",
                    "coverage_status": "cancelled",
                    "coverage_id": "cov-b"
                }
            ]
        })
    );
}

#[tokio::test]
async fn fhir_lookup_uses_named_query_values_for_relationship_graphs() {
    let upstream = fhir_fixture_server();
    let sidecar = fhir_sidecar(upstream.server_address().unwrap().as_str()).await;

    let response = sidecar
        .get("/v1/datasets/health_registry/entities/guardian/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("national_id", "person-123")
        .add_query_param("requester_id", "guardian-1")
        .add_query_param("fields", "national_id,related_person_id,relationship_code")
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "data": [{
                "national_id": "person-123",
                "related_person_id": "rel-guardian-1",
                "relationship_code": "GUARD"
            }]
        })
    );
}

#[tokio::test]
async fn fhir_lookup_projects_administrative_p0_claim_facts() {
    let upstream = fhir_fixture_server();
    let sidecar = fhir_sidecar(upstream.server_address().unwrap().as_str()).await;

    let coverage = sidecar
        .get("/v1/datasets/health_registry/entities/coverage/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,coverage_status,coverage_class")
        .await;
    coverage.assert_status_ok();
    assert_eq!(
        coverage.json::<Value>(),
        json!({
            "data": [{
                "national_id": "person-123",
                "coverage_status": "active",
                "coverage_class": "gold"
            }]
        })
    );

    let consent = sidecar
        .get("/v1/datasets/health_registry/entities/consent/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,consent_status,consent_purpose")
        .await;
    consent.assert_status_ok();
    assert_eq!(
        consent.json::<Value>(),
        json!({
            "data": [{
                "national_id": "person-123",
                "consent_status": "active",
                "consent_purpose": "TREAT"
            }]
        })
    );

    let provider = sidecar
        .get("/v1/datasets/health_registry/entities/provider_affiliation/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("provider_id", "provider-123")
        .add_query_param(
            "fields",
            "provider_id,practitioner_role_id,organization_ref",
        )
        .await;
    provider.assert_status_ok();
    assert_eq!(
        provider.json::<Value>(),
        json!({
            "data": [{
                "provider_id": "provider-123",
                "practitioner_role_id": "role-provider-123-org-1",
                "organization_ref": "Organization/org-1"
            }]
        })
    );

    let facility = sidecar
        .get("/v1/datasets/health_registry/entities/facility_service/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("organization_id", "facility-1")
        .add_query_param(
            "fields",
            "organization_id,location_id,healthcare_service_id,service_active",
        )
        .await;
    facility.assert_status_ok();
    assert_eq!(
        facility.json::<Value>(),
        json!({
            "data": [{
                "organization_id": "facility-1",
                "location_id": "location-facility-1",
                "healthcare_service_id": "service-facility-1",
                "service_active": true
            }]
        })
    );
}

#[tokio::test]
async fn fhir_lookup_projects_patient_claim_facts_with_missing_defaults() {
    let upstream = fhir_fixture_server();
    let sidecar = fhir_sidecar(upstream.server_address().unwrap().as_str()).await;

    let absent_deceased = sidecar
        .get("/v1/datasets/health_registry/entities/patient/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,patient_id,birth_date,deceased")
        .await;

    absent_deceased.assert_status_ok();
    assert_eq!(
        absent_deceased.json::<Value>(),
        json!({
            "data": [{
                "national_id": "person-123",
                "patient_id": "person-123",
                "birth_date": "1990-01-01",
                "deceased": false
            }]
        })
    );

    let explicit_deceased = sidecar
        .get("/v1/datasets/health_registry/entities/patient/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("national_id", "deceased-person")
        .add_query_param("fields", "national_id,patient_id,birth_date,deceased")
        .await;

    explicit_deceased.assert_status_ok();
    assert_eq!(
        explicit_deceased.json::<Value>(),
        json!({
            "data": [{
                "national_id": "deceased-person",
                "patient_id": "deceased-person",
                "birth_date": "1940-01-01",
                "deceased": true
            }]
        })
    );
}

#[tokio::test]
async fn fhir_lookup_uses_configured_primary_lookup_field_when_query_has_extra_predicates() {
    let upstream = fhir_fixture_server();
    let sidecar = fhir_sidecar(upstream.server_address().unwrap().as_str()).await;

    let response = sidecar
        .get("/v1/datasets/health_registry/entities/patient_hint/records")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_query_param("aa_context", "wrong-primary-if-sorted")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,patient_id")
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "data": [{
                "national_id": "person-123",
                "patient_id": "person-123"
            }]
        })
    );
}

#[tokio::test]
async fn fhir_batch_match_returns_per_item_graph_results() {
    let upstream = fhir_fixture_server();
    let sidecar = fhir_sidecar(upstream.server_address().unwrap().as_str()).await;

    let response = sidecar
        .post("/v1/datasets/health_registry/entities/coverage/records:batchMatch")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .json(&json!({
            "fields": ["national_id", "coverage_status", "coverage_id"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [
                { "id": "active", "values": ["person-123"] },
                { "id": "missing", "values": ["missing-person"] },
                { "id": "bad-item", "values": [{"not": "scalar"}] },
                { "id": "ambiguous", "values": ["ambiguous-coverage"] }
            ]
        }))
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "items": [
                {
                    "id": "active",
                    "data": [{
                        "national_id": "person-123",
                        "coverage_status": "active",
                        "coverage_id": "cov-active"
                    }]
                },
                { "id": "missing", "data": [] },
                {
                    "id": "bad-item",
                    "error": { "code": "source_unavailable" }
                },
                {
                    "id": "ambiguous",
                    "data": [
                        {
                            "national_id": "ambiguous-coverage",
                            "coverage_status": "active",
                            "coverage_id": "cov-a"
                        },
                        {
                            "national_id": "ambiguous-coverage",
                            "coverage_status": "cancelled",
                            "coverage_id": "cov-b"
                        }
                    ]
                }
            ]
        })
    );
}

#[tokio::test]
async fn fhir_batch_match_uses_named_query_values_for_relationship_graphs() {
    let upstream = fhir_fixture_server();
    let sidecar = fhir_sidecar(upstream.server_address().unwrap().as_str()).await;

    let response = sidecar
        .post("/v1/datasets/health_registry/entities/guardian/records:batchMatch")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .json(&json!({
            "fields": ["national_id", "related_person_id", "relationship_code"],
            "query_signature": [
                { "field": "national_id", "op": "eq" },
                { "field": "requester_id", "op": "eq" }
            ],
            "items": [
                { "id": "guardian", "values": ["person-123", "guardian-1"] },
                { "id": "not-related", "values": ["person-123", "neighbor-1"] }
            ]
        }))
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "items": [
                {
                    "id": "guardian",
                    "data": [{
                        "national_id": "person-123",
                        "related_person_id": "rel-guardian-1",
                        "relationship_code": "GUARD"
                    }]
                },
                { "id": "not-related", "data": [] }
            ]
        })
    );
}

#[tokio::test]
async fn fhir_startup_rejects_unsafe_base_url_and_resource_type_escape() {
    std::env::set_var(TOKEN_HASH_ENV, TOKEN_HASH);
    let unsafe_manifest = manifest_yaml("http://169.254.169.254/latest/meta-data");
    let unsafe_config: SidecarConfig =
        serde_norway::from_str(&unsafe_manifest).expect("unsafe manifest parses");
    let unsafe_error = sidecar_router(unsafe_config)
        .await
        .expect_err("unsafe FHIR base URL is rejected")
        .to_string();
    assert!(
        unsafe_error.contains("fhir.base_url"),
        "unexpected unsafe base URL error: {unsafe_error}"
    );

    let upstream = fhir_fixture_server();
    let escaped_manifest = manifest_yaml(upstream.server_address().unwrap().as_str()).replacen(
        "resource_type: Patient",
        "resource_type: ../Patient",
        1,
    );
    let escaped_config: SidecarConfig =
        serde_norway::from_str(&escaped_manifest).expect("escaped manifest parses");
    let escaped_error = sidecar_router(escaped_config)
        .await
        .expect_err("resource type path escape is rejected")
        .to_string();
    assert!(
        escaped_error.contains("resource_type"),
        "unexpected escaped resource type error: {escaped_error}"
    );
}

fn fhir_fixture_server() -> TestServer {
    TestServer::builder().http_transport().build(
        Router::new()
            .route("/fhir/Patient", axum::routing::get(patient_search))
            .route("/fhir/Coverage", axum::routing::get(coverage_search))
            .route("/fhir/Consent", axum::routing::get(consent_search))
            .route(
                "/fhir/Practitioner",
                axum::routing::get(practitioner_search),
            )
            .route(
                "/fhir/PractitionerRole",
                axum::routing::get(practitioner_role_search),
            )
            .route(
                "/fhir/Organization",
                axum::routing::get(organization_search),
            )
            .route("/fhir/Location", axum::routing::get(location_search))
            .route(
                "/fhir/HealthcareService",
                axum::routing::get(healthcare_service_search),
            )
            .route(
                "/fhir/RelatedPerson",
                axum::routing::get(related_person_search),
            ),
    )
}

async fn patient_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let identifier = query.get("identifier").map(String::as_str).unwrap_or("");
    let national_id = identifier
        .strip_prefix("https://example.gov/id/national-id|")
        .unwrap_or(identifier);
    let entries = match national_id {
        "person-123" | "inactive-person" | "ambiguous-coverage" | "smoke-person" => {
            vec![fhir_entry(patient(national_id))]
        }
        "child-person" => vec![fhir_entry(patient_with_claim_facts(
            national_id,
            "2015-01-01",
            Some(false),
        ))],
        "deceased-person" => vec![fhir_entry(patient_with_claim_facts(
            national_id,
            "1940-01-01",
            Some(true),
        ))],
        "explicit-alive-person" => vec![fhir_entry(patient_with_claim_facts(
            national_id,
            "1985-05-05",
            Some(false),
        ))],
        "ambiguous-patient" => vec![
            fhir_entry(patient("ambiguous-patient-a")),
            fhir_entry(patient("ambiguous-patient-b")),
        ],
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn coverage_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let beneficiary = query.get("beneficiary").map(String::as_str).unwrap_or("");
    let entries = match beneficiary {
        "Patient/person-123" => vec![fhir_entry(coverage("cov-active", beneficiary, "active"))],
        "Patient/inactive-person" => {
            vec![fhir_entry(coverage(
                "cov-inactive",
                beneficiary,
                "inactive",
            ))]
        }
        "Patient/ambiguous-coverage" => vec![
            fhir_entry(coverage("cov-a", beneficiary, "active")),
            fhir_outcome_entry(),
            fhir_entry_with_mode(coverage("cov-included", beneficiary, "draft"), "include"),
            fhir_entry(coverage("cov-b", beneficiary, "cancelled")),
        ],
        "Patient/smoke-person" => vec![fhir_entry(coverage("cov-smoke", beneficiary, "active"))],
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn consent_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let patient = query.get("patient").map(String::as_str).unwrap_or("");
    let purpose = query.get("purpose").map(String::as_str).unwrap_or("");
    let entries = match (patient, purpose) {
        ("Patient/person-123", "TREAT") => {
            vec![fhir_entry(consent(
                "consent-person-123",
                patient,
                "active",
                purpose,
            ))]
        }
        ("Patient/inactive-person", "TREAT") => {
            vec![fhir_entry(consent(
                "consent-inactive-person",
                patient,
                "inactive",
                purpose,
            ))]
        }
        ("Patient/smoke-person", "TREAT") => {
            vec![fhir_entry(consent(
                "consent-smoke",
                patient,
                "active",
                purpose,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn practitioner_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let identifier = query.get("identifier").map(String::as_str).unwrap_or("");
    let provider_id = identifier
        .strip_prefix("https://example.gov/id/provider-id|")
        .unwrap_or(identifier);
    let entries = match provider_id {
        "provider-123" | "smoke-provider" => vec![fhir_entry(practitioner(provider_id))],
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn practitioner_role_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let practitioner = query.get("practitioner").map(String::as_str).unwrap_or("");
    let organization = query.get("organization").map(String::as_str).unwrap_or("");
    let entries = match (practitioner, organization) {
        ("Practitioner/provider-123", "Organization/org-1") => {
            vec![fhir_entry(practitioner_role(
                "role-provider-123-org-1",
                practitioner,
                organization,
            ))]
        }
        ("Practitioner/smoke-provider", "Organization/org-1") => {
            vec![fhir_entry(practitioner_role(
                "role-smoke-org-1",
                practitioner,
                organization,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn organization_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let identifier = query.get("identifier").map(String::as_str).unwrap_or("");
    let organization_id = identifier
        .strip_prefix("https://example.gov/id/organization-id|")
        .unwrap_or(identifier);
    let entries = match organization_id {
        "facility-1" | "smoke-facility" => vec![fhir_entry(organization(organization_id))],
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn location_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let organization = query.get("organization").map(String::as_str).unwrap_or("");
    let entries = match organization {
        "Organization/facility-1" => {
            vec![fhir_entry(location("location-facility-1", organization))]
        }
        "Organization/smoke-facility" => vec![fhir_entry(location(
            "location-smoke-facility",
            organization,
        ))],
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn healthcare_service_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let location_ref = query.get("location").map(String::as_str).unwrap_or("");
    let service_type = query.get("service-type").map(String::as_str).unwrap_or("");
    let entries = match (location_ref, service_type) {
        ("Location/location-facility-1", "general-practice") => {
            vec![fhir_entry(healthcare_service(
                "service-facility-1",
                location_ref,
                true,
                service_type,
            ))]
        }
        ("Location/location-smoke-facility", "general-practice") => {
            vec![fhir_entry(healthcare_service(
                "service-smoke-facility",
                location_ref,
                true,
                service_type,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn related_person_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let patient = query.get("patient").map(String::as_str).unwrap_or("");
    let identifier = query.get("identifier").map(String::as_str).unwrap_or("");
    let requester_id = identifier
        .strip_prefix("https://example.gov/id/requester-id|")
        .unwrap_or(identifier);
    let entries = match (patient, requester_id) {
        ("Patient/person-123", "guardian-1") => {
            vec![fhir_entry(related_person(
                "rel-guardian-1",
                patient,
                requester_id,
            ))]
        }
        ("Patient/smoke-person", "smoke-guardian") => {
            vec![fhir_entry(related_person(
                "rel-smoke",
                patient,
                requester_id,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

fn assert_fhir_headers(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer fhir-upstream-token")
    );
    assert!(
        headers
            .get("data-purpose")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.is_empty()),
        "FHIR source request must forward Data-Purpose"
    );
}

fn patient(national_id: &str) -> Value {
    patient_with_claim_facts(national_id, "1990-01-01", None)
}

fn patient_with_claim_facts(national_id: &str, birth_date: &str, deceased: Option<bool>) -> Value {
    let mut patient = json!({
        "resourceType": "Patient",
        "id": national_id,
        "birthDate": birth_date,
        "identifier": [{
            "system": "https://example.gov/id/national-id",
            "value": national_id
        }]
    });
    if let Some(deceased) = deceased {
        patient["deceasedBoolean"] = json!(deceased);
    }
    patient
}

fn related_person(id: &str, patient: &str, requester_id: &str) -> Value {
    json!({
        "resourceType": "RelatedPerson",
        "id": id,
        "patient": { "reference": patient },
        "identifier": [{
            "system": "https://example.gov/id/requester-id",
            "value": requester_id
        }],
        "relationship": [{
            "coding": [{
                "system": "http://terminology.hl7.org/CodeSystem/v3-RoleCode",
                "code": "GUARD"
            }]
        }]
    })
}

fn coverage(id: &str, beneficiary: &str, status: &str) -> Value {
    json!({
        "resourceType": "Coverage",
        "id": id,
        "status": status,
        "beneficiary": { "reference": beneficiary },
        "class": [{
            "type": {
                "coding": [{
                    "system": "http://terminology.hl7.org/CodeSystem/coverage-class",
                    "code": "plan"
                }]
            },
            "value": if status == "active" { "gold" } else { "bronze" }
        }]
    })
}

fn consent(id: &str, patient: &str, status: &str, purpose: &str) -> Value {
    json!({
        "resourceType": "Consent",
        "id": id,
        "status": status,
        "patient": { "reference": patient },
        "provision": {
            "purpose": [{
                "coding": [{
                    "system": "http://terminology.hl7.org/CodeSystem/v3-ActReason",
                    "code": purpose
                }]
            }]
        }
    })
}

fn practitioner(provider_id: &str) -> Value {
    json!({
        "resourceType": "Practitioner",
        "id": provider_id,
        "identifier": [{
            "system": "https://example.gov/id/provider-id",
            "value": provider_id
        }]
    })
}

fn practitioner_role(id: &str, practitioner: &str, organization: &str) -> Value {
    json!({
        "resourceType": "PractitionerRole",
        "id": id,
        "active": true,
        "practitioner": { "reference": practitioner },
        "organization": { "reference": organization }
    })
}

fn organization(organization_id: &str) -> Value {
    json!({
        "resourceType": "Organization",
        "id": organization_id,
        "identifier": [{
            "system": "https://example.gov/id/organization-id",
            "value": organization_id
        }]
    })
}

fn location(id: &str, organization: &str) -> Value {
    json!({
        "resourceType": "Location",
        "id": id,
        "managingOrganization": { "reference": organization }
    })
}

fn healthcare_service(id: &str, location_ref: &str, active: bool, service_type: &str) -> Value {
    json!({
        "resourceType": "HealthcareService",
        "id": id,
        "active": active,
        "location": [{ "reference": location_ref }],
        "type": [{
            "coding": [{
                "system": "http://terminology.hl7.org/CodeSystem/service-type",
                "code": service_type
            }]
        }]
    })
}

fn fhir_bundle(entry: Vec<Value>) -> Value {
    json!({
        "resourceType": "Bundle",
        "type": "searchset",
        "entry": entry
    })
}

fn fhir_entry(resource: Value) -> Value {
    fhir_entry_with_mode(resource, "match")
}

fn fhir_entry_with_mode(resource: Value, mode: &str) -> Value {
    json!({
        "search": { "mode": mode },
        "resource": resource
    })
}

fn fhir_outcome_entry() -> Value {
    json!({
        "search": { "mode": "outcome" },
        "resource": { "resourceType": "OperationOutcome" }
    })
}

async fn fhir_sidecar(fhir_base: &str) -> TestServer {
    std::env::set_var(TOKEN_HASH_ENV, TOKEN_HASH);
    std::env::set_var(UPSTREAM_TOKEN_ENV, UPSTREAM_TOKEN);
    let config: SidecarConfig =
        serde_norway::from_str(&manifest_yaml(fhir_base)).expect("FHIR manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("FHIR sidecar router builds");
    TestServer::builder().http_transport().build(app)
}

fn manifest_yaml(fhir_base: &str) -> String {
    let worker = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/contract_worker.sh");
    let fhir_url = format!("{}/fhir", fhir_base.trim_end_matches('/'));
    format!(
        r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: {token_hash_env}
limits:
  max_workers: 1
  worker_timeout_ms: 250
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 256
  liveness_window_ms: 1000
  max_batch_items: 100
  max_worker_memory_mb: 256
openfn:
  cli_build_tool: "1.36.0"
  runtime: "1.36.0"
worker:
  command: "/bin/sh"
  args:
    - {worker}
    - "/tmp/registry-notary-fhir-contract-unused.jsonl"
sources:
  fhir_coverage:
    dataset: health_registry
    entity: coverage
    engine: fhir
    allow_insecure_localhost: true
    allowed_base_urls:
      - {fhir_url}
    fhir:
      base_url: {fhir_url}
      bearer_token_env: {upstream_token_env}
      anchor:
        id: patient
        resource_type: Patient
        cardinality: one
        search:
          - param: identifier
            type: token
            system: https://example.gov/id/national-id
            value_from_lookup: true
      relations:
        - id: coverage
          resource_type: Coverage
          cardinality: one
          search:
            - param: beneficiary
              type: reference
              value_from_node: patient.reference
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        coverage_status:
          node: coverage
          pointer: /status
        coverage_id:
          node: coverage
          pointer: /id
        coverage_class:
          node: coverage
          pointer: /class/0/value
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
  fhir_patient:
    dataset: health_registry
    entity: patient
    engine: fhir
    allow_insecure_localhost: true
    allowed_base_urls:
      - {fhir_url}
    fhir:
      base_url: {fhir_url}
      bearer_token_env: {upstream_token_env}
      anchor:
        id: patient
        resource_type: Patient
        cardinality: one
        search:
          - param: identifier
            type: token
            system: https://example.gov/id/national-id
            value_from_lookup: true
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        patient_id:
          node: patient
          pointer: /id
        birth_date:
          node: patient
          pointer: /birthDate
        deceased:
          node: patient
          pointer: /deceasedBoolean
          default: false
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
  fhir_patient_hint:
    dataset: health_registry
    entity: patient_hint
    engine: fhir
    allow_insecure_localhost: true
    allowed_base_urls:
      - {fhir_url}
    fhir:
      base_url: {fhir_url}
      bearer_token_env: {upstream_token_env}
      anchor:
        id: patient
        resource_type: Patient
        cardinality: one
        search:
          - param: identifier
            type: token
            system: https://example.gov/id/national-id
            value_from_lookup: true
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        patient_id:
          node: patient
          pointer: /id
    smoke_lookup:
      field: national_id
      value: smoke-person
      query_values:
        aa_context: smoke-context
      fields:
        - national_id
      purpose: startup-smoke
  fhir_guardian:
    dataset: health_registry
    entity: guardian
    engine: fhir
    allow_insecure_localhost: true
    allowed_base_urls:
      - {fhir_url}
    fhir:
      base_url: {fhir_url}
      bearer_token_env: {upstream_token_env}
      anchor:
        id: patient
        resource_type: Patient
        cardinality: one
        search:
          - param: identifier
            type: token
            system: https://example.gov/id/national-id
            value_from_query: national_id
      relations:
        - id: related_person
          resource_type: RelatedPerson
          cardinality: one
          search:
            - param: patient
              type: reference
              value_from_node: patient.reference
            - param: identifier
              type: token
              system: https://example.gov/id/requester-id
              value_from_query: requester_id
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        related_person_id:
          node: related_person
          pointer: /id
        relationship_code:
          node: related_person
          pointer: /relationship/0/coding/0/code
    smoke_lookup:
      field: national_id
      value: smoke-person
      query_values:
        requester_id: smoke-guardian
      fields:
        - national_id
      purpose: startup-smoke
  fhir_consent:
    dataset: health_registry
    entity: consent
    engine: fhir
    allow_insecure_localhost: true
    allowed_base_urls:
      - {fhir_url}
    fhir:
      base_url: {fhir_url}
      bearer_token_env: {upstream_token_env}
      anchor:
        id: patient
        resource_type: Patient
        cardinality: one
        search:
          - param: identifier
            type: token
            system: https://example.gov/id/national-id
            value_from_lookup: true
      relations:
        - id: consent
          resource_type: Consent
          cardinality: one
          search:
            - param: patient
              type: reference
              value_from_node: patient.reference
            - param: purpose
              type: code
              value: TREAT
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        consent_status:
          node: consent
          pointer: /status
        consent_purpose:
          node: consent
          pointer: /provision/purpose/0/coding/0/code
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
  fhir_provider_affiliation:
    dataset: health_registry
    entity: provider_affiliation
    engine: fhir
    allow_insecure_localhost: true
    allowed_base_urls:
      - {fhir_url}
    fhir:
      base_url: {fhir_url}
      bearer_token_env: {upstream_token_env}
      anchor:
        id: practitioner
        resource_type: Practitioner
        cardinality: one
        search:
          - param: identifier
            type: token
            system: https://example.gov/id/provider-id
            value_from_lookup: true
      relations:
        - id: practitioner_role
          resource_type: PractitionerRole
          cardinality: one
          search:
            - param: practitioner
              type: reference
              value_from_node: practitioner.reference
            - param: organization
              type: reference
              value: Organization/org-1
      project:
        provider_id:
          node: practitioner
          pointer: /identifier/0/value
        practitioner_role_id:
          node: practitioner_role
          pointer: /id
        organization_ref:
          node: practitioner_role
          pointer: /organization/reference
    smoke_lookup:
      field: provider_id
      value: smoke-provider
      fields:
        - provider_id
      purpose: startup-smoke
  fhir_facility_service:
    dataset: health_registry
    entity: facility_service
    engine: fhir
    allow_insecure_localhost: true
    allowed_base_urls:
      - {fhir_url}
    fhir:
      base_url: {fhir_url}
      bearer_token_env: {upstream_token_env}
      anchor:
        id: organization
        resource_type: Organization
        cardinality: one
        search:
          - param: identifier
            type: token
            system: https://example.gov/id/organization-id
            value_from_lookup: true
      relations:
        - id: location
          resource_type: Location
          cardinality: one
          search:
            - param: organization
              type: reference
              value_from_node: organization.reference
        - id: healthcare_service
          resource_type: HealthcareService
          cardinality: one
          search:
            - param: location
              type: reference
              value_from_node: location.reference
            - param: service-type
              type: code
              value: general-practice
      project:
        organization_id:
          node: organization
          pointer: /identifier/0/value
        location_id:
          node: location
          pointer: /id
        healthcare_service_id:
          node: healthcare_service
          pointer: /id
        service_active:
          node: healthcare_service
          pointer: /active
    smoke_lookup:
      field: organization_id
      value: smoke-facility
      fields:
        - organization_id
      purpose: startup-smoke
"#,
        token_hash_env = yaml_string(TOKEN_HASH_ENV),
        upstream_token_env = yaml_string(UPSTREAM_TOKEN_ENV),
        worker = yaml_string(worker.to_str().expect("fixture worker path is UTF-8")),
        fhir_url = yaml_string(&fhir_url),
    )
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serializes")
}
