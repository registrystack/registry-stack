// SPDX-License-Identifier: Apache-2.0

use axum::{extract::Query, http::HeaderMap, Json, Router};
use axum_test::TestServer;
use registry_notary_source_adapter_sidecar::{sidecar_router, SidecarConfig};
use serde_json::{json, Value};
use std::collections::HashMap;

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
async fn fhir_lookup_projects_remaining_spec_claim_family_facts() {
    let upstream = fhir_fixture_server();
    let sidecar = fhir_sidecar(upstream.server_address().unwrap().as_str()).await;

    let cases = [
        (
            "eligibility",
            "fields=national_id,eligibility_status,eligibility_outcome,service_type",
            json!({
                "national_id": "person-123",
                "eligibility_status": "active",
                "eligibility_outcome": "complete",
                "service_type": "general-practice"
            }),
        ),
        (
            "program_enrollment",
            "fields=national_id,enrollment_status,program_code",
            json!({
                "national_id": "person-123",
                "enrollment_status": "active",
                "program_code": "tb-program"
            }),
        ),
        (
            "encounter",
            "fields=national_id,encounter_status,encounter_type",
            json!({
                "national_id": "person-123",
                "encounter_status": "finished",
                "encounter_type": "annual-wellness"
            }),
        ),
        (
            "referral",
            "fields=national_id,referral_status,referral_code",
            json!({
                "national_id": "person-123",
                "referral_status": "active",
                "referral_code": "general-referral"
            }),
        ),
        (
            "appointment",
            "fields=national_id,appointment_status,appointment_service_type",
            json!({
                "national_id": "person-123",
                "appointment_status": "booked",
                "appointment_service_type": "general-practice"
            }),
        ),
        (
            "lab_report",
            "fields=national_id,diagnostic_report_status,diagnostic_report_code",
            json!({
                "national_id": "person-123",
                "diagnostic_report_status": "final",
                "diagnostic_report_code": "viral-load-panel"
            }),
        ),
        (
            "immunization",
            "fields=national_id,immunization_status,vaccine_code",
            json!({
                "national_id": "person-123",
                "immunization_status": "completed",
                "vaccine_code": "03"
            }),
        ),
        (
            "source_trace",
            "fields=national_id,trace_id,trace_activity,trace_recorded",
            json!({
                "national_id": "person-123",
                "trace_id": "provenance-person-123",
                "trace_activity": "verify",
                "trace_recorded": "2026-06-16T00:00:00Z"
            }),
        ),
        (
            "prior_authorization",
            "fields=national_id,authorization_status,authorization_outcome,authorization_disposition",
            json!({
                "national_id": "person-123",
                "authorization_status": "active",
                "authorization_outcome": "complete",
                "authorization_disposition": "approved"
            }),
        ),
    ];

    for (entity, fields_query, expected_row) in cases {
        let response = sidecar
            .get(&format!(
                "/v1/datasets/health_registry/entities/{entity}/records?national_id=person-123&{fields_query}"
            ))
            .add_header("authorization", format!("Bearer {TOKEN}"))
            .add_header("data-purpose", PURPOSE)
            .await;

        response.assert_status_ok();
        assert_eq!(
            response.json::<Value>(),
            json!({ "data": [expected_row] }),
            "unexpected projection for {entity}"
        );
    }
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
            )
            .route(
                "/fhir/CoverageEligibilityResponse",
                axum::routing::get(eligibility_response_search),
            )
            .route(
                "/fhir/EpisodeOfCare",
                axum::routing::get(episode_of_care_search),
            )
            .route("/fhir/Encounter", axum::routing::get(encounter_search))
            .route(
                "/fhir/ServiceRequest",
                axum::routing::get(service_request_search),
            )
            .route("/fhir/Appointment", axum::routing::get(appointment_search))
            .route(
                "/fhir/MedicationRequest",
                axum::routing::get(medication_request_search),
            )
            .route(
                "/fhir/DiagnosticReport",
                axum::routing::get(diagnostic_report_search),
            )
            .route("/fhir/Observation", axum::routing::get(observation_search))
            .route(
                "/fhir/Immunization",
                axum::routing::get(immunization_search),
            )
            .route("/fhir/Provenance", axum::routing::get(provenance_search))
            .route("/fhir/Condition", axum::routing::get(condition_search))
            .route("/fhir/CarePlan", axum::routing::get(care_plan_search))
            .route("/fhir/Procedure", axum::routing::get(procedure_search))
            .route(
                "/fhir/ClaimResponse",
                axum::routing::get(claim_response_search),
            )
            .route("/fhir/AuditEvent", axum::routing::get(audit_event_search)),
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

async fn eligibility_response_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let patient = query.get("patient").map(String::as_str).unwrap_or("");
    let service_type = query.get("service-type").map(String::as_str).unwrap_or("");
    let entries = match (patient, service_type) {
        ("Patient/person-123", "general-practice") => {
            vec![fhir_entry(coverage_eligibility_response(
                "eligibility-person-123",
                patient,
                "active",
                "complete",
                service_type,
            ))]
        }
        ("Patient/smoke-person", "general-practice") => {
            vec![fhir_entry(coverage_eligibility_response(
                "eligibility-smoke",
                patient,
                "active",
                "complete",
                service_type,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn episode_of_care_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let patient = query.get("patient").map(String::as_str).unwrap_or("");
    let episode_type = query.get("type").map(String::as_str).unwrap_or("");
    let entries = match (patient, episode_type) {
        ("Patient/person-123", "tb-program") => {
            vec![fhir_entry(episode_of_care(
                "episode-person-123",
                patient,
                "active",
                episode_type,
            ))]
        }
        ("Patient/smoke-person", "tb-program") => {
            vec![fhir_entry(episode_of_care(
                "episode-smoke",
                patient,
                "active",
                episode_type,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn encounter_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let patient = query.get("patient").map(String::as_str).unwrap_or("");
    let encounter_type = query.get("type").map(String::as_str).unwrap_or("");
    let entries = match (patient, encounter_type) {
        ("Patient/person-123", "annual-wellness") => {
            vec![fhir_entry(encounter(
                "encounter-person-123",
                patient,
                "finished",
                encounter_type,
            ))]
        }
        ("Patient/smoke-person", "annual-wellness") => {
            vec![fhir_entry(encounter(
                "encounter-smoke",
                patient,
                "finished",
                encounter_type,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn service_request_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let subject = query.get("subject").map(String::as_str).unwrap_or("");
    let code = query.get("code").map(String::as_str).unwrap_or("");
    let entries = match (subject, code) {
        ("Patient/person-123", "general-referral") => {
            vec![fhir_entry(service_request(
                "referral-person-123",
                subject,
                "active",
                code,
            ))]
        }
        ("Patient/smoke-person", "general-referral") => {
            vec![fhir_entry(service_request(
                "referral-smoke",
                subject,
                "active",
                code,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn appointment_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let patient = query.get("patient").map(String::as_str).unwrap_or("");
    let service_type = query.get("service-type").map(String::as_str).unwrap_or("");
    let entries = match (patient, service_type) {
        ("Patient/person-123", "general-practice") => {
            vec![fhir_entry(appointment(
                "appointment-person-123",
                patient,
                "booked",
                service_type,
            ))]
        }
        ("Patient/smoke-person", "general-practice") => {
            vec![fhir_entry(appointment(
                "appointment-smoke",
                patient,
                "booked",
                service_type,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn medication_request_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let subject = query.get("subject").map(String::as_str).unwrap_or("");
    let code = query.get("code").map(String::as_str).unwrap_or("");
    let entries = match (subject, code) {
        ("Patient/person-123", "example-medication") => {
            vec![fhir_entry(medication_request(
                "medication-person-123",
                subject,
                "active",
                code,
            ))]
        }
        ("Patient/smoke-person", "example-medication") => {
            vec![fhir_entry(medication_request(
                "medication-smoke",
                subject,
                "active",
                code,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn diagnostic_report_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let patient = query.get("patient").map(String::as_str).unwrap_or("");
    let code = query.get("code").map(String::as_str).unwrap_or("");
    let entries = match (patient, code) {
        ("Patient/person-123", "viral-load-panel") => {
            vec![fhir_entry(diagnostic_report(
                "report-person-123",
                patient,
                "final",
                code,
            ))]
        }
        ("Patient/smoke-person", "viral-load-panel") => {
            vec![fhir_entry(diagnostic_report(
                "report-smoke",
                patient,
                "final",
                code,
            ))]
        }
        ("Patient/person-123", "diagnostic-panel") => {
            vec![fhir_entry(diagnostic_report(
                "diagnostic-report-person-123",
                patient,
                "final",
                code,
            ))]
        }
        ("Patient/smoke-person", "diagnostic-panel") => {
            vec![fhir_entry(diagnostic_report(
                "diagnostic-report-smoke",
                patient,
                "final",
                code,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn observation_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let subject = query.get("subject").map(String::as_str).unwrap_or("");
    let code = query.get("code").map(String::as_str).unwrap_or("");
    let entries = match (subject, code) {
        ("Patient/person-123", "viral-load") => {
            vec![fhir_entry(observation_quantity(
                "observation-person-123",
                subject,
                "final",
                code,
                120,
            ))]
        }
        ("Patient/person-123", "pregnancy-status") => {
            vec![fhir_entry(observation_code(
                "pregnancy-person-123",
                subject,
                "final",
                code,
                "pregnant",
            ))]
        }
        ("Patient/person-123", "blood-pressure") => {
            vec![fhir_entry(observation_quantity(
                "blood-pressure-person-123",
                subject,
                "final",
                code,
                120,
            ))]
        }
        ("Patient/smoke-person", "viral-load") => {
            vec![fhir_entry(observation_quantity(
                "observation-smoke",
                subject,
                "final",
                code,
                120,
            ))]
        }
        ("Patient/smoke-person", "pregnancy-status") => {
            vec![fhir_entry(observation_code(
                "pregnancy-smoke",
                subject,
                "final",
                code,
                "pregnant",
            ))]
        }
        ("Patient/smoke-person", "blood-pressure") => {
            vec![fhir_entry(observation_quantity(
                "blood-pressure-smoke",
                subject,
                "final",
                code,
                120,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn immunization_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let patient = query.get("patient").map(String::as_str).unwrap_or("");
    let vaccine_code = query.get("vaccine-code").map(String::as_str).unwrap_or("");
    let entries = match (patient, vaccine_code) {
        ("Patient/person-123", "http://hl7.org/fhir/sid/cvx|03") => {
            vec![fhir_entry(immunization(
                "immunization-person-123",
                patient,
                "completed",
                "03",
            ))]
        }
        ("Patient/smoke-person", "http://hl7.org/fhir/sid/cvx|03") => {
            vec![fhir_entry(immunization(
                "immunization-smoke",
                patient,
                "completed",
                "03",
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn provenance_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let target = query.get("target").map(String::as_str).unwrap_or("");
    let entries = match target {
        "Patient/person-123" => vec![fhir_entry(provenance(
            "provenance-person-123",
            target,
            "2026-06-16T00:00:00Z",
            "verify",
        ))],
        "Patient/smoke-person" => vec![fhir_entry(provenance(
            "provenance-smoke",
            target,
            "2026-06-16T00:00:00Z",
            "verify",
        ))],
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn condition_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let subject = query.get("subject").map(String::as_str).unwrap_or("");
    let code = query.get("code").map(String::as_str).unwrap_or("");
    let entries = match (subject, code) {
        ("Patient/person-123", "tb-register") => {
            vec![fhir_entry(condition(
                "condition-person-123",
                subject,
                "active",
                code,
            ))]
        }
        ("Patient/smoke-person", "tb-register") => {
            vec![fhir_entry(condition(
                "condition-smoke",
                subject,
                "active",
                code,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn care_plan_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let subject = query.get("subject").map(String::as_str).unwrap_or("");
    let category = query.get("category").map(String::as_str).unwrap_or("");
    let entries = match (subject, category) {
        ("Patient/person-123", "tb-program") => {
            vec![fhir_entry(care_plan(
                "care-plan-person-123",
                subject,
                "active",
                category,
            ))]
        }
        ("Patient/smoke-person", "tb-program") => {
            vec![fhir_entry(care_plan(
                "care-plan-smoke",
                subject,
                "active",
                category,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn procedure_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let subject = query.get("subject").map(String::as_str).unwrap_or("");
    let code = query.get("code").map(String::as_str).unwrap_or("");
    let entries = match (subject, code) {
        ("Patient/person-123", "procedure-general") => {
            vec![fhir_entry(procedure(
                "procedure-person-123",
                subject,
                "completed",
                code,
            ))]
        }
        ("Patient/smoke-person", "procedure-general") => {
            vec![fhir_entry(procedure(
                "procedure-smoke",
                subject,
                "completed",
                code,
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn claim_response_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let patient = query.get("patient").map(String::as_str).unwrap_or("");
    let request = query.get("request").map(String::as_str).unwrap_or("");
    let entries = match (patient, request) {
        ("Patient/person-123", "ServiceRequest/referral-person-123") => {
            vec![fhir_entry(claim_response(
                "claim-response-person-123",
                patient,
                "active",
                "complete",
                "approved",
            ))]
        }
        ("Patient/smoke-person", "ServiceRequest/referral-person-123") => {
            vec![fhir_entry(claim_response(
                "claim-response-smoke",
                patient,
                "active",
                "complete",
                "approved",
            ))]
        }
        _ => Vec::new(),
    };
    Json(fhir_bundle(entries))
}

async fn audit_event_search(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_fhir_headers(&headers);
    let patient = query.get("patient").map(String::as_str).unwrap_or("");
    let entries = match patient {
        "Patient/person-123" => vec![fhir_entry(audit_event("audit-person-123", patient, "R"))],
        "Patient/smoke-person" => vec![fhir_entry(audit_event("audit-smoke", patient, "R"))],
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

fn coverage_eligibility_response(
    id: &str,
    patient: &str,
    status: &str,
    outcome: &str,
    service_type: &str,
) -> Value {
    json!({
        "resourceType": "CoverageEligibilityResponse",
        "id": id,
        "status": status,
        "outcome": outcome,
        "patient": { "reference": patient },
        "insurance": [{
            "item": [{
                "category": {
                    "coding": [{
                        "system": "http://terminology.hl7.org/CodeSystem/service-type",
                        "code": service_type
                    }]
                }
            }]
        }]
    })
}

fn episode_of_care(id: &str, patient: &str, status: &str, program_code: &str) -> Value {
    json!({
        "resourceType": "EpisodeOfCare",
        "id": id,
        "status": status,
        "patient": { "reference": patient },
        "type": [{
            "coding": [{
                "system": "https://example.gov/fhir/program-code",
                "code": program_code
            }]
        }]
    })
}

fn encounter(id: &str, patient: &str, status: &str, encounter_type: &str) -> Value {
    json!({
        "resourceType": "Encounter",
        "id": id,
        "status": status,
        "subject": { "reference": patient },
        "type": [{
            "coding": [{
                "system": "https://example.gov/fhir/encounter-type",
                "code": encounter_type
            }]
        }]
    })
}

fn service_request(id: &str, subject: &str, status: &str, code: &str) -> Value {
    json!({
        "resourceType": "ServiceRequest",
        "id": id,
        "status": status,
        "intent": "order",
        "subject": { "reference": subject },
        "code": {
            "coding": [{
                "system": "https://example.gov/fhir/referral-code",
                "code": code
            }]
        }
    })
}

fn appointment(id: &str, patient: &str, status: &str, service_type: &str) -> Value {
    json!({
        "resourceType": "Appointment",
        "id": id,
        "status": status,
        "participant": [{
            "actor": { "reference": patient },
            "status": "accepted"
        }],
        "serviceType": [{
            "coding": [{
                "system": "http://terminology.hl7.org/CodeSystem/service-type",
                "code": service_type
            }]
        }]
    })
}

fn medication_request(id: &str, subject: &str, status: &str, code: &str) -> Value {
    json!({
        "resourceType": "MedicationRequest",
        "id": id,
        "status": status,
        "intent": "order",
        "subject": { "reference": subject },
        "medicationCodeableConcept": {
            "coding": [{
                "system": "https://example.gov/fhir/medication-code",
                "code": code
            }]
        }
    })
}

fn diagnostic_report(id: &str, patient: &str, status: &str, code: &str) -> Value {
    json!({
        "resourceType": "DiagnosticReport",
        "id": id,
        "status": status,
        "subject": { "reference": patient },
        "code": {
            "coding": [{
                "system": "https://loinc.org",
                "code": code
            }]
        }
    })
}

fn observation_quantity(id: &str, subject: &str, status: &str, code: &str, value: i64) -> Value {
    json!({
        "resourceType": "Observation",
        "id": id,
        "status": status,
        "subject": { "reference": subject },
        "code": {
            "coding": [{
                "system": "https://loinc.org",
                "code": code
            }]
        },
        "valueQuantity": {
            "value": value,
            "unit": "copies/mL"
        },
        "effectiveDateTime": "2026-06-01T00:00:00Z"
    })
}

fn observation_code(id: &str, subject: &str, status: &str, code: &str, value_code: &str) -> Value {
    json!({
        "resourceType": "Observation",
        "id": id,
        "status": status,
        "subject": { "reference": subject },
        "code": {
            "coding": [{
                "system": "https://loinc.org",
                "code": code
            }]
        },
        "valueCodeableConcept": {
            "coding": [{
                "system": "https://example.gov/fhir/observation-value",
                "code": value_code
            }]
        },
        "effectiveDateTime": "2026-06-01T00:00:00Z"
    })
}

fn immunization(id: &str, patient: &str, status: &str, vaccine_code: &str) -> Value {
    json!({
        "resourceType": "Immunization",
        "id": id,
        "status": status,
        "patient": { "reference": patient },
        "vaccineCode": {
            "coding": [{
                "system": "http://hl7.org/fhir/sid/cvx",
                "code": vaccine_code
            }]
        },
        "occurrenceDateTime": "2026-01-15T00:00:00Z"
    })
}

fn provenance(id: &str, target: &str, recorded: &str, activity_code: &str) -> Value {
    json!({
        "resourceType": "Provenance",
        "id": id,
        "target": [{ "reference": target }],
        "recorded": recorded,
        "activity": {
            "coding": [{
                "system": "https://example.gov/fhir/provenance-activity",
                "code": activity_code
            }]
        }
    })
}

fn condition(id: &str, subject: &str, status: &str, code: &str) -> Value {
    json!({
        "resourceType": "Condition",
        "id": id,
        "subject": { "reference": subject },
        "clinicalStatus": {
            "coding": [{
                "system": "http://terminology.hl7.org/CodeSystem/condition-clinical",
                "code": status
            }]
        },
        "code": {
            "coding": [{
                "system": "https://example.gov/fhir/condition-code",
                "code": code
            }]
        }
    })
}

fn care_plan(id: &str, subject: &str, status: &str, category: &str) -> Value {
    json!({
        "resourceType": "CarePlan",
        "id": id,
        "status": status,
        "intent": "plan",
        "subject": { "reference": subject },
        "category": [{
            "coding": [{
                "system": "https://example.gov/fhir/care-plan-category",
                "code": category
            }]
        }]
    })
}

fn procedure(id: &str, subject: &str, status: &str, code: &str) -> Value {
    json!({
        "resourceType": "Procedure",
        "id": id,
        "status": status,
        "subject": { "reference": subject },
        "code": {
            "coding": [{
                "system": "https://example.gov/fhir/procedure-code",
                "code": code
            }]
        }
    })
}

fn claim_response(
    id: &str,
    patient: &str,
    status: &str,
    outcome: &str,
    disposition: &str,
) -> Value {
    json!({
        "resourceType": "ClaimResponse",
        "id": id,
        "status": status,
        "outcome": outcome,
        "patient": { "reference": patient },
        "disposition": disposition
    })
}

fn audit_event(id: &str, patient: &str, action: &str) -> Value {
    json!({
        "resourceType": "AuditEvent",
        "id": id,
        "type": {
            "system": "http://terminology.hl7.org/CodeSystem/audit-event-type",
            "code": "rest"
        },
        "action": action,
        "recorded": "2026-06-16T00:00:00Z",
        "entity": [{
            "what": { "reference": patient }
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
sources:
  fhir_coverage:
    dataset: health_registry
    entity: coverage
    engine: fhir
    batch:
      mode: parallel_lookup
      max_parallel: 2
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
  fhir_eligibility:
    dataset: health_registry
    entity: eligibility
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
        - id: eligibility
          resource_type: CoverageEligibilityResponse
          cardinality: one
          search:
            - param: patient
              type: reference
              value_from_node: patient.reference
            - param: service-type
              type: code
              value: general-practice
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        eligibility_status:
          node: eligibility
          pointer: /status
        eligibility_outcome:
          node: eligibility
          pointer: /outcome
        service_type:
          node: eligibility
          pointer: /insurance/0/item/0/category/coding/0/code
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
  fhir_program_enrollment:
    dataset: health_registry
    entity: program_enrollment
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
        - id: episode
          resource_type: EpisodeOfCare
          cardinality: one
          search:
            - param: patient
              type: reference
              value_from_node: patient.reference
            - param: type
              type: code
              value: tb-program
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        enrollment_status:
          node: episode
          pointer: /status
        program_code:
          node: episode
          pointer: /type/0/coding/0/code
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
  fhir_encounter:
    dataset: health_registry
    entity: encounter
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
        - id: encounter
          resource_type: Encounter
          cardinality: one
          search:
            - param: patient
              type: reference
              value_from_node: patient.reference
            - param: type
              type: code
              value: annual-wellness
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        encounter_status:
          node: encounter
          pointer: /status
        encounter_type:
          node: encounter
          pointer: /type/0/coding/0/code
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
  fhir_referral:
    dataset: health_registry
    entity: referral
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
        - id: referral
          resource_type: ServiceRequest
          cardinality: one
          search:
            - param: subject
              type: reference
              value_from_node: patient.reference
            - param: code
              type: code
              value: general-referral
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        referral_status:
          node: referral
          pointer: /status
        referral_code:
          node: referral
          pointer: /code/coding/0/code
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
  fhir_appointment:
    dataset: health_registry
    entity: appointment
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
        - id: appointment
          resource_type: Appointment
          cardinality: one
          search:
            - param: patient
              type: reference
              value_from_node: patient.reference
            - param: service-type
              type: code
              value: general-practice
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        appointment_status:
          node: appointment
          pointer: /status
        appointment_service_type:
          node: appointment
          pointer: /serviceType/0/coding/0/code
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
  fhir_lab_report:
    dataset: health_registry
    entity: lab_report
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
        - id: diagnostic_report
          resource_type: DiagnosticReport
          cardinality: one
          search:
            - param: patient
              type: reference
              value_from_node: patient.reference
            - param: code
              type: code
              value: viral-load-panel
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        diagnostic_report_status:
          node: diagnostic_report
          pointer: /status
        diagnostic_report_code:
          node: diagnostic_report
          pointer: /code/coding/0/code
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
  fhir_immunization:
    dataset: health_registry
    entity: immunization
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
        - id: immunization
          resource_type: Immunization
          cardinality: one
          search:
            - param: patient
              type: reference
              value_from_node: patient.reference
            - param: vaccine-code
              type: token
              value: http://hl7.org/fhir/sid/cvx|03
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        immunization_status:
          node: immunization
          pointer: /status
        vaccine_code:
          node: immunization
          pointer: /vaccineCode/coding/0/code
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
  fhir_source_trace:
    dataset: health_registry
    entity: source_trace
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
        - id: provenance
          resource_type: Provenance
          cardinality: one
          search:
            - param: target
              type: reference
              value_from_node: patient.reference
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        trace_id:
          node: provenance
          pointer: /id
        trace_activity:
          node: provenance
          pointer: /activity/coding/0/code
        trace_recorded:
          node: provenance
          pointer: /recorded
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
  fhir_prior_authorization:
    dataset: health_registry
    entity: prior_authorization
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
        - id: authorization
          resource_type: ClaimResponse
          cardinality: one
          search:
            - param: patient
              type: reference
              value_from_node: patient.reference
            - param: request
              type: reference
              value: ServiceRequest/referral-person-123
      project:
        national_id:
          node: patient
          pointer: /identifier/0/value
        authorization_status:
          node: authorization
          pointer: /status
        authorization_outcome:
          node: authorization
          pointer: /outcome
        authorization_disposition:
          node: authorization
          pointer: /disposition
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#,
        token_hash_env = yaml_string(TOKEN_HASH_ENV),
        upstream_token_env = yaml_string(UPSTREAM_TOKEN_ENV),
        fhir_url = yaml_string(&fhir_url),
    )
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serializes")
}
