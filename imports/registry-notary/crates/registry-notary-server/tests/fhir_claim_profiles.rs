// SPDX-License-Identifier: Apache-2.0
//! End-to-end checks that the FHIR demo claim profiles evaluate over
//! minimized sidecar facts.

use axum::extract::{Path, Query};
#[cfg(feature = "registry-notary-cel")]
use axum::http::StatusCode;
use axum::{Json, Router};
use axum_test::TestServer;
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_notary_server::standalone_router;
use registry_platform_authcommon::{
    credential_fingerprint_commitment, fingerprint_api_key, CredentialCommitmentContext,
    CredentialProduct, CredentialType,
};
use serde_json::{json, Value};
use std::collections::HashMap;
#[cfg(feature = "registry-notary-cel")]
use std::path::PathBuf;

const API_KEY: &str = "fhir-claim-profile-test-api-key";
const AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
const SIDECAR_TOKEN: &str = "fhir-claim-profile-sidecar-token";
const PURPOSE: &str = "https://purpose.example.test/coverage";

#[cfg(feature = "registry-notary-cel")]
fn cel_worker_bin() -> PathBuf {
    let env_path = PathBuf::from(env!("CARGO_BIN_EXE_registry-notary-cel-worker"));
    if env_path
        .parent()
        .and_then(|parent| parent.file_name())
        .is_some_and(|file_name| file_name == "deps")
    {
        let candidate = env_path
            .parent()
            .and_then(|parent| parent.parent())
            .expect("target debug dir")
            .join("registry-notary-cel-worker");
        if candidate.is_file() {
            return candidate;
        }
    }
    env_path
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn fhir_demo_claim_profiles_evaluate_against_minimized_source_facts() {
    let sidecar = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/{dataset}/entities/{entity}/records",
            axum::routing::get(mock_sidecar_records),
        ));
    let notary = TestServer::builder().http_transport().build(
        standalone_router(fhir_demo_config(
            sidecar.server_address().expect("sidecar address").as_str(),
        ))
        .expect("notary router builds"),
    );

    let person_claims = [
        "coverage-active",
        "provider-affiliated-with-facility",
        "patient-record-exists",
        "age-over-18",
        "not-recorded-deceased",
        "coverage-eligibility-confirmed",
        "enrolled-in-program",
        "encounter-completed",
        "referral-active",
        "appointment-booked",
        "lab-result-available",
        "vaccination-recorded",
        "prior-authorization-approved",
        "source-trace-available",
        "requester-guardian-confirmed",
    ];
    for claim_id in person_claims.iter().copied() {
        assert_claim_satisfied(
            &notary,
            claim_id,
            json!({
                "requester": { "type": "Person", "id": "guardian-1" },
                "target": { "type": "Person", "id": "person-123" },
                "relationship": { "type": "guardian" },
                "claims": [claim_id],
                "purpose": PURPOSE
            }),
        )
        .await;
    }
    assert_claims_satisfied(
        &notary,
        &person_claims,
        json!({
            "requester": { "type": "Person", "id": "guardian-1" },
            "target": { "type": "Person", "id": "person-123" },
            "relationship": { "type": "guardian" },
            "claims": person_claims,
            "purpose": PURPOSE
        }),
    )
    .await;
    let batch_notary = TestServer::builder().http_transport().build(
        standalone_router(fhir_demo_config_with_batch(
            sidecar.server_address().expect("sidecar address").as_str(),
        ))
        .expect("batch notary router builds"),
    );
    let response = batch_notary
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", API_KEY)
        .json(&json!({
            "claims": person_claims,
            "purpose": PURPOSE,
            "items": [
                {
                    "requester": { "type": "Person", "id": "guardian-1" },
                    "target": { "type": "Person", "id": "person-123" },
                    "relationship": { "type": "guardian" }
                },
                {
                    "requester": { "type": "Person", "id": "guardian-1" },
                    "target": { "type": "Person", "id": "person-123" },
                    "relationship": { "type": "guardian" }
                }
            ]
        }))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::OK,
        "unexpected batch evaluation body: {}",
        response.text()
    );
    let batch_body: Value = response.json();
    assert_eq!(batch_body["summary"]["succeeded"], json!(2));
    assert_eq!(batch_body["summary"]["failed"], json!(0));
    for item in batch_body["items"].as_array().expect("batch items") {
        assert_eq!(item["status"], "succeeded");
        assert_eq!(
            item["claim_results"]
                .as_array()
                .expect("batch item claim results")
                .len(),
            person_claims.len()
        );
    }

    let facility_claims = ["facility-offers-service"];
    assert_claim_satisfied(
        &notary,
        facility_claims[0],
        json!({
            "target": { "type": "Organization", "id": "facility-1" },
            "claims": facility_claims,
            "purpose": PURPOSE
        }),
    )
    .await;
}

#[tokio::test]
async fn fhir_demo_claim_profiles_fail_closed_when_source_facts_are_absent() {
    let sidecar = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/{dataset}/entities/{entity}/records",
            axum::routing::get(mock_sidecar_records),
        ));
    let notary = TestServer::builder().http_transport().build(
        standalone_router(fhir_demo_config(
            sidecar.server_address().expect("sidecar address").as_str(),
        ))
        .expect("notary router builds"),
    );

    let response = notary
        .post("/v1/evaluations")
        .add_header("x-api-key", API_KEY)
        .json(&json!({
            "target": { "type": "Person", "id": "missing-person" },
            "claims": ["coverage-active"],
            "purpose": PURPOSE
        }))
        .await;

    response.assert_status_conflict();
    let body: Value = response.json();
    assert_eq!(body["code"], "evidence.not_available");
}

fn fhir_demo_config(sidecar_base_url: &str) -> StandaloneRegistryNotaryConfig {
    let fingerprint = fingerprint_api_key(API_KEY);
    let commitment = credential_fingerprint_commitment(
        CredentialCommitmentContext {
            product: CredentialProduct::RegistryNotary,
            credential_type: CredentialType::ApiKey,
            credential_id: "verification_service",
        },
        &fingerprint,
    );
    std::env::set_var("REGISTRY_NOTARY_API_KEY_HASH", fingerprint);
    std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", AUDIT_SECRET);
    std::env::set_var("FHIR_SIDECAR_TOKEN", SIDECAR_TOKEN);
    #[cfg(feature = "registry-notary-cel")]
    std::env::set_var("REGISTRY_NOTARY_CEL_WORKER_COMMAND", cel_worker_bin());

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("demo/config/fhir-coverage-registry-notary.yaml");
    let raw = std::fs::read_to_string(config_path).expect("FHIR demo config reads");
    let mut config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(&raw).expect("FHIR demo config parses");
    config.auth.api_keys[0].fingerprint.commitment = commitment;
    config
        .evidence
        .source_connections
        .get_mut("fhir_sidecar")
        .expect("FHIR sidecar source exists")
        .base_url = sidecar_base_url.trim_end_matches('/').to_string();
    config
        .evidence
        .source_connections
        .get_mut("fhir_sidecar")
        .expect("FHIR sidecar source exists")
        .expected_sidecar = None;
    config.cel.eval_timeout_ms = 10_000;
    let audit_path = std::env::temp_dir().join(format!(
        "registry-notary-fhir-claim-profiles-{}-{}.jsonl",
        std::process::id(),
        ulid::Ulid::new()
    ));
    config.audit.path = Some(audit_path.to_string_lossy().into_owned());
    config
}

#[cfg(feature = "registry-notary-cel")]
fn fhir_demo_config_with_batch(sidecar_base_url: &str) -> StandaloneRegistryNotaryConfig {
    let mut config = fhir_demo_config(sidecar_base_url);
    for claim in &mut config.evidence.claims {
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 10;
    }
    config
}

async fn mock_sidecar_records(
    Path((_dataset, entity)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    if query
        .iter()
        .any(|(field, value)| field != "fields" && field != "limit" && value == "missing-person")
    {
        return Json(json!({ "data": [] }));
    }

    let row = match entity.as_str() {
        "coverage" => json!({
            "national_id": "person-123",
            "coverage_status": "active",
            "coverage_class": "gold"
        }),
        "provider_affiliation" => json!({
            "provider_id": "person-123",
            "organization_ref": "Organization/org-1"
        }),
        "facility_service" => json!({
            "organization_id": "facility-1",
            "service_active": true
        }),
        "patient" => json!({
            "national_id": "person-123",
            "patient_id": "person-123",
            "birth_date": "1990-01-01",
            "deceased": false
        }),
        "eligibility" => json!({
            "national_id": "person-123",
            "eligibility_status": "active",
            "eligibility_outcome": "complete",
            "service_type": "general-practice"
        }),
        "program_enrollment" => json!({
            "national_id": "person-123",
            "enrollment_status": "active",
            "program_code": "tb-program"
        }),
        "encounter" => json!({
            "national_id": "person-123",
            "encounter_status": "finished",
            "encounter_type": "annual-wellness"
        }),
        "referral" => json!({
            "national_id": "person-123",
            "referral_status": "active",
            "referral_code": "general-referral"
        }),
        "appointment" => json!({
            "national_id": "person-123",
            "appointment_status": "booked",
            "appointment_service_type": "general-practice"
        }),
        "lab_report" => json!({
            "national_id": "person-123",
            "diagnostic_report_status": "final",
            "diagnostic_report_code": "viral-load-panel"
        }),
        "immunization" => json!({
            "national_id": "person-123",
            "immunization_status": "completed",
            "vaccine_code": "03"
        }),
        "prior_authorization" => json!({
            "national_id": "person-123",
            "authorization_status": "active",
            "authorization_outcome": "complete",
            "authorization_disposition": "approved"
        }),
        "source_trace" => json!({
            "national_id": "person-123",
            "trace_id": "provenance-person-123",
            "trace_activity": "verify"
        }),
        "guardian" => json!({
            "national_id": "person-123",
            "requester_id": "guardian-1",
            "relationship_code": "GUARD"
        }),
        _ => return Json(json!({ "data": [] })),
    };
    Json(json!({ "data": [row] }))
}

#[cfg(feature = "registry-notary-cel")]
async fn assert_claim_satisfied(notary: &TestServer, claim_id: &str, request: Value) {
    assert_claims_satisfied(notary, &[claim_id], request).await;
}

#[cfg(feature = "registry-notary-cel")]
async fn assert_claims_satisfied(notary: &TestServer, claim_ids: &[&str], request: Value) {
    let response = notary
        .post("/v1/evaluations")
        .add_header("x-api-key", API_KEY)
        .json(&request)
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::OK,
        "unexpected evaluation body for {claim_ids:?}: {}",
        response.text()
    );
    assert_all_results_satisfied(response.json(), claim_ids);
}

#[cfg(feature = "registry-notary-cel")]
fn assert_all_results_satisfied(body: Value, claim_ids: &[&str]) {
    let results = body["results"].as_array().expect("results array");
    assert_eq!(results.len(), claim_ids.len(), "unexpected result count");
    for claim_id in claim_ids {
        let result = results
            .iter()
            .find(|result| result["claim_id"] == json!(claim_id))
            .unwrap_or_else(|| panic!("missing result for {claim_id}"));
        assert_eq!(
            result["satisfied"], true,
            "claim {claim_id} is not satisfied"
        );
        assert_eq!(result["value"], true, "claim {claim_id} value is not true");
    }
}
