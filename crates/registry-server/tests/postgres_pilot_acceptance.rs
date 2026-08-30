// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/pilot_acceptance_harness.rs"]
mod pilot_acceptance_harness;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::http::{Method, StatusCode};
use pilot_acceptance_harness::{response_bytes, response_json, PilotHarness};
use serde_json::{json, Value};

const FOREIGN_UUID: &str = "00000000-0000-4000-8000-000000000999";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_five_domain_pilot_is_configured_production_closed_and_source_neutral() {
    let asset = PilotHarness::start("asset-site-placement").await;
    asset_site_placement_journey(&asset).await;
    asset.finish().await;

    let household = PilotHarness::start("publicschema-household").await;
    household_journey(&household).await;
    household.finish().await;

    let disability = PilotHarness::start("disability").await;
    disability_journey(&disability).await;
    disability.finish().await;

    let farmer = PilotHarness::start("farmer").await;
    farmer_journey(&farmer).await;
    farmer.finish().await;

    let business = PilotHarness::start("business").await;
    business_journey(&business).await;
    business.finish().await;
}

async fn asset_site_placement_journey(harness: &PilotHarness) {
    let token = harness.token("asset-management", &[]);
    assert_fixture_surface(harness, "asset-operator", &token, "asset").await;
    let planner_token = harness.token("site-planning", &[]);
    let planner_openapi =
        assert_fixture_surface(harness, "site-planner", &planner_token, "asset").await;
    assert!(planner_openapi["paths"]
        .get("/v1/records/inspections")
        .is_none());
    assert!(planner_openapi["paths"]["/v1/records/assets"]
        .get("post")
        .is_none());
    assert!(
        planner_openapi["components"]["schemas"]["asset-item"]["properties"]
            .get("asset-class")
            .is_none()
    );

    let asset = create_record(
        harness,
        "/v1/records/assets",
        &token,
        "asset-create",
        json!({"asset-code":"A-100","label":"Portable pump","asset-class":"equipment"}),
    )
    .await;
    let old_site = create_record(
        harness,
        "/v1/records/sites",
        &token,
        "site-old-create",
        json!({"site-code":"S-OLD","label":"Old depot"}),
    )
    .await;
    let current_site = create_record(
        harness,
        "/v1/records/sites",
        &token,
        "site-current-create",
        json!({"site-code":"S-CURRENT","label":"Current depot"}),
    )
    .await;
    let old_placement = create_record(
        harness,
        "/v1/records/placements",
        &token,
        "placement-old-create",
        json!({
            "asset": asset.id,
            "site": old_site.id,
            "valid-from":"2020-01-01",
            "valid-to":"2021-01-01"
        }),
    )
    .await;
    let current_placement = create_record(
        harness,
        "/v1/records/placements",
        &token,
        "placement-current-create",
        json!({
            "asset": asset.id,
            "site": current_site.id,
            "valid-from":"2021-01-01"
        }),
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/placements:as-of?accessProfile=asset-operator&asOf=2020-12-31T23:59:59Z",
        Some(&token),
        &[&old_placement.id],
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/placements:as-of?accessProfile=asset-operator&asOf=2021-01-01T00:00:00Z",
        Some(&token),
        &[&current_placement.id],
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/placements:current?accessProfile=asset-operator",
        Some(&token),
        &[&current_placement.id],
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/placements:current?accessProfile=site-planner",
        Some(&planner_token),
        &[&current_placement.id],
    )
    .await;
    let wrong_purpose = harness
        .send(
            Method::GET,
            "/v1/records/placements:current?accessProfile=site-planner",
            Some(&token),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(wrong_purpose.status(), StatusCode::NOT_FOUND);

    let overlap = harness
        .send_json(
            Method::POST,
            "/v1/records/placements",
            Some(&token),
            Some("placement-overlap"),
            json!({
                "data":{
                    "asset":asset.id,
                    "site":old_site.id,
                    "valid-from":"2020-06-01",
                    "valid-to":"2021-06-01"
                }
            }),
        )
        .await;
    assert_eq!(overlap.status(), StatusCode::CONFLICT);

    let foreign_reference = harness
        .send_json(
            Method::POST,
            "/v1/records/placements",
            Some(&token),
            Some("placement-foreign-reference"),
            json!({
                "data":{
                    "asset":FOREIGN_UUID,
                    "site":current_site.id,
                    "valid-from":"2030-01-01"
                }
            }),
        )
        .await;
    assert_eq!(foreign_reference.status(), StatusCode::CONFLICT);

    let inspection = create_record(
        harness,
        "/v1/records/inspections",
        &token,
        "inspection-create",
        json!({
            "asset":asset.id,
            "observed-at":"2026-08-30T10:00:00Z",
            "result":"passed"
        }),
    )
    .await;
    assert_create_only_refuses_patch_and_tombstone(
        harness,
        "/v1/records/inspections",
        &inspection,
        &token,
    )
    .await;
    let event_count: i64 = harness
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_outbox WHERE event_type = 'inspection-created'",
            &[],
        )
        .await
        .expect("administrator samples the configured create event type")
        .get(0);
    assert_eq!(event_count, 1);
}

async fn household_journey(harness: &PilotHarness) {
    let token = harness.token("household-administration", &[]);
    let openapi = assert_fixture_surface(harness, "household-operator", &token, "household").await;
    assert_eq!(
        openapi["components"]["schemas"]["person"]["properties"]["residency-status"]
            ["x-registry-vocabulary"],
        "residency-status"
    );
    assert!(openapi["components"]["schemas"]["person"]["properties"]
        .get("preferred-language")
        .is_some());

    let person = create_record(
        harness,
        "/v1/records/persons",
        &token,
        "person-create",
        json!({
            "person-code":"P-100",
            "legal-name":"Ada North",
            "family-name":"North",
            "date-of-birth":"1990-04-03",
            "residency-status":"usual-resident",
            "preferred-language":"en"
        }),
    )
    .await;
    assert_eq!(person.body["data"]["residency-status"], "usual-resident");
    assert_eq!(person.body["data"]["preferred-language"], "en");
    let old_household = create_record(
        harness,
        "/v1/records/households",
        &token,
        "household-old-create",
        json!({
            "household-code":"H-OLD",
            "household-name":"Old household",
            "administrative-area":"north",
            "household-type":"private"
        }),
    )
    .await;
    let current_household = create_record(
        harness,
        "/v1/records/households",
        &token,
        "household-current-create",
        json!({
            "household-code":"H-CURRENT",
            "household-name":"Current household",
            "administrative-area":"north",
            "household-type":"private"
        }),
    )
    .await;
    let old_membership = create_record(
        harness,
        "/v1/records/group-memberships",
        &token,
        "membership-old-create",
        json!({
            "person":person.id,
            "household":old_household.id,
            "relationship":"head",
            "valid-from":"2019-01-01",
            "valid-to":"2022-01-01"
        }),
    )
    .await;
    let current_membership = create_record(
        harness,
        "/v1/records/group-memberships",
        &token,
        "membership-current-create",
        json!({
            "person":person.id,
            "household":current_household.id,
            "relationship":"head",
            "valid-from":"2022-01-01"
        }),
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/group-memberships:as-of?accessProfile=household-operator&asOf=2021-12-31T23:59:59Z",
        Some(&token),
        &[&old_membership.id],
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/group-memberships:current?accessProfile=household-operator",
        Some(&token),
        &[&current_membership.id],
    )
    .await;

    let overlap = harness
        .send_json(
            Method::POST,
            "/v1/records/group-memberships",
            Some(&token),
            Some("membership-overlap"),
            json!({"data":{
                "person":person.id,
                "household":old_household.id,
                "relationship":"dependent",
                "valid-from":"2021-06-01",
                "valid-to":"2023-01-01"
            }}),
        )
        .await;
    assert_eq!(overlap.status(), StatusCode::CONFLICT);
}

async fn disability_journey(harness: &PilotHarness) {
    let token = harness.token("disability-assessment", &[]);
    let openapi =
        assert_fixture_surface(harness, "disability-caseworker", &token, "disability").await;
    assert_eq!(
        openapi["components"]["schemas"]["functioning-observation"]["properties"]
            ["observation-schema-metadata"]["additionalProperties"],
        false
    );
    let concealed_schema = harness
        .send(
            Method::GET,
            "/openapi.json?accessProfile=disability-caseworker",
            None,
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(concealed_schema.status(), StatusCode::NOT_FOUND);

    let assessment = create_record(
        harness,
        "/v1/records/assessment-episodes",
        &token,
        "assessment-create",
        json!({
            "episode-code":"EP-100",
            "subject-code":"SUBJECT-100",
            "opened-on":"2026-01-10",
            "assessment-source":"case-management"
        }),
    )
    .await;
    let invalid_range = harness
        .send_json(
            Method::POST,
            "/v1/records/functioning-observations",
            Some(&token),
            Some("observation-invalid-range"),
            json!({"data":{
                "assessment-episode":assessment.id,
                "observed-at":"2026-01-11T09:00:00Z",
                "functioning-domain":"mobility",
                "severity-score":5,
                "observation-schema-metadata":{
                    "schemaVersion":"1","vocabularyRelease":"2026-01","scoringScale":"zero-to-four"
                }
            }}),
        )
        .await;
    assert_eq!(invalid_range.status(), StatusCode::CONFLICT);
    let invalid_structure = harness
        .send_json(
            Method::POST,
            "/v1/records/functioning-observations",
            Some(&token),
            Some("observation-invalid-structure"),
            json!({"data":{
                "assessment-episode":assessment.id,
                "observed-at":"2026-01-11T09:00:00Z",
                "functioning-domain":"mobility",
                "severity-score":3,
                "observation-schema-metadata":{
                    "schemaVersion":"1","vocabularyRelease":"2026-01",
                    "scoringScale":"zero-to-four","undeclared":"refused"
                }
            }}),
        )
        .await;
    assert_eq!(invalid_structure.status(), StatusCode::BAD_REQUEST);
    let observation = create_record(
        harness,
        "/v1/records/functioning-observations",
        &token,
        "observation-create",
        json!({
            "assessment-episode":assessment.id,
            "observed-at":"2026-01-11T09:00:00Z",
            "functioning-domain":"mobility",
            "severity-score":3,
            "observation-schema-metadata":{
                "schemaVersion":"1","vocabularyRelease":"2026-01","scoringScale":"zero-to-four"
            }
        }),
    )
    .await;
    assert_eq!(observation.body["data"]["severity-score"], 3);

    let original = create_record(
        harness,
        "/v1/records/certifications",
        &token,
        "certification-original",
        json!({
            "certification-code":"CERT-100",
            "assessment-episode":assessment.id,
            "certification-status":"corrected",
            "valid-from":"2026-01-01",
            "valid-to":"2026-07-01",
            "validity-source":"review-board"
        }),
    )
    .await;
    let correction = create_record(
        harness,
        "/v1/records/certifications",
        &token,
        "certification-correction",
        json!({
            "certification-code":"CERT-101",
            "assessment-episode":assessment.id,
            "certification-status":"active",
            "valid-from":"2026-07-01",
            "corrected-certification":original.id,
            "correction-reason":"reviewed correction",
            "validity-source":"review-board",
            "provenance-note":"signed review packet"
        }),
    )
    .await;
    assert_eq!(
        correction.body["data"]["corrected-certification"],
        original.id
    );
    assert!(correction.body["data"]["correction-reason"].is_string());
    assert!(correction.body["data"]["provenance-note"].is_string());
    assert_create_only_refuses_patch_and_tombstone(
        harness,
        "/v1/records/certifications",
        &correction,
        &token,
    )
    .await;

    let anonymous = harness
        .send(
            Method::GET,
            &format!("/v1/records/certifications/{}", correction.id),
            None,
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(anonymous.status(), StatusCode::NOT_FOUND);
    assert_eq!(response_json(anonymous).await["code"], "resource.not_found");
}

async fn farmer_journey(harness: &PilotHarness) {
    let north_token = harness.token(
        "farmer-registry",
        &[("administrative_boundaries", json!(["north-district"]))],
    );
    let south_token = harness.token(
        "farmer-registry",
        &[("administrative_boundaries", json!(["south-district"]))],
    );
    let openapi = assert_fixture_surface(harness, "farmer-operator", &north_token, "farmer").await;
    assert_eq!(
        openapi["paths"]["/v1/records/plots:batch"]["post"]["x-registry-maximumItems"],
        4
    );
    let ddl = harness.registry.ddl().script().to_ascii_lowercase();
    assert!(!ddl.contains("postgis"));
    assert!(!ddl.contains("geometry"));
    assert!(!ddl.contains("geography"));
    let postgis_count: i64 = harness
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_extension WHERE extname = 'postgis'",
            &[],
        )
        .await
        .expect("administrator samples installed extension inventory")
        .get(0);
    assert_eq!(postgis_count, 0);

    let north_farmer = create_record(
        harness,
        "/v1/records/farmers",
        &north_token,
        "north-farmer",
        json!({
            "farmer-code":"F-NORTH","display-name":"North operator",
            "administrative-boundary":"north-district"
        }),
    )
    .await;
    let south_farmer = create_record(
        harness,
        "/v1/records/farmers",
        &south_token,
        "south-farmer",
        json!({
            "farmer-code":"F-SOUTH","display-name":"South operator",
            "administrative-boundary":"south-district"
        }),
    )
    .await;
    let concealed = harness
        .send(
            Method::GET,
            &format!(
                "/v1/records/farmers/{}?accessProfile=farmer-operator",
                south_farmer.id
            ),
            Some(&north_token),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(concealed.status(), StatusCode::NOT_FOUND);
    let north_list = response_json(
        harness
            .send(
                Method::GET,
                "/v1/records/farmers?accessProfile=farmer-operator",
                Some(&north_token),
                &[],
                Vec::new(),
            )
            .await,
    )
    .await;
    let north_ids = item_ids(&north_list);
    assert!(north_ids.contains(&north_farmer.id.as_str()));
    assert!(!north_ids.contains(&south_farmer.id.as_str()));

    let old_holding = create_record(
        harness,
        "/v1/records/holdings",
        &north_token,
        "holding-old",
        json!({
            "holding-code":"H-NORTH","farmer":north_farmer.id,"tenure-type":"leased",
            "tenure-start":"2020-01-01","tenure-end":"2024-01-01",
            "administrative-boundary":"north-district","import-source":"survey-a",
            "source-record-id":"holding-old"
        }),
    )
    .await;
    let current_holding = create_record(
        harness,
        "/v1/records/holdings",
        &north_token,
        "holding-current",
        json!({
            "holding-code":"H-NORTH","farmer":north_farmer.id,"tenure-type":"owned",
            "tenure-start":"2024-01-01","administrative-boundary":"north-district",
            "import-source":"survey-a","source-record-id":"holding-current"
        }),
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/holdings:as-of?accessProfile=farmer-operator&asOf=2023-12-31T23:59:59Z",
        Some(&north_token),
        &[&old_holding.id],
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/holdings:current?accessProfile=farmer-operator",
        Some(&north_token),
        &[&current_holding.id],
    )
    .await;

    let invalid_point = harness
        .send_json(
            Method::POST,
            "/v1/records/plots",
            Some(&north_token),
            Some("plot-invalid-point"),
            json!({"data":{
                "plot-code":"P-BAD-POINT","holding":current_holding.id,
                "administrative-boundary":"north-district",
                "centroid":{"type":"Point","coordinates":[32.0,-9.5]},
                "area-value":"1.2500","area-unit":"hectare",
                "import-source":"survey-a","source-record-id":"plot-bad-point"
            }}),
        )
        .await;
    assert_eq!(invalid_point.status(), StatusCode::BAD_REQUEST);
    let invalid_decimal = harness
        .send_json(
            Method::POST,
            "/v1/records/plots",
            Some(&north_token),
            Some("plot-invalid-decimal"),
            json!({"data":{
                "plot-code":"P-BAD-DECIMAL","holding":current_holding.id,
                "administrative-boundary":"north-district",
                "centroid":{"type":"Point","coordinates":[30.5,-9.5]},
                "area-value":"01.2500","area-unit":"hectare",
                "import-source":"survey-a","source-record-id":"plot-bad-decimal"
            }}),
        )
        .await;
    assert_eq!(invalid_decimal.status(), StatusCode::BAD_REQUEST);
    let plot = create_record(
        harness,
        "/v1/records/plots",
        &north_token,
        "plot-create",
        json!({
            "plot-code":"P-NORTH","holding":current_holding.id,
            "administrative-boundary":"north-district",
            "centroid":{"type":"Point","coordinates":[30.5,-9.5]},
            "area-value":"1.2500","area-unit":"hectare",
            "import-source":"survey-a","source-record-id":"plot-primary"
        }),
    )
    .await;
    assert_eq!(plot.body["data"]["area-value"], "1.2500");
    assert_eq!(plot.body["data"]["area-unit"], "hectare");

    let old_activity = create_record(
        harness,
        "/v1/records/seasonal-activities",
        &north_token,
        "activity-old",
        json!({
            "plot":plot.id,"administrative-boundary":"north-district",
            "activity-type":"planting","season-start":"2024-01-01","season-end":"2024-07-01",
            "quantity-value":"12.500","quantity-unit":"kilogram"
        }),
    )
    .await;
    let current_activity = create_record(
        harness,
        "/v1/records/seasonal-activities",
        &north_token,
        "activity-current",
        json!({
            "plot":plot.id,"administrative-boundary":"north-district",
            "activity-type":"planting","season-start":"2024-07-01",
            "quantity-value":"8.250","quantity-unit":"kilogram"
        }),
    )
    .await;
    assert_eq!(current_activity.body["data"]["quantity-value"], "8.250");
    assert_list_ids(
        harness,
        "/v1/records/seasonal-activities:as-of?accessProfile=farmer-operator&asOf=2024-06-30T23:59:59Z",
        Some(&north_token),
        &[&old_activity.id],
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/seasonal-activities:current?accessProfile=farmer-operator",
        Some(&north_token),
        &[&current_activity.id],
    )
    .await;

    let batch_body = json!({"items":[{"operation":"create","data":{
        "plot-code":"P-BATCH","holding":current_holding.id,
        "administrative-boundary":"north-district",
        "centroid":{"type":"Point","coordinates":[30.75,-9.25]},
        "area-value":"2.0000","area-unit":"hectare",
        "import-source":"survey-b","source-record-id":"plot-batch"
    }}]});
    let first_batch = harness
        .send_json(
            Method::POST,
            "/v1/records/plots:batch",
            Some(&north_token),
            Some("plot-batch"),
            batch_body.clone(),
        )
        .await;
    assert_eq!(first_batch.status(), StatusCode::OK);
    let first_batch_bytes = response_bytes(first_batch).await;
    let replay = harness
        .send_json(
            Method::POST,
            "/v1/records/plots:batch",
            Some(&north_token),
            Some("plot-batch"),
            batch_body,
        )
        .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(replay).await, first_batch_bytes);

    let duplicate_import = harness
        .send_json(
            Method::POST,
            "/v1/records/plots",
            Some(&north_token),
            Some("plot-duplicate-import"),
            json!({"data":{
                "plot-code":"P-DUPLICATE","holding":current_holding.id,
                "administrative-boundary":"north-district",
                "centroid":{"type":"Point","coordinates":[30.8,-9.2]},
                "area-value":"3.0000","area-unit":"hectare",
                "import-source":"survey-b","source-record-id":"plot-batch"
            }}),
        )
        .await;
    assert_eq!(duplicate_import.status(), StatusCode::CONFLICT);
}

async fn business_journey(harness: &PilotHarness) {
    let token = harness.token("business-registry", &[]);
    assert_fixture_surface(harness, "business-registrar", &token, "business").await;
    let legal_entity = create_record(
        harness,
        "/v1/records/legal-entities",
        &token,
        "legal-entity-create",
        json!({
            "jurisdiction-code":"XY","registration-number":"10001",
            "legal-name":"Example Cooperative","entity-status":"active",
            "public-service-address":"Public office",
            "protected-contact":"protected-contact@example.test",
            "protected-ownership-reference":"ownership-10001",
            "internal-case-note":"registrar review complete"
        }),
    )
    .await;
    let public = response_json(
        harness
            .send(
                Method::GET,
                &format!("/v1/records/legal-entities/{}", legal_entity.id),
                None,
                &[],
                Vec::new(),
            )
            .await,
    )
    .await;
    assert_eq!(public["data"]["legal-name"], "Example Cooperative");
    assert!(public["data"].get("protected-contact").is_none());
    assert!(public["data"]
        .get("protected-ownership-reference")
        .is_none());
    assert!(public["data"].get("internal-case-note").is_none());
    let protected = response_json(
        harness
            .send(
                Method::GET,
                &format!(
                    "/v1/records/legal-entities/{}?accessProfile=business-registrar",
                    legal_entity.id
                ),
                Some(&token),
                &[],
                Vec::new(),
            )
            .await,
    )
    .await;
    assert!(protected["data"]["protected-contact"].is_string());
    assert!(protected["data"]["protected-ownership-reference"].is_string());
    assert!(protected["data"]["internal-case-note"].is_string());

    let duplicate_identifier = harness
        .send_json(
            Method::POST,
            "/v1/records/legal-entities",
            Some(&token),
            Some("legal-entity-duplicate"),
            json!({"data":{
                "jurisdiction-code":"XY","registration-number":"10001",
                "legal-name":"Duplicate","entity-status":"active"
            }}),
        )
        .await;
    assert_eq!(duplicate_identifier.status(), StatusCode::CONFLICT);

    let filing = create_record(
        harness,
        "/v1/records/filings",
        &token,
        "filing-create",
        json!({
            "legal-entity":legal_entity.id,"filing-number":"F-100",
            "filing-type":"incorporation","filed-date":"2020-01-01",
            "source-system":"registrar","source-record-id":"filing-100",
            "provenance-note":"accepted filing"
        }),
    )
    .await;
    assert_create_only_refuses_patch_and_tombstone(harness, "/v1/records/filings", &filing, &token)
        .await;

    let historical = create_record(
        harness,
        "/v1/records/officer-appointments",
        &token,
        "appointment-historical",
        json!({
            "legal-entity":legal_entity.id,"officer-code":"OFFICER-A",
            "officer-name":"First Director","officer-role":"director",
            "effective-from":"2020-01-01","effective-to":"2022-01-01",
            "protected-officer-id":"protected-a"
        }),
    )
    .await;
    let current = create_record(
        harness,
        "/v1/records/officer-appointments",
        &token,
        "appointment-current",
        json!({
            "legal-entity":legal_entity.id,"officer-code":"OFFICER-A",
            "officer-name":"First Director","officer-role":"director",
            "effective-from":"2022-01-01","protected-officer-id":"protected-a"
        }),
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/officer-appointments:as-of?asOf=2021-12-31T23:59:59Z",
        None,
        &[&historical.id],
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/officer-appointments:as-of?asOf=2022-01-01T00:00:00Z",
        None,
        &[&current.id],
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/officer-appointments:current",
        None,
        &[&current.id],
    )
    .await;

    let partial_unique = harness
        .send_json(
            Method::POST,
            "/v1/records/officer-appointments",
            Some(&token),
            Some("appointment-partial-unique"),
            json!({"data":{
                "legal-entity":legal_entity.id,"officer-code":"OFFICER-B",
                "officer-name":"Second Director","officer-role":"director",
                "effective-from":"2023-01-01"
            }}),
        )
        .await;
    assert_eq!(partial_unique.status(), StatusCode::CONFLICT);
    let overlap = harness
        .send_json(
            Method::POST,
            "/v1/records/officer-appointments",
            Some(&token),
            Some("appointment-overlap"),
            json!({"data":{
                "legal-entity":legal_entity.id,"officer-code":"OFFICER-A",
                "officer-name":"First Director","officer-role":"secretary",
                "effective-from":"2021-01-01","effective-to":"2023-01-01"
            }}),
        )
        .await;
    assert_eq!(overlap.status(), StatusCode::CONFLICT);
}

async fn assert_fixture_surface(
    harness: &PilotHarness,
    profile: &str,
    token: &str,
    active_family: &str,
) -> Value {
    let response = harness
        .send(
            Method::GET,
            &format!("/openapi.json?accessProfile={profile}"),
            Some(token),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let openapi = response_json(response).await;
    let families = [
        ("asset", "/v1/records/assets", "asset-item"),
        ("household", "/v1/records/persons", "person"),
        ("household", "/v1/records/households", "household"),
        (
            "disability",
            "/v1/records/assessment-episodes",
            "assessment-episode",
        ),
        ("farmer", "/v1/records/farmers", "farmer"),
        ("business", "/v1/records/legal-entities", "legal-entity"),
    ];
    for (family, route, schema) in families {
        if family == active_family {
            assert!(openapi["paths"].get(route).is_some());
            assert!(openapi["components"]["schemas"].get(schema).is_some());
        } else {
            assert!(openapi["paths"].get(route).is_none());
            assert!(openapi["components"]["schemas"].get(schema).is_none());
            let foreign_http = harness
                .send(Method::GET, route, Some(token), &[], Vec::new())
                .await;
            assert_eq!(foreign_http.status(), StatusCode::NOT_FOUND);
        }
    }
    openapi
}

async fn assert_list_ids(
    harness: &PilotHarness,
    uri: &str,
    token: Option<&str>,
    expected: &[&str],
) {
    let response = harness.send(Method::GET, uri, token, &[], Vec::new()).await;
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    let body = response_json(response).await;
    assert_eq!(item_ids(&body), expected, "{uri}");
}

fn item_ids(body: &Value) -> Vec<&str> {
    body["items"]
        .as_array()
        .expect("temporal/list response has items")
        .iter()
        .map(|item| item["id"].as_str().expect("listed item has id"))
        .collect()
}

async fn assert_create_only_refuses_patch_and_tombstone(
    harness: &PilotHarness,
    collection: &str,
    record: &CreatedRecord,
    token: &str,
) {
    let target = format!("{collection}/{}", record.id);
    let patch = harness
        .send(
            Method::PATCH,
            &target,
            Some(token),
            &[
                ("content-type", "application/json-patch+json"),
                ("idempotency-key", "create-only-patch"),
                ("if-match", &record.etag),
            ],
            br#"[{"op":"replace","path":"/data/provenance-note","value":"refused"}]"#.to_vec(),
        )
        .await;
    assert_eq!(patch.status(), StatusCode::NOT_FOUND);
    let tombstone = harness
        .send(
            Method::DELETE,
            &target,
            Some(token),
            &[
                ("idempotency-key", "create-only-tombstone"),
                ("if-match", &record.etag),
            ],
            Vec::new(),
        )
        .await;
    assert_eq!(tombstone.status(), StatusCode::NOT_FOUND);
}

struct CreatedRecord {
    id: String,
    etag: String,
    body: Value,
}

async fn create_record(
    harness: &PilotHarness,
    uri: &str,
    token: &str,
    idempotency_key: &str,
    data: Value,
) -> CreatedRecord {
    let response = harness
        .send_json(
            Method::POST,
            uri,
            Some(token),
            Some(idempotency_key),
            json!({"data":data}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED, "{uri}");
    let etag = response
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .expect("created record has a strong ETag")
        .to_owned();
    let body = response_json(response).await;
    let id = body["id"]
        .as_str()
        .expect("created record has a server UUID")
        .to_owned();
    CreatedRecord { id, etag, body }
}
