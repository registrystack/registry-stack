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

    let business = PilotHarness::start("business-establishments").await;
    establishments_journey(&business).await;
    business.finish().await;

    let inspection = PilotHarness::start("inspection").await;
    inspection_journey(&inspection).await;
    inspection.finish().await;

    let facility = PilotHarness::start("facility").await;
    facility_journey(&facility).await;
    facility.finish().await;

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
            .get("assetClass")
            .is_none()
    );

    let asset = create_record(
        harness,
        "/v1/records/assets",
        &token,
        "asset-create",
        json!({"assetCode":"A-100","label":"Portable pump","assetClass":"equipment"}),
    )
    .await;
    let old_site = create_record(
        harness,
        "/v1/records/sites",
        &token,
        "site-old-create",
        json!({"siteCode":"S-OLD","label":"Old depot"}),
    )
    .await;
    let current_site = create_record(
        harness,
        "/v1/records/sites",
        &token,
        "site-current-create",
        json!({"siteCode":"S-CURRENT","label":"Current depot"}),
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
            "validFrom":"2020-01-01",
            "validTo":"2021-01-01"
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
            "validFrom":"2021-01-01"
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
                    "validFrom":"2020-06-01",
                    "validTo":"2021-06-01"
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
                    "validFrom":"2030-01-01"
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
            "observedAt":"2026-08-30T10:00:00Z",
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
}

async fn establishments_journey(harness: &PilotHarness) {
    let token = harness.token_with_scopes(
        "business-administration",
        &[],
        &["registry:business:operate"],
    );
    let openapi =
        assert_fixture_surface(harness, "business-operator", &token, "establishments").await;
    assert_eq!(
        openapi["components"]["schemas"]["establishment"]["properties"]["operatingStatus"]
            ["x-registry-vocabulary"],
        "operating-status"
    );
    assert_eq!(
        openapi["components"]["schemas"]["establishment"]["properties"]["preferredLanguage"]
            ["x-registry-vocabulary"],
        "preferred-language"
    );

    let establishment = create_record(
        harness,
        "/v1/records/establishments",
        &token,
        "establishment-create",
        json!({
            "establishmentCode":"P-100",
            "siteName":"North Industrial Works",
            "locality":"North",
            "openedOn":"1990-04-03",
            "establishmentKind":"production",
            "operatingStatus":"operating",
            "preferredLanguage":"en"
        }),
    )
    .await;
    assert_eq!(establishment.body["data"]["operatingStatus"], "operating");
    assert_eq!(establishment.body["data"]["preferredLanguage"], "en");
    let old_business = create_record(
        harness,
        "/v1/records/businesses",
        &token,
        "business-old-create",
        json!({
            "businessCode":"H-OLD",
            "localRegistrationNumber":100,
            "registeredName":"Old business",
            "administrativeArea":"north",
            "businessType":"private"
        }),
    )
    .await;
    let current_business = create_record(
        harness,
        "/v1/records/businesses",
        &token,
        "business-current-create",
        json!({
            "businessCode":"H-CURRENT",
            "localRegistrationNumber":101,
            "registeredName":"Current business",
            "administrativeArea":"north",
            "businessType":"private"
        }),
    )
    .await;
    let old_assignment = create_record(
        harness,
        "/v1/records/operator-assignments",
        &token,
        "assignment-old-create",
        json!({
            "establishment":establishment.id,
            "business":old_business.id,
            "relationship":"head-office",
            "validFrom":"2019-01-01",
            "validTo":"2022-01-01"
        }),
    )
    .await;
    let current_assignment = create_record(
        harness,
        "/v1/records/operator-assignments",
        &token,
        "assignment-current-create",
        json!({
            "establishment":establishment.id,
            "business":current_business.id,
            "relationship":"head-office",
            "validFrom":"2022-01-01"
        }),
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/operator-assignments:as-of?accessProfile=business-operator&asOf=2021-12-31T23:59:59Z",
        Some(&token),
        &[&old_assignment.id],
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/operator-assignments:current?accessProfile=business-operator",
        Some(&token),
        &[&current_assignment.id],
    )
    .await;

    let business = harness
        .send(
            Method::GET,
            &format!(
                "/v1/records/businesses/{}?accessProfile=business-operator&$select=businessCode,headOfficeCount,hasHeadOffice,hasProductionSite",
                current_business.id
            ),
            Some(&token),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(business.status(), StatusCode::OK);
    let business = response_json(business).await;
    assert_eq!(business["data"]["businessCode"], "H-CURRENT");
    assert_eq!(business["data"]["headOfficeCount"], 1);
    assert_eq!(business["data"]["hasHeadOffice"], true);
    assert_eq!(business["data"]["hasProductionSite"], true);

    let establishments = harness
        .send(
            Method::GET,
            &format!(
                "/v1/records/businesses/{}/establishments?accessProfile=business-operator&$select=establishmentCode,establishmentKind&$filter=establishmentKind%20eq%20%27production%27&$count=true",
                current_business.id
            ),
            Some(&token),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(establishments.status(), StatusCode::OK);
    let establishments = response_json(establishments).await;
    assert_eq!(establishments["count"], 1);
    assert_eq!(
        establishments["items"][0]["data"]["establishmentCode"],
        "P-100"
    );
    assert_eq!(
        establishments["items"][0]["data"]["establishmentKind"],
        "production"
    );

    let overlap = harness
        .send_json(
            Method::POST,
            "/v1/records/operator-assignments",
            Some(&token),
            Some("assignment-overlap"),
            json!({"data":{
                "establishment":establishment.id,
                "business":old_business.id,
                "relationship":"depot",
                "validFrom":"2021-06-01",
                "validTo":"2023-01-01"
            }}),
        )
        .await;
    assert_eq!(overlap.status(), StatusCode::CONFLICT);
}

async fn inspection_journey(harness: &PilotHarness) {
    let token = harness.token("facility-inspection", &[]);
    let openapi =
        assert_fixture_surface(harness, "inspection-inspector", &token, "inspection").await;
    assert_eq!(
        openapi["components"]["schemas"]["inspection-observation"]["properties"]
            ["observationSchemaMetadata"]["additionalProperties"],
        false
    );
    let concealed_schema = harness
        .send(
            Method::GET,
            "/openapi.json?accessProfile=inspection-inspector",
            None,
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(concealed_schema.status(), StatusCode::NOT_FOUND);

    let authority = create_record(
        harness,
        "/v1/records/authorities",
        &token,
        "authority-create",
        json!({"authorityCode":"ENV-NORTH","name":"Northern Environmental Authority","jurisdiction":"north-district"}),
    ).await;

    let assessment = create_record(
        harness,
        "/v1/records/inspections",
        &token,
        "assessment-create",
        json!({
            "inspectionCode":"EP-100",
            "facilityCode":"FACILITY-100",
            "openedOn":"2026-01-10",
            "inspectionAuthority":"case-management"
        }),
    )
    .await;
    let invalid_range = harness
        .send_json(
            Method::POST,
            "/v1/records/inspection-observations",
            Some(&token),
            Some("observation-invalid-range"),
            json!({"data":{
                "inspection":assessment.id,
                "observedAt":"2026-01-11T09:00:00Z",
                "inspectionDomain":"air",
                "findingGrade":5,
                "observationSchemaMetadata":{
                    "schemaVersion":"1","vocabularyRelease":"2026-01","scoringScale":"zero-to-four"
                }
            }}),
        )
        .await;
    assert_eq!(invalid_range.status(), StatusCode::CONFLICT);
    let invalid_structure = harness
        .send_json(
            Method::POST,
            "/v1/records/inspection-observations",
            Some(&token),
            Some("observation-invalid-structure"),
            json!({"data":{
                "inspection":assessment.id,
                "observedAt":"2026-01-11T09:00:00Z",
                "inspectionDomain":"air",
                "findingGrade":3,
                "observationSchemaMetadata":{
                    "schemaVersion":"1","vocabularyRelease":"2026-01",
                    "scoringScale":"zero-to-four","undeclared":"refused"
                }
            }}),
        )
        .await;
    assert_eq!(invalid_structure.status(), StatusCode::BAD_REQUEST);
    let observation = create_record(
        harness,
        "/v1/records/inspection-observations",
        &token,
        "observation-create",
        json!({
            "inspection":assessment.id,
            "observedAt":"2026-01-11T09:00:00Z",
            "inspectionDomain":"air",
            "findingGrade":3,
            "observationSchemaMetadata":{
                "schemaVersion":"1","vocabularyRelease":"2026-01","scoringScale":"zero-to-four"
            }
        }),
    )
    .await;
    assert_eq!(observation.body["data"]["findingGrade"], 3);

    let original = create_record(
        harness,
        "/v1/records/permits",
        &token,
        "permit-original",
        json!({
            "permitCode":"PERMIT-100",
            "inspection":assessment.id,
            "permitStatus":"active",
            "validFrom":"2026-01-01",
            "validTo":"2026-07-01",
            "issuingAuthority":authority.id,
            "validitySource":"review-board"
        }),
    )
    .await;
    let correction = create_record(
        harness,
        "/v1/records/permits",
        &token,
        "permit-correction",
        json!({
            "permitCode":"PERMIT-101",
            "inspection":assessment.id,
            "permitStatus":"active",
            "validFrom":"2026-01-01",
            "validTo":"2026-07-01",
            "correctedPermit":original.id,
            "correctionReason":"reviewed correction",
            "issuingAuthority":authority.id,
            "validitySource":"review-board",
            "provenanceNote":"signed review packet"
        }),
    )
    .await;
    assert_eq!(correction.body["data"]["correctedPermit"], original.id);
    assert_eq!(correction.body["data"]["issuingAuthority"], authority.id);
    assert_eq!(
        correction.body["data"]["validFrom"],
        original.body["data"]["validFrom"]
    );
    assert_eq!(
        correction.body["data"]["validTo"],
        original.body["data"]["validTo"]
    );
    let retained = harness
        .send(
            Method::GET,
            &format!("/v1/records/permits/{}", original.id),
            Some(&token),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(retained.status(), StatusCode::OK);
    assert_eq!(response_json(retained).await["data"], original.body["data"]);
    assert!(correction.body["data"]["correctionReason"].is_string());
    assert!(correction.body["data"]["provenanceNote"].is_string());
    assert_create_only_refuses_patch_and_tombstone(
        harness,
        "/v1/records/permits",
        &correction,
        &token,
    )
    .await;

    let anonymous = harness
        .send(
            Method::GET,
            &format!("/v1/records/permits/{}", correction.id),
            None,
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(anonymous.status(), StatusCode::NOT_FOUND);
    assert_eq!(response_json(anonymous).await["code"], "resource.not_found");
}

async fn facility_journey(harness: &PilotHarness) {
    let north_token = harness.token(
        "facility-registry",
        &[("administrative_boundaries", json!(["north-district"]))],
    );
    let south_token = harness.token(
        "facility-registry",
        &[("administrative_boundaries", json!(["south-district"]))],
    );
    let openapi =
        assert_fixture_surface(harness, "facility-operator", &north_token, "facility").await;
    assert_eq!(
        openapi["paths"]["/v1/records/installations:batch"]["post"]["x-registry-maximumItems"],
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

    let north_facility = create_record(
        harness,
        "/v1/records/facilities",
        &north_token,
        "north-facility",
        json!({
            "facilityCode":"F-NORTH","displayName":"North operator",
            "administrativeBoundary":"north-district"
        }),
    )
    .await;
    let south_facility = create_record(
        harness,
        "/v1/records/facilities",
        &south_token,
        "south-facility",
        json!({
            "facilityCode":"F-SOUTH","displayName":"South operator",
            "administrativeBoundary":"south-district"
        }),
    )
    .await;
    let concealed = harness
        .send(
            Method::GET,
            &format!(
                "/v1/records/facilities/{}?accessProfile=facility-operator",
                south_facility.id
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
                "/v1/records/facilities?accessProfile=facility-operator",
                Some(&north_token),
                &[],
                Vec::new(),
            )
            .await,
    )
    .await;
    let north_ids = item_ids(&north_list);
    assert!(north_ids.contains(&north_facility.id.as_str()));
    assert!(!north_ids.contains(&south_facility.id.as_str()));

    let old_permit = create_record(
        harness,
        "/v1/records/permits",
        &north_token,
        "permit-old",
        json!({
            "permitNumber":"H-NORTH","facility":north_facility.id,"permitType":"air-emissions",
            "validFrom":"2020-01-01","validTo":"2024-01-01",
            "administrativeBoundary":"north-district","importSource":"survey-a",
            "sourceRecordId":"permit-old"
        }),
    )
    .await;
    let current_permit = create_record(
        harness,
        "/v1/records/permits",
        &north_token,
        "permit-current",
        json!({
            "permitNumber":"H-NORTH","facility":north_facility.id,"permitType":"water-discharge",
            "validFrom":"2024-01-01","administrativeBoundary":"north-district",
            "importSource":"survey-a","sourceRecordId":"permit-current"
        }),
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/permits:as-of?accessProfile=facility-operator&asOf=2023-12-31T23:59:59Z",
        Some(&north_token),
        &[&old_permit.id],
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/permits:current?accessProfile=facility-operator",
        Some(&north_token),
        &[&current_permit.id],
    )
    .await;

    let invalid_point = harness
        .send_json(
            Method::POST,
            "/v1/records/installations",
            Some(&north_token),
            Some("installation-invalid-point"),
            json!({"data":{
                "installationCode":"P-BAD-POINT","permit":current_permit.id,
                "administrativeBoundary":"north-district",
                "centroid":{"type":"Point","coordinates":[32.0,-9.5]},
                "areaValue":"1.2500","areaUnit":"hectare",
                "importSource":"survey-a","sourceRecordId":"installation-bad-point"
            }}),
        )
        .await;
    assert_eq!(invalid_point.status(), StatusCode::BAD_REQUEST);
    let invalid_decimal = harness
        .send_json(
            Method::POST,
            "/v1/records/installations",
            Some(&north_token),
            Some("installation-invalid-decimal"),
            json!({"data":{
                "installationCode":"P-BAD-DECIMAL","permit":current_permit.id,
                "administrativeBoundary":"north-district",
                "centroid":{"type":"Point","coordinates":[30.5,-9.5]},
                "areaValue":"01.2500","areaUnit":"hectare",
                "importSource":"survey-a","sourceRecordId":"installation-bad-decimal"
            }}),
        )
        .await;
    assert_eq!(invalid_decimal.status(), StatusCode::BAD_REQUEST);
    let installation = create_record(
        harness,
        "/v1/records/installations",
        &north_token,
        "installation-create",
        json!({
            "installationCode":"P-NORTH","permit":current_permit.id,
            "administrativeBoundary":"north-district",
            "centroid":{"type":"Point","coordinates":[30.5,-9.5]},
            "areaValue":"1.2500","areaUnit":"hectare",
            "importSource":"survey-a","sourceRecordId":"installation-primary"
        }),
    )
    .await;
    assert_eq!(installation.body["data"]["areaValue"], "1.2500");
    assert_eq!(installation.body["data"]["areaUnit"], "hectare");

    let old_activity = create_record(
        harness,
        "/v1/records/discharge-reports",
        &north_token,
        "activity-old",
        json!({
            "installation":installation.id,"administrativeBoundary":"north-district",
            "substanceCode":"nitrogen","periodStart":"2024-01-01","periodEnd":"2024-07-01",
            "quantityValue":"12.500","quantityUnit":"kilogram"
        }),
    )
    .await;
    let current_activity = create_record(
        harness,
        "/v1/records/discharge-reports",
        &north_token,
        "activity-current",
        json!({
            "installation":installation.id,"administrativeBoundary":"north-district",
            "substanceCode":"nitrogen","periodStart":"2024-07-01",
            "quantityValue":"8.250","quantityUnit":"kilogram"
        }),
    )
    .await;
    assert_eq!(current_activity.body["data"]["quantityValue"], "8.250");
    assert_list_ids(
        harness,
        "/v1/records/discharge-reports:as-of?accessProfile=facility-operator&asOf=2024-06-30T23:59:59Z",
        Some(&north_token),
        &[&old_activity.id],
    )
    .await;
    assert_list_ids(
        harness,
        "/v1/records/discharge-reports:current?accessProfile=facility-operator",
        Some(&north_token),
        &[&current_activity.id],
    )
    .await;

    let batch_body = json!({"items":[{"operation":"create","data":{
        "installationCode":"P-BATCH","permit":current_permit.id,
        "administrativeBoundary":"north-district",
        "centroid":{"type":"Point","coordinates":[30.75,-9.25]},
        "areaValue":"2.0000","areaUnit":"hectare",
        "importSource":"survey-b","sourceRecordId":"installation-batch"
    }}]});
    let first_batch = harness
        .send_json(
            Method::POST,
            "/v1/records/installations:batch",
            Some(&north_token),
            Some("installation-batch"),
            batch_body.clone(),
        )
        .await;
    assert_eq!(first_batch.status(), StatusCode::OK);
    let first_batch_bytes = response_bytes(first_batch).await;
    let replay = harness
        .send_json(
            Method::POST,
            "/v1/records/installations:batch",
            Some(&north_token),
            Some("installation-batch"),
            batch_body,
        )
        .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(replay).await, first_batch_bytes);

    let duplicate_import = harness
        .send_json(
            Method::POST,
            "/v1/records/installations",
            Some(&north_token),
            Some("installation-duplicate-import"),
            json!({"data":{
                "installationCode":"P-DUPLICATE","permit":current_permit.id,
                "administrativeBoundary":"north-district",
                "centroid":{"type":"Point","coordinates":[30.8,-9.2]},
                "areaValue":"3.0000","areaUnit":"hectare",
                "importSource":"survey-b","sourceRecordId":"installation-batch"
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
            "jurisdictionCode":"XY","registrationNumber":"10001",
            "legalName":"Example Cooperative","entityStatus":"active",
            "publicServiceAddress":"Public office",
            "protectedContact":"protected-contact@example.test",
            "protectedOwnershipReference":"ownership-10001",
            "internalCaseNote":"registrar review complete"
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
    assert_eq!(public["data"]["legalName"], "Example Cooperative");
    assert!(public["data"].get("protectedContact").is_none());
    assert!(public["data"].get("protectedOwnershipReference").is_none());
    assert!(public["data"].get("internalCaseNote").is_none());
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
    assert!(protected["data"]["protectedContact"].is_string());
    assert!(protected["data"]["protectedOwnershipReference"].is_string());
    assert!(protected["data"]["internalCaseNote"].is_string());

    let duplicate_identifier = harness
        .send_json(
            Method::POST,
            "/v1/records/legal-entities",
            Some(&token),
            Some("legal-entity-duplicate"),
            json!({"data":{
                "jurisdictionCode":"XY","registrationNumber":"10001",
                "legalName":"Duplicate","entityStatus":"active"
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
            "legalEntity":legal_entity.id,"filingNumber":"F-100",
            "filingType":"incorporation","filedDate":"2020-01-01",
            "sourceSystem":"registrar","sourceRecordId":"filing-100",
            "provenanceNote":"accepted filing"
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
            "legalEntity":legal_entity.id,"officerCode":"OFFICER-A",
            "officerName":"First Director","officerRole":"director",
            "effectiveFrom":"2020-01-01","effectiveTo":"2022-01-01",
            "protectedOfficerId":"protected-a"
        }),
    )
    .await;
    let current = create_record(
        harness,
        "/v1/records/officer-appointments",
        &token,
        "appointment-current",
        json!({
            "legalEntity":legal_entity.id,"officerCode":"OFFICER-A",
            "officerName":"First Director","officerRole":"director",
            "effectiveFrom":"2022-01-01","protectedOfficerId":"protected-a"
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
                "legalEntity":legal_entity.id,"officerCode":"OFFICER-B",
                "officerName":"Second Director","officerRole":"director",
                "effectiveFrom":"2023-01-01"
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
                "legalEntity":legal_entity.id,"officerCode":"OFFICER-A",
                "officerName":"First Director","officerRole":"secretary",
                "effectiveFrom":"2021-01-01","effectiveTo":"2023-01-01"
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
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "compiled OpenAPI is visible to the {profile} profile"
    );
    let openapi = response_json(response).await;
    let families = [
        ("asset", "/v1/records/assets", "asset-item"),
        (
            "establishments",
            "/v1/records/establishments",
            "establishment",
        ),
        ("establishments", "/v1/records/businesses", "business"),
        (
            "inspection",
            "/v1/records/inspection-observations",
            "inspection-observation",
        ),
        ("facility", "/v1/records/facilities", "facility"),
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
            br#"[{"op":"replace","path":"/data/provenanceNote","value":"refused"}]"#.to_vec(),
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
