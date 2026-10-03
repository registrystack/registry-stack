// SPDX-License-Identifier: Apache-2.0
#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/pilot_acceptance_harness.rs"]
#[allow(dead_code)]
mod pilot_acceptance_harness;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::http::{Method, StatusCode};
use chrono::{Days, Utc};
use pilot_acceptance_harness::{response_json, PilotHarness};
use registry_breg::statistics::{current_period, PeriodGranularity};
use serde_json::{json, Value};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn facility_statistics_match_count_twins_and_release_evaluation_date() {
    let harness = PilotHarness::start("facility").await;
    let today = Utc::now().date_naive();
    let current = current_period(PeriodGranularity::Month, today).unwrap();
    let prior_date = current.start.checked_sub_days(Days::new(1)).unwrap();
    let prior = current_period(PeriodGranularity::Month, prior_date).unwrap();
    let expiry = prior
        .reference_date
        .checked_add_days(Days::new(91))
        .unwrap();
    assert!(
        expiry
            > prior
                .reference_date
                .checked_add_days(Days::new(90))
                .unwrap()
    );
    assert!(expiry <= today.checked_add_days(Days::new(90)).unwrap());
    let north = harness.token_with_scopes(
        "facility-registry",
        &[("administrative_boundaries", json!(["north-district"]))],
        &["registry:facility:operate"],
    );
    let south = harness.token_with_scopes(
        "facility-registry",
        &[("administrative_boundaries", json!(["south-district"]))],
        &["registry:facility:operate"],
    );
    let publisher =
        harness.token_with_scopes("statistics", &[], &["registry:facility:statistics:publish"]);
    let reader =
        harness.token_with_scopes("statistics", &[], &["registry:facility:statistics:read"]);
    let mut first_north_permit = String::new();
    for (boundary, token) in [("north-district", &north), ("south-district", &south)] {
        let facility = create(&harness,"facilities",token,&format!("facility-{boundary}"),json!({
            "facilityCode":format!("F-{boundary}"),"displayName":boundary,"administrativeBoundary":boundary
        })).await;
        for index in 0..5 {
            let permit = create(&harness,"permits",token,&format!("permit-{boundary}-{index}"),json!({
                "permitNumber":format!("P-{boundary}-{index}"),"facility":facility,
                "permitType":"water-discharge","validFrom":"2025-01-01","validTo":expiry.to_string(),
                "administrativeBoundary":boundary,"importSource":"statistics-test",
                "sourceRecordId":format!("{boundary}-{index}")
            })).await;
            if boundary == "north-district" && index == 0 {
                first_north_permit = permit;
            }
        }
        if boundary == "north-district" {
            // Both boundary cases must be absent from current stock, including margins.
            for (suffix, from, until) in [
                (
                    "expired",
                    "2025-01-01".to_owned(),
                    Some(prior.reference_date.to_string()),
                ),
                ("future", current.end.to_string(), None),
            ] {
                create(&harness,"permits",token,&format!("permit-{suffix}"),json!({
                    "permitNumber":format!("P-{suffix}"),"facility":facility,"permitType":"water-discharge",
                    "validFrom":from,"validTo":until,"administrativeBoundary":boundary,
                    "importSource":"statistics-test","sourceRecordId":suffix
                })).await;
            }
        }
    }
    let mut stock_documents = Vec::new();
    for dataset in [
        "monthly-valid-permits-temporal",
        "monthly-valid-permits-fields",
    ] {
        let live = get(
            &harness,
            &format!(
                "/v1/statistics/{dataset}:live?accessProfile=facility-operator&from={0}&to={0}",
                current.code
            ),
            &north,
        )
        .await;
        assert_count_twins(
            &harness,
            &north,
            if dataset.ends_with("temporal") { "permits:as-of" } else { "permits" },
            &live,
            &format!(
                "permitType ne null and validFrom le '{0}' and (validTo eq null or validTo gt '{0}')",
                current.reference_date
            ),
        )
        .await;
        assert_eq!(cell(&live, "north-district", "true")["value"], 5);
        assert_eq!(cell(&live, "south-district", "_T")["value"], 0);
        let south_live = get(
            &harness,
            &format!("/v1/statistics/{dataset}:live?accessProfile=facility-operator"),
            &south,
        )
        .await;
        assert_eq!(cell(&south_live, "north-district", "_T")["value"], 0);
        assert_eq!(cell(&south_live, "south-district", "true")["value"], 5);
        let past = harness
            .send(
                Method::GET,
                &format!(
                    "/v1/statistics/{dataset}:live?accessProfile=facility-operator&from={0}&to={0}",
                    prior.code
                ),
                Some(&north),
                &[],
                Vec::new(),
            )
            .await;
        assert_eq!(past.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(past).await["code"], "query.invalid");
        stock_documents.push(live);
        let published=harness.send_json(Method::POST,&format!("/v1/statistics/{dataset}/releases/{}/versions?accessProfile=statistics-publisher",prior.code),Some(&publisher),Some(&format!("publish-{dataset}")),json!({"status":"final"})).await;
        assert_eq!(
            published.status(),
            StatusCode::CREATED,
            "{}",
            response_json(published).await
        );
        let released = get(
            &harness,
            &format!(
                "/v1/statistics/{dataset}/releases/{}?accessProfile=statistics-reader",
                prior.code
            ),
            &reader,
        )
        .await;
        // Publication evaluates the derived dimension at the prior reference date,
        // not today: the five permits move from the true cell to the false cell.
        assert_eq!(cell(&released, "north-district", "false")["value"], 5);
        assert_eq!(cell(&released, "north-district", "true")["value"], 0);
        assert_eq!(cell(&released, "south-district", "false")["value"], 5);
        assert_eq!(
            released["periods"][0]["referenceDate"],
            prior.reference_date.to_string()
        );
    }
    assert_eq!(stock_documents[0]["cells"], stock_documents[1]["cells"]);
    let installation=create(&harness,"installations",&north,"installation",json!({
        "installationCode":"I-STATS","permit":first_north_permit,"administrativeBoundary":"north-district",
        "centroid":{"type":"Point","coordinates":[30.5,-9.5]},"areaValue":"1.0000","areaUnit":"hectare",
        "importSource":"statistics-test","sourceRecordId":"installation"
    })).await;
    for (index, quantity) in [(0, Some("5.000")), (1, None)] {
        let mut data = json!({"installation":installation,"administrativeBoundary":"north-district",
            "substanceCode":"nitrogen","periodStart":prior.start.checked_add_days(Days::new(index)).unwrap().to_string(),
            "periodEnd":prior.start.checked_add_days(Days::new(index + 1)).unwrap().to_string()});
        if let Some(quantity) = quantity {
            data["quantityValue"] = json!(quantity);
            data["quantityUnit"] = json!("kilogram");
        }
        create(
            &harness,
            "discharge-reports",
            &north,
            &format!("discharge-{index}"),
            data,
        )
        .await;
    }
    let flow=get(&harness,&format!("/v1/statistics/monthly-discharge-reports:live?accessProfile=facility-operator&from={0}&to={0}",prior.code),&north).await;
    assert_count_twins(
        &harness,
        &north,
        "discharge-reports",
        &flow,
        &format!(
            "substanceCode ne null and periodStart ge '{}' and periodStart lt '{}'",
            prior.start, prior.end
        ),
    )
    .await;
    harness.finish().await;
}

async fn create(
    harness: &PilotHarness,
    collection: &str,
    token: &str,
    key: &str,
    data: Value,
) -> String {
    let response = harness
        .send_json(
            Method::POST,
            &format!("/v1/records/{collection}?accessProfile=facility-operator"),
            Some(token),
            Some(key),
            json!({"data":data}),
        )
        .await;
    let status = response.status();
    let value = response_json(response).await;
    assert_eq!(status, StatusCode::CREATED, "{collection} {key}: {value}");
    value["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn get(harness: &PilotHarness, uri: &str, token: &str) -> Value {
    let response = harness
        .send(Method::GET, uri, Some(token), &[], Vec::new())
        .await;
    let status = response.status();
    let value = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    value
}

fn cell<'a>(document: &'a Value, boundary: &str, boolean: &str) -> &'a Value {
    document["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|cell| {
            cell["dimensions"]["administrative-boundary"] == boundary
                && cell["dimensions"]["expiring-soon"] == boolean
        })
        .unwrap()
}

async fn assert_count_twins(
    harness: &PilotHarness,
    token: &str,
    collection: &str,
    document: &Value,
    population: &str,
) {
    let unit = document["dataset"]["unit"].as_str().unwrap();
    let entity = &harness.registry.entities()[unit];
    for cell in document["cells"].as_array().unwrap() {
        let mut filter = population.to_owned();
        for (field, code) in cell["dimensions"].as_object().unwrap() {
            let code = code.as_str().unwrap();
            if code == "_T" {
                continue;
            }
            let api = &entity
                .stored_fields
                .iter()
                .map(|field| &field.logical)
                .chain(entity.derived_fields.values().map(|field| &field.logical))
                .find(|candidate| candidate.id == *field)
                .unwrap()
                .api_name;
            let literal = match code {
                "_U" => "null".to_owned(),
                "true" | "false" => code.to_owned(),
                _ => format!("'{}'", code.replace('\'', "''")),
            };
            filter.push_str(&format!(" and {api} eq {literal}"));
        }
        let encoded_filter: String = filter.bytes().map(|byte| format!("%{byte:02X}")).collect();
        let mut query =
            format!("accessProfile=facility-operator&$count=true&$top=1&$filter={encoded_filter}");
        if collection.ends_with(":as-of") {
            query.push_str(&format!(
                "&asOf={}T00:00:00Z",
                document["periods"][0]["referenceDate"].as_str().unwrap()
            ));
        }
        let counted = get(harness, &format!("/v1/records/{collection}?{query}"), token).await;
        assert_eq!(cell["value"], counted["count"], "{filter}");
    }
}
