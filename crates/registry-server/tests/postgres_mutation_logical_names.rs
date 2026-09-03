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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_mutations_use_only_governed_api_field_names() {
    let harness = PilotHarness::start("asset-site-placement").await;
    let token = harness.token("asset-management", &[]);

    let created = harness
        .send_json(
            Method::POST,
            "/v1/records/assets",
            Some(&token),
            Some("logical-name-create"),
            json!({"data":{
                "assetCode":"A-100",
                "label":"Portable pump",
                "assetClass":"equipment"
            }}),
        )
        .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let etag = created
        .headers()
        .get("etag")
        .expect("create response carries an ETag")
        .to_str()
        .expect("ETag is ASCII")
        .to_owned();
    let created = response_json(created).await;
    assert_eq!(created["data"]["domainData"]["assetCode"], "A-100");
    assert_eq!(created["data"]["domainData"]["assetClass"], "equipment");
    assert!(created["data"]["domainData"].get("asset-code").is_none());
    assert!(created["data"]["domainData"].get("asset-class").is_none());
    let record_id = created["data"]["recordIdentifier"]
        .as_str()
        .expect("created record identifier is present");

    let patched = harness
        .send(
            Method::PATCH,
            &format!("/v1/records/assets/{record_id}"),
            Some(&token),
            &[
                ("content-type", "application/json-patch+json"),
                ("idempotency-key", "logical-name-patch"),
                ("if-match", &etag),
            ],
            serde_json::to_vec(&json!([
                {"op":"test","path":"/data/assetCode","value":"A-100"},
                {"op":"replace","path":"/data/assetCode","value":"A-101"}
            ]))
            .expect("patch JSON serializes"),
        )
        .await;
    assert_eq!(patched.status(), StatusCode::OK);
    let patch_etag = patched
        .headers()
        .get("etag")
        .expect("patch response carries an ETag")
        .to_str()
        .expect("ETag is ASCII")
        .to_owned();
    let patched = response_json(patched).await;
    assert_eq!(patched["data"]["domainData"]["assetCode"], "A-101");
    assert!(patched["data"]["domainData"].get("asset-code").is_none());

    let batch = harness
        .send_json(
            Method::POST,
            "/v1/records/assets:batch",
            Some(&token),
            Some("logical-name-batch"),
            json!({"items":[
                {
                    "operation":"patch",
                    "recordId":record_id,
                    "ifMatch":patch_etag,
                    "patch":[
                        {"op":"test","path":"/data/assetCode","value":"A-101"},
                        {"op":"replace","path":"/data/assetCode","value":"A-102"}
                    ]
                },
                {
                    "operation":"create",
                    "data":{
                        "assetCode":"A-103",
                        "label":"Batch pump",
                        "assetClass":"equipment"
                    }
                }
            ]}),
        )
        .await;
    assert_eq!(batch.status(), StatusCode::OK);
    let batch = response_json(batch).await;
    assert_eq!(batch["results"][0]["data"]["assetCode"], "A-102");
    assert_eq!(batch["results"][1]["data"]["assetCode"], "A-103");
    assert!(batch["results"][0]["data"].get("asset-code").is_none());

    for (key, invalid_data) in [
        (
            "logical-name-internal-alias",
            json!({
                "asset-code":"A-200",
                "label":"Alias attempt",
                "assetClass":"equipment"
            }),
        ),
        (
            "logical-name-unknown",
            json!({
                "assetCode":"A-201",
                "label":"Unknown attempt",
                "assetClass":"equipment",
                "unreviewedValue":"must-not-leak"
            }),
        ),
        (
            "logical-name-required",
            json!({"label":"Missing code","assetClass":"equipment"}),
        ),
    ] {
        let refused = harness
            .send_json(
                Method::POST,
                "/v1/records/assets",
                Some(&token),
                Some(key),
                json!({"data":invalid_data}),
            )
            .await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        let body = response_bytes(refused).await;
        let problem: Value = serde_json::from_slice(&body).expect("problem body is JSON");
        assert_eq!(problem["code"], "request.invalid");
        let rendered = String::from_utf8(body).expect("problem body is UTF-8");
        assert!(!rendered.contains("asset-code"));
        assert!(!rendered.contains("unreviewedValue"));
        assert!(!rendered.contains("must-not-leak"));
    }

    let alias_patch = harness
        .send(
            Method::PATCH,
            &format!("/v1/records/assets/{record_id}"),
            Some(&token),
            &[
                ("content-type", "application/json-patch+json"),
                ("idempotency-key", "logical-name-alias-patch"),
                ("if-match", "\"rs-valid-shape\""),
            ],
            serde_json::to_vec(&json!([
                {"op":"replace","path":"/data/asset-code","value":"must-not-leak"}
            ]))
            .expect("alias patch JSON serializes"),
        )
        .await;
    assert_eq!(alias_patch.status(), StatusCode::BAD_REQUEST);
    let alias_patch_body = response_bytes(alias_patch).await;
    assert!(!String::from_utf8(alias_patch_body)
        .expect("problem body is UTF-8")
        .contains("must-not-leak"));

    harness.finish().await;
}
