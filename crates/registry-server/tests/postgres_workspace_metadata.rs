// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

use std::collections::BTreeSet;

#[path = "support/pilot_acceptance_harness.rs"]
mod pilot_acceptance_harness;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::http::{Method, StatusCode};
use pilot_acceptance_harness::{response_bytes, response_json, PilotHarness};
use registry_server::mutation::parse_json_patch_document;
use serde_json::{json, Value};

fn operation<'a>(document: &'a Value, id: &str) -> &'a Value {
    document["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["id"] == id)
        .expect("authorized operation")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_workspace_metadata_marks_request_lifecycle_without_direct_controlled_writes()
{
    let harness = PilotHarness::start("asset-site-placement-change-requests").await;
    let token = harness.token("asset-management", &[]);
    let metadata = response_json(
        harness
            .send(
                Method::GET,
                "/v1/registry?accessProfile=asset-operator",
                Some(&token),
                &[],
                Vec::new(),
            )
            .await,
    )
    .await;
    let operation_ids = metadata["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|operation| operation["id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert!(operation_ids.contains("records.asset-placement.create"));
    assert!(
        !operation_ids.contains("records.asset-placement.patch"),
        "controlled placement patch must be absent as a direct operation"
    );
    assert_eq!(
        operation(&metadata, "records.asset-placement.create")["request"]["mutationSemantics"],
        "direct"
    );
    assert_eq!(
        metadata["entities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entity| entity["id"] == "asset-placement")
            .unwrap()["changeControl"],
        json!({
            "controlledOperations": ["patch"],
            "eligibleRequestTypes": [{"id": "placement-correction-request", "primaryDataset": "asset-site-placement-change-requests", "route": "placement-correction-requests"}]
        })
    );

    let submitter_token =
        harness.token_with_scopes("asset-correction", &[], &["registry:corrections:submit"]);
    let submitter = response_json(
        harness
            .send(
                Method::GET,
                "/v1/registry?accessProfile=correction-submitter",
                Some(&submitter_token),
                &[],
                Vec::new(),
            )
            .await,
    )
    .await;
    assert_eq!(
        operation(&submitter, "records.placement-correction-request.create")["request"]
            ["mutationSemantics"],
        "direct"
    );
    let placement_list = operation(&submitter, "records.asset-placement.list");
    assert_eq!(placement_list["accessProfile"], "correction-submitter");
    assert_eq!(
        placement_list["readableFields"],
        json!(["asset", "valid-from", "valid-to"])
    );
    assert_eq!(placement_list["titleFields"], json!([]));
    let asset_get = operation(&submitter, "records.asset-item.get");
    assert_eq!(asset_get["accessProfile"], "correction-submitter");
    assert_eq!(asset_get["readableFields"], json!(["asset-code", "label"]));
    assert_eq!(asset_get["titleFields"], json!(["asset-code"]));
    let asset_reference = &placement_list["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["id"] == "asset")
        .unwrap()["reference"];
    assert_eq!(asset_reference["targetEntity"], "asset-item");
    assert_eq!(
        asset_reference["operations"],
        json!([{
            "accessProfile": "correction-submitter",
            "labelFields": ["asset-code"],
            "operationId": "records.asset-item.get"
        }])
    );
    let site_list = operation(&submitter, "records.asset-site.list");
    assert_eq!(site_list["accessProfile"], "correction-submitter");
    assert_eq!(site_list["readableFields"], json!(["site-code"]));
    assert_eq!(site_list["titleFields"], json!(["site-code"]));

    let create = operation(&submitter, "records.placement-correction-request.create");
    for (field_id, target_entity, target_operation, label_fields) in [
        (
            "placement",
            "asset-placement",
            "records.asset-placement.list",
            json!([]),
        ),
        (
            "proposed-site",
            "asset-site",
            "records.asset-site.list",
            json!(["site-code"]),
        ),
    ] {
        let reference = &create["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["id"] == field_id)
            .unwrap()["reference"];
        assert_eq!(reference["targetEntity"], target_entity);
        assert_eq!(reference["manualEntry"], true);
        let binding = reference["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|binding| binding["operationId"] == target_operation)
            .expect("ordinary list reference binding");
        assert_eq!(binding["accessProfile"], "correction-submitter");
        assert_eq!(binding["labelFields"], label_fields);
        assert!(reference["operations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|binding| binding["accessProfile"] == "correction-submitter"));
    }
    for operation_id in [
        "records.placement-correction-request.request.submit",
        "records.placement-correction-request.request.revise",
        "records.placement-correction-request.request.cancel",
    ] {
        let operation = operation(&submitter, operation_id);
        assert_eq!(
            operation["requiredCapabilities"],
            json!(["change_request_lifecycle"])
        );
        assert_eq!(
            operation["request"]["mutationSemantics"],
            "change_request_lifecycle"
        );
        assert_eq!(operation["request"]["body"], "change_request_action");
        assert_eq!(operation["request"]["contentType"], "application/json");
        assert_eq!(operation["request"]["idempotencyKeyRequired"], true);
        assert_eq!(operation["request"]["ifMatchRequired"], true);
        assert_eq!(
            operation["request"]["schema"]["additionalProperties"],
            false
        );
        if operation_id.ends_with(".revise") {
            assert_eq!(
                operation["request"]["schema"]["required"],
                json!(["rebase"])
            );
        } else {
            assert!(operation["request"]["schema"].get("required").is_none());
            assert_eq!(operation["request"]["schema"]["properties"], json!({}));
        }
    }
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_workspace_metadata_mutation_and_replay_contract() {
    let harness = PilotHarness::start("asset-site-placement").await;
    let token = harness.token("asset-management", &[]);
    let metadata_response = harness
        .send(Method::GET, "/v1/registry", Some(&token), &[], Vec::new())
        .await;
    assert_eq!(metadata_response.status(), StatusCode::OK);
    assert_eq!(metadata_response.headers()["cache-control"], "no-store");
    let metadata = response_json(metadata_response).await;
    assert_eq!(metadata["revision"], harness.registry.revision());
    let create = operation(&metadata, "records.asset-item.create");
    let patch = operation(&metadata, "records.asset-item.patch");
    assert_eq!(
        create["createWritableFields"],
        json!(["asset-class", "asset-code", "label"])
    );
    assert_eq!(create["patchWritableFields"], json!([]));
    assert_eq!(patch["patchWritableFields"], create["createWritableFields"]);
    assert_eq!(patch["createWritableFields"], json!([]));
    assert_eq!(patch["request"]["patchPathPrefix"], "/data/");
    assert_eq!(patch["request"]["ifMatchRequired"], true);
    assert_eq!(patch["request"]["idempotencyKeyRequired"], true);
    assert_eq!(patch["request"]["mutationSemantics"], "direct");
    assert_eq!(
        patch["request"]["patchOperations"],
        json!(["add", "replace", "remove", "test"])
    );
    assert!(metadata["operations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|op| op["id"] != "records.inspection-event.patch"));
    let placement = operation(&metadata, "records.asset-placement.patch");
    let end = placement["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["id"] == "valid-to")
        .unwrap();
    assert_eq!(end["apiName"], "validTo");
    assert_eq!(end["nullable"], true);
    assert_eq!(end["removable"], true);
    let nullable = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&end["schema"])
        .unwrap();
    assert!(nullable.is_valid(&Value::Null));
    assert!(nullable.is_valid(&json!("2026-08-31")));
    assert!(!nullable.is_valid(&json!(42)));
    let reference = &placement["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["id"] == "asset")
        .unwrap()["reference"];
    assert_eq!(reference["targetEntity"], "asset-item");
    assert!(!reference["operations"].as_array().unwrap().is_empty());
    let openapi_response = harness
        .send(Method::GET, "/openapi.json", Some(&token), &[], Vec::new())
        .await;
    assert_eq!(openapi_response.headers()["cache-control"], "no-store");
    let openapi = response_json(openapi_response).await;
    let patch_schema = &openapi["paths"]["/v1/records/assets/{record_id}"]["patch"]["requestBody"]
        ["content"]["application/json-patch+json"]["schema"];
    assert_eq!(patch_schema, &patch["request"]["schema"]);
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(patch_schema)
        .unwrap();
    for document in [
        json!([{"op":"add","path":"/data/label","value":"Value"}]),
        json!([{"op":"replace","path":"/data/label","value":"Value"}]),
        json!([{"op":"remove","path":"/data/label"}]),
        json!([{"op":"test","path":"/data/label","value":"Value"}]),
        json!([{"op":"move","path":"/data/label","from":"/data/assetCode"}]),
        json!([{"op":"copy","path":"/data/label","from":"/data/assetCode"}]),
        json!([{"op":"remove","path":"/data/label","value":null}]),
        json!([{"op":"replace","path":"/data/label"}]),
        json!([{"op":"add","path":"/data/label","value":null,"extra":true}]),
        json!([]),
    ] {
        assert_eq!(
            validator.is_valid(&document),
            parse_json_patch_document(document.clone()).is_ok(),
            "schema and parser disagree: {document}"
        );
    }
    let planner_token = harness.token("site-planning", &[]);
    let planner = response_json(
        harness
            .send(
                Method::GET,
                "/v1/registry?accessProfile=site-planner",
                Some(&planner_token),
                &[],
                Vec::new(),
            )
            .await,
    )
    .await;
    assert_eq!(planner["revision"], metadata["revision"]);
    assert!(planner["operations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|op| op["accessProfile"] == "site-planner"));
    assert!(planner["operations"].as_array().unwrap().iter().all(|op| ![
        "records.asset-item.create",
        "records.asset-item.patch",
        "records.inspection-event.create"
    ]
    .contains(&op["id"].as_str().unwrap())));
    let planner_rendered = planner.to_string();
    for hidden in [
        "asset-class",
        "assetClass",
        "inspection-event",
        "inspection-result",
    ] {
        assert!(
            !planner_rendered.contains(hidden),
            "planner metadata leaked {hidden}"
        );
    }
    assert_eq!(
        operation(&planner, "records.asset-placement.patch")["patchWritableFields"],
        json!(["asset", "site", "valid-from", "valid-to"])
    );
    let body = json!({"data":{"assetCode":"META-001","label":"Metadata contract asset","assetClass":"equipment"}});
    assert!(jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&create["request"]["schema"])
        .unwrap()
        .is_valid(&body));
    let created = harness
        .send_json(
            Method::POST,
            "/v1/records/assets",
            Some(&token),
            Some("workspace-meta-create"),
            body.clone(),
        )
        .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(created.headers()["cache-control"], "no-store");
    let etag = created.headers()["etag"].to_str().unwrap().to_owned();
    let location = created.headers()["location"].to_str().unwrap().to_owned();
    let bytes = response_bytes(created).await;
    let replay = harness
        .send_json(
            Method::POST,
            "/v1/records/assets",
            Some(&token),
            Some("workspace-meta-create"),
            body,
        )
        .await;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(replay.headers()["cache-control"], "no-store");
    assert_eq!(replay.headers()["etag"], etag);
    assert_eq!(replay.headers()["location"], location);
    assert_eq!(response_bytes(replay).await, bytes);
    let detail = harness
        .send(Method::GET, &location, Some(&token), &[], Vec::new())
        .await;
    assert_eq!(detail.status(), StatusCode::OK);
    assert_eq!(detail.headers()["cache-control"], "no-store");
    assert_eq!(detail.headers()["etag"], etag);
    let patch_body =
        serde_json::to_vec(&json!([{"op":"replace","path":"/data/label","value":"Revised label"}]))
            .unwrap();
    let headers = [
        ("content-type", "application/json-patch+json"),
        ("idempotency-key", "workspace-meta-patch"),
        ("if-match", etag.as_str()),
    ];
    let patched = harness
        .send(
            Method::PATCH,
            &location,
            Some(&token),
            &headers,
            patch_body.clone(),
        )
        .await;
    assert_eq!(patched.status(), StatusCode::OK);
    assert_eq!(patched.headers()["cache-control"], "no-store");
    let patch_etag = patched.headers()["etag"].to_str().unwrap().to_owned();
    let patched_bytes = response_bytes(patched).await;
    let replay = harness
        .send(
            Method::PATCH,
            &location,
            Some(&token),
            &headers,
            patch_body.clone(),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.headers()["cache-control"], "no-store");
    assert_eq!(replay.headers()["etag"], patch_etag);
    assert_eq!(response_bytes(replay).await, patched_bytes);
    let stale = harness
        .send(
            Method::PATCH,
            &location,
            Some(&token),
            &[
                ("content-type", "application/json-patch+json"),
                ("idempotency-key", "workspace-meta-stale"),
                ("if-match", etag.as_str()),
            ],
            patch_body,
        )
        .await;
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(stale.headers()["cache-control"], "no-store");
    assert!(stale.headers().contains_key("traceparent"));
    let refused = harness
        .send(
            Method::GET,
            "/v1/registry",
            Some("invalid-bearer"),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(refused.headers()["cache-control"], "no-store");
    harness.finish().await;
}
