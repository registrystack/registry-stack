// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/pilot_acceptance_harness.rs"]
mod pilot_acceptance_harness;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::http::{Method, StatusCode};
use pilot_acceptance_harness::{response_bytes, response_json, PilotHarness};
use registry_server::data::{
    execute_import_chunk, DataError, DataHttpMethod, DataHttpRequest, DataHttpResponse,
    DataImportCheckpoint, DataImportOperation, DataImportPlan,
};
use serde_json::{json, Value};

const PROFILE: &str = "farmer-operator";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_farmer_import_is_authenticated_chunked_resumable_and_race_safe() {
    let harness = PilotHarness::start("farmer").await;
    let north_token = harness.token(
        "farmer-registry",
        &[("administrative_boundaries", json!(["north-district"]))],
    );
    let south_token = harness.token(
        "farmer-registry",
        &[("administrative_boundaries", json!(["south-district"]))],
    );
    let farmer_id = create(
        &harness,
        &north_token,
        "/v1/records/farmers",
        "data-farmer-seed",
        json!({
            "farmer-code":"F-DATA", "display-name":"Data import operator",
            "administrative-boundary":"north-district"
        }),
    )
    .await;
    let holding_id = create(
        &harness,
        &north_token,
        "/v1/records/holdings",
        "data-holding-seed",
        json!({
            "holding-code":"H-DATA", "farmer":farmer_id, "tenure-type":"owned",
            "tenure-start":"2026-01-01", "administrative-boundary":"north-district",
            "import-source":"data-seed", "source-record-id":"holding"
        }),
    )
    .await;
    let (package_revision, schema_fingerprint) = active_identity(&harness).await;

    let input = (0..5)
        .map(|index| {
            serde_json::to_string(&plot_item(
                &holding_id,
                &format!("P-IMPORT-{index}"),
                "bounded-import",
                &format!("source-{index}"),
                format!("30.{:02}", 10 + index)
                    .parse()
                    .expect("bounded longitude parses"),
            ))
            .expect("farmer import item serializes")
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let plan = DataImportPlan::from_jsonl(
        &harness.registry,
        "plot",
        DataImportOperation::Create,
        PROFILE,
        input.as_bytes(),
    )
    .expect("farmer import validates against the compiled model");
    assert_eq!(
        plan.chunks().len(),
        2,
        "the compiled bound creates two chunks"
    );
    let before = effect_counts(&harness).await;
    let mut checkpoint = DataImportCheckpoint::start(&plan, &package_revision, &schema_fingerprint)
        .expect("checkpoint binds active identity");
    let import_id = checkpoint.import_id().to_owned();

    let first = execute_import_chunk(
        &plan,
        &mut checkpoint,
        &package_revision,
        &schema_fingerprint,
        &import_id,
        |request| dispatch(&harness, Some(&north_token), request),
    )
    .await
    .expect("first authenticated HTTP chunk commits")
    .expect("one chunk remained");
    assert_eq!(first.chunk_index(), 0);
    assert_eq!(first.committed_items(), 4);
    assert!(!first.is_complete());
    let serialized = checkpoint
        .canonical_json()
        .expect("checkpoint serializes canonically");
    let mut resumed = DataImportCheckpoint::from_json(
        &serialized,
        &plan,
        &package_revision,
        &schema_fingerprint,
        &import_id,
    )
    .expect("exact checkpoint resumes");
    let second = execute_import_chunk(
        &plan,
        &mut resumed,
        &package_revision,
        &schema_fingerprint,
        &import_id,
        |request| dispatch(&harness, Some(&north_token), request),
    )
    .await
    .expect("resumed authenticated HTTP chunk commits")
    .expect("one chunk remained");
    assert_eq!(second.chunk_index(), 1);
    assert_eq!(second.committed_items(), 1);
    assert!(second.is_complete());
    assert!(execute_import_chunk(
        &plan,
        &mut resumed,
        &package_revision,
        &schema_fingerprint,
        &import_id,
        |request| dispatch(&harness, Some(&north_token), request),
    )
    .await
    .expect("a completed checkpoint is stable")
    .is_none());
    let after = effect_counts(&harness).await;
    assert_eq!(after.current - before.current, 5);
    assert_eq!(after.revisions - before.revisions, 5);
    assert_eq!(
        after.outbox - before.outbox,
        0,
        "a fixture without configured events cannot gain an import-only outbox side path"
    );
    assert_eq!(after.idempotency - before.idempotency, 2);
    assert!(after.audit > before.audit);

    let unauthorized_input = serde_json::to_string(&plot_item(
        &holding_id,
        "P-CONCEALED-CANARY",
        "concealed-import-source-canary",
        "concealed-record-canary",
        30.70,
    ))
    .expect("negative item serializes")
        + "\n";
    let unauthorized_plan = DataImportPlan::from_jsonl(
        &harness.registry,
        "plot",
        DataImportOperation::Create,
        PROFILE,
        unauthorized_input.as_bytes(),
    )
    .expect("offline validation does not invent caller authority");
    let mut unauthorized_checkpoint =
        DataImportCheckpoint::start(&unauthorized_plan, &package_revision, &schema_fingerprint)
            .expect("negative checkpoint starts");
    let unauthorized_import_id = unauthorized_checkpoint.import_id().to_owned();
    let unauthorized = execute_import_chunk(
        &unauthorized_plan,
        &mut unauthorized_checkpoint,
        &package_revision,
        &schema_fingerprint,
        &unauthorized_import_id,
        |request| dispatch(&harness, Some(&south_token), request),
    )
    .await
    .expect_err("a token outside the row boundary is refused by normal HTTP authorization");
    assert_eq!(unauthorized, DataError::OperationRefused);
    assert_eq!(unauthorized_checkpoint.completed_chunk_count(), 0);
    let rendered = format!("{unauthorized:?} {unauthorized}");
    for canary in [
        "P-CONCEALED-CANARY",
        "concealed-import-source-canary",
        "concealed-record-canary",
        &holding_id,
        &south_token,
    ] {
        assert!(!rendered.contains(canary));
    }

    let race_left = one_item_plan(
        &harness,
        &holding_id,
        "P-RACE-LEFT",
        "race-source",
        "same-key",
        30.80,
    );
    let race_right = one_item_plan(
        &harness,
        &holding_id,
        "P-RACE-RIGHT",
        "race-source",
        "same-key",
        30.81,
    );
    let mut left_checkpoint =
        DataImportCheckpoint::start(&race_left, &package_revision, &schema_fingerprint).unwrap();
    let mut right_checkpoint =
        DataImportCheckpoint::start(&race_right, &package_revision, &schema_fingerprint).unwrap();
    let left_import_id = left_checkpoint.import_id().to_owned();
    let right_import_id = right_checkpoint.import_id().to_owned();
    let left = execute_import_chunk(
        &race_left,
        &mut left_checkpoint,
        &package_revision,
        &schema_fingerprint,
        &left_import_id,
        |request| dispatch(&harness, Some(&north_token), request),
    );
    let right = execute_import_chunk(
        &race_right,
        &mut right_checkpoint,
        &package_revision,
        &schema_fingerprint,
        &right_import_id,
        |request| dispatch(&harness, Some(&north_token), request),
    );
    let (left, right) = tokio::join!(left, right);
    let outcomes = [left, right];
    assert_eq!(
        outcomes.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one independently keyed import wins the database uniqueness race"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(DataError::OperationRefused)))
            .count(),
        1
    );
    assert_eq!(
        left_checkpoint.completed_chunk_count() + right_checkpoint.completed_chunk_count(),
        1,
        "only the committed HTTP response advances a checkpoint"
    );
    assert_eq!(race_key_count(&harness).await, 1);

    harness.finish().await;
}

fn one_item_plan(
    harness: &PilotHarness,
    holding_id: &str,
    plot_code: &str,
    source: &str,
    source_record_id: &str,
    longitude: f64,
) -> DataImportPlan {
    let input = serde_json::to_string(&plot_item(
        holding_id,
        plot_code,
        source,
        source_record_id,
        longitude,
    ))
    .unwrap()
        + "\n";
    DataImportPlan::from_jsonl(
        &harness.registry,
        "plot",
        DataImportOperation::Create,
        PROFILE,
        input.as_bytes(),
    )
    .expect("race import validates")
}

fn plot_item(
    holding_id: &str,
    plot_code: &str,
    source: &str,
    source_record_id: &str,
    longitude: f64,
) -> Value {
    json!({"operation":"create", "data":{
        "plot-code":plot_code, "holding":holding_id,
        "administrative-boundary":"north-district",
        "centroid":{"type":"Point","coordinates":[longitude,-9.5]},
        "area-value":"1.2500", "area-unit":"hectare",
        "import-source":source, "source-record-id":source_record_id
    }})
}

async fn dispatch(
    harness: &PilotHarness,
    token: Option<&str>,
    request: DataHttpRequest,
) -> Result<DataHttpResponse, ()> {
    let method = match request.method() {
        DataHttpMethod::Get => Method::GET,
        DataHttpMethod::Post => Method::POST,
    };
    let mut headers = Vec::new();
    if let Some(content_type) = request.content_type() {
        headers.push(("content-type", content_type));
    }
    if let Some(key) = request.idempotency_key() {
        headers.push(("idempotency-key", key));
    }
    let response = harness
        .send(
            method,
            request.path_and_query(),
            token,
            &headers,
            request.body().to_vec(),
        )
        .await;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response_bytes(response).await;
    DataHttpResponse::new(status, content_type, body).map_err(|_| ())
}

async fn create(
    harness: &PilotHarness,
    token: &str,
    route: &str,
    key: &str,
    data: Value,
) -> String {
    let response = harness
        .send_json(
            Method::POST,
            route,
            Some(token),
            Some(key),
            json!({"data":data}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    response_json(response).await["id"]
        .as_str()
        .expect("created record has id")
        .to_owned()
}

async fn active_identity(harness: &PilotHarness) -> (String, String) {
    let row = harness
        .database
        .admin
        .query_one(
            "SELECT active_package_revision, schema_fingerprint FROM registry_internal.registry_state",
            &[],
        )
        .await
        .expect("administrator reads active test identity");
    (row.get(0), row.get(1))
}

#[derive(Clone, Copy)]
struct Counts {
    current: i64,
    revisions: i64,
    outbox: i64,
    audit: i64,
    idempotency: i64,
}

async fn effect_counts(harness: &PilotHarness) -> Counts {
    let table = &harness.registry.entities()["plot"].physical_table;
    let row = harness
        .database
        .admin
        .query_one(
            &format!(
                "SELECT
                   (SELECT count(*) FROM registry_data.\"{table}\"),
                   (SELECT count(*) FROM registry_internal.registry_revisions),
                   (SELECT count(*) FROM registry_internal.registry_outbox),
                   (SELECT count(*) FROM registry_internal.registry_audit),
                   (SELECT count(*) FROM registry_internal.registry_idempotency)"
            ),
            &[],
        )
        .await
        .expect("administrator inspects durable import effects");
    Counts {
        current: row.get(0),
        revisions: row.get(1),
        outbox: row.get(2),
        audit: row.get(3),
        idempotency: row.get(4),
    }
}

async fn race_key_count(harness: &PilotHarness) -> i64 {
    let entity = &harness.registry.entities()["plot"];
    let table = &entity.physical_table;
    let source = &entity.fields["import-source"].physical_name;
    let record = &entity.fields["source-record-id"].physical_name;
    harness
        .database
        .admin
        .query_one(
            &format!(
                "SELECT count(*) FROM registry_data.\"{table}\"
                  WHERE \"{source}\" = 'race-source' AND \"{record}\" = 'same-key'"
            ),
            &[],
        )
        .await
        .expect("administrator verifies unique import key")
        .get(0)
}
