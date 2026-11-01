// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "breg")]
//! Mock boundary tests for the BReg connector's batch family and finite
//! ingestion run protocol (N5): bound enforcement at prepare, the
//! replayed-chunk note, the read-then-decide run recovery, and the
//! operator-authority gate, against a scripted in-process BReg.

#[path = "support/mod.rs"]
mod support;

use axum::http::StatusCode;
use registry_adapter_connectors::operation::{
    CommandKey, ConnectorFault, Observable, Operation, OutcomeCategory, PreparedAttempt,
    SendOutcome,
};
use registry_breg_client::BRegProblemCode;
use serde_json::{json, Value};

use support::{
    chunk_submission, ingestion_run, problem, Mock, INPUT_DIGEST, PACKAGE_REVISION, PROFILE,
    RECORD_ID, RUN_ID, SCHEMA_FINGERPRINT, SERVER_ETAG, TOKEN,
};

fn key(step: &str) -> CommandKey {
    CommandKey::new(format!("adapter-unit/company/{step}")).expect("derived key")
}

fn batch_input() -> Value {
    json!({
        "items": [
            {"operation": "create", "data": {"legalName": "Batch Ltd"}},
            {"operation": "patch", "record": RECORD_ID, "etag": SERVER_ETAG,
             "operations": [{"op": "replace", "field": "legalName", "value": "Batched Ltd"}]}
        ]
    })
}

fn batch_receipt() -> Value {
    json!({"snapshot": format!("breg1_{RUN_ID}"), "results": [
        {"operation": "create", "recordIdentifier": RECORD_ID, "revisionIdentifier": "1",
         "etag": SERVER_ETAG, "domainData": {"legalName": "Batch Ltd"}},
        {"operation": "patch", "recordIdentifier": RECORD_ID, "revisionIdentifier": "2",
         "etag": SERVER_ETAG, "domainData": {"legalName": "Batched Ltd"}}
    ]})
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_sends_one_atomic_exchange_and_completes_on_the_snapshot() {
    let mock = Mock::start("immediate", false).await;
    mock.push(support::mutation_json(StatusCode::OK, batch_receipt()));
    let answer = {
        let prepared = mock
            .connector
            .batch_records()
            .prepare(&batch_input(), key("batch"))
            .expect("prepares");
        mock.connector.batch_records().send(&prepared)
    };
    let outcome = answer.expect("send answers");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    assert_eq!(
        outcome.correlation.as_deref(),
        Some(format!("breg1_{RUN_ID}").as_str())
    );
    let requests = mock.exchanges();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].uri,
        "/tenant/prefix/v1/records/companies:batch?accessProfile=writer"
    );
    assert_eq!(
        requests[0].idempotency_key.as_deref(),
        Some("adapter-unit/company/batch")
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("batch body");
    assert_eq!(body["items"].as_array().map(Vec::len), Some(2));
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_over_the_binding_bounds_refuses_at_prepare() {
    let mock = Mock::start("immediate", false).await;
    // The fixture binding admits two items; three refuse with no I/O.
    let over_bound = json!({
        "items": [
            {"operation": "create", "data": {"legalName": "One"}},
            {"operation": "create", "data": {"legalName": "Two"}},
            {"operation": "create", "data": {"legalName": "Three"}}
        ]
    });
    let fault = mock
        .connector
        .batch_records()
        .prepare(&over_bound, key("batch"));
    assert_eq!(fault.unwrap_err(), ConnectorFault::InvalidInput);
    assert!(mock.exchanges().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_recovery_resends_the_sealed_items_under_the_same_key() {
    let mock = Mock::start("immediate", false).await;
    let stored = {
        let prepared = mock
            .connector
            .batch_records()
            .prepare(&batch_input(), key("batch"))
            .expect("prepares");
        prepared.as_bytes().to_vec()
    };
    mock.push(support::mutation_json(StatusCode::OK, batch_receipt()));
    let outcome = {
        let prepared = registry_adapter_connectors::breg::batch::PreparedBatch::from_bytes(&stored)
            .expect("restores");
        mock.connector.batch_records().recover(&prepared)
    }
    .expect("recovery answers");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    let requests = mock.exchanges();
    assert_eq!(
        requests[0].idempotency_key.as_deref(),
        Some("adapter-unit/company/batch")
    );
    let bytes = String::from_utf8_lossy(&stored).to_string();
    assert!(!bytes.contains(TOKEN));
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_recovery_refuses_when_the_batch_binding_changed() {
    let original = Mock::start("immediate", false).await;
    let stored = {
        let prepared = original
            .connector
            .batch_records()
            .prepare(&batch_input(), key("batch"))
            .expect("prepares");
        prepared.as_bytes().to_vec()
    };
    // The deployment now resolves a batch binding of another identity; the
    // persisted attempt is never rebuilt against it.
    let changed = Mock::start_at_revision(
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    )
    .await;
    let prepared = registry_adapter_connectors::breg::batch::PreparedBatch::from_bytes(&stored)
        .expect("restores");
    let fault = changed.connector.batch_records().recover(&prepared);
    assert_eq!(fault.unwrap_err(), ConnectorFault::BindingChanged);
    assert!(changed.exchanges().is_empty(), "nothing is sent");
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_observation_reads_the_receipt_snapshot_back() {
    let mock = Mock::start("immediate", false).await;
    mock.push(
        support::MockResponse::json(
            StatusCode::OK,
            json!({
                "items": [],
                "snapshot": format!("breg1_{RUN_ID}"),
                "pageInfo": {"nextCursor": null},
                "meta": {
                    "registryIdentifier": "business-registry",
                    "datasetIdentifier": "legal-entities",
                    "recordTypeIdentifier": "company"
                }
            }),
        )
        .with_header(
            "link",
            "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </tenant/prefix/v1/schemas/company>; rel=\"describedby\"",
        )
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept"),
    );
    let state = mock
        .connector
        .batch_records()
        .observe(&format!("breg1_{RUN_ID}"))
        .expect("observation answers");
    assert_eq!(state.state, "snapshot-readable");
    assert!(state
        .details
        .iter()
        .any(|(name, value)| name == "snapshot" && value.as_str() == format!("breg1_{RUN_ID}")));
}

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_family_stays_out_of_the_catalog_until_authority_opens() {
    let closed = Mock::start_closed_import().await;
    let names: Vec<&str> = closed
        .connector
        .catalog()
        .iter()
        .map(|descriptor| descriptor.name)
        .collect();
    assert!(!names.contains(&"breg.ingestion.create-run"));
    assert!(!names.contains(&"breg.ingestion.submit-chunk"));
    let fault = closed.connector.ingestion_create_run().prepare(
        &json!({
            "profile": PROFILE, "operation": "create",
            "packageRevision": PACKAGE_REVISION,
            "schemaFingerprint": SCHEMA_FINGERPRINT,
            "inputDigest": INPUT_DIGEST, "inputLength": 64,
            "itemCount": 2, "chunkCount": 1
        }),
        key("create-run"),
    );
    assert_eq!(fault.unwrap_err(), ConnectorFault::AuthorityAbsent);
}

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_create_run_accepts_with_the_run_correlation() {
    let mock = Mock::start("immediate", false).await;
    mock.push(support::mutation_json(
        StatusCode::CREATED,
        json!({"run": ingestion_run("open", 0, 0, &support::empty_prefix_digest())}),
    ));
    let outcome = {
        let prepared = mock
            .connector
            .ingestion_create_run()
            .prepare(
                &json!({
                    "profile": PROFILE, "operation": "create",
                    "packageRevision": PACKAGE_REVISION,
                    "schemaFingerprint": SCHEMA_FINGERPRINT,
                    "inputDigest": INPUT_DIGEST, "inputLength": 64,
                    "itemCount": 2, "chunkCount": 1
                }),
                key("create-run"),
            )
            .expect("prepares");
        assert!(mock.exchanges().is_empty());
        mock.connector.ingestion_create_run().send(&prepared)
    }
    .expect("send answers");
    assert_eq!(outcome.category, OutcomeCategory::Accepted);
    assert_eq!(
        outcome.correlation.as_deref(),
        Some(format!("{RUN_ID}/{PROFILE}").as_str())
    );
    // The announcement carries no idempotency key; the destination derives
    // its own attempt identity.
    let requests = mock.exchanges();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].idempotency_key.is_none());
    assert_eq!(
        requests[0].uri,
        "/tenant/prefix/v1/records/companies/ingestion-runs?accessProfile=writer"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("announcement");
    assert_eq!(body["inputDigest"], INPUT_DIGEST);
    assert_eq!(body["itemCount"], 2);
    assert_eq!(
        body["chunkAlgorithmVersion"],
        "greedy-canonical-http-batch-v1"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_create_run_recovery_reads_before_it_announces_again() {
    let mock = Mock::start("immediate", false).await;
    // The announcement's answer is lost past the attempt timeout.
    mock.push(support::mutation_json(StatusCode::CREATED, json!({})).hanging());
    let stored = {
        let prepared = mock
            .connector
            .ingestion_create_run()
            .prepare(
                &json!({
                    "profile": PROFILE, "operation": "create",
                    "packageRevision": PACKAGE_REVISION,
                    "schemaFingerprint": SCHEMA_FINGERPRINT,
                    "inputDigest": INPUT_DIGEST, "inputLength": 64,
                    "itemCount": 2, "chunkCount": 1
                }),
                key("create-run"),
            )
            .expect("prepares");
        prepared.as_bytes().to_vec()
    };
    let uncertain = {
        let prepared =
            registry_adapter_connectors::breg::ingestion::PreparedCreateRun::from_bytes(&stored)
                .expect("restores");
        mock.connector.ingestion_create_run().send(&prepared)
    }
    .expect("uncertainty is an outcome");
    assert_eq!(uncertain.category, OutcomeCategory::Uncertain);
    // Recovery lists the caller's open runs under the input digest and
    // settles on the run the destination proves, announcing nothing new.
    mock.push(support::mutation_json(
        StatusCode::OK,
        json!({
            "runs": [ingestion_run("open", 0, 0, &support::empty_prefix_digest())],
            "hasMore": false,
            "nextCursor": null
        }),
    ));
    let recovered = {
        let prepared =
            registry_adapter_connectors::breg::ingestion::PreparedCreateRun::from_bytes(&stored)
                .expect("restores");
        mock.connector.ingestion_create_run().recover(&prepared)
    }
    .expect("recovery answers");
    assert_eq!(recovered.category, OutcomeCategory::Accepted);
    assert_eq!(
        recovered.correlation.as_deref(),
        Some(format!("{RUN_ID}/{PROFILE}").as_str())
    );
    let requests = mock.exchanges();
    assert_eq!(requests.len(), 2, "the lost announcement, then the listing");
    assert_eq!(
        requests[1].uri,
        format!(
            "/tenant/prefix/v1/records/companies/ingestion-runs?accessProfile={PROFILE}&status=open&inputDigest={INPUT_DIGEST}"
        )
    );
}

/// Announce a run whose answer is lost, and return the stored prepared
/// form for recovery.
async fn lost_announcement(mock: &Mock) -> Vec<u8> {
    mock.push(support::mutation_json(StatusCode::CREATED, json!({})).hanging());
    let stored = {
        let prepared = mock
            .connector
            .ingestion_create_run()
            .prepare(
                &json!({
                    "profile": PROFILE, "operation": "create",
                    "packageRevision": PACKAGE_REVISION,
                    "schemaFingerprint": SCHEMA_FINGERPRINT,
                    "inputDigest": INPUT_DIGEST, "inputLength": 64,
                    "itemCount": 2, "chunkCount": 1
                }),
                key("create-run"),
            )
            .expect("prepares");
        prepared.as_bytes().to_vec()
    };
    let uncertain = {
        let prepared =
            registry_adapter_connectors::breg::ingestion::PreparedCreateRun::from_bytes(&stored)
                .expect("restores");
        mock.connector.ingestion_create_run().send(&prepared)
    }
    .expect("uncertainty is an outcome");
    assert_eq!(uncertain.category, OutcomeCategory::Uncertain);
    stored
}

fn recover_run(mock: &Mock, stored: &[u8]) -> SendOutcome {
    let prepared =
        registry_adapter_connectors::breg::ingestion::PreparedCreateRun::from_bytes(stored)
            .expect("restores");
    mock.connector
        .ingestion_create_run()
        .recover(&prepared)
        .expect("recovery answers")
}

/// An open run under the same input digest whose announcement differs
/// (here: two chunks instead of one), under its own run id.
fn other_announcement(run_id: &str) -> Value {
    let mut run = ingestion_run("open", 0, 0, &support::empty_prefix_digest());
    run["runId"] = json!(run_id);
    run["chunkCount"] = json!(2);
    run
}

const OTHER_RUN_ID: &str = "0b9e9a0e-7c55-4a8f-9d8e-2f2a3c4b5d6e";

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_create_run_recovery_settles_only_on_the_matching_announcement() {
    let mock = Mock::start("immediate", false).await;
    let stored = lost_announcement(&mock).await;
    // The caller holds an older open run under the same digest announced
    // with a different chunk count; recovery skips it.
    mock.push(support::mutation_json(
        StatusCode::OK,
        json!({
            "runs": [
                other_announcement(OTHER_RUN_ID),
                ingestion_run("open", 0, 0, &support::empty_prefix_digest())
            ],
            "hasMore": false,
            "nextCursor": null
        }),
    ));
    let recovered = recover_run(&mock, &stored);
    assert_eq!(recovered.category, OutcomeCategory::Accepted);
    assert_eq!(
        recovered.correlation.as_deref(),
        Some(format!("{RUN_ID}/{PROFILE}").as_str())
    );
    assert_eq!(mock.exchanges().len(), 2, "no new announcement");
}

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_create_run_recovery_announces_again_when_no_listed_run_matches() {
    let mock = Mock::start("immediate", false).await;
    let stored = lost_announcement(&mock).await;
    mock.push(support::mutation_json(
        StatusCode::OK,
        json!({
            "runs": [other_announcement(OTHER_RUN_ID)],
            "hasMore": false,
            "nextCursor": null
        }),
    ));
    mock.push(support::mutation_json(
        StatusCode::CREATED,
        json!({"run": ingestion_run("open", 0, 0, &support::empty_prefix_digest())}),
    ));
    let recovered = recover_run(&mock, &stored);
    assert_eq!(recovered.category, OutcomeCategory::Accepted);
    assert_eq!(
        recovered.correlation.as_deref(),
        Some(format!("{RUN_ID}/{PROFILE}").as_str())
    );
    let requests = mock.exchanges();
    assert_eq!(
        requests.len(),
        3,
        "the lost announcement, the listing, the announcement"
    );
    assert_eq!(
        requests[2].uri,
        "/tenant/prefix/v1/records/companies/ingestion-runs?accessProfile=writer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_create_run_recovery_is_uncertain_when_two_runs_match() {
    let mock = Mock::start("immediate", false).await;
    let stored = lost_announcement(&mock).await;
    let mut twin = ingestion_run("open", 0, 0, &support::empty_prefix_digest());
    twin["runId"] = json!(OTHER_RUN_ID);
    mock.push(support::mutation_json(
        StatusCode::OK,
        json!({
            "runs": [ingestion_run("open", 0, 0, &support::empty_prefix_digest()), twin],
            "hasMore": false,
            "nextCursor": null
        }),
    ));
    let recovered = recover_run(&mock, &stored);
    assert_eq!(recovered.category, OutcomeCategory::Uncertain);
    assert!(recovered.correlation.is_none());
    assert_eq!(mock.exchanges().len(), 2, "no new announcement");
}

/// One page of the open-run listing.
fn run_page(runs: Vec<Value>, next_cursor: Option<&str>) -> support::MockResponse {
    support::mutation_json(
        StatusCode::OK,
        json!({"runs": runs, "hasMore": next_cursor.is_some(), "nextCursor": next_cursor}),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_create_run_recovery_follows_the_listing_past_its_first_page() {
    let mock = Mock::start("immediate", false).await;
    let stored = lost_announcement(&mock).await;
    mock.push(run_page(
        vec![other_announcement(OTHER_RUN_ID)],
        Some(OTHER_RUN_ID),
    ));
    mock.push(run_page(
        vec![ingestion_run("open", 0, 0, &support::empty_prefix_digest())],
        None,
    ));
    let recovered = recover_run(&mock, &stored);
    assert_eq!(recovered.category, OutcomeCategory::Accepted);
    assert_eq!(
        recovered.correlation.as_deref(),
        Some(format!("{RUN_ID}/{PROFILE}").as_str())
    );
    let requests = mock.exchanges();
    assert_eq!(requests.len(), 3, "the lost announcement, then two pages");
    assert!(
        requests[2]
            .uri
            .contains(&format!("&cursor={OTHER_RUN_ID}&")),
        "the second page continues after the first: {}",
        requests[2].uri
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_create_run_recovery_is_uncertain_when_a_later_page_holds_a_twin() {
    let mock = Mock::start("immediate", false).await;
    let stored = lost_announcement(&mock).await;
    let mut twin = ingestion_run("open", 0, 0, &support::empty_prefix_digest());
    twin["runId"] = json!(OTHER_RUN_ID);
    mock.push(run_page(
        vec![ingestion_run("open", 0, 0, &support::empty_prefix_digest())],
        Some(RUN_ID),
    ));
    mock.push(run_page(vec![twin], None));
    let recovered = recover_run(&mock, &stored);
    assert_eq!(recovered.category, OutcomeCategory::Uncertain);
    assert!(recovered.correlation.is_none());
    assert_eq!(mock.exchanges().len(), 3, "no new announcement");
}

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_create_run_recovery_is_uncertain_when_the_listing_outruns_its_bound() {
    let mock = Mock::start("immediate", false).await;
    let stored = lost_announcement(&mock).await;
    // Every page continues; recovery stops at its page bound without
    // proving the run absent, so it announces nothing.
    for _ in 0..RECOVERY_PAGE_BOUND {
        mock.push(run_page(
            vec![other_announcement(OTHER_RUN_ID)],
            Some(OTHER_RUN_ID),
        ));
    }
    let recovered = recover_run(&mock, &stored);
    assert_eq!(recovered.category, OutcomeCategory::Uncertain);
    assert!(recovered.correlation.is_none());
    assert_eq!(
        mock.exchanges().len(),
        1 + RECOVERY_PAGE_BOUND,
        "the listing pages, and no new announcement"
    );
}

/// The open-run pages recovery reads before it stays uncertain.
const RECOVERY_PAGE_BOUND: usize = 10;

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_chunk_submits_and_names_a_replay_in_the_note() {
    let mock = Mock::start("immediate", false).await;
    let items = json!([
        {"operation": "create", "data": {"legalName": "Chunk One"}},
        {"operation": "create", "data": {"legalName": "Chunk Two"}}
    ]);
    let items = items.as_array().expect("items").clone();
    // First commit.
    mock.push(support::mutation_json(
        StatusCode::OK,
        chunk_submission(&items, false),
    ));
    let input = json!({
        "run": RUN_ID, "profile": PROFILE, "chunkIndex": 0,
        "prefixDigest": support::empty_prefix_digest(),
        "items": items
    });
    let outcome = {
        let prepared = mock
            .connector
            .ingestion_submit_chunk()
            .prepare(&input, key("chunk"))
            .expect("prepares");
        mock.connector.ingestion_submit_chunk().send(&prepared)
    }
    .expect("send answers");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    assert!(outcome.note.is_none());
    // The identical resubmission replays the retained receipt; the
    // outcome names the replay in its note, never as a problem.
    mock.push(support::mutation_json(
        StatusCode::OK,
        chunk_submission(&items, true),
    ));
    let replayed = {
        let prepared = mock
            .connector
            .ingestion_submit_chunk()
            .prepare(&input, key("chunk"))
            .expect("prepares");
        mock.connector.ingestion_submit_chunk().send(&prepared)
    }
    .expect("replay answers");
    assert_eq!(replayed.category, OutcomeCategory::Completed);
    assert_eq!(
        replayed.note,
        Some("the destination replayed its retained receipt for this chunk")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_chunk_recovery_resends_the_identical_chunk() {
    let mock = Mock::start("immediate", false).await;
    let items = json!([{"operation": "create", "data": {"legalName": "Chunk One"}}]);
    let items = items.as_array().expect("items").clone();
    mock.push(support::mutation_json(StatusCode::OK, json!({})).hanging());
    let stored = {
        let prepared = mock
            .connector
            .ingestion_submit_chunk()
            .prepare(
                &json!({
                    "run": RUN_ID, "profile": PROFILE, "chunkIndex": 0,
                    "prefixDigest": support::empty_prefix_digest(),
                    "items": items
                }),
                key("chunk"),
            )
            .expect("prepares");
        prepared.as_bytes().to_vec()
    };
    let uncertain = {
        let prepared =
            registry_adapter_connectors::breg::ingestion::PreparedSubmitChunk::from_bytes(&stored)
                .expect("restores");
        mock.connector.ingestion_submit_chunk().send(&prepared)
    }
    .expect("uncertainty is an outcome");
    assert_eq!(uncertain.category, OutcomeCategory::Uncertain);
    mock.push(support::mutation_json(
        StatusCode::OK,
        chunk_submission(&items, true),
    ));
    let recovered = {
        let prepared =
            registry_adapter_connectors::breg::ingestion::PreparedSubmitChunk::from_bytes(&stored)
                .expect("restores");
        mock.connector.ingestion_submit_chunk().recover(&prepared)
    }
    .expect("recovery answers");
    assert_eq!(recovered.category, OutcomeCategory::Completed);
    assert_eq!(
        recovered.note,
        Some("the destination replayed its retained receipt for this chunk")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_observation_reads_the_run_state() {
    let mock = Mock::start("immediate", false).await;
    mock.push(support::mutation_json(
        StatusCode::OK,
        json!({"run": ingestion_run("open", 1, 2, &support::empty_prefix_digest())}),
    ));
    let state = mock
        .connector
        .ingestion_create_run()
        .observe(&format!("{RUN_ID}/{PROFILE}"))
        .expect("observation answers");
    assert_eq!(state.state, "open");
    assert!(state
        .details
        .iter()
        .any(|(name, value)| name == "inputDigest" && value == INPUT_DIGEST));
    assert!(state
        .details
        .iter()
        .any(|(name, value)| name == "committedItems" && value == "2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn ingestion_refusal_surfaces_the_product_word() {
    let mock = Mock::start("immediate", false).await;
    mock.push(problem(BRegProblemCode::IngestionRunNotOpen));
    let outcome = {
        let prepared = mock
            .connector
            .ingestion_create_run()
            .prepare(
                &json!({
                    "profile": PROFILE, "operation": "create",
                    "packageRevision": PACKAGE_REVISION,
                    "schemaFingerprint": SCHEMA_FINGERPRINT,
                    "inputDigest": INPUT_DIGEST, "inputLength": 64,
                    "itemCount": 2, "chunkCount": 1
                }),
                key("create-run"),
            )
            .expect("prepares");
        mock.connector.ingestion_create_run().send(&prepared)
    }
    .expect("refusal is an outcome");
    assert_eq!(outcome.category, OutcomeCategory::Refused);
    assert_eq!(
        outcome.native_problem.as_deref(),
        Some("ingestion.run_not_open")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_recovery_under_a_spent_key_is_uncertain() {
    let mock = Mock::start("immediate", false).await;
    let prepared = mock
        .connector
        .batch_records()
        .prepare(&batch_input(), key("batch"))
        .expect("prepares");
    mock.push(problem(BRegProblemCode::IdempotencyConflict));
    let recovered = mock
        .connector
        .batch_records()
        .recover(&prepared)
        .expect("recovery answers");
    assert_eq!(
        recovered.category,
        OutcomeCategory::Uncertain,
        "{recovered:?}"
    );
}
