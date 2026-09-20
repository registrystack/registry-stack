// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::field_encryption::{FieldEncryptionProvider, FieldEncryptionService};
use registry_breg::mutation::MutationFaultPoint;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use registry_platform_config::{SecretProvider, SecretReference, SecretResolver};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PRINCIPAL: &str = "ingestion-principal-must-not-enter-run-rows";
const OTHER_PRINCIPAL: &str = "ingestion-other-principal";
const RECORD_CANARY: &str = "ingestion-record-value-must-not-enter-run-rows";
const PACKAGE_ID: &str = "ingestion-registry";
const PACKAGE_REVISION: &str = "package-ingestion-1";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ingestion_run_journey_commits_resumes_and_replays_without_duplicates() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items: Vec<Value> = (0..5)
        .map(|index| {
            json!({"operation":"create", "data": {
                "jurisdiction": "zone-a",
                "label": format!("{RECORD_CANARY}-{index}"),
                "quantity": index
            }})
        })
        .collect();
    let chunks = plan_chunks(&items, 3);

    let created = harness
        .post_json(
            "/v1/records/widgets/ingestion-runs",
            &claims,
            harness.run_body("create", &chunks),
        )
        .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let run = body_json(created).await["run"].clone();
    assert_eq!(run["status"], "open");
    assert_eq!(run["complete"], false);
    assert_eq!(run["nextChunkIndex"], 0);
    assert_eq!(run["committedItems"], 0);
    assert_eq!(run["itemCount"], 5);
    assert_eq!(run["chunkCount"], 2);
    assert_eq!(run["maximumItems"], 3);
    assert_eq!(
        run["chunkAlgorithmVersion"],
        "greedy-canonical-http-batch-v1"
    );
    assert_eq!(run["lastAttempt"], Value::Null);
    let run_id = run["runId"].as_str().expect("run id").to_owned();

    let first = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = body_json(first).await;
    assert_eq!(first_body["run"]["nextChunkIndex"], 1);
    assert_eq!(first_body["run"]["committedItems"], 3);
    assert_eq!(first_body["run"]["complete"], false);
    assert_eq!(first_body["receipt"]["chunkIndex"], 0);
    assert_eq!(first_body["receipt"]["replayed"], false);
    assert_eq!(first_body["receipt"]["digest"], chunks.digests[0]);
    assert_eq!(
        first_body["receipt"]["batch"]["results"]
            .as_array()
            .expect("receipt results")
            .len(),
        3
    );

    // A restarted process resumes from the stored checkpoint alone: the new
    // router shares only the database with the one that committed chunk 0.
    let resumed = harness.restart(None).await;
    let second = resumed
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 1),
        )
        .await;
    assert_eq!(second.status(), StatusCode::OK);
    let second_body = body_json(second).await;
    assert_eq!(second_body["run"]["status"], "complete");
    assert_eq!(second_body["run"]["complete"], true);
    assert_eq!(second_body["run"]["committedItems"], 5);
    assert_eq!(second_body["run"]["nextChunkIndex"], 2);
    assert_eq!(second_body["receipt"]["replayed"], false);

    let durable = durable_widget_count(&harness).await;
    assert_eq!(durable, 5, "every announced item is committed exactly once");

    // Resubmitting the exact final chunk answers with the original receipt
    // and mutates nothing.
    let replay = resumed
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 1),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::OK);
    let replay_body = body_json(replay).await;
    assert_eq!(replay_body["receipt"]["replayed"], true);
    assert_eq!(
        replay_body["receipt"]["batch"],
        second_body["receipt"]["batch"]
    );
    assert_eq!(durable_widget_count(&harness).await, 5);

    // The receipt-recovery endpoint returns the same stored receipt.
    let recovered = resumed
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks/0/receipt"),
            &claims,
        )
        .await;
    assert_eq!(recovered.status(), StatusCode::OK);
    let recovered_body = body_json(recovered).await;
    assert_eq!(recovered_body["chunkIndex"], 0);
    assert_eq!(recovered_body["digest"], chunks.digests[0]);
    assert_eq!(recovered_body["replayed"], true);
    assert_eq!(
        recovered_body["batch"]["results"]
            .as_array()
            .expect("results")
            .len(),
        3
    );

    // A completed run refuses further chunks.
    let refused = resumed
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            json!({"chunkIndex": 2, "items": [
                {"operation":"create", "data": {"jurisdiction": "zone-a", "label": "post-completion", "quantity": 1}
            }], "digest": zero_digest(), "prefixDigest": zero_digest()}),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["code"], "ingestion.run_not_open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_chunk_response_replays_original_receipt_without_duplicate_mutation() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items: Vec<Value> = (0..5)
        .map(|index| {
            json!({"operation":"create", "data": {
                "jurisdiction": "zone-a",
                "label": format!("{RECORD_CANARY}-faulted-{index}"),
                "quantity": index
            }})
        })
        .collect();
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;

    // The commit lands and the response is lost: the client sees an outage.
    let faulted = harness
        .restart(Some(MutationFaultPoint::AfterCommitBeforeResponseRelease))
        .await;
    let lost = faulted
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(lost.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(durable_widget_count(&harness).await, 3);

    // The same client rereads the file and resubmits the exact chunk.
    let recovered = harness.restart(None).await;
    let replay = recovered
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::OK);
    let replay_body = body_json(replay).await;
    assert_eq!(replay_body["receipt"]["replayed"], true);
    assert_eq!(replay_body["receipt"]["chunkIndex"], 0);
    assert_eq!(durable_widget_count(&harness).await, 3);
    assert_eq!(
        replay_body["run"]["committedItems"], 3,
        "the lost-response recovery advances the checkpoint exactly once"
    );

    // The run still finishes from the recovered checkpoint.
    let finish = recovered
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 1),
        )
        .await;
    assert_eq!(finish.status(), StatusCode::OK);
    assert_eq!(body_json(finish).await["run"]["complete"], true);
    assert_eq!(durable_widget_count(&harness).await, 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn divergent_chunk_submissions_are_refused_without_moving_the_checkpoint() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items: Vec<Value> = (0..5)
        .map(|index| {
            json!({"operation":"create", "data": {
                "jurisdiction": "zone-a",
                "label": format!("{RECORD_CANARY}-diverge-{index}"),
                "quantity": index
            }})
        })
        .collect();
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;
    let uri = format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks");

    // Skipping ahead past the next expected chunk is a mismatch.
    let ahead = harness
        .post_json(&uri, &claims, chunk_body(&chunks, 1))
        .await;
    assert_eq!(ahead.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(ahead).await["code"], "ingestion.chunk_mismatch");

    // Item bytes that do not hash to the announced digest are a mismatch.
    let mut swapped = chunk_body(&chunks, 0);
    swapped["items"][0]["data"]["label"] = json!(format!("{RECORD_CANARY}-swapped"));
    let mismatch = harness.post_json(&uri, &claims, swapped).await;
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_json(mismatch).await["code"],
        "ingestion.chunk_mismatch"
    );

    // An item no chunk operation admits is an invalid request.
    let invalid = harness
        .post_json(
            &uri,
            &claims,
            json!({"chunkIndex": 0, "items": [{"operation":"upsert","data":{}}], "digest": zero_digest(), "prefixDigest": zero_digest()}),
        )
        .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    // The checkpoint has not moved under any refusal.
    let run = harness.read_run(&claims, &run_id).await;
    assert_eq!(run["nextChunkIndex"], 0);
    assert_eq!(run["committedItems"], 0);
    assert_eq!(run["lastAttempt"]["outcome"], "chunkMismatch");

    // The exact chunk still commits after the refusals.
    let accepted = harness
        .post_json(&uri, &claims, chunk_body(&chunks, 0))
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);

    // Committing past the announced item total is a mismatch: the remaining
    // chunk may not carry more items than the run announced in total.
    let mut overrun = chunk_body(&chunks, 1);
    overrun["items"]
        .as_array_mut()
        .expect("items")
        .push(json!({"operation":"create", "data": {
            "jurisdiction": "zone-a", "label": format!("{RECORD_CANARY}-overrun"), "quantity": 9
        }}));
    overrun["digest"] = json!(chunk_digest(overrun["items"].as_array().expect("items")));
    let exceeded = harness.post_json(&uri, &claims, overrun).await;
    assert_eq!(exceeded.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_json(exceeded).await["code"],
        "ingestion.chunk_mismatch"
    );

    // Replaying a committed chunk index with different bytes is a mismatch.
    let mut divergent = chunk_body(&chunks, 0);
    divergent["items"][1]["data"]["label"] = json!(format!("{RECORD_CANARY}-rewritten"));
    divergent["digest"] = json!(chunk_digest(divergent["items"].as_array().expect("items")));
    let rewritten = harness.post_json(&uri, &claims, divergent).await;
    assert_eq!(rewritten.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_json(rewritten).await["code"],
        "ingestion.chunk_mismatch"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_access_is_creator_scoped_and_possession_grants_nothing() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let other = operator_claims(OTHER_PRINCIPAL, "zone-a");
    let items = announce_items("scoped", 1);
    let chunks = plan_chunks(&items, 1);
    let run_id = harness.create_run(&claims, &chunks).await;

    let foreign_read = harness
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{}", run_id),
            &other,
        )
        .await;
    assert_eq!(foreign_read.status(), StatusCode::NOT_FOUND);

    let foreign_chunk = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{}/chunks", run_id),
            &other,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(foreign_chunk.status(), StatusCode::NOT_FOUND);

    let foreign_receipt = harness
        .get_json(
            &format!(
                "/v1/records/widgets/ingestion-runs/{}/chunks/0/receipt",
                run_id
            ),
            &other,
        )
        .await;
    assert_eq!(foreign_receipt.status(), StatusCode::NOT_FOUND);

    let foreign_cancel = harness
        .post_empty(
            &format!("/v1/records/widgets/ingestion-runs/{}/cancel", run_id),
            &other,
        )
        .await;
    assert_eq!(foreign_cancel.status(), StatusCode::NOT_FOUND);

    // Another principal still creates and lists their own runs.
    let own = harness
        .post_json(
            "/v1/records/widgets/ingestion-runs",
            &other,
            harness.run_body(
                "create",
                &plan_chunks(&announce_items("scoped-other", 1), 1),
            ),
        )
        .await;
    assert_eq!(own.status(), StatusCode::CREATED);

    let listed = harness
        .get_json("/v1/records/widgets/ingestion-runs", &claims)
        .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = body_json(listed).await;
    let runs = listed["runs"].as_array().expect("runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["runId"], run_id.as_str());
    assert_eq!(listed["hasMore"], false);

    // An unauthenticated caller cannot create a run at all.
    let anonymous = harness
        .post_json(
            "/v1/records/widgets/ingestion-runs",
            &anonymous_claims(),
            harness.run_body("create", &chunks),
        )
        .await;
    assert_ne!(anonymous.status(), StatusCode::CREATED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_creation_refuses_mismatched_profiles_bindings_and_algorithms() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("refused", 1);
    let chunks = plan_chunks(&items, 1);

    let mut mismatched = harness.run_body("create", &chunks);
    mismatched["profileId"] = json!("operator-minimal");
    let profile = harness
        .post_json(
            "/v1/records/widgets/ingestion-runs?accessProfile=operator",
            &claims,
            mismatched,
        )
        .await;
    assert_eq!(profile.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(profile).await["code"],
        "ingestion.profile_mismatch"
    );

    let mut stale = harness.run_body("create", &chunks);
    stale["packageRevision"] = json!("package-ingestion-0");
    let refused = harness
        .post_json("/v1/records/widgets/ingestion-runs", &claims, stale)
        .await;
    assert_eq!(refused.status(), StatusCode::PRECONDITION_FAILED);

    let mut algorithm = harness.run_body("create", &chunks);
    algorithm["chunkAlgorithmVersion"] = json!("future-algorithm-v9");
    let refused = harness
        .post_json("/v1/records/widgets/ingestion-runs", &claims, algorithm)
        .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

    let refused = harness
        .post_json(
            "/v1/records/ledgers/ingestion-runs",
            &claims,
            harness.run_body("create", &chunks),
        )
        .await;
    // The ledger entity carries no batch surface, so no ingestion-run
    // resource exists for it at all.
    assert_eq!(refused.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn package_change_blocks_the_run_and_keeps_it_inspectable() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("blocked", 5);
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;

    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{}/chunks", run_id),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);
    assert_eq!(durable_widget_count(&harness).await, 3);
    let original_receipt = body_json(committed).await["receipt"].clone();

    // A new active package revision must not reinterpret remaining source
    // bytes: the run is blocked, not silently re-bound.
    let changed = harness.restart_with_revision("package-ingestion-2").await;
    let blocked = changed
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{}/chunks", run_id),
            &claims,
            chunk_body(&chunks, 1),
        )
        .await;
    assert_eq!(blocked.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(blocked).await["code"], "ingestion.run_blocked");

    let inspected = changed
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{}", run_id),
            &claims,
        )
        .await;
    assert_eq!(inspected.status(), StatusCode::OK);
    let run = body_json(inspected).await["run"].clone();
    assert_eq!(run["status"], "blocked");
    assert_eq!(run["blockedReason"], "activePackageChanged");
    assert_eq!(run["committedItems"], 3);
    assert_eq!(run["nextChunkIndex"], 1);

    // A committed chunk replays in any run status: the blocked binding
    // governs only chunks the checkpoint has not covered.
    let replayed = changed
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{}/chunks", run_id),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replayed.status(), StatusCode::OK);
    let replay_body = body_json(replayed).await;
    assert_eq!(replay_body["receipt"]["replayed"], true);
    assert_eq!(replay_body["receipt"]["batch"], original_receipt["batch"]);
    assert_eq!(durable_widget_count(&harness).await, 3);

    // A blocked run refuses the next uncommitted chunk again, consistently.
    let refused = changed
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{}/chunks", run_id),
            &claims,
            chunk_body(&chunks, 1),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["code"], "ingestion.run_blocked");

    // The blocking audit record carries the blocked state it wrote.
    let blocked_records = harness
        .database
        .admin
        .query(
            "SELECT convert_from(envelope, 'UTF8')
               FROM registry_internal.registry_audit
              WHERE convert_from(envelope, 'UTF8') LIKE '%\"kind\":\"ingestionRun\"%'
                AND convert_from(envelope, 'UTF8') LIKE '%\"outcome\":\"blocked\"%'",
            &[],
        )
        .await
        .expect("administrator inspects the run audit journal");
    assert!(
        !blocked_records.is_empty(),
        "the blocked transition is audited"
    );
    for row in blocked_records {
        let envelope: Value =
            serde_json::from_str(&row.get::<_, String>(0)).expect("audit envelope is JSON");
        assert_eq!(envelope["record"]["status"], "blocked");
    }

    // The creator may still cancel a blocked run.
    let cancelled = changed
        .post_empty(
            &format!("/v1/records/widgets/ingestion-runs/{}/cancel", run_id),
            &claims,
        )
        .await;
    assert_eq!(cancelled.status(), StatusCode::OK);
    assert_eq!(body_json(cancelled).await["run"]["status"], "cancelled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_closes_the_run_and_preserves_the_committed_prefix() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("cancelled", 4);
    let chunks = plan_chunks(&items, 2);
    let run_id = harness.create_run(&claims, &chunks).await;

    let cancelled = harness
        .post_empty(
            &format!("/v1/records/widgets/ingestion-runs/{}/cancel", run_id),
            &claims,
        )
        .await;
    assert_eq!(cancelled.status(), StatusCode::OK);
    let run = body_json(cancelled).await["run"].clone();
    assert_eq!(run["status"], "cancelled");
    assert_eq!(run["committedItems"], 0);

    let refused = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{}/chunks", run_id),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["code"], "ingestion.run_not_open");

    // Cancelling twice reports the already-closed state.
    let second = harness
        .post_empty(
            &format!("/v1/records/widgets/ingestion-runs/{}/cancel", run_id),
            &claims,
        )
        .await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(second).await["code"], "ingestion.run_not_open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn erasing_record_history_erases_the_receipt_that_describes_it() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("erased", 2);
    let chunks = plan_chunks(&items, 2);
    let run_id = harness.create_run(&claims, &chunks).await;

    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{}/chunks", run_id),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);
    let receipt = body_json(committed).await["receipt"].clone();
    let erased_record = receipt["batch"]["results"][0]["id"]
        .as_str()
        .expect("receipt carries a created record id")
        .to_owned();

    let before = harness
        .get_json(
            &format!(
                "/v1/records/widgets/ingestion-runs/{}/chunks/0/receipt",
                run_id
            ),
            &claims,
        )
        .await;
    assert_eq!(before.status(), StatusCode::OK);

    harness.erase_widget_history(&erased_record).await;

    // The receipt described erased history: recovery reports it gone instead
    // of replaying bytes the record history no longer backs.
    let after = harness
        .get_json(
            &format!(
                "/v1/records/widgets/ingestion-runs/{}/chunks/0/receipt",
                run_id
            ),
            &claims,
        )
        .await;
    assert_eq!(after.status(), StatusCode::GONE);
    assert_eq!(body_json(after).await["code"], "ingestion.receipt_erased");

    let replay = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{}/chunks", run_id),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::GONE);
    assert_eq!(body_json(replay).await["code"], "ingestion.receipt_erased");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receipt_recovery_enforces_the_runs_profile() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("profiled", 1);
    let chunks = plan_chunks(&items, 1);

    // The run is created and driven under the non-default batch profile the
    // same principal also holds.
    let created = harness
        .post_json(
            "/v1/records/widgets/ingestion-runs?accessProfile=operator-minimal",
            &claims,
            run_body_under(
                "create",
                &harness.identity.schema_fingerprint,
                &chunks,
                "operator-minimal",
            ),
        )
        .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let run_id = body_json(created).await["run"]["runId"]
        .as_str()
        .expect("run id")
        .to_owned();

    let committed = harness
        .post_json(
            &format!(
                "/v1/records/widgets/ingestion-runs/{run_id}/chunks?accessProfile=operator-minimal"
            ),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);

    // Recovering the receipt projects record values, so it answers under the
    // run's own profile even for a caller granted another one.
    let mismatched = harness
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks/0/receipt"),
            &claims,
        )
        .await;
    assert_eq!(mismatched.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(mismatched).await["code"],
        "ingestion.profile_mismatch"
    );

    let recovered = harness
        .get_json(
            &format!(
                "/v1/records/widgets/ingestion-runs/{run_id}/chunks/0/receipt?accessProfile=operator-minimal"
            ),
            &claims,
        )
        .await;
    assert_eq!(recovered.status(), StatusCode::OK);
    assert_eq!(body_json(recovered).await["chunkIndex"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_committed_chunk_replay_with_a_divergent_prefix_digest_is_a_mismatch() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("prefix-divergent", 4);
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;
    let uri = format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks");

    let committed = harness
        .post_json(&uri, &claims, chunk_body(&chunks, 0))
        .await;
    assert_eq!(committed.status(), StatusCode::OK);
    let original = body_json(committed).await["receipt"].clone();

    // The same items hash to the announced chunk digest, but the rolling
    // prefix names a different input: the submission is a divergent replay
    // and must not be answered with the retained receipt.
    let mut divergent = chunk_body(&chunks, 0);
    divergent["prefixDigest"] = json!("1".repeat(64));
    let refused = harness.post_json(&uri, &claims, divergent).await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["code"], "ingestion.chunk_mismatch");

    // The exact replay still returns the original receipt's batch answer.
    let replay = harness
        .post_json(&uri, &claims, chunk_body(&chunks, 0))
        .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        body_json(replay).await["receipt"]["batch"],
        original["batch"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_chunks_must_satisfy_the_announced_operation_totals_and_prefix() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");

    // A create run whose chunk carries a well-formed patch item: the item
    // parses for the batch route, but diverges from the announced operation.
    let patch_item = json!({
        "operation": "patch",
        "recordId": Uuid::new_v4().to_string(),
        "ifMatch": "\"breg-ingestion-terminal-proof\"",
        "patch": [{"op": "replace", "path": "/data/quantity", "value": 5}]
    });
    let patch_plan = plan_chunks(std::slice::from_ref(&patch_item), 3);
    let patch_run = harness.create_run(&claims, &patch_plan).await;
    let refused = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{patch_run}/chunks"),
            &claims,
            chunk_body(&patch_plan, 0),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["code"], "ingestion.chunk_mismatch");
    let run = harness.read_run(&claims, &patch_run).await;
    assert_eq!(run["nextChunkIndex"], 0, "the checkpoint does not move");

    // A run announcing four items whose final chunk totals fewer: the run
    // stays open instead of completing on an underrun.
    let items = announce_items("terminal", 4);
    let underrun = chunk_plan(&items, &[(0, 2), (2, 3)]);
    let run_id = harness.create_run(&claims, &underrun).await;
    let uri = format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks");
    let first = harness
        .post_json(&uri, &claims, chunk_body(&underrun, 0))
        .await;
    assert_eq!(first.status(), StatusCode::OK);
    let short = harness
        .post_json(&uri, &claims, chunk_body(&underrun, 1))
        .await;
    assert_eq!(short.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(short).await["code"], "ingestion.chunk_mismatch");
    let run = harness.read_run(&claims, &run_id).await;
    assert_eq!(run["status"], "open");
    assert_eq!(run["committedItems"], 2);
    assert_eq!(run["nextChunkIndex"], 1);

    // A terminal chunk that totals the announced items but binds a prefix
    // other than the whole-input digest is refused the same way.
    let complete = chunk_plan(&items, &[(0, 2), (2, 4)]);
    let mut wrong_prefix = chunk_body(&complete, 1);
    wrong_prefix["prefixDigest"] = json!("2".repeat(64));
    let refused = harness.post_json(&uri, &claims, wrong_prefix).await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["code"], "ingestion.chunk_mismatch");

    // The compliant terminal chunk completes the announced totals exactly.
    let final_chunk = harness
        .post_json(&uri, &claims, chunk_body(&complete, 1))
        .await;
    assert_eq!(final_chunk.status(), StatusCode::OK);
    assert_eq!(body_json(final_chunk).await["run"]["complete"], true);
    assert_eq!(durable_widget_count(&harness).await, 4);
}

/// A chunk digest binds the items as the caller submits them, so a field whose
/// API name differs from its field id must not break the binding: the digest
/// is verified at the ingestion boundary, and the field-id normalization the
/// mutation performs afterwards is not a different chunk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunk_digests_bind_the_submitted_api_names_not_the_field_ids() {
    let fixture = format!("{FIXTURE_HEAD}{FIXTURE_TAIL}")
        .replacen(
            concat!(
                r#"      {"id":"quantity","type":"int64","required":true,"classification":"public"}"#,
                "\n",
            ),
            concat!(
                r#"      {"id":"quantity","type":"int64","required":true,"classification":"public"},"#,
                "\n",
                r#"      {"id":"serial-number","apiName":"serialNumber","type":"string","maxLength":64,"classification":"public"}"#,
                "\n",
            ),
            1,
        )
        .replace(
            r#""writableFields":["jurisdiction","label","quantity"]"#,
            r#""writableFields":["jurisdiction","label","quantity","serial-number"]"#,
        );
    let project = parse_project_json(fixture.as_bytes()).expect("the api-name fixture parses");
    let registry = Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("the api-name fixture compiles to trusted inventories"),
    );
    let harness = IngestionHarness::from_registry(registry).await;
    let claims = operator_claims(PRINCIPAL, "zone-a");

    let items: Vec<Value> = (0..2)
        .map(|index| {
            json!({"operation":"create", "data": {
                "jurisdiction": "zone-a",
                "label": format!("api-name-{index}"),
                "quantity": index,
                "serialNumber": format!("SN-{index:04}")
            }})
        })
        .collect();
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;

    let submitted = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(submitted.status(), StatusCode::OK);
    let body = body_json(submitted).await;
    assert_eq!(body["run"]["status"], "complete");
    assert_eq!(body["receipt"]["digest"], chunks.digests[0]);
    assert_eq!(durable_widget_count(&harness).await, 2);
}

/// A caller who derives the server's chunk key may run the same items through
/// the ordinary batch route first, but that cached batch result can never
/// adopt a run chunk: the chunk still owes its own commit under the run lock,
/// with the run lifecycle the batch route never writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn caller_seeded_batch_keys_cannot_preseed_a_run_chunk() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("preseeded", 3);
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;

    // The caller replays the exact derivation the run API uses, drives the
    // ordinary batch route with it, and the batch commits the same items.
    let key = chunk_idempotency_key(&run_id, &chunks.input_digest, 0, &chunks.digests[0]);
    let seeded = send(
        &harness.app,
        Method::POST,
        "/v1/records/widgets:batch",
        Some(claims.clone()),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", key.as_str()),
        ],
        serde_json::to_vec(&json!({"items": items})).expect("batch body"),
    )
    .await;
    assert_eq!(seeded.status(), StatusCode::OK);

    // The run chunk executes as its own mutation: the labels the seeded batch
    // already took make the commit fail visibly (the run surface reports a
    // refused chunk) instead of the checkpoint silently adopting the
    // caller-seeded batch answer.
    let submitted = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(submitted.status(), StatusCode::PRECONDITION_FAILED);
    let run = harness.read_run(&claims, &run_id).await;
    assert_eq!(run["status"], "open");
    assert_eq!(run["nextChunkIndex"], 0);
    assert_eq!(run["committedItems"], 0);
}

/// Receipts answer only under the access context the run was bound to: the
/// same principal and profile id presenting different row-boundary claims, or
/// a different purpose, recovers nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_receipts_replay_only_under_the_bound_access_context() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let drifted = operator_claims(PRINCIPAL, "zone-b");
    let items = announce_items("context-bound", 5);
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);

    // The same principal and profile under a different row boundary recovers
    // neither the committed chunk's receipt nor the dedicated receipt read,
    // and cannot drive the next chunk either.
    let refused_replay = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &drifted,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(refused_replay.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(refused_replay).await["code"],
        "ingestion.profile_mismatch"
    );
    let refused_receipt = harness
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks/0/receipt"),
            &drifted,
        )
        .await;
    assert_eq!(refused_receipt.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(refused_receipt).await["code"],
        "ingestion.profile_mismatch"
    );
    let refused_fresh = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &drifted,
            chunk_body(&chunks, 1),
        )
        .await;
    assert_eq!(refused_fresh.status(), StatusCode::FORBIDDEN);

    // Under the bound context the recovery still answers.
    let replayed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replayed.status(), StatusCode::OK);
    assert_eq!(body_json(replayed).await["receipt"]["replayed"], true);
}

/// The recovery answer renders the run the replay just touched, so its last
/// attempt says `replayed`, exactly like a fresh read would.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_chunk_reports_the_replayed_attempt() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("attempt-freshness", 5);
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);

    let replayed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replayed.status(), StatusCode::OK);
    let run = body_json(replayed).await["run"].clone();
    assert_eq!(run["lastAttempt"]["outcome"], "replayed");
    assert_eq!(run["lastAttempt"]["chunkIndex"], 0);
}

/// A replay releases the retained batch answer a second time, so the journal
/// must carry a value-free disclosure record for it: an unaudited second
/// release is indistinguishable from a leak.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_chunk_discloses_an_audited_receipt() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("replay-disclosure", 4);
    let chunks = plan_chunks(&items, 2);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);

    let replayed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replayed.status(), StatusCode::OK);
    assert_eq!(body_json(replayed).await["receipt"]["replayed"], true);

    let records = harness
        .database
        .admin
        .query(
            "SELECT convert_from(envelope, 'UTF8')
               FROM registry_internal.registry_audit
              WHERE convert_from(envelope, 'UTF8') LIKE '%\"kind\":\"ingestionReceipt\"%'",
            &[],
        )
        .await
        .expect("administrator inspects the run audit journal");
    assert!(
        !records.is_empty(),
        "the replayed receipt is disclosed in the audit journal"
    );
    for row in records {
        let envelope: Value =
            serde_json::from_str(&row.get::<_, String>(0)).expect("audit envelope is JSON");
        let record = &envelope["record"];
        assert_eq!(record["runId"], run_id);
        assert_eq!(record["chunkIndex"], 0);
        assert!(record["principalReference"].is_string());
        assert!(
            record.get("correlation").is_some(),
            "the disclosure names the request that caused it"
        );
    }
}

/// Receipt recovery projects the same retained record values, so it owes the
/// same disclosure record the replay owes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recovered_receipt_discloses_an_audited_receipt() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("recovery-disclosure", 2);
    let chunks = plan_chunks(&items, 2);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);

    let recovered = harness
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks/0/receipt"),
            &claims,
        )
        .await;
    assert_eq!(recovered.status(), StatusCode::OK);

    let records = harness
        .database
        .admin
        .query(
            "SELECT convert_from(envelope, 'UTF8')
               FROM registry_internal.registry_audit
              WHERE convert_from(envelope, 'UTF8') LIKE '%\"kind\":\"ingestionReceipt\"%'",
            &[],
        )
        .await
        .expect("administrator inspects the run audit journal");
    assert!(
        !records.is_empty(),
        "the recovered receipt is disclosed in the audit journal"
    );
    for row in records {
        let envelope: Value =
            serde_json::from_str(&row.get::<_, String>(0)).expect("audit envelope is JSON");
        assert_eq!(envelope["record"]["runId"], run_id);
        assert_eq!(envelope["record"]["chunkIndex"], 0);
    }
}

/// An audit outage gates both release paths: while the journal cannot extend
/// its chain, a keyed process answers an outage instead of releasing the
/// retained answer unaudited, and the receipt releases once the chain
/// extends again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_audit_outage_gates_the_receipt_release() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("audit-outage", 2);
    let chunks = plan_chunks(&items, 2);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);

    // A journal the runtime role can no longer extend refuses every further
    // append, as a revoked grant or an unwritable journal would.
    let role = harness.database.runtime_role.as_str().to_owned();
    harness
        .database
        .admin
        .execute(
            &format!("REVOKE INSERT ON registry_internal.registry_audit FROM \"{role}\""),
            &[],
        )
        .await
        .expect("the audit insert grant is revoked");

    let replayed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replayed.status(), StatusCode::SERVICE_UNAVAILABLE);
    let recovered = harness
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks/0/receipt"),
            &claims,
        )
        .await;
    assert_eq!(recovered.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Once the journal accepts appends again, the same replay discloses and
    // releases.
    harness
        .database
        .admin
        .execute(
            &format!("GRANT INSERT ON registry_internal.registry_audit TO \"{role}\""),
            &[],
        )
        .await
        .expect("the audit insert grant is restored");
    let replayed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replayed.status(), StatusCode::OK);
    assert_eq!(body_json(replayed).await["receipt"]["replayed"], true);
}

/// Two identical submissions that both pass the service preflight serialize
/// on the run row lock: the winner commits the chunk and the loser replays
/// the stored receipt inside the coordinator, under the lock. That row-lock
/// replay releases the retained record values a second time, so it owes the
/// journal the same disclosure record the service-level releases owe; an
/// unaudited second release is indistinguishable from a leak.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_lock_replay_discloses_an_audited_receipt() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("row-lock-disclosure", 2);
    let chunks = plan_chunks(&items, 2);
    let run_id = harness.create_run(&claims, &chunks).await;

    // Hold the run row lock just long enough for both submissions to pass
    // their plain-SELECT preflight and queue inside the coordinator's
    // lock_run. The hold must stay under the mutation lock timeout, or the
    // waiters would fail out of the queue instead of racing on the lock.
    harness
        .database
        .admin
        .execute("BEGIN", &[])
        .await
        .expect("administrator opens a locking transaction");
    let locked = harness
        .database
        .admin
        .query_opt(
            "SELECT run_id FROM registry_internal.registry_ingestion_runs
              WHERE run_id = $1 FOR UPDATE",
            &[&Uuid::parse_str(&run_id).expect("run id parses")],
        )
        .await
        .expect("administrator holds the run row lock");
    assert!(locked.is_some(), "the created run row is locked");

    let uri = format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks");
    let submission_b = {
        let app = harness.app.clone();
        let uri = uri.clone();
        let claims = claims.clone();
        let body = chunk_body(&chunks, 0);
        tokio::spawn(async move { post_json(&app, &uri, &claims, body).await })
    };
    assert_eq!(
        poll_waiting_runtime_locks(&harness, 1, Duration::from_secs(3)).await,
        1,
        "submission B parks on the run row lock"
    );

    let submission_a = {
        let app = harness.app.clone();
        let claims = claims.clone();
        let body = chunk_body(&chunks, 0);
        tokio::spawn(async move { post_json(&app, &uri, &claims, body).await })
    };
    assert_eq!(
        poll_waiting_runtime_locks(&harness, 2, Duration::from_millis(1500)).await,
        2,
        "submission A parks behind submission B on the run row lock"
    );

    // Release the row lock: the winner commits the chunk, and the loser
    // replays the stored receipt under the row lock.
    harness
        .database
        .admin
        .execute("COMMIT", &[])
        .await
        .expect("administrator releases the run row lock");
    let response_b = submission_b.await.expect("submission B completes");
    let response_a = submission_a.await.expect("submission A completes");
    assert_eq!(response_b.status(), StatusCode::OK);
    assert_eq!(response_a.status(), StatusCode::OK);
    let replayed_b = body_json(response_b).await["receipt"]["replayed"]
        .as_bool()
        .expect("submission B answers a receipt");
    let replayed_a = body_json(response_a).await["receipt"]["replayed"]
        .as_bool()
        .expect("submission A answers a receipt");
    assert_ne!(
        replayed_a, replayed_b,
        "one submission commits and the other replays under the row lock"
    );
    assert_eq!(
        durable_widget_count(&harness).await,
        2,
        "the raced chunk mutates exactly once"
    );

    let disclosures = receipt_disclosures(&harness, &run_id).await;
    assert_eq!(
        disclosures.len(),
        1,
        "the row-lock replay discloses exactly the one release it makes"
    );
    assert_eq!(disclosures[0]["chunkIndex"], 0);
    assert!(
        disclosures[0]
            .get("correlation")
            .is_some_and(Value::is_string),
        "the disclosure names the request that caused it"
    );
}

/// A chunk receipt over an encrypted field stores the sealed envelope exactly
/// as the batch route's idempotency cache does, and opens it at the same
/// release edge: the fresh answer carries the plaintext member, no envelope
/// marker reaches the caller, and the stored receipt bytes stay sealed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_receipt_opens_encrypted_members_and_stays_sealed_at_rest() {
    let harness =
        IngestionHarness::from_registry_with_encryption(encrypted_widget_registry()).await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let chunks = plan_chunks(&encrypted_items("encrypted-fresh", 2), 2);
    let run_id = harness.create_run(&claims, &chunks).await;

    let submitted = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(submitted.status(), StatusCode::OK);
    let raw = body_bytes(submitted).await;
    assert!(
        !contains_envelope_marker(&raw),
        "the fresh receipt answer carries no sealed envelope"
    );
    let body: Value = serde_json::from_slice(&raw).expect("receipt answer is JSON");
    let results = body["receipt"]["batch"]["results"]
        .as_array()
        .expect("receipt results");
    assert_eq!(results[0]["data"]["serialNumber"], "SN-0000");
    assert_eq!(results[1]["data"]["serialNumber"], "SN-0001");

    assert_receipt_stays_sealed(&harness, &run_id).await;
}

/// Replays and the receipt recovery release the same stored bytes, so both
/// open the sealed members before the answer leaves while the receipt stays
/// sealed at rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_and_recovered_receipts_open_encrypted_members() {
    let harness =
        IngestionHarness::from_registry_with_encryption(encrypted_widget_registry()).await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let chunks = plan_chunks(&encrypted_items("encrypted-replay", 1), 2);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);

    let replay = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::OK);
    let raw = body_bytes(replay).await;
    assert!(
        !contains_envelope_marker(&raw),
        "the replayed receipt answer carries no sealed envelope"
    );
    let body: Value = serde_json::from_slice(&raw).expect("replay answer is JSON");
    assert_eq!(body["receipt"]["replayed"], true);
    assert_eq!(
        body["receipt"]["batch"]["results"][0]["data"]["serialNumber"],
        "SN-0000"
    );

    let recovered = harness
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks/0/receipt"),
            &claims,
        )
        .await;
    assert_eq!(recovered.status(), StatusCode::OK);
    let raw = body_bytes(recovered).await;
    assert!(
        !contains_envelope_marker(&raw),
        "the recovered receipt answer carries no sealed envelope"
    );
    let body: Value = serde_json::from_slice(&raw).expect("recovery answer is JSON");
    assert_eq!(
        body["batch"]["results"][0]["data"]["serialNumber"],
        "SN-0000"
    );

    assert_receipt_stays_sealed(&harness, &run_id).await;
}

/// Without key state, no receipt release may answer sealed members: a fresh
/// submission, a replay, and a recovery all answer an outage, no envelope
/// reaches any caller, and the stored receipt stays sealed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receipt_releases_fail_closed_without_key_state() {
    let harness =
        IngestionHarness::from_registry_with_encryption(encrypted_widget_registry()).await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let chunks = plan_chunks(&encrypted_items("encrypted-closed", 2), 2);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);
    assert_eq!(durable_widget_count(&harness).await, 2);

    // A restarted process without key state can still admit the run surface,
    // but no receipt it holds may leave sealed.
    let closed = harness.restart_without_field_encryption().await;
    let replay = closed
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!contains_envelope_marker(&body_bytes(replay).await));

    let recovered = closed
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks/0/receipt"),
            &claims,
        )
        .await;
    assert_eq!(recovered.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!contains_envelope_marker(&body_bytes(recovered).await));

    // A fresh submission under the same process cannot even seal its items,
    // so it answers an outage and commits nothing.
    let fresh_chunks = plan_chunks(&encrypted_items("encrypted-closed-fresh", 1), 2);
    let created = closed
        .post_json(
            "/v1/records/widgets/ingestion-runs",
            &claims,
            harness.run_body("create", &fresh_chunks),
        )
        .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let fresh_run = body_json(created).await["run"]["runId"]
        .as_str()
        .expect("run id")
        .to_owned();
    let fresh = closed
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{fresh_run}/chunks"),
            &claims,
            chunk_body(&fresh_chunks, 0),
        )
        .await;
    assert_eq!(fresh.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!contains_envelope_marker(&body_bytes(fresh).await));
    assert_eq!(
        durable_widget_count(&harness).await,
        2,
        "the refused fresh chunk commits nothing"
    );

    assert_receipt_stays_sealed(&harness, &run_id).await;
}

/// The binding a stale serving instance reports and enforces is the one the
/// database holds active, not the retired identity the process started
/// under: reads report the run blocked, and the next chunk submission takes
/// the blocked transition durably even through the stale instance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_instance_reports_and_blocks_runs_against_the_durable_binding() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("stale-instance", 4);
    let chunks = plan_chunks(&items, 2);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);

    // The successor revision activates in the database while the original
    // process keeps serving its retired identity.
    let successor = harness.restart_with_revision("package-ingestion-2").await;

    let run = harness.read_run(&claims, &run_id).await;
    assert_eq!(run["status"], "blocked");
    assert_eq!(run["blockedReason"], "activePackageChanged");

    // The stale instance takes the blocking transition, and its refusal
    // still answers an outage: the refusal envelope itself cannot be
    // written under the retired identity, so the caller is told the process
    // is unavailable while the run is durably blocked.
    let refused = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 1),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);

    let after = successor
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}"),
            &claims,
        )
        .await;
    let after = body_json(after).await["run"].clone();
    assert_eq!(after["status"], "blocked");
    assert_eq!(after["blockedReason"], "activePackageChanged");
    assert_eq!(after["committedItems"], 2);
    assert_eq!(after["nextChunkIndex"], 1);

    let blocked_records = harness
        .database
        .admin
        .query(
            "SELECT convert_from(envelope, 'UTF8')
               FROM registry_internal.registry_audit
              WHERE convert_from(envelope, 'UTF8') LIKE '%\"kind\":\"ingestionRun\"%'
                AND convert_from(envelope, 'UTF8') LIKE '%\"outcome\":\"blocked\"%'",
            &[],
        )
        .await
        .expect("administrator inspects the run audit journal");
    assert!(
        !blocked_records.is_empty(),
        "the stale instance wrote the blocked transition"
    );
}

/// The published ingestion operations carry every problem response their
/// handlers can produce: a producible refusal outside the published contract
/// is invisible to generated clients and contract validators.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ingestion_operations_publish_their_producible_problem_responses() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let openapi = harness.get_json("/openapi.json", &claims).await;
    assert_eq!(openapi.status(), StatusCode::OK);
    let paths = body_json(openapi).await["paths"].clone();

    let create = &paths["/v1/records/widgets/ingestion-runs"]["post"]["responses"];
    assert!(
        create["415"].is_object(),
        "create-run publishes its media-type refusal"
    );
    let submit = &paths["/v1/records/widgets/ingestion-runs/{run_id}/chunks"]["post"]["responses"];
    assert!(
        submit["415"].is_object(),
        "submit-chunk publishes its media-type refusal"
    );
    let cancel = &paths["/v1/records/widgets/ingestion-runs/{run_id}/cancel"]["post"]["responses"];
    assert!(
        cancel["403"]["content"]["application/problem+json"]["examples"]
            ["ingestion.profile_mismatch"]
            .is_object(),
        "cancel publishes its profile-mismatch refusal"
    );
    assert!(
        cancel["415"].is_object(),
        "cancel publishes its media-type refusal"
    );
}

/// The published chunk schema carries the compiled batch ceiling the runtime
/// enforces, so generated clients refuse oversized chunks before sending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_chunk_submission_schema_publishes_the_batch_maximum_items() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let openapi = harness.get_json("/openapi.json", &claims).await;
    assert_eq!(openapi.status(), StatusCode::OK);
    let schema = body_json(openapi).await["paths"]
        ["/v1/records/widgets/ingestion-runs/{run_id}/chunks"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"]
        .clone();
    assert_eq!(schema["properties"]["items"]["minItems"], 1);
    assert_eq!(schema["properties"]["items"]["maxItems"], 3);
}

/// A drifted access context can neither drive nor terminate a run: cancel
/// owes the run the same profile and bound-context checks chunk submission
/// and receipt recovery owe it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_cancellation_requires_the_runs_bound_access_context() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let drifted = operator_claims(PRINCIPAL, "zone-b");
    let chunks = plan_chunks(&announce_items("cancel-bound", 3), 3);
    let run_id = harness.create_run(&claims, &chunks).await;

    let refused = harness
        .post_empty(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/cancel"),
            &drifted,
        )
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(refused).await["code"],
        "ingestion.profile_mismatch"
    );
    let run = harness.read_run(&claims, &run_id).await;
    assert_eq!(run["status"], "open");

    let cancelled = harness
        .post_empty(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/cancel"),
            &claims,
        )
        .await;
    assert_eq!(cancelled.status(), StatusCode::OK);
    assert_eq!(body_json(cancelled).await["run"]["status"], "cancelled");
}

/// A run may be created only under the package the database still holds
/// active: a stale process whose compiled configuration a successor package
/// superseded cannot insert a run bound to the retired revision, because run
/// creation takes the same durable activation interlock ordinary mutations
/// take.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_process_cannot_create_a_run_under_a_retired_package() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let chunks = plan_chunks(&announce_items("stale-create", 1), 3);

    // The database activates a successor revision while this process keeps
    // serving with its original compiled configuration.
    let _successor = harness.restart_with_revision("package-ingestion-2").await;
    let refused = harness
        .post_json(
            "/v1/records/widgets/ingestion-runs",
            &claims,
            harness.run_body("create", &chunks),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);

    // No run row was written under the retired binding.
    let listed = harness
        .get_json("/v1/records/widgets/ingestion-runs", &claims)
        .await;
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(
        body_json(listed).await["runs"]
            .as_array()
            .expect("runs")
            .len(),
        0
    );
}

/// A syntactically valid submission the run refuses still owes the journal a
/// durable refusal envelope: divergent attempts on the run routes are audited
/// exactly like the refusals the ordinary mutation boundary audits, and an
/// audit outage gates the refusal answer instead of passing silently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn service_level_chunk_refusals_are_audited() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("audited-refusal", 5);
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;

    // A well-formed submission at the wrong index is refused before the batch
    // coordinator, so only the boundary refusal audit can record it.
    let refused = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 1),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["code"], "ingestion.chunk_mismatch");

    let rows = harness
        .database
        .admin
        .query(
            "SELECT convert_from(envelope, 'UTF8')
               FROM registry_internal.registry_audit
              WHERE convert_from(envelope, 'UTF8') LIKE '%\"phase\":\"refusal\"%'
                AND convert_from(envelope, 'UTF8')
                    LIKE '%\"operationId\":\"records.widget.batch\"%'",
            &[],
        )
        .await
        .expect("administrator inspects the audit journal");
    assert!(
        !rows.is_empty(),
        "the chunk refusal is audited like any mutation refusal"
    );
}

/// A committed chunk replays from the stored receipt whatever a successor
/// package does to the compiled batch limits: the replay comparison is
/// package-independent by design, so recovery of the committed prefix must
/// survive a package that lowers the ceilings the chunk was admitted under.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_committed_chunk_replays_after_the_package_lowers_the_batch_limits() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("lowered-limits", 3);
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);
    assert_eq!(durable_widget_count(&harness).await, 3);

    // A successor package with lower compiled batch limits activates; its
    // process serves the replay of a chunk the old ceiling admitted.
    let fixture = format!("{FIXTURE_HEAD}{FIXTURE_TAIL}").replace(
        r#""batch":{"maximumItems":3,"maximumBytes":8192}"#,
        r#""batch":{"maximumItems":1,"maximumBytes":1024}"#,
    );
    let project = parse_project_json(fixture.as_bytes()).expect("the lowered fixture parses");
    let lowered = Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("the lowered fixture compiles"),
    );
    let successor = harness.restart_with_registry(lowered).await;

    let replay = successor
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::OK);
    let replay_body = body_json(replay).await;
    assert_eq!(replay_body["receipt"]["replayed"], true);
    assert_eq!(durable_widget_count(&harness).await, 3);
}

/// The runtime role inserts and reads receipt links but never rewrites them:
/// repointing a link could make a retained receipt outlive the history it
/// discloses or scrub an unrelated receipt, so the link table carries no
/// UPDATE authority at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_runtime_role_cannot_rewrite_receipt_links() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let chunks = plan_chunks(&announce_items("link-authority", 3), 3);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);

    let pool = harness
        .database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let refused = client
        .execute(
            "UPDATE registry_internal.registry_ingestion_run_chunk_records
                SET record_id = record_id",
            &[],
        )
        .await;
    assert!(
        refused.is_err(),
        "the runtime role holds no UPDATE authority on receipt links"
    );
}

/// The replay comparison binds the submitted items, not the caller-stated
/// digests: a body whose items do not hash to the announced digest is a
/// mismatch even at an already committed index, never a receipt loan.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_digest_cannot_borrow_a_committed_receipt() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items("forged-digest", 3);
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);
    assert_eq!(durable_widget_count(&harness).await, 3);

    // The digest and prefix digest are copied from the committed chunk; the
    // items are not the items they announce.
    let mut forged = chunk_body(&chunks, 0);
    forged["items"] = json!([{"operation":"create", "data": {
        "jurisdiction": "zone-a",
        "label": "forged-digest-borrowed",
        "quantity": 9
    }}]);
    let refused = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            forged,
        )
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["code"], "ingestion.chunk_mismatch");
    assert_eq!(durable_widget_count(&harness).await, 3);

    // The exact body still replays the retained receipt.
    let replayed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replayed.status(), StatusCode::OK);
    assert_eq!(body_json(replayed).await["receipt"]["replayed"], true);
}

/// A terminal run stays terminal when the active package later changes: the
/// blocking transition belongs to open runs, and a stale next-chunk
/// submission answers run_not_open, never a blocked answer or a blocked
/// audit record for a run whose stored status never moved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_run_whose_package_changed_answers_run_not_open() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let chunks = plan_chunks(&announce_items("terminal-binding", 5), 3);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);
    let cancelled = harness
        .post_empty(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/cancel"),
            &claims,
        )
        .await;
    assert_eq!(cancelled.status(), StatusCode::OK);

    let changed = harness.restart_with_revision("package-ingestion-2").await;
    let stale = changed
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 1),
        )
        .await;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(stale).await["code"], "ingestion.run_not_open");
    let run = harness.read_run(&claims, &run_id).await;
    assert_eq!(run["status"], "cancelled");
    assert_eq!(run["nextChunkIndex"], 1);
    assert_eq!(
        run["lastAttempt"]["outcome"], "refused",
        "cancellation's own attempt is the last one recorded"
    );
}

/// A field that violates its declared storage pattern is a deterministic
/// refusal, not an outage: the chunk answer matches the ordinary batch
/// contract's conflict shape instead of an unavailable problem.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pattern_violation_is_a_refused_chunk_not_an_outage() {
    let fixture = format!("{FIXTURE_HEAD}{FIXTURE_TAIL}").replacen(
        r#"{"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"}"#,
        r#"{"id":"label","type":"string","maxLength":128,"required":true,"classification":"public","pattern":"^[a-z0-9-]+$"}"#,
        1,
    );
    let project = parse_project_json(fixture.as_bytes()).expect("the pattern fixture parses");
    let registry = Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("the pattern fixture compiles to trusted inventories"),
    );
    let harness = IngestionHarness::from_registry(registry).await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    // The label violates the declared lowercase pattern at insert time.
    let items = vec![json!({"operation":"create", "data": {
        "jurisdiction": "zone-a",
        "label": "Pattern-Violation",
        "quantity": 1
    }})];
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;

    let refused = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(body_json(refused).await["code"], "precondition.failed");
    let run = harness.read_run(&claims, &run_id).await;
    assert_eq!(run["status"], "open");
    assert_eq!(run["nextChunkIndex"], 0);
    assert_eq!(run["lastAttempt"]["outcome"], "refused");
    assert_eq!(durable_widget_count(&harness).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listing_runs_filters_by_status_and_input_digest() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let open_plan = plan_chunks(&announce_items("filter-open", 2), 3);
    let open_id = harness.create_run(&claims, &open_plan).await;
    let complete_plan = plan_chunks(&announce_items("filter-complete", 2), 3);
    let complete_id = harness.create_run(&claims, &complete_plan).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{complete_id}/chunks"),
            &claims,
            chunk_body(&complete_plan, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);
    assert_eq!(body_json(committed).await["run"]["complete"], true);

    let by_digest = harness
        .get_json(
            &format!(
                "/v1/records/widgets/ingestion-runs?inputDigest={}",
                complete_plan.input_digest
            ),
            &claims,
        )
        .await;
    assert_eq!(by_digest.status(), StatusCode::OK);
    let runs = body_json(by_digest).await["runs"]
        .as_array()
        .expect("runs")
        .clone();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["runId"], complete_id.as_str());

    let by_status = harness
        .get_json("/v1/records/widgets/ingestion-runs?status=open", &claims)
        .await;
    assert_eq!(by_status.status(), StatusCode::OK);
    let runs = body_json(by_status).await["runs"]
        .as_array()
        .expect("runs")
        .clone();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["runId"], open_id.as_str());

    let by_both = harness
        .get_json(
            &format!(
                "/v1/records/widgets/ingestion-runs?status=complete&inputDigest={}",
                complete_plan.input_digest
            ),
            &claims,
        )
        .await;
    assert_eq!(by_both.status(), StatusCode::OK);
    let runs = body_json(by_both).await["runs"]
        .as_array()
        .expect("runs")
        .clone();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["runId"], complete_id.as_str());

    // Values outside the closed filter vocabularies are invalid queries.
    for invalid in ["status=pending", "inputDigest=not-a-digest"] {
        let refused = harness
            .get_json(
                &format!("/v1/records/widgets/ingestion-runs?{invalid}"),
                &claims,
            )
            .await;
        assert_eq!(refused.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn erasing_through_revision_one_keeps_the_revision_two_receipt() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");

    // Revision 1 arrives through a create run; revision 2 of the same record
    // through a patch run, so each run's receipt describes one revision.
    let create_plan = plan_chunks(&announce_items("ranged", 1), 3);
    let create_run = harness.create_run(&claims, &create_plan).await;
    let created = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{create_run}/chunks"),
            &claims,
            chunk_body(&create_plan, 0),
        )
        .await;
    assert_eq!(created.status(), StatusCode::OK);
    let results = body_json(created).await["receipt"]["batch"]["results"].clone();
    let record_id = results[0]["id"].as_str().expect("record id").to_owned();
    let etag = results[0]["etag"].as_str().expect("record etag").to_owned();
    assert_eq!(results[0]["revision"], 1);

    let patch_item = json!({
        "operation": "patch",
        "recordId": record_id,
        "ifMatch": etag,
        "patch": [{"op": "replace", "path": "/data/quantity", "value": 7}]
    });
    let patch_plan = plan_chunks(std::slice::from_ref(&patch_item), 3);
    let patch_run = harness.create_run_for(&claims, "patch", &patch_plan).await;
    let patched = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{patch_run}/chunks"),
            &claims,
            chunk_body(&patch_plan, 0),
        )
        .await;
    assert_eq!(patched.status(), StatusCode::OK);
    assert_eq!(
        body_json(patched).await["receipt"]["batch"]["results"][0]["revision"],
        2
    );

    harness.erase_widget_history(&record_id).await;

    // The receipt describing revision 1 answers erased; the receipt
    // describing the surviving revision 2 still recovers.
    let erased = harness
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{create_run}/chunks/0/receipt"),
            &claims,
        )
        .await;
    assert_eq!(erased.status(), StatusCode::GONE);
    assert_eq!(body_json(erased).await["code"], "ingestion.receipt_erased");

    let retained = harness
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{patch_run}/chunks/0/receipt"),
            &claims,
        )
        .await;
    assert_eq!(retained.status(), StatusCode::OK);
    assert_eq!(
        body_json(retained).await["batch"]["results"][0]["revision"],
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_rows_and_audit_never_carry_source_values() {
    let harness = IngestionHarness::create().await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let items = announce_items(RECORD_CANARY, 3);
    let chunks = plan_chunks(&items, 3);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{}/chunks", run_id),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);

    // The run row, the run audit, and the shared audit journal carry digests,
    // counts, and hashed references only. The stored chunk receipt is the
    // replayable batch answer and holds the same profile-bound projection the
    // ordinary batch route returned, so it is out of scope for this sweep.
    for table in ["registry_ingestion_runs"] {
        let row = harness
            .database
            .admin
            .query_one(
                &format!(
                    "SELECT count(*) FROM (
                         SELECT scanned::text AS row_text
                           FROM registry_internal.{table} AS scanned
                     ) rows WHERE row_text LIKE '%' || $1 || '%'"
                ),
                &[&RECORD_CANARY],
            )
            .await
            .unwrap_or_else(|error| panic!("{table} must be scannable: {error}"));
        assert_eq!(row.get::<_, i64>(0), 0, "{table} carries no source canary");
    }

    for canary in [RECORD_CANARY, PRINCIPAL] {
        let row = harness
            .database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_audit
                 WHERE envelope::text LIKE '%' || $1 || '%'",
                &[&canary],
            )
            .await
            .expect("audit envelopes are readable");
        assert_eq!(
            row.get::<_, i64>(0),
            0,
            "no audit envelope carries the canary"
        );
    }
}

struct IngestionHarness {
    database: TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit_profile: AuditProfile,
    field_encryption: Option<Arc<FieldEncryptionService>>,
    /// Held, never read: the activated service keeps its key in memory, and
    /// the secret file must outlive every restart that shares the service.
    #[allow(dead_code)]
    secrets_root: Option<tempfile::TempDir>,
    app: axum::Router,
}

impl IngestionHarness {
    async fn create() -> Self {
        Self::from_registry(Arc::new(compiled_registry())).await
    }

    /// Build the same harness around one caller-chosen compiled registry, so a
    /// test can pin authored shapes the shared fixture does not carry.
    async fn from_registry(registry: Arc<registry_breg::CompiledRegistry>) -> Self {
        Self::from_registry_with_secrets(registry, None).await
    }

    /// The same harness with local-file field-encryption key state activated,
    /// so chunks over the encrypted field seal at rest under the key this
    /// harness holds for every restart that keeps it.
    async fn from_registry_with_encryption(registry: Arc<registry_breg::CompiledRegistry>) -> Self {
        let secrets_root = tempfile::Builder::new()
            .prefix("breg-ingestion-field-dek-")
            .tempdir_in(
                std::env::temp_dir()
                    .canonicalize()
                    .expect("temporary parent canonicalizes"),
            )
            .expect("field-encryption secret root creates");
        write_secret(
            &secrets_root.path().join("field-dek"),
            BASE64.encode([0x71_u8; 32]).as_bytes(),
        );
        Self::from_registry_with_secrets(registry, Some(secrets_root)).await
    }

    async fn from_registry_with_secrets(
        registry: Arc<registry_breg::CompiledRegistry>,
        secrets_root: Option<tempfile::TempDir>,
    ) -> Self {
        let database = TestDatabase::create(8).await;
        let (migration, migration_task) = database.connect_migration().await;
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("migration installs the compiler-owned schema");
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: PACKAGE_ID,
                environment: "local",
                instance_id: "ingestion-instance",
                database_id: "ingestion-database",
                package_revision: PACKAGE_REVISION,
                package_sequence: 1,
            },
        )
        .await
        .expect("active package identity is initialized");
        let field_encryption = match &secrets_root {
            Some(root) => {
                let dek_ref = SecretReference::parse("secret:file/field-dek")
                    .expect("local-file key reference parses");
                let secrets = SecretResolver::new([SecretProvider::File], root.path())
                    .expect("local-file secret resolver builds");
                Some(Arc::new(
                    FieldEncryptionService::activate(
                        &FieldEncryptionProvider::LocalFile { dek_ref },
                        registry.registry_id(),
                        PACKAGE_REVISION,
                        &secrets,
                        &migration,
                    )
                    .await
                    .expect("field-encryption key state activates"),
                ))
            }
            None => None,
        };
        migration_task.abort();
        let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
        let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x7c; 32].into())
            .expect("test owns a keyed audit profile");
        let pool = database
            .runtime_config
            .build_pool()
            .expect("bounded runtime pool builds");
        let app = build_router(
            pool,
            registry.clone(),
            identity.clone(),
            lock_key,
            audit_profile.clone(),
            None,
            field_encryption.clone(),
        );
        Self {
            database,
            registry,
            identity,
            lock_key,
            audit_profile,
            field_encryption,
            secrets_root,
            app,
        }
    }

    /// Rebuild the HTTP surface from the same database, as a restarted
    /// process would, optionally under an injected mutation fault.
    async fn restart(&self, fault: Option<MutationFaultPoint>) -> Surface {
        self.build_surface(
            self.registry.clone(),
            self.identity.clone(),
            fault,
            self.field_encryption.clone(),
        )
        .await
    }

    /// Rebuild the HTTP surface without field-encryption key state, as a
    /// restarted process whose key material is unavailable would.
    async fn restart_without_field_encryption(&self) -> Surface {
        self.build_surface(self.registry.clone(), self.identity.clone(), None, None)
            .await
    }

    async fn build_surface(
        &self,
        registry: Arc<registry_breg::CompiledRegistry>,
        identity: registry_breg::postgres::ExpectedRegistryIdentity,
        fault: Option<MutationFaultPoint>,
        field_encryption: Option<Arc<FieldEncryptionService>>,
    ) -> Surface {
        let pool = self
            .database
            .runtime_config
            .build_pool()
            .expect("bounded runtime pool builds");
        Surface {
            app: build_router(
                pool,
                registry,
                identity,
                self.lock_key,
                self.audit_profile.clone(),
                fault,
                field_encryption,
            ),
        }
    }

    async fn restart_with_revision(&self, package_revision: &str) -> Surface {
        self.restart_serving(self.registry.clone(), package_revision)
            .await
    }

    /// Rebuild the HTTP surface from a caller-chosen successor registry, as a
    /// restarted process under an activated successor package would.
    async fn restart_with_registry(
        &self,
        registry: Arc<registry_breg::CompiledRegistry>,
    ) -> Surface {
        self.restart_serving(registry, "package-ingestion-2").await
    }

    async fn restart_serving(
        &self,
        registry: Arc<registry_breg::CompiledRegistry>,
        package_revision: &str,
    ) -> Surface {
        let successor = registry_breg::postgres::ExpectedRegistryIdentity {
            package_revision: package_revision.to_owned(),
            package_sequence: 2,
            ..self.identity.clone()
        };
        let changed = self
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_state
                    SET active_package_revision = $1, schema_fingerprint = $2,
                        package_sequence = $3
                  WHERE singleton",
                &[
                    &successor.package_revision,
                    &successor.schema_fingerprint,
                    &successor.package_sequence,
                ],
            )
            .await
            .expect("successor revision activates");
        assert_eq!(changed, 1);
        self.build_surface(registry, successor, None, self.field_encryption.clone())
            .await
    }

    async fn post_empty(
        &self,
        uri: &str,
        claims: &VerifiedRequestClaims,
    ) -> axum::response::Response {
        post_empty(&self.app, uri, claims).await
    }

    fn run_body(&self, operation: &str, plan: &ChunkPlan) -> Value {
        run_body(operation, &self.identity.schema_fingerprint, plan)
    }

    async fn post_json(
        &self,
        uri: &str,
        claims: &VerifiedRequestClaims,
        body: Value,
    ) -> axum::response::Response {
        post_json(&self.app, uri, claims, body).await
    }

    async fn get_json(
        &self,
        uri: &str,
        claims: &VerifiedRequestClaims,
    ) -> axum::response::Response {
        get_json(&self.app, uri, claims).await
    }

    async fn create_run(&self, claims: &VerifiedRequestClaims, plan: &ChunkPlan) -> String {
        self.create_run_for(claims, "create", plan).await
    }

    async fn create_run_for(
        &self,
        claims: &VerifiedRequestClaims,
        operation: &str,
        plan: &ChunkPlan,
    ) -> String {
        let response = self
            .post_json(
                "/v1/records/widgets/ingestion-runs",
                claims,
                self.run_body(operation, plan),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        body_json(response).await["run"]["runId"]
            .as_str()
            .expect("run id")
            .to_owned()
    }

    async fn read_run(&self, claims: &VerifiedRequestClaims, run_id: &str) -> Value {
        let response = self
            .get_json(
                &format!("/v1/records/widgets/ingestion-runs/{}", run_id),
                claims,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        body_json(response).await["run"].clone()
    }

    async fn erase_widget_history(&self, record_id: &str) {
        use registry_breg::history_erasure::{
            erase_record_history, HistoryErasureRequest, HistoryErasureTimeouts,
            RecordHistoryErasureTarget,
        };
        let (mut migration, migration_task) = self.database.connect_migration().await;
        let target = RecordHistoryErasureTarget::new(
            "widget",
            Uuid::parse_str(record_id).expect("record id parses"),
            1,
        );
        erase_record_history(
            &mut migration,
            HistoryErasureRequest {
                expected: &self.identity,
                migration_role: &self.database.migration_role,
                lock_key: self.lock_key,
                timeouts: HistoryErasureTimeouts::new(
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .expect("timeouts are bounded"),
                audit_profile: &self.audit_profile,
                operator_reference: "ingestion-erasure-operator",
                reason: "ingestion-receipt-erasure-proof",
                target,
            },
        )
        .await
        .expect("targeted erasure succeeds");
        migration_task.abort();
    }
}

fn build_router(
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
    fault: Option<MutationFaultPoint>,
    field_encryption: Option<Arc<FieldEncryptionService>>,
) -> axum::Router {
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x53; 32]), Duration::from_secs(300))
            .expect("cursor key is valid"),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        profile.clone(),
        cursors.clone(),
    ));
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        profile,
    );
    let mutations = match field_encryption {
        Some(service) => mutations.with_field_encryption(service),
        None => mutations,
    };
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
    router(Arc::new(
        HttpService::new(
            registry,
            ReadRuntimeIdentity {
                package_revision: identity.package_revision,
                schema_fingerprint: identity.schema_fingerprint,
            },
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(Arc::new(mutations)),
    ))
}

/// A restarted HTTP surface over the same database, so a test can drive the
/// run through a process boundary with the same request helpers.
struct Surface {
    app: axum::Router,
}

impl Surface {
    async fn post_empty(
        &self,
        uri: &str,
        claims: &VerifiedRequestClaims,
    ) -> axum::response::Response {
        post_empty(&self.app, uri, claims).await
    }

    async fn post_json(
        &self,
        uri: &str,
        claims: &VerifiedRequestClaims,
        body: Value,
    ) -> axum::response::Response {
        post_json(&self.app, uri, claims, body).await
    }

    async fn get_json(
        &self,
        uri: &str,
        claims: &VerifiedRequestClaims,
    ) -> axum::response::Response {
        get_json(&self.app, uri, claims).await
    }
}

async fn post_json(
    app: &axum::Router,
    uri: &str,
    claims: &VerifiedRequestClaims,
    body: Value,
) -> axum::response::Response {
    send(
        app,
        Method::POST,
        uri,
        Some(claims.clone()),
        &[("content-type", "application/json")],
        serde_json::to_vec(&body).expect("request JSON"),
    )
    .await
}

async fn get_json(
    app: &axum::Router,
    uri: &str,
    claims: &VerifiedRequestClaims,
) -> axum::response::Response {
    send(app, Method::GET, uri, Some(claims.clone()), &[], Vec::new()).await
}

/// A body-less POST with no Content-Type, as the cancel route requires.
async fn post_empty(
    app: &axum::Router,
    uri: &str,
    claims: &VerifiedRequestClaims,
) -> axum::response::Response {
    send(
        app,
        Method::POST,
        uri,
        Some(claims.clone()),
        &[],
        Vec::new(),
    )
    .await
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn operator_claims(principal: &str, jurisdiction: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::new(),
        Some("case-management".to_owned()),
        BTreeMap::from([(
            "jurisdiction".to_owned(),
            VerifiedClaimValue::direct_string(jurisdiction).expect("direct claim"),
        )]),
    )
    .expect("verified claims are bounded")
}

fn anonymous_claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::anonymous()
}

const FIXTURE_HEAD: &str = r#"{
  "apiVersion":"registry.registrystack.org/v1alpha1",
  "kind":"RegistryProject",
  "registry":{"id":"ingestion-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
  "entities":[{
    "id":"widget","primaryDataset":"test-dataset","route":"widgets","mutationMode":"mutable","classification":"public",
    "batch":{"maximumItems":3,"maximumBytes":8192},
    "constraints":[{"kind":"unique","fields":["label"]}],
    "fields":[
      {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
      {"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"},
      {"id":"quantity","type":"int64","required":true,"classification":"public"}
    ],
    "hooks":[
      {"phase":"after","id":"widget-created","trigger":"created","projection":["label"]},
      {"phase":"after","id":"widget-patched","trigger":"patched","projection":["label","quantity"]}
    ]
  },{
    "id":"ledger","primaryDataset":"test-dataset","route":"ledgers","mutationMode":"create_only","classification":"public",
    "fields":[
      {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
      {"id":"memo","type":"string","maxLength":128,"required":true,"classification":"public"}
    ]
  }],"#;

const FIXTURE_TAIL: &str = r#"
  "accessProfiles":[{
    "id":"operator","default":true,"principalClaim":"registry_principal",
    "requiredPurposes":["case-management","case-review"],
    "permissions":[{
      "entity":"widget","operations":["create","get","patch","batch"],
      "readableFields":["jurisdiction","label","quantity"],
      "writableFields":["jurisdiction","label","quantity"],
      "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
    }]
  },{
    "id":"operator-minimal","principalClaim":"registry_principal",
    "requiredPurposes":["case-management"],
    "permissions":[{
      "entity":"widget","operations":["create","patch","batch"],
      "readableFields":["label"],
      "writableFields":["jurisdiction","label","quantity"],
      "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
    }]
  },{
    "id":"anonymous-reader","anonymous":true,
    "permissions":[{
      "entity":"widget","operations":["get","list"],
      "readableFields":["label"],
      "rowBoundaries":[]
    }]
  }]
}"#;

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(format!("{FIXTURE_HEAD}{FIXTURE_TAIL}").as_bytes())
        .expect("ingestion fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("ingestion fixture compiles to trusted inventories")
}

/// A widget registry carrying one restricted, encrypted field, so chunk
/// receipts hold sealed envelope members only key state can open.
fn encrypted_widget_registry() -> Arc<registry_breg::CompiledRegistry> {
    let fixture = format!("{FIXTURE_HEAD}{FIXTURE_TAIL}")
        .replacen(
            concat!(
                r#"      {"id":"quantity","type":"int64","required":true,"classification":"public"}"#,
                "\n",
            ),
            concat!(
                r#"      {"id":"quantity","type":"int64","required":true,"classification":"public"},"#,
                "\n",
                r#"      {"id":"serial-number","apiName":"serialNumber","type":"string","maxLength":64,"classification":"restricted","encrypted":true}"#,
                "\n",
            ),
            1,
        )
        .replace(
            r#""readableFields":["jurisdiction","label","quantity"]"#,
            r#""readableFields":["jurisdiction","label","quantity","serial-number"]"#,
        )
        .replace(
            r#""writableFields":["jurisdiction","label","quantity"]"#,
            r#""writableFields":["jurisdiction","label","quantity","serial-number"]"#,
        );
    let project = parse_project_json(fixture.as_bytes()).expect("the encrypted fixture parses");
    Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("the encrypted fixture compiles to trusted inventories"),
    )
}

/// The client-side chunk plan over the full item array, derived exactly the
/// way the durable-run client contract derives it: greedy fixed-size chunks
/// of canonical items, each chunk bound to its digest, and prefix digests
/// over the raw source input through the end of each chunk.
struct ChunkPlan {
    items: Vec<Value>,
    starts: Vec<usize>,
    ends: Vec<usize>,
    digests: Vec<String>,
    prefix_digests: Vec<String>,
    input_digest: String,
    input_length: i64,
    item_count: i64,
    chunk_count: i64,
}

fn announce_items(label_prefix: &str, count: i64) -> Vec<Value> {
    (0..count)
        .map(|index| {
            json!({"operation":"create", "data": {
                "jurisdiction": "zone-a",
                "label": format!("{label_prefix}-{index}"),
                "quantity": index
            }})
        })
        .collect()
}

/// Items over the encrypted fixture, so every receipt the run stores carries
/// one sealed serial-number envelope per created record.
fn encrypted_items(label_prefix: &str, count: i64) -> Vec<Value> {
    (0..count)
        .map(|index| {
            json!({"operation":"create", "data": {
                "jurisdiction": "zone-a",
                "label": format!("{label_prefix}-{index}"),
                "quantity": index,
                "serialNumber": format!("SN-{index:04}")
            }})
        })
        .collect()
}

/// The sealed-envelope member tag an opened answer must never carry.
const ENVELOPE_MARKER: &[u8] = b"__bregEncryptedV1";

fn contains_envelope_marker(bytes: &[u8]) -> bool {
    bytes
        .windows(ENVELOPE_MARKER.len())
        .any(|window| window == ENVELOPE_MARKER)
}

/// Assert one stored chunk receipt keeps its serial-number member sealed: the
/// envelope marker is present and no plaintext serial survives at rest.
async fn assert_receipt_stays_sealed(harness: &IngestionHarness, run_id: &str) {
    let row = harness
        .database
        .admin
        .query_one(
            "SELECT position('__bregEncryptedV1' in convert_from(receipt, 'UTF8')) > 0,
                    position('SN-0000' in convert_from(receipt, 'UTF8')) = 0
               FROM registry_internal.registry_ingestion_run_chunks
              WHERE run_id = $1 AND chunk_index = 0 AND erased_at IS NULL",
            &[&Uuid::parse_str(run_id).expect("run id parses")],
        )
        .await
        .expect("the stored chunk receipt reads");
    assert!(
        row.get::<_, bool>(0),
        "the stored receipt keeps the sealed envelope"
    );
    assert!(
        row.get::<_, bool>(1),
        "the stored receipt carries no plaintext serial"
    );
}

fn write_secret(path: &std::path::Path, value: &[u8]) {
    std::fs::write(path, value).expect("test secret writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("test secret permissions set");
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in Sha256::digest(bytes) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn zero_digest() -> String {
    "0".repeat(64)
}

/// The server-derived idempotency key one chunk submission uses, derived here
/// the way a caller can: from public run facts alone.
fn chunk_idempotency_key(
    run_id: &str,
    input_digest: &str,
    chunk_index: u64,
    digest: &str,
) -> String {
    let binding = registry_platform_canonical_json::canonicalize_json(&json!({
        "domain": "registry-data-import-chunk-v1",
        "importId": run_id,
        "inputDigest": input_digest,
        "chunkIndex": chunk_index,
        "chunkDigest": digest,
    }))
    .expect("chunk key binding canonicalizes");
    format!("breg-data-v1-{}", hex_digest(&binding))
}

fn chunk_digest(items: &[Value]) -> String {
    let canonical = registry_platform_canonical_json::canonicalize_json(&json!({ "items": items }))
        .expect("canonical JSON derives");
    hex_digest(&canonical)
}

fn plan_chunks(items: &[Value], maximum_per_chunk: usize) -> ChunkPlan {
    assert!(!items.is_empty(), "a run announces at least one item");
    let mut bounds = Vec::new();
    let mut start = 0;
    while start < items.len() {
        let end = (start + maximum_per_chunk).min(items.len());
        bounds.push((start, end));
        start = end;
    }
    chunk_plan(items, &bounds)
}

/// One plan over an explicit partition of the items, so a test can announce
/// the whole input while submitting a chunk partition the run must refuse.
/// The announced digests bind one canonical JSON line per item: the raw
/// source input the client contract chunks, whose full-input digest the
/// terminal chunk's prefix digest must equal.
fn chunk_plan(items: &[Value], bounds: &[(usize, usize)]) -> ChunkPlan {
    assert!(!items.is_empty(), "a run announces at least one item");
    assert!(!bounds.is_empty(), "a plan carries at least one chunk");
    let lines: Vec<Vec<u8>> = items
        .iter()
        .map(|item| {
            let mut line = registry_platform_canonical_json::canonicalize_json(item)
                .expect("canonical JSON derives");
            line.push(b'\n');
            line
        })
        .collect();
    let mut raw_input = Vec::new();
    for line in &lines {
        raw_input.extend_from_slice(line);
    }
    let mut starts = Vec::new();
    let mut ends = Vec::new();
    let mut digests = Vec::new();
    let mut prefix_digests = Vec::new();
    for &(start, end) in bounds {
        let chunk = &items[start..end];
        let mut raw_prefix = Vec::new();
        for line in &lines[..end] {
            raw_prefix.extend_from_slice(line);
        }
        starts.push(start);
        ends.push(end);
        digests.push(chunk_digest(chunk));
        prefix_digests.push(hex_digest(&raw_prefix));
    }
    ChunkPlan {
        items: items.to_vec(),
        starts,
        ends,
        digests,
        prefix_digests,
        input_digest: hex_digest(&raw_input),
        input_length: raw_input.len() as i64,
        item_count: items.len() as i64,
        chunk_count: bounds.len() as i64,
    }
}

fn chunk_body(plan: &ChunkPlan, index: usize) -> Value {
    json!({
        "chunkIndex": index,
        "items": plan.items[plan.starts[index]..plan.ends[index]],
        "digest": plan.digests[index],
        "prefixDigest": plan.prefix_digests[index],
    })
}

fn run_body(operation: &str, schema_fingerprint: &str, plan: &ChunkPlan) -> Value {
    run_body_under(operation, schema_fingerprint, plan, "operator")
}

fn run_body_under(
    operation: &str,
    schema_fingerprint: &str,
    plan: &ChunkPlan,
    profile_id: &str,
) -> Value {
    json!({
        "operation": operation,
        "profileId": profile_id,
        "packageRevision": PACKAGE_REVISION,
        "schemaFingerprint": schema_fingerprint,
        "inputDigest": plan.input_digest,
        "inputLength": plan.input_length,
        "itemCount": plan.item_count,
        "chunkCount": plan.chunk_count,
        "chunkAlgorithmVersion": "greedy-canonical-http-batch-v1",
    })
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("request");
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("response")
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("JSON response")
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body")
        .to_vec()
}

async fn durable_widget_count(harness: &IngestionHarness) -> i64 {
    let table = &harness.registry.entities()["widget"].physical_table;
    let row = harness
        .database
        .admin
        .query_one(
            &format!("SELECT count(*) FROM registry_data.\"{table}\""),
            &[],
        )
        .await
        .expect("widget rows are readable");
    row.get(0)
}

/// Poll until `expected` sessions queue on the run row lock the
/// administrator's open transaction holds, and report the last count so a
/// timeout fails the test instead of passing vacuously. The count walks the
/// lock manager rather than `pg_stat_activity`, which a pipelined runtime
/// session in a lock wait does not reliably report: the first waiter parks on
/// the holder's transaction id, and a second waiter on the same row parks on
/// the tuple lock instead, so the count is the waits on the holder's own
/// transaction id (this query runs inside that holding transaction) plus the
/// tuple waits inside this database, which only the runtime sessions of this
/// test can hold while the administrator's locks stay granted.
async fn poll_waiting_runtime_locks(
    harness: &IngestionHarness,
    expected: i64,
    deadline: Duration,
) -> i64 {
    let started = std::time::Instant::now();
    let mut parked;
    loop {
        parked = harness
            .database
            .admin
            .query_one(
                "SELECT count(*)
                   FROM pg_locks AS locks
                  WHERE NOT locks.granted
                    AND (
                      (locks.locktype = 'transactionid'
                       AND locks.transactionid::text =
                           pg_current_xact_id_if_assigned()::text)
                      OR
                      (locks.locktype = 'tuple'
                       AND locks.database::text =
                           (SELECT oid::text FROM pg_database
                             WHERE datname = current_database()))
                    )",
                &[],
            )
            .await
            .expect("administrator inspects waiting locks")
            .get(0);
        if parked >= expected || started.elapsed() >= deadline {
            return parked;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The parsed disclosure records the journal holds for one run.
async fn receipt_disclosures(harness: &IngestionHarness, run_id: &str) -> Vec<Value> {
    let rows = harness
        .database
        .admin
        .query(
            "SELECT convert_from(envelope, 'UTF8')
               FROM registry_internal.registry_audit
              WHERE convert_from(envelope, 'UTF8') LIKE '%\"kind\":\"ingestionReceipt\"%'",
            &[],
        )
        .await
        .expect("administrator inspects the run audit journal");
    rows.iter()
        .map(|row| {
            let envelope: Value =
                serde_json::from_str(&row.get::<_, String>(0)).expect("audit envelope is JSON");
            envelope["record"].clone()
        })
        .filter(|record| record["runId"] == run_id)
        .collect()
}
