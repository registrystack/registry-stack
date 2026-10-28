// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_only_timer_checks_the_anchor_guard_before_any_effect_commits() {
    let source = create_only_guard_source("status", "approved");
    let harness = timer_outcome_harness(
        compile_registry(source),
        "record-timer-create-only-anchor-guard",
        0x6a,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "create-only-anchor-guard",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = create_only_effect_counts(&harness).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("the failed authored guard settles normally"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "refused", 1, "declared-refusal").await;
    assert_eq!(
        create_only_effect_counts(&harness).await,
        before,
        "a disallowed current anchor status creates no Record, revision, outbox row, receipt, application, or result"
    );
    assert_timer_refusal_audit(&harness.database);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_only_timer_executes_when_the_anchor_guard_allows_it() {
    let source = create_only_guard_source("status", "scheduled");
    let harness = timer_outcome_harness(
        compile_registry(source),
        "record-timer-create-only-anchor-guard-allowed",
        0x6b,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "create-only-anchor-guard-allowed",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("the allowed authored guard executes normally"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 1, "completed").await;
    assert_eq!(
        create_only_effect_counts(&harness).await,
        [1; 6],
        "an allowed guard commits the bounded create and its records exactly once"
    );
    harness.database.cleanup().await;
}

fn create_only_guard_source(field: &str, expected: &str) -> Value {
    let mut source = timer_project_source();
    source["datasets"]
        .as_array_mut()
        .expect("datasets are an array")
        .push(json!({"id":"activation-logs"}));
    source["recordTypes"]
        .as_array_mut()
        .expect("Record types are an array")
        .push(json!({
            "id":"activation-log","primaryDataset":"activation-logs","route":"activation-logs",
            "mutationMode":"mutable","fields":[
                {"id":"planned-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"operation-id","type":"uuid","required":true,"classification":"internal"}
            ],
            "hooks":[{"phase":"after","id":"activation-log-created","trigger":"created",
                "projection":["operation-id"]}]
        }));
    source["actions"][0]["commitGuards"] = json!({"targets":[{
        "input":"service","field":field,"equals":expected
    }]});
    source["actions"][0]["plan"] = json!({"type":"fixed","effects":[{
        "id":"activation-log","target":{"recordType":"activation-log"},"operation":"create",
        "set":{
            "planned-at":{"fromInput":"planned-at"},
            "operation-id":{"fromInput":"operation-id"}
        }
    }]});
    source
}

async fn create_only_effect_counts(harness: &TimerOutcomeHarness) -> [i64; 6] {
    let table = &harness.registry.entities()["activation-log"].physical_table;
    let row = harness
        .database
        .admin
        .query_one(
            &format!(
                "SELECT
                    (SELECT count(*) FROM registry_data.\"{table}\"),
                    (SELECT count(*) FROM registry_internal.registry_revisions
                      WHERE entity_id='activation-log'),
                    (SELECT count(*) FROM registry_internal.registry_outbox
                      WHERE entity_id='activation-log'),
                    (SELECT count(*) FROM registry_internal.registry_idempotency
                      WHERE result_kind='immediate_action'),
                    (SELECT count(*) FROM registry_internal.registry_immediate_action_applications),
                    (SELECT count(*) FROM registry_internal.registry_immediate_action_results)"
            ),
            &[],
        )
        .await
        .expect("create-only Action effects are queryable");
    std::array::from_fn(|index| row.get(index))
}
