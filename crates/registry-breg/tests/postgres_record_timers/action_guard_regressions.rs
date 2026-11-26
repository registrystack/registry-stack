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

/// A timer has no request to carry files, so `bregctl check` refuses a timer
/// Action that fills a record slot. A compiled registry that binds a file to
/// one anyway must not commit the record without it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_create_whose_declared_file_never_arrived_commits_nothing() {
    let mut source = create_only_guard_source("status", "scheduled");
    source["recordTypes"]["activation-log"]["attachments"] = json!([{"id":"evidence",
        "maximumBytes":64,"contentTypes":["text/plain"],"classification":"internal",
        "writeOnce":true}]);
    let mut wire = serde_json::to_value(compile_registry(source)).unwrap();
    let action = wire["actionInventory"]["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["id"] == "activate-service")
        .expect("the timer Action is compiled");
    action["attachments"] = json!({"evidence":{"effectId":"activation-log",
        "recordType":"activation-log","slotId":"evidence","maximumBytes":64,
        "contentTypes":["text/plain"]}});
    let registry: registry_breg::CompiledRegistry = serde_json::from_value(wire).unwrap();
    let harness = timer_outcome_harness(registry, "record-timer-undelivered-file", 0x6e).await;
    let created = create_outcome_service(
        &harness,
        "undelivered-file",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    timer_occurrence(&harness.database, &record_id).await;
    let before = create_only_effect_counts(&harness).await;

    let ran = harness.worker(Duration::from_secs(2)).run_once().await;
    assert_eq!(
        create_only_effect_counts(&harness).await,
        before,
        "a create whose declared file never arrived commits nothing: {ran:?}"
    );
    harness.database.cleanup().await;
}

fn create_only_guard_source(field: &str, expected: &str) -> Value {
    let mut source = timer_project_source();
    source["datasets"]
        .as_object_mut()
        .expect("datasets are a mapping")
        .insert("activation-logs".to_owned(), json!({}));
    source["recordTypes"]
        .as_object_mut()
        .expect("Record types are an array")
        .insert("activation-log".to_owned(), json!({"primaryDataset":"activation-logs","route":"activation-logs",
            "mutationMode":"mutable","fields":[
                {"id":"planned-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"operation-id","type":"uuid","required":true,"classification":"internal"}
            ],
            "hooks":[{"phase":"after","id":"activation-log-created","trigger":"created",
                "projection":["operation-id"]}]
        }));
    source["actions"]["activate-service"]["commitGuards"] = json!({"targets":[{
        "input":"service","field":field,"equals":expected
    }]});
    source["actions"]["activate-service"]["plan"] = json!({"type":"fixed","effects":[{
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
