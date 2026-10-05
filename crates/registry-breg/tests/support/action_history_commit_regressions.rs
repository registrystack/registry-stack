// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn immediate_action_advances_the_history_head_and_rebaseline_accepts_its_revision() {
    let (database, registry, identity) =
        install_action_registry_with_history(compiled_registry(), true).await;
    let app = action_router(&database, registry.clone(), identity.clone());
    let before: i64 = database
        .admin
        .query_one(
            "SELECT latest_position FROM registry_internal.registry_commit_head WHERE singleton",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let applied = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/create-local-person",
            Some(action_claims()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "history-create"),
            ],
            serde_json::to_vec(&json!({"input":{
                "personCode":"P-HISTORY", "legalName":"History fixture", "jurisdiction":"zone-a"
            }}))
            .unwrap(),
        )
        .await,
    )
    .await;
    assert_eq!(applied.status, StatusCode::OK, "{}", applied.body);
    let after = database.admin.query_one(
        "SELECT h.latest_position, c.origin_kind, count(m.*)::bigint
         FROM registry_internal.registry_commit_head h
         JOIN registry_internal.registry_revision_commits c ON c.commit_position = h.latest_position
         LEFT JOIN registry_internal.registry_revision_commit_members m ON m.commit_position = c.commit_position
         WHERE h.singleton GROUP BY h.latest_position, c.origin_kind", &[]
    ).await.unwrap();
    assert_eq!(
        after.get::<_, i64>(0),
        before + 1,
        "action must advance the shared history head"
    );
    assert_eq!(after.get::<_, String>(1), "mutation");
    assert_eq!(after.get::<_, i64>(2), 1);

    let replay = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/create-local-person",
            Some(action_claims()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "history-create"),
            ],
            serde_json::to_vec(&json!({"input":{
                "personCode":"P-HISTORY", "legalName":"History fixture", "jurisdiction":"zone-a"
            }}))
            .unwrap(),
        )
        .await,
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(replay.body, applied.body);
    let replay_head: i64 = database
        .admin
        .query_one(
            "SELECT latest_position FROM registry_internal.registry_commit_head WHERE singleton",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        replay_head,
        before + 1,
        "replay does not allocate another history commit"
    );

    // Simulate loss of coverage, then exercise the actual maintenance path.
    // It must accept the action revision as an indexed journal head.
    database.admin.batch_execute(
        "UPDATE registry_internal.registry_commit_head SET coverage_ready = false WHERE singleton"
    ).await.unwrap();
    let (mut migration, migration_task) = database.connect_migration().await;
    let audit = database.activation_audit();
    let result = registry_breg::history_rebaseline::rebaseline_history_coverage(
        &mut migration,
        registry_breg::history_rebaseline::HistoryRebaselineRequest {
            expected: &identity,
            migration_role: &database.migration_role,
            lock_key: RegistryLockKey::derive(PACKAGE_ID).unwrap(),
            timeouts: registry_breg::history_rebaseline::HistoryRebaselineTimeouts::new(
                Duration::from_secs(2),
                Duration::from_secs(10),
            )
            .unwrap(),
            audit: &audit,
            operator_reference: "action-history-test",
            registry: &registry,
        },
    )
    .await
    .expect("indexed immediate-action revision permits a coverage rebaseline");
    assert_eq!(result.verified_record_count, 1);
    drop(migration);
    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn immediate_action_indexes_each_distinct_record_once_in_one_history_commit() {
    let (database, registry, identity) =
        install_action_registry_with_history(history_registry(), true).await;
    seed_household(
        &database,
        &registry,
        &identity,
        HOUSEHOLD_ID,
        "H-HISTORY",
        "zone-a",
    )
    .await;
    let app = action_router(&database, registry.clone(), identity);
    let claims = action_claims();
    let conditions = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"householdId":HOUSEHOLD_ID}})).unwrap(),
        )
        .await,
    )
    .await;
    assert_eq!(conditions.status, StatusCode::OK, "{}", conditions.body);
    let before: i64 = database
        .admin
        .query_one(
            "SELECT latest_position FROM registry_internal.registry_commit_head WHERE singleton",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let applied = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "history-many"),
            ],
            serde_json::to_vec(&json!({
                "input":{"householdId":HOUSEHOLD_ID,"personCode":"P-HISTORY-MANY",
                         "legalName":"Several records", "jurisdiction":"zone-a"},
                "preconditions":conditions.body["preconditions"]
            }))
            .unwrap(),
        )
        .await,
    )
    .await;
    assert_eq!(applied.status, StatusCode::OK, "{}", applied.body);
    let members = database.admin.query(
        "SELECT m.entity_id, m.record_id::text, m.record_revision, h.latest_position
         FROM registry_internal.registry_commit_head h
         JOIN registry_internal.registry_revision_commit_members m ON m.commit_position = h.latest_position
         WHERE h.singleton ORDER BY m.entity_id", &[]
    ).await.unwrap();
    assert_eq!(
        members.len(),
        3,
        "three changed records belong to the action's single commit"
    );
    for member in members {
        assert_eq!(member.get::<_, i64>(3), before + 1);
        let entity: String = member.get(0);
        let result_key = if entity == "group-membership" {
            "membership"
        } else {
            &entity
        };
        assert_eq!(
            applied.body["results"][result_key]["recordId"],
            member.get::<_, String>(1)
        );
        assert_eq!(
            applied.body["results"][result_key]["revision"],
            member.get::<_, i64>(2)
        );
    }
    let snapshot = history_read(
        &app,
        "/v1/records/households:snapshot?accessProfile=record-history",
    )
    .await;
    assert_eq!(snapshot.status, StatusCode::OK, "{}", snapshot.body);
    assert_eq!(snapshot.body["items"][0]["recordIdentifier"], HOUSEHOLD_ID);
    assert_eq!(snapshot.body["items"][0]["revisionIdentifier"], "2");
    assert_eq!(
        snapshot.body["items"][0]["domainData"]["householdCode"],
        "H-HISTORY"
    );

    // Reading the latest snapshot does not advance the shared history head.
    let head: i64 = database
        .admin
        .query_one(
            "SELECT latest_position FROM registry_internal.registry_commit_head WHERE singleton",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(head, before + 1);
    database.cleanup().await;
}
