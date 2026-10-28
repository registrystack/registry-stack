// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn technical_block_can_be_rescheduled_atomically() {
    let harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-technical-block-reschedule",
        0xb1,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "technical-block-reschedule-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let blocked_occurrence = timer_occurrence(&harness.database, &record_id).await;
    let faulting = harness
        .worker(Duration::from_secs(2))
        .with_fault_for_test(MutationFaultPoint::BeforeCommit);
    for attempt in 1..=5_i32 {
        assert!(
            faulting.run_once().await.is_err(),
            "the injected pre-commit failure remains visible"
        );
        if attempt < 5 {
            harness
                .database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_record_timer_generations
                        SET retry_at=clock_timestamp()
                      WHERE occurrence_id=$1",
                    &[&blocked_occurrence],
                )
                .await
                .expect("fixture advances only the persisted retry gate");
        }
    }
    let blocked = harness
        .database
        .admin
        .query_one(
            "SELECT state,block_kind,outcome_code,executed_attempt_count
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&blocked_occurrence],
        )
        .await
        .expect("the actual technical block is queryable");
    assert_eq!(blocked.get::<_, String>(0), "blocked");
    assert_eq!(
        blocked.get::<_, Option<String>>(1).as_deref(),
        Some("technical")
    );
    assert_eq!(
        blocked.get::<_, Option<String>>(2).as_deref(),
        Some("attempts-exhausted")
    );
    assert_eq!(blocked.get::<_, i32>(3), 5);

    patch_outcome_service_for_registry(
        &harness,
        &harness.registry,
        &harness.identity,
        &record_id,
        "technical-block-material-rearm",
        PatchOperation::Add {
            path: "/data/activationRevision".to_owned(),
            value: json!(uuid::Uuid::new_v4()),
        },
        0xb2,
    )
    .await;

    let rearmed_occurrence = timer_occurrence(&harness.database, &record_id).await;
    assert_ne!(rearmed_occurrence, blocked_occurrence);
    let settled = harness
        .database
        .admin
        .query_one(
            "SELECT state,block_kind,retry_at,claim_token,completed_at IS NOT NULL
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&blocked_occurrence],
        )
        .await
        .expect("the superseded technical block is retained");
    assert_eq!(settled.get::<_, String>(0), "superseded");
    assert!(settled.get::<_, Option<String>>(1).is_none());
    assert!(settled.get::<_, Option<chrono::DateTime<Utc>>>(2).is_none());
    assert!(settled.get::<_, Option<uuid::Uuid>>(3).is_none());
    assert!(settled.get::<_, bool>(4));
    assert_eq!(timer_state(&harness.database, &record_id).await, "pending");
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configuration_block_can_be_tombstoned_atomically() {
    let harness = timer_outcome_harness(
        compiled_tombstone_registry(),
        "record-timer-configuration-block-tombstone",
        0xb3,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "configuration-block-tombstone-anchor",
        "scheduled",
        Utc::now() + chrono::Duration::hours(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let blocked = harness
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_record_timer_generations AS generation
                SET state='blocked',block_kind='configuration',outcome_code=NULL,
                    retry_at=NULL,updated_at=clock_timestamp()
               FROM registry_internal.registry_record_timer_current AS current
              WHERE current.record_type='service'
                AND current.record_id=$1::text::uuid
                AND current.timer_id='activate'
                AND generation.record_type=current.record_type
                AND generation.record_id=current.record_id
                AND generation.timer_id=current.timer_id
                AND generation.occurrence_id=current.occurrence_id
                AND generation.binding_incarnation=current.binding_incarnation
                AND generation.material_signature=current.material_signature
                AND generation.state='pending'",
            &[&record_id],
        )
        .await
        .expect("fixture installs one exact current configuration block");
    assert_eq!(blocked, 1);
    let profile = AuditProfile::production_from_secret_bytes(vec![0xb4; 32].into())
        .expect("test owns a keyed tombstone audit profile");
    let record_revision = record_values(&harness.database, &harness.registry, &record_id)
        .await
        .2;
    let expected_etag = strong_record_etag_for_test(
        &profile,
        &harness.claims,
        &harness.identity.activation_id,
        &record_id,
        record_revision,
        &response_fields(),
    )
    .expect("the tombstone ETag is authority-bound");
    let coordinator = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        harness.identity.clone(),
        INSTANCE_ID,
        harness.database.audit(profile),
    );
    let plan = MutationPlan::from_compiled(&harness.registry, "records.service.tombstone")
        .expect("the mutable Record type compiles a tombstone route");
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &plan,
                idempotency_key: "tombstone-configuration-block",
                claims: &harness.claims,
                record_id: Some(&record_id),
                expected_etag: Some(&expected_etag),
                body: MutationBody::Tombstone,
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary tombstone settles the current configuration block atomically");
    let settled = harness
        .database
        .admin
        .query_one(
            &format!(
                "SELECT generation.state,generation.block_kind,generation.retry_at,
                        generation.claim_token,generation.completed_at IS NOT NULL,
                        record.record_lifecycle
                   FROM registry_internal.registry_record_timer_generations AS generation
                   JOIN registry_data.\"{}\" AS record
                     ON record.record_id=generation.record_id
                  WHERE generation.occurrence_id=$1",
                harness.registry.entities()["service"].physical_table
            ),
            &[&occurrence_id],
        )
        .await
        .expect("the tombstoned configuration block remains queryable");
    assert_eq!(settled.get::<_, String>(0), "cancelled");
    assert!(settled.get::<_, Option<String>>(1).is_none());
    assert!(settled.get::<_, Option<chrono::DateTime<Utc>>>(2).is_none());
    assert!(settled.get::<_, Option<uuid::Uuid>>(3).is_none());
    assert!(settled.get::<_, bool>(4));
    assert_eq!(settled.get::<_, String>(5), "tombstoned");
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_crashed_claim_refreshes_after_successor_without_a_new_occurrence() {
    let harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-expired-crashed-claim-refresh",
        0xb5,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "expired-crashed-claim-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let claimed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let claiming = harness
        .worker(Duration::from_secs(2))
        .with_claim_barrier_for_test(Arc::clone(&claimed), resume);
    let mut crashed = tokio::spawn(async move { claiming.run_once().await });
    wait_for_timer_barrier(&claimed, &mut crashed, "the claim barrier").await;
    patch_outcome_service_for_registry(
        &harness,
        &harness.registry,
        &harness.identity,
        &record_id,
        "crashed-claim-current-predicate",
        PatchOperation::Replace {
            path: "/data/status".to_owned(),
            value: json!("reviewed"),
        },
        0xb6,
    )
    .await;
    let old_claim = harness
        .database
        .admin
        .query_one(
            "SELECT claim_owner_id,claim_token,claim_epoch,claim_until,
                    claimed_control_epoch,claimed_instance_epoch,claimed_activation_id,
                    definition_revision,action_revision,system_grant_revision
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the crashed worker persisted one exact claim");
    let claim_until = old_claim.get::<_, chrono::DateTime<Utc>>(3);
    crashed.abort();
    assert!(crashed.await.unwrap_err().is_cancelled());

    let successor_registry = Arc::new(compiled_changed_predicate_registry());
    let successor_timer = &successor_registry.entities()["service"].timers["activate"];
    let successor = activate_timer_successor(
        &harness,
        &successor_registry,
        "record-timer-expired-crashed-claim-refresh-successor",
    )
    .await;
    wait_until_database_time(&harness.database, claim_until).await;
    let worker = successor_worker(&harness, Arc::clone(&successor_registry), successor, 0xb7);
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the expired crashed claim is refreshed under the successor"),
        1
    );
    let refreshed = harness
        .database
        .admin
        .query_one(
            "SELECT state,claim_owner_id,claim_token,claim_until,claimed_control_epoch,
                    claimed_instance_epoch,claimed_activation_id,definition_revision,
                    action_revision,system_grant_revision,executed_attempt_count,
                    (SELECT count(*) FROM registry_internal.registry_record_timer_attempts
                      WHERE occurrence_id=generation.occurrence_id)
               FROM registry_internal.registry_record_timer_generations AS generation
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the refreshed occurrence remains queryable");
    assert_eq!(refreshed.get::<_, String>(0), "pending");
    assert!(refreshed.get::<_, Option<uuid::Uuid>>(1).is_none());
    assert!(refreshed.get::<_, Option<uuid::Uuid>>(2).is_none());
    assert!(refreshed
        .get::<_, Option<chrono::DateTime<Utc>>>(3)
        .is_none());
    assert!(refreshed.get::<_, Option<i64>>(4).is_none());
    assert!(refreshed.get::<_, Option<i64>>(5).is_none());
    assert!(refreshed.get::<_, Option<uuid::Uuid>>(6).is_none());
    assert_eq!(
        refreshed.get::<_, String>(7),
        successor_timer.definition_revision
    );
    assert_eq!(
        refreshed.get::<_, String>(8),
        successor_timer.action_revision
    );
    assert_eq!(
        refreshed.get::<_, String>(9),
        successor_timer.system_grant.revision
    );
    assert_eq!(refreshed.get::<_, i32>(10), 0);
    assert_eq!(refreshed.get::<_, i64>(11), 0);
    assert_eq!(
        timer_occurrence(&harness.database, &record_id).await,
        occurrence_id
    );
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the refreshed occurrence executes once"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 1, "completed").await;
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn successor_between_claim_and_start_refuses_the_stale_owner_then_refreshes() {
    let harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-successor-between-claim-start",
        0xb8,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "successor-between-claim-start-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let claimed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let claiming = harness
        .worker(Duration::from_secs(2))
        .with_claim_barrier_for_test(Arc::clone(&claimed), Arc::clone(&resume));
    let mut stale = tokio::spawn(async move { claiming.run_once().await });
    wait_for_timer_barrier(&claimed, &mut stale, "the claim barrier").await;
    patch_outcome_service_for_registry(
        &harness,
        &harness.registry,
        &harness.identity,
        &record_id,
        "stale-owner-current-predicate",
        PatchOperation::Replace {
            path: "/data/status".to_owned(),
            value: json!("reviewed"),
        },
        0xb9,
    )
    .await;
    let claimed_row = harness
        .database
        .admin
        .query_one(
            "SELECT claim_owner_id,claim_token,claim_epoch,claim_until,
                    claimed_control_epoch,claimed_instance_epoch,claimed_activation_id,
                    definition_revision,action_revision,system_grant_revision
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the old worker persisted one exact live claim");
    let expected_owner = claimed_row.get::<_, uuid::Uuid>(0);
    let expected_token = claimed_row.get::<_, uuid::Uuid>(1);
    let expected_epoch = claimed_row.get::<_, i64>(2);
    let claim_until = claimed_row.get::<_, chrono::DateTime<Utc>>(3);
    let prior_revisions = (
        claimed_row.get::<_, String>(7),
        claimed_row.get::<_, String>(8),
        claimed_row.get::<_, String>(9),
    );
    let successor_registry = Arc::new(compiled_changed_predicate_registry());
    let successor = activate_timer_successor(
        &harness,
        &successor_registry,
        "record-timer-successor-between-claim-start-successor",
    )
    .await;
    resume.notify_one();
    let stale_result = stale.await.expect("stale worker task joins");
    assert!(
        matches!(
            stale_result,
            Err(registry_breg::mutation::MutationError::Unavailable)
        ),
        "the predecessor runtime is refused by the successor activation fence: {stale_result:?}"
    );
    let unchanged = harness
        .database
        .admin
        .query_one(
            "SELECT state,claim_owner_id,claim_token,claim_epoch,definition_revision,
                    action_revision,system_grant_revision,executed_attempt_count,
                    (SELECT count(*) FROM registry_internal.registry_record_timer_attempts
                      WHERE occurrence_id=generation.occurrence_id)
               FROM registry_internal.registry_record_timer_generations AS generation
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the stale owner cannot mutate its old claim");
    assert_eq!(unchanged.get::<_, String>(0), "leased");
    assert_eq!(unchanged.get::<_, uuid::Uuid>(1), expected_owner);
    assert_eq!(unchanged.get::<_, uuid::Uuid>(2), expected_token);
    assert_eq!(unchanged.get::<_, i64>(3), expected_epoch);
    assert_eq!(unchanged.get::<_, String>(4), prior_revisions.0);
    assert_eq!(unchanged.get::<_, String>(5), prior_revisions.1);
    assert_eq!(unchanged.get::<_, String>(6), prior_revisions.2);
    assert_eq!(unchanged.get::<_, i32>(7), 0);
    assert_eq!(unchanged.get::<_, i64>(8), 0);

    let worker = successor_worker(&harness, successor_registry, successor, 0xba);
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the successor cannot steal an unexpired predecessor lease"),
        0
    );
    wait_until_database_time(&harness.database, claim_until).await;
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the expired stale claim refreshes after successor activation"),
        1
    );
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the refreshed occurrence executes once under the successor"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 1, "completed").await;
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_occurrence_survives_control_remap_and_unrelated_write() {
    for (control, successor_path, successor_value) in [
        (
            "at",
            "/data/successorAt",
            json!((Utc::now() - chrono::Duration::seconds(1))
                .to_rfc3339_opts(SecondsFormat::Micros, true)),
        ),
        (
            "notAfter",
            "/data/successorWindowEnd",
            json!((Utc::now() + chrono::Duration::hours(1))
                .to_rfc3339_opts(SecondsFormat::Micros, true)),
        ),
        (
            "rearmOn",
            "/data/successorRevision",
            json!(uuid::Uuid::new_v4()),
        ),
    ] {
        let predecessor = compiled_control_remap_registry(None);
        let harness =
            timer_outcome_harness(predecessor, "record-timer-terminal-control-remap", 0xb1).await;
        let created = create_outcome_service(
            &harness,
            &format!("terminal-control-remap-{control}"),
            "scheduled",
            Utc::now() - chrono::Duration::seconds(1),
            None,
            None,
        )
        .await;
        let record_id = response_id(&created);
        let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
        patch_outcome_service_for_registry(
            &harness,
            &harness.registry,
            &harness.identity,
            &record_id,
            &format!("set-successor-control-{control}"),
            PatchOperation::Replace {
                path: successor_path.to_owned(),
                value: successor_value,
            },
            0xb2,
        )
        .await;
        assert_eq!(
            harness
                .worker(Duration::from_secs(2))
                .run_once()
                .await
                .expect("the predecessor occurrence completes"),
            1
        );
        let settled = current_timer_snapshot(&harness.database, &record_id).await;
        assert_eq!(settled.occurrence_id, occurrence_id);
        assert_eq!(settled.state, "completed");

        let successor_registry = Arc::new(compiled_control_remap_registry(Some(control)));
        let successor_identity = activate_timer_successor(
            &harness,
            &successor_registry,
            &format!("record-timer-terminal-control-remap-{control}-successor"),
        )
        .await;
        patch_outcome_service_for_registry(
            &harness,
            &successor_registry,
            &successor_identity,
            &record_id,
            &format!("unrelated-after-control-remap-{control}"),
            PatchOperation::Replace {
                path: "/data/note".to_owned(),
                value: json!(format!("unrelated after {control} remap")),
            },
            0xb3,
        )
        .await;
        let after = current_timer_snapshot(&harness.database, &record_id).await;
        assert_eq!(
            after, settled,
            "{control} remap must retain the settled marker"
        );
        assert_eq!(
            successor_worker(&harness, successor_registry, successor_identity, 0xb4)
                .run_once()
                .await
                .expect("a terminal remapped occurrence is not rediscovered"),
            0
        );
        harness.database.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inherited_invalid_window_allows_unrelated_edit_but_revalidates_material_changes() {
    let harness = timer_outcome_harness(
        compiled_no_window_registry(),
        "record-timer-inherited-invalid-window-edit",
        0xb5,
    )
    .await;
    let due_at = Utc::now() + chrono::Duration::hours(1);
    let created = create_outcome_service(
        &harness,
        "inherited-invalid-window-anchor",
        "scheduled",
        due_at,
        Some(due_at - chrono::Duration::minutes(1)),
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let successor_registry = Arc::new(compiled_registry());
    let successor_identity = activate_timer_successor(
        &harness,
        &successor_registry,
        "record-timer-inherited-invalid-window-successor",
    )
    .await;
    let worker = successor_worker(
        &harness,
        Arc::clone(&successor_registry),
        successor_identity.clone(),
        0xb6,
    );
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the inherited invalid window becomes a configuration block"),
        1
    );
    let blocked = current_timer_snapshot(&harness.database, &record_id).await;
    assert_eq!(blocked.occurrence_id, occurrence_id);
    assert_eq!(blocked.state, "blocked");
    assert_eq!(blocked.block_kind.as_deref(), Some("configuration"));

    try_patch_outcome_service_for_registry(
        &harness,
        &successor_registry,
        &successor_identity,
        &record_id,
        "unrelated-over-inherited-invalid-window",
        PatchOperation::Replace {
            path: "/data/note".to_owned(),
            value: json!("unrelated edit remains available"),
        },
        0xb7,
    )
    .await
    .expect("an inherited invalid window cannot block an unrelated edit");
    assert_eq!(
        current_timer_snapshot(&harness.database, &record_id).await,
        blocked
    );

    let invalid_change = try_patch_outcome_service_for_registry(
        &harness,
        &successor_registry,
        &successor_identity,
        &record_id,
        "material-change-keeps-invalid-window",
        PatchOperation::Replace {
            path: "/data/activatesAt".to_owned(),
            value: json!((due_at + chrono::Duration::minutes(1))
                .to_rfc3339_opts(SecondsFormat::Micros, true)),
        },
        0xb8,
    )
    .await
    .expect_err("a materially changed invalid window must still be refused");
    assert_eq!(
        invalid_change,
        registry_breg::mutation::MutationError::InvalidTimerWindow {
            at_field: "activates-at".to_owned(),
            not_after_field: "activation-window-end".to_owned(),
        }
    );

    try_patch_outcome_service_for_registry(
        &harness,
        &successor_registry,
        &successor_identity,
        &record_id,
        "correct-inherited-invalid-window",
        PatchOperation::Replace {
            path: "/data/activationWindowEnd".to_owned(),
            value: json!((due_at + chrono::Duration::minutes(5))
                .to_rfc3339_opts(SecondsFormat::Micros, true)),
        },
        0xb9,
    )
    .await
    .expect("a valid material correction remains available");
    let corrected = current_timer_snapshot(&harness.database, &record_id).await;
    assert_ne!(corrected.occurrence_id, occurrence_id);
    assert_eq!(corrected.state, "pending");
    assert!(corrected.block_kind.is_none());
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn technical_exhaustion_survives_invalid_and_corrected_successors() {
    let harness = timer_outcome_harness(
        compiled_no_window_registry(),
        "record-timer-technical-block-successor-recovery",
        0xba,
    )
    .await;
    let due_at = Utc::now() - chrono::Duration::seconds(1);
    let created = create_outcome_service(
        &harness,
        "technical-block-successor-anchor",
        "scheduled",
        due_at,
        Some(due_at - chrono::Duration::minutes(1)),
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let faulting = harness
        .worker(Duration::from_secs(2))
        .with_fault_for_test(MutationFaultPoint::BeforeCommit);
    for attempt in 1..=5_i32 {
        assert!(
            faulting.run_once().await.is_err(),
            "the injected automatic attempt {attempt} fails visibly"
        );
        if attempt < 5 {
            harness
                .database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_record_timer_generations
                        SET retry_at=clock_timestamp()
                      WHERE occurrence_id=$1",
                    &[&occurrence_id],
                )
                .await
                .expect("fixture advances only the persisted automatic retry gate");
        }
    }
    let exhausted = current_timer_snapshot(&harness.database, &record_id).await;
    assert_eq!(exhausted.state, "blocked");
    assert_eq!(exhausted.block_kind.as_deref(), Some("technical"));
    assert_eq!(exhausted.executed_attempt_count, 5);
    assert_eq!(exhausted.retry_allowance, 0);

    let invalid_registry = Arc::new(compiled_registry());
    let invalid_identity = activate_timer_successor(
        &harness,
        &invalid_registry,
        "record-timer-technical-block-invalid-successor",
    )
    .await;
    let invalid_worker =
        successor_worker(&harness, invalid_registry, invalid_identity.clone(), 0xbb);
    assert_eq!(
        invalid_worker
            .run_once()
            .await
            .expect("the invalid successor reconciles without releasing technical exhaustion"),
        1
    );
    assert_technical_exhaustion_preserved(
        &harness.database,
        &record_id,
        occurrence_id,
        &invalid_identity.activation_id,
        due_at,
        Some(due_at - chrono::Duration::minutes(1)),
    )
    .await;

    let corrected_registry = Arc::new(compiled_no_window_registry());
    let corrected_identity = activate_timer_successor_from(
        &harness,
        &invalid_identity,
        &corrected_registry,
        "record-timer-technical-block-corrected-successor",
    )
    .await;
    let corrected_activation_id = corrected_identity.activation_id.clone();
    let corrected_worker = successor_worker(&harness, corrected_registry, corrected_identity, 0xbc);
    assert_eq!(
        corrected_worker
            .run_once()
            .await
            .expect("the corrected successor refreshes but does not release technical exhaustion"),
        1
    );
    assert_technical_exhaustion_preserved(
        &harness.database,
        &record_id,
        occurrence_id,
        &corrected_activation_id,
        due_at,
        None,
    )
    .await;
    assert_eq!(
        corrected_worker
            .run_once()
            .await
            .expect("an exhausted occurrence is not a due hot loop"),
        0
    );
    harness.database.cleanup().await;
}

#[derive(Debug, Eq, PartialEq)]
struct CurrentTimerSnapshot {
    occurrence_id: uuid::Uuid,
    material_signature: String,
    state: String,
    block_kind: Option<String>,
    executed_attempt_count: i32,
    retry_allowance: i16,
}

async fn current_timer_snapshot(database: &TestDatabase, record_id: &str) -> CurrentTimerSnapshot {
    let row = database
        .admin
        .query_one(
            "SELECT current.occurrence_id,current.material_signature,generation.state,
                    generation.block_kind,generation.executed_attempt_count,
                    generation.retry_allowance
               FROM registry_internal.registry_record_timer_current AS current
               JOIN registry_internal.registry_record_timer_generations AS generation
                 ON generation.record_type=current.record_type
                AND generation.record_id=current.record_id
                AND generation.timer_id=current.timer_id
                AND generation.occurrence_id=current.occurrence_id
                AND generation.binding_incarnation=current.binding_incarnation
                AND generation.material_signature=current.material_signature
              WHERE current.record_type='service' AND current.record_id=$1::text::uuid
                AND current.timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("the exact current timer marker is queryable");
    CurrentTimerSnapshot {
        occurrence_id: row.get(0),
        material_signature: row.get(1),
        state: row.get(2),
        block_kind: row.get(3),
        executed_attempt_count: row.get(4),
        retry_allowance: row.get(5),
    }
}

async fn assert_technical_exhaustion_preserved(
    database: &TestDatabase,
    record_id: &str,
    occurrence_id: uuid::Uuid,
    expected_activation_id: &str,
    expected_due_at: chrono::DateTime<Utc>,
    expected_not_after: Option<chrono::DateTime<Utc>>,
) {
    let snapshot = current_timer_snapshot(database, record_id).await;
    assert_eq!(snapshot.occurrence_id, occurrence_id);
    assert_eq!(snapshot.state, "blocked");
    assert_eq!(snapshot.block_kind.as_deref(), Some("technical"));
    assert_eq!(snapshot.executed_attempt_count, 5);
    assert_eq!(snapshot.retry_allowance, 0);
    let row = database
        .admin
        .query_one(
            "SELECT generation.outcome_code,generation.retry_at,
                    generation.claim_owner_id,generation.claim_token,generation.claim_until,
                    (SELECT count(*)
                       FROM registry_internal.registry_record_timer_attempts AS attempt
                      WHERE attempt.occurrence_id=generation.occurrence_id),
                    generation.due_at,generation.not_after,
                    generation.definition_revision=binding.definition_revision,
                    generation.action_revision=binding.action_revision,
                    generation.system_grant_revision=binding.system_grant_revision,
                    generation.current_policy_activation_id=binding.current_policy_activation_id,
                    binding.current_policy_activation_id=state.active_activation_id,
                    state.active_activation_id::text
               FROM registry_internal.registry_record_timer_generations AS generation
               JOIN registry_internal.registry_record_timer_bindings AS binding
                 ON binding.record_type=generation.record_type
                AND binding.timer_id=generation.timer_id
                AND binding.incarnation=generation.binding_incarnation
                AND binding.removed_activation_id IS NULL
               JOIN registry_internal.registry_state AS state ON state.singleton
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the exact exhausted generation remains queryable");
    assert_eq!(
        row.get::<_, Option<String>>(0).as_deref(),
        Some("attempts-exhausted")
    );
    assert!(row.get::<_, Option<chrono::DateTime<Utc>>>(1).is_none());
    assert!(row.get::<_, Option<uuid::Uuid>>(2).is_none());
    assert!(row.get::<_, Option<uuid::Uuid>>(3).is_none());
    assert!(row.get::<_, Option<chrono::DateTime<Utc>>>(4).is_none());
    assert_eq!(row.get::<_, i64>(5), 5);
    assert_eq!(row.get::<_, chrono::DateTime<Utc>>(6), expected_due_at);
    assert_eq!(
        row.get::<_, Option<chrono::DateTime<Utc>>>(7),
        expected_not_after
    );
    for column in 8..=12 {
        assert!(
            row.get::<_, bool>(column),
            "the exhausted occurrence lost a current binding fence at column {column}"
        );
    }
    assert_eq!(row.get::<_, String>(13), expected_activation_id);
}

async fn wait_until_database_time(database: &TestDatabase, instant: chrono::DateTime<Utc>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let reached: bool = database
                .admin
                .query_one("SELECT clock_timestamp() >= $1", &[&instant])
                .await
                .expect("fixture reads the database clock")
                .get(0);
            if reached {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the bounded claim lease reaches its database deadline");
}

fn compiled_control_remap_registry(control: Option<&str>) -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .expect("service fields are an array")
        .extend([
            json!({
                "id":"successor-at","type":"timestamp","classification":"internal"
            }),
            json!({
                "id":"successor-window-end","type":"timestamp","classification":"internal"
            }),
            json!({
                "id":"successor-revision","type":"uuid","classification":"internal"
            }),
        ]);
    for access_key in ["readableFields", "writableFields"] {
        source["accessProfiles"][0]["permissions"]["records"][0][access_key]
            .as_array_mut()
            .expect("service access fields are an array")
            .extend([
                json!("successor-at"),
                json!("successor-window-end"),
                json!("successor-revision"),
            ]);
    }
    match control {
        Some("at") => {
            source["recordTypes"][0]["timers"][0]["at"] = json!("successor-at");
            source["recordTypes"][0]["timers"][0]["input"]["planned-at"] =
                json!({"fromField":"successor-at"});
        }
        Some("notAfter") => {
            source["recordTypes"][0]["timers"][0]["notAfter"] = json!("successor-window-end");
        }
        Some("rearmOn") => {
            source["recordTypes"][0]["timers"][0]["rearmOn"] = json!("successor-revision");
        }
        Some(other) => panic!("unsupported timer control remap {other}"),
        None => {}
    }
    compile_registry(source)
}

fn compiled_tombstone_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]["tombstone"] = json!(true);
    source["accessProfiles"][0]["permissions"]["records"][0]["operations"]
        .as_array_mut()
        .expect("service operations are an array")
        .push(json!("tombstone"));
    compile_registry(source)
}
