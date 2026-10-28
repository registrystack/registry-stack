// SPDX-License-Identifier: Apache-2.0

//! Native-process record-timer acceptance journeys over real PostgreSQL.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
#[path = "support/record_timer_native.rs"]
mod record_timer_native;

use std::{collections::BTreeSet, time::Duration};

use record_timer_native::{
    NativeOutcomeSettlementKind, NativeProcessIdentity, NativeRunIdentity, NativeTimerCheckpoint,
    NativeTimerHarness, TimerEvidence,
};
use registry_breg::timer_operator::{TimerControlState, TimerOperatorService};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_native_process_activates_one_future_record_exactly_once() {
    let mut harness = NativeTimerHarness::start().await;
    let result = future_activation(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_native_processes_contend_then_restart_without_duplicate_effect() {
    let mut harness = NativeTimerHarness::start().await;
    let result = two_replica_contention_and_restart(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_native_processes_pause_resume_and_do_not_refire_after_restart() {
    let mut harness = NativeTimerHarness::start().await;
    let result = three_replica_pause_resume_and_restart(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_fault_after_claim_kill_reclaims_once_after_lease_expiry() {
    let mut harness = NativeTimerHarness::start().await;
    let result = after_claim_kill_reclaim(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_fault_before_commit_kill_rolls_back_then_reclaims_once() {
    let mut harness = NativeTimerHarness::start().await;
    let result = before_commit_kill_reclaim(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_fault_after_commit_kill_preserves_one_durable_outcome() {
    let mut harness = NativeTimerHarness::start().await;
    let result = after_commit_kill_preserves_outcome(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_fault_stale_resumed_owner_cannot_settle_after_peer() {
    let mut harness = NativeTimerHarness::start().await;
    let result = stale_resumed_owner_is_fenced(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_stale_outcome_technical_failure_cannot_overwrite_peer() {
    let mut harness = NativeTimerHarness::start().await;
    let result = stale_technical_failure_settlement_is_fenced(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_stale_outcome_business_refusal_cannot_overwrite_peer() {
    let mut harness = NativeTimerHarness::start_with_business_refusal_enabled().await;
    let result = stale_business_refusal_settlement_is_fenced(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_removed_timer_fences_a_predecessor_process_after_claim() {
    let mut harness = NativeTimerHarness::start().await;
    let result = removed_timer_fences_predecessor_process(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_database_session_loss_rolls_back_active_transaction_for_peer_recovery() {
    let mut harness = NativeTimerHarness::start().await;
    let result = database_session_loss_recovery(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_fixture_pause_resume_fences_pre_pause_claim_across_processes() {
    let mut harness = NativeTimerHarness::start().await;
    let result = fixture_pause_resume_fences_claim(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_writer_first_race_rechecks_eligibility_without_partial_timer_effect() {
    let mut harness = NativeTimerHarness::start().await;
    let result = writer_first_race(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_timer_first_race_preserves_if_match_and_refuses_stale_writer() {
    let mut harness = NativeTimerHarness::start().await;
    let result = timer_first_race(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_lifecycle_writer_first_predicate_hold_preserves_pending_occurrence() {
    let mut harness = NativeTimerHarness::start().await;
    let result = writer_first_lifecycle(&mut harness, LifecycleMutation::Hold).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_lifecycle_predicate_release_executes_the_same_occurrence_once() {
    let mut harness = NativeTimerHarness::start().await;
    let result = predicate_release(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_reviewed_successor_refreshes_held_occurrence_once_after_restart() {
    let mut harness = NativeTimerHarness::start().await;
    let result = reviewed_successor_releases_cached_predicate(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_lifecycle_writer_first_clear_date_cancels_without_timer_effect() {
    let mut harness = NativeTimerHarness::start().await;
    let result = writer_first_lifecycle(&mut harness, LifecycleMutation::ClearDate).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_lifecycle_writer_first_tombstone_cancels_without_timer_effect() {
    let mut harness = NativeTimerHarness::start().await;
    let result = writer_first_lifecycle(&mut harness, LifecycleMutation::Tombstone).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_terminal_refused_survives_writes_and_replacement_process() {
    let mut harness = NativeTimerHarness::start_with_business_refusal_enabled().await;
    let result = terminal_refused_restart(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_terminal_missed_survives_writes_and_replacement_process() {
    let mut harness = NativeTimerHarness::start().await;
    let result = terminal_missed_restart(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_bounded_fairness_interleaves_all_timer_lanes_across_types_and_replicas() {
    let mut harness = NativeTimerHarness::start_with_fairness_types().await;
    let result = bounded_two_type_two_replica_fairness(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_terminal_cancelled_survives_writes_and_replacement_process() {
    let mut harness = NativeTimerHarness::start().await;
    let result = terminal_cancelled_restart(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_historical_record_stays_unarmed_until_a_material_control_write() {
    let mut harness = NativeTimerHarness::start_timer_free().await;
    let result = historical_record_requires_material_rearm(&mut harness).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_lifecycle_timer_first_hold_patch_refuses_stale_if_match() {
    let mut harness = NativeTimerHarness::start().await;
    let result = timer_first_lifecycle(&mut harness, LifecycleMutation::Hold).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_lifecycle_timer_first_clear_date_refuses_stale_if_match() {
    let mut harness = NativeTimerHarness::start().await;
    let result = timer_first_lifecycle(&mut harness, LifecycleMutation::ClearDate).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_lifecycle_timer_first_tombstone_refuses_stale_if_match() {
    let mut harness = NativeTimerHarness::start().await;
    let result = timer_first_lifecycle(&mut harness, LifecycleMutation::Tombstone).await;
    report_identity(&harness.run_identity());
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_bulk_race_batch_preserves_atomicity_in_both_lock_orders() {
    let mut writer_first = NativeTimerHarness::start_with_bulk_writes_enabled().await;
    let result = batch_writer_first(&mut writer_first).await;
    report_identity(&writer_first.run_identity());
    finish_result(writer_first, result).await;

    let mut timer_first = NativeTimerHarness::start_with_bulk_writes_enabled().await;
    let result = batch_timer_first(&mut timer_first).await;
    report_identity(&timer_first.run_identity());
    finish_result(timer_first, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_bulk_race_ingestion_preserves_checkpoint_in_both_lock_orders() {
    let mut writer_first = NativeTimerHarness::start_with_bulk_writes_enabled().await;
    let result = ingestion_writer_first(&mut writer_first).await;
    report_identity(&writer_first.run_identity());
    finish_result(writer_first, result).await;

    let mut timer_first = NativeTimerHarness::start_with_bulk_writes_enabled().await;
    let result = ingestion_timer_first(&mut timer_first).await;
    report_identity(&timer_first.run_identity());
    finish_result(timer_first, result).await;
}

#[derive(Clone, Copy, Debug)]
enum LifecycleMutation {
    Hold,
    ClearDate,
    Tombstone,
}

async fn bounded_two_type_two_replica_fairness(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    let paused_epoch = harness.set_scheduler_paused(true).await?;
    harness.enable_checkpoint(NativeTimerCheckpoint::AfterClaim, None)?;
    harness.start_replicas(2).await?;
    let client = harness.client(0)?;
    let service_create = harness.create_binding_for(&client, "service").await?;
    let case_create = harness.create_binding_for(&client, "case").await?;
    let service_patch = harness.patch_binding(&client).await?;
    let now = harness.database_now().await?;
    let due_at = now + chrono::Duration::seconds(5);
    let future_at = now + chrono::Duration::seconds(120);

    let repeated = harness
        .create_timer_record(
            &client,
            &service_create,
            due_at,
            due_at + chrono::Duration::seconds(30),
            false,
        )
        .await?;
    let repeated =
        NativeTimerHarness::reschedule_activation(&client, &service_patch, &repeated, due_at)
            .await?;
    let repeated =
        NativeTimerHarness::reschedule_activation(&client, &service_patch, &repeated, due_at)
            .await?;
    let repeated_id = repeated.value.data.record_identifier.clone();
    let repeated_current = harness.timer_evidence(&repeated_id).await?;

    let current_case = harness
        .create_timer_record(
            &client,
            &case_create,
            due_at,
            due_at + chrono::Duration::seconds(30),
            false,
        )
        .await?;
    let current_case_id = current_case.value.data.record_identifier.clone();
    let current_case_evidence = harness
        .timer_evidence_for("case", "activate", &current_case_id)
        .await?;

    let false_gate = harness
        .create_timer_record(
            &client,
            &service_create,
            due_at,
            due_at + chrono::Duration::seconds(30),
            true,
        )
        .await?;
    let false_gate_id = false_gate.value.data.record_identifier.clone();
    let false_gate_armed = harness.timer_evidence(&false_gate_id).await?;

    let elapsed_due = now - chrono::Duration::seconds(10);
    let elapsed = harness
        .create_timer_record(
            &client,
            &case_create,
            elapsed_due,
            now - chrono::Duration::seconds(1),
            false,
        )
        .await?;
    let elapsed_id = elapsed.value.data.record_identifier.clone();

    // Fixture-authored semantic staleness is deliberately ordered by
    // (record_type, occurrence_id): the busy `case` key sorts before the
    // available `service` key, so cursor progress and wrap are observable.
    let busy = harness
        .create_timer_record(
            &client,
            &case_create,
            future_at,
            future_at + chrono::Duration::seconds(30),
            false,
        )
        .await?;
    let busy_id = busy.value.data.record_identifier.clone();
    let busy_occurrence = harness
        .fixture_only_mark_current_timer_stale("case", "activate", &busy_id)
        .await?;
    let available = harness
        .create_timer_record(
            &client,
            &service_create,
            future_at,
            future_at + chrono::Duration::seconds(30),
            true,
        )
        .await?;
    let available_id = available.value.data.record_identifier.clone();
    let available_occurrence = harness
        .fixture_only_mark_current_timer_stale("service", "activate", &available_id)
        .await?;
    let busy_lock = harness.hold_anchor_lock("case", &busy_id).await?;

    let resumed_epoch = harness.set_scheduler_paused(false).await?;
    if resumed_epoch != paused_epoch + 1 {
        return Err("fairness fixture did not advance the scheduler epoch once".to_owned());
    }
    let due_occurrences = BTreeSet::from([
        repeated_current.occurrence_id,
        current_case_evidence.occurrence_id,
    ]);
    let observers = harness
        .wait_checkpoint_observed_any(&due_occurrences, Duration::from_secs(15))
        .await?;
    let observed_occurrences = observers
        .iter()
        .map(|(occurrence_id, _)| *occurrence_id)
        .collect::<BTreeSet<_>>();
    if observed_occurrences != due_occurrences {
        return Err(format!(
            "the two replicas did not hold distinct actual claims: observed={observed_occurrences:?}, expected={due_occurrences:?}"
        ));
    }
    let observer_processes = observers
        .iter()
        .map(|(_, process)| process.clone())
        .collect::<Vec<_>>();
    assert_distinct_processes(&observer_processes, 2)?;

    let available_refreshed = harness
        .wait_for_current_timer_revision(
            "service",
            "activate",
            &available_id,
            Duration::from_secs(2),
        )
        .await?;
    let busy_still_stale = harness
        .timer_evidence_for("case", "activate", &busy_id)
        .await?;
    let elapsed_missed = wait_for_timer_state(
        harness,
        "case",
        "activate",
        &elapsed_id,
        "missed",
        Duration::from_secs(2),
    )
    .await?;
    if available_refreshed.occurrence_id != available_occurrence
        || available_refreshed.gate_open
        || busy_still_stale.occurrence_id != busy_occurrence
        || busy_still_stale.definition_revision
            == harness.registry.entities()["case"].timers["activate"].definition_revision
        || elapsed_missed.executed_attempt_count != 0
        || elapsed_missed.outcome_code.as_deref() != Some("execution-window-expired")
    {
        return Err(format!(
            "fairness lanes did not progress past the locked stale key: available={available_refreshed:?}, busy={busy_still_stale:?}, elapsed={elapsed_missed:?}"
        ));
    }

    harness.release_checkpoint_barriers()?;
    harness
        .wait_for_completion(&repeated_id, Duration::from_secs(8))
        .await?;
    harness
        .wait_for_completion_for("case", "activate", &current_case_id, Duration::from_secs(8))
        .await?;
    let held_false_gate = harness.timer_evidence(&false_gate_id).await?;
    if held_false_gate.occurrence_id != false_gate_armed.occurrence_id
        || held_false_gate.state != "pending"
        || held_false_gate.gate_open
        || held_false_gate.executed_attempt_count != 0
    {
        return Err(format!(
            "current false-gate work did not stay held without an attempt: {held_false_gate:?}"
        ));
    }

    busy_lock.release().await?;
    let busy_refreshed = harness
        .wait_for_current_timer_revision("case", "activate", &busy_id, Duration::from_secs(5))
        .await?;
    if busy_refreshed.occurrence_id != busy_occurrence {
        return Err("cursor wrap changed the formerly busy occurrence identity".to_owned());
    }

    let false_gate_record = harness.get_service(&client, &false_gate_id).await?;
    NativeTimerHarness::set_paused(&client, &service_patch, &false_gate_record, false).await?;
    let false_gate_completed = harness
        .wait_for_completion(&false_gate_id, Duration::from_secs(8))
        .await?;
    if false_gate_completed.occurrence_id != false_gate_armed.occurrence_id
        || false_gate_completed.executed_attempt_count != 1
    {
        return Err(format!(
            "false-gate release did not execute the same occurrence exactly once: {false_gate_completed:?}"
        ));
    }

    let generations = harness
        .timer_generation_states("service", "activate", &repeated_id)
        .await?;
    let superseded = generations
        .iter()
        .filter(|generation| generation.state == "superseded")
        .count();
    let completed = generations
        .iter()
        .filter(|generation| generation.state == "completed" && generation.is_current)
        .count();
    if generations.len() != 3 || superseded != 2 || completed != 1 {
        return Err(format!(
            "repeated generations did not retain two predecessors and one current completion: {generations:?}"
        ));
    }

    let operator_config = harness.write_operator_runtime_config("fairness-status")?;
    let operator = TimerOperatorService::from_runtime_config(&operator_config.path)
        .await
        .map_err(|error| format!("fairness timer operator construction failed: {error}"))?;
    let status = operator
        .status()
        .await
        .map_err(|error| format!("fairness timer status failed: {error}"))?;
    if status.control_state != TimerControlState::Running
        || status.control_epoch != resumed_epoch
        || status.limits.claim_batch_maximum != 1
        || status.limits.maximum_concurrent_attempts != 1
        || status.limits.stale_revision_batch_maximum != 32
        || status.limits.elapsed_window_batch_maximum != 32
    {
        return Err(format!(
            "fairness status did not publish the scheduler's exact bounded limits: {status:?}"
        ));
    }
    drop(operator);

    let settled_before_restart = vec![
        harness.timer_evidence(&repeated_id).await?,
        harness
            .timer_evidence_for("case", "activate", &current_case_id)
            .await?,
        harness.timer_evidence(&false_gate_id).await?,
        harness
            .timer_evidence_for("case", "activate", &elapsed_id)
            .await?,
        harness.timer_evidence(&available_id).await?,
        harness
            .timer_evidence_for("case", "activate", &busy_id)
            .await?,
    ];
    harness.crash_all_replicas()?;
    harness.disable_before_claim_barrier();
    harness.start_replicas(2).await?;
    assert_restart_processes(&harness.run_identity().processes, 4, 2)?;
    harness
        .wait_for_timer_worker_first_success(&[2, 3], Duration::from_secs(5))
        .await?;
    let settled_after_restart = vec![
        harness.timer_evidence(&repeated_id).await?,
        harness
            .timer_evidence_for("case", "activate", &current_case_id)
            .await?,
        harness.timer_evidence(&false_gate_id).await?,
        harness
            .timer_evidence_for("case", "activate", &elapsed_id)
            .await?,
        harness.timer_evidence(&available_id).await?,
        harness
            .timer_evidence_for("case", "activate", &busy_id)
            .await?,
    ];
    if settled_after_restart != settled_before_restart {
        return Err(format!(
            "replacement processes changed settled markers or pending future work: before={settled_before_restart:?}, after={settled_after_restart:?}"
        ));
    }
    println!(
        "record-timer-native fairness=bounded record_types=2 replicas=2 launches=4 stale_available={} stale_busy={} repeated_generations={}",
        available_occurrence,
        busy_occurrence,
        generations.len()
    );
    Ok(())
}

async fn wait_for_timer_state(
    harness: &NativeTimerHarness,
    record_type: &str,
    timer_id: &str,
    record_id: &str,
    state: &str,
    timeout: Duration,
) -> Result<TimerEvidence, String> {
    tokio::time::timeout(timeout, async {
        loop {
            let evidence = harness
                .timer_evidence_for(record_type, timer_id, record_id)
                .await?;
            if evidence.state == state {
                return Ok(evidence);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| format!("timer did not reach {state} within the bounded wait"))?
}

async fn future_activation(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(3);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();

    let armed = harness.timer_evidence(&record_id).await?;
    if armed.state != "pending"
        || armed.status != "scheduled"
        || armed.revision != 1
        || armed.due_at != due_at
        || armed.completed_at.is_some()
        || armed.control_state != "running"
    {
        return Err(format!(
            "future timer was not durably armed before its due instant: {armed:?}"
        ));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let early_database_now = harness.database_now().await?;
    if early_database_now >= due_at {
        return Err(format!(
            "native timer pre-due checkpoint ran too slowly: database_now={early_database_now}, due_at={due_at}"
        ));
    }
    let early = harness.timer_evidence(&record_id).await?;
    if early != armed {
        return Err(format!(
            "future timer changed before the database due instant: armed={armed:?}, early={early:?}"
        ));
    }

    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(10))
        .await?;
    if completed.revision != armed.revision + 1
        || completed.revisions != armed.revisions + 1
        || completed.outbox_entries != armed.outbox_entries + 1
        || completed.action_receipts != armed.action_receipts + 1
        || completed.occurrence_id != armed.occurrence_id
        || completed.due_at != due_at
        || completed
            .completed_at
            .is_none_or(|executed| executed < due_at)
    {
        return Err(format!(
            "native timer completion was not one atomic exact-once effect: armed={armed:?}, completed={completed:?}"
        ));
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    let settled = harness.timer_evidence(&record_id).await?;
    if settled != completed {
        return Err(format!(
            "settled native timer changed on a later scan: completed={completed:?}, settled={settled:?}"
        ));
    }
    let fetched = harness.get_service(&client, &record_id).await?;
    if fetched.value.data.domain_data.get("status") != Some(&serde_json::json!("active")) {
        return Err("Record API did not expose the activated status".to_owned());
    }
    let patch = harness.patch_binding(&client).await?;
    let edited = harness
        .replace_description(
            &client,
            &patch,
            &fetched,
            "unrelated edit after native timer completion",
        )
        .await?;
    let after_edit = harness.timer_evidence(&record_id).await?;
    assert_unrelated_write_preserved_settlement(&completed, &after_edit)?;

    harness.crash_all_replicas()?;
    harness.start_replicas(1).await?;
    harness
        .wait_for_timer_worker_first_success(&[1], Duration::from_secs(5))
        .await?;
    let restarted = harness.timer_evidence(&record_id).await?;
    if restarted != after_edit {
        return Err(format!(
            "completed timer refired after a replacement process started: after_edit={after_edit:?}, restarted={restarted:?}"
        ));
    }
    let replacement_client = harness.client(1)?;
    let after_restart = harness.get_service(&replacement_client, &record_id).await?;
    if after_restart.value.data.domain_data.get("description")
        != edited.value.data.domain_data.get("description")
    {
        return Err("unrelated Record edit did not survive process replacement".to_owned());
    }
    assert_restart_processes(&harness.run_identity().processes, 2, 1)
}

async fn terminal_refused_restart(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let patch = harness.patch_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(2);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let refused = wait_for_terminal_state(harness, &record_id, "refused").await?;
    if refused.outcome_code.as_deref() != Some("declared-refusal")
        || refused.executed_attempt_count != 1
    {
        return Err(format!(
            "native refusal did not settle exactly once: {refused:?}"
        ));
    }
    let current = harness.get_service(&client, &record_id).await?;
    let paused = NativeTimerHarness::set_paused(&client, &patch, &current, true).await?;
    let reopened = NativeTimerHarness::set_paused(&client, &patch, &paused, false).await?;
    harness
        .replace_description(
            &client,
            &patch,
            &reopened,
            "terminal refused unrelated write",
        )
        .await?;
    let after_writes = harness.timer_evidence(&record_id).await?;
    assert_terminal_marker(&refused, &after_writes, "refused")?;
    harness.crash_all_replicas()?;
    harness.start_replicas(1).await?;
    harness
        .wait_for_timer_worker_first_success(&[1], Duration::from_secs(5))
        .await?;
    let restarted = harness.timer_evidence(&record_id).await?;
    if restarted != after_writes {
        return Err(format!(
            "terminal refusal changed after replacement process: before={after_writes:?}, after={restarted:?}"
        ));
    }
    assert_restart_processes(&harness.run_identity().processes, 2, 1)
}

async fn terminal_missed_restart(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let patch = harness.patch_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(5);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let held = NativeTimerHarness::set_paused(&client, &patch, &created, true).await?;
    let shortened = NativeTimerHarness::set_activation_not_after(
        &client,
        &patch,
        &held,
        due_at + chrono::Duration::seconds(1),
    )
    .await?;
    let record_id = shortened.value.data.record_identifier.clone();
    let missed = wait_for_terminal_state(harness, &record_id, "missed").await?;
    if missed.outcome_code.as_deref() != Some("execution-window-expired")
        || missed.executed_attempt_count != 0
    {
        return Err(format!("native missed window was not exact: {missed:?}"));
    }
    let reopened = NativeTimerHarness::set_paused(&client, &patch, &shortened, false).await?;
    let paused = NativeTimerHarness::set_paused(&client, &patch, &reopened, true).await?;
    harness
        .replace_description(&client, &patch, &paused, "terminal missed unrelated write")
        .await?;
    let after_writes = harness.timer_evidence(&record_id).await?;
    assert_terminal_marker(&missed, &after_writes, "missed")?;
    harness.crash_all_replicas()?;
    harness.start_replicas(1).await?;
    harness
        .wait_for_timer_worker_first_success(&[1], Duration::from_secs(5))
        .await?;
    let restarted = harness.timer_evidence(&record_id).await?;
    if restarted != after_writes {
        return Err(format!(
            "terminal missed marker changed after replacement process: before={after_writes:?}, after={restarted:?}"
        ));
    }
    assert_restart_processes(&harness.run_identity().processes, 2, 1)
}

async fn terminal_cancelled_restart(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let patch = harness.patch_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::minutes(5);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let cancelled = NativeTimerHarness::clear_activation(&client, &patch, &created).await?;
    let record_id = cancelled.value.data.record_identifier.clone();
    let terminal = harness.timer_evidence(&record_id).await?;
    if terminal.state != "cancelled"
        || terminal.outcome_code.as_deref() != Some("control-cleared")
        || terminal.executed_attempt_count != 0
    {
        return Err(format!("native cancellation was not exact: {terminal:?}"));
    }
    let paused = NativeTimerHarness::set_paused(&client, &patch, &cancelled, true).await?;
    let reopened = NativeTimerHarness::set_paused(&client, &patch, &paused, false).await?;
    harness
        .replace_description(
            &client,
            &patch,
            &reopened,
            "terminal cancelled unrelated write",
        )
        .await?;
    let after_writes = harness.timer_evidence(&record_id).await?;
    assert_terminal_marker(&terminal, &after_writes, "cancelled")?;
    harness.crash_all_replicas()?;
    harness.start_replicas(1).await?;
    harness
        .wait_for_timer_worker_first_success(&[1], Duration::from_secs(5))
        .await?;
    let restarted = harness.timer_evidence(&record_id).await?;
    if restarted != after_writes {
        return Err(format!(
            "terminal cancelled marker changed after replacement process: before={after_writes:?}, after={restarted:?}"
        ));
    }
    assert_restart_processes(&harness.run_identity().processes, 2, 1)
}

#[cfg(feature = "tooling")]
async fn removed_timer_fences_predecessor_process(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.enable_checkpoint(NativeTimerCheckpoint::AfterClaim, Some(2_000))?;
    harness.start_replicas(1).await?;
    let predecessor_client = harness.client(0)?;
    let create = harness.create_binding(&predecessor_client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(2);
    let created = harness
        .create_scheduled_service(&predecessor_client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    let (predecessor, predecessor_process) = harness
        .wait_for_one_checkpoint(armed.occurrence_id, Duration::from_secs(10))
        .await?;

    let activation = harness.activate_reviewed_timer_removal_successor().await?;
    if activation.predecessor_package_digest == activation.successor_package_digest
        || activation.predecessor_activation_id == activation.successor_activation_id
    {
        return Err("timer-removal successor did not change governed identity".to_owned());
    }
    let after_apply = harness.timer_evidence(&record_id).await?;
    assert_business_unchanged(&armed, &after_apply, "timer-removal successor apply")?;
    if after_apply.state != "leased"
        || after_apply.executed_attempt_count != 0
        || after_apply.claimed_activation_id
            != Some(
                uuid::Uuid::parse_str(&activation.predecessor_activation_id)
                    .map_err(|_| "predecessor activation id was not a UUID".to_owned())?,
            )
    {
        return Err(format!(
            "timer-removal successor did not preserve the predecessor lease without effects: {after_apply:?}"
        ));
    }
    harness.release_checkpoint(predecessor)?;
    harness
        .wait_replica_unready(predecessor, Duration::from_secs(10))
        .await?;
    harness.expect_non_info_code_range(
        predecessor,
        "record_timer.worker.iteration_failed",
        1,
        6,
    )?;
    harness.expect_non_info_code_range(predecessor, "hook.claim.identity_refused", 0, 6)?;
    harness.expect_non_info_code_range(predecessor, "hook.worker.iteration_failed", 0, 6)?;
    harness.expect_non_info_code_range(predecessor, "review.worker.iteration_failed", 0, 2)?;
    let after_stale_owner = harness.timer_evidence(&record_id).await?;
    if after_stale_owner != after_apply {
        return Err(format!(
            "the predecessor process changed its fenced lease after removal: leased={after_apply:?}, after={after_stale_owner:?}"
        ));
    }
    if predecessor_process.pid == 0 {
        return Err("timer-removal checkpoint omitted predecessor process identity".to_owned());
    }

    harness.crash_all_replicas()?;
    harness.disable_before_claim_barrier();
    harness.start_replicas(1).await?;
    let cancelled = wait_for_terminal_state(harness, &record_id, "cancelled").await?;
    if cancelled.occurrence_id != armed.occurrence_id
        || cancelled.outcome_code.as_deref() != Some("binding-removed")
        || cancelled.executed_attempt_count != 0
        || cancelled.revision != armed.revision
        || cancelled.revisions != armed.revisions
        || cancelled.outbox_entries != armed.outbox_entries
        || cancelled.action_receipts != armed.action_receipts
    {
        return Err(format!(
            "successor cleanup did not cancel the exact removed occurrence without effects: armed={armed:?}, cancelled={cancelled:?}"
        ));
    }
    let attempts = harness.timer_attempt_evidence(armed.occurrence_id).await?;
    if !attempts.is_empty() {
        return Err(format!(
            "removed timer retained unexpected predecessor attempts: {attempts:?}"
        ));
    }
    assert_restart_processes(&harness.run_identity().processes, 2, 1)
}

#[cfg(feature = "tooling")]
async fn historical_record_requires_material_rearm(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    let predecessor_client = harness.client(0)?;
    let create = harness.create_binding(&predecessor_client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::minutes(5);
    let historical = harness
        .create_scheduled_service(&predecessor_client, &create, due_at)
        .await?;
    let record_id = historical.value.data.record_identifier.clone();
    if harness.timer_metadata_counts(&record_id).await? != (0, 0) {
        return Err("timer-free predecessor unexpectedly created timer metadata".to_owned());
    }

    let activation = harness.activate_maintained_timer_successor().await?;
    if activation.predecessor_package_digest == activation.successor_package_digest
        || activation.predecessor_activation_id == activation.successor_activation_id
    {
        return Err(
            "timer-adding successor did not change package and activation identity".to_owned(),
        );
    }
    harness
        .wait_replica_unready(0, Duration::from_secs(10))
        .await?;
    harness.expect_non_info_code_range(0, "hook.claim.identity_refused", 0, 6)?;
    harness.expect_non_info_code_range(0, "hook.worker.iteration_failed", 0, 6)?;
    harness.expect_non_info_code_range(0, "review.worker.iteration_failed", 0, 2)?;
    harness.crash_all_replicas()?;
    harness.start_replicas(1).await?;
    harness
        .wait_for_timer_worker_first_success(&[1], Duration::from_secs(5))
        .await?;
    if harness.timer_metadata_counts(&record_id).await? != (0, 0) {
        return Err("timer activation or its first scan armed a historical Record".to_owned());
    }

    let successor_client = harness.client(1)?;
    let patch = harness.patch_binding(&successor_client).await?;
    let current = harness.get_service(&successor_client, &record_id).await?;
    let held = NativeTimerHarness::set_paused(&successor_client, &patch, &current, true).await?;
    let reopened = NativeTimerHarness::set_paused(&successor_client, &patch, &held, false).await?;
    if harness.timer_metadata_counts(&record_id).await? != (0, 0) {
        return Err("predicate-only writes armed a historical Record".to_owned());
    }

    harness.crash_all_replicas()?;
    harness.start_replicas(1).await?;
    harness
        .wait_for_timer_worker_first_success(&[2], Duration::from_secs(5))
        .await?;
    if harness.timer_metadata_counts(&record_id).await? != (0, 0) {
        return Err("a replacement process armed a historical Record".to_owned());
    }

    let replacement_client = harness.client(2)?;
    let replacement_patch = harness.patch_binding(&replacement_client).await?;
    let material_due_at = harness.database_now().await? + chrono::Duration::minutes(5);
    NativeTimerHarness::reschedule_activation(
        &replacement_client,
        &replacement_patch,
        &reopened,
        material_due_at,
    )
    .await?;
    if harness.timer_metadata_counts(&record_id).await? != (1, 1) {
        return Err("one material control write did not create exactly one occurrence".to_owned());
    }
    let pending = harness.timer_evidence(&record_id).await?;
    if pending.state != "pending" || pending.executed_attempt_count != 0 {
        return Err(format!(
            "material control write did not leave one unexecuted pending occurrence: {pending:?}"
        ));
    }
    assert_restart_processes(&harness.run_identity().processes, 3, 1)
}

async fn wait_for_terminal_state(
    harness: &NativeTimerHarness,
    record_id: &str,
    expected: &str,
) -> Result<TimerEvidence, String> {
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let evidence = harness.timer_evidence(record_id).await?;
            if evidence.state == expected {
                return Ok(evidence);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| format!("native timer did not reach {expected} within the bounded wait"))?
}

fn assert_terminal_marker(
    terminal: &TimerEvidence,
    after_writes: &TimerEvidence,
    expected: &str,
) -> Result<(), String> {
    if after_writes.state != expected
        || after_writes.occurrence_id != terminal.occurrence_id
        || after_writes.outcome_code != terminal.outcome_code
        || after_writes.executed_attempt_count != terminal.executed_attempt_count
        || after_writes.action_receipts != terminal.action_receipts
        || after_writes.completed_at != terminal.completed_at
        || after_writes.revision != terminal.revision + 3
        || after_writes.revisions != terminal.revisions + 3
    {
        return Err(format!(
            "predicate and unrelated writes changed terminal {expected} state: terminal={terminal:?}, after={after_writes:?}"
        ));
    }
    Ok(())
}

async fn two_replica_contention_and_restart(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.enable_before_claim_barrier()?;
    harness.start_replicas(2).await?;
    let first_client = harness.client(0)?;
    let second_client = harness.client(1)?;
    let create = harness.create_binding(&first_client).await?;
    let patch = harness.patch_binding(&first_client).await?;

    let unrelated_due = harness.database_now().await? + chrono::Duration::minutes(5);
    let unrelated = harness
        .create_scheduled_service(&first_client, &create, unrelated_due)
        .await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(3);
    let created = harness
        .create_scheduled_service(&first_client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    assert_armed(&armed, due_at)?;

    let observed = harness
        .wait_before_claim_observed(armed.occurrence_id, Duration::from_secs(10))
        .await?;
    assert_distinct_processes(&observed, 2)?;
    report_contention(armed.occurrence_id, &observed);

    let unrelated_patched = harness
        .replace_description(
            &first_client,
            &patch,
            &unrelated,
            "unrelated write completed during timer contention",
        )
        .await?;
    if unrelated_patched.value.data.domain_data.get("description")
        != Some(&serde_json::json!(
            "unrelated write completed during timer contention"
        ))
    {
        return Err("unrelated Record write did not complete during contention".to_owned());
    }

    harness.release_before_claim_barriers()?;
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(10))
        .await?;
    assert_one_completion(&armed, &completed, due_at)?;
    assert_settled_and_public(harness, &second_client, &record_id, &completed).await?;

    harness.crash_all_replicas()?;
    harness.disable_before_claim_barrier();
    harness.start_replicas(2).await?;
    harness
        .wait_for_timer_worker_first_success(&[2, 3], Duration::from_secs(5))
        .await?;
    let restarted = harness.timer_evidence(&record_id).await?;
    if restarted != completed {
        return Err(format!(
            "completed timer refired after two replacement processes started: completed={completed:?}, restarted={restarted:?}"
        ));
    }
    let identity = harness.run_identity();
    assert_restart_processes(&identity.processes, 4, 2)
}

async fn three_replica_pause_resume_and_restart(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.enable_before_claim_barrier()?;
    harness.start_replicas(3).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let paused_epoch = harness.set_scheduler_paused(true).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(3);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    assert_armed(&armed, due_at)?;

    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if harness.database_now().await? > due_at {
                return Ok::<(), String>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| "database clock did not pass the paused timer due instant".to_owned())??;
    let held = harness.timer_evidence(&record_id).await?;
    if held != armed {
        return Err(format!(
            "paused scheduler changed an eligible generation: armed={armed:?}, held={held:?}"
        ));
    }
    let consumer_now = harness.database_now().await?;
    let held_public = harness.get_service(&client, &record_id).await?;
    if held_public.value.data.domain_data.get("status") != Some(&serde_json::json!("scheduled"))
        || !reference_consumer_treats_intended_time_as_effective(&held_public.value, consumer_now)?
    {
        return Err(
            "reference consumer did not derive time-based validity from activatesAt while materialized status remained scheduled"
                .to_owned(),
        );
    }

    let resumed_epoch = harness.set_scheduler_paused(false).await?;
    if resumed_epoch != paused_epoch + 1 {
        return Err(format!(
            "pause/resume did not advance the control epoch exactly once: paused={paused_epoch}, resumed={resumed_epoch}"
        ));
    }
    let observed = harness
        .wait_before_claim_observed(armed.occurrence_id, Duration::from_secs(10))
        .await?;
    assert_distinct_processes(&observed, 3)?;
    report_contention(armed.occurrence_id, &observed);
    harness.release_before_claim_barriers()?;

    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(10))
        .await?;
    assert_one_completion(&armed, &completed, due_at)?;
    let completed_public = harness.get_service(&client, &record_id).await?;
    if completed_public.value.data.domain_data.get("status") != Some(&serde_json::json!("active"))
        || intended_activation(&completed_public.value)? != due_at
    {
        return Err(
            "materialized activation did not preserve the authoritative intended instant"
                .to_owned(),
        );
    }
    harness.crash_all_replicas()?;
    harness.disable_before_claim_barrier();
    harness.start_replicas(3).await?;
    harness
        .wait_for_timer_worker_first_success(&[3, 4, 5], Duration::from_secs(5))
        .await?;
    let restarted = harness.timer_evidence(&record_id).await?;
    if restarted != completed {
        return Err(format!(
            "completed timer refired after three replacement processes started: completed={completed:?}, restarted={restarted:?}"
        ));
    }
    let fetched = harness.get_service(&harness.client(5)?, &record_id).await?;
    if fetched.value.data.domain_data.get("status") != Some(&serde_json::json!("active")) {
        return Err("replacement process did not expose the activated Record".to_owned());
    }
    let identity = harness.run_identity();
    assert_restart_processes(&identity.processes, 6, 3)
}

async fn after_claim_kill_reclaim(harness: &mut NativeTimerHarness) -> Result<(), String> {
    let (record_id, armed, due_at, owner, _) =
        prepare_fault_journey(harness, NativeTimerCheckpoint::AfterClaim).await?;
    let leased = assert_durable_lease(harness, &record_id, &armed).await?;
    harness.crash_replica(owner)?;
    harness.release_checkpoints_except(owner)?;
    assert_no_effect_before_lease_expiry(harness, &record_id, &leased).await?;
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(10))
        .await?;
    assert_one_completion(&armed, &completed, due_at)?;
    assert_settled_after_delay(harness, &record_id, &completed).await
}

async fn before_commit_kill_reclaim(harness: &mut NativeTimerHarness) -> Result<(), String> {
    let (record_id, armed, due_at, owner, _) =
        prepare_fault_journey(harness, NativeTimerCheckpoint::BeforeCommit).await?;
    let staged = harness.timer_evidence(&record_id).await?;
    if staged.state != "leased"
        || staged.status != "scheduled"
        || staged.revision != armed.revision
        || staged.revisions != armed.revisions
        || staged.outbox_entries != armed.outbox_entries
        || staged.action_receipts != armed.action_receipts
    {
        return Err(format!(
            "before-commit checkpoint exposed a partial business effect: armed={armed:?}, staged={staged:?}"
        ));
    }
    harness.crash_replica(owner)?;
    harness.release_checkpoints_except(owner)?;
    assert_no_effect_before_lease_expiry(harness, &record_id, &staged).await?;
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(10))
        .await?;
    assert_one_completion(&armed, &completed, due_at)?;
    assert_settled_after_delay(harness, &record_id, &completed).await
}

async fn after_commit_kill_preserves_outcome(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    let (record_id, armed, due_at, owner, _) =
        prepare_fault_journey(harness, NativeTimerCheckpoint::AfterCommitBeforeResponse).await?;
    let committed = harness.timer_evidence(&record_id).await?;
    assert_one_completion(&armed, &committed, due_at)?;
    harness.crash_replica(owner)?;
    let peer = if owner == 0 { 1 } else { 0 };
    let peer_client = harness.client(peer)?;
    let fetched = harness.get_service(&peer_client, &record_id).await?;
    if fetched.value.data.domain_data.get("status") != Some(&serde_json::json!("active")) {
        return Err("peer process did not expose the committed timer outcome".to_owned());
    }
    assert_settled_after_delay(harness, &record_id, &committed).await
}

async fn stale_resumed_owner_is_fenced(harness: &mut NativeTimerHarness) -> Result<(), String> {
    let (record_id, armed, due_at, owner, owner_identity) =
        prepare_fault_journey(harness, NativeTimerCheckpoint::AfterClaim).await?;
    let leased = assert_durable_lease(harness, &record_id, &armed).await?;
    let suspended = harness.suspend_replica(owner)?;
    if suspended != owner_identity {
        return Err("suspended process did not match the checkpoint owner".to_owned());
    }
    harness.release_checkpoints_except(owner)?;
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(10))
        .await?;
    assert_one_completion(&armed, &completed, due_at)?;
    let claim_until = leased
        .claim_until
        .ok_or_else(|| "leased timer omitted claim expiry".to_owned())?;
    if completed
        .completed_at
        .is_none_or(|completed_at| completed_at < claim_until)
    {
        return Err(format!(
            "peer completed before the stale owner's lease expired: leased={leased:?}, completed={completed:?}"
        ));
    }

    harness.expect_non_info_code(owner, "record_timer.worker.iteration_failed", 1)?;
    harness.release_checkpoint(owner)?;
    let resumed = harness.resume_replica(owner)?;
    if resumed != owner_identity {
        return Err("resumed process did not match the stale checkpoint owner".to_owned());
    }
    harness
        .wait_for_log_code(
            owner,
            "record_timer.worker.iteration_failed",
            Duration::from_secs(5),
        )
        .await?;
    assert_settled_after_delay(harness, &record_id, &completed).await
}

async fn stale_technical_failure_settlement_is_fenced(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.enable_outcome_checkpoint(NativeOutcomeSettlementKind::TechnicalFailure, 2_000)?;
    harness.start_replicas(2).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(2);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    assert_armed(&armed, due_at)?;

    let (owner, owner_identity) = harness
        .wait_for_one_checkpoint(armed.occurrence_id, Duration::from_secs(10))
        .await?;
    let owner_claim = harness.timer_evidence(&record_id).await?;
    assert_business_unchanged(&armed, &owner_claim, "technical owner rollback")?;
    if !harness
        .timer_attempt_evidence(armed.occurrence_id)
        .await?
        .is_empty()
    {
        return Err("technical owner recorded an attempt before settlement".to_owned());
    }
    let suspended_owner = harness.suspend_replica(owner)?;
    if suspended_owner != owner_identity {
        return Err("suspended technical owner did not match its outcome marker".to_owned());
    }

    let (peer, peer_identity) = harness
        .wait_for_checkpoint_except(armed.occurrence_id, owner, Duration::from_secs(10))
        .await?;
    let peer_claim = harness.timer_evidence(&record_id).await?;
    assert_business_unchanged(&armed, &peer_claim, "technical peer rollback")?;
    if peer_claim.claim_epoch <= owner_claim.claim_epoch {
        return Err(format!(
            "technical peer did not reclaim under a higher claim epoch: owner={owner_claim:?}, peer={peer_claim:?}"
        ));
    }
    if !harness
        .timer_attempt_evidence(armed.occurrence_id)
        .await?
        .is_empty()
    {
        return Err("technical peer recorded an attempt before settlement release".to_owned());
    }

    harness.expect_non_info_code(peer, "record_timer.worker.iteration_failed", 1)?;
    harness.release_checkpoint(peer)?;
    let (settled, attempts) = wait_for_first_technical_settlement(
        harness,
        &record_id,
        armed.occurrence_id,
        Duration::from_secs(5),
    )
    .await?;
    harness
        .wait_for_log_code(
            peer,
            "record_timer.worker.iteration_failed",
            Duration::from_secs(5),
        )
        .await?;
    let suspended_peer = harness.suspend_replica(peer)?;
    if suspended_peer != peer_identity {
        return Err("suspended technical peer did not match its outcome marker".to_owned());
    }
    if settled.claim_epoch != peer_claim.claim_epoch
        || settled.retry_at.is_none()
        || attempts.len() != 1
        || attempts[0].attempt_number != 1
        || attempts[0].claim_epoch != peer_claim.claim_epoch
        || attempts[0].block_kind.as_deref() != Some("technical")
        || attempts[0].technical_code.as_deref() != Some("runtime-unavailable")
        || attempts[0].outcome_code.is_some()
        || attempts[0].receipt_correlation.is_some()
    {
        return Err(format!(
            "technical peer did not retain one exact retry settlement: peer={peer_claim:?}, settled={settled:?}, attempts={attempts:?}"
        ));
    }

    harness.expect_non_info_code(owner, "record_timer.worker.iteration_failed", 1)?;
    harness.release_checkpoint(owner)?;
    let resumed_owner = harness.resume_replica(owner)?;
    if resumed_owner != owner_identity {
        return Err("resumed technical owner did not match its stale marker".to_owned());
    }
    harness
        .wait_for_log_code(
            owner,
            "record_timer.worker.iteration_failed",
            Duration::from_secs(5),
        )
        .await?;
    let after_stale = harness.timer_evidence(&record_id).await?;
    let after_attempts = harness.timer_attempt_evidence(armed.occurrence_id).await?;
    if after_stale != settled || after_attempts != attempts {
        return Err(format!(
            "stale technical settlement changed the peer outcome: settled={settled:?}, after={after_stale:?}, attempts={attempts:?}, after_attempts={after_attempts:?}"
        ));
    }
    Ok(())
}

async fn stale_business_refusal_settlement_is_fenced(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.enable_outcome_checkpoint(NativeOutcomeSettlementKind::DeclaredRefusal, 2_000)?;
    harness.start_replicas(2).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(2);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    assert_armed(&armed, due_at)?;

    let (owner, owner_identity) = harness
        .wait_for_one_checkpoint(armed.occurrence_id, Duration::from_secs(10))
        .await?;
    let owner_claim = harness.timer_evidence(&record_id).await?;
    assert_business_unchanged(&armed, &owner_claim, "declared-refusal owner rollback")?;
    if !harness
        .timer_attempt_evidence(armed.occurrence_id)
        .await?
        .is_empty()
    {
        return Err("declared-refusal owner recorded an attempt before settlement".to_owned());
    }
    let suspended_owner = harness.suspend_replica(owner)?;
    if suspended_owner != owner_identity {
        return Err("suspended refusal owner did not match its outcome marker".to_owned());
    }

    let writer = if owner == 0 { 1 } else { 0 };
    let writer_client = harness.client(writer)?;
    let patch = harness.patch_binding(&writer_client).await?;
    let current = harness.get_service(&writer_client, &record_id).await?;
    let approved = NativeTimerHarness::set_approved(&writer_client, &patch, &current, true).await?;
    if approved.value.data.domain_data.get("approved") != Some(&serde_json::json!(true)) {
        return Err("ordinary approval patch did not expose the approved guard".to_owned());
    }
    let after_patch = harness.timer_evidence(&record_id).await?;
    if after_patch.occurrence_id != armed.occurrence_id
        || after_patch.binding_incarnation != armed.binding_incarnation
        || after_patch.material_signature != armed.material_signature
        || after_patch.executed_attempt_count != 0
        || after_patch.status != "scheduled"
    {
        return Err(format!(
            "ordinary guard patch rearmed or attempted the timer: armed={armed:?}, after_patch={after_patch:?}"
        ));
    }

    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(10))
        .await?;
    assert_one_completion(&after_patch, &completed, due_at)?;
    if completed.claim_epoch <= owner_claim.claim_epoch {
        return Err(format!(
            "declared-refusal peer did not complete under a higher claim epoch: owner={owner_claim:?}, completed={completed:?}"
        ));
    }
    let attempts = harness.timer_attempt_evidence(armed.occurrence_id).await?;
    if attempts.len() != 1
        || attempts[0].attempt_number != 1
        || attempts[0].claim_epoch != completed.claim_epoch
        || attempts[0].outcome_code.as_deref() != Some("completed")
        || attempts[0].technical_code.is_some()
        || attempts[0].receipt_correlation != completed.receipt_correlation
    {
        return Err(format!(
            "declared-refusal peer did not retain one exact completion attempt: completed={completed:?}, attempts={attempts:?}"
        ));
    }

    harness.expect_non_info_code(owner, "record_timer.worker.iteration_failed", 1)?;
    harness.release_checkpoint(owner)?;
    let resumed_owner = harness.resume_replica(owner)?;
    if resumed_owner != owner_identity {
        return Err("resumed refusal owner did not match its stale marker".to_owned());
    }
    harness
        .wait_for_log_code(
            owner,
            "record_timer.worker.iteration_failed",
            Duration::from_secs(5),
        )
        .await?;
    let after_stale = harness.timer_evidence(&record_id).await?;
    let after_attempts = harness.timer_attempt_evidence(armed.occurrence_id).await?;
    if after_stale != completed || after_attempts != attempts {
        return Err(format!(
            "stale business refusal changed the peer outcome: completed={completed:?}, after={after_stale:?}, attempts={attempts:?}, after_attempts={after_attempts:?}"
        ));
    }

    harness.crash_all_replicas()?;
    harness.disable_outcome_checkpoint();
    harness.start_replicas(1).await?;
    harness
        .wait_for_timer_worker_first_success(&[2], Duration::from_secs(5))
        .await?;
    let restarted = harness.timer_evidence(&record_id).await?;
    if restarted != completed {
        return Err(format!(
            "completed refusal recovery changed after restart: completed={completed:?}, restarted={restarted:?}"
        ));
    }
    Ok(())
}

async fn wait_for_first_technical_settlement(
    harness: &NativeTimerHarness,
    record_id: &str,
    occurrence_id: uuid::Uuid,
    timeout: Duration,
) -> Result<
    (
        TimerEvidence,
        Vec<record_timer_native::TimerAttemptEvidence>,
    ),
    String,
> {
    tokio::time::timeout(timeout, async {
        loop {
            let evidence = harness.timer_evidence(record_id).await?;
            let attempts = harness.timer_attempt_evidence(occurrence_id).await?;
            if evidence.state == "pending"
                && evidence.executed_attempt_count == 1
                && evidence.retry_at.is_some()
                && attempts.len() == 1
            {
                return Ok((evidence, attempts));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| "technical peer did not settle one retry before the bound".to_owned())?
}

async fn database_session_loss_recovery(harness: &mut NativeTimerHarness) -> Result<(), String> {
    let (record_id, armed, due_at, owner, _) =
        prepare_fault_journey(harness, NativeTimerCheckpoint::BeforeCommit).await?;
    let staged = harness.timer_evidence(&record_id).await?;
    if staged.state != "leased"
        || staged.status != "scheduled"
        || staged.revision != armed.revision
        || staged.revisions != armed.revisions
        || staged.outbox_entries != armed.outbox_entries
        || staged.action_receipts != armed.action_receipts
    {
        return Err(format!(
            "database-disconnect checkpoint exposed a partial business effect: armed={armed:?}, staged={staged:?}"
        ));
    }
    let disconnected_owner = staged
        .claim_owner_id
        .ok_or_else(|| "leased timer omitted claim owner".to_owned())?;
    let terminated = harness.terminate_replica_database_sessions(owner).await?;
    if terminated == 0 {
        return Err("target replica had no PostgreSQL session to terminate".to_owned());
    }
    harness.expect_non_info_code(owner, "record_timer.worker.iteration_failed", 1)?;
    harness.expect_non_info_code_range(owner, "hook.worker.iteration_failed", 0, 1)?;
    harness.release_checkpoint(owner)?;
    harness.release_checkpoints_except(owner)?;
    harness
        .wait_for_log_code(
            owner,
            "record_timer.worker.iteration_failed",
            Duration::from_secs(5),
        )
        .await?;
    let suspended = harness.suspend_replica(owner)?;
    let recovery = harness.timer_evidence(&record_id).await?;
    assert_business_unchanged(&armed, &recovery, "database-disconnect recovery")?;
    let recovery_not_before = match recovery.state.as_str() {
        "leased" => recovery
            .claim_until
            .ok_or_else(|| "retained database-disconnect lease omitted expiry".to_owned())?,
        "pending" => recovery
            .retry_at
            .ok_or_else(|| "released database-disconnect recovery omitted retryAt".to_owned())?,
        state => {
            return Err(format!(
                "database-disconnect failure produced unsupported recovery state {state}: {recovery:?}"
            ));
        }
    };
    assert_no_change_before_database_instant(
        harness,
        &record_id,
        &recovery,
        recovery_not_before,
        "database-disconnect recovery",
    )
    .await?;
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(10))
        .await?;
    assert_one_completion(&armed, &completed, due_at)?;
    if completed
        .completed_at
        .is_none_or(|completed_at| completed_at < recovery_not_before)
    {
        return Err(format!(
            "timer completed before peer recovery was eligible after transaction loss: recovery={recovery:?}, completed={completed:?}"
        ));
    }
    let attempts = harness.timer_attempt_evidence(armed.occurrence_id).await?;
    let terminal = attempts
        .last()
        .ok_or_else(|| "database-disconnect recovery recorded no durable attempt".to_owned())?;
    if terminal.claim_owner_id == disconnected_owner {
        return Err(format!(
            "database-disconnect recovery completed under the disconnected claim owner: disconnected_owner={disconnected_owner}, attempts={attempts:?}"
        ));
    }
    let resumed = harness.resume_replica(owner)?;
    if resumed != suspended {
        return Err("resumed process did not match the disconnected checkpoint owner".to_owned());
    }
    assert_settled_after_delay(harness, &record_id, &completed).await
}

/// This isolates the durable control-row fence with fixture-admin SQL. It is
/// not evidence for the protected operator command, its authority, or audit.
async fn fixture_pause_resume_fences_claim(harness: &mut NativeTimerHarness) -> Result<(), String> {
    let (record_id, armed, due_at, owner, _) =
        prepare_fault_journey(harness, NativeTimerCheckpoint::AfterClaim).await?;
    let leased = assert_durable_lease(harness, &record_id, &armed).await?;
    let paused_epoch = harness.set_scheduler_paused(true).await?;
    harness.expect_non_info_code(owner, "record_timer.worker.iteration_failed", 1)?;
    harness.release_checkpoint(owner)?;
    harness.release_checkpoints_except(owner)?;
    harness
        .wait_for_log_code(
            owner,
            "record_timer.worker.iteration_failed",
            Duration::from_secs(5),
        )
        .await?;
    let paused_recovery = harness.timer_evidence(&record_id).await?;
    assert_business_unchanged(&armed, &paused_recovery, "pause fence")?;
    if paused_recovery.control_state != "paused" {
        return Err(format!(
            "fixture pause was not visible in durable control state: {paused_recovery:?}"
        ));
    }

    let claim_until = leased
        .claim_until
        .ok_or_else(|| "leased timer omitted claim expiry".to_owned())?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if harness.database_now().await? > claim_until {
                return Ok::<(), String>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| "database clock did not pass the paused claim expiry".to_owned())??;
    let held = harness.timer_evidence(&record_id).await?;
    if held != paused_recovery {
        return Err(format!(
            "paused scheduler changed the fenced recovery after lease expiry: paused_recovery={paused_recovery:?}, held={held:?}"
        ));
    }

    let resumed_epoch = harness.set_scheduler_paused(false).await?;
    if resumed_epoch != paused_epoch + 1 {
        return Err(format!(
            "fixture pause/resume did not advance the control epoch exactly once: paused={paused_epoch}, resumed={resumed_epoch}"
        ));
    }
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(10))
        .await?;
    assert_one_completion(&armed, &completed, due_at)?;
    let attempts = harness.timer_attempt_evidence(armed.occurrence_id).await?;
    let terminal = attempts
        .last()
        .ok_or_else(|| "pause/resume recovery recorded no durable attempt".to_owned())?;
    if terminal.claim_epoch <= leased.claim_epoch || terminal.control_epoch != resumed_epoch {
        return Err(format!(
            "pause/resume recovery did not use a fresh claim under the resumed control epoch: leased={leased:?}, resumed_epoch={resumed_epoch}, attempts={attempts:?}"
        ));
    }
    assert_settled_after_delay(harness, &record_id, &completed).await
}

async fn prepare_fault_journey(
    harness: &mut NativeTimerHarness,
    checkpoint: NativeTimerCheckpoint,
) -> Result<
    (
        String,
        TimerEvidence,
        chrono::DateTime<chrono::Utc>,
        usize,
        NativeProcessIdentity,
    ),
    String,
> {
    harness.enable_checkpoint(checkpoint, Some(2_000))?;
    harness.start_replicas(2).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(2);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    assert_armed(&armed, due_at)?;
    let (owner, identity) = harness
        .wait_for_one_checkpoint(armed.occurrence_id, Duration::from_secs(10))
        .await?;
    println!(
        "record-timer-native checkpoint={checkpoint:?} occurrence_id={} owner={}:{}",
        armed.occurrence_id, identity.launch_id, identity.pid
    );
    Ok((record_id, armed, due_at, owner, identity))
}

async fn assert_durable_lease(
    harness: &NativeTimerHarness,
    record_id: &str,
    armed: &TimerEvidence,
) -> Result<TimerEvidence, String> {
    let leased = harness.timer_evidence(record_id).await?;
    let database_now = harness.database_now().await?;
    if leased.state != "leased"
        || leased.status != "scheduled"
        || leased.revision != armed.revision
        || leased.revisions != armed.revisions
        || leased.outbox_entries != armed.outbox_entries
        || leased.action_receipts != armed.action_receipts
        || leased.executed_attempt_count != armed.executed_attempt_count
        || leased.retry_allowance != armed.retry_allowance
        || leased.claim_owner_id.is_none()
        || leased.claim_epoch != armed.claim_epoch + 1
        || leased.claim_token.is_none()
        || leased.claim_until.is_none_or(|until| until <= database_now)
        || leased.claimed_control_epoch != Some(leased.control_epoch)
        || leased.claimed_instance_epoch != Some(leased.bound_instance_epoch)
        || leased.claimed_activation_id.is_none()
    {
        return Err(format!(
            "checkpoint did not expose one durable unexpired lease without an effect: armed={armed:?}, leased={leased:?}, database_now={database_now}"
        ));
    }
    Ok(leased)
}

async fn assert_no_effect_before_lease_expiry(
    harness: &NativeTimerHarness,
    record_id: &str,
    leased: &TimerEvidence,
) -> Result<(), String> {
    let claim_until = leased
        .claim_until
        .ok_or_else(|| "leased timer omitted claim expiry".to_owned())?;
    let database_now = harness.database_now().await?;
    if database_now + chrono::Duration::milliseconds(100) >= claim_until {
        return Err(format!(
            "fault fixture reached the lease boundary before the pre-expiry assertion: database_now={database_now}, claim_until={claim_until}"
        ));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let before_expiry = harness.timer_evidence(record_id).await?;
    if before_expiry != *leased {
        return Err(format!(
            "peer changed timer state before lease expiry: leased={leased:?}, before_expiry={before_expiry:?}"
        ));
    }
    Ok(())
}

async fn writer_first_race(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_before_claim_barrier()?;
    harness.enable_metrics_for_new_replicas()?;
    harness.enable_mutation_checkpoint_for_new_replicas();
    harness.start_replicas(1).await?;
    harness.disable_mutation_checkpoint_for_new_replicas();
    harness.start_replicas(1).await?;

    // Replica zero owns the writer checkpoint, so use the uninstrumented
    // replica for fixture setup and only route the raced patch through zero.
    let setup_client = harness.client(1)?;
    let writer_client = harness.checkpoint_race_client(0)?;
    let create = harness.create_binding(&setup_client).await?;
    let patch = harness.patch_binding(&writer_client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(4);
    let created = harness
        .create_scheduled_service(&setup_client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    let fetched = harness.get_service(&setup_client, &record_id).await?;
    let replacement_due_at = due_at + chrono::Duration::seconds(60);
    let writer = tokio::spawn(async move {
        NativeTimerHarness::reschedule_activation(
            &writer_client,
            &patch,
            &fetched,
            replacement_due_at,
        )
        .await
    });

    let writer_process = harness
        .wait_for_mutation_checkpoint(0, "patch", Duration::from_secs(5))
        .await?;
    let observers = harness
        .wait_before_claim_observed(armed.occurrence_id, Duration::from_secs(10))
        .await?;
    report_contention(armed.occurrence_id, &observers);
    release_claim_barriers_and_require_progress(harness).await?;
    let skipped = harness.timer_evidence(&record_id).await?;
    if skipped != armed {
        return Err(format!(
            "writer-first claim did not skip the writer-locked ledger row without effect: armed={armed:?}, skipped={skipped:?}"
        ));
    }

    harness.release_mutation_checkpoint(0)?;
    let patched = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .map_err(|_| "writer-first Record patch did not finish after release".to_owned())?
        .map_err(|error| format!("writer-first Record patch task failed: {error}"))??;
    if patched.value.data.domain_data.get("status") != Some(&serde_json::json!("scheduled")) {
        return Err("writer-first Record patch changed the business status".to_owned());
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    let current = harness.timer_evidence(&record_id).await?;
    if current.occurrence_id == armed.occurrence_id
        || current.state != "pending"
        || current.status != "scheduled"
        || current.due_at != replacement_due_at
        || current.executed_attempt_count != 0
        || current.revision != armed.revision + 1
    {
        return Err(format!(
            "writer-first reschedule did not win with one fresh pending occurrence: armed={armed:?}, current={current:?}"
        ));
    }
    let predecessor = harness
        .timer_generation_evidence(armed.occurrence_id)
        .await?;
    if predecessor.state != "superseded"
        || predecessor.outcome_code.as_deref() != Some("superseded")
        || predecessor.executed_attempt_count != 0
        || predecessor.is_current
    {
        return Err(format!(
            "writer-first predecessor did not close without execution: {predecessor:?}"
        ));
    }
    println!(
        "record-timer-native writer-first occurrence_id={} writer_pid={}",
        armed.occurrence_id, writer_process.pid
    );
    Ok(())
}

async fn writer_first_lifecycle(
    harness: &mut NativeTimerHarness,
    mutation: LifecycleMutation,
) -> Result<(), String> {
    harness.enable_before_claim_barrier()?;
    harness.enable_metrics_for_new_replicas()?;
    harness.enable_mutation_checkpoint_for_new_replicas();
    harness.start_replicas(1).await?;
    harness.disable_mutation_checkpoint_for_new_replicas();
    harness.start_replicas(1).await?;

    let setup_client = harness.client(1)?;
    let writer_client = harness.checkpoint_race_client(0)?;
    let create = harness.create_binding(&setup_client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(4);
    let created = harness
        .create_scheduled_service(&setup_client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    let stale = harness.get_service(&writer_client, &record_id).await?;
    let operation = match mutation {
        LifecycleMutation::Hold | LifecycleMutation::ClearDate => "patch",
        LifecycleMutation::Tombstone => "tombstone",
    };
    let writer = match mutation {
        LifecycleMutation::Hold => {
            let binding = harness.patch_binding(&writer_client).await?;
            tokio::spawn(async move {
                NativeTimerHarness::set_paused(&writer_client, &binding, &stale, true)
                    .await
                    .map(|_| ())
            })
        }
        LifecycleMutation::ClearDate => {
            let binding = harness.patch_binding(&writer_client).await?;
            tokio::spawn(async move {
                NativeTimerHarness::clear_activation(&writer_client, &binding, &stale)
                    .await
                    .map(|_| ())
            })
        }
        LifecycleMutation::Tombstone => {
            let binding = harness.tombstone_binding(&writer_client).await?;
            tokio::spawn(async move {
                NativeTimerHarness::tombstone_service(&writer_client, &binding, &stale)
                    .await
                    .map(|_| ())
            })
        }
    };

    let writer_process = harness
        .wait_for_mutation_checkpoint(0, operation, Duration::from_secs(5))
        .await?;
    let observers = harness
        .wait_before_claim_observed(armed.occurrence_id, Duration::from_secs(10))
        .await?;
    report_contention(armed.occurrence_id, &observers);
    release_claim_barriers_and_require_progress(harness).await?;
    let skipped = harness.timer_evidence(&record_id).await?;
    if skipped != armed {
        return Err(format!(
            "writer-first {mutation:?} claim changed the writer-locked occurrence: armed={armed:?}, skipped={skipped:?}"
        ));
    }

    harness.release_mutation_checkpoint(0)?;
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .map_err(|_| format!("writer-first {mutation:?} did not finish after release"))?
        .map_err(|error| format!("writer-first {mutation:?} task failed: {error}"))??;
    let current = harness.timer_evidence(&record_id).await?;
    if current.occurrence_id != armed.occurrence_id
        || current.status != "scheduled"
        || current.revision != armed.revision + 1
        || current.revisions != armed.revisions + 1
        || current.executed_attempt_count != 0
        || current.action_receipts != armed.action_receipts
    {
        return Err(format!(
            "writer-first {mutation:?} did not preserve the expected business boundary: armed={armed:?}, current={current:?}"
        ));
    }
    match mutation {
        LifecycleMutation::Hold => {
            if current.state != "pending"
                || current.gate_open
                || current.outcome_code.is_some()
                || current.outbox_entries != armed.outbox_entries
            {
                return Err(format!(
                    "writer-first predicate hold did not retain one held occurrence: {current:?}"
                ));
            }
        }
        LifecycleMutation::ClearDate => {
            if current.state != "cancelled"
                || current.outcome_code.as_deref() != Some("control-cleared")
                || current.outbox_entries != armed.outbox_entries
            {
                return Err(format!(
                    "writer-first clear-date did not cancel without timer effect: {current:?}"
                ));
            }
        }
        LifecycleMutation::Tombstone => {
            if current.state != "cancelled"
                || current.outcome_code.as_deref() != Some("anchor-tombstoned")
                || harness.record_lifecycle(&record_id).await? != "tombstoned"
            {
                return Err(format!(
                    "writer-first Tombstone did not close the exact anchor occurrence: {current:?}"
                ));
            }
        }
    }
    println!(
        "record-timer-native writer-first lifecycle={mutation:?} occurrence_id={} writer_pid={}",
        armed.occurrence_id, writer_process.pid
    );
    Ok(())
}

async fn predicate_release(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_before_claim_barrier()?;
    harness.enable_mutation_checkpoint_for_new_replicas();
    harness.start_replicas(1).await?;
    harness.disable_mutation_checkpoint_for_new_replicas();
    harness.start_replicas(1).await?;

    let setup_client = harness.client(1)?;
    let writer_client = harness.client(0)?;
    let create = harness.create_binding(&setup_client).await?;
    let setup_patch = harness.patch_binding(&setup_client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(4);
    let created = harness
        .create_scheduled_service(&setup_client, &create, due_at)
        .await?;
    let held = NativeTimerHarness::set_paused(&setup_client, &setup_patch, &created, true).await?;
    let record_id = held.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    if armed.state != "pending" || armed.gate_open || armed.executed_attempt_count != 0 {
        return Err(format!("predicate release fixture was not held: {armed:?}"));
    }

    let writer_patch = harness.patch_binding(&writer_client).await?;
    let writer = tokio::spawn(async move {
        NativeTimerHarness::set_paused(&writer_client, &writer_patch, &held, false).await
    });
    let writer_process = harness
        .wait_for_mutation_checkpoint(0, "patch", Duration::from_secs(5))
        .await?;
    wait_until_database_instant(harness, due_at, Duration::from_secs(8)).await?;
    let still_held = harness.timer_evidence(&record_id).await?;
    if still_held != armed {
        return Err(format!(
            "staged predicate release became visible before commit: armed={armed:?}, observed={still_held:?}"
        ));
    }

    harness.release_mutation_checkpoint(0)?;
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .map_err(|_| "predicate release patch did not finish".to_owned())?
        .map_err(|error| format!("predicate release task failed: {error}"))??;
    let observers = harness
        .wait_before_claim_observed(armed.occurrence_id, Duration::from_secs(10))
        .await?;
    report_contention(armed.occurrence_id, &observers);
    harness.release_before_claim_barriers()?;
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(8))
        .await?;
    if completed.occurrence_id != armed.occurrence_id
        || completed.state != "completed"
        || completed.status != "active"
        || completed.executed_attempt_count != 1
    {
        return Err(format!(
            "predicate release did not execute the same occurrence once: armed={armed:?}, completed={completed:?}"
        ));
    }
    println!(
        "record-timer-native predicate-release occurrence_id={} writer_pid={}",
        armed.occurrence_id, writer_process.pid
    );
    Ok(())
}

#[cfg(feature = "tooling")]
async fn reviewed_successor_releases_cached_predicate(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    let predecessor_client = harness.client(0)?;
    let create = harness.create_binding(&predecessor_client).await?;
    let patch = harness.patch_binding(&predecessor_client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(20);
    let created = harness
        .create_scheduled_service(&predecessor_client, &create, due_at)
        .await?;
    let held = NativeTimerHarness::set_paused(&predecessor_client, &patch, &created, true).await?;
    let record_id = held.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    if armed.state != "pending"
        || armed.status != "scheduled"
        || armed.gate_open
        || armed.executed_attempt_count != 0
        || armed.outcome_code.is_some()
        || armed.block_kind.is_some()
    {
        return Err(format!(
            "reviewed-successor fixture did not cache one false predicate: {armed:?}"
        ));
    }

    let activation = harness.activate_reviewed_predicate_successor().await?;
    if activation.predecessor_package_digest == activation.successor_package_digest
        || activation.predecessor_activation_id == activation.successor_activation_id
    {
        return Err(format!(
            "reviewed successor did not change both governed identities: {activation:?}"
        ));
    }
    let predecessor_process = harness
        .wait_replica_unready(0, Duration::from_secs(5))
        .await?;
    harness.expect_non_info_code_range(0, "record_timer.worker.iteration_failed", 0, 6)?;
    harness.expect_non_info_code_range(0, "hook.claim.identity_refused", 0, 6)?;
    harness.expect_non_info_code_range(0, "hook.worker.iteration_failed", 0, 6)?;
    harness.expect_non_info_code_range(0, "review.worker.iteration_failed", 0, 2)?;
    let after_apply = harness.timer_evidence(&record_id).await?;
    assert_business_unchanged(&armed, &after_apply, "governed successor apply")?;
    if after_apply.state != "pending"
        || after_apply.gate_open
        || after_apply.executed_attempt_count != 0
        || after_apply.outcome_code.is_some()
    {
        return Err(format!(
            "package apply executed or released cached work before successor restart: armed={armed:?}, after_apply={after_apply:?}"
        ));
    }

    harness.crash_all_replicas()?;
    harness.start_replicas(1).await?;
    let refreshed = wait_for_successor_refresh(
        harness,
        &record_id,
        armed.occurrence_id,
        &activation.successor_activation_id,
        Duration::from_secs(10),
    )
    .await?;
    if refreshed.revision != armed.revision
        || refreshed.revisions != armed.revisions
        || refreshed.outbox_entries != armed.outbox_entries
        || refreshed.action_receipts != armed.action_receipts
        || refreshed.executed_attempt_count != 0
        || refreshed.material_signature != armed.material_signature
        || refreshed.definition_revision == armed.definition_revision
    {
        return Err(format!(
            "successor refresh changed business state or material identity, attempted the Action, or retained predecessor policy: armed={armed:?}, refreshed={refreshed:?}"
        ));
    }

    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(25))
        .await?;
    assert_one_completion(&armed, &completed, due_at)?;
    if completed.executed_attempt_count != 1
        || completed.executed_activation_id
            != Some(
                uuid::Uuid::parse_str(&activation.successor_activation_id)
                    .map_err(|_| "successor activation id was not a UUID".to_owned())?,
            )
    {
        return Err(format!(
            "successor execution did not bind one attempt to the reviewed activation: {completed:?}"
        ));
    }
    let attempts = harness.timer_attempt_evidence(armed.occurrence_id).await?;
    if attempts.len() != 1
        || attempts[0].attempt_number != 1
        || attempts[0].outcome_code.as_deref() != Some("completed")
        || attempts[0].technical_code.is_some()
        || attempts[0].receipt_correlation != completed.receipt_correlation
    {
        return Err(format!(
            "successor refresh introduced an extra or unbound Action attempt: {attempts:?}"
        ));
    }

    harness.crash_all_replicas()?;
    harness.start_replicas(1).await?;
    harness
        .wait_for_timer_worker_first_success(&[2], Duration::from_secs(5))
        .await?;
    assert_settled(harness, &record_id, &completed).await?;
    println!(
        "record-timer-native reviewed-successor occurrence_id={} predecessor_package={} successor_package={} predecessor_activation={} successor_activation={} predecessor_pid={}",
        armed.occurrence_id,
        activation.predecessor_package_digest,
        activation.successor_package_digest,
        activation.predecessor_activation_id,
        activation.successor_activation_id,
        predecessor_process.pid
    );
    Ok(())
}

#[cfg(feature = "tooling")]
async fn wait_for_successor_refresh(
    harness: &NativeTimerHarness,
    record_id: &str,
    occurrence_id: uuid::Uuid,
    successor_activation_id: &str,
    timeout: Duration,
) -> Result<TimerEvidence, String> {
    let successor_activation_id = uuid::Uuid::parse_str(successor_activation_id)
        .map_err(|_| "successor activation id was not a UUID".to_owned())?;
    tokio::time::timeout(timeout, async {
        loop {
            let evidence = harness.timer_evidence(record_id).await?;
            if evidence.occurrence_id != occurrence_id {
                return Err(format!(
                    "reviewed successor replaced rather than refreshed the current occurrence: {evidence:?}"
                ));
            }
            if evidence.state != "pending"
                || evidence.executed_attempt_count != 0
                || evidence.outcome_code.is_some()
            {
                return Err(format!(
                    "reviewed successor executed before a zero-attempt refresh was observed: {evidence:?}"
                ));
            }
            if evidence.gate_open
                && evidence.current_policy_activation_id == Some(successor_activation_id)
            {
                return Ok(evidence);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "reviewed successor did not refresh the held occurrence".to_owned())?
}

async fn timer_first_lifecycle(
    harness: &mut NativeTimerHarness,
    mutation: LifecycleMutation,
) -> Result<(), String> {
    harness.enable_checkpoint(NativeTimerCheckpoint::BeforeCommit, Some(2_000))?;
    harness.start_replicas(2).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(3);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    let (owner, _) = harness
        .wait_for_one_checkpoint(armed.occurrence_id, Duration::from_secs(10))
        .await?;
    let writer_replica = if owner == 0 { 1 } else { 0 };
    let writer_client = harness.client(writer_replica)?;
    let stale = harness.get_service(&writer_client, &record_id).await?;
    let writer = match mutation {
        LifecycleMutation::Hold => {
            let binding = harness.patch_binding(&writer_client).await?;
            tokio::spawn(async move {
                NativeTimerHarness::set_paused_expect_precondition_failure(
                    &writer_client,
                    &binding,
                    &stale,
                    true,
                )
                .await
            })
        }
        LifecycleMutation::ClearDate => {
            let binding = harness.patch_binding(&writer_client).await?;
            tokio::spawn(async move {
                NativeTimerHarness::clear_activation_expect_precondition_failure(
                    &writer_client,
                    &binding,
                    &stale,
                )
                .await
            })
        }
        LifecycleMutation::Tombstone => {
            let binding = harness.tombstone_binding(&writer_client).await?;
            tokio::spawn(async move {
                NativeTimerHarness::tombstone_service_expect_precondition_failure(
                    &writer_client,
                    &binding,
                    &stale,
                )
                .await
            })
        }
    };
    harness
        .wait_for_replica_database_lock_wait(writer_replica, Duration::from_secs(5))
        .await?;
    let staged = harness.timer_evidence(&record_id).await?;
    assert_business_unchanged(&armed, &staged, "timer-first lifecycle staged transaction")?;

    harness.release_checkpoint(owner)?;
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .map_err(|_| format!("timer-first {mutation:?} did not finish after release"))?
        .map_err(|error| format!("timer-first {mutation:?} task failed: {error}"))??;
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(5))
        .await?;
    assert_one_completion(&armed, &completed, due_at)?;
    let final_client = harness.client(writer_replica)?;
    let final_record = harness.get_service(&final_client, &record_id).await?;
    if final_record.value.data.domain_data.get("paused") != Some(&serde_json::json!(false))
        || !final_record
            .value
            .data
            .domain_data
            .contains_key("activatesAt")
        || harness.record_lifecycle(&record_id).await? != "active"
    {
        return Err(format!(
            "timer-first {mutation:?} exposed a stale writer effect: {:?}",
            final_record.value.data.domain_data
        ));
    }
    Ok(())
}

async fn wait_until_database_instant(
    harness: &NativeTimerHarness,
    instant: chrono::DateTime<chrono::Utc>,
    timeout: Duration,
) -> Result<(), String> {
    tokio::time::timeout(timeout, async {
        loop {
            if harness.database_now().await? >= instant {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| "database clock did not reach the lifecycle race instant".to_owned())?
}

async fn timer_first_race(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_checkpoint(NativeTimerCheckpoint::BeforeCommit, Some(2_000))?;
    harness.start_replicas(2).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(3);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    let (owner, _) = harness
        .wait_for_one_checkpoint(armed.occurrence_id, Duration::from_secs(10))
        .await?;
    let writer_replica = if owner == 0 { 1 } else { 0 };
    let writer_client = harness.client(writer_replica)?;
    let patch = harness.patch_binding(&writer_client).await?;
    let stale = harness.get_service(&writer_client, &record_id).await?;
    let writer = tokio::spawn(async move {
        NativeTimerHarness::replace_description_expect_precondition_failure(
            &writer_client,
            &patch,
            &stale,
            "timer-first stale writer canary",
        )
        .await
    });
    harness
        .wait_for_replica_database_lock_wait(writer_replica, Duration::from_secs(5))
        .await?;
    let staged = harness.timer_evidence(&record_id).await?;
    assert_business_unchanged(&armed, &staged, "timer-first staged transaction")?;

    harness.release_checkpoint(owner)?;
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .map_err(|_| "timer-first stale writer did not finish after release".to_owned())?
        .map_err(|error| format!("timer-first stale writer task failed: {error}"))??;
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(5))
        .await?;
    assert_one_completion(&armed, &completed, due_at)?;
    let final_client = harness.client(writer_replica)?;
    let final_record = harness.get_service(&final_client, &record_id).await?;
    if final_record.value.data.domain_data.get("description")
        != Some(&serde_json::json!("native future activation canary"))
    {
        return Err("timer-first stale writer exposed a partial description effect".to_owned());
    }
    Ok(())
}

async fn batch_writer_first(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_before_claim_barrier()?;
    harness.enable_metrics_for_new_replicas()?;
    harness.enable_mutation_checkpoint_for_new_replicas();
    harness.start_replicas(1).await?;
    harness.disable_mutation_checkpoint_for_new_replicas();
    harness.start_replicas(2).await?;

    let setup_client = harness.client(1)?;
    let writer_client = harness.checkpoint_race_client(0)?;
    let create = harness.create_binding(&setup_client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(6);
    let first = harness
        .create_scheduled_service(&setup_client, &create, due_at)
        .await?;
    let second = harness
        .create_scheduled_service(&setup_client, &create, due_at)
        .await?;
    let mut records = vec![first, second];
    records.sort_by(|left, right| {
        right
            .value
            .data
            .record_identifier
            .cmp(&left.value.data.record_identifier)
    });
    let armed = bulk_timer_evidence(harness, &records).await?;
    let binding = harness.batch_binding(&writer_client).await?;
    let replacement_due_at = due_at + chrono::Duration::seconds(60);
    let writer = tokio::spawn(async move {
        NativeTimerHarness::reschedule_batch_and_replay(
            writer_client,
            binding,
            records,
            replacement_due_at,
        )
        .await
    });

    let writer_process = harness
        .wait_for_mutation_checkpoint(0, "batch", Duration::from_secs(5))
        .await?;
    let occurrence_ids = armed
        .iter()
        .map(|(_, evidence)| evidence.occurrence_id)
        .collect::<BTreeSet<_>>();
    let observers = harness
        .wait_before_claim_observed_any(&occurrence_ids, Duration::from_secs(12))
        .await?;
    report_bulk_contention("batch-writer-first", &observers);
    release_claim_barriers_and_require_progress(harness).await?;
    assert_bulk_unchanged(harness, &armed, "writer-first Batch").await?;
    let staged_run = writer_process.pid;

    harness.release_mutation_checkpoint(0)?;
    let receipt = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .map_err(|_| "writer-first Batch did not finish after release".to_owned())?
        .map_err(|error| format!("writer-first Batch task failed: {error}"))??;
    if receipt.value.results().len() != 2 {
        return Err("writer-first Batch did not retain two result states".to_owned());
    }
    assert_bulk_successors(harness, &armed, replacement_due_at, "writer-first Batch").await?;
    println!("record-timer-native bulk=batch order=writer-first writer_pid={staged_run}");
    Ok(())
}

async fn batch_timer_first(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_checkpoint(NativeTimerCheckpoint::BeforeCommit, Some(5_000))?;
    harness.start_replicas(3).await?;
    let setup_client = harness.client(0)?;
    let create = harness.create_binding(&setup_client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(3);
    let due = harness
        .create_scheduled_service(&setup_client, &create, due_at)
        .await?;
    let future = harness
        .create_scheduled_service(
            &setup_client,
            &create,
            due_at + chrono::Duration::seconds(90),
        )
        .await?;
    let due_record_id = due.value.data.record_identifier.clone();
    let due_armed = harness.timer_evidence(&due_record_id).await?;
    let future_record_id = future.value.data.record_identifier.clone();
    let future_armed = harness.timer_evidence(&future_record_id).await?;
    let (owner, owner_process) = harness
        .wait_for_one_checkpoint(due_armed.occurrence_id, Duration::from_secs(10))
        .await?;
    let writer_replica = (owner + 1) % 3;
    let writer_client = harness.checkpoint_race_client(writer_replica)?;
    let stale_due = harness.get_service(&writer_client, &due_record_id).await?;
    let stale_future = harness
        .get_service(&writer_client, &future_record_id)
        .await?;
    let binding = harness.batch_binding(&writer_client).await?;
    let replacement_due_at = due_at + chrono::Duration::seconds(120);
    let writer = tokio::spawn(async move {
        NativeTimerHarness::reschedule_batch_expect_precondition_failure(
            writer_client,
            binding,
            vec![stale_future, stale_due],
            replacement_due_at,
        )
        .await
    });
    let blocking = harness
        .wait_for_replica_blocked_by(writer_replica, owner, Duration::from_secs(5))
        .await?;
    assert_business_unchanged(
        &due_armed,
        &harness.timer_evidence(&due_record_id).await?,
        "timer-first Batch staged transaction",
    )?;
    if harness.timer_evidence(&future_record_id).await? != future_armed {
        return Err("timer-first Batch changed its unaffected member before release".to_owned());
    }

    harness.release_checkpoint(owner)?;
    harness.release_checkpoints_except(owner)?;
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .map_err(|_| "timer-first Batch did not finish after release".to_owned())?
        .map_err(|error| format!("timer-first Batch task failed: {error}"))??;
    let completed = harness
        .wait_for_completion(&due_record_id, Duration::from_secs(5))
        .await?;
    assert_one_completion(&due_armed, &completed, due_at)?;
    assert_unaffected_bulk_member(
        &future_armed,
        &harness.timer_evidence(&future_record_id).await?,
        "timer-first stale Batch",
    )?;
    println!(
        "record-timer-native bulk=batch order=timer-first owner_pid={} blocked_backend={} blocker_backend={}",
        owner_process.pid, blocking.blocked_pid, blocking.blocker_pid
    );
    Ok(())
}

async fn ingestion_writer_first(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_before_claim_barrier()?;
    harness.enable_metrics_for_new_replicas()?;
    harness.enable_mutation_checkpoint_for_new_replicas();
    harness.start_replicas(1).await?;
    harness.disable_mutation_checkpoint_for_new_replicas();
    harness.start_replicas(2).await?;

    let setup_client = harness.client(1)?;
    let writer_client = harness.checkpoint_race_client(0)?;
    let create = harness.create_binding(&setup_client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(6);
    let first = harness
        .create_scheduled_service(&setup_client, &create, due_at)
        .await?;
    let second = harness
        .create_scheduled_service(&setup_client, &create, due_at)
        .await?;
    let mut records = vec![first, second];
    records.sort_by(|left, right| {
        right
            .value
            .data
            .record_identifier
            .cmp(&left.value.data.record_identifier)
    });
    let armed = bulk_timer_evidence(harness, &records).await?;
    let replacement_due_at = due_at + chrono::Duration::seconds(60);
    let patch = harness
        .prepare_reschedule_ingestion(&writer_client, &records, replacement_due_at)
        .await?;
    let run_id = patch.run_id();
    let mut writer = tokio::spawn(async move {
        NativeTimerHarness::submit_ingestion_and_replay(writer_client, patch).await
    });

    let writer_process = tokio::select! {
        checkpoint = harness.wait_for_mutation_checkpoint(
            0,
            "ingestion",
            Duration::from_secs(5),
        ) => checkpoint?,
        completed = &mut writer => {
            completed
                .map_err(|error| format!("writer-first ingestion task failed before checkpoint: {error}"))?
                .map_err(|error| format!("writer-first ingestion failed before checkpoint: {error}"))?;
            return Err("writer-first ingestion committed before its configured checkpoint".to_owned());
        }
    };
    let occurrence_ids = armed
        .iter()
        .map(|(_, evidence)| evidence.occurrence_id)
        .collect::<BTreeSet<_>>();
    let observers = harness
        .wait_before_claim_observed_any(&occurrence_ids, Duration::from_secs(12))
        .await?;
    report_bulk_contention("ingestion-writer-first", &observers);
    release_claim_barriers_and_require_progress(harness).await?;
    assert_bulk_unchanged(harness, &armed, "writer-first ingestion").await?;
    let staged = harness.ingestion_evidence(run_id).await?;
    if staged.status != "open"
        || staged.next_chunk_index != 0
        || staged.committed_items != 0
        || staged.chunk_receipts != 0
        || staged.linked_records != 0
    {
        return Err(format!(
            "writer-first ingestion exposed staged checkpoint or receipt state: {staged:?}"
        ));
    }

    harness.release_mutation_checkpoint(0)?;
    let submission = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .map_err(|_| "writer-first ingestion did not finish after release".to_owned())?
        .map_err(|error| format!("writer-first ingestion task failed: {error}"))??;
    if !submission.value.run().complete()
        || submission.value.run().next_chunk_index() != 1
        || submission.value.run().committed_items() != 2
        || submission.value.receipt().batch().results().len() != 2
    {
        return Err(format!(
            "writer-first ingestion returned the wrong terminal checkpoint: {:?}",
            submission.value
        ));
    }
    let committed = harness.ingestion_evidence(run_id).await?;
    if committed.status != "complete"
        || committed.next_chunk_index != 1
        || committed.committed_items != 2
        || committed.chunk_receipts != 1
        || committed.linked_records != 2
    {
        return Err(format!(
            "writer-first ingestion did not retain one exact chunk receipt: {committed:?}"
        ));
    }
    assert_bulk_successors(
        harness,
        &armed,
        replacement_due_at,
        "writer-first ingestion",
    )
    .await?;
    println!(
        "record-timer-native bulk=ingestion order=writer-first writer_pid={}",
        writer_process.pid
    );
    Ok(())
}

async fn ingestion_timer_first(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_checkpoint(NativeTimerCheckpoint::BeforeCommit, Some(5_000))?;
    harness.start_replicas(3).await?;
    let setup_client = harness.client(0)?;
    let create = harness.create_binding(&setup_client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(3);
    let due = harness
        .create_scheduled_service(&setup_client, &create, due_at)
        .await?;
    let future = harness
        .create_scheduled_service(
            &setup_client,
            &create,
            due_at + chrono::Duration::seconds(90),
        )
        .await?;
    let due_record_id = due.value.data.record_identifier.clone();
    let due_armed = harness.timer_evidence(&due_record_id).await?;
    let future_record_id = future.value.data.record_identifier.clone();
    let future_armed = harness.timer_evidence(&future_record_id).await?;
    let (owner, owner_process) = harness
        .wait_for_one_checkpoint(due_armed.occurrence_id, Duration::from_secs(10))
        .await?;
    let writer_replica = (owner + 1) % 3;
    let writer_client = harness.checkpoint_race_client(writer_replica)?;
    let stale_due = harness.get_service(&writer_client, &due_record_id).await?;
    let stale_future = harness
        .get_service(&writer_client, &future_record_id)
        .await?;
    let replacement_due_at = due_at + chrono::Duration::seconds(120);
    let patch = harness
        .prepare_reschedule_ingestion(
            &writer_client,
            &[stale_future, stale_due],
            replacement_due_at,
        )
        .await?;
    let run_id = patch.run_id();
    let writer = tokio::spawn(async move {
        NativeTimerHarness::submit_ingestion_expect_precondition_failure(writer_client, patch).await
    });
    let blocking = harness
        .wait_for_replica_blocked_by(writer_replica, owner, Duration::from_secs(5))
        .await?;
    assert_business_unchanged(
        &due_armed,
        &harness.timer_evidence(&due_record_id).await?,
        "timer-first ingestion staged transaction",
    )?;
    if harness.timer_evidence(&future_record_id).await? != future_armed {
        return Err(
            "timer-first ingestion changed its unaffected member before release".to_owned(),
        );
    }

    harness.release_checkpoint(owner)?;
    harness.release_checkpoints_except(owner)?;
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .map_err(|_| "timer-first ingestion did not finish after release".to_owned())?
        .map_err(|error| format!("timer-first ingestion task failed: {error}"))??;
    let completed = harness
        .wait_for_completion(&due_record_id, Duration::from_secs(5))
        .await?;
    assert_one_completion(&due_armed, &completed, due_at)?;
    assert_unaffected_bulk_member(
        &future_armed,
        &harness.timer_evidence(&future_record_id).await?,
        "timer-first stale ingestion",
    )?;
    let refused = harness.ingestion_evidence(run_id).await?;
    if refused.status != "open"
        || refused.next_chunk_index != 0
        || refused.committed_items != 0
        || refused.chunk_receipts != 0
        || refused.linked_records != 0
    {
        return Err(format!(
            "timer-first stale ingestion persisted a partial checkpoint or receipt: {refused:?}"
        ));
    }
    println!(
        "record-timer-native bulk=ingestion order=timer-first owner_pid={} blocked_backend={} blocker_backend={}",
        owner_process.pid, blocking.blocked_pid, blocking.blocker_pid
    );
    Ok(())
}

async fn bulk_timer_evidence(
    harness: &NativeTimerHarness,
    records: &[registry_breg_client::BRegComplete<
        registry_breg_client::RegistryRecordSingleResponse,
    >],
) -> Result<Vec<(String, TimerEvidence)>, String> {
    let mut evidence = Vec::with_capacity(records.len());
    for record in records {
        let record_id = record.value.data.record_identifier.clone();
        evidence.push((record_id.clone(), harness.timer_evidence(&record_id).await?));
    }
    Ok(evidence)
}

async fn assert_bulk_unchanged(
    harness: &NativeTimerHarness,
    armed: &[(String, TimerEvidence)],
    context: &str,
) -> Result<(), String> {
    for (record_id, expected) in armed {
        let observed = harness.timer_evidence(record_id).await?;
        if observed != *expected {
            return Err(format!(
                "{context} changed a writer-locked occurrence: expected={expected:?}, observed={observed:?}"
            ));
        }
    }
    Ok(())
}

async fn assert_bulk_successors(
    harness: &NativeTimerHarness,
    armed: &[(String, TimerEvidence)],
    replacement_due_at: chrono::DateTime<chrono::Utc>,
    context: &str,
) -> Result<(), String> {
    for (record_id, predecessor) in armed {
        let successor = harness.timer_evidence(record_id).await?;
        if successor.occurrence_id == predecessor.occurrence_id
            || successor.state != "pending"
            || successor.status != "scheduled"
            || successor.due_at != replacement_due_at
            || successor.executed_attempt_count != 0
            || successor.revision != predecessor.revision + 1
            || successor.revisions != predecessor.revisions + 1
            || successor.outbox_entries != predecessor.outbox_entries
            || successor.action_receipts != predecessor.action_receipts
        {
            return Err(format!(
                "{context} did not produce one clean future successor: predecessor={predecessor:?}, successor={successor:?}"
            ));
        }
        let closed = harness
            .timer_generation_evidence(predecessor.occurrence_id)
            .await?;
        if closed.state != "superseded"
            || closed.outcome_code.as_deref() != Some("superseded")
            || closed.executed_attempt_count != 0
            || closed.is_current
        {
            return Err(format!(
                "{context} did not permanently exclude its predecessor: {closed:?}"
            ));
        }
    }
    Ok(())
}

fn assert_unaffected_bulk_member(
    expected: &TimerEvidence,
    observed: &TimerEvidence,
    context: &str,
) -> Result<(), String> {
    if observed.occurrence_id != expected.occurrence_id
        || observed.state != expected.state
        || observed.status != expected.status
        || observed.revision != expected.revision
        || observed.revisions != expected.revisions
        || observed.outbox_entries != expected.outbox_entries
        || observed.due_at != expected.due_at
        || observed.not_after != expected.not_after
        || observed.material_signature != expected.material_signature
        || observed.gate_open != expected.gate_open
        || observed.executed_attempt_count != expected.executed_attempt_count
        || observed.claim_epoch != expected.claim_epoch
        || observed.completed_at != expected.completed_at
    {
        return Err(format!(
            "{context} partially changed its unaffected member: expected={expected:?}, observed={observed:?}"
        ));
    }
    Ok(())
}

fn report_bulk_contention(label: &str, observations: &[(uuid::Uuid, NativeProcessIdentity)]) {
    let rendered = observations
        .iter()
        .map(|(occurrence_id, process)| {
            format!("{}:{}:{occurrence_id}", process.launch_id, process.pid)
        })
        .collect::<Vec<_>>();
    println!("record-timer-native bulk-contention label={label} observers={rendered:?}");
}

async fn release_claim_barriers_and_require_progress(
    harness: &NativeTimerHarness,
) -> Result<(), String> {
    let held_ages = harness
        .wait_for_timer_worker_age_at_least(Duration::from_millis(750), Duration::from_secs(5))
        .await?;
    harness.release_before_claim_barriers()?;
    harness
        .wait_for_timer_worker_progress_reset(&held_ages, Duration::from_secs(5))
        .await
}

async fn assert_no_change_before_database_instant(
    harness: &NativeTimerHarness,
    record_id: &str,
    expected: &TimerEvidence,
    not_before: chrono::DateTime<chrono::Utc>,
    context: &str,
) -> Result<(), String> {
    let database_now = harness.database_now().await?;
    if database_now + chrono::Duration::milliseconds(100) >= not_before {
        return Err(format!(
            "{context} fixture reached its recovery boundary before the early assertion: database_now={database_now}, not_before={not_before}"
        ));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let early = harness.timer_evidence(record_id).await?;
    if early != *expected {
        return Err(format!(
            "{context} changed before its durable recovery boundary: expected={expected:?}, early={early:?}"
        ));
    }
    Ok(())
}

fn assert_business_unchanged(
    armed: &TimerEvidence,
    observed: &TimerEvidence,
    context: &str,
) -> Result<(), String> {
    if observed.status != armed.status
        || observed.revision != armed.revision
        || observed.revisions != armed.revisions
        || observed.outbox_entries != armed.outbox_entries
        || observed.action_receipts != armed.action_receipts
        || observed.occurrence_id != armed.occurrence_id
        || observed.binding_incarnation != armed.binding_incarnation
        || observed.due_at != armed.due_at
    {
        return Err(format!(
            "{context} changed business state before recovery: armed={armed:?}, observed={observed:?}"
        ));
    }
    Ok(())
}

async fn assert_settled_after_delay(
    harness: &NativeTimerHarness,
    record_id: &str,
    completed: &TimerEvidence,
) -> Result<(), String> {
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_settled(harness, record_id, completed).await
}

async fn assert_settled(
    harness: &NativeTimerHarness,
    record_id: &str,
    completed: &TimerEvidence,
) -> Result<(), String> {
    let settled = harness.timer_evidence(record_id).await?;
    if &settled != completed {
        return Err(format!(
            "timer outcome changed after fault recovery: completed={completed:?}, settled={settled:?}"
        ));
    }
    Ok(())
}

fn assert_armed(
    armed: &TimerEvidence,
    due_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    if armed.state != "pending"
        || armed.status != "scheduled"
        || armed.revision != 1
        || armed.due_at != due_at
        || armed.completed_at.is_some()
        || !armed.gate_open
        || armed.executed_attempt_count != 0
        || armed.retry_allowance != 0
        || armed.claim_owner_id.is_some()
        || armed.claim_epoch != 0
        || armed.claim_token.is_some()
        || armed.outcome_code.is_some()
        || armed.block_kind.is_some()
    {
        return Err(format!(
            "future timer was not durably armed before its due instant: {armed:?}"
        ));
    }
    Ok(())
}

fn assert_one_completion(
    armed: &TimerEvidence,
    completed: &TimerEvidence,
    due_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    if completed.revision != armed.revision + 1
        || completed.state != "completed"
        || completed.revisions != armed.revisions + 1
        || completed.outbox_entries != armed.outbox_entries + 1
        || completed.action_receipts != armed.action_receipts + 1
        || completed.occurrence_id != armed.occurrence_id
        || completed.binding_incarnation != armed.binding_incarnation
        || completed.due_at != due_at
        || completed.outcome_code.as_deref() != Some("completed")
        || completed.block_kind.is_some()
        || completed.executed_attempt_count < 1
        || completed.retry_allowance != 0
        || completed.claim_owner_id.is_some()
        || completed.claim_token.is_some()
        || completed.claim_until.is_some()
        || completed.receipt_correlation.is_none()
        || completed.executed_activation_id.is_none()
        || completed
            .completed_at
            .is_none_or(|executed| executed < due_at)
    {
        return Err(format!(
            "native timer completion was not one atomic exact-once effect: armed={armed:?}, completed={completed:?}"
        ));
    }
    Ok(())
}

fn assert_unrelated_write_preserved_settlement(
    completed: &TimerEvidence,
    after_edit: &TimerEvidence,
) -> Result<(), String> {
    if after_edit.state != completed.state
        || after_edit.status != completed.status
        || after_edit.revision != completed.revision + 1
        || after_edit.revisions != completed.revisions + 1
        || after_edit.outbox_entries != completed.outbox_entries
        || after_edit.action_receipts != completed.action_receipts
        || after_edit.occurrence_id != completed.occurrence_id
        || after_edit.due_at != completed.due_at
        || after_edit.completed_at != completed.completed_at
        || after_edit.claim_until != completed.claim_until
    {
        return Err(format!(
            "unrelated Record write changed the completed timer outcome: completed={completed:?}, after_edit={after_edit:?}"
        ));
    }
    Ok(())
}

/// Reference-consumer assumption for this example: a service is effective
/// once the authoritative `activatesAt` instant is not later than the
/// authoritative database time. Materialized `status` is deliberately not an
/// input to this consumer decision.
fn reference_consumer_treats_intended_time_as_effective(
    record: &registry_breg_client::RegistryRecordSingleResponse,
    database_now: chrono::DateTime<chrono::Utc>,
) -> Result<bool, String> {
    intended_activation(record).map(|intended| intended <= database_now)
}

fn intended_activation(
    record: &registry_breg_client::RegistryRecordSingleResponse,
) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let intended = record
        .data
        .domain_data
        .get("activatesAt")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "public Record omitted the authoritative activatesAt value".to_owned())?;
    chrono::DateTime::parse_from_rfc3339(intended)
        .map(|value| value.with_timezone(&chrono::Utc))
        .map_err(|_| "public Record returned a noncanonical activatesAt value".to_owned())
}

async fn assert_settled_and_public(
    harness: &NativeTimerHarness,
    client: &registry_breg_client::BaseRegistryClient,
    record_id: &str,
    completed: &TimerEvidence,
) -> Result<(), String> {
    tokio::time::sleep(Duration::from_millis(500)).await;
    let settled = harness.timer_evidence(record_id).await?;
    if &settled != completed {
        return Err(format!(
            "settled native timer changed on a later scan: completed={completed:?}, settled={settled:?}"
        ));
    }
    let fetched = harness.get_service(client, record_id).await?;
    if fetched.value.data.domain_data.get("status") != Some(&serde_json::json!("active")) {
        return Err("Record API did not expose the activated status".to_owned());
    }
    Ok(())
}

fn assert_distinct_processes(
    processes: &[NativeProcessIdentity],
    expected: usize,
) -> Result<(), String> {
    let pids = processes
        .iter()
        .map(|process| process.pid)
        .collect::<BTreeSet<_>>();
    let instances = processes
        .iter()
        .map(|process| process.instance_id.as_str())
        .collect::<BTreeSet<_>>();
    let replicas = processes
        .iter()
        .map(|process| process.replica_id.as_str())
        .collect::<BTreeSet<_>>();
    let launches = processes
        .iter()
        .map(|process| process.launch_id.as_str())
        .collect::<BTreeSet<_>>();
    if processes.len() != expected
        || pids.len() != expected
        || replicas.len() != expected
        || launches.len() != expected
        || instances.len() != 1
    {
        return Err(format!(
            "native timer observer identities are not exact: expected_processes={expected}, expected_common_instance=1, processes={processes:?}"
        ));
    }
    Ok(())
}

fn assert_restart_processes(
    processes: &[NativeProcessIdentity],
    expected_launches: usize,
    expected_replica_slots: usize,
) -> Result<(), String> {
    let pids = processes
        .iter()
        .map(|process| process.pid)
        .collect::<BTreeSet<_>>();
    let instances = processes
        .iter()
        .map(|process| process.instance_id.as_str())
        .collect::<BTreeSet<_>>();
    let replicas = processes
        .iter()
        .map(|process| process.replica_id.as_str())
        .collect::<BTreeSet<_>>();
    let launches = processes
        .iter()
        .map(|process| process.launch_id.as_str())
        .collect::<BTreeSet<_>>();
    if processes.len() != expected_launches
        || pids.len() != expected_launches
        || launches.len() != expected_launches
        || replicas.len() != expected_replica_slots
        || instances.len() != 1
    {
        return Err(format!(
            "native timer replacement identities are not exact: launches={expected_launches}, replica_slots={expected_replica_slots}, expected_common_instance=1, processes={processes:?}"
        ));
    }
    Ok(())
}

fn report_identity(identity: &NativeRunIdentity) {
    println!(
        "record-timer-native package_id={} package_digest={}",
        identity.package_id, identity.package_digest
    );
    for process in &identity.processes {
        println!(
            "record-timer-native instance_id={} replica_id={} launch_id={} pid={} executable={} arguments={:?}",
            process.instance_id,
            process.replica_id,
            process.launch_id,
            process.pid,
            process.executable.display(),
            process.arguments
        );
    }
}

fn report_contention(occurrence_id: uuid::Uuid, processes: &[NativeProcessIdentity]) {
    let observers = processes
        .iter()
        .map(|process| format!("{}:{}", process.launch_id, process.pid))
        .collect::<Vec<_>>();
    println!(
        "record-timer-native contention occurrence_id={} observers={:?}",
        occurrence_id, observers
    );
}

async fn finish_result(harness: NativeTimerHarness, result: Result<(), String>) {
    let retained = harness.finish(result.is_ok()).await;
    match (result, retained) {
        (Ok(()), Ok(None)) => {}
        (Ok(()), Ok(Some(path))) => {
            panic!(
                "successful native timer journey unexpectedly retained {}",
                path.display()
            )
        }
        (Err(error), Ok(Some(path))) => {
            panic!(
                "{error}; bounded native-process logs retained at {}",
                path.display()
            )
        }
        (Err(error), Ok(None)) => panic!("{error}"),
        (result, Err(cleanup)) => panic!("native timer result {result:?}; {cleanup}"),
    }
}
