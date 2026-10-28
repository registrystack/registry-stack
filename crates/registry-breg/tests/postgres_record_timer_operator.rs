// SPDX-License-Identifier: Apache-2.0

//! Public operator-read acceptance over a native BReg process and real PostgreSQL.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
#[path = "support/record_timer_native.rs"]
#[allow(dead_code)]
mod record_timer_native;

use std::{collections::BTreeSet, os::unix::fs::PermissionsExt as _, path::Path, time::Duration};

use record_timer_native::{
    NativeOperatorConfig, NativeOutcomeSettlementKind, NativeRunIdentity, NativeTimerCheckpoint,
    NativeTimerHarness,
};
use registry_breg::instance_claim::{InstanceClaimError, InstanceClaimService};
use registry_breg::timer_operator::{
    TimerBlockKind, TimerControlRequest, TimerControlState, TimerListRequest,
    TimerOccurrenceDetail, TimerOccurrenceState, TimerOperatorError, TimerOperatorService,
    TimerOutcomeCode, TimerRetryRequest,
};
use serde::Serialize;
use uuid::Uuid;

const DESCRIPTION_CANARY: &str = "native future activation canary";
const JURISDICTION_CANARY: &str = "zone-a";
const OPERATOR_REFERENCE_CANARY: &str = "operator-reference-raw-canary";
const OPERATOR_REASON_CANARY: &str = "operator-reason-raw-canary";
const TIMER_OPERATOR_AUDIT_SCHEMA: &str = "breg-timer-operator-audit/v1";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_service_requires_absolute_config_and_the_verified_active_package() {
    let mut harness = NativeTimerHarness::start().await;
    let result = operator_admission(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_reads_pending_and_completed_occurrences_without_record_values() {
    let mut harness = NativeTimerHarness::start().await;
    let result = operator_reads(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_status_preserves_later_block_kinds_after_bounded_terminal_history() {
    let mut harness = NativeTimerHarness::start().await;
    let result = bounded_status_preserves_later_blocks(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_fixture_removed_binding_projects_blocked_retry_as_safe_false() {
    let mut harness = NativeTimerHarness::start().await;
    let result = removed_binding_projection(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_fixture_completed_revision_drift_is_not_unfinished_stale_backlog() {
    let mut harness = NativeTimerHarness::start().await;
    let result = completed_revision_drift_projection(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_fixture_activation_only_drift_keeps_current_technical_retry_eligible() {
    let mut harness = NativeTimerHarness::start().await;
    let result = activation_only_drift_projection(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_fixture_non_exhausted_technical_block_is_not_retry_eligible() {
    let mut harness = NativeTimerHarness::start().await;
    let result = non_exhausted_technical_block_projection(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_pause_resume_uses_shared_control_epoch_and_fences_native_workers() {
    let mut harness = NativeTimerHarness::start().await;
    let result = operator_pause_resume(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_pause_waits_for_inflight_timer_commit_before_epoch_change() {
    let mut harness = NativeTimerHarness::start().await;
    let result = operator_pause_interlock(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_retry_grants_one_technical_allowance_and_refuses_other_states() {
    let mut harness = NativeTimerHarness::start().await;
    let result = operator_retry(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_retry_after_actual_exhaustion_fails_again_and_preserves_history() {
    let mut harness = NativeTimerHarness::start().await;
    let result = operator_retry_after_actual_exhaustion(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_show_serializes_a_known_retained_technical_code() {
    let mut harness = NativeTimerHarness::start().await;
    let result = known_retained_technical_code(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_show_fails_closed_for_an_unknown_stored_technical_code() {
    let mut harness = NativeTimerHarness::start().await;
    let result = unknown_retained_technical_code(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn built_bregctl_executes_every_timer_operator_command_against_real_postgres() {
    let mut harness = NativeTimerHarness::start().await;
    let result = built_bregctl_operator_journey(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn instance_claim_adoption_fences_old_timer_lease_until_audited_resume() {
    let mut harness = NativeTimerHarness::start().await;
    let result = adoption_hold_fences_old_lease(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn instance_claim_adoption_rolls_back_for_an_unsupported_timer_protocol() {
    let mut harness = NativeTimerHarness::start().await;
    let result = unsupported_protocol_adoption_rolls_back(&mut harness).await;
    finish_result(harness, result).await;
}

async fn adoption_hold_fences_old_lease(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_checkpoint(NativeTimerCheckpoint::AfterClaim, Some(2_000))?;
    harness.start_replicas(2).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(2);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    let (owner, owner_identity) = harness
        .wait_for_one_checkpoint(armed.occurrence_id, Duration::from_secs(10))
        .await?;
    let leased = harness.timer_evidence(&record_id).await?;
    let old_owner = leased
        .claim_owner_id
        .ok_or_else(|| "adoption fixture omitted the durable claim owner".to_owned())?;
    let old_claim_until = leased
        .claim_until
        .ok_or_else(|| "adoption fixture omitted the durable claim expiry".to_owned())?;
    if leased.state != "leased"
        || leased.status != "scheduled"
        || leased.executed_attempt_count != 0
        || leased.claimed_control_epoch != Some(leased.control_epoch)
        || leased.claimed_instance_epoch != Some(leased.bound_instance_epoch)
    {
        return Err(format!(
            "adoption fixture did not expose one exact pre-adoption lease: {leased:?}"
        ));
    }

    let config = harness.operator_runtime_config_path(0)?;
    let audit_baseline = harness.operator_audit_entries(0)?.len();
    let claims = InstanceClaimService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("instance-claim service construction failed: {error}"))?;
    let adoption = claims
        .adopt()
        .await
        .map_err(|error| format!("instance-claim re-adoption failed: {error}"))?;
    if adoption.previous.as_ref().map(|claim| claim.epoch) != Some(leased.bound_instance_epoch)
        || adoption.current.epoch != leased.bound_instance_epoch + 1
        || adoption.previous.as_ref().map(|claim| &claim.identity)
            != Some(&adoption.current.identity)
    {
        return Err(format!(
            "instance re-adoption did not advance the same physical claim once: {adoption:?}"
        ));
    }
    // Each operator service owns one companion-audit writer. Close the claim
    // service before opening the timer operator on that same destination.
    drop(claims);

    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("post-adoption timer operator construction failed: {error}"))?;
    let held_status = service
        .status()
        .await
        .map_err(|error| format!("post-adoption timer status failed: {error}"))?;
    let held = harness.timer_evidence(&record_id).await?;
    if held.protocol_version != leased.protocol_version
        || held.control_state != "adoption-hold"
        || held.control_epoch != leased.control_epoch + 1
        || held.bound_instance_epoch != adoption.current.epoch
        || held_status.protocol_version
            != u32::try_from(leased.protocol_version)
                .map_err(|_| "pre-adoption protocol was not positive".to_owned())?
        || held_status.control_state != TimerControlState::AdoptionHold
        || held_status.control_epoch != held.control_epoch
        || held_status.instance_epoch != adoption.current.epoch
        || held.claimed_control_epoch != leased.claimed_control_epoch
        || held.claimed_instance_epoch != leased.claimed_instance_epoch
    {
        return Err(format!(
            "adoption did not atomically rebind timer control into adoption-hold: leased={leased:?}, held={held:?}, status={held_status:?}"
        ));
    }
    if harness.probe_status(0, "/health").await? != 200
        || harness.probe_status(0, "/ready").await? != 200
    {
        return Err("supported adoption-hold made the ordinary service unavailable".to_owned());
    }

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
    let stale_refused = harness.timer_evidence(&record_id).await?;
    assert_adoption_business_unchanged(&armed, &stale_refused, "old lease refusal")?;
    if stale_refused.claim_owner_id != Some(old_owner)
        || stale_refused.claim_epoch != leased.claim_epoch
        || !harness
            .timer_attempt_evidence(armed.occurrence_id)
            .await?
            .is_empty()
    {
        return Err(format!(
            "old lease changed durable timer state after adoption: leased={leased:?}, observed={stale_refused:?}"
        ));
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if harness.database_now().await?
                >= old_claim_until + chrono::Duration::milliseconds(250)
            {
                return Ok::<_, String>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| "database clock did not pass the old adoption lease".to_owned())??;
    let expired_held = harness.timer_evidence(&record_id).await?;
    assert_adoption_business_unchanged(&armed, &expired_held, "expired adoption hold")?;
    if expired_held.state != "leased"
        || expired_held.claim_owner_id != Some(old_owner)
        || expired_held.claim_epoch != leased.claim_epoch
    {
        return Err(format!(
            "adoption-hold permitted a peer claim after old lease expiry: {expired_held:?}"
        ));
    }

    let resumed = service
        .resume(control_request(held.control_epoch))
        .await
        .map_err(|error| format!("audited adoption resume failed: {error}"))?;
    if resumed.previous_control_epoch != held.control_epoch
        || resumed.control_epoch != held.control_epoch + 1
        || resumed.state != TimerControlState::Running
        || !resumed.changed
    {
        return Err(format!(
            "adoption resume outcome was not exact: {resumed:?}"
        ));
    }
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(10))
        .await?;
    if completed.state != "completed"
        || completed.status != "active"
        || completed.executed_attempt_count != 1
        || completed.revision != armed.revision + 1
        || completed.revisions != armed.revisions + 1
        || completed.action_receipts != armed.action_receipts + 1
        || completed.outbox_entries != armed.outbox_entries + 1
        || completed.control_state != "running"
        || completed.control_epoch != resumed.control_epoch
        || completed.bound_instance_epoch != adoption.current.epoch
    {
        return Err(format!(
            "post-adoption resume did not complete exactly once: armed={armed:?}, completed={completed:?}"
        ));
    }
    let attempts = harness.timer_attempt_evidence(armed.occurrence_id).await?;
    if attempts.len() != 1
        || attempts[0].attempt_number != 1
        || attempts[0].claim_epoch <= leased.claim_epoch
        || attempts[0].control_epoch != resumed.control_epoch
        || attempts[0].instance_epoch != adoption.current.epoch
        || attempts[0].outcome_code.as_deref() != Some("completed")
    {
        return Err(format!(
            "post-adoption attempt did not carry the new fences: {attempts:?}"
        ));
    }

    let audit = harness.operator_audit_entries(0)?;
    let delta = &audit[audit_baseline..];
    assert_instance_claim_audit_pair(delta, "committed")?;
    let occurrence = armed.occurrence_id.hyphenated().to_string();
    assert_operator_audit_pairs(
        delta,
        &[("breg.timer.resume", "succeeded")],
        &[record_id.as_str(), occurrence.as_str()],
    )?;
    println!(
        "record-timer-adoption owner={}:{} old_instance_epoch={} new_instance_epoch={} resumed_control_epoch={}",
        owner_identity.launch_id,
        owner_identity.pid,
        leased.bound_instance_epoch,
        adoption.current.epoch,
        resumed.control_epoch
    );
    Ok(())
}

async fn unsupported_protocol_adoption_rolls_back(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.start_replicas(1).await?;
    let config = harness.operator_runtime_config_path(0)?;
    harness.crash_all_replicas()?;
    let claims = InstanceClaimService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("instance-claim service construction failed: {error}"))?;
    let before = claims
        .status()
        .await
        .map_err(|error| format!("pre-refusal instance-claim status failed: {error}"))?;
    let before_epoch = before
        .claim
        .as_ref()
        .ok_or_else(|| "pre-refusal instance claim was missing".to_owned())?
        .epoch;
    harness
        .fixture_only_set_timer_control("running", 2, 0)
        .await?;
    let audit_baseline = harness.operator_audit_entries(0)?.len();
    let refusal = claims.adopt().await;
    let after = claims
        .status()
        .await
        .map_err(|error| format!("post-refusal instance-claim status failed: {error}"))?;
    harness
        .fixture_only_set_timer_control("running", 1, 0)
        .await?;

    let after_epoch = after
        .claim
        .as_ref()
        .ok_or_else(|| "refused adoption removed the instance claim".to_owned())?
        .epoch;
    if refusal != Err(InstanceClaimError::Unavailable) || after_epoch != before_epoch {
        return Err(format!(
            "unsupported timer protocol did not atomically refuse adoption: result={refusal:?}, before_epoch={before_epoch}, after_epoch={after_epoch}"
        ));
    }
    let audit = harness.operator_audit_entries(0)?;
    assert_instance_claim_audit_pair(&audit[audit_baseline..], "failed")?;
    Ok(())
}

fn assert_adoption_business_unchanged(
    armed: &record_timer_native::TimerEvidence,
    observed: &record_timer_native::TimerEvidence,
    label: &str,
) -> Result<(), String> {
    if observed.status != "scheduled"
        || observed.revision != armed.revision
        || observed.revisions != armed.revisions
        || observed.outbox_entries != armed.outbox_entries
        || observed.action_receipts != armed.action_receipts
        || observed.executed_attempt_count != 0
        || observed.retry_allowance != 0
        || observed.block_kind.is_some()
        || observed.outcome_code.is_some()
        || observed.completed_at.is_some()
    {
        return Err(format!(
            "{label} changed business or attempt state: armed={armed:?}, observed={observed:?}"
        ));
    }
    Ok(())
}

fn assert_instance_claim_audit_pair(
    entries: &[serde_json::Value],
    outcome: &str,
) -> Result<(), String> {
    let instance_entries = entries
        .iter()
        .filter(|entry| entry["schema"] == "breg-instance-claim-audit/v1")
        .collect::<Vec<_>>();
    if instance_entries.len() != 2
        || instance_entries[0]["phase"] != "request"
        || instance_entries[0]["record"]["phase"] != "attempt"
        || instance_entries[1]["phase"] != "response"
        || instance_entries[1]["record"]["phase"] != "terminal"
        || instance_entries[1]["record"]["outcome"] != outcome
        || instance_entries[0]["correlation"] != instance_entries[1]["correlation"]
    {
        return Err(format!(
            "instance adoption audit pair differed from outcome {outcome}: {instance_entries:?}"
        ));
    }
    Ok(())
}

async fn operator_admission(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.start_replicas(1).await?;
    let config = harness.operator_runtime_config_path(0)?;
    if !config.is_absolute() {
        return Err("native operator runtime configuration was not absolute".to_owned());
    }
    let mode = std::fs::metadata(&config)
        .map_err(|_| "native operator runtime configuration metadata was unavailable".to_owned())?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "native operator runtime configuration permissions were {mode:o}, expected 600"
        ));
    }

    let relative = TimerOperatorService::from_runtime_config(Path::new("runtime.yaml"))
        .await
        .err();
    if relative != Some(TimerOperatorError::RuntimeConfigPath) {
        return Err(format!(
            "relative operator runtime configuration was not refused: {relative:?}"
        ));
    }

    let refused = harness.write_package_refused_operator_config(0)?;
    let refusal = TimerOperatorService::from_runtime_config(&refused)
        .await
        .err();
    if refusal != Some(TimerOperatorError::PackageRefused) {
        return Err(format!(
            "inactive signed timer package was not refused: {refusal:?}"
        ));
    }

    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("active timer package operator admission failed: {error}"))?;
    let status = service
        .status()
        .await
        .map_err(|error| format!("admitted timer operator status failed: {error}"))?;
    if status.protocol_version != 1
        || status.control_state != TimerControlState::Running
        || status.control_epoch < 1
        || status.instance_epoch < 1
    {
        return Err(format!(
            "admitted timer operator status did not bind the live protocol: {status:?}"
        ));
    }
    Ok(())
}

async fn operator_reads(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let database_now = harness.database_now().await?;

    let pending = harness
        .create_scheduled_service(
            &client,
            &create,
            database_now + chrono::Duration::seconds(60),
        )
        .await?;
    let pending_record_id = pending.value.data.record_identifier.clone();
    let pending_evidence = harness.timer_evidence(&pending_record_id).await?;

    let completing = harness
        .create_scheduled_service(
            &client,
            &create,
            database_now + chrono::Duration::seconds(3),
        )
        .await?;
    let completed_record_id = completing.value.data.record_identifier.clone();
    let completed_evidence = harness
        .wait_for_completion(&completed_record_id, Duration::from_secs(12))
        .await?;

    let config = harness.operator_runtime_config_path(0)?;
    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("timer operator service construction failed: {error}"))?;
    let status = service
        .status()
        .await
        .map_err(|error| format!("timer operator status failed: {error}"))?;
    if status.protocol_version != 1
        || status.control_state != TimerControlState::Running
        || status.occurrence_counts.pending != 1
        || status.occurrence_counts.completed != 1
        || status.occurrence_counts.leased != 0
        || status.observed_lease_owner_count != 0
        || status.counts_truncated
    {
        return Err(format!(
            "timer operator status did not count the exact pending/completed ledger: {status:?}"
        ));
    }

    let first = service
        .list(TimerListRequest {
            state: None,
            record_type: Some("service"),
            timer: Some("activate"),
            after_cursor: None,
            limit: Some(1),
        })
        .await
        .map_err(|error| format!("first timer operator page failed: {error}"))?;
    if first.occurrences.len() != 1 || first.next_cursor.is_none() {
        return Err(format!(
            "first timer operator page did not expose bounded pagination: {first:?}"
        ));
    }
    let second = service
        .list(TimerListRequest {
            state: None,
            record_type: Some("service"),
            timer: Some("activate"),
            after_cursor: first.next_cursor.as_deref(),
            limit: Some(1),
        })
        .await
        .map_err(|error| format!("second timer operator page failed: {error}"))?;
    if second.occurrences.len() != 1 || second.next_cursor.is_some() {
        return Err(format!(
            "second timer operator page did not terminate pagination: {second:?}"
        ));
    }
    let listed = first
        .occurrences
        .iter()
        .chain(&second.occurrences)
        .map(|occurrence| occurrence.occurrence_id.clone())
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        pending_evidence.occurrence_id.hyphenated().to_string(),
        completed_evidence.occurrence_id.hyphenated().to_string(),
    ]);
    if listed != expected {
        return Err(format!(
            "timer operator pagination did not return the exact occurrences: listed={listed:?}, expected={expected:?}"
        ));
    }

    let pending_page = service
        .list(TimerListRequest {
            state: Some(TimerOccurrenceState::Pending),
            record_type: Some("service"),
            timer: Some("activate"),
            after_cursor: None,
            limit: Some(2),
        })
        .await
        .map_err(|error| format!("pending timer operator filter failed: {error}"))?;
    let completed_page = service
        .list(TimerListRequest {
            state: Some(TimerOccurrenceState::Completed),
            record_type: Some("service"),
            timer: Some("activate"),
            after_cursor: None,
            limit: Some(2),
        })
        .await
        .map_err(|error| format!("completed timer operator filter failed: {error}"))?;
    if pending_page.occurrences.len() != 1
        || completed_page.occurrences.len() != 1
        || pending_page.occurrences[0].attempt_count != 0
        || completed_page.occurrences[0].attempt_count != 1
        || completed_page.occurrences[0].outcome_code != Some(TimerOutcomeCode::Completed)
    {
        return Err(format!(
            "timer operator filters did not preserve pending/completed summaries: pending={pending_page:?}, completed={completed_page:?}"
        ));
    }

    let pending_detail = service
        .show(pending_evidence.occurrence_id)
        .await
        .map_err(|error| format!("pending timer operator show failed: {error}"))?;
    let completed_detail = service
        .show(completed_evidence.occurrence_id)
        .await
        .map_err(|error| format!("completed timer operator show failed: {error}"))?;
    assert_pending_detail(&pending_detail)?;
    assert_completed_detail(&completed_detail)?;

    let missing = service.show(Uuid::new_v4()).await.err();
    if missing != Some(TimerOperatorError::OccurrenceNotFound) {
        return Err(format!(
            "missing timer occurrence did not return the closed refusal: {missing:?}"
        ));
    }

    assert_value_free(&status, &pending_record_id, &completed_record_id, "status")?;
    assert_value_free(
        &first,
        &pending_record_id,
        &completed_record_id,
        "first list page",
    )?;
    assert_value_free(
        &second,
        &pending_record_id,
        &completed_record_id,
        "second list page",
    )?;
    assert_value_free(
        &pending_detail,
        &pending_record_id,
        &completed_record_id,
        "pending detail",
    )?;
    assert_value_free(
        &completed_detail,
        &pending_record_id,
        &completed_record_id,
        "completed detail",
    )?;
    Ok(())
}

async fn bounded_status_preserves_later_blocks(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.start_replicas(1).await?;
    harness
        .fixture_only_set_timer_control("paused", 1, 0)
        .await?;
    harness
        .fixture_only_seed_terminal_history_before_later_blocks()
        .await?;

    let config = harness.operator_runtime_config_path(0)?;
    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("bounded-history timer operator construction failed: {error}"))?;
    let status = service
        .status()
        .await
        .map_err(|error| format!("bounded-history timer status failed: {error}"))?;
    if status.occurrence_counts.cancelled != 10_000
        || status.occurrence_counts.pending != 10_000
        || status.occurrence_counts.blocked != 10_000
        || status.block_counts.technical != 10_000
        || status.block_counts.configuration != 1
        || !status.counts_truncated
    {
        return Err(format!(
            "bounded timer status hid later blocked work or misstated truncation: {status:?}"
        ));
    }
    Ok(())
}

async fn operator_pause_resume(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.start_replicas(2).await?;
    harness.assert_runtime_timer_control_column_acl().await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(5);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let occurrence_id = harness.timer_evidence(&record_id).await?.occurrence_id;
    let config = harness.operator_runtime_config_path(0)?;
    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("timer operator service construction failed: {error}"))?;
    let initial = service
        .status()
        .await
        .map_err(|error| format!("initial timer operator status failed: {error}"))?;
    let audit_baseline = harness.operator_audit_entries(0)?.len();

    let invalid = service
        .pause(TimerControlRequest {
            expected_control_epoch: 0,
            operator_reference: OPERATOR_REFERENCE_CANARY,
            reason: OPERATOR_REASON_CANARY,
        })
        .await
        .err();
    if invalid != Some(TimerOperatorError::OperationRefused)
        || harness.operator_audit_entries(0)?.len() != audit_baseline
    {
        return Err(format!(
            "invalid control request was not refused before audit/store access: {invalid:?}"
        ));
    }

    let paused = service
        .pause(control_request(initial.control_epoch))
        .await
        .map_err(|error| format!("timer operator pause failed: {error}"))?;
    if paused.previous_control_epoch != initial.control_epoch
        || paused.control_epoch != initial.control_epoch + 1
        || paused.state != TimerControlState::Paused
        || !paused.changed
    {
        return Err(format!(
            "timer operator pause outcome was not exact: {paused:?}"
        ));
    }
    let repeated_pause = service
        .pause(control_request(paused.control_epoch))
        .await
        .map_err(|error| format!("repeated timer operator pause failed: {error}"))?;
    if repeated_pause.previous_control_epoch != paused.control_epoch
        || repeated_pause.control_epoch != paused.control_epoch
        || repeated_pause.state != TimerControlState::Paused
        || repeated_pause.changed
    {
        return Err(format!(
            "repeated timer operator pause was not a no-op: {repeated_pause:?}"
        ));
    }
    let stale_pause = service
        .pause(control_request(initial.control_epoch))
        .await
        .err();
    if stale_pause != Some(TimerOperatorError::ControlEpochMismatch) {
        return Err(format!(
            "stale timer operator pause returned the wrong refusal: {stale_pause:?}"
        ));
    }

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if harness.database_now().await? >= due_at + chrono::Duration::milliseconds(250) {
                return Ok::<_, String>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| "database clock did not pass the due instant while paused".to_owned())??;
    let held = harness.timer_evidence(&record_id).await?;
    if held.state != "pending"
        || held.status != "scheduled"
        || held.executed_attempt_count != 0
        || held.control_state != "paused"
        || held.control_epoch != paused.control_epoch
    {
        return Err(format!(
            "shared timer control did not fence native workers while paused: {held:?}"
        ));
    }

    let resumed = service
        .resume(control_request(paused.control_epoch))
        .await
        .map_err(|error| format!("timer operator resume failed: {error}"))?;
    if resumed.previous_control_epoch != paused.control_epoch
        || resumed.control_epoch != paused.control_epoch + 1
        || resumed.state != TimerControlState::Running
        || !resumed.changed
    {
        return Err(format!(
            "timer operator resume outcome was not exact: {resumed:?}"
        ));
    }
    let repeated_resume = service
        .resume(control_request(resumed.control_epoch))
        .await
        .map_err(|error| format!("repeated timer operator resume failed: {error}"))?;
    if repeated_resume.previous_control_epoch != resumed.control_epoch
        || repeated_resume.control_epoch != resumed.control_epoch
        || repeated_resume.state != TimerControlState::Running
        || repeated_resume.changed
    {
        return Err(format!(
            "repeated timer operator resume was not a no-op: {repeated_resume:?}"
        ));
    }
    let stale_resume = service
        .resume(control_request(paused.control_epoch))
        .await
        .err();
    if stale_resume != Some(TimerOperatorError::ControlEpochMismatch) {
        return Err(format!(
            "stale timer operator resume returned the wrong refusal: {stale_resume:?}"
        ));
    }

    let audit = harness.operator_audit_entries(0)?;
    let occurrence_string = occurrence_id.hyphenated().to_string();
    assert_operator_audit_pairs(
        &audit[audit_baseline..],
        &[
            ("breg.timer.pause", "succeeded"),
            ("breg.timer.pause", "succeeded"),
            ("breg.timer.pause", "refused"),
            ("breg.timer.resume", "succeeded"),
            ("breg.timer.resume", "succeeded"),
            ("breg.timer.resume", "refused"),
        ],
        &[record_id.as_str(), occurrence_string.as_str()],
    )?;
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(8))
        .await?;
    if completed.control_epoch != resumed.control_epoch || completed.executed_attempt_count != 1 {
        return Err(format!(
            "native worker did not resume under the operator control epoch: {completed:?}"
        ));
    }
    Ok(())
}

async fn operator_pause_interlock(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_checkpoint(NativeTimerCheckpoint::BeforeCommit, None)?;
    harness.start_replicas(1).await?;
    let operator_config = harness.write_operator_runtime_config("pause-interlock")?;
    let service = TimerOperatorService::from_runtime_config(&operator_config.path)
        .await
        .map_err(|error| format!("interlock timer operator construction failed: {error}"))?;
    let initial = service
        .status()
        .await
        .map_err(|error| format!("interlock timer operator status failed: {error}"))?;
    let initial_control_epoch = initial.control_epoch;
    let audit_baseline = harness
        .separate_operator_audit_entries(&operator_config)?
        .len();

    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(3);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    let (owner, owner_identity) = harness
        .wait_for_one_checkpoint(armed.occurrence_id, Duration::from_secs(10))
        .await?;

    let pause =
        tokio::spawn(async move { service.pause(control_request(initial_control_epoch)).await });
    let blocking = harness
        .wait_for_database_blocking_relation(
            &operator_config.application_name,
            owner,
            Duration::from_secs(5),
        )
        .await?;
    if pause.is_finished() {
        return Err(
            "operator pause completed while PostgreSQL still reported its blocker".to_owned(),
        );
    }
    let staged = harness.timer_evidence(&record_id).await?;
    if staged.status != "scheduled"
        || staged.executed_attempt_count != 0
        || staged.revision != armed.revision
        || staged.action_receipts != armed.action_receipts
        || staged.outbox_entries != armed.outbox_entries
    {
        return Err(format!(
            "in-flight timer effects became visible before release: armed={armed:?}, staged={staged:?}"
        ));
    }

    harness.release_checkpoint(owner)?;
    let paused = tokio::time::timeout(Duration::from_secs(5), pause)
        .await
        .map_err(|_| "operator pause did not finish after the timer commit".to_owned())?
        .map_err(|error| format!("operator pause task failed: {error}"))?
        .map_err(|error| format!("operator pause failed after timer commit: {error}"))?;
    if paused.previous_control_epoch != initial_control_epoch
        || paused.control_epoch != initial_control_epoch + 1
        || paused.state != TimerControlState::Paused
        || !paused.changed
    {
        return Err(format!(
            "operator pause did not advance exactly once after the timer commit: {paused:?}"
        ));
    }

    let completed = harness.timer_evidence(&record_id).await?;
    if completed.state != "completed"
        || completed.status != "active"
        || completed.executed_attempt_count != 1
        || completed.action_receipts != armed.action_receipts + 1
        || completed.outbox_entries != armed.outbox_entries + 1
        || completed.control_state != "paused"
        || completed.control_epoch != paused.control_epoch
    {
        return Err(format!(
            "timer commit was not durably visible before pause completion: {completed:?}"
        ));
    }
    let attempts = harness.timer_attempt_evidence(armed.occurrence_id).await?;
    if attempts.len() != 1
        || attempts[0].attempt_number != 1
        || attempts[0].control_epoch != initial_control_epoch
        || attempts[0].outcome_code.as_deref() != Some("completed")
        || attempts[0].finished_at.is_none()
    {
        return Err(format!(
            "timer commit did not retain one pre-pause-epoch attempt: {attempts:?}"
        ));
    }

    let audit = harness.separate_operator_audit_entries(&operator_config)?;
    let occurrence_string = armed.occurrence_id.hyphenated().to_string();
    assert_operator_audit_pairs(
        &audit[audit_baseline..],
        &[("breg.timer.pause", "succeeded")],
        &[record_id.as_str(), occurrence_string.as_str()],
    )?;

    let stable_after = harness.database_now().await? + chrono::Duration::milliseconds(500);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if harness.database_now().await? >= stable_after {
                return Ok::<_, String>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| "database clock did not reach the post-pause stability bound".to_owned())??;
    let settled = harness.timer_evidence(&record_id).await?;
    if settled != completed {
        return Err(format!(
            "pre-pause timer work changed after pause completed: completed={completed:?}, settled={settled:?}"
        ));
    }
    println!(
        "record-timer-operator interlock occurrence_id={} worker_pid={} blocked_database_pid={} blocker_database_pid={}",
        armed.occurrence_id,
        owner_identity.pid,
        blocking.blocked_pid,
        blocking.blocker_pid
    );
    Ok(())
}

async fn operator_retry(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let database_now = harness.database_now().await?;
    let candidate = harness
        .create_scheduled_service(
            &client,
            &create,
            database_now + chrono::Duration::seconds(60),
        )
        .await?;
    let configuration = harness
        .create_scheduled_service(
            &client,
            &create,
            database_now + chrono::Duration::seconds(61),
        )
        .await?;
    let expired = harness
        .create_scheduled_service(
            &client,
            &create,
            database_now + chrono::Duration::seconds(62),
        )
        .await?;
    let terminal = harness
        .create_scheduled_service(
            &client,
            &create,
            database_now + chrono::Duration::seconds(3),
        )
        .await?;
    let candidate_record = candidate.value.data.record_identifier.clone();
    let configuration_record = configuration.value.data.record_identifier.clone();
    let expired_record = expired.value.data.record_identifier.clone();
    let terminal_record = terminal.value.data.record_identifier.clone();
    let candidate_occurrence = harness
        .timer_evidence(&candidate_record)
        .await?
        .occurrence_id;
    let configuration_occurrence = harness
        .timer_evidence(&configuration_record)
        .await?
        .occurrence_id;
    let expired_occurrence = harness.timer_evidence(&expired_record).await?.occurrence_id;
    let terminal_occurrence = harness
        .wait_for_completion(&terminal_record, Duration::from_secs(12))
        .await?
        .occurrence_id;
    harness
        .fixture_only_set_technical_retry_candidate(&candidate_record)
        .await?;
    harness
        .fixture_only_set_configuration_block(&configuration_record)
        .await?;
    harness
        .fixture_only_set_expired_technical_block(&expired_record)
        .await?;

    let config = harness.operator_runtime_config_path(0)?;
    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("timer operator service construction failed: {error}"))?;
    let audit_baseline = harness.operator_audit_entries(0)?.len();
    let invalid = service
        .retry(TimerRetryRequest {
            occurrence_id: candidate_occurrence,
            expected_attempt_count: 5,
            operator_reference: "",
            reason: OPERATOR_REASON_CANARY,
        })
        .await
        .err();
    if invalid != Some(TimerOperatorError::OperationRefused)
        || harness.operator_audit_entries(0)?.len() != audit_baseline
    {
        return Err(format!(
            "invalid retry request was not refused before audit/store access: {invalid:?}"
        ));
    }

    let retried = service
        .retry(retry_request(candidate_occurrence, 5))
        .await
        .map_err(|error| format!("technical timer retry failed: {error}"))?;
    if retried.occurrence_id != candidate_occurrence.hyphenated().to_string()
        || retried.state != TimerOccurrenceState::Pending
        || retried.attempt_count != 5
        || retried.retry_allowance != 1
    {
        return Err(format!(
            "technical timer retry outcome was not exact: {retried:?}"
        ));
    }
    let queued = harness.timer_evidence(&candidate_record).await?;
    if queued.state != "pending"
        || queued.executed_attempt_count != 5
        || queued.retry_allowance != 1
    {
        return Err(format!(
            "technical retry did not queue exactly one allowance without resetting attempts: {queued:?}"
        ));
    }

    for (label, result) in [
        (
            "replayed technical retry",
            service.retry(retry_request(candidate_occurrence, 5)).await,
        ),
        (
            "terminal retry",
            service.retry(retry_request(terminal_occurrence, 1)).await,
        ),
        (
            "configuration-blocked retry",
            service
                .retry(retry_request(configuration_occurrence, 0))
                .await,
        ),
        (
            "expired-window retry",
            service.retry(retry_request(expired_occurrence, 5)).await,
        ),
    ] {
        if result.err() != Some(TimerOperatorError::RetryIneligible) {
            return Err(format!("{label} returned the wrong refusal"));
        }
    }
    let replayed = harness.timer_evidence(&candidate_record).await?;
    if replayed.executed_attempt_count != 5 || replayed.retry_allowance != 1 {
        return Err(format!(
            "replayed technical retry duplicated or reset allowance state: {replayed:?}"
        ));
    }

    let audit = harness.operator_audit_entries(0)?;
    let occurrence_strings = [
        candidate_occurrence.hyphenated().to_string(),
        terminal_occurrence.hyphenated().to_string(),
        configuration_occurrence.hyphenated().to_string(),
        expired_occurrence.hyphenated().to_string(),
    ];
    assert_operator_audit_pairs(
        &audit[audit_baseline..],
        &[
            ("breg.timer.retry", "succeeded"),
            ("breg.timer.retry", "refused"),
            ("breg.timer.retry", "refused"),
            ("breg.timer.retry", "refused"),
            ("breg.timer.retry", "refused"),
        ],
        &[
            candidate_record.as_str(),
            terminal_record.as_str(),
            configuration_record.as_str(),
            expired_record.as_str(),
            occurrence_strings[0].as_str(),
            occurrence_strings[1].as_str(),
            occurrence_strings[2].as_str(),
            occurrence_strings[3].as_str(),
        ],
    )?;
    Ok(())
}

async fn operator_retry_after_actual_exhaustion(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.enable_outcome_checkpoint(NativeOutcomeSettlementKind::TechnicalFailure, 2_000)?;
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(2);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let armed = harness.timer_evidence(&record_id).await?;
    let occurrence_id = armed.occurrence_id;
    let (owner, _) = harness
        .wait_for_one_checkpoint(occurrence_id, Duration::from_secs(10))
        .await?;
    harness.release_checkpoint(owner)?;

    for expected in 1..=5_i32 {
        let failed =
            wait_for_technical_attempt_count(harness, &record_id, expected, Duration::from_secs(8))
                .await?;
        if expected < 5 {
            if failed.state != "pending"
                || failed.block_kind.is_some()
                || failed.outcome_code.is_some()
                || failed.retry_allowance != 0
            {
                return Err(format!(
                    "automatic technical attempt {expected} did not remain pending: {failed:?}"
                ));
            }
            harness
                .fixture_only_release_technical_retry(&record_id, expected)
                .await?;
        } else if failed.state != "blocked"
            || failed.block_kind.as_deref() != Some("technical")
            || failed.outcome_code.as_deref() != Some("attempts-exhausted")
            || failed.retry_allowance != 0
        {
            return Err(format!(
                "five actual technical failures did not exhaust automatically: {failed:?}"
            ));
        }
    }
    harness.expect_non_info_code(owner, "record_timer.worker.iteration_failed", 5)?;
    harness.crash_all_replicas()?;

    let operator_config = harness.write_operator_runtime_config("actual-retry")?;
    let service = TimerOperatorService::from_runtime_config(&operator_config.path)
        .await
        .map_err(|error| format!("actual retry operator construction failed: {error}"))?;
    let audit_baseline = harness
        .separate_operator_audit_entries(&operator_config)?
        .len();
    let retried = service
        .retry(retry_request(occurrence_id, 5))
        .await
        .map_err(|error| format!("actual exhausted occurrence retry failed: {error}"))?;
    if retried.state != TimerOccurrenceState::Pending
        || retried.attempt_count != 5
        || retried.retry_allowance != 1
    {
        return Err(format!(
            "operator retry did not grant exactly one allowance: {retried:?}"
        ));
    }
    let queued = harness.timer_evidence(&record_id).await?;
    if queued.occurrence_id != occurrence_id
        || queued.state != "pending"
        || queued.executed_attempt_count != 5
        || queued.retry_allowance != 1
    {
        return Err(format!(
            "operator retry did not preserve the exhausted occurrence: {queued:?}"
        ));
    }
    let audit = harness.separate_operator_audit_entries(&operator_config)?;
    let occurrence_string = occurrence_id.hyphenated().to_string();
    assert_operator_audit_pairs(
        &audit[audit_baseline..],
        &[("breg.timer.retry", "succeeded")],
        &[record_id.as_str(), occurrence_string.as_str()],
    )?;
    drop(service);

    harness.start_replicas(1).await?;
    let replacement = 1;
    let (retry_owner, _) = harness
        .wait_for_checkpoint_except(occurrence_id, owner, Duration::from_secs(10))
        .await?;
    if retry_owner != replacement {
        return Err("replacement process did not own the manual retry attempt".to_owned());
    }
    harness.release_checkpoint(retry_owner)?;
    let blocked =
        wait_for_technical_attempt_count(harness, &record_id, 6, Duration::from_secs(8)).await?;
    harness.expect_non_info_code(retry_owner, "record_timer.worker.iteration_failed", 1)?;
    if blocked.occurrence_id != occurrence_id
        || blocked.state != "blocked"
        || blocked.block_kind.as_deref() != Some("technical")
        || blocked.outcome_code.as_deref() != Some("attempts-exhausted")
        || blocked.executed_attempt_count != 6
        || blocked.retry_allowance != 0
        || blocked.status != armed.status
        || blocked.revision != armed.revision
        || blocked.revisions != armed.revisions
        || blocked.outbox_entries != armed.outbox_entries
        || blocked.action_receipts != armed.action_receipts
    {
        return Err(format!(
            "manual technical retry did not fail back into the exact blocked occurrence: armed={armed:?}, blocked={blocked:?}"
        ));
    }

    let expected_activation = armed
        .current_policy_activation_id
        .ok_or_else(|| "exhausted retry fixture omitted its active policy activation".to_owned())?;
    let attempts = harness.timer_attempt_evidence(occurrence_id).await?;
    if attempts.len() != 6
        || blocked.current_policy_activation_id != Some(expected_activation)
        || attempts.iter().enumerate().any(|(index, attempt)| {
            attempt.attempt_number != i32::try_from(index + 1).unwrap_or_default()
                || attempt.finished_at.is_none()
                || attempt.block_kind.as_deref() != Some("technical")
                || attempt.technical_code.is_none()
                || attempt.receipt_correlation.is_some()
                || attempt.control_epoch != blocked.control_epoch
                || attempt.instance_epoch != blocked.bound_instance_epoch
                || attempt.activation_id != expected_activation
                || attempt.definition_revision != blocked.definition_revision
                || attempt.action_revision != blocked.action_revision
                || attempt.system_grant_revision != blocked.system_grant_revision
        })
        || attempts
            .windows(2)
            .any(|pair| pair[0].claim_epoch >= pair[1].claim_epoch)
        || attempts[..5]
            .iter()
            .any(|attempt| attempt.claim_owner_id != attempts[0].claim_owner_id)
        || attempts[5].claim_owner_id == attempts[0].claim_owner_id
        || attempts[5].outcome_code.as_deref() != Some("attempts-exhausted")
    {
        return Err(format!(
            "actual retry did not preserve six cumulatively fenced attempts: {attempts:?}"
        ));
    }
    Ok(())
}

async fn wait_for_technical_attempt_count(
    harness: &NativeTimerHarness,
    record_id: &str,
    expected: i32,
    timeout: Duration,
) -> Result<record_timer_native::TimerEvidence, String> {
    tokio::time::timeout(timeout, async {
        loop {
            let evidence = harness.timer_evidence(record_id).await?;
            let attempts = harness
                .timer_attempt_evidence(evidence.occurrence_id)
                .await?;
            if evidence.executed_attempt_count == expected
                && attempts.len() == usize::try_from(expected).unwrap_or_default()
            {
                return Ok(evidence);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| format!("technical timer did not retain attempt {expected} before the bound"))?
}

async fn built_bregctl_operator_journey(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let now = harness.database_now().await?;
    let pending = harness
        .create_scheduled_service(&client, &create, now + chrono::Duration::seconds(60))
        .await?;
    let completed = harness
        .create_scheduled_service(&client, &create, now + chrono::Duration::seconds(2))
        .await?;
    let pending_record = pending.value.data.record_identifier.clone();
    let completed_record = completed.value.data.record_identifier.clone();
    let pending_occurrence = harness.timer_evidence(&pending_record).await?.occurrence_id;
    let completed_occurrence = harness
        .wait_for_completion(&completed_record, Duration::from_secs(12))
        .await?
        .occurrence_id;
    let config = harness.write_operator_runtime_config("cli-journey")?;
    let audit_baseline = harness.separate_operator_audit_entries(&config)?.len();

    let status = run_bregctl_json(harness, &config, "status", &["status"], true).await?;
    let initial_control_epoch = status["status"]["controlEpoch"]
        .as_i64()
        .ok_or_else(|| "bregctl timer status omitted controlEpoch".to_owned())?;
    if status["status"]["controlState"] != "running" {
        return Err(format!("bregctl timer status was not running: {status}"));
    }

    let first_page = run_bregctl_json(
        harness,
        &config,
        "list-first",
        &["list", "--limit", "1"],
        true,
    )
    .await?;
    let first_occurrence = first_page["page"]["occurrences"]
        .as_array()
        .filter(|items| items.len() == 1)
        .and_then(|items| items[0]["occurrenceId"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| "bregctl timer list did not return one bounded first page".to_owned())?;
    let next_cursor = first_page["page"]["nextCursor"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "bregctl timer list omitted its next cursor".to_owned())?;
    let second_page = run_bregctl_json(
        harness,
        &config,
        "list-second",
        &[
            "list",
            "--limit",
            "1",
            "--after-cursor",
            next_cursor.as_str(),
        ],
        true,
    )
    .await?;
    let second_occurrence = second_page["page"]["occurrences"]
        .as_array()
        .filter(|items| items.len() == 1)
        .and_then(|items| items[0]["occurrenceId"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| "bregctl timer list did not return one bounded second page".to_owned())?;
    if first_occurrence == second_occurrence {
        return Err("bregctl timer list cursor replayed the first occurrence".to_owned());
    }

    let completed_occurrence_text = completed_occurrence.hyphenated().to_string();
    let shown = run_bregctl_json(
        harness,
        &config,
        "show",
        &["show", "--occurrence-id", &completed_occurrence_text],
        true,
    )
    .await?;
    if shown["occurrence"]["occurrenceId"] != completed_occurrence_text
        || shown["occurrence"]["state"] != "completed"
        || shown["occurrence"]["attempts"]
            .as_array()
            .is_none_or(|attempts| attempts.len() != 1)
    {
        return Err(format!("bregctl timer show was not exact: {shown}"));
    }

    let initial_epoch = initial_control_epoch.to_string();
    let paused = run_bregctl_json(
        harness,
        &config,
        "pause",
        &[
            "pause",
            "--expected-control-epoch",
            &initial_epoch,
            "--operator-reference",
            OPERATOR_REFERENCE_CANARY,
            "--reason",
            OPERATOR_REASON_CANARY,
        ],
        true,
    )
    .await?;
    let paused_epoch = paused["control"]["controlEpoch"]
        .as_i64()
        .ok_or_else(|| "bregctl timer pause omitted controlEpoch".to_owned())?;
    if paused_epoch != initial_control_epoch + 1
        || paused["control"]["state"] != "paused"
        || paused["control"]["changed"] != true
    {
        return Err(format!("bregctl timer pause was not exact: {paused}"));
    }
    let stale_pause = run_bregctl_json(
        harness,
        &config,
        "pause-stale",
        &[
            "pause",
            "--expected-control-epoch",
            &initial_epoch,
            "--operator-reference",
            OPERATOR_REFERENCE_CANARY,
            "--reason",
            OPERATOR_REASON_CANARY,
        ],
        false,
    )
    .await?;
    expect_bregctl_problem(&stale_pause, "timer.control.epoch-mismatch")?;

    let paused_epoch_text = paused_epoch.to_string();
    let resumed = run_bregctl_json(
        harness,
        &config,
        "resume",
        &[
            "resume",
            "--expected-control-epoch",
            &paused_epoch_text,
            "--operator-reference",
            OPERATOR_REFERENCE_CANARY,
            "--reason",
            OPERATOR_REASON_CANARY,
        ],
        true,
    )
    .await?;
    let resumed_epoch = resumed["control"]["controlEpoch"]
        .as_i64()
        .ok_or_else(|| "bregctl timer resume omitted controlEpoch".to_owned())?;
    if resumed_epoch != paused_epoch + 1
        || resumed["control"]["state"] != "running"
        || resumed["control"]["changed"] != true
    {
        return Err(format!("bregctl timer resume was not exact: {resumed}"));
    }

    harness
        .fixture_only_set_technical_retry_candidate(&pending_record)
        .await?;
    let pending_occurrence_text = pending_occurrence.hyphenated().to_string();
    let retry_arguments = [
        "retry",
        "--occurrence-id",
        pending_occurrence_text.as_str(),
        "--expected-attempt-count",
        "5",
        "--operator-reference",
        OPERATOR_REFERENCE_CANARY,
        "--reason",
        OPERATOR_REASON_CANARY,
    ];
    let retried = run_bregctl_json(harness, &config, "retry", &retry_arguments, true).await?;
    if retried["retry"]["occurrenceId"] != pending_occurrence_text
        || retried["retry"]["state"] != "pending"
        || retried["retry"]["attemptCount"] != 5
        || retried["retry"]["retryAllowance"] != 1
    {
        return Err(format!("bregctl timer retry was not exact: {retried}"));
    }
    let replayed =
        run_bregctl_json(harness, &config, "retry-replay", &retry_arguments, false).await?;
    expect_bregctl_problem(&replayed, "timer.retry.ineligible")?;

    let durable = harness.timer_evidence(&pending_record).await?;
    if durable.state != "pending"
        || durable.executed_attempt_count != 5
        || durable.retry_allowance != 1
        || durable.control_state != "running"
        || durable.control_epoch != resumed_epoch
    {
        return Err(format!(
            "bregctl transitions did not preserve exact durable state: {durable:?}"
        ));
    }

    let audit = harness.separate_operator_audit_entries(&config)?;
    assert_operator_audit_pairs(
        &audit[audit_baseline..],
        &[
            ("breg.timer.pause", "succeeded"),
            ("breg.timer.pause", "refused"),
            ("breg.timer.resume", "succeeded"),
            ("breg.timer.retry", "succeeded"),
            ("breg.timer.retry", "refused"),
        ],
        &[
            pending_record.as_str(),
            completed_record.as_str(),
            pending_occurrence_text.as_str(),
            completed_occurrence_text.as_str(),
        ],
    )?;
    Ok(())
}

async fn run_bregctl_json(
    harness: &NativeTimerHarness,
    config: &NativeOperatorConfig,
    label: &str,
    command: &[&str],
    expect_success: bool,
) -> Result<serde_json::Value, String> {
    let config_path = config
        .path
        .to_str()
        .ok_or_else(|| "native bregctl runtime configuration path was not UTF-8".to_owned())?;
    let mut arguments = vec!["--format".to_owned(), "json".to_owned(), "timer".to_owned()];
    arguments.extend(command.iter().map(|argument| (*argument).to_owned()));
    arguments.extend(["--runtime-config".to_owned(), config_path.to_owned()]);
    let output = harness.run_bregctl(label, &arguments).await?;
    if output.status.success() != expect_success {
        return Err(format!(
            "bregctl timer command had exit {:?}, expected success={expect_success}; stdout={}; stderr={}",
            output.status.code(), output.stdout, output.stderr
        ));
    }
    if !output.stderr.is_empty() {
        return Err(format!(
            "bregctl JSON command wrote stderr: {}",
            output.stderr
        ));
    }
    for canary in [
        OPERATOR_REFERENCE_CANARY,
        OPERATOR_REASON_CANARY,
        DESCRIPTION_CANARY,
        JURISDICTION_CANARY,
    ] {
        if output.stdout.contains(canary) {
            return Err(format!(
                "bregctl output disclosed a raw value canary: {canary}"
            ));
        }
    }
    println!(
        "record-timer-operator bregctl={} command={} exit={:?}",
        output.executable.display(),
        label,
        output.status.code()
    );
    serde_json::from_str(&output.stdout)
        .map_err(|_| format!("bregctl timer {label} output was not JSON"))
}

fn expect_bregctl_problem(value: &serde_json::Value, code: &str) -> Result<(), String> {
    if value["ok"] != false || value["diagnostics"][0]["code"] != code {
        return Err(format!(
            "bregctl refusal did not use problem code {code}: {value}"
        ));
    }
    Ok(())
}

async fn known_retained_technical_code(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(60);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let occurrence_id = harness
        .fixture_only_set_retained_technical_attempt(&record_id, "handler-failure")
        .await?;
    let config = harness.operator_runtime_config_path(0)?;
    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("timer operator service construction failed: {error}"))?;
    let detail = service
        .show(occurrence_id)
        .await
        .map_err(|error| format!("known technical-code show failed: {error}"))?;
    let serialized = serde_json::to_value(&detail)
        .map_err(|_| "known technical-code detail did not serialize".to_owned())?;
    if serialized.pointer("/attempts/0/technicalCode")
        != Some(&serde_json::Value::String("handler-failure".to_owned()))
    {
        return Err(format!(
            "known retained technical code was not projected through the closed public JSON field: {serialized}"
        ));
    }
    assert_value_free(
        &detail,
        &record_id,
        "raw-handler-failure-detail-canary",
        "known technical-code detail",
    )?;
    Ok(())
}

async fn unknown_retained_technical_code(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(60);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let occurrence_id = harness
        .fixture_only_set_retained_technical_attempt(&record_id, "unknown-technical-code-canary")
        .await?;
    let config = harness.operator_runtime_config_path(0)?;
    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("timer operator service construction failed: {error}"))?;
    let error = service.show(occurrence_id).await.err();
    if error != Some(TimerOperatorError::DatabaseUnavailable) {
        return Err(format!(
            "unknown stored technical code did not fail closed as database-unavailable: {error:?}"
        ));
    }
    Ok(())
}

/// Fixture-only ledger transition. This proves the read projection is total
/// after binding removal; it is not worker lifecycle evidence.
async fn removed_binding_projection(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(60);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let occurrence_id = harness.timer_evidence(&record_id).await?.occurrence_id;
    let config = harness.operator_runtime_config_path(0)?;
    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("timer operator service construction failed: {error}"))?;

    harness
        .fixture_only_block_timer_and_remove_binding(&record_id)
        .await?;
    let read = tokio::spawn(async move {
        let page = service
            .list(TimerListRequest {
                state: Some(TimerOccurrenceState::Blocked),
                record_type: Some("service"),
                timer: Some("activate"),
                after_cursor: None,
                limit: Some(1),
            })
            .await?;
        let detail = service.show(occurrence_id).await?;
        Ok::<_, TimerOperatorError>((page, detail))
    })
    .await
    .map_err(|error| format!("timer operator removed-binding projection panicked: {error}"))?
    .map_err(|error| format!("timer operator removed-binding projection failed: {error}"))?;
    let (page, detail) = read;
    if page.occurrences.len() != 1
        || page.occurrences[0].retry_eligible
        || page.occurrences[0].block_kind != Some(TimerBlockKind::Technical)
        || detail.summary.retry_eligible
        || detail.summary.block_kind != Some(TimerBlockKind::Technical)
    {
        return Err(format!(
            "removed timer binding did not project a safe non-retryable technical block: page={page:?}, detail={detail:?}"
        ));
    }
    assert_value_free(&page, &record_id, &record_id, "removed-binding list")?;
    assert_value_free(&detail, &record_id, &record_id, "removed-binding detail")?;
    Ok(())
}

/// Fixture-only binding drift. This proves status distinguishes terminal
/// history from unfinished stale backlog; it is not activation lifecycle proof.
async fn completed_revision_drift_projection(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(3);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let completed = harness
        .wait_for_completion(&record_id, Duration::from_secs(12))
        .await?;
    let config = harness.operator_runtime_config_path(0)?;
    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("timer operator service construction failed: {error}"))?;

    harness.fixture_only_change_timer_binding_revision().await?;
    let status = service
        .status()
        .await
        .map_err(|error| format!("timer operator drifted-binding status failed: {error}"))?;
    if status.occurrence_counts.completed != 1 || status.stale_revision_count != 0 {
        return Err(format!(
            "terminal timer history was counted as unfinished stale backlog: {status:?}"
        ));
    }
    let detail = service
        .show(completed.occurrence_id)
        .await
        .map_err(|error| format!("timer operator drifted-binding show failed: {error}"))?;
    if detail.summary.state != TimerOccurrenceState::Completed
        || detail.summary.retry_eligible
        || detail.summary.outcome_code != Some(TimerOutcomeCode::Completed)
    {
        return Err(format!(
            "terminal timer detail changed under fixture binding drift: {detail:?}"
        ));
    }
    assert_value_free(&status, &record_id, &record_id, "drifted-binding status")?;
    assert_value_free(&detail, &record_id, &record_id, "drifted-binding detail")?;
    Ok(())
}

/// Fixture-only historical activation metadata drift. This proves an unchanged
/// current semantic revision remains fresh and retryable; it is not governed
/// activation or reconciliation lifecycle evidence.
async fn activation_only_drift_projection(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(60);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let occurrence_id = harness.timer_evidence(&record_id).await?.occurrence_id;

    harness
        .fixture_only_set_technical_retry_candidate(&record_id)
        .await?;
    harness
        .fixture_only_change_generation_policy_activation(&record_id)
        .await?;

    let config = harness.operator_runtime_config_path(0)?;
    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| format!("timer operator service construction failed: {error}"))?;
    let status = service
        .status()
        .await
        .map_err(|error| format!("activation-only drift status failed: {error}"))?;
    let page = service
        .list(TimerListRequest {
            state: Some(TimerOccurrenceState::Blocked),
            record_type: Some("service"),
            timer: Some("activate"),
            after_cursor: None,
            limit: Some(1),
        })
        .await
        .map_err(|error| format!("activation-only drift list failed: {error}"))?;
    let detail = service
        .show(occurrence_id)
        .await
        .map_err(|error| format!("activation-only drift show failed: {error}"))?;

    if status.stale_revision_count != 0
        || page.occurrences.len() != 1
        || page.occurrences[0].occurrence_id != occurrence_id.hyphenated().to_string()
        || page.occurrences[0].state != TimerOccurrenceState::Blocked
        || page.occurrences[0].block_kind != Some(TimerBlockKind::Technical)
        || !page.occurrences[0].retry_eligible
        || detail.summary.occurrence_id != occurrence_id.hyphenated().to_string()
        || detail.summary.state != TimerOccurrenceState::Blocked
        || detail.summary.block_kind != Some(TimerBlockKind::Technical)
        || !detail.summary.retry_eligible
    {
        return Err(format!(
            "activation-only historical metadata drift changed current semantic status/retry projection: status={status:?}, page={page:?}, detail={detail:?}"
        ));
    }
    assert_value_free(
        &status,
        &record_id,
        &record_id,
        "activation-only drift status",
    )?;
    assert_value_free(&page, &record_id, &record_id, "activation-only drift list")?;
    assert_value_free(
        &detail,
        &record_id,
        &record_id,
        "activation-only drift detail",
    )?;
    Ok(())
}

/// Fixture-only permitted stored shape. This proves public eligibility remains
/// aligned with the exact retry transition; it is not worker-lifecycle proof.
async fn non_exhausted_technical_block_projection(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.start_replicas(1).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let due_at = harness.database_now().await? + chrono::Duration::seconds(60);
    let created = harness
        .create_scheduled_service(&client, &create, due_at)
        .await?;
    let record_id = created.value.data.record_identifier.clone();
    let occurrence_id = harness.timer_evidence(&record_id).await?.occurrence_id;
    harness
        .fixture_only_set_non_exhausted_technical_block(&record_id)
        .await?;

    let config = harness.operator_runtime_config_path(0)?;
    let service = TimerOperatorService::from_runtime_config(&config)
        .await
        .map_err(|error| {
            format!("non-exhausted technical-block operator construction failed: {error}")
        })?;
    let page = service
        .list(TimerListRequest {
            state: Some(TimerOccurrenceState::Blocked),
            record_type: Some("service"),
            timer: Some("activate"),
            after_cursor: None,
            limit: Some(1),
        })
        .await
        .map_err(|error| format!("non-exhausted technical-block list failed: {error}"))?;
    let detail = service
        .show(occurrence_id)
        .await
        .map_err(|error| format!("non-exhausted technical-block show failed: {error}"))?;
    let retry_error = service.retry(retry_request(occurrence_id, 5)).await.err();
    if page.occurrences.len() != 1
        || page.occurrences[0].block_kind != Some(TimerBlockKind::Technical)
        || page.occurrences[0].outcome_code.is_some()
        || page.occurrences[0].retry_eligible
        || detail.summary.block_kind != Some(TimerBlockKind::Technical)
        || detail.summary.outcome_code.is_some()
        || detail.summary.retry_eligible
        || retry_error != Some(TimerOperatorError::RetryIneligible)
    {
        return Err(format!(
            "non-exhausted technical block disagreed with retry transition: page={page:?}, detail={detail:?}, retry_error={retry_error:?}"
        ));
    }
    Ok(())
}

fn control_request(expected_control_epoch: i64) -> TimerControlRequest<'static> {
    TimerControlRequest {
        expected_control_epoch,
        operator_reference: OPERATOR_REFERENCE_CANARY,
        reason: OPERATOR_REASON_CANARY,
    }
}

fn retry_request(occurrence_id: Uuid, expected_attempt_count: u32) -> TimerRetryRequest<'static> {
    TimerRetryRequest {
        occurrence_id,
        expected_attempt_count,
        operator_reference: OPERATOR_REFERENCE_CANARY,
        reason: OPERATOR_REASON_CANARY,
    }
}

fn assert_operator_audit_pairs(
    entries: &[serde_json::Value],
    expected: &[(&str, &str)],
    additional_forbidden: &[&str],
) -> Result<(), String> {
    let operator_entries = entries
        .iter()
        .filter(|entry| entry["schema"] == TIMER_OPERATOR_AUDIT_SCHEMA)
        .collect::<Vec<_>>();
    if operator_entries.len() != expected.len() * 2 {
        return Err(format!(
            "timer operator audit pair count differed: expected={}, actual={}",
            expected.len() * 2,
            operator_entries.len()
        ));
    }
    for (pair, (operation, outcome)) in operator_entries.chunks_exact(2).zip(expected) {
        if pair[0]["phase"] != "request"
            || pair[0]["record"]["phase"] != "request"
            || pair[0]["record"]["outcome"] != "started"
            || pair[1]["phase"] != "response"
            || pair[1]["record"]["phase"] != "response"
            || pair[1]["record"]["outcome"] != *outcome
            || pair[0]["record"]["operationId"] != *operation
            || pair[1]["record"]["operationId"] != *operation
            || pair[0]["correlation"] != pair[1]["correlation"]
        {
            return Err(format!(
                "timer operator audit pair was not exact: operation={operation}, outcome={outcome}, pair={pair:?}"
            ));
        }
        let request_record = &pair[0]["record"];
        let response_record = &pair[1]["record"];
        for field in ["operatorReference", "reasonReference"] {
            let Some(reference) = request_record[field].as_str() else {
                return Err(format!(
                    "timer operator audit request omitted keyed {field}: {request_record:?}"
                ));
            };
            if reference.is_empty() || response_record[field] != reference {
                return Err(format!(
                    "timer operator audit did not preserve keyed {field} across the pair: {pair:?}"
                ));
            }
        }
        if request_record["operatorReference"] == request_record["reasonReference"] {
            return Err(format!(
                "timer operator audit did not domain-separate its keyed references: {pair:?}"
            ));
        }
        let occurrence_reference = request_record.get("occurrenceReference");
        if *operation == "breg.timer.retry" {
            let Some(reference) = occurrence_reference.and_then(serde_json::Value::as_str) else {
                return Err(format!(
                    "timer retry audit omitted its keyed occurrence reference: {pair:?}"
                ));
            };
            if reference.is_empty() || response_record["occurrenceReference"] != reference {
                return Err(format!(
                    "timer retry audit did not preserve its keyed occurrence reference: {pair:?}"
                ));
            }
        } else if occurrence_reference.is_some()
            || response_record.get("occurrenceReference").is_some()
        {
            return Err(format!(
                "timer control audit unexpectedly exposed an occurrence reference: {pair:?}"
            ));
        }
        let result = response_record
            .get("result")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                format!("timer operator audit response omitted its closed result: {pair:?}")
            })?;
        let result_keys = result.keys().map(String::as_str).collect::<BTreeSet<_>>();
        let expected_result_keys = if *outcome == "refused" {
            BTreeSet::from(["problemCode"])
        } else if *operation == "breg.timer.retry" {
            BTreeSet::from(["attemptCount", "controlEpoch", "retryAllowance", "state"])
        } else {
            BTreeSet::from(["changed", "controlEpoch", "previousControlEpoch", "state"])
        };
        if result_keys != expected_result_keys {
            return Err(format!(
                "timer operator audit response used a non-closed result vocabulary: {pair:?}"
            ));
        }
    }
    let rendered = serde_json::to_string(&operator_entries)
        .map_err(|_| "timer operator audit entries did not serialize".to_owned())?;
    for forbidden in [OPERATOR_REFERENCE_CANARY, OPERATOR_REASON_CANARY]
        .into_iter()
        .chain(additional_forbidden.iter().copied())
    {
        if rendered.contains(forbidden) {
            return Err("timer operator audit disclosed a raw value canary".to_owned());
        }
    }
    if rendered.contains("\"outcome\":\"unfinished\"") {
        return Err("timer operator audit left an accepted request unfinished".to_owned());
    }
    Ok(())
}

fn assert_pending_detail(detail: &TimerOccurrenceDetail) -> Result<(), String> {
    if detail.summary.state != TimerOccurrenceState::Pending
        || detail.summary.attempt_count != 0
        || detail.summary.outcome_code.is_some()
        || !detail.summary.detail_available
        || !detail.attempts.is_empty()
        || detail.attempts_truncated
        || detail.claim_epoch.is_some()
        || detail.receipt_reference.is_some()
    {
        return Err(format!(
            "pending timer operator detail was not exact and value-free: {detail:?}"
        ));
    }
    Ok(())
}

fn assert_completed_detail(detail: &TimerOccurrenceDetail) -> Result<(), String> {
    if detail.summary.state != TimerOccurrenceState::Completed
        || detail.summary.attempt_count != 1
        || detail.summary.outcome_code != Some(TimerOutcomeCode::Completed)
        || !detail.summary.detail_available
        || detail.attempts.len() != 1
        || detail.attempts[0].attempt != 1
        || detail.attempts[0].outcome_code != Some(TimerOutcomeCode::Completed)
        || detail.attempts[0].finished_at.is_none()
        || detail.attempts_truncated
        || detail.claim_epoch.is_none()
        || detail.receipt_reference.is_none()
    {
        return Err(format!(
            "completed timer operator detail was not exact and value-free: {detail:?}"
        ));
    }
    let finished_at = detail.attempts[0]
        .finished_at
        .as_ref()
        .ok_or_else(|| "completed timer attempt omitted its finish time".to_owned())?;
    if detail.attempts[0].started_at > *finished_at {
        return Err(format!(
            "completed timer attempt finished before it started under the live database clock: {detail:?}"
        ));
    }
    Ok(())
}

fn assert_value_free<T: Serialize>(
    value: &T,
    pending_record_id: &str,
    completed_record_id: &str,
    label: &str,
) -> Result<(), String> {
    let encoded = serde_json::to_string(value)
        .map_err(|_| format!("timer operator {label} did not serialize"))?;
    if encoded.len() > 64 * 1024 {
        return Err(format!(
            "timer operator {label} exceeded the acceptance output bound"
        ));
    }
    for forbidden in [
        pending_record_id,
        completed_record_id,
        DESCRIPTION_CANARY,
        JURISDICTION_CANARY,
        "scheduled",
        "active",
        "activationRevision",
    ] {
        if encoded.contains(forbidden) {
            return Err(format!(
                "timer operator {label} disclosed a Record value canary"
            ));
        }
    }
    Ok(())
}

async fn finish_result(harness: NativeTimerHarness, result: Result<(), String>) {
    report_identity(&harness.run_identity());
    let retained = harness.finish(result.is_ok()).await;
    match (result, retained) {
        (Ok(()), Ok(None)) => {}
        (Ok(()), Ok(Some(path))) => panic!(
            "successful native timer operator journey unexpectedly retained {}",
            path.display()
        ),
        (Err(error), Ok(Some(path))) => panic!(
            "{error}; bounded native-process logs retained at {}",
            path.display()
        ),
        (Err(error), Ok(None)) => panic!("{error}"),
        (result, Err(cleanup)) => panic!("native timer operator result {result:?}; {cleanup}"),
    }
}

fn report_identity(identity: &NativeRunIdentity) {
    println!(
        "record-timer-operator package_id={} package_digest={}",
        identity.package_id, identity.package_digest
    );
    for process in &identity.processes {
        println!(
            "record-timer-operator instance_id={} replica_id={} launch_id={} pid={} executable={} arguments={:?}",
            process.instance_id,
            process.replica_id,
            process.launch_id,
            process.pid,
            process.executable.display(),
            process.arguments
        );
    }
}
