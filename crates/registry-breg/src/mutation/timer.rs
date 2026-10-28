// SPDX-License-Identifier: Apache-2.0

//! Transactional record-timer staging and exact system Action authority.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::field_encryption::{open_member_value, FieldEncryptionService};
use crate::model::{
    CompiledAction, CompiledEntity, CompiledPlanMutation, CompiledPlanTargetBinding,
    CompiledRegistry, CompiledTimer, CompiledTimerInput, CompiledTimerValue,
};
use crate::postgres::ActionClaimContext;

use super::{CurrentRow, MutationError};

pub(crate) const TIMER_PRINCIPAL: &str = "urn:registrystack:breg:system:record-timer";
pub(crate) const TIMER_ACCESS_PROFILE: &str = "system-record-timer";
pub(crate) const MAX_AUTOMATIC_TIMER_ATTEMPTS: i32 = 5;

#[cfg(feature = "postgres-test")]
const TIMER_TEST_BARRIER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(feature = "postgres-test")]
pub(crate) async fn wait_at_timer_test_barrier(
    observed: &tokio::sync::Notify,
    resume: &tokio::sync::Notify,
) -> Result<(), MutationError> {
    observed.notify_one();
    tokio::time::timeout(TIMER_TEST_BARRIER_TIMEOUT, resume.notified())
        .await
        .map_err(|_| MutationError::Unavailable)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimerAdmission {
    Proceed,
    Hold,
    Missed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimerRefusalOutcome {
    DeclaredRefusal,
    InputRefused,
    EffectConflict,
}

impl TimerRefusalOutcome {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DeclaredRefusal => "declared-refusal",
            Self::InputRefused => "input-refused",
            Self::EffectConflict => "effect-conflict",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimerActionDisposition {
    Applied,
    Held,
    Missed,
    Refused(TimerRefusalOutcome),
}

#[cfg(feature = "postgres-test")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeTimerCheckpointPhase {
    AfterClaim,
    BeforeCommit,
    AfterCommitBeforeResponseRelease,
    BeforeOutcomeSettlement,
}

#[cfg(feature = "postgres-test")]
#[derive(Clone)]
pub(crate) struct NativeTimerCheckpoint {
    phase: NativeTimerCheckpointPhase,
    instance_id: String,
    observed_path: std::path::PathBuf,
    release_path: std::path::PathBuf,
}

#[cfg(feature = "postgres-test")]
impl NativeTimerCheckpoint {
    pub(crate) fn new(
        phase: NativeTimerCheckpointPhase,
        instance_id: &str,
        observed_path: std::path::PathBuf,
        release_path: std::path::PathBuf,
    ) -> Self {
        Self {
            phase,
            instance_id: instance_id.to_owned(),
            observed_path,
            release_path,
        }
    }

    pub(crate) async fn observe_and_wait(
        &self,
        phase: NativeTimerCheckpointPhase,
        occurrence_id: Uuid,
    ) -> Result<(), MutationError> {
        if self.phase != phase {
            return Ok(());
        }
        let marker = canonicalize_json(&json!({
            "instanceId": self.instance_id,
            "occurrenceId": occurrence_id,
            "processId": std::process::id(),
        }))
        .map_err(|_| MutationError::Unavailable)?;
        let parent = self
            .observed_path
            .parent()
            .ok_or(MutationError::Unavailable)?;
        let name = self
            .observed_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(MutationError::Unavailable)?;
        let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| MutationError::Unavailable)?;
        {
            use std::io::Write as _;
            file.write_all(&marker)
                .map_err(|_| MutationError::Unavailable)?;
        }
        file.sync_all().map_err(|_| MutationError::Unavailable)?;
        std::fs::rename(&temporary, &self.observed_path).map_err(|_| MutationError::Unavailable)?;
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                match std::fs::symlink_metadata(&self.release_path) {
                    Ok(metadata) if metadata.file_type().is_file() => return Ok(()),
                    Ok(_) => return Err(MutationError::Unavailable),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                    Err(_) => return Err(MutationError::Unavailable),
                }
            }
        })
        .await
        .map_err(|_| MutationError::Unavailable)?
    }
}

/// The timer-control lock is always taken after the package activation lock
/// and before any current-record or generation lock.
pub(crate) async fn lock_timer_control(
    transaction: &Transaction<'_>,
) -> Result<i64, MutationError> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock_shared(
                 pg_catalog.hashtextextended('breg/record-timer-control/v1', 0)
             )",
            &[],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    transaction
        .query_one(
            "SELECT control_epoch
               FROM registry_internal.registry_record_timer_control
              WHERE singleton AND protocol_version=1",
            &[],
        )
        .await
        .map(|row| row.get(0))
        .map_err(|_| MutationError::Unavailable)
}

/// Stage material timer identity from the current record image in the same
/// transaction as the ordinary mutation. Predicate-only changes deliberately
/// do not rearm or replace a generation.
#[derive(Clone, Debug)]
pub(crate) struct TimerMutationOrigin {
    firing: Option<FiringTimerOrigin>,
}

#[derive(Clone, Debug)]
struct FiringTimerOrigin {
    record_type: String,
    record_id: Uuid,
    timer_id: String,
    occurrence_id: Uuid,
}

impl TimerMutationOrigin {
    pub(crate) const fn ordinary() -> Self {
        Self { firing: None }
    }

    pub(crate) fn firing(authority: &TimerActionAuthority) -> Self {
        Self {
            firing: Some(FiringTimerOrigin {
                record_type: authority.timer.record_type.clone(),
                record_id: authority.record_id,
                timer_id: authority.timer.id.clone(),
                occurrence_id: authority.occurrence_id,
            }),
        }
    }

    fn exact_firing_timer(
        &self,
        entity: &CompiledEntity,
        current: &CurrentRow,
        timer: &CompiledTimer,
    ) -> bool {
        self.firing.as_ref().is_some_and(|firing| {
            firing.record_type == entity.id
                && firing.record_id == current.record_uuid
                && firing.timer_id == timer.id
        })
    }

    fn refuses_new_generation(&self) -> bool {
        self.firing.is_some()
    }
}

pub(crate) struct RecordTimerStaging {
    activation_id: Uuid,
    detail_retention_days: u16,
    entity_ids: BTreeSet<String>,
    origin: TimerMutationOrigin,
}

pub(crate) struct RecordTimerStage<'a> {
    entity: &'a CompiledEntity,
    current: &'a CurrentRow,
}

impl<'a> RecordTimerStage<'a> {
    pub(crate) const fn new(entity: &'a CompiledEntity, current: &'a CurrentRow) -> Self {
        Self { entity, current }
    }
}

#[derive(Clone, Debug)]
struct CurrentTimerMarker {
    occurrence_id: Uuid,
    binding_incarnation: i64,
    material_signature: String,
    state: String,
}

pub(crate) fn timer_target_binding_prefix(input_id: &str, target_entity_id: &str) -> String {
    format!(
        "breg/record-timer-target-binding/v1\n{}\n{}\n{}\n{}\n",
        input_id.len(),
        input_id,
        target_entity_id.len(),
        target_entity_id
    )
}

pub(crate) fn timer_create_target_prefix(
    action_revision: &str,
    effect_id: &str,
    target_entity_id: &str,
) -> String {
    format!(
        "breg/record-timer-create/v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
        action_revision.len(),
        action_revision,
        effect_id.len(),
        effect_id,
        target_entity_id.len(),
        target_entity_id,
    )
}

pub(crate) fn timer_create_target_id(
    occurrence_id: Uuid,
    action_revision: &str,
    effect_id: &str,
    target_entity_id: &str,
) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(timer_create_target_prefix(
        action_revision,
        effect_id,
        target_entity_id,
    ));
    digest.update(occurrence_id.hyphenated().to_string());
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x0f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn timer_target_binding_digest(input_id: &str, target_entity_id: &str, record_id: Uuid) -> String {
    let mut digest = Sha256::new();
    digest.update(timer_target_binding_prefix(input_id, target_entity_id));
    digest.update(record_id.to_string());
    hex::encode(digest.finalize())
}

fn timer_target_binding_digests(
    timer: &CompiledTimer,
    current: &CurrentRow,
) -> Result<Value, MutationError> {
    let targets = timer
        .system_grant
        .targets
        .iter()
        .filter(|target| target.operation == crate::contract::Operation::Get)
        .map(|target| target.entity_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut bindings = Map::new();
    for (input_id, mapping) in &timer.input {
        let value = match mapping {
            CompiledTimerInput::RecordId => Some(Value::String(current.record_id.clone())),
            CompiledTimerInput::Field { field } => current.data.get(field).cloned(),
            CompiledTimerInput::Literal { value } => Some(value.clone()),
            CompiledTimerInput::Timer { .. } => None,
        };
        let Some(record_id) = value
            .as_ref()
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            continue;
        };
        let mut input_targets = Map::new();
        for target in &targets {
            input_targets.insert(
                (*target).to_owned(),
                Value::String(timer_target_binding_digest(input_id, target, record_id)),
            );
        }
        if !input_targets.is_empty() {
            bindings.insert(input_id.clone(), Value::Object(input_targets));
        }
    }
    Ok(Value::Object(bindings))
}

pub(crate) async fn begin_record_timer_staging<'a>(
    transaction: &Transaction<'_>,
    entities: impl IntoIterator<Item = &'a CompiledEntity>,
    activation_id: &str,
    detail_retention_days: u16,
    origin: TimerMutationOrigin,
) -> Result<Option<RecordTimerStaging>, MutationError> {
    let entity_ids = entities
        .into_iter()
        .filter(|entity| !entity.timers.is_empty())
        .map(|entity| entity.id.clone())
        .collect::<BTreeSet<_>>();
    if entity_ids.is_empty() {
        return Ok(None);
    }
    lock_timer_control(transaction).await?;
    let activation_id = Uuid::parse_str(activation_id).map_err(|_| MutationError::Unavailable)?;
    Ok(Some(RecordTimerStaging {
        activation_id,
        detail_retention_days,
        entity_ids,
        origin,
    }))
}

pub(crate) async fn stage_record_timer_rows<'a>(
    transaction: &Transaction<'_>,
    admission: Option<&RecordTimerStaging>,
    rows: impl IntoIterator<Item = RecordTimerStage<'a>>,
    field_encryption: Option<&FieldEncryptionService>,
) -> Result<(), MutationError> {
    let mut ordered = BTreeMap::new();
    for row in rows {
        let key = (row.entity.id.clone(), row.current.record_uuid);
        if ordered.insert(key, row).is_some() {
            return Err(MutationError::Unavailable);
        }
    }
    if admission.is_none() {
        return if ordered.values().all(|row| row.entity.timers.is_empty()) {
            Ok(())
        } else {
            Err(MutationError::Unavailable)
        };
    }
    let admission = admission.ok_or(MutationError::Unavailable)?;
    for row in ordered.into_values() {
        if row.entity.timers.is_empty() {
            continue;
        }
        if !admission.entity_ids.contains(&row.entity.id) {
            return Err(MutationError::Unavailable);
        }
        stage_record_timers(
            transaction,
            row.entity,
            row.current,
            admission.activation_id,
            admission.detail_retention_days,
            &admission.origin,
            field_encryption,
        )
        .await?;
    }
    Ok(())
}

async fn load_current_timer_marker(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    timer_id: &str,
) -> Result<Option<CurrentTimerMarker>, MutationError> {
    let Some(row) = transaction
        .query_opt(
            "SELECT occurrence_id,binding_incarnation,material_signature
               FROM registry_internal.registry_record_timer_current
              WHERE record_type=$1 AND record_id=$2 AND timer_id=$3
              FOR UPDATE",
            &[&entity_id, &record_id, &timer_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
    else {
        return Ok(None);
    };
    let occurrence_id = row.get(0);
    let binding_incarnation = row.get(1);
    let material_signature = row.get(2);
    let state = transaction
        .query_opt(
            "SELECT state
               FROM registry_internal.registry_record_timer_generations
              WHERE record_type=$1 AND record_id=$2 AND timer_id=$3
                AND occurrence_id=$4 AND binding_incarnation=$5 AND material_signature=$6
              FOR UPDATE",
            &[
                &entity_id,
                &record_id,
                &timer_id,
                &occurrence_id,
                &binding_incarnation,
                &material_signature,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::Unavailable)?
        .get(0);
    Ok(Some(CurrentTimerMarker {
        occurrence_id,
        binding_incarnation,
        material_signature,
        state,
    }))
}

// The settlement call spells out every durable fence and terminal value at
// each transition site so none can be silently inherited from mutable state.
#[allow(clippy::too_many_arguments)]
async fn settle_staged_current_marker(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    timer_id: &str,
    marker: &CurrentTimerMarker,
    state: &str,
    outcome_code: &str,
    detail_retention_days: u16,
) -> Result<(), MutationError> {
    transaction
        .execute(
            "UPDATE registry_internal.registry_record_timer_generations
                SET state=$7,block_kind=NULL,outcome_code=$8,retry_at=NULL,
                    claim_owner_id=NULL,claim_token=NULL,claim_until=NULL,
                    claimed_control_epoch=NULL,claimed_instance_epoch=NULL,
                    claimed_activation_id=NULL,completed_at=statement_timestamp(),
                    detail_expires_at=statement_timestamp()+$9::bigint*interval '1 day',
                    updated_at=clock_timestamp()
              WHERE record_type=$1 AND record_id=$2 AND timer_id=$3
                AND occurrence_id=$4 AND binding_incarnation=$5 AND material_signature=$6
                AND state IN ('pending','leased','blocked')",
            &[
                &entity_id,
                &record_id,
                &timer_id,
                &marker.occurrence_id,
                &marker.binding_incarnation,
                &marker.material_signature,
                &state,
                &outcome_code,
                &i64::from(detail_retention_days),
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    Ok(())
}

async fn stage_record_timers(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    current: &CurrentRow,
    activation_id: Uuid,
    detail_retention_days: u16,
    origin: &TimerMutationOrigin,
    field_encryption: Option<&FieldEncryptionService>,
) -> Result<(), MutationError> {
    if entity.timers.is_empty() {
        return Ok(());
    }
    for timer in entity.timers.values() {
        if timer.record_type != entity.id {
            return Err(MutationError::Unavailable);
        }
        let binding = transaction
            .query_opt(
                "SELECT incarnation
                   FROM registry_internal.registry_record_timer_bindings
                  WHERE record_type=$1 AND timer_id=$2
                    AND removed_activation_id IS NULL
                    AND current_policy_activation_id=$3
                    AND definition_revision=$4 AND action_revision=$5
                    AND system_grant_revision=$6",
                &[
                    &entity.id,
                    &timer.id,
                    &activation_id,
                    &timer.definition_revision,
                    &timer.action_revision,
                    &timer.system_grant.revision,
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .ok_or(MutationError::Unavailable)?;
        let binding_incarnation: i64 = binding.get(0);
        let marker =
            load_current_timer_marker(transaction, &entity.id, current.record_uuid, &timer.id)
                .await?;
        let target_binding_digests = timer_target_binding_digests(timer, current)?;
        if current.record_lifecycle != "active" {
            if origin.exact_firing_timer(entity, current, timer) {
                ensure_exact_firing_marker(transaction, origin).await?;
                continue;
            }
            if let Some(marker) = &marker {
                settle_staged_current_marker(
                    transaction,
                    &entity.id,
                    current.record_uuid,
                    &timer.id,
                    marker,
                    "cancelled",
                    "anchor-tombstoned",
                    detail_retention_days,
                )
                .await?;
            }
            continue;
        }
        let Some(at) = timestamp_field(&current.data, &timer.at)? else {
            if origin.exact_firing_timer(entity, current, timer) {
                ensure_exact_firing_marker(transaction, origin).await?;
                continue;
            }
            if let Some(marker) = &marker {
                settle_staged_current_marker(
                    transaction,
                    &entity.id,
                    current.record_uuid,
                    &timer.id,
                    marker,
                    "cancelled",
                    "control-cleared",
                    detail_retention_days,
                )
                .await?;
            }
            continue;
        };
        let not_after = timer
            .not_after
            .as_deref()
            .map(|field| timestamp_field(&current.data, field))
            .transpose()?
            .flatten();
        let before_controls = current
            .before_data
            .as_ref()
            .map(|before| {
                let before_at = timestamp_field(before, &timer.at)?;
                let before_not_after = timer
                    .not_after
                    .as_deref()
                    .map(|field| timestamp_field(before, field))
                    .transpose()?
                    .flatten();
                let before_rearm = timer
                    .rearm_on
                    .as_ref()
                    .and_then(|field| before.get(field))
                    .cloned()
                    .unwrap_or(Value::Null);
                Ok::<_, MutationError>((before_at, before_not_after, before_rearm))
            })
            .transpose()?;
        let gate_data =
            materialize_timer_predicate_fields(entity, current, timer, field_encryption)?;
        let gate_open = timer
            .when
            .as_ref()
            .is_none_or(|predicate| predicate.matches(&gate_data));
        let rearm = timer
            .rearm_on
            .as_ref()
            .and_then(|field| current.data.get(field))
            .cloned()
            .unwrap_or(Value::Null);
        let controls_unchanged =
            before_controls
                .as_ref()
                .is_some_and(|(before_at, before_not_after, before_rearm)| {
                    *before_at == Some(at)
                        && *before_not_after == not_after
                        && *before_rearm == rearm
                });
        if not_after.is_some_and(|end| end <= at) && !controls_unchanged {
            return Err(MutationError::InvalidTimerWindow {
                at_field: timer.at.clone(),
                not_after_field: timer.not_after.clone().ok_or(MutationError::Unavailable)?,
            });
        }
        let signature = material_signature(at, not_after, &rearm)?;
        if let Some((before_at, before_not_after, before_rearm)) = before_controls {
            let before_signature = before_at
                .map(|value| material_signature(value, before_not_after, &before_rearm))
                .transpose()?;
            if before_signature.as_deref() == Some(signature.as_str()) {
                let Some(marker) = &marker else {
                    continue;
                };
                if marker.material_signature != signature {
                    if matches!(
                        marker.state.as_str(),
                        "blocked" | "completed" | "refused" | "cancelled" | "superseded" | "missed"
                    ) {
                        continue;
                    }
                    return Err(MutationError::Unavailable);
                }
                if marker.binding_incarnation != binding_incarnation {
                    let retired = transaction
                        .query_opt(
                            "SELECT 1
                               FROM registry_internal.registry_record_timer_bindings
                              WHERE record_type=$1 AND timer_id=$2 AND incarnation=$3
                                AND removed_activation_id IS NOT NULL",
                            &[&entity.id, &timer.id, &marker.binding_incarnation],
                        )
                        .await
                        .map_err(|_| MutationError::Unavailable)?;
                    if retired.is_none() {
                        return Err(MutationError::Unavailable);
                    }
                    continue;
                }
                transaction
                    .execute(
                        "UPDATE registry_internal.registry_record_timer_generations
                            SET gate_open=$7,target_binding_digests=$8,updated_at=clock_timestamp()
                          WHERE record_type=$1 AND record_id=$2 AND timer_id=$3
                            AND occurrence_id=$4 AND binding_incarnation=$5
                            AND material_signature=$6
                            AND state IN ('pending','leased','blocked')",
                        &[
                            &entity.id,
                            &current.record_uuid,
                            &timer.id,
                            &marker.occurrence_id,
                            &binding_incarnation,
                            &signature,
                            &gate_open,
                            &target_binding_digests,
                        ],
                    )
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
                continue;
            }
        }
        if origin.refuses_new_generation() {
            return Err(MutationError::TimerGenerationUnsupported);
        }
        let occurrence_id = Uuid::new_v4();
        if let Some(marker) = &marker {
            settle_staged_current_marker(
                transaction,
                &entity.id,
                current.record_uuid,
                &timer.id,
                marker,
                "superseded",
                "superseded",
                detail_retention_days,
            )
            .await?;
        }
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_record_timer_generations (
                     record_type,record_id,timer_id,occurrence_id,binding_incarnation,material_signature,
                     due_at,not_after,definition_revision,action_revision,
                     system_grant_revision,gate_open,target_binding_digests,state,created_activation_id,
                     current_policy_activation_id
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending',$14,$14)",
                &[
                    &entity.id,
                    &current.record_uuid,
                    &timer.id,
                    &occurrence_id,
                    &binding_incarnation,
                    &signature,
                    &at,
                    &not_after,
                    &timer.definition_revision,
                    &timer.action_revision,
                    &timer.system_grant.revision,
                    &gate_open,
                    &target_binding_digests,
                    &activation_id,
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_record_timer_current (
                     record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                     material_signature
                 ) VALUES ($1,$2,$3,$4,$5,$6)
                 ON CONFLICT (record_type,record_id,timer_id) DO UPDATE SET
                     occurrence_id=EXCLUDED.occurrence_id,
                     binding_incarnation=EXCLUDED.binding_incarnation,
                     material_signature=EXCLUDED.material_signature,
                     updated_at=clock_timestamp()",
                &[
                    &entity.id,
                    &current.record_uuid,
                    &timer.id,
                    &occurrence_id,
                    &binding_incarnation,
                    &signature,
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
    }
    Ok(())
}

fn materialize_timer_predicate_fields(
    entity: &CompiledEntity,
    current: &CurrentRow,
    timer: &CompiledTimer,
    field_encryption: Option<&FieldEncryptionService>,
) -> Result<Map<String, Value>, MutationError> {
    let mut data = current.data.clone();
    for field_id in &timer.predicate_fields {
        let field = entity
            .fields
            .get(field_id)
            .ok_or(MutationError::Unavailable)?;
        if field.encryption.is_none() {
            continue;
        }
        let Some(member) = data.get_mut(field_id) else {
            continue;
        };
        let service = field_encryption.ok_or(MutationError::FieldEncryptionUnavailable)?;
        *member = open_member_value(
            service,
            &entity.id,
            &field.id,
            &current.record_id,
            &field.field_type,
            member,
        )
        .map_err(|_| MutationError::FieldEncryptionUnavailable)?
        .unwrap_or(Value::Null);
    }
    Ok(data)
}

async fn ensure_exact_firing_marker(
    transaction: &Transaction<'_>,
    origin: &TimerMutationOrigin,
) -> Result<(), MutationError> {
    let firing = origin.firing.as_ref().ok_or(MutationError::Unavailable)?;
    let matches: bool = transaction
        .query_one(
            "SELECT EXISTS (
                 SELECT 1
                   FROM registry_internal.registry_record_timer_current
                  WHERE record_type=$1 AND record_id=$2 AND timer_id=$3
                    AND occurrence_id=$4
             )",
            &[
                &firing.record_type,
                &firing.record_id,
                &firing.timer_id,
                &firing.occurrence_id,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .get(0);
    if !matches {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

fn timestamp_field(
    record: &Map<String, Value>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, MutationError> {
    let Some(value) = record.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = value.as_str().ok_or(MutationError::Unavailable)?;
    DateTime::parse_from_rfc3339(text)
        .map(|parsed| Some(parsed.with_timezone(&Utc)))
        .map_err(|_| MutationError::Unavailable)
}

fn material_signature(
    at: DateTime<Utc>,
    not_after: Option<DateTime<Utc>>,
    rearm: &Value,
) -> Result<String, MutationError> {
    let rearm = if rearm.is_null() {
        json!({"kind":"none"})
    } else if let Some(value) = rearm.as_i64() {
        json!({"kind":"int64","value":value.to_string()})
    } else if let Some(value) = rearm.as_str() {
        json!({"kind":"uuid","value":value})
    } else {
        return Err(MutationError::Unavailable);
    };
    let payload = json!({
        "at":at.to_rfc3339(),
        "notAfter":not_after.map(|v|v.to_rfc3339()),
        "rearmOn":rearm
    });
    let bytes = canonicalize_json(&payload).map_err(|_| MutationError::Unavailable)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

pub(crate) struct RefreshedTimerMetadata {
    pub(crate) due_at: DateTime<Utc>,
    pub(crate) not_after: Option<DateTime<Utc>>,
    pub(crate) material_signature: String,
    pub(crate) gate_open: bool,
    pub(crate) target_binding_digests: Value,
    pub(crate) configuration_blocked: bool,
}

pub(crate) fn refreshed_timer_metadata(
    entity: &CompiledEntity,
    timer: &CompiledTimer,
    record_id: Uuid,
    data: Map<String, Value>,
    field_encryption: Option<&FieldEncryptionService>,
) -> Result<Option<RefreshedTimerMetadata>, MutationError> {
    if timer.record_type != entity.id {
        return Err(MutationError::Unavailable);
    }
    let current = CurrentRow {
        record_uuid: record_id,
        record_id: record_id.to_string(),
        record_revision: 1,
        predecessor_revision: None,
        record_lifecycle: "active".to_owned(),
        before_data: None,
        data,
    };
    let Some(due_at) = timestamp_field(&current.data, &timer.at)? else {
        return Ok(None);
    };
    let not_after = timer
        .not_after
        .as_deref()
        .map(|field| timestamp_field(&current.data, field))
        .transpose()?
        .flatten();
    let configuration_blocked = not_after.is_some_and(|end| end <= due_at);
    let gate_data = materialize_timer_predicate_fields(entity, &current, timer, field_encryption)?;
    let gate_open = timer
        .when
        .as_ref()
        .is_none_or(|predicate| predicate.matches(&gate_data));
    let rearm = timer
        .rearm_on
        .as_ref()
        .and_then(|field| current.data.get(field))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(Some(RefreshedTimerMetadata {
        due_at,
        not_after,
        material_signature: material_signature(due_at, not_after, &rearm)?,
        gate_open,
        target_binding_digests: timer_target_binding_digests(timer, &current)?,
        configuration_blocked,
    }))
}

/// One claimed generation bound to the exact package-owned Action ceiling.
#[derive(Clone)]
pub(crate) struct TimerActionAuthority {
    pub(crate) timer: CompiledTimer,
    pub(crate) occurrence_id: Uuid,
    pub(crate) record_id: Uuid,
    pub(crate) claim_token: Uuid,
    pub(crate) claim_owner_id: Uuid,
    pub(crate) claim_epoch: i64,
    pub(crate) due_at: DateTime<Utc>,
    pub(crate) not_after: Option<DateTime<Utc>>,
    pub(crate) control_epoch: i64,
    pub(crate) instance_epoch: i64,
    pub(crate) activation_id: Uuid,
    detail_retention_days: u16,
    claims: ActionClaimContext,
    #[cfg(feature = "postgres-test")]
    database_clock_fixture: bool,
    #[cfg(feature = "postgres-test")]
    native_checkpoint: Option<NativeTimerCheckpoint>,
    #[cfg(feature = "postgres-test")]
    preflight_barrier: Option<(
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    )>,
}

impl TimerActionAuthority {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        registry: &CompiledRegistry,
        timer: &CompiledTimer,
        occurrence_id: Uuid,
        record_id: Uuid,
        claim_token: Uuid,
        claim_owner_id: Uuid,
        claim_epoch: i64,
        due_at: DateTime<Utc>,
        not_after: Option<DateTime<Utc>>,
        control_epoch: i64,
        instance_epoch: i64,
        activation_id: Uuid,
        detail_retention_days: u16,
    ) -> Result<Self, MutationError> {
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == timer.invoke)
            .ok_or(MutationError::Unavailable)?;
        if !matches!(
            action.execution,
            crate::model::CompiledActionExecution::Immediate
        ) || action.definition_revision != timer.action_revision
            || timer.system_grant.action_id != action.id
            || timer.system_grant.action_revision != action.definition_revision
            || !valid_live_timer_claim(
                occurrence_id,
                record_id,
                claim_token,
                claim_owner_id,
                claim_epoch,
                control_epoch,
                instance_epoch,
            )
        {
            return Err(MutationError::Unavailable);
        }
        let claims = ActionClaimContext::new(
            action.id.clone(),
            TIMER_PRINCIPAL.to_owned(),
            TIMER_ACCESS_PROFILE.to_owned(),
            None,
            BTreeSet::new(),
        )
        .map_err(|_| MutationError::Unavailable)?;
        Ok(Self {
            timer: timer.clone(),
            occurrence_id,
            record_id,
            claim_token,
            claim_owner_id,
            claim_epoch,
            due_at,
            not_after,
            control_epoch,
            instance_epoch,
            activation_id,
            detail_retention_days,
            claims,
            #[cfg(feature = "postgres-test")]
            database_clock_fixture: false,
            #[cfg(feature = "postgres-test")]
            native_checkpoint: None,
            #[cfg(feature = "postgres-test")]
            preflight_barrier: None,
        })
    }

    #[cfg(feature = "postgres-test")]
    pub(crate) fn with_database_clock_fixture_for_test(mut self) -> Self {
        self.database_clock_fixture = true;
        self
    }

    pub(crate) fn database_clock_sql<'a>(&self, sql: &'a str) -> Cow<'a, str> {
        #[cfg(feature = "postgres-test")]
        {
            if self.database_clock_fixture {
                return Cow::Owned(
                    sql.replace(
                        "clock_timestamp()",
                        "registry_internal.record_timer_clock_fixture_now()",
                    )
                    .replace(
                        "statement_timestamp()",
                        "registry_internal.record_timer_clock_fixture_now()",
                    ),
                );
            }
        }
        Cow::Borrowed(sql)
    }

    #[cfg(feature = "postgres-test")]
    pub(crate) fn with_native_checkpoint(
        mut self,
        checkpoint: Option<NativeTimerCheckpoint>,
    ) -> Self {
        self.native_checkpoint = checkpoint;
        self
    }

    #[cfg(feature = "postgres-test")]
    pub(crate) async fn wait_at_native_checkpoint(
        &self,
        phase: NativeTimerCheckpointPhase,
    ) -> Result<(), MutationError> {
        match &self.native_checkpoint {
            Some(checkpoint) => checkpoint.observe_and_wait(phase, self.occurrence_id).await,
            None => Ok(()),
        }
    }

    #[cfg(feature = "postgres-test")]
    pub(crate) fn with_preflight_barrier(
        mut self,
        barrier: Option<(
            std::sync::Arc<tokio::sync::Notify>,
            std::sync::Arc<tokio::sync::Notify>,
        )>,
    ) -> Self {
        self.preflight_barrier = barrier;
        self
    }

    #[cfg(feature = "postgres-test")]
    pub(crate) async fn wait_after_preflight(&self) -> Result<(), MutationError> {
        if let Some((observed, resume)) = &self.preflight_barrier {
            wait_at_timer_test_barrier(observed, resume).await?;
        }
        Ok(())
    }

    pub(crate) fn claims(&self) -> &ActionClaimContext {
        &self.claims
    }

    pub(crate) fn action<'a>(
        &self,
        registry: &'a CompiledRegistry,
    ) -> Result<&'a CompiledAction, MutationError> {
        registry
            .actions()
            .actions
            .iter()
            .find(|action| {
                action.id == self.timer.invoke
                    && action.definition_revision == self.timer.action_revision
                    && matches!(
                        action.execution,
                        crate::model::CompiledActionExecution::Immediate
                    )
            })
            .ok_or(MutationError::Unavailable)
    }

    pub(crate) fn target_authority(
        &self,
    ) -> BTreeMap<String, Vec<crate::postgres::RowBoundaryContext>> {
        self.timer
            .system_grant
            .targets
            .iter()
            .map(|target| (target.entity_id.clone(), Vec::new()))
            .collect()
    }

    pub(crate) fn anchor_read_fields(&self) -> Result<BTreeSet<String>, MutationError> {
        let mut fields = self.timer.control_fields.clone();
        fields.extend(self.timer.predicate_fields.iter().cloned());
        fields.extend(self.timer.effect_input_fields.iter().cloned());
        let grant = self
            .timer
            .system_grant
            .targets
            .iter()
            .find(|target| {
                target.entity_id == self.timer.record_type
                    && target.operation == crate::contract::Operation::Get
            })
            .ok_or(MutationError::Unavailable)?;
        if !fields.is_subset(&grant.read_fields) {
            return Err(MutationError::Unavailable);
        }
        Ok(fields)
    }

    pub(crate) fn read_fields_for_input(
        &self,
        action: &CompiledAction,
        input_id: &str,
        entity_id: &str,
    ) -> Result<BTreeSet<String>, MutationError> {
        let grant = self
            .timer
            .system_grant
            .targets
            .iter()
            .find(|target| {
                target.entity_id == entity_id && target.operation == crate::contract::Operation::Get
            })
            .ok_or(MutationError::Unavailable)?;
        let fields = action
            .target_uses
            .iter()
            .find(|target| {
                target.entity_id == entity_id
                    && target.operation == crate::contract::Operation::Get
                    && matches!(
                        &target.source,
                        crate::model::CompiledActionTargetUseSource::Input { input }
                            if input == input_id
                    )
            })
            .map(|target| target.fields.clone())
            .ok_or(MutationError::Unavailable)?;
        if !fields.is_subset(&grant.read_fields) {
            return Err(MutationError::Unavailable);
        }
        Ok(fields)
    }

    pub(crate) fn materialize_anchor_fields(
        &self,
        entity: &CompiledEntity,
        anchor: &mut CurrentRow,
        field_encryption: Option<&FieldEncryptionService>,
    ) -> Result<(), MutationError> {
        let fields = self.anchor_read_fields()?;
        self.materialize_read_fields(entity, anchor, &fields, field_encryption)
    }

    pub(crate) fn materialize_read_fields(
        &self,
        entity: &CompiledEntity,
        current: &mut CurrentRow,
        fields: &BTreeSet<String>,
        field_encryption: Option<&FieldEncryptionService>,
    ) -> Result<(), MutationError> {
        for field_id in fields {
            let Some(field) = entity.fields.get(field_id) else {
                return Err(MutationError::Unavailable);
            };
            if field.encryption.is_none() {
                continue;
            }
            let Some(member) = current.data.get_mut(field_id) else {
                continue;
            };
            let service = field_encryption.ok_or(MutationError::FieldEncryptionUnavailable)?;
            let opened = open_member_value(
                service,
                &entity.id,
                &field.id,
                &current.record_id,
                &field.field_type,
                member,
            )
            .map_err(|_| MutationError::FieldEncryptionUnavailable)?;
            *member = opened.unwrap_or(Value::Null);
        }
        Ok(())
    }

    pub(crate) fn input_values(
        &self,
        anchor: &CurrentRow,
    ) -> Result<Map<String, Value>, MutationError> {
        if anchor.record_uuid != self.record_id {
            return Err(MutationError::PreconditionFailed);
        }
        let mut values = Map::new();
        for (input, mapping) in &self.timer.input {
            let value = match mapping {
                CompiledTimerInput::RecordId => Value::String(self.record_id.to_string()),
                CompiledTimerInput::Field { field } => {
                    anchor.data.get(field).cloned().unwrap_or(Value::Null)
                }
                CompiledTimerInput::Timer {
                    value: CompiledTimerValue::OccurrenceId,
                } => Value::String(self.occurrence_id.to_string()),
                CompiledTimerInput::Timer {
                    value: CompiledTimerValue::DueAt,
                } => Value::String(
                    self.due_at
                        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                ),
                CompiledTimerInput::Literal { value } => value.clone(),
            };
            values.insert(input.clone(), value);
        }
        Ok(values)
    }

    pub(crate) fn validates_effects(
        &self,
        action: &CompiledAction,
        effects: &[&crate::model::CompiledPlanEffect],
        target_record: Uuid,
    ) -> bool {
        if action.id != self.timer.system_grant.action_id {
            return false;
        }
        effects.iter().all(|effect| {
            match effect.target.binding {
                CompiledPlanTargetBinding::Existing { .. } if target_record != self.record_id => {
                    return false;
                }
                CompiledPlanTargetBinding::Create
                    if effects.len() != 1
                        || target_record
                            != timer_create_target_id(
                                self.occurrence_id,
                                &action.definition_revision,
                                &effect.id,
                                &effect.target.entity_id,
                            ) =>
                {
                    return false;
                }
                _ => {}
            }
            let fields = effect
                .mutations
                .iter()
                .map(|mutation| match mutation {
                    CompiledPlanMutation::Set { field, .. }
                    | CompiledPlanMutation::Clear { field } => field.clone(),
                })
                .collect::<BTreeSet<_>>();
            self.timer.system_grant.targets.iter().any(|target| {
                target.entity_id == effect.target.entity_id
                    && target.operation == effect.operation
                    && fields.is_subset(&target.fields)
            })
        })
    }

    pub(crate) async fn admit_locked_anchor_and_clock(
        &self,
        transaction: &Transaction<'_>,
        anchor: &CurrentRow,
        input_values: &Map<String, Value>,
    ) -> Result<TimerAdmission, MutationError> {
        if anchor.record_uuid != self.record_id || anchor.record_lifecycle != "active" {
            return Err(MutationError::PreconditionFailed);
        }
        if self
            .timer
            .when
            .as_ref()
            .is_some_and(|predicate| !predicate.matches(&anchor.data))
        {
            return Ok(TimerAdmission::Hold);
        }
        for (input, mapping) in &self.timer.input {
            if let CompiledTimerInput::Field { field } = mapping {
                let matches = if field == &self.timer.at {
                    timestamp_field(&anchor.data, field)? == Some(self.due_at)
                } else {
                    input_values.get(input) == Some(anchor.data.get(field).unwrap_or(&Value::Null))
                };
                if !matches {
                    return Err(MutationError::RetryableConflict);
                }
            }
        }
        if timestamp_field(&anchor.data, &self.timer.at)? != Some(self.due_at) {
            return Err(MutationError::RetryableConflict);
        }
        let current_not_after = self
            .timer
            .not_after
            .as_deref()
            .map(|field| timestamp_field(&anchor.data, field))
            .transpose()?
            .flatten();
        if current_not_after != self.not_after {
            return Err(MutationError::RetryableConflict);
        }
        if current_not_after.is_some_and(|end| end <= self.due_at) {
            return Err(MutationError::PreconditionFailed);
        }
        let now_sql = self.database_clock_sql("SELECT clock_timestamp()");
        let now: DateTime<Utc> = transaction
            .query_one(now_sql.as_ref(), &[])
            .await
            .map_err(|_| MutationError::Unavailable)?
            .get(0);
        if now < self.due_at {
            return Ok(TimerAdmission::Hold);
        }
        if self.not_after.is_some_and(|end| now >= end) {
            return Ok(TimerAdmission::Missed);
        }
        Ok(TimerAdmission::Proceed)
    }

    pub(crate) async fn settle_missed(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<(), MutationError> {
        let updated = transaction
            .execute(
                self.database_clock_sql(
                    "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET state='missed', outcome_code='execution-window-expired',
                        retry_at=NULL, claim_owner_id=NULL, claim_token=NULL, claim_until=NULL,
                        claimed_control_epoch=NULL, claimed_instance_epoch=NULL,
                        claimed_activation_id=NULL, completed_at=clock_timestamp(),
                        updated_at=clock_timestamp()
                  WHERE occurrence_id=$1 AND claim_owner_id=$2 AND claim_epoch=$3
                    AND claim_token=$4 AND state='leased'
                    AND claimed_control_epoch=$5 AND claimed_instance_epoch=$6
                    AND claimed_activation_id=$7 AND system_grant_revision=$8
                    AND claim_until > clock_timestamp()
                    AND not_after IS NOT NULL AND not_after>due_at
                    AND clock_timestamp() >= not_after
                    AND EXISTS (
                        SELECT 1
                          FROM registry_internal.registry_record_timer_control AS control
                          JOIN registry_internal.registry_state AS registry ON registry.singleton
                          JOIN registry_internal.registry_record_timer_current AS current
                            ON current.occurrence_id=generation.occurrence_id
                           AND current.record_type=generation.record_type
                           AND current.record_id=generation.record_id
                           AND current.timer_id=generation.timer_id
                           AND current.binding_incarnation=generation.binding_incarnation
                           AND current.material_signature=generation.material_signature
                          JOIN registry_internal.registry_record_timer_bindings AS binding
                            ON binding.record_type=current.record_type
                           AND binding.timer_id=current.timer_id
                           AND binding.incarnation=current.binding_incarnation
                         WHERE control.singleton AND control.protocol_version=1
                           AND control.control_state='running' AND control.control_epoch=$5
                           AND control.bound_instance_epoch=$6
                           AND registry.epoch=$6 AND registry.active_activation_id=$7
                           AND binding.removed_activation_id IS NULL
                           AND binding.current_policy_activation_id=$7
                           AND binding.definition_revision=generation.definition_revision
                           AND binding.action_revision=generation.action_revision
                           AND binding.system_grant_revision=$8
                    )",
                )
                .as_ref(),
                &[
                    &self.occurrence_id,
                    &self.claim_owner_id,
                    &self.claim_epoch,
                    &self.claim_token,
                    &self.control_epoch,
                    &self.instance_epoch,
                    &self.activation_id,
                    &self.timer.system_grant.revision,
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if updated != 1 {
            return Err(MutationError::PreconditionFailed);
        }
        self.retain_terminal_detail(transaction).await?;
        Ok(())
    }

    pub(crate) async fn settle_refusal(
        &self,
        transaction: &Transaction<'_>,
        outcome: TimerRefusalOutcome,
        started_at: DateTime<Utc>,
    ) -> Result<(), MutationError> {
        let row = transaction
            .query_opt(
                self.database_clock_sql("WITH settled AS (
                     UPDATE registry_internal.registry_record_timer_generations AS generation
                        SET executed_attempt_count=executed_attempt_count+1,
                            retry_allowance=CASE
                                WHEN executed_attempt_count >= $9 THEN 0
                                ELSE retry_allowance
                            END,
                            state='refused', block_kind=NULL, outcome_code=$10,
                            retry_at=NULL, claim_owner_id=NULL, claim_token=NULL, claim_until=NULL,
                            claimed_control_epoch=NULL, claimed_instance_epoch=NULL,
                            claimed_activation_id=NULL, completed_at=clock_timestamp(),
                            updated_at=clock_timestamp()
                      WHERE occurrence_id=$1 AND claim_owner_id=$2 AND claim_epoch=$3
                        AND claim_token=$4 AND state='leased'
                        AND claimed_control_epoch=$5 AND claimed_instance_epoch=$6
                        AND claimed_activation_id=$7 AND system_grant_revision=$8
                        AND claim_until > clock_timestamp()
                        AND (executed_attempt_count < $9 OR retry_allowance=1)
                        AND EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_record_timer_control AS control
                              JOIN registry_internal.registry_state AS registry ON registry.singleton
                              JOIN registry_internal.registry_record_timer_current AS current
                                ON current.occurrence_id=generation.occurrence_id
                               AND current.record_type=generation.record_type
                               AND current.record_id=generation.record_id
                               AND current.timer_id=generation.timer_id
                               AND current.binding_incarnation=generation.binding_incarnation
                               AND current.material_signature=generation.material_signature
                              JOIN registry_internal.registry_record_timer_bindings AS binding
                                ON binding.record_type=current.record_type
                               AND binding.timer_id=current.timer_id
                               AND binding.incarnation=current.binding_incarnation
                             WHERE control.singleton AND control.protocol_version=1
                               AND control.control_state='running' AND control.control_epoch=$5
                               AND control.bound_instance_epoch=$6
                               AND registry.epoch=$6 AND registry.active_activation_id=$7
                               AND binding.removed_activation_id IS NULL
                               AND binding.current_policy_activation_id=$7
                               AND binding.definition_revision=generation.definition_revision
                               AND binding.action_revision=generation.action_revision
                               AND binding.system_grant_revision=$8
                        )
                  RETURNING occurrence_id,executed_attempt_count
                 ), retained AS (
                     INSERT INTO registry_internal.registry_record_timer_attempts (
                         occurrence_id,attempt_number,claim_owner_id,claim_epoch,
                         control_epoch,instance_epoch,activation_id,definition_revision,
                         action_revision,system_grant_revision,started_at,finished_at,
                         detail_expires_at,outcome_code
                     )
                     SELECT settled.occurrence_id,settled.executed_attempt_count,$2,$3,$5,$6,$7,
                            $11,$12,$8,$13,statement_timestamp(),
                            statement_timestamp()+$14::bigint*interval '1 day',$10
                       FROM settled
                  RETURNING occurrence_id,attempt_number
                 )
                 SELECT settled.executed_attempt_count
                   FROM settled JOIN retained USING (occurrence_id)").as_ref(),
                &[
                    &self.occurrence_id,
                    &self.claim_owner_id,
                    &self.claim_epoch,
                    &self.claim_token,
                    &self.control_epoch,
                    &self.instance_epoch,
                    &self.activation_id,
                    &self.timer.system_grant.revision,
                    &MAX_AUTOMATIC_TIMER_ATTEMPTS,
                    &outcome.as_str(),
                    &self.timer.definition_revision,
                    &self.timer.action_revision,
                    &started_at,
                    &i64::from(self.detail_retention_days),
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        row.ok_or(MutationError::PreconditionFailed)?;
        self.retain_terminal_detail(transaction).await?;
        Ok(())
    }

    pub(crate) async fn settle_hold(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<(), MutationError> {
        let updated = transaction
            .execute(
                self.database_clock_sql(
                    "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET state='pending', claim_owner_id=NULL, claim_token=NULL, claim_until=NULL,
                        claimed_control_epoch=NULL, claimed_instance_epoch=NULL,
                        claimed_activation_id=NULL,
                        updated_at=clock_timestamp()
                  WHERE occurrence_id=$1 AND claim_owner_id=$2 AND claim_epoch=$3
                    AND claim_token=$4 AND state='leased'
                    AND claimed_control_epoch=$5 AND claimed_instance_epoch=$6
                    AND claimed_activation_id=$7 AND system_grant_revision=$8
                    AND claim_until > clock_timestamp()
                    AND EXISTS (
                        SELECT 1
                          FROM registry_internal.registry_record_timer_control AS control
                          JOIN registry_internal.registry_state AS registry ON registry.singleton
                          JOIN registry_internal.registry_record_timer_current AS current
                            ON current.occurrence_id=generation.occurrence_id
                           AND current.record_type=generation.record_type
                           AND current.record_id=generation.record_id
                           AND current.timer_id=generation.timer_id
                           AND current.binding_incarnation=generation.binding_incarnation
                           AND current.material_signature=generation.material_signature
                          JOIN registry_internal.registry_record_timer_bindings AS binding
                            ON binding.record_type=current.record_type
                           AND binding.timer_id=current.timer_id
                           AND binding.incarnation=current.binding_incarnation
                         WHERE control.singleton AND control.protocol_version=1
                           AND control.control_state='running' AND control.control_epoch=$5
                           AND control.bound_instance_epoch=$6
                           AND registry.epoch=$6 AND registry.active_activation_id=$7
                           AND binding.removed_activation_id IS NULL
                           AND binding.current_policy_activation_id=$7
                           AND binding.definition_revision=generation.definition_revision
                           AND binding.action_revision=generation.action_revision
                           AND binding.system_grant_revision=$8
                    )",
                )
                .as_ref(),
                &[
                    &self.occurrence_id,
                    &self.claim_owner_id,
                    &self.claim_epoch,
                    &self.claim_token,
                    &self.control_epoch,
                    &self.instance_epoch,
                    &self.activation_id,
                    &self.timer.system_grant.revision,
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if updated != 1 {
            return Err(MutationError::PreconditionFailed);
        }
        Ok(())
    }

    pub(crate) async fn settle_clock_transition(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<bool, MutationError> {
        let now_sql = self.database_clock_sql("SELECT clock_timestamp()");
        let now: DateTime<Utc> = transaction
            .query_one(now_sql.as_ref(), &[])
            .await
            .map_err(|_| MutationError::Unavailable)?
            .get(0);
        if now < self.due_at {
            self.settle_hold(transaction).await?;
            return Ok(true);
        }
        if self
            .not_after
            .is_some_and(|end| end > self.due_at && now >= end)
        {
            self.settle_missed(transaction).await?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) async fn settle_technical_failure(
        &self,
        transaction: &Transaction<'_>,
        technical_code: &str,
        started_at: DateTime<Utc>,
    ) -> Result<(), MutationError> {
        if technical_code.is_empty()
            || technical_code.len() > 64
            || !technical_code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(MutationError::Unavailable);
        }
        let row = transaction
            .query_opt(
                self.database_clock_sql("WITH settled AS (
                     UPDATE registry_internal.registry_record_timer_generations AS generation
                        SET executed_attempt_count=executed_attempt_count+1,
                            retry_allowance=CASE
                                WHEN executed_attempt_count >= $9 THEN 0
                                ELSE retry_allowance
                            END,
                            state=CASE
                                WHEN executed_attempt_count+1 >= $9 THEN 'blocked'
                                ELSE 'pending'
                            END,
                            block_kind=CASE
                                WHEN executed_attempt_count+1 >= $9 THEN 'technical'
                                ELSE NULL
                            END,
                            outcome_code=CASE
                                WHEN executed_attempt_count+1 >= $9 THEN 'attempts-exhausted'
                                ELSE NULL
                            END,
                            retry_at=CASE executed_attempt_count
                                WHEN 0 THEN clock_timestamp()+interval '1 second'
                                WHEN 1 THEN clock_timestamp()+interval '2 seconds'
                                WHEN 2 THEN clock_timestamp()+interval '4 seconds'
                                WHEN 3 THEN clock_timestamp()+interval '8 seconds'
                                ELSE NULL
                            END,
                            claim_owner_id=NULL, claim_token=NULL, claim_until=NULL,
                            claimed_control_epoch=NULL, claimed_instance_epoch=NULL,
                            claimed_activation_id=NULL, updated_at=clock_timestamp()
                      WHERE occurrence_id=$1 AND claim_owner_id=$2 AND claim_epoch=$3
                        AND claim_token=$4 AND state='leased'
                        AND claimed_control_epoch=$5 AND claimed_instance_epoch=$6
                        AND claimed_activation_id=$7 AND system_grant_revision=$8
                        AND claim_until > clock_timestamp()
                        AND (executed_attempt_count < $9 OR retry_allowance=1)
                        AND EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_record_timer_control AS control
                              JOIN registry_internal.registry_state AS registry ON registry.singleton
                              JOIN registry_internal.registry_record_timer_current AS current
                                ON current.occurrence_id=generation.occurrence_id
                               AND current.record_type=generation.record_type
                               AND current.record_id=generation.record_id
                               AND current.timer_id=generation.timer_id
                               AND current.binding_incarnation=generation.binding_incarnation
                               AND current.material_signature=generation.material_signature
                              JOIN registry_internal.registry_record_timer_bindings AS binding
                                ON binding.record_type=current.record_type
                               AND binding.timer_id=current.timer_id
                               AND binding.incarnation=current.binding_incarnation
                             WHERE control.singleton AND control.protocol_version=1
                               AND control.control_state='running' AND control.control_epoch=$5
                               AND control.bound_instance_epoch=$6
                               AND registry.epoch=$6 AND registry.active_activation_id=$7
                               AND binding.removed_activation_id IS NULL
                               AND binding.current_policy_activation_id=$7
                               AND binding.definition_revision=generation.definition_revision
                               AND binding.action_revision=generation.action_revision
                               AND binding.system_grant_revision=$8
                        )
                  RETURNING occurrence_id,executed_attempt_count,outcome_code
                 ), retained AS (
                     INSERT INTO registry_internal.registry_record_timer_attempts (
                         occurrence_id,attempt_number,claim_owner_id,claim_epoch,
                         control_epoch,instance_epoch,activation_id,definition_revision,
                         action_revision,system_grant_revision,started_at,finished_at,
                         detail_expires_at,block_kind,outcome_code,technical_code
                     )
                     SELECT settled.occurrence_id,settled.executed_attempt_count,$2,$3,$5,$6,$7,
                            $10,$11,$8,$13,statement_timestamp(),
                            statement_timestamp()+$14::bigint*interval '1 day',
                            'technical',settled.outcome_code,$12
                       FROM settled
                  RETURNING occurrence_id,attempt_number
                 )
                 SELECT settled.executed_attempt_count
                   FROM settled
                   JOIN retained USING (occurrence_id)").as_ref(),
                &[
                    &self.occurrence_id,
                    &self.claim_owner_id,
                    &self.claim_epoch,
                    &self.claim_token,
                    &self.control_epoch,
                    &self.instance_epoch,
                    &self.activation_id,
                    &self.timer.system_grant.revision,
                    &MAX_AUTOMATIC_TIMER_ATTEMPTS,
                    &self.timer.definition_revision,
                    &self.timer.action_revision,
                    &technical_code,
                    &started_at,
                    &i64::from(self.detail_retention_days),
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        row.ok_or(MutationError::PreconditionFailed)?;
        Ok(())
    }

    pub(crate) async fn start_attempt(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<i32, MutationError> {
        let row = transaction
            .query_opt(
                self.database_clock_sql(
                    "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET executed_attempt_count=executed_attempt_count+1,
                        retry_allowance=CASE
                            WHEN executed_attempt_count >= $9 THEN 0
                            ELSE retry_allowance
                        END,
                        updated_at=clock_timestamp()
                  WHERE occurrence_id=$1 AND claim_owner_id=$2 AND claim_epoch=$3
                    AND claim_token=$4 AND state='leased'
                    AND claimed_control_epoch=$5 AND claimed_instance_epoch=$6
                    AND claimed_activation_id=$7 AND system_grant_revision=$8
                    AND claim_until > clock_timestamp()
                    AND (executed_attempt_count < $9 OR retry_allowance=1)
                    AND EXISTS (
                        SELECT 1
                          FROM registry_internal.registry_record_timer_control AS control
                          JOIN registry_internal.registry_state AS registry ON registry.singleton
                          JOIN registry_internal.registry_record_timer_current AS current
                            ON current.occurrence_id=generation.occurrence_id
                           AND current.record_type=generation.record_type
                           AND current.record_id=generation.record_id
                           AND current.timer_id=generation.timer_id
                           AND current.binding_incarnation=generation.binding_incarnation
                           AND current.material_signature=generation.material_signature
                          JOIN registry_internal.registry_record_timer_bindings AS binding
                            ON binding.record_type=current.record_type
                           AND binding.timer_id=current.timer_id
                           AND binding.incarnation=current.binding_incarnation
                         WHERE control.singleton AND control.protocol_version=1
                           AND control.control_state='running' AND control.control_epoch=$5
                           AND control.bound_instance_epoch=$6
                           AND registry.epoch=$6 AND registry.active_activation_id=$7
                           AND binding.removed_activation_id IS NULL
                           AND binding.current_policy_activation_id=$7
                           AND binding.system_grant_revision=$8
                    )
              RETURNING executed_attempt_count",
                )
                .as_ref(),
                &[
                    &self.occurrence_id,
                    &self.claim_owner_id,
                    &self.claim_epoch,
                    &self.claim_token,
                    &self.control_epoch,
                    &self.instance_epoch,
                    &self.activation_id,
                    &self.timer.system_grant.revision,
                    &MAX_AUTOMATIC_TIMER_ATTEMPTS,
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let attempt_number: i32 = row.ok_or(MutationError::PreconditionFailed)?.get(0);
        let inserted = transaction
            .execute(
                self.database_clock_sql(
                    "INSERT INTO registry_internal.registry_record_timer_attempts (
                     occurrence_id,attempt_number,claim_owner_id,claim_epoch,
                     control_epoch,instance_epoch,activation_id,definition_revision,
                     action_revision,system_grant_revision,started_at
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp())",
                )
                .as_ref(),
                &[
                    &self.occurrence_id,
                    &attempt_number,
                    &self.claim_owner_id,
                    &self.claim_epoch,
                    &self.control_epoch,
                    &self.instance_epoch,
                    &self.activation_id,
                    &self.timer.definition_revision,
                    &self.timer.action_revision,
                    &self.timer.system_grant.revision,
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if inserted != 1 {
            return Err(MutationError::PreconditionFailed);
        }
        Ok(attempt_number)
    }

    pub(crate) async fn refresh_target_binding_digests(
        &self,
        transaction: &Transaction<'_>,
        anchor: &CurrentRow,
    ) -> Result<(), MutationError> {
        if anchor.record_uuid != self.record_id || anchor.record_lifecycle != "active" {
            return Err(MutationError::PreconditionFailed);
        }
        let target_binding_digests = timer_target_binding_digests(&self.timer, anchor)?;
        let updated = transaction
            .execute(
                self.database_clock_sql(
                    "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET target_binding_digests=$9,updated_at=clock_timestamp()
                  WHERE occurrence_id=$1 AND claim_owner_id=$2 AND claim_epoch=$3
                    AND claim_token=$4 AND state='leased'
                    AND claimed_control_epoch=$5 AND claimed_instance_epoch=$6
                    AND claimed_activation_id=$7 AND system_grant_revision=$8
                    AND definition_revision=$10 AND action_revision=$11
                    AND claim_until > clock_timestamp()
                    AND EXISTS (
                        SELECT 1
                          FROM registry_internal.registry_record_timer_control AS control
                          JOIN registry_internal.registry_state AS registry ON registry.singleton
                          JOIN registry_internal.registry_record_timer_current AS current
                            ON current.occurrence_id=generation.occurrence_id
                           AND current.record_type=generation.record_type
                           AND current.record_id=generation.record_id
                           AND current.timer_id=generation.timer_id
                           AND current.binding_incarnation=generation.binding_incarnation
                           AND current.material_signature=generation.material_signature
                          JOIN registry_internal.registry_record_timer_bindings AS binding
                            ON binding.record_type=current.record_type
                           AND binding.timer_id=current.timer_id
                           AND binding.incarnation=current.binding_incarnation
                         WHERE control.singleton AND control.protocol_version=1
                           AND control.control_state='running' AND control.control_epoch=$5
                           AND control.bound_instance_epoch=$6
                           AND registry.epoch=$6 AND registry.active_activation_id=$7
                           AND binding.removed_activation_id IS NULL
                           AND binding.current_policy_activation_id=$7
                           AND binding.definition_revision=$10
                           AND binding.action_revision=$11
                           AND binding.system_grant_revision=$8
                    )",
                )
                .as_ref(),
                &[
                    &self.occurrence_id,
                    &self.claim_owner_id,
                    &self.claim_epoch,
                    &self.claim_token,
                    &self.control_epoch,
                    &self.instance_epoch,
                    &self.activation_id,
                    &self.timer.system_grant.revision,
                    &target_binding_digests,
                    &self.timer.definition_revision,
                    &self.timer.action_revision,
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if updated != 1 {
            return Err(MutationError::PreconditionFailed);
        }
        Ok(())
    }

    pub(crate) async fn settle_completed(
        &self,
        transaction: &Transaction<'_>,
        attempt_number: i32,
        receipt_correlation: Uuid,
    ) -> Result<(), MutationError> {
        let attempt = transaction
            .execute(
                self.database_clock_sql(
                    "UPDATE registry_internal.registry_record_timer_attempts
                    SET finished_at=statement_timestamp(),
                        detail_expires_at=statement_timestamp()+$12::bigint*interval '1 day',
                        outcome_code='completed', receipt_correlation=$11
                  WHERE occurrence_id=$1 AND attempt_number=$2
                    AND claim_owner_id=$3 AND claim_epoch=$4
                    AND control_epoch=$5 AND instance_epoch=$6 AND activation_id=$7
                    AND definition_revision=$8 AND action_revision=$9
                    AND system_grant_revision=$10 AND finished_at IS NULL",
                )
                .as_ref(),
                &[
                    &self.occurrence_id,
                    &attempt_number,
                    &self.claim_owner_id,
                    &self.claim_epoch,
                    &self.control_epoch,
                    &self.instance_epoch,
                    &self.activation_id,
                    &self.timer.definition_revision,
                    &self.timer.action_revision,
                    &self.timer.system_grant.revision,
                    &receipt_correlation,
                    &i64::from(self.detail_retention_days),
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if attempt != 1 {
            return Err(MutationError::PreconditionFailed);
        }
        let updated = transaction
            .execute(
                self.database_clock_sql(
                    "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET state='completed', outcome_code='completed', receipt_correlation=$9,
                        completed_at=clock_timestamp(), executed_activation_id=$7,
                        claim_owner_id=NULL, claim_token=NULL, claim_until=NULL,
                        claimed_control_epoch=NULL, claimed_instance_epoch=NULL,
                        claimed_activation_id=NULL,
                        updated_at=clock_timestamp()
                  WHERE occurrence_id=$1 AND claim_owner_id=$2 AND claim_epoch=$3
                    AND claim_token=$4 AND state='leased'
                    AND claimed_control_epoch=$5 AND claimed_instance_epoch=$6
                    AND claimed_activation_id=$7 AND system_grant_revision=$8
                    AND claim_until > clock_timestamp()
                    AND due_at <= clock_timestamp()
                    AND (not_after IS NULL OR clock_timestamp() < not_after)
                    AND EXISTS (
                        SELECT 1
                          FROM registry_internal.registry_record_timer_control AS control
                          JOIN registry_internal.registry_state AS registry ON registry.singleton
                          JOIN registry_internal.registry_record_timer_current AS current
                            ON current.occurrence_id=generation.occurrence_id
                           AND current.record_type=generation.record_type
                           AND current.record_id=generation.record_id
                           AND current.timer_id=generation.timer_id
                           AND current.binding_incarnation=generation.binding_incarnation
                           AND current.material_signature=generation.material_signature
                          JOIN registry_internal.registry_record_timer_bindings AS binding
                            ON binding.record_type=current.record_type
                           AND binding.timer_id=current.timer_id
                           AND binding.incarnation=current.binding_incarnation
                         WHERE control.singleton AND control.protocol_version=1
                           AND control.control_state='running' AND control.control_epoch=$5
                           AND control.bound_instance_epoch=$6
                           AND registry.epoch=$6 AND registry.active_activation_id=$7
                           AND binding.removed_activation_id IS NULL
                           AND binding.current_policy_activation_id=$7
                           AND binding.system_grant_revision=$8
                    )",
                )
                .as_ref(),
                &[
                    &self.occurrence_id,
                    &self.claim_owner_id,
                    &self.claim_epoch,
                    &self.claim_token,
                    &self.control_epoch,
                    &self.instance_epoch,
                    &self.activation_id,
                    &self.timer.system_grant.revision,
                    &receipt_correlation,
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if updated != 1 {
            return Err(MutationError::PreconditionFailed);
        }
        self.retain_terminal_detail(transaction).await?;
        Ok(())
    }

    async fn retain_terminal_detail(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<(), MutationError> {
        let updated = transaction
            .execute(
                "UPDATE registry_internal.registry_record_timer_generations
                    SET detail_expires_at=completed_at+$2::bigint*interval '1 day'
                  WHERE occurrence_id=$1 AND completed_at IS NOT NULL
                    AND state IN ('completed','refused','cancelled','superseded','missed')
                    AND detail_expires_at IS NULL",
                &[&self.occurrence_id, &i64::from(self.detail_retention_days)],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if updated != 1 {
            return Err(MutationError::PreconditionFailed);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn valid_live_timer_claim(
    occurrence_id: Uuid,
    record_id: Uuid,
    claim_token: Uuid,
    claim_owner_id: Uuid,
    claim_epoch: i64,
    control_epoch: i64,
    instance_epoch: i64,
) -> bool {
    !occurrence_id.is_nil()
        && !record_id.is_nil()
        && !claim_token.is_nil()
        && !claim_owner_id.is_nil()
        && claim_epoch >= 1
        && control_epoch >= 1
        && instance_epoch >= 1
}

pub(crate) struct TimerActionExecution<'a> {
    pub(crate) authority: &'a TimerActionAuthority,
    pub(crate) correlation: &'a crate::correlation::RequestCorrelation,
}

#[cfg(test)]
mod tests {
    use super::{material_signature, timer_create_target_id, valid_live_timer_claim};
    use chrono::{TimeZone, Utc};
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn timer_action_authority_refuses_zero_control_epoch() {
        let occurrence_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let claim_token = Uuid::new_v4();
        let claim_owner_id = Uuid::new_v4();

        assert!(!valid_live_timer_claim(
            occurrence_id,
            record_id,
            claim_token,
            claim_owner_id,
            1,
            0,
            1,
        ));
        assert!(valid_live_timer_claim(
            occurrence_id,
            record_id,
            claim_token,
            claim_owner_id,
            1,
            1,
            1,
        ));
    }

    #[test]
    fn adjacent_large_int64_rearm_values_have_distinct_material_identity() {
        let at = Utc
            .with_ymd_and_hms(2026, 10, 28, 12, 0, 0)
            .single()
            .expect("the fixture instant is valid");
        let first = material_signature(at, None, &json!(9_007_199_254_740_992_i64))
            .expect("the first exact Int64 has a typed signature");
        let adjacent = material_signature(at, None, &json!(9_007_199_254_740_993_i64))
            .expect("the adjacent exact Int64 has a typed signature");

        assert_ne!(first, adjacent);
        assert_eq!(
            first,
            material_signature(at, None, &json!(9_007_199_254_740_992_i64))
                .expect("typed signatures are stable")
        );
    }

    #[test]
    fn timer_create_target_identity_is_stable_and_domain_separated() {
        let occurrence =
            Uuid::parse_str("00000000-0000-4000-8000-000000000123").expect("UUID parses");
        let revision = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let target = timer_create_target_id(occurrence, revision, "created", "entry");
        assert_eq!(
            target,
            Uuid::parse_str("396fd1b8-fe85-840d-8234-1dd1a05d7b0a").unwrap()
        );
        assert_eq!(
            target,
            timer_create_target_id(occurrence, revision, "created", "entry")
        );
        assert_ne!(
            target,
            timer_create_target_id(Uuid::new_v4(), revision, "created", "entry")
        );
        assert_ne!(
            target,
            timer_create_target_id(occurrence, revision, "created-again", "entry")
        );
        assert_ne!(
            target,
            timer_create_target_id(occurrence, revision, "created", "other-entry")
        );
        assert_ne!(
            target,
            timer_create_target_id(
                occurrence,
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "created",
                "entry",
            )
        );
    }
}
