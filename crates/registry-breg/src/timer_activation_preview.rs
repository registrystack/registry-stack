// SPDX-License-Identifier: Apache-2.0

//! Value-free Record-timer facts for a governed successor activation preview.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::contract::Operation;
use crate::model::{CompiledRegistry, CompiledTimer};
use crate::package::{
    CompiledRegistryChange, CompiledRegistryChangeCode, CompiledRegistryChangeTargetKind,
    CompiledRegistryMigrationBaseline, PackageError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimerActivationChange {
    Added,
    Changed,
    Removed,
    EffectInputMigration,
}

impl TimerActivationChange {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Changed => "changed",
            Self::Removed => "removed",
            Self::EffectInputMigration => "effect-input-migration",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimerSuccessorEvaluation {
    HistoricalRecordsUnarmed,
    UnknownUntilRefresh,
    RemovedNoExecutionFenced,
}

impl TimerSuccessorEvaluation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HistoricalRecordsUnarmed => "historical-records-unarmed",
            Self::UnknownUntilRefresh => "unknown-until-refresh",
            Self::RemovedNoExecutionFenced => "removed-no-execution-fenced",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimerRemovalFence {
    NotApplicable,
    Retained,
}

impl TimerRemovalFence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not-applicable",
            Self::Retained => "retained",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimerHistoricalRecords {
    Unarmed,
}

impl TimerHistoricalRecords {
    pub fn as_str(self) -> &'static str {
        "unarmed"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimerBackfill {
    Unavailable,
}

impl TimerBackfill {
    pub fn as_str(self) -> &'static str {
        "unavailable"
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerPolicyRevisions {
    pub definition: String,
    pub action: String,
    pub system_grant: String,
}

impl From<&CompiledTimer> for TimerPolicyRevisions {
    fn from(timer: &CompiledTimer) -> Self {
        Self {
            definition: timer.definition_revision.clone(),
            action: timer.action_revision.clone(),
            system_grant: timer.system_grant.revision.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerActivationPreviewDefinition {
    #[serde(rename = "recordType")]
    pub record_type: String,
    pub timer: String,
    pub change: TimerActivationChange,
    pub predecessor_revisions: Option<TimerPolicyRevisions>,
    pub successor_revisions: Option<TimerPolicyRevisions>,
    pub successor_evaluation: TimerSuccessorEvaluation,
    pub historical_records: TimerHistoricalRecords,
    pub backfill: TimerBackfill,
    pub effect_shaping_migration_fields: Vec<TimerMigrationField>,
    pub removal_fence: TimerRemovalFence,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerMigrationField {
    #[serde(rename = "recordType")]
    pub record_type: String,
    pub field: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimerCachedPredecessorBasis {
    NoPredecessorBinding,
    CurrentMarkerActiveBindingCache,
}

impl TimerCachedPredecessorBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoPredecessorBinding => "no-predecessor-binding",
            Self::CurrentMarkerActiveBindingCache => "current-marker-active-binding-cache",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerCachedPredecessor {
    pub basis: TimerCachedPredecessorBasis,
    pub observed_unfinished_count: u64,
    pub earliest_due_at: Option<DateTime<Utc>>,
    pub has_stale_revisions: bool,
    pub truncated: bool,
}

impl TimerCachedPredecessor {
    pub fn no_predecessor_binding() -> Self {
        Self {
            basis: TimerCachedPredecessorBasis::NoPredecessorBinding,
            observed_unfinished_count: 0,
            earliest_due_at: None,
            has_stale_revisions: false,
            truncated: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerActivationPreview {
    #[serde(flatten)]
    pub definition: TimerActivationPreviewDefinition,
    pub cached_predecessor: TimerCachedPredecessor,
}

/// Derive only package-owned structural facts. Cached database observations
/// are joined later under the exact active-package/apply-lock admission.
pub fn timer_activation_preview_definitions(
    predecessor: &CompiledRegistryMigrationBaseline,
    successor: &CompiledRegistry,
    changes: &[CompiledRegistryChange],
    reviewed_migration_fields: &BTreeSet<(String, String)>,
) -> Result<Vec<TimerActivationPreviewDefinition>, PackageError> {
    let mut timer_changes = changes
        .iter()
        .filter(|change| {
            change.target.kind == CompiledRegistryChangeTargetKind::Timer
                && matches!(
                    change.code,
                    CompiledRegistryChangeCode::TimerAdded
                        | CompiledRegistryChangeCode::TimerChanged
                        | CompiledRegistryChangeCode::TimerRemoved
                )
        })
        .map(|change| {
            let entity = change
                .target
                .record_type_id
                .clone()
                .ok_or(PackageError::MigrationPlan)?;
            let timer = change
                .target
                .member_id
                .clone()
                .ok_or(PackageError::MigrationPlan)?;
            Ok(((entity, timer), change.code))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, PackageError>>()?;

    for (entity_id, before_entity) in &predecessor.entities {
        for (timer_id, before) in &before_entity.timers {
            let after = successor
                .entities()
                .get(entity_id)
                .and_then(|entity| entity.timers.get(timer_id));
            if after.is_some()
                && effect_shaping_fields(Some(before), after, reviewed_migration_fields)
                    .next()
                    .is_some()
            {
                timer_changes
                    .entry((entity_id.clone(), timer_id.clone()))
                    .or_insert(CompiledRegistryChangeCode::TimerChanged);
            }
        }
    }

    let mut definitions = Vec::new();
    for ((entity_id, timer_id), change_code) in timer_changes {
        let before = predecessor
            .entities
            .get(&entity_id)
            .and_then(|entity| entity.timers.get(&timer_id));
        let after = successor
            .entities()
            .get(&entity_id)
            .and_then(|entity| entity.timers.get(&timer_id));
        let (change, successor_evaluation, removal_fence) = match change_code {
            CompiledRegistryChangeCode::TimerAdded if before.is_none() && after.is_some() => (
                TimerActivationChange::Added,
                TimerSuccessorEvaluation::HistoricalRecordsUnarmed,
                TimerRemovalFence::NotApplicable,
            ),
            CompiledRegistryChangeCode::TimerChanged if before.is_some() && after.is_some() => (
                if before == after {
                    TimerActivationChange::EffectInputMigration
                } else {
                    TimerActivationChange::Changed
                },
                TimerSuccessorEvaluation::UnknownUntilRefresh,
                TimerRemovalFence::NotApplicable,
            ),
            CompiledRegistryChangeCode::TimerRemoved if before.is_some() && after.is_none() => (
                TimerActivationChange::Removed,
                TimerSuccessorEvaluation::RemovedNoExecutionFenced,
                TimerRemovalFence::Retained,
            ),
            _ => return Err(PackageError::MigrationPlan),
        };
        let effect_fields = effect_shaping_fields(before, after, reviewed_migration_fields)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        definitions.push(TimerActivationPreviewDefinition {
            record_type: entity_id,
            timer: timer_id,
            change,
            predecessor_revisions: before.map(TimerPolicyRevisions::from),
            successor_revisions: after.map(TimerPolicyRevisions::from),
            successor_evaluation,
            historical_records: TimerHistoricalRecords::Unarmed,
            backfill: TimerBackfill::Unavailable,
            effect_shaping_migration_fields: effect_fields,
            removal_fence,
        });
    }
    definitions.sort_by(|left, right| {
        (&left.record_type, &left.timer).cmp(&(&right.record_type, &right.timer))
    });
    Ok(definitions)
}

fn effect_shaping_fields<'a>(
    before: Option<&'a CompiledTimer>,
    after: Option<&'a CompiledTimer>,
    migrated: &'a BTreeSet<(String, String)>,
) -> impl Iterator<Item = TimerMigrationField> + 'a {
    before
        .into_iter()
        .chain(after)
        .flat_map(timer_effect_read_closure)
        .filter(|field| migrated.contains(&(field.record_type.clone(), field.field.clone())))
}

fn timer_effect_read_closure(timer: &CompiledTimer) -> BTreeSet<TimerMigrationField> {
    let mut fields = timer
        .effect_input_fields
        .iter()
        .map(|field| TimerMigrationField {
            record_type: timer.record_type.clone(),
            field: field.clone(),
        })
        .collect::<BTreeSet<_>>();
    for target in timer
        .system_grant
        .targets
        .iter()
        .filter(|target| target.operation == Operation::Get)
    {
        fields.extend(target.read_fields.iter().filter_map(|field| {
            let anchor_control_or_predicate = target.entity_id == timer.record_type
                && (timer.control_fields.contains(field) || timer.predicate_fields.contains(field));
            (!anchor_control_or_predicate).then(|| TimerMigrationField {
                record_type: target.entity_id.clone(),
                field: field.clone(),
            })
        }));
    }
    fields
}
