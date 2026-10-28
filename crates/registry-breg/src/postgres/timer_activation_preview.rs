// SPDX-License-Identifier: Apache-2.0

//! Bounded cached Record-timer facts for governed activation preview.

use chrono::{DateTime, Utc};
use tokio_postgres::GenericClient;

use crate::timer_activation_preview::{
    TimerActivationChange, TimerActivationPreview, TimerActivationPreviewDefinition,
    TimerCachedPredecessor, TimerCachedPredecessorBasis,
};

use super::{PostgresKernelError, Result};

pub(super) const TIMER_ACTIVATION_PREVIEW_SCAN_MAXIMUM: i64 = 10_000;
const TIMER_ACTIVATION_PREVIEW_SCAN_SENTINEL: i64 = TIMER_ACTIVATION_PREVIEW_SCAN_MAXIMUM + 1;

/// Join package-owned preview definitions to bounded cached ledger facts.
///
/// The caller owns exact active-package admission and the apply lock. Added
/// bindings have no predecessor cache. Changed and removed bindings must match
/// one open predecessor incarnation and count only its complete current-marker
/// tuples; detached or retired work is not successor-executable work.
pub(crate) async fn read_timer_activation_previews(
    client: &impl GenericClient,
    definitions: Vec<TimerActivationPreviewDefinition>,
) -> Result<Vec<TimerActivationPreview>> {
    let mut previews = Vec::with_capacity(definitions.len());
    for definition in definitions {
        let cached_predecessor = if definition.change == TimerActivationChange::Added {
            TimerCachedPredecessor::no_predecessor_binding()
        } else {
            let revisions = definition.predecessor_revisions.as_ref().ok_or(
                PostgresKernelError::CatalogInvariant(
                    "a changed or removed timer preview lacks predecessor revisions",
                ),
            )?;
            let row = client
                .query_one(
                    "WITH predecessor_binding AS MATERIALIZED (
                         SELECT incarnation,definition_revision,action_revision,
                                system_grant_revision
                           FROM registry_internal.registry_record_timer_bindings
                          WHERE record_type=$1 AND timer_id=$2
                            AND removed_activation_id IS NULL
                            AND definition_revision=$3
                            AND action_revision=$4
                            AND system_grant_revision=$5
                     ), observed AS MATERIALIZED (
                         SELECT generation.due_at,
                                generation.definition_revision<>binding.definition_revision
                                OR generation.action_revision<>binding.action_revision
                                OR generation.system_grant_revision<>
                                   binding.system_grant_revision AS stale_revision
                           FROM predecessor_binding AS binding
                           JOIN registry_internal.registry_record_timer_generations AS generation
                             ON generation.record_type=$1
                            AND generation.timer_id=$2
                            AND generation.binding_incarnation=binding.incarnation
                           JOIN registry_internal.registry_record_timer_current AS current
                             ON current.record_type=generation.record_type
                            AND current.record_id=generation.record_id
                            AND current.timer_id=generation.timer_id
                            AND current.occurrence_id=generation.occurrence_id
                            AND current.binding_incarnation=generation.binding_incarnation
                            AND current.material_signature=generation.material_signature
                          WHERE generation.state IN ('pending','leased','blocked')
                          ORDER BY generation.due_at ASC,generation.occurrence_id ASC
                          LIMIT $6
                     )
                     SELECT (SELECT count(*) FROM predecessor_binding)::bigint AS binding_count,
                            count(*)::bigint AS observed_count,
                            min(due_at) AS earliest_due_at,
                            coalesce(bool_or(stale_revision),false) AS has_stale_revisions
                       FROM observed",
                    &[
                        &definition.record_type,
                        &definition.timer,
                        &revisions.definition,
                        &revisions.action,
                        &revisions.system_grant,
                        &TIMER_ACTIVATION_PREVIEW_SCAN_SENTINEL,
                    ],
                )
                .await?;
            if row.get::<_, i64>("binding_count") != 1 {
                return Err(PostgresKernelError::CatalogInvariant(
                    "the active timer binding does not match its predecessor package",
                ));
            }
            let observed_count = row.get::<_, i64>("observed_count");
            TimerCachedPredecessor {
                basis: TimerCachedPredecessorBasis::CurrentMarkerActiveBindingCache,
                observed_unfinished_count: u64::try_from(
                    observed_count.min(TIMER_ACTIVATION_PREVIEW_SCAN_MAXIMUM),
                )
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
                earliest_due_at: row.get::<_, Option<DateTime<Utc>>>("earliest_due_at"),
                has_stale_revisions: row.get("has_stale_revisions"),
                truncated: observed_count > TIMER_ACTIVATION_PREVIEW_SCAN_MAXIMUM,
            }
        };
        previews.push(TimerActivationPreview {
            definition,
            cached_predecessor,
        });
    }
    Ok(previews)
}
