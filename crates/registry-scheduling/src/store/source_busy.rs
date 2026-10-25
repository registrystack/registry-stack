// SPDX-License-Identifier: Apache-2.0

//! Revision-CAS persistence for source-owned busy intervals.

use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;
use thiserror::Error;

use crate::source_busy::{
    busy_reconciliation_request_digest, AuthorizedBusySource, BusyApplyOutcome,
    BusyApplyOutcomeKind, BusyCommitmentImpact, BusyImpactSummary, BusyReconciliationPreview,
    BusyReconciliationRequest, BusySourceStatus, MAX_BUSY_IMPORT_IMPACTS,
};

use super::{BundleSupplyLine, CapacityStatements, PostgresStore, StoreError};

#[derive(Debug, Error)]
pub enum BusyStoreError {
    #[error("the busy source revision changed from {expected} to {current}")]
    RevisionMismatch { expected: u64, current: u64 },
    #[error("the busy source record crosses the reconciliation coverage boundary")]
    CoverageBoundary,
    #[error("the busy source observation does not follow the applied observation stream")]
    ObservationConflict,
    #[error("the original busy source outcome is unavailable")]
    RecoveryUnavailable,
    #[error("one or more busy source resources are not current Scheduling resources")]
    ResourceMissing,
    #[error("the Scheduling source-busy audit destination is unavailable")]
    AuditUnavailable,
    #[error("the Scheduling busy-source query failed")]
    Query(#[from] tokio_postgres::Error),
    #[error(transparent)]
    Store(#[from] StoreError),
}

pub(super) fn as_store_error(error: BusyStoreError) -> StoreError {
    match error {
        BusyStoreError::Store(error) => error,
        BusyStoreError::Query(error) => StoreError::Query(error),
        BusyStoreError::RevisionMismatch { .. }
        | BusyStoreError::CoverageBoundary
        | BusyStoreError::ObservationConflict
        | BusyStoreError::RecoveryUnavailable
        | BusyStoreError::ResourceMissing
        | BusyStoreError::AuditUnavailable => StoreError::Corrupt,
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct BusyDiff {
    added: u64,
    changed: u64,
    deleted: u64,
    retained_outside_authority: u64,
    retained_across_coverage_boundary: u64,
}

impl PostgresStore {
    /// Preview one exact source snapshot without acquiring a write lock. Apply
    /// repeats the same comparison after locking the source revision.
    pub async fn preview_busy_reconciliation(
        &self,
        authority: &AuthorizedBusySource,
        request: &BusyReconciliationRequest,
    ) -> Result<BusyReconciliationPreview, BusyStoreError> {
        let client = self.client().await?;
        ensure_resources_exist(&client, &request.coverage.resources).await?;
        let request_digest = busy_reconciliation_request_digest(request, authority)
            .map_err(|_| StoreError::Corrupt)?;
        let current_revision = source_revision(&client, authority.source_id()).await?;
        reject_boundary_replacement(&client, authority.source_id(), request).await?;
        let diff = reconciliation_diff(&client, authority, request).await?;
        let impacts = reconciliation_impacts(
            &client,
            request,
            self.observed_now(),
            authority.includes_impact_details(),
        )
        .await?;
        Ok(BusyReconciliationPreview {
            source_id: authority.source_id().to_owned(),
            expected_revision: request.expected_revision,
            current_revision,
            request_digest,
            added: diff.added,
            changed: diff.changed,
            deleted: diff.deleted,
            retained_outside_authority: diff.retained_outside_authority,
            retained_across_coverage_boundary: diff.retained_across_coverage_boundary,
            impacts,
        })
    }

    /// Apply only the selected source's covered rows under an exact revision.
    /// Retrying an acknowledged-or-not request with the same digest returns
    /// `already-applied`; a different stale request receives the current
    /// revision and no mutation.
    pub async fn apply_busy_reconciliation(
        &self,
        authority: &AuthorizedBusySource,
        request: &BusyReconciliationRequest,
    ) -> Result<BusyApplyOutcome, BusyStoreError> {
        let request_digest = busy_reconciliation_request_digest(request, authority)
            .map_err(|_| StoreError::Corrupt)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction
            .execute(
                "INSERT INTO scheduling_busy_source_heads(source_id) VALUES($1) ON CONFLICT(source_id) DO NOTHING",
                &[&authority.source_id()],
            )
            .await?;
        let row = transaction
            .query_one(
                "SELECT revision,last_request_digest,last_outcome FROM scheduling_busy_source_heads WHERE source_id=$1 FOR UPDATE",
                &[&authority.source_id()],
            )
            .await?;
        let current_i64: i64 = row.get(0);
        let current = u64::try_from(current_i64).map_err(|_| StoreError::Corrupt)?;
        let previous_digest: Option<String> = row.get(1);
        let previous_outcome: Option<serde_json::Value> = row.get(2);
        if current != request.expected_revision {
            if current == request.expected_revision.saturating_add(1)
                && previous_digest.as_deref() == Some(&request_digest)
            {
                let mut applied: BusyApplyOutcome = previous_outcome
                    .ok_or(BusyStoreError::RecoveryUnavailable)
                    .and_then(|value| {
                        serde_json::from_value(value)
                            .map_err(|_| BusyStoreError::RecoveryUnavailable)
                    })?;
                if applied.kind != BusyApplyOutcomeKind::Applied
                    || applied.source_id != authority.source_id()
                    || applied.revision != current
                    || applied.request_digest != request_digest
                {
                    return Err(BusyStoreError::RecoveryUnavailable);
                }
                applied.kind = BusyApplyOutcomeKind::AlreadyApplied;
                transaction.commit().await?;
                return Ok(applied);
            }
            return Err(BusyStoreError::RevisionMismatch {
                expected: request.expected_revision,
                current,
            });
        }
        lock_covered_supply(&transaction, &request.coverage.resources).await?;
        reject_non_monotonic_observation(&transaction, authority.source_id(), request).await?;
        reject_boundary_replacement(&transaction, authority.source_id(), request).await?;
        let diff = reconciliation_diff(&transaction, authority, request).await?;
        let impacts = reconciliation_impacts(
            &transaction,
            request,
            self.observed_now(),
            authority.includes_impact_details(),
        )
        .await?;
        let next = current.checked_add(1).ok_or(StoreError::Corrupt)?;
        let next_i64 = i64::try_from(next).map_err(|_| StoreError::Corrupt)?;
        let records = serde_json::to_value(&request.records).map_err(|_| StoreError::Corrupt)?;

        if request.status == BusySourceStatus::Fresh {
            transaction
                .execute(
                    "WITH input AS ( \
                       SELECT * FROM jsonb_to_recordset($5::jsonb) AS i( \
                         \"externalUid\" text, \"externalRevision\" text, resource text, \
                         start timestamptz, \"end\" timestamptz) \
                     ) \
                     DELETE FROM scheduling_busy_intervals b \
                     WHERE b.source_id=$1 AND b.resource_id=ANY($2) \
                       AND b.busy_start >= $3 AND b.busy_end <= $4 \
                       AND NOT EXISTS (SELECT 1 FROM input i \
                         WHERE i.resource=b.resource_id AND i.\"externalUid\"=b.external_uid)",
                    &[
                        &authority.source_id(),
                        &request.coverage.resources,
                        &request.coverage.start,
                        &request.coverage.end,
                        &records,
                    ],
                )
                .await?;
            transaction
                .execute(
                    "WITH input AS ( \
                       SELECT * FROM jsonb_to_recordset($4::jsonb) AS i( \
                         \"externalUid\" text, \"externalRevision\" text, resource text, \
                         start timestamptz, \"end\" timestamptz) \
                     ) \
                     INSERT INTO scheduling_busy_intervals( \
                       source_id,resource_id,external_uid,external_revision,busy_start,busy_end, \
                       source_revision,observed_at,updated_at) \
                     SELECT $1,i.resource,i.\"externalUid\",i.\"externalRevision\",i.start,i.\"end\",$2,$3,now() \
                     FROM input i \
                     ON CONFLICT(source_id,resource_id,external_uid) DO UPDATE SET \
                       external_revision=EXCLUDED.external_revision,busy_start=EXCLUDED.busy_start, \
                       busy_end=EXCLUDED.busy_end,source_revision=EXCLUDED.source_revision, \
                       observed_at=EXCLUDED.observed_at,updated_at=now()",
                    &[&authority.source_id(), &next_i64, &request.observed_at, &records],
                )
                .await?;
        }

        let status = match request.status {
            BusySourceStatus::Fresh => "fresh",
            BusySourceStatus::Unavailable => "unavailable",
        };
        transaction
            .execute(
                "INSERT INTO scheduling_busy_source_coverage( \
                   source_id,resource_id,source_revision,status,coverage_start,coverage_end, \
                   observed_at,fresh_until,updated_at) \
                 SELECT $1,resource,$2,$3,$4,$5,$6,$7,now() FROM unnest($8::text[]) resource \
                 ON CONFLICT(source_id,resource_id) DO UPDATE SET \
                   source_revision=EXCLUDED.source_revision,status=EXCLUDED.status, \
                   coverage_start=EXCLUDED.coverage_start,coverage_end=EXCLUDED.coverage_end, \
                   observed_at=EXCLUDED.observed_at,fresh_until=EXCLUDED.fresh_until,updated_at=now()",
                &[
                    &authority.source_id(),
                    &next_i64,
                    &status,
                    &request.coverage.start,
                    &request.coverage.end,
                    &request.observed_at,
                    &request.fresh_until,
                    &request.coverage.resources,
                ],
            )
            .await?;
        let applied = outcome(
            BusyApplyOutcomeKind::Applied,
            authority,
            next,
            request_digest.clone(),
            diff,
            impacts,
        );
        let stored_outcome = serde_json::to_value(&applied).map_err(|_| StoreError::Corrupt)?;
        transaction
            .execute(
                "UPDATE scheduling_busy_source_heads SET revision=$2,last_request_digest=$3,last_outcome=$4,updated_at=now() WHERE source_id=$1",
                &[
                    &authority.source_id(),
                    &next_i64,
                    &request_digest,
                    &stored_outcome,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(applied)
    }
}

/// One source id is one totally ordered observation stream. Exact-digest
/// lost-ack replay is resolved before this check. Every different mutation
/// must therefore carry an observation strictly newer than the source's last
/// applied snapshot. This also prevents equal, second-resolution timestamps
/// from replacing overlapping facts with different content.
async fn reject_non_monotonic_observation(
    client: &impl GenericClient,
    source_id: &str,
    request: &BusyReconciliationRequest,
) -> Result<(), BusyStoreError> {
    let row = client
        .query_one(
            "SELECT max(observed_at) FROM scheduling_busy_source_coverage WHERE source_id=$1",
            &[&source_id],
        )
        .await?;
    let latest: Option<DateTime<Utc>> = row.get(0);
    if latest.is_some_and(|latest| request.observed_at <= latest) {
        return Err(BusyStoreError::ObservationConflict);
    }
    Ok(())
}

fn outcome(
    kind: BusyApplyOutcomeKind,
    authority: &AuthorizedBusySource,
    revision: u64,
    request_digest: String,
    diff: BusyDiff,
    impacts: BusyImpactSummary,
) -> BusyApplyOutcome {
    BusyApplyOutcome {
        kind,
        source_id: authority.source_id().to_owned(),
        revision,
        request_digest,
        added: diff.added,
        changed: diff.changed,
        deleted: diff.deleted,
        retained_outside_authority: diff.retained_outside_authority,
        retained_across_coverage_boundary: diff.retained_across_coverage_boundary,
        impacts,
    }
}

async fn source_revision(
    client: &impl GenericClient,
    source_id: &str,
) -> Result<u64, BusyStoreError> {
    let revision = client
        .query_opt(
            "SELECT revision FROM scheduling_busy_source_heads WHERE source_id=$1",
            &[&source_id],
        )
        .await?;
    revision.map_or(Ok(0), |row| {
        u64::try_from(row.get::<_, i64>(0)).map_err(|_| StoreError::Corrupt.into())
    })
}

async fn ensure_resources_exist(
    client: &impl GenericClient,
    resources: &[String],
) -> Result<(), BusyStoreError> {
    let row = client
        .query_one(
            "SELECT count(DISTINCT resource_id) FROM scheduling_pool_members WHERE resource_id=ANY($1)",
            &[&resources],
        )
        .await?;
    let count: i64 = row.get(0);
    if usize::try_from(count).ok() != Some(resources.len()) {
        return Err(BusyStoreError::ResourceMissing);
    }
    Ok(())
}

async fn lock_covered_supply(
    transaction: &deadpool_postgres::Transaction<'_>,
    resources: &[String],
) -> Result<(), BusyStoreError> {
    let rows = transaction
        .query(
            "SELECT DISTINCT pool_id FROM scheduling_pool_members WHERE resource_id=ANY($1) ORDER BY pool_id",
            &[&resources],
        )
        .await?;
    let anchors: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
    if anchors.is_empty() {
        return Err(BusyStoreError::ResourceMissing);
    }
    ensure_resources_exist(transaction, resources).await?;
    transaction.lock_supply(&anchors).await?;
    Ok(())
}

/// A record crossing the coverage edge is retained if omitted. It cannot be
/// replaced by the same stable key, because that would silently discard the
/// portion outside the source's authoritative snapshot.
async fn reject_boundary_replacement(
    client: &impl GenericClient,
    source_id: &str,
    request: &BusyReconciliationRequest,
) -> Result<(), BusyStoreError> {
    if request.status == BusySourceStatus::Unavailable || request.records.is_empty() {
        return Ok(());
    }
    let records = serde_json::to_value(&request.records).map_err(|_| StoreError::Corrupt)?;
    let row = client
        .query_one(
            "WITH input AS ( \
               SELECT * FROM jsonb_to_recordset($4::jsonb) AS i( \
                 \"externalUid\" text, resource text) \
             ) \
             SELECT EXISTS(SELECT 1 FROM scheduling_busy_intervals b JOIN input i \
               ON i.resource=b.resource_id AND i.\"externalUid\"=b.external_uid \
               WHERE b.source_id=$1 AND NOT (b.busy_start >= $2 AND b.busy_end <= $3))",
            &[
                &source_id,
                &request.coverage.start,
                &request.coverage.end,
                &records,
            ],
        )
        .await?;
    if row.get(0) {
        return Err(BusyStoreError::CoverageBoundary);
    }
    Ok(())
}

async fn reconciliation_diff(
    client: &impl GenericClient,
    authority: &AuthorizedBusySource,
    request: &BusyReconciliationRequest,
) -> Result<BusyDiff, BusyStoreError> {
    let retained = client
        .query_one(
            "SELECT \
               count(*) FILTER (WHERE NOT (resource_id=ANY($2))) AS outside_authority, \
               count(*) FILTER (WHERE resource_id=ANY($3) \
                 AND busy_start < $5 AND $4 < busy_end \
                 AND NOT (busy_start >= $4 AND busy_end <= $5)) AS crossing \
             FROM scheduling_busy_intervals WHERE source_id=$1",
            &[
                &authority.source_id(),
                &authority.resources().iter().cloned().collect::<Vec<_>>(),
                &request.coverage.resources,
                &request.coverage.start,
                &request.coverage.end,
            ],
        )
        .await?;
    let retained_outside_authority = count(retained.get(0))?;
    let retained_across_coverage_boundary = count(retained.get(1))?;
    if request.status == BusySourceStatus::Unavailable {
        return Ok(BusyDiff {
            retained_outside_authority,
            retained_across_coverage_boundary,
            ..BusyDiff::default()
        });
    }
    let records = serde_json::to_value(&request.records).map_err(|_| StoreError::Corrupt)?;
    let row = client
        .query_one(
            "WITH input AS ( \
               SELECT * FROM jsonb_to_recordset($5::jsonb) AS i( \
                 \"externalUid\" text, \"externalRevision\" text, resource text, \
                 start timestamptz, \"end\" timestamptz) \
             ), compared AS ( \
               SELECT i.*,b.external_uid,b.external_revision,b.busy_start,b.busy_end \
               FROM input i LEFT JOIN scheduling_busy_intervals b \
                 ON b.source_id=$1 AND b.resource_id=i.resource AND b.external_uid=i.\"externalUid\" \
             ) \
             SELECT \
               count(*) FILTER (WHERE external_uid IS NULL), \
               count(*) FILTER (WHERE external_uid IS NOT NULL AND ( \
                 external_revision IS DISTINCT FROM \"externalRevision\" \
                 OR busy_start IS DISTINCT FROM start OR busy_end IS DISTINCT FROM \"end\")), \
               (SELECT count(*) FROM scheduling_busy_intervals b \
                 WHERE b.source_id=$1 AND b.resource_id=ANY($2) \
                   AND b.busy_start >= $3 AND b.busy_end <= $4 \
                   AND NOT EXISTS (SELECT 1 FROM input i \
                     WHERE i.resource=b.resource_id AND i.\"externalUid\"=b.external_uid)) \
             FROM compared",
            &[
                &authority.source_id(),
                &request.coverage.resources,
                &request.coverage.start,
                &request.coverage.end,
                &records,
            ],
        )
        .await?;
    Ok(BusyDiff {
        added: count(row.get(0))?,
        changed: count(row.get(1))?,
        deleted: count(row.get(2))?,
        retained_outside_authority,
        retained_across_coverage_boundary,
    })
}

async fn reconciliation_impacts(
    client: &impl GenericClient,
    request: &BusyReconciliationRequest,
    now: DateTime<Utc>,
    include_details: bool,
) -> Result<BusyImpactSummary, BusyStoreError> {
    if request.status == BusySourceStatus::Fresh && request.records.is_empty() {
        return Ok(BusyImpactSummary {
            total: 0,
            details_available: include_details,
            truncated: false,
            items: Vec::new(),
        });
    }
    let records = if request.status == BusySourceStatus::Unavailable {
        serde_json::Value::Array(
            request
                .coverage
                .resources
                .iter()
                .map(|resource| {
                    serde_json::json!({
                        "resource": resource,
                        "start": request.coverage.start,
                        "end": request.coverage.end,
                    })
                })
                .collect(),
        )
    } else {
        serde_json::to_value(&request.records).map_err(|_| StoreError::Corrupt)?
    };
    let impacted = "WITH input AS ( \
           SELECT * FROM jsonb_to_recordset($1::jsonb) AS i( \
             resource text,start timestamptz,\"end\" timestamptz) \
         ), impacted AS ( \
           SELECT DISTINCT c.claim_id,c.kind,a.resource_id,a.occupied_start,a.occupied_end \
           FROM input i JOIN scheduling_claim_allocations a ON a.resource_id=i.resource \
             AND a.occupied_start < i.\"end\" AND i.start < a.occupied_end \
           JOIN scheduling_claims c ON c.claim_id=a.claim_id \
           WHERE c.state='active' \
             AND (c.kind IN ('booking','window') OR (c.kind='hold' AND c.hold_expires_at > $3)) \
         ) ";
    if !include_details {
        let statement = format!("{impacted} SELECT count(*) FROM impacted WHERE $2::bigint=0");
        let total = count(
            client
                .query_one(&statement, &[&records, &0_i64, &now])
                .await?
                .get(0),
        )?;
        return Ok(BusyImpactSummary {
            total,
            details_available: false,
            truncated: total > 0,
            items: Vec::new(),
        });
    }
    let limit = i64::try_from(MAX_BUSY_IMPORT_IMPACTS).map_err(|_| StoreError::Corrupt)?;
    let statement = format!(
        "{impacted} SELECT kind,resource_id,occupied_start,occupied_end,count(*) OVER() \
         FROM impacted ORDER BY occupied_start,claim_id,resource_id LIMIT $2"
    );
    let rows = client.query(&statement, &[&records, &limit, &now]).await?;
    let total = rows.first().map_or(Ok(0), |row| count(row.get(4)))?;
    Ok(BusyImpactSummary {
        total,
        details_available: true,
        truncated: total > u64::try_from(rows.len()).map_err(|_| StoreError::Corrupt)?,
        items: rows
            .iter()
            .map(|row| BusyCommitmentImpact {
                kind: row.get(0),
                resource: row.get(1),
                occupied_start: row.get(2),
                occupied_end: row.get(3),
            })
            .collect(),
    })
}

fn count(value: i64) -> Result<u64, BusyStoreError> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt.into())
}

/// The allocation-side predicate shared wiring must invoke for every atomic
/// resource allocation. Retained busy rows always block overlaps. Each
/// currently configured source binding for the resource must also have fresh
/// coverage containing the whole requested interval.
pub async fn resource_interval_is_available(
    client: &impl GenericClient,
    required_sources: &[String],
    resource: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<bool, BusyStoreError> {
    if start >= end {
        return Ok(false);
    }
    let row = client
        .query_one(
            "SELECT \
               NOT EXISTS(SELECT 1 FROM scheduling_busy_intervals b \
                 WHERE b.resource_id=$1 AND b.busy_start < $3 AND $2 < b.busy_end), \
               (SELECT count(*) FROM scheduling_busy_source_coverage c \
                 WHERE c.source_id=ANY($4) AND c.resource_id=$1 AND c.status='fresh' \
                   AND c.coverage_start <= $2 AND c.coverage_end >= $3 \
                   AND c.observed_at <= $5 AND c.fresh_until > $5)",
            &[&resource, &start, &end, &required_sources, &now],
        )
        .await?;
    let no_busy_overlap: bool = row.get(0);
    let covered: i64 = row.get(1);
    Ok(no_busy_overlap && usize::try_from(covered).ok() == Some(required_sources.len()))
}

/// Add one synthetic full-capacity claim for each candidate whose requested
/// interval overlaps retained busy time or lacks fresh configured coverage.
/// The pure allocator then applies its ordinary every-allocation capacity
/// semantics without learning source protocol concepts.
pub(super) async fn append_busy_allocation_blocks(
    client: &impl GenericClient,
    bindings: &std::collections::BTreeMap<String, Vec<String>>,
    lines: &[BundleSupplyLine<'_>],
    request: &registry_scheduling_core::AdmissionRequest,
    now: DateTime<Utc>,
    snapshot: &mut registry_scheduling_core::LedgerSnapshot,
) -> Result<(), BusyStoreError> {
    let Some(primary) = lines.first() else {
        return Err(StoreError::Corrupt.into());
    };
    let duration = primary
        .exact
        .selected_duration_minutes(request.duration_minutes)
        .ok_or(StoreError::Corrupt)?;
    let displayed_end = request
        .start
        .checked_add_signed(chrono::TimeDelta::minutes(i64::from(duration)))
        .ok_or(StoreError::Corrupt)?;
    let mut candidates = Vec::new();
    for line in lines {
        let start = request
            .start
            .checked_sub_signed(chrono::TimeDelta::minutes(i64::from(
                line.exact.buffer_before_minutes,
            )))
            .ok_or(StoreError::Corrupt)?;
        let end = displayed_end
            .checked_add_signed(chrono::TimeDelta::minutes(i64::from(
                line.exact.buffer_after_minutes,
            )))
            .ok_or(StoreError::Corrupt)?;
        for member in line.members {
            if member.capacity_units == 0 {
                continue;
            }
            candidates.push(serde_json::json!({
                "resource": member.resource_id,
                "start": start,
                "end": end,
                "units": member.capacity_units,
                "requiredSources": bindings
                    .get(&member.resource_id)
                    .cloned()
                    .unwrap_or_default(),
            }));
        }
    }
    if candidates.is_empty() {
        return Ok(());
    }
    let rows = client
        .query(
            "WITH candidates AS ( \
               SELECT * FROM jsonb_to_recordset($1::jsonb) AS c( \
                 resource text,start timestamptz,\"end\" timestamptz,units integer, \
                 \"requiredSources\" jsonb) \
             ) \
             SELECT resource,start,\"end\",units FROM candidates c \
             WHERE EXISTS(SELECT 1 FROM scheduling_busy_intervals b \
                     WHERE b.resource_id=c.resource \
                       AND b.busy_start < c.\"end\" AND c.start < b.busy_end) \
                OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(c.\"requiredSources\") s(source_id) \
                     WHERE NOT EXISTS(SELECT 1 FROM scheduling_busy_source_coverage x \
                       WHERE x.source_id=s.source_id AND x.resource_id=c.resource \
                         AND x.status='fresh' AND x.coverage_start <= c.start \
                         AND x.coverage_end >= c.\"end\" AND x.observed_at <= $2 \
                         AND x.fresh_until > $2)) \
             ORDER BY resource,start,\"end\"",
            &[&serde_json::Value::Array(candidates), &now],
        )
        .await?;
    if snapshot.claims.len().saturating_add(rows.len()) > 4_096 {
        return Err(StoreError::CapacitySnapshotTooLarge.into());
    }
    for (index, row) in rows.iter().enumerate() {
        snapshot.claims.push(registry_scheduling_core::LedgerClaim {
            id: format!("source-busy-block-{index}"),
            offering: "source-busy".to_owned(),
            supply_id: row.get(0),
            kind: registry_scheduling_core::LedgerKind::Booking,
            channel: None,
            start: row.get(1),
            end: row.get(2),
            units: u32::try_from(row.get::<_, i32>(3)).map_err(|_| StoreError::Corrupt)?,
            duplicate_key: None,
            expires_at: None,
        });
    }
    Ok(())
}

/// Add effective source unavailability to a read-only availability snapshot.
/// Busy rows retain their exact intervals. Fresh coverage from all configured
/// sources is intersected; the uncovered prefix and suffix are blocked.
pub(super) async fn append_busy_search_blocks(
    client: &impl GenericClient,
    bindings: &std::collections::BTreeMap<String, Vec<String>>,
    resources: &[String],
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    now: DateTime<Utc>,
    snapshot: &mut registry_scheduling_core::LedgerSnapshot,
) -> Result<(), BusyStoreError> {
    if resources.is_empty() || from >= to {
        return Ok(());
    }
    let capacities = client
        .query(
            "SELECT resource_id,capacity_units FROM scheduling_pool_members WHERE resource_id=ANY($1)",
            &[&resources],
        )
        .await?
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, i32>(1)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let busy = client
        .query(
            "WITH combined AS ( \
               SELECT resource_id,range_agg(tstzrange( \
                 GREATEST(busy_start,$2),LEAST(busy_end,$3),'[)')) AS spans \
               FROM scheduling_busy_intervals \
               WHERE resource_id=ANY($1) AND busy_start < $3 AND $2 < busy_end \
               GROUP BY resource_id \
             ) \
             SELECT resource_id,lower(span),upper(span) \
             FROM combined CROSS JOIN LATERAL unnest(spans) span \
             ORDER BY resource_id,lower(span)",
            &[&resources, &from, &to],
        )
        .await?;
    let coverage = client
        .query(
            "SELECT source_id,resource_id,status,coverage_start,coverage_end,observed_at,fresh_until \
             FROM scheduling_busy_source_coverage \
             WHERE resource_id=ANY($1) ORDER BY resource_id,source_id",
            &[&resources],
        )
        .await?;
    let mut coverage_by_key = std::collections::BTreeMap::new();
    for row in coverage {
        coverage_by_key.insert(
            (row.get::<_, String>(1), row.get::<_, String>(0)),
            (
                row.get::<_, String>(2),
                row.get::<_, DateTime<Utc>>(3),
                row.get::<_, DateTime<Utc>>(4),
                row.get::<_, DateTime<Utc>>(5),
                row.get::<_, Option<DateTime<Utc>>>(6),
            ),
        );
    }
    let mut blocks = busy
        .into_iter()
        .map(|row| {
            (
                row.get::<_, String>(0),
                row.get::<_, DateTime<Utc>>(1),
                row.get::<_, DateTime<Utc>>(2),
            )
        })
        .collect::<Vec<_>>();
    for resource in resources {
        let Some(required) = bindings.get(resource) else {
            continue;
        };
        if required.is_empty() {
            continue;
        }
        let mut covered_start = from;
        let mut covered_end = to;
        let mut complete = true;
        for source in required {
            let Some((status, start, end, observed_at, fresh_until)) =
                coverage_by_key.get(&(resource.clone(), source.clone()))
            else {
                complete = false;
                break;
            };
            if status != "fresh"
                || *observed_at > now
                || !fresh_until.is_some_and(|fresh_until| fresh_until > now)
            {
                complete = false;
                break;
            }
            covered_start = covered_start.max(*start);
            covered_end = covered_end.min(*end);
        }
        if !complete || covered_start >= covered_end {
            blocks.push((resource.clone(), from, to));
        } else {
            if from < covered_start {
                blocks.push((resource.clone(), from, covered_start.min(to)));
            }
            if covered_end < to {
                blocks.push((resource.clone(), covered_end.max(from), to));
            }
        }
    }
    blocks.sort_unstable_by(|left, right| {
        (&left.0, left.1, left.2).cmp(&(&right.0, right.1, right.2))
    });
    let mut merged: Vec<(String, DateTime<Utc>, DateTime<Utc>)> = Vec::new();
    for (resource, start, end) in blocks {
        if start >= end {
            continue;
        }
        if let Some((previous_resource, _, previous_end)) = merged.last_mut() {
            if previous_resource == &resource && start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((resource, start, end));
    }
    if snapshot.claims.len().saturating_add(merged.len()) > 4_096 {
        return Err(StoreError::CapacitySnapshotTooLarge.into());
    }
    for (index, (resource, start, end)) in merged.into_iter().enumerate() {
        let capacity = capacities.get(&resource).ok_or(StoreError::Corrupt)?;
        if *capacity == 0 {
            continue;
        }
        snapshot.claims.push(registry_scheduling_core::LedgerClaim {
            id: format!("source-busy-read-block-{index}"),
            offering: "source-busy".to_owned(),
            supply_id: resource,
            kind: registry_scheduling_core::LedgerKind::Booking,
            channel: None,
            start,
            end,
            units: u32::try_from(*capacity).map_err(|_| StoreError::Corrupt)?,
            duplicate_key: None,
            expires_at: None,
        });
    }
    Ok(())
}
