// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL computation and immutable storage for governed statistical datasets.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, NaiveDate, Utc};
use registry_platform_canonical_json::canonicalize_json;
use tokio_postgres::types::ToSql;

use crate::api::{AuthorizedRequestContext, ReadServiceError};
use crate::audit::RegistryAudit;
use crate::history_reference::SnapshotReference;
use crate::idempotency::{
    insert_result, lock_and_load, resolve_binding, HeldResponse, IdempotencyBinding,
    IdempotencyError, IdempotencyKeyDomain, IdempotencyPolicy, PermittedResponseHeader,
    StoredResultMetadata,
};
use crate::model::{
    CompiledEntity, CompiledRegistry, CompiledStatisticalDataset,
    CompiledStatisticalDimensionDomain, CompiledStatisticalPeriod, CompiledStatisticalValidity,
    HttpMethod,
};
use crate::mutation::BoundValue;
use crate::statistics::{
    apply_disclosure, build_exact_cells, canonical_document_and_digest, current_period,
    period_for_code, period_range, Cell, DatasetDocument, DimensionDomain, DisclosureDocument,
    GroupedCell, LiveDocument, Measure, Period, PeriodDocument, PeriodGranularity, PeriodKind,
    PeriodVersionHeader, ReleaseDocument, ReleaseStatus, ReleaseVersionHeader, StatisticsDocument,
    StatisticsError, WithdrawalDocument, WithdrawalReason, MAX_CELLS_PER_RESPONSE,
};

use super::read::{
    install_statistics_evaluation_date, read_predicates, strict_claim_context, ReadRelations,
};
use super::{
    begin_record_transaction, ExpectedRegistryIdentity, GuardedTransaction, RegistryLockKey,
    RuntimePool,
};

const CONTENT_TYPE_JSON: &[u8] = b"application/json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatisticsReleaseSelection {
    Any,
    Final,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatisticsReleaseRefusal {
    PeriodNotEnded,
    BeforeFirstPeriod,
    ProvisionalAfterFinal,
    AlreadyWithdrawn,
}

#[derive(Debug, thiserror::Error)]
pub enum StatisticsServiceError {
    #[error("statistical dataset is not available")]
    Concealed,
    #[error("statistical query is invalid")]
    QueryInvalid { field_path: &'static str },
    #[error("statistical release was refused")]
    ReleaseRefused(StatisticsReleaseRefusal),
    #[error("statistical release version conflicts with current state")]
    VersionConflict,
    #[error("statistical release version was withdrawn")]
    VersionWithdrawn { reason_code: String },
    #[error("statistical dimension domain was violated")]
    DomainViolation {
        dataset_id: String,
        dimension: String,
    },
    #[error("statistical request timed out")]
    Timeout,
    #[error("idempotency key is already bound to another request")]
    IdempotencyConflict,
    #[error("idempotency key is spent and its held response has expired")]
    IdempotencyExpired,
    #[error("statistical service is unavailable")]
    Unavailable,
    /// A release or withdrawal reached its commit and its outcome is not
    /// proven: the commit itself failed, or the deadline passed while it was
    /// in flight. The attempt is answered `unfinished`, never refused, and
    /// callers see the same response as `Unavailable`.
    #[error("statistical release commit outcome is not proven")]
    CommitUnresolved,
}

pub struct StatisticsLiveRequest<'a> {
    pub context: &'a AuthorizedRequestContext,
    pub dataset_id: &'a str,
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub today: NaiveDate,
    pub deadline: tokio::time::Instant,
}

pub struct StatisticsPublishRequest<'a> {
    pub context: &'a AuthorizedRequestContext,
    pub dataset_id: &'a str,
    pub period_code: &'a str,
    pub status: ReleaseStatus,
    pub idempotency_key: &'a str,
    pub route_id: &'a str,
    pub canonical_request_digest: [u8; 32],
    pub computed_at: DateTime<Utc>,
    pub today: NaiveDate,
    pub deadline: tokio::time::Instant,
}

pub struct StatisticsWithdrawalRequest<'a> {
    pub context: &'a AuthorizedRequestContext,
    pub dataset_id: &'a str,
    pub period_code: &'a str,
    pub version: i64,
    pub reason: WithdrawalReason,
    pub idempotency_key: &'a str,
    pub route_id: &'a str,
    pub canonical_request_digest: [u8; 32],
    pub deadline: tokio::time::Instant,
}

pub struct StatisticsVersionReadRequest<'a> {
    pub context: &'a AuthorizedRequestContext,
    pub dataset_id: &'a str,
    pub period_code: &'a str,
    pub version: Option<i64>,
    pub selection: StatisticsReleaseSelection,
    pub deadline: tokio::time::Instant,
}

pub struct StatisticsReleaseListRequest<'a> {
    pub context: &'a AuthorizedRequestContext,
    pub dataset_id: &'a str,
    pub after: Option<StatisticsReleaseListCursor>,
    pub limit: u16,
    pub deadline: tokio::time::Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatisticsReleaseListCursor {
    pub period: String,
    pub version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatisticsReleasePage {
    pub items: Vec<ReleaseVersionHeader>,
    pub has_more: bool,
    pub next: Option<StatisticsReleaseListCursor>,
}

pub struct StatisticsSeriesRequest<'a> {
    pub context: &'a AuthorizedRequestContext,
    pub dataset_id: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub selection: StatisticsReleaseSelection,
    pub today: NaiveDate,
    pub deadline: tokio::time::Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatisticsStoredDocument {
    pub header: ReleaseVersionHeader,
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct StatisticsMutationOutcome {
    pub response: HeldResponse,
    pub replayed: bool,
    pub header: ReleaseVersionHeader,
    pub result_count: usize,
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
#[derive(Clone)]
pub struct StatisticsPublishPause {
    reached: Arc<tokio::sync::Semaphore>,
    resume: Arc<tokio::sync::Semaphore>,
}

#[cfg(feature = "postgres-test")]
impl Default for StatisticsPublishPause {
    fn default() -> Self {
        Self {
            reached: Arc::new(tokio::sync::Semaphore::new(0)),
            resume: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }
}

#[cfg(feature = "postgres-test")]
impl StatisticsPublishPause {
    pub async fn wait_until_reached(&self) {
        self.reached
            .acquire()
            .await
            .expect("statistics publish pause remains open")
            .forget();
    }

    pub fn resume(&self) {
        self.resume.add_permits(1);
    }
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
#[derive(Clone)]
pub struct StatisticsWithdrawalPause {
    reached: Arc<tokio::sync::Semaphore>,
    resume: Arc<tokio::sync::Semaphore>,
}

#[cfg(feature = "postgres-test")]
impl Default for StatisticsWithdrawalPause {
    fn default() -> Self {
        Self {
            reached: Arc::new(tokio::sync::Semaphore::new(0)),
            resume: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }
}

#[cfg(feature = "postgres-test")]
impl StatisticsWithdrawalPause {
    pub async fn wait_until_reached(&self) {
        self.reached
            .acquire()
            .await
            .expect("statistics withdrawal pause remains open")
            .forget();
    }

    pub fn resume(&self) {
        self.resume.add_permits(1);
    }
}

impl StatisticsStoredDocument {
    #[must_use]
    pub fn repr_digest(&self) -> String {
        repr_digest(&self.bytes)
    }
}

#[derive(Clone)]
pub struct PostgresStatisticsService {
    pool: RuntimePool,
    registry: Arc<CompiledRegistry>,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit: RegistryAudit,
    idempotency: IdempotencyPolicy,
    #[cfg(feature = "postgres-test")]
    test_trace: Option<Arc<std::sync::Mutex<Vec<String>>>>,
    #[cfg(feature = "postgres-test")]
    publish_pause: Option<StatisticsPublishPause>,
    #[cfg(feature = "postgres-test")]
    withdrawal_pause: Option<StatisticsWithdrawalPause>,
}

impl PostgresStatisticsService {
    async fn publish_replay(
        &self,
        dataset: &CompiledStatisticalDataset,
        request: &StatisticsPublishRequest<'_>,
    ) -> Result<Option<StatisticsMutationOutcome>, StatisticsServiceError> {
        let claims = strict_claim_context(&self.registry, request.context, &dataset.unit_entity_id)
            .map_err(map_read_error)?;
        let response_fields = BTreeSet::new();
        let binding = IdempotencyBinding {
            key: request.idempotency_key,
            context: &claims,
            method: HttpMethod::Post,
            route: request.route_id,
            target_record: None,
            package_revision: &self.expected.activation_id,
            response_fields: &response_fields,
            canonical_request_digest: request.canonical_request_digest,
            key_domain: IdempotencyKeyDomain::Caller,
        };
        let resolved = resolve_binding(self.audit.profile(), &self.idempotency, &binding)
            .map_err(map_idempotency)?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = begin_record_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout.min(remaining_budget(request.deadline)?),
            &self.expected,
            &claims,
        )
        .await
        .map_err(unavailable)?;
        transaction
            .set_statement_budget(remaining_budget(request.deadline)?)
            .await
            .map_err(unavailable)?;
        let stored = lock_and_load(transaction.transaction(), &resolved)
            .await
            .map_err(map_idempotency)?;
        transaction.commit().await.map_err(unavailable)?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        let matches = matches!(
            stored.metadata,
            StoredResultMetadata::Release {
                release_reference,
                release_version,
            } if release_reference == release_reference_for(dataset, request.period_code)
                && release_version > 0
        );
        if !matches {
            return Err(StatisticsServiceError::IdempotencyConflict);
        }
        Ok(Some(replayed_outcome(
            stored.response,
            dataset,
            request.period_code,
            published_cell_count(dataset)?,
        )?))
    }

    async fn persist_release(
        &self,
        dataset: &CompiledStatisticalDataset,
        period: Period,
        mut computation: Computation,
        request: StatisticsPublishRequest<'_>,
        commit: &CommitReach,
    ) -> Result<StatisticsMutationOutcome, StatisticsServiceError> {
        let history_head = computation
            .history_head
            .ok_or(StatisticsServiceError::Unavailable)?;
        let mut snapshot = computation.snapshot.take();
        let claims = strict_claim_context(&self.registry, request.context, &dataset.unit_entity_id)
            .map_err(map_read_error)?;
        let response_fields = BTreeSet::new();
        let binding = IdempotencyBinding {
            key: request.idempotency_key,
            context: &claims,
            method: HttpMethod::Post,
            route: request.route_id,
            target_record: None,
            package_revision: &self.expected.activation_id,
            response_fields: &response_fields,
            canonical_request_digest: request.canonical_request_digest,
            key_domain: IdempotencyKeyDomain::Caller,
        };
        let resolved = resolve_binding(self.audit.profile(), &self.idempotency, &binding)
            .map_err(map_idempotency)?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = match begin_record_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout.min(remaining_budget(request.deadline)?),
            &self.expected,
            &claims,
        )
        .await
        {
            Ok(transaction) => transaction,
            Err(_) => {
                if remaining_budget(request.deadline).is_err() {
                    return Err(StatisticsServiceError::Timeout);
                }
                let verification_client = self.pool.get().await.map_err(unavailable)?;
                return match active_identity_matches(&verification_client, &self.expected).await? {
                    Some(false) => Err(StatisticsServiceError::VersionConflict),
                    Some(true) | None => Err(StatisticsServiceError::Unavailable),
                };
            }
        };
        transaction
            .set_statement_budget(remaining_budget(request.deadline)?)
            .await
            .map_err(unavailable)?;
        if let Some(stored) = lock_and_load(transaction.transaction(), &resolved)
            .await
            .map_err(map_idempotency)?
        {
            transaction.commit().await.map_err(unavailable)?;
            let matches = matches!(
                stored.metadata,
                StoredResultMetadata::Release {
                    release_reference,
                    release_version,
                } if release_reference == release_reference_for(dataset, &period.code)
                    && release_version > 0
            );
            return if matches {
                replayed_outcome(
                    stored.response,
                    dataset,
                    &period.code,
                    published_cell_count(dataset)?,
                )
            } else {
                Err(StatisticsServiceError::IdempotencyConflict)
            };
        }
        lock_release_key(transaction.transaction(), dataset, &period.code).await?;
        if request.status == ReleaseStatus::Provisional {
            let final_exists = transaction
                .transaction()
                .query_one(
                    "SELECT EXISTS (
                         SELECT 1
                           FROM registry_internal.registry_statistical_release_versions
                          WHERE dataset_id = $1 AND period_code = $2
                            AND definition_digest = $3 AND release_status = 'final'
                     )",
                    &[&dataset.id, &period.code, &dataset.definition_digest],
                )
                .await
                .map_err(unavailable)?
                .get::<_, bool>(0);
            if final_exists {
                transaction.rollback().await.map_err(unavailable)?;
                return Err(StatisticsServiceError::ReleaseRefused(
                    StatisticsReleaseRefusal::ProvisionalAfterFinal,
                ));
            }
        }
        let row = transaction
            .transaction()
            .query_one(
                "SELECT COALESCE(max(release_version), 0),
                        COALESCE(max(history_head_position)
                            FILTER (WHERE definition_digest = $3), -1)
                   FROM registry_internal.registry_statistical_release_versions
                  WHERE dataset_id = $1 AND period_code = $2",
                &[&dataset.id, &period.code, &dataset.definition_digest],
            )
            .await
            .map_err(unavailable)?;
        let previous_version = row.get::<_, i64>(0);
        let previous_head = row.get::<_, i64>(1);
        if previous_head > history_head {
            transaction.rollback().await.map_err(unavailable)?;
            return Err(StatisticsServiceError::VersionConflict);
        }
        snapshot =
            revalidate_snapshot_for_persist(transaction.transaction(), history_head, snapshot)
                .await?;
        let version = previous_version
            .checked_add(1)
            .ok_or(StatisticsServiceError::Unavailable)?;
        apply_disclosure(&mut computation.cells, dataset.disclosure)
            .map_err(map_statistics_error)?;
        let document = document_for(
            dataset,
            vec![period.clone()],
            computation.cells,
            Some(ReleaseDocument {
                period: period.code.clone(),
                version: u64::try_from(version).map_err(|_| StatisticsServiceError::Unavailable)?,
                status: request.status,
                snapshot: snapshot.clone(),
                computed_at: request.computed_at.to_rfc3339(),
                package_digest: self.expected.package_digest.clone(),
            }),
            None,
            Some(DisclosureDocument::from(dataset.disclosure)),
        )?;
        let canonical = canonical_document_and_digest(&document).map_err(map_statistics_error)?;
        let result_count = document.cells.len();
        self.trace_for_test("publish.canonical");
        let snapshot_uuid = snapshot
            .as_deref()
            .map(crate::history_reference::SnapshotReference::parse)
            .transpose()
            .map_err(|_| StatisticsServiceError::Unavailable)?
            .map(|reference| reference.uuid());
        let inserted = transaction
            .transaction()
            .execute(
                "INSERT INTO registry_internal.registry_statistical_release_versions
                     (dataset_id, period_code, release_version, release_status,
                      history_head_position, snapshot_reference, computed_at,
                      package_digest, definition_digest, content_digest)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                &[
                    &dataset.id,
                    &period.code,
                    &version,
                    &release_status(request.status),
                    &history_head,
                    &snapshot_uuid,
                    &request.computed_at,
                    &self.expected.package_digest,
                    &dataset.definition_digest,
                    &canonical.content_digest,
                ],
            )
            .await
            .map_err(|error| {
                self.trace_error_for_test("publish.version-error", &error);
                unavailable(error)
            })?;
        self.trace_for_test("publish.version-inserted");
        let content_inserted = transaction
            .transaction()
            .execute(
                "INSERT INTO registry_internal.registry_statistical_release_contents
                     (dataset_id, period_code, release_version, document)
                 VALUES ($1, $2, $3, $4)",
                &[&dataset.id, &period.code, &version, &canonical.bytes],
            )
            .await
            .map_err(unavailable)?;
        self.trace_for_test("publish.content-inserted");
        if inserted != 1 || content_inserted != 1 {
            return Err(StatisticsServiceError::Unavailable);
        }
        self.trace_for_test("publish.release-inserted");
        let header = ReleaseVersionHeader {
            dataset: dataset.id.clone(),
            period: period.code.clone(),
            version: u64::try_from(version).map_err(unavailable)?,
            status: request.status,
            snapshot,
            computed_at: request.computed_at.to_rfc3339(),
            package_digest: self.expected.package_digest.clone(),
            definition_digest: dataset.definition_digest.clone(),
            content_digest: Some(canonical.content_digest),
            withdrawal: None,
        };
        let response =
            held_json_response(201, &serde_json::to_value(&header).map_err(unavailable)?)?;
        insert_result(
            transaction.transaction(),
            &resolved,
            &StoredResultMetadata::Release {
                release_reference: release_reference_for(dataset, &period.code),
                release_version: version,
            },
            &response,
        )
        .await
        .map_err(map_idempotency)?;
        self.trace_for_test("publish.idempotency-inserted");
        commit_release_write(transaction, commit).await?;
        self.trace_for_test("publish.committed");
        Ok(StatisticsMutationOutcome {
            response,
            replayed: false,
            header,
            result_count,
        })
    }

    async fn compute(
        &self,
        dataset: &CompiledStatisticalDataset,
        context: &AuthorizedRequestContext,
        periods: &[Period],
        evaluation_date: NaiveDate,
        deadline: tokio::time::Instant,
        capture_history: bool,
    ) -> Result<Computation, StatisticsServiceError> {
        let entity = self
            .registry
            .entities()
            .get(&dataset.unit_entity_id)
            .ok_or(StatisticsServiceError::Unavailable)?;
        let operation = self
            .registry
            .queries()
            .operations
            .iter()
            .find(|operation| {
                operation.entity_id == dataset.unit_entity_id
                    && operation.profile_id == context.selected_profile()
                    && operation.kind == crate::model::CompiledQueryKind::List
                    && operation.read_path.is_none()
                    && operation.allow_count
            })
            .ok_or(StatisticsServiceError::Concealed)?;
        let filter =
            crate::api::compile_statistics_population(entity, operation, &dataset.population)
                .map_err(map_read_error)?;
        let required_fields = dataset
            .referenced_fields
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let relations =
            ReadRelations::statistics(entity, &required_fields).map_err(map_read_error)?;
        let predicates =
            read_predicates(entity, &relations, filter.as_ref(), None).map_err(map_read_error)?;
        let claims = strict_claim_context(&self.registry, context, &dataset.unit_entity_id)
            .map_err(map_read_error)?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = begin_record_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout.min(remaining_budget(deadline)?),
            &self.expected,
            &claims,
        )
        .await
        .map_err(unavailable)?;
        transaction
            .set_statement_budget(remaining_budget(deadline)?)
            .await
            .map_err(unavailable)?;
        crate::mutation::install_request_visibility_context(
            transaction.transaction(),
            entity,
            &claims,
            self.audit.profile(),
            &self.expected.database_id,
        )
        .await
        .map_err(unavailable)?;
        install_statistics_evaluation_date(transaction.transaction(), &evaluation_date.to_string())
            .await
            .map_err(map_read_error)?;
        let sql = grouped_sql(
            dataset,
            entity,
            &relations,
            &predicates.where_sql,
            periods,
            capture_history,
        )?;
        let parameters = predicates
            .values
            .iter()
            .map(BoundValue::as_parameter)
            .collect::<Vec<&(dyn ToSql + Sync)>>();
        let rows = transaction
            .transaction()
            .query(&sql, &parameters)
            .await
            .map_err(map_statement_error)?;
        let mut grouped = Vec::new();
        let mut history_head = None;
        let mut snapshot = None;
        for row in rows {
            if capture_history {
                let position = row.get::<_, i64>(0);
                let reference = snapshot_reference(row.get::<_, Option<String>>(1))?;
                let inconsistent_head = history_head
                    .replace(position)
                    .is_some_and(|prior| prior != position);
                let inconsistent_snapshot = snapshot
                    .replace(reference.clone())
                    .is_some_and(|prior| prior != reference);
                if inconsistent_head || inconsistent_snapshot {
                    return Err(StatisticsServiceError::Unavailable);
                }
            }
            let offset = if capture_history { 2 } else { 0 };
            let Some(period) = row.get::<_, Option<String>>(offset) else {
                continue;
            };
            let mut codes = Vec::with_capacity(dataset.dimensions.len());
            for index in 0..dataset.dimensions.len() {
                let code = row
                    .get::<_, Option<String>>(offset + 1 + index)
                    .ok_or(StatisticsServiceError::Unavailable)?;
                codes.push(code);
            }
            let value = row
                .get::<_, Option<i64>>(offset + 1 + dataset.dimensions.len())
                .ok_or(StatisticsServiceError::Unavailable)?;
            grouped.push(GroupedCell {
                period,
                codes,
                value: u64::try_from(value).map_err(|_| StatisticsServiceError::Unavailable)?,
            });
        }
        if capture_history && history_head.is_none() {
            return Err(StatisticsServiceError::Unavailable);
        }
        transaction.commit().await.map_err(unavailable)?;
        let cells = build_exact_cells(&dataset.id, periods, &dimensions(dataset), &grouped)
            .map_err(map_statistics_error)?;
        Ok(Computation {
            cells,
            history_head,
            snapshot: snapshot.flatten(),
        })
    }

    #[must_use]
    pub fn new(
        pool: RuntimePool,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit: RegistryAudit,
    ) -> Self {
        Self {
            pool,
            registry,
            expected,
            lock_key,
            lock_timeout,
            audit,
            idempotency: IdempotencyPolicy::default(),
            #[cfg(feature = "postgres-test")]
            test_trace: None,
            #[cfg(feature = "postgres-test")]
            publish_pause: None,
            #[cfg(feature = "postgres-test")]
            withdrawal_pause: None,
        }
    }

    /// Scope spent idempotency keys under the verified token issuer and keep
    /// held responses for the configured receipt horizon.
    #[must_use]
    pub fn with_idempotency_policy(mut self, policy: IdempotencyPolicy) -> Self {
        self.idempotency = policy;
        self
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[must_use]
    pub fn with_trace_for_test(mut self, trace: Arc<std::sync::Mutex<Vec<String>>>) -> Self {
        self.test_trace = Some(trace);
        self
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[must_use]
    pub fn with_publish_pause_for_test(mut self, pause: StatisticsPublishPause) -> Self {
        self.publish_pause = Some(pause);
        self
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[must_use]
    pub fn with_withdrawal_pause_for_test(mut self, pause: StatisticsWithdrawalPause) -> Self {
        self.withdrawal_pause = Some(pause);
        self
    }

    fn trace_for_test(&self, stage: &'static str) {
        #[cfg(feature = "postgres-test")]
        if let Some(trace) = &self.test_trace {
            trace
                .lock()
                .expect("statistics test trace lock")
                .push(stage.to_owned());
        }
        #[cfg(not(feature = "postgres-test"))]
        let _ = stage;
    }

    fn trace_error_for_test(&self, stage: &'static str, error: &tokio_postgres::Error) {
        #[cfg(feature = "postgres-test")]
        if let Some(trace) = &self.test_trace {
            let detail = error.as_db_error().map_or_else(
                || error.to_string(),
                |database| {
                    format!(
                        "{} {} constraint={:?}",
                        database.code().code(),
                        database.message(),
                        database.constraint()
                    )
                },
            );
            trace
                .lock()
                .expect("statistics test trace lock")
                .push(format!("{stage}: {detail}"));
        }
        #[cfg(not(feature = "postgres-test"))]
        let _ = (stage, error);
    }

    async fn pause_before_persist_for_test(&self) {
        #[cfg(feature = "postgres-test")]
        if let Some(pause) = &self.publish_pause {
            pause.reached.add_permits(1);
            pause
                .resume
                .acquire()
                .await
                .expect("statistics publish pause remains open")
                .forget();
        }
    }

    async fn pause_before_withdrawal_persist_for_test(&self) {
        #[cfg(feature = "postgres-test")]
        if let Some(pause) = &self.withdrawal_pause {
            pause.reached.add_permits(1);
            pause
                .resume
                .acquire()
                .await
                .expect("statistics withdrawal pause remains open")
                .forget();
        }
    }

    pub(crate) fn audit(&self) -> &RegistryAudit {
        &self.audit
    }

    pub(crate) fn expected(&self) -> &ExpectedRegistryIdentity {
        &self.expected
    }

    pub async fn live(
        &self,
        request: StatisticsLiveRequest<'_>,
    ) -> Result<StatisticsDocument, StatisticsServiceError> {
        within_deadline(request.deadline, self.live_inner(request)).await
    }

    async fn live_inner(
        &self,
        request: StatisticsLiveRequest<'_>,
    ) -> Result<StatisticsDocument, StatisticsServiceError> {
        let dataset = self.live_dataset(request.dataset_id, request.context)?;
        let periods = requested_periods(dataset, request.from, request.to, request.today)?;
        enforce_response_cell_limit(dataset, periods.len())?;
        let computation = self
            .compute(
                dataset,
                request.context,
                &periods,
                request.today,
                request.deadline,
                false,
            )
            .await?;
        document_for(
            dataset,
            periods,
            computation.cells,
            None,
            Some(LiveDocument {
                evaluated_at: request.today.to_string(),
                access_profile: request.context.selected_profile().to_owned(),
            }),
            None,
        )
    }

    pub async fn publish(
        &self,
        request: StatisticsPublishRequest<'_>,
    ) -> Result<StatisticsMutationOutcome, StatisticsServiceError> {
        let commit = CommitReach::default();
        write_within_deadline(
            request.deadline,
            &commit,
            self.publish_inner(request, &commit),
        )
        .await
    }

    async fn publish_inner(
        &self,
        request: StatisticsPublishRequest<'_>,
        commit: &CommitReach,
    ) -> Result<StatisticsMutationOutcome, StatisticsServiceError> {
        let dataset = self.publisher_dataset(request.dataset_id, request.context)?;
        if let Some(response) = self.publish_replay(dataset, &request).await? {
            return Ok(response);
        }
        let period = release_period(dataset, request.period_code, request.today)?;
        self.ensure_release_eligible(dataset, &period, request.status, request.deadline)
            .await?;
        let computation = self
            .compute(
                dataset,
                request.context,
                std::slice::from_ref(&period),
                period.reference_date,
                request.deadline,
                true,
            )
            .await?;
        self.trace_for_test("publish.computed");
        self.pause_before_persist_for_test().await;
        self.persist_release(dataset, period, computation, request, commit)
            .await
    }

    pub async fn withdraw(
        &self,
        request: StatisticsWithdrawalRequest<'_>,
    ) -> Result<StatisticsMutationOutcome, StatisticsServiceError> {
        let commit = CommitReach::default();
        write_within_deadline(
            request.deadline,
            &commit,
            self.withdraw_inner(request, &commit),
        )
        .await
    }

    async fn withdraw_inner(
        &self,
        request: StatisticsWithdrawalRequest<'_>,
        commit: &CommitReach,
    ) -> Result<StatisticsMutationOutcome, StatisticsServiceError> {
        let dataset = self.publisher_dataset(request.dataset_id, request.context)?;
        let reason_code = withdrawal_reason(request.reason);
        let claims = strict_claim_context(&self.registry, request.context, &dataset.unit_entity_id)
            .map_err(map_read_error)?;
        let response_fields = BTreeSet::new();
        let binding = IdempotencyBinding {
            key: request.idempotency_key,
            context: &claims,
            method: HttpMethod::Post,
            route: request.route_id,
            target_record: None,
            package_revision: &self.expected.activation_id,
            response_fields: &response_fields,
            canonical_request_digest: request.canonical_request_digest,
            key_domain: IdempotencyKeyDomain::Caller,
        };
        let resolved = resolve_binding(self.audit.profile(), &self.idempotency, &binding)
            .map_err(map_idempotency)?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = begin_record_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout.min(remaining_budget(request.deadline)?),
            &self.expected,
            &claims,
        )
        .await
        .map_err(unavailable)?;
        transaction
            .set_statement_budget(remaining_budget(request.deadline)?)
            .await
            .map_err(unavailable)?;
        if let Some(stored) = lock_and_load(transaction.transaction(), &resolved)
            .await
            .map_err(map_idempotency)?
        {
            let matches = matches!(
                stored.metadata,
                StoredResultMetadata::Release {
                    release_reference,
                    release_version,
                } if release_reference == release_reference_for(dataset, request.period_code)
                    && release_version == request.version
            );
            if !matches {
                transaction.rollback().await.map_err(unavailable)?;
                return Err(StatisticsServiceError::IdempotencyConflict);
            }
            transaction.commit().await.map_err(unavailable)?;
            return replayed_outcome(stored.response, dataset, request.period_code, 0);
        }
        let _period = release_period(dataset, request.period_code, NaiveDate::MAX)?;
        if request.period_code < first_period(dataset).as_str() {
            transaction.rollback().await.map_err(unavailable)?;
            return Err(StatisticsServiceError::ReleaseRefused(
                StatisticsReleaseRefusal::BeforeFirstPeriod,
            ));
        }
        if request.version <= 0 {
            transaction.rollback().await.map_err(unavailable)?;
            return Err(StatisticsServiceError::Concealed);
        }
        self.pause_before_withdrawal_persist_for_test().await;
        lock_release_key(transaction.transaction(), dataset, request.period_code).await?;
        let state = transaction
            .transaction()
            .query_opt(
                "SELECT version.release_version, version.release_status,
                        version.snapshot_reference::text, version.computed_at,
                        version.package_digest, version.definition_digest,
                        version.content_digest, withdrawal.reason_code,
                        withdrawal.withdrawn_at
                   FROM registry_internal.registry_statistical_release_versions AS version
              LEFT JOIN registry_internal.registry_statistical_release_withdrawals AS withdrawal
                     USING (dataset_id, period_code, release_version)
                  WHERE version.dataset_id = $1 AND version.period_code = $2
                    AND version.release_version = $3",
                &[&dataset.id, &request.period_code, &request.version],
            )
            .await
            .map_err(unavailable)?;
        let Some(state) = state else {
            transaction.rollback().await.map_err(unavailable)?;
            return Err(StatisticsServiceError::Concealed);
        };
        if state.get::<_, String>(5) != dataset.definition_digest {
            transaction.rollback().await.map_err(unavailable)?;
            return Err(StatisticsServiceError::Concealed);
        }
        if state.get::<_, Option<String>>(7).is_some() {
            transaction.rollback().await.map_err(unavailable)?;
            return Err(StatisticsServiceError::ReleaseRefused(
                StatisticsReleaseRefusal::AlreadyWithdrawn,
            ));
        }
        let changed: bool = transaction
            .transaction()
            .query_one(
                "SELECT registry_internal.withdraw_statistical_release($1, $2, $3, $4)",
                &[
                    &dataset.id,
                    &request.period_code,
                    &request.version,
                    &reason_code,
                ],
            )
            .await
            .map_err(unavailable)?
            .get(0);
        if !changed {
            transaction.rollback().await.map_err(unavailable)?;
            return Err(StatisticsServiceError::ReleaseRefused(
                StatisticsReleaseRefusal::AlreadyWithdrawn,
            ));
        }
        let withdrawn_at = transaction
            .transaction()
            .query_one(
                "SELECT withdrawn_at
                   FROM registry_internal.registry_statistical_release_withdrawals
                  WHERE dataset_id = $1 AND period_code = $2 AND release_version = $3",
                &[&dataset.id, &request.period_code, &request.version],
            )
            .await
            .map_err(unavailable)?
            .get::<_, DateTime<Utc>>(0);
        let header = header_from_row(
            dataset,
            request.period_code,
            &state,
            Some(WithdrawalDocument {
                withdrawn_at: withdrawn_at.to_rfc3339(),
                reason: request.reason,
            }),
        )?;
        let response =
            held_json_response(200, &serde_json::to_value(&header).map_err(unavailable)?)?;
        insert_result(
            transaction.transaction(),
            &resolved,
            &StoredResultMetadata::Release {
                release_reference: release_reference_for(dataset, request.period_code),
                release_version: request.version,
            },
            &response,
        )
        .await
        .map_err(map_idempotency)?;
        commit_release_write(transaction, commit).await?;
        Ok(StatisticsMutationOutcome {
            response,
            replayed: false,
            header,
            result_count: 0,
        })
    }

    pub async fn read_version(
        &self,
        request: StatisticsVersionReadRequest<'_>,
    ) -> Result<StatisticsStoredDocument, StatisticsServiceError> {
        within_deadline(request.deadline, self.read_version_inner(request)).await
    }

    async fn read_version_inner(
        &self,
        request: StatisticsVersionReadRequest<'_>,
    ) -> Result<StatisticsStoredDocument, StatisticsServiceError> {
        let dataset = self.reader_dataset(request.dataset_id, request.context)?;
        let _period = release_period(dataset, request.period_code, NaiveDate::MAX)?;
        if request.period_code < first_period(dataset).as_str() {
            return Err(StatisticsServiceError::Concealed);
        }
        if request.version.is_some_and(|version| version <= 0) {
            return Err(StatisticsServiceError::Concealed);
        }
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = begin_release_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            request.deadline,
        )
        .await?;
        let status = selection_status(request.selection);
        let parameters: [&(dyn ToSql + Sync); 5] = [
            &dataset.id,
            &request.period_code,
            &dataset.definition_digest,
            &request.version,
            &status,
        ];
        let row = transaction
            .query_opt(
                "SELECT version.release_version, version.release_status,
                        version.snapshot_reference::text, version.computed_at,
                        version.package_digest, version.definition_digest,
                        version.content_digest, withdrawal.reason_code,
                        withdrawal.withdrawn_at, content.document
                   FROM registry_internal.registry_statistical_release_versions AS version
              LEFT JOIN registry_internal.registry_statistical_release_withdrawals AS withdrawal
                     USING (dataset_id, period_code, release_version)
              LEFT JOIN registry_internal.registry_statistical_release_contents AS content
                     USING (dataset_id, period_code, release_version)
                  WHERE version.dataset_id = $1 AND version.period_code = $2
                    AND version.definition_digest = $3
                    AND ($4::bigint IS NULL OR version.release_version = $4)
                    AND ($5::text IS NULL OR version.release_status = $5)
                    AND ($4::bigint IS NOT NULL OR withdrawal.dataset_id IS NULL)
               ORDER BY version.release_version DESC LIMIT 1",
                &parameters,
            )
            .await
            .map_err(unavailable)?;
        let Some(row) = row else {
            transaction.rollback().await.map_err(unavailable)?;
            return Err(StatisticsServiceError::Concealed);
        };
        let reason = row.get::<_, Option<String>>(7);
        if let Some(reason_code) = reason {
            transaction.rollback().await.map_err(unavailable)?;
            return Err(StatisticsServiceError::VersionWithdrawn { reason_code });
        }
        let bytes = row
            .get::<_, Option<Vec<u8>>>(9)
            .ok_or(StatisticsServiceError::Unavailable)?;
        let header = header_from_row(dataset, request.period_code, &row, None)?;
        let document: StatisticsDocument =
            serde_json::from_slice(&bytes).map_err(|_| StatisticsServiceError::Unavailable)?;
        let canonical = canonical_document_and_digest(&document).map_err(map_statistics_error)?;
        if canonical.bytes != bytes
            || header.content_digest.as_deref() != Some(canonical.content_digest.as_str())
            || document.dataset.id != dataset.id
            || document.dataset.definition_digest != dataset.definition_digest
            || document.periods.len() != 1
            || document.periods[0].code != request.period_code
        {
            return Err(StatisticsServiceError::Unavailable);
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(StatisticsStoredDocument { header, bytes })
    }

    pub async fn list_releases(
        &self,
        request: StatisticsReleaseListRequest<'_>,
    ) -> Result<StatisticsReleasePage, StatisticsServiceError> {
        within_deadline(request.deadline, self.list_releases_inner(request)).await
    }

    async fn list_releases_inner(
        &self,
        request: StatisticsReleaseListRequest<'_>,
    ) -> Result<StatisticsReleasePage, StatisticsServiceError> {
        let dataset = self.reader_dataset(request.dataset_id, request.context)?;
        if request.limit == 0 || request.limit > 100 {
            return Err(StatisticsServiceError::QueryInvalid { field_path: "$top" });
        }
        let (after_period, after_version) = if let Some(after) = &request.after {
            let version =
                i64::try_from(after.version).map_err(|_| StatisticsServiceError::QueryInvalid {
                    field_path: "$skiptoken",
                })?;
            (Some(after.period.as_str()), Some(version))
        } else {
            (None, None)
        };
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = begin_release_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            request.deadline,
        )
        .await?;
        let fetch = i64::from(request.limit) + 1;
        let parameters: [&(dyn ToSql + Sync); 6] = [
            &dataset.id,
            &dataset.definition_digest,
            &after_period,
            &after_version,
            &fetch,
            first_period(dataset),
        ];
        let rows = transaction
            .query(
                "SELECT version.period_code, version.release_version, version.release_status,
                        version.snapshot_reference::text, version.computed_at,
                        version.package_digest, version.definition_digest,
                        version.content_digest, withdrawal.reason_code,
                        withdrawal.withdrawn_at
                   FROM registry_internal.registry_statistical_release_versions AS version
              LEFT JOIN registry_internal.registry_statistical_release_withdrawals AS withdrawal
                     USING (dataset_id, period_code, release_version)
                  WHERE version.dataset_id = $1 AND version.definition_digest = $2
                    AND version.period_code >= $6
                    AND ($3::text IS NULL OR
                         (version.period_code, version.release_version)
                           < ($3::text, $4::bigint))
               ORDER BY version.period_code DESC, version.release_version DESC
                  LIMIT $5",
                &parameters,
            )
            .await
            .map_err(unavailable)?;
        let has_more = rows.len() > usize::from(request.limit);
        let mut headers = Vec::with_capacity(rows.len().min(usize::from(request.limit)));
        for row in rows.into_iter().take(usize::from(request.limit)) {
            let reason = row.get::<_, Option<String>>(8);
            let withdrawn_at = row.get::<_, Option<DateTime<Utc>>>(9);
            let withdrawn = withdrawal(reason, withdrawn_at)?;
            headers.push(ReleaseVersionHeader {
                dataset: dataset.id.clone(),
                period: row.get(0),
                version: u64::try_from(row.get::<_, i64>(1))
                    .map_err(|_| StatisticsServiceError::Unavailable)?,
                status: parse_release_status(row.get::<_, String>(2).as_str())?,
                snapshot: snapshot_reference(row.get::<_, Option<String>>(3))?,
                computed_at: row.get::<_, DateTime<Utc>>(4).to_rfc3339(),
                package_digest: row.get(5),
                definition_digest: row.get(6),
                content_digest: withdrawn.is_none().then(|| row.get(7)),
                withdrawal: withdrawn,
            });
        }
        let next =
            has_more
                .then(|| headers.last())
                .flatten()
                .map(|header| StatisticsReleaseListCursor {
                    period: header.period.clone(),
                    version: header.version,
                });
        transaction.commit().await.map_err(unavailable)?;
        Ok(StatisticsReleasePage {
            items: headers,
            has_more,
            next,
        })
    }

    pub async fn read_series(
        &self,
        request: StatisticsSeriesRequest<'_>,
    ) -> Result<StatisticsDocument, StatisticsServiceError> {
        within_deadline(request.deadline, self.read_series_inner(request)).await
    }

    async fn read_series_inner(
        &self,
        request: StatisticsSeriesRequest<'_>,
    ) -> Result<StatisticsDocument, StatisticsServiceError> {
        let dataset = self.reader_dataset(request.dataset_id, request.context)?;
        let periods = period_range(
            granularity(dataset),
            request.from,
            request.to,
            request.today,
        )
        .map_err(|error| map_period_range_error(error, request.from, request.to))?;
        enforce_first_period(dataset, &periods)?;
        let period_codes = periods
            .iter()
            .map(|period| period.code.clone())
            .collect::<Vec<_>>();
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = begin_release_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            request.deadline,
        )
        .await?;
        let status = selection_status(request.selection);
        let fetch_limit = i64::try_from(series_release_fetch_limit(dataset)?)
            .map_err(|_| StatisticsServiceError::Unavailable)?;
        let parameters: [&(dyn ToSql + Sync); 5] = [
            &dataset.id,
            &dataset.definition_digest,
            &period_codes,
            &status,
            &fetch_limit,
        ];
        let rows = transaction
            .query(
                "SELECT DISTINCT ON (version.period_code)
                        version.period_code, version.release_version,
                        version.release_status, version.snapshot_reference::text,
                        version.content_digest, content.document
                   FROM registry_internal.registry_statistical_release_versions AS version
                   JOIN registry_internal.registry_statistical_release_contents AS content
                     USING (dataset_id, period_code, release_version)
              LEFT JOIN registry_internal.registry_statistical_release_withdrawals AS withdrawal
                     USING (dataset_id, period_code, release_version)
                  WHERE version.dataset_id = $1 AND version.definition_digest = $2
                    AND version.period_code = ANY($3)
                    AND ($4::text IS NULL OR version.release_status = $4)
                    AND withdrawal.dataset_id IS NULL
               ORDER BY version.period_code, version.release_version DESC
                  LIMIT $5",
                &parameters,
            )
            .await
            .map_err(unavailable)?;
        let mut versions = BTreeMap::new();
        let mut cells = Vec::new();
        for row in rows {
            let period_code = row.get::<_, String>(0);
            let version = row.get::<_, i64>(1);
            let status = parse_release_status(row.get::<_, String>(2).as_str())?;
            let snapshot = snapshot_reference(row.get::<_, Option<String>>(3))?;
            let content_digest = row.get::<_, String>(4);
            let bytes = row.get::<_, Vec<u8>>(5);
            let document: StatisticsDocument =
                serde_json::from_slice(&bytes).map_err(|_| StatisticsServiceError::Unavailable)?;
            let canonical =
                canonical_document_and_digest(&document).map_err(map_statistics_error)?;
            if canonical.bytes != bytes || canonical.content_digest != content_digest {
                return Err(StatisticsServiceError::Unavailable);
            }
            if document.dataset.definition_digest != dataset.definition_digest
                || document.dataset.id != dataset.id
                || document.periods.len() != 1
                || document.periods[0].code != period_code
            {
                return Err(StatisticsServiceError::Unavailable);
            }
            cells.extend(document.cells);
            if cells.len() > MAX_CELLS_PER_RESPONSE {
                return Err(StatisticsServiceError::QueryInvalid {
                    field_path: "period",
                });
            }
            versions.insert(
                period_code,
                PeriodVersionHeader {
                    version: u64::try_from(version)
                        .map_err(|_| StatisticsServiceError::Unavailable)?,
                    status,
                    content_digest,
                    snapshot,
                },
            );
        }
        transaction.commit().await.map_err(unavailable)?;
        let mut document = document_for(
            dataset,
            periods,
            cells,
            None,
            None,
            Some(DisclosureDocument::from(dataset.disclosure)),
        )?;
        for period in &mut document.periods {
            period.version = versions.remove(&period.code);
        }
        Ok(document)
    }

    fn dataset(&self, id: &str) -> Result<&CompiledStatisticalDataset, StatisticsServiceError> {
        self.registry
            .statistical_datasets()
            .get(id)
            .ok_or(StatisticsServiceError::Concealed)
    }

    fn live_dataset(
        &self,
        id: &str,
        context: &AuthorizedRequestContext,
    ) -> Result<&CompiledStatisticalDataset, StatisticsServiceError> {
        let dataset = self.dataset(id)?;
        dataset
            .live_profiles
            .contains(context.selected_profile())
            .then_some(dataset)
            .ok_or(StatisticsServiceError::Concealed)
    }

    fn publisher_dataset(
        &self,
        id: &str,
        context: &AuthorizedRequestContext,
    ) -> Result<&CompiledStatisticalDataset, StatisticsServiceError> {
        let dataset = self.dataset(id)?;
        dataset
            .releases
            .as_ref()
            .is_some_and(|release| release.publisher == context.selected_profile())
            .then_some(dataset)
            .ok_or(StatisticsServiceError::Concealed)
    }

    fn reader_dataset(
        &self,
        id: &str,
        context: &AuthorizedRequestContext,
    ) -> Result<&CompiledStatisticalDataset, StatisticsServiceError> {
        let dataset = self.dataset(id)?;
        let profile = context.selected_profile();
        let allowed = dataset.releases.as_ref().is_some_and(|release| {
            release.readers.contains(profile)
                || release.publisher == profile
                || dataset.live_profiles.contains(profile)
        });
        allowed
            .then_some(dataset)
            .ok_or(StatisticsServiceError::Concealed)
    }
}

async fn revalidate_snapshot_for_persist(
    transaction: &tokio_postgres::Transaction<'_>,
    captured_head: i64,
    snapshot: Option<String>,
) -> Result<Option<String>, StatisticsServiceError> {
    let Some(snapshot) = snapshot else {
        // Publication computed while coverage was unavailable. A later
        // rebaseline must not retroactively attach a bookmark to those counts.
        return Ok(None);
    };
    let reference =
        SnapshotReference::parse(&snapshot).map_err(|_| StatisticsServiceError::Unavailable)?;
    let row = transaction
        .query_opt(
            "SELECT head.history_lineage, head.latest_position,
                    head.coverage_baseline_position, head.coverage_ready,
                    head.unavailable_after_position,
                    commit.commit_position, commit.history_lineage
               FROM registry_internal.registry_commit_head AS head
          LEFT JOIN registry_internal.registry_revision_commits AS commit
                 ON commit.snapshot_reference = $1
              WHERE head.singleton",
            &[&reference.uuid()],
        )
        .await
        .map_err(unavailable)?
        .ok_or(StatisticsServiceError::Unavailable)?;
    let head_lineage = row.get::<_, uuid::Uuid>(0);
    let latest_position = row.get::<_, i64>(1);
    let coverage_baseline = row.get::<_, i64>(2);
    let coverage_ready = row.get::<_, bool>(3);
    let unavailable_after = row.get::<_, Option<i64>>(4);
    let position = row
        .get::<_, Option<i64>>(5)
        .ok_or(StatisticsServiceError::Unavailable)?;
    let lineage = row
        .get::<_, Option<uuid::Uuid>>(6)
        .ok_or(StatisticsServiceError::Unavailable)?;
    if lineage != head_lineage || position > latest_position || position != captured_head {
        return Err(StatisticsServiceError::Unavailable);
    }
    if !coverage_ready
        || position < coverage_baseline
        || unavailable_after.is_some_and(|boundary| position > boundary)
    {
        Ok(None)
    } else {
        Ok(Some(snapshot))
    }
}

struct Computation {
    cells: Vec<Cell>,
    history_head: Option<i64>,
    snapshot: Option<String>,
}

impl PostgresStatisticsService {
    async fn ensure_release_eligible(
        &self,
        dataset: &CompiledStatisticalDataset,
        period: &Period,
        status: ReleaseStatus,
        deadline: tokio::time::Instant,
    ) -> Result<(), StatisticsServiceError> {
        if !period.ended {
            return Err(StatisticsServiceError::ReleaseRefused(
                StatisticsReleaseRefusal::PeriodNotEnded,
            ));
        }
        if period.code < *first_period(dataset) {
            return Err(StatisticsServiceError::ReleaseRefused(
                StatisticsReleaseRefusal::BeforeFirstPeriod,
            ));
        }
        if status == ReleaseStatus::Provisional {
            let mut client = self.pool.get().await.map_err(unavailable)?;
            let transaction = begin_release_transaction(
                &mut client,
                self.lock_key,
                self.lock_timeout,
                &self.expected,
                deadline,
            )
            .await?;
            let exists = transaction
                .query_one(
                    "SELECT EXISTS (
                         SELECT 1
                           FROM registry_internal.registry_statistical_release_versions
                          WHERE dataset_id = $1 AND period_code = $2
                            AND definition_digest = $3 AND release_status = 'final'
                     )",
                    &[&dataset.id, &period.code, &dataset.definition_digest],
                )
                .await
                .map_err(unavailable)?
                .get::<_, bool>(0);
            transaction.commit().await.map_err(unavailable)?;
            if exists {
                return Err(StatisticsServiceError::ReleaseRefused(
                    StatisticsReleaseRefusal::ProvisionalAfterFinal,
                ));
            }
        }
        Ok(())
    }
}

async fn begin_release_transaction<'a>(
    client: &'a mut deadpool_postgres::Client,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    expected: &ExpectedRegistryIdentity,
    deadline: tokio::time::Instant,
) -> Result<deadpool_postgres::Transaction<'a>, StatisticsServiceError> {
    if lock_timeout.is_zero() || lock_timeout > Duration::from_secs(30) {
        return Err(StatisticsServiceError::Unavailable);
    }
    let statement_budget = remaining_budget(deadline)?;
    let lock_budget = lock_timeout.min(statement_budget);
    let transaction = client.transaction().await.map_err(unavailable)?;
    transaction
        .execute(
            "SELECT set_config('lock_timeout', $1, true),
                    set_config('statement_timeout', $2, true),
                    set_config('TimeZone', 'UTC', true)",
            &[
                &format!("{}ms", lock_budget.as_millis()),
                &format!("{}ms", statement_budget.as_millis()),
            ],
        )
        .await
        .map_err(unavailable)?;
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock_shared($1)",
            &[&lock_key.get()],
        )
        .await
        .map_err(unavailable)?;
    let identity = transaction
        .query_opt(
            "SELECT package_id, database_id, active_package_digest,
                    active_activation_id::text, schema_fingerprint, maintenance_status
               FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .map_err(unavailable)?
        .ok_or(StatisticsServiceError::Unavailable)?;
    let matches = identity.get::<_, String>(0) == expected.package_id
        && identity.get::<_, String>(1) == expected.database_id
        && identity.get::<_, String>(2) == expected.package_digest
        && identity.get::<_, String>(3) == expected.activation_id
        && identity.get::<_, String>(4) == expected.schema_fingerprint
        && identity.get::<_, String>(5) == "ready";
    if !matches {
        return Err(StatisticsServiceError::Unavailable);
    }
    Ok(transaction)
}

async fn active_identity_matches(
    client: &deadpool_postgres::Client,
    expected: &ExpectedRegistryIdentity,
) -> Result<Option<bool>, StatisticsServiceError> {
    let row = client
        .query_opt(
            "SELECT package_id, database_id, active_package_digest,
                    active_activation_id::text, schema_fingerprint
               FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .map_err(unavailable)?;
    Ok(row.map(|identity| {
        identity.get::<_, String>(0) == expected.package_id
            && identity.get::<_, String>(1) == expected.database_id
            && identity.get::<_, String>(2) == expected.package_digest
            && identity.get::<_, String>(3) == expected.activation_id
            && identity.get::<_, String>(4) == expected.schema_fingerprint
    }))
}

async fn lock_release_key(
    transaction: &tokio_postgres::Transaction<'_>,
    dataset: &CompiledStatisticalDataset,
    period_code: &str,
) -> Result<(), StatisticsServiceError> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))",
            &[&format!("statistics/{}/{}", dataset.id, period_code)],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

fn selection_status(selection: StatisticsReleaseSelection) -> Option<&'static str> {
    match selection {
        StatisticsReleaseSelection::Any => None,
        StatisticsReleaseSelection::Final => Some("final"),
    }
}

fn parse_release_status(value: &str) -> Result<ReleaseStatus, StatisticsServiceError> {
    match value {
        "provisional" => Ok(ReleaseStatus::Provisional),
        "final" => Ok(ReleaseStatus::Final),
        _ => Err(StatisticsServiceError::Unavailable),
    }
}

fn release_status(value: ReleaseStatus) -> &'static str {
    match value {
        ReleaseStatus::Provisional => "provisional",
        ReleaseStatus::Final => "final",
    }
}

fn withdrawal_reason(value: WithdrawalReason) -> &'static str {
    match value {
        WithdrawalReason::ComputationError => "computation-error",
        WithdrawalReason::SourceDataError => "source-data-error",
        WithdrawalReason::DisclosureRisk => "disclosure-risk",
    }
}

fn snapshot_reference(value: Option<String>) -> Result<Option<String>, StatisticsServiceError> {
    value
        .map(|value| {
            let uuid =
                uuid::Uuid::parse_str(&value).map_err(|_| StatisticsServiceError::Unavailable)?;
            Ok(crate::history_reference::SnapshotReference::for_uuid(uuid).as_string())
        })
        .transpose()
}

fn header_from_row(
    dataset: &CompiledStatisticalDataset,
    period_code: &str,
    row: &tokio_postgres::Row,
    withdrawal: Option<WithdrawalDocument>,
) -> Result<ReleaseVersionHeader, StatisticsServiceError> {
    Ok(ReleaseVersionHeader {
        dataset: dataset.id.clone(),
        period: period_code.to_owned(),
        version: u64::try_from(row.get::<_, i64>(0))
            .map_err(|_| StatisticsServiceError::Unavailable)?,
        status: parse_release_status(row.get::<_, String>(1).as_str())?,
        snapshot: snapshot_reference(row.get::<_, Option<String>>(2))?,
        computed_at: row.get::<_, DateTime<Utc>>(3).to_rfc3339(),
        package_digest: row.get(4),
        definition_digest: row.get(5),
        content_digest: withdrawal.is_none().then(|| row.get(6)),
        withdrawal,
    })
}

fn withdrawal(
    reason: Option<String>,
    withdrawn_at: Option<DateTime<Utc>>,
) -> Result<Option<WithdrawalDocument>, StatisticsServiceError> {
    match (reason, withdrawn_at) {
        (None, None) => Ok(None),
        (Some(reason), Some(withdrawn_at)) => Ok(Some(WithdrawalDocument {
            withdrawn_at: withdrawn_at.to_rfc3339(),
            reason: match reason.as_str() {
                "computation-error" => WithdrawalReason::ComputationError,
                "source-data-error" => WithdrawalReason::SourceDataError,
                "disclosure-risk" => WithdrawalReason::DisclosureRisk,
                _ => return Err(StatisticsServiceError::Unavailable),
            },
        })),
        _ => Err(StatisticsServiceError::Unavailable),
    }
}

fn release_reference_for(dataset: &CompiledStatisticalDataset, period_code: &str) -> String {
    format!("{}/{}", dataset.id, period_code)
}

fn map_read_error(_: ReadServiceError) -> StatisticsServiceError {
    StatisticsServiceError::Unavailable
}

fn map_idempotency(error: IdempotencyError) -> StatisticsServiceError {
    match error {
        IdempotencyError::Conflict => StatisticsServiceError::IdempotencyConflict,
        IdempotencyError::Expired => StatisticsServiceError::IdempotencyExpired,
        IdempotencyError::InvalidInput => StatisticsServiceError::QueryInvalid {
            field_path: "Idempotency-Key",
        },
        IdempotencyError::Timeout => StatisticsServiceError::Timeout,
        IdempotencyError::CachedResponseUnreadable | IdempotencyError::Unavailable => {
            StatisticsServiceError::Unavailable
        }
    }
}

fn unavailable<T: std::any::Any>(error: T) -> StatisticsServiceError {
    (&error as &dyn std::any::Any)
        .downcast_ref::<tokio_postgres::Error>()
        .map_or(StatisticsServiceError::Unavailable, |error| {
            if error
                .code()
                .is_some_and(|code| code == &tokio_postgres::error::SqlState::QUERY_CANCELED)
            {
                StatisticsServiceError::Timeout
            } else {
                StatisticsServiceError::Unavailable
            }
        })
}

fn held_json_response(
    status: u16,
    body: &serde_json::Value,
) -> Result<HeldResponse, StatisticsServiceError> {
    let bytes = canonicalize_json(body).map_err(unavailable)?;
    HeldResponse::from_json(
        status,
        body,
        BTreeMap::from([
            (
                PermittedResponseHeader::ContentType,
                CONTENT_TYPE_JSON.to_vec(),
            ),
            (
                PermittedResponseHeader::ReprDigest,
                repr_digest(&bytes).into_bytes(),
            ),
        ]),
    )
    .map_err(map_idempotency)
}

fn replayed_outcome(
    response: HeldResponse,
    dataset: &CompiledStatisticalDataset,
    period_code: &str,
    result_count: usize,
) -> Result<StatisticsMutationOutcome, StatisticsServiceError> {
    let header: ReleaseVersionHeader =
        serde_json::from_slice(response.body()).map_err(|_| StatisticsServiceError::Unavailable)?;
    if header.dataset != dataset.id
        || header.period != period_code
        || header.version == 0
        || header.definition_digest != dataset.definition_digest
    {
        return Err(StatisticsServiceError::Unavailable);
    }
    Ok(StatisticsMutationOutcome {
        response,
        replayed: true,
        header,
        result_count,
    })
}

fn published_cell_count(
    dataset: &CompiledStatisticalDataset,
) -> Result<usize, StatisticsServiceError> {
    dataset
        .dimensions
        .iter()
        .try_fold(1_usize, |count, dimension| {
            let codes = dimension
                .codes
                .len()
                .checked_add(usize::from(dimension.include_unknown))
                .and_then(|value| value.checked_add(1))
                .ok_or(StatisticsServiceError::Unavailable)?;
            count
                .checked_mul(codes)
                .filter(|value| *value <= MAX_CELLS_PER_RESPONSE)
                .ok_or(StatisticsServiceError::Unavailable)
        })
}

fn series_release_fetch_limit(
    dataset: &CompiledStatisticalDataset,
) -> Result<usize, StatisticsServiceError> {
    MAX_CELLS_PER_RESPONSE
        .checked_div(published_cell_count(dataset)?)
        .and_then(|within_cap| within_cap.checked_add(1))
        .ok_or(StatisticsServiceError::Unavailable)
}

fn enforce_response_cell_limit(
    dataset: &CompiledStatisticalDataset,
    period_count: usize,
) -> Result<(), StatisticsServiceError> {
    period_count
        .checked_mul(published_cell_count(dataset)?)
        .filter(|cells| *cells <= MAX_CELLS_PER_RESPONSE)
        .map(|_| ())
        .ok_or(StatisticsServiceError::QueryInvalid {
            field_path: "response",
        })
}

async fn within_deadline<T>(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = Result<T, StatisticsServiceError>>,
) -> Result<T, StatisticsServiceError> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| StatisticsServiceError::Timeout)?
}

/// Whether a release write has reached its COMMIT. The write and the deadline
/// around it share one, so a deadline that passes while COMMIT is in flight is
/// not reported as a timeout that proves nothing committed.
#[derive(Default)]
struct CommitReach(AtomicBool);

impl CommitReach {
    fn reach(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn reached(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Commits a release or withdrawal. From here the outcome is not proven until
/// COMMIT is acknowledged, so a failure is `CommitUnresolved`, never a refusal.
async fn commit_release_write(
    transaction: GuardedTransaction<'_>,
    commit: &CommitReach,
) -> Result<(), StatisticsServiceError> {
    commit.reach();
    transaction
        .commit()
        .await
        .map_err(|_| StatisticsServiceError::CommitUnresolved)
}

/// Bounds a release write by its deadline. A deadline that passes before the
/// write reaches its COMMIT is a timeout; one that passes afterwards leaves
/// the outcome unproven, like a COMMIT that fails.
async fn write_within_deadline<T>(
    deadline: tokio::time::Instant,
    commit: &CommitReach,
    future: impl std::future::Future<Output = Result<T, StatisticsServiceError>>,
) -> Result<T, StatisticsServiceError> {
    match tokio::time::timeout_at(deadline, future).await {
        Ok(result) => result,
        Err(_) if commit.reached() => Err(StatisticsServiceError::CommitUnresolved),
        Err(_) => Err(StatisticsServiceError::Timeout),
    }
}

fn remaining_budget(deadline: tokio::time::Instant) -> Result<Duration, StatisticsServiceError> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining < Duration::from_millis(1) {
        Err(StatisticsServiceError::Timeout)
    } else {
        Ok(remaining.min(Duration::from_secs(30)))
    }
}

fn granularity(dataset: &CompiledStatisticalDataset) -> PeriodGranularity {
    match &dataset.period {
        CompiledStatisticalPeriod::Flow { granularity, .. }
        | CompiledStatisticalPeriod::Stock { granularity, .. } => *granularity,
    }
}

fn first_period(dataset: &CompiledStatisticalDataset) -> &String {
    match &dataset.period {
        CompiledStatisticalPeriod::Flow { first_period, .. }
        | CompiledStatisticalPeriod::Stock { first_period, .. } => first_period,
    }
}

fn requested_periods(
    dataset: &CompiledStatisticalDataset,
    from: Option<&str>,
    to: Option<&str>,
    today: NaiveDate,
) -> Result<Vec<Period>, StatisticsServiceError> {
    let current = current_period(granularity(dataset), today).map_err(map_statistics_error)?;
    let from = from.unwrap_or(current.code.as_str());
    let to = to.unwrap_or(current.code.as_str());
    let periods = period_range(granularity(dataset), from, to, today)
        .map_err(|error| map_period_range_error(error, from, to))?;
    enforce_first_period(dataset, &periods)?;
    if periods
        .last()
        .is_some_and(|period| period.start > current.start)
    {
        return Err(StatisticsServiceError::QueryInvalid { field_path: "to" });
    }
    if dataset.evaluation_date_dependent
        && periods
            .first()
            .is_some_and(|period| period.start < current.start)
    {
        return Err(StatisticsServiceError::QueryInvalid { field_path: "from" });
    }
    Ok(periods)
}

fn enforce_first_period(
    dataset: &CompiledStatisticalDataset,
    periods: &[Period],
) -> Result<(), StatisticsServiceError> {
    let first = period_for_code(granularity(dataset), first_period(dataset), NaiveDate::MAX)
        .map_err(|_| StatisticsServiceError::Unavailable)?;
    if periods
        .first()
        .is_some_and(|period| period.start < first.start)
    {
        return Err(StatisticsServiceError::QueryInvalid { field_path: "from" });
    }
    Ok(())
}

fn release_period(
    dataset: &CompiledStatisticalDataset,
    code: &str,
    today: NaiveDate,
) -> Result<Period, StatisticsServiceError> {
    period_for_code(granularity(dataset), code, today)
        .map_err(|_| StatisticsServiceError::Concealed)
}

fn dimensions(dataset: &CompiledStatisticalDataset) -> Vec<DimensionDomain> {
    dataset
        .dimensions
        .iter()
        .map(|dimension| DimensionDomain {
            field: dimension.field.clone(),
            vocabulary: match &dimension.domain {
                CompiledStatisticalDimensionDomain::Boolean => "boolean".to_owned(),
                CompiledStatisticalDimensionDomain::Vocabulary { vocabulary } => vocabulary.clone(),
            },
            codes: dimension.codes.clone(),
            include_unknown: dimension.include_unknown,
        })
        .collect()
}

fn period_kind(dataset: &CompiledStatisticalDataset) -> PeriodKind {
    match dataset.period {
        CompiledStatisticalPeriod::Flow { .. } => PeriodKind::Flow,
        CompiledStatisticalPeriod::Stock { .. } => PeriodKind::Stock,
    }
}

fn document_for(
    dataset: &CompiledStatisticalDataset,
    periods: Vec<Period>,
    cells: Vec<Cell>,
    release: Option<ReleaseDocument>,
    live: Option<LiveDocument>,
    disclosure: Option<DisclosureDocument>,
) -> Result<StatisticsDocument, StatisticsServiceError> {
    let domains = dimensions(dataset);
    Ok(StatisticsDocument {
        dataset: DatasetDocument {
            id: dataset.id.clone(),
            unit: dataset.unit_entity_id.clone(),
            measure: Measure::Count,
            period_kind: period_kind(dataset),
            granularity: granularity(dataset),
            population: dataset.population.clone(),
            definition_digest: dataset.definition_digest.clone(),
        },
        periods: periods.iter().map(PeriodDocument::from).collect(),
        dimensions: domains.iter().map(DimensionDomain::document).collect(),
        cells,
        release,
        live,
        disclosure,
    })
}

fn map_period_range_error(error: StatisticsError, from: &str, to: &str) -> StatisticsServiceError {
    match error {
        StatisticsError::InvalidPeriodCode { code, .. } => StatisticsServiceError::QueryInvalid {
            field_path: if code == to && code != from {
                "to"
            } else {
                "from"
            },
        },
        StatisticsError::ReversedPeriodRange
        | StatisticsError::TooManyPeriods
        | StatisticsError::TooManyCells => {
            StatisticsServiceError::QueryInvalid { field_path: "from" }
        }
        other => map_statistics_error(other),
    }
}

fn map_statistics_error(error: StatisticsError) -> StatisticsServiceError {
    match error {
        StatisticsError::InvalidPeriodCode { .. }
        | StatisticsError::ReversedPeriodRange
        | StatisticsError::TooManyPeriods
        | StatisticsError::TooManyCells => StatisticsServiceError::QueryInvalid {
            field_path: "period",
        },
        StatisticsError::UnknownCode { dataset, dimension } => {
            StatisticsServiceError::DomainViolation {
                dataset_id: dataset,
                dimension,
            }
        }
        StatisticsError::DimensionCount { .. }
        | StatisticsError::UnknownPeriod { .. }
        | StatisticsError::DuplicateGroupedCell { .. }
        | StatisticsError::InvalidDimensionDomain { .. }
        | StatisticsError::CountOverflow
        | StatisticsError::InvalidDisclosureParameters
        | StatisticsError::InvalidDocument(_)
        | StatisticsError::Canonicalization => StatisticsServiceError::Unavailable,
    }
}

fn grouped_sql(
    dataset: &CompiledStatisticalDataset,
    entity: &CompiledEntity,
    relations: &ReadRelations,
    population_where: &str,
    periods: &[Period],
    capture_history: bool,
) -> Result<String, StatisticsServiceError> {
    if periods.is_empty() {
        return Err(StatisticsServiceError::QueryInvalid {
            field_path: "period",
        });
    }
    let period_values = periods
        .iter()
        .map(|period| {
            format!(
                "({}, DATE {}, DATE {}, DATE {})",
                sql_literal(&period.code),
                sql_literal(&period.start.to_string()),
                sql_literal(&period.end.to_string()),
                sql_literal(&period.reference_date.to_string()),
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut dimension_sql = Vec::with_capacity(dataset.dimensions.len());
    for dimension in &dataset.dimensions {
        let expression = relations
            .field_expression(entity, &dimension.field)
            .map_err(map_read_error)?;
        if expression.encrypted {
            return Err(StatisticsServiceError::Unavailable);
        }
        dimension_sql.push(format!("COALESCE(({})::text, '_U')", expression.sql));
    }
    let dimension_select = dimension_sql
        .iter()
        .enumerate()
        .map(|(index, expression)| format!("{expression} AS dimension_{index}"))
        .collect::<Vec<_>>();
    let mut grouped_select = vec!["periods.code AS period_code".to_owned()];
    grouped_select.extend(dimension_select);
    grouped_select.push("count(*)::bigint AS cell_count".to_owned());
    let mut grouped_by = vec!["periods.code".to_owned()];
    grouped_by.extend(dimension_sql);
    let (period_join, period_predicate) = match &dataset.period {
        CompiledStatisticalPeriod::Flow { field, .. } => {
            let expression = relations
                .field_expression(entity, field)
                .map_err(map_read_error)?;
            (
                format!(
                    "JOIN periods ON {field} >= periods.start_date AND {field} < periods.end_date",
                    field = expression.sql
                ),
                None,
            )
        }
        CompiledStatisticalPeriod::Stock { validity, .. } => {
            let (from, until) = match validity {
                CompiledStatisticalValidity::Temporal { from, until } => {
                    (from.as_str(), Some(until.as_str()))
                }
                CompiledStatisticalValidity::Fields { from, until } => {
                    (from.as_str(), until.as_deref())
                }
            };
            let from = relations
                .field_expression(entity, from)
                .map_err(map_read_error)?
                .sql;
            let validity = if let Some(until) = until {
                let until = relations
                    .field_expression(entity, until)
                    .map_err(map_read_error)?
                    .sql;
                format!(
                    "{from} <= periods.reference_date AND ({until} IS NULL OR periods.reference_date < {until})"
                )
            } else {
                format!("{from} <= periods.reference_date")
            };
            ("CROSS JOIN periods".to_owned(), Some(validity))
        }
    };
    let where_sql = period_predicate
        .map(|period| format!("({population_where}) AND ({period})"))
        .unwrap_or_else(|| population_where.to_owned());
    let grouped = format!(
        "periods(code, start_date, end_date, reference_date) AS (VALUES {period_values}),
         grouped AS (
             SELECT {select}
               FROM {from_sql}
               {period_join}
              WHERE {where_sql}
           GROUP BY {group_by}
         )",
        select = grouped_select.join(", "),
        from_sql = relations.from_sql,
        group_by = grouped_by.join(", "),
    );
    let grouped_columns = (0..dataset.dimensions.len())
        .map(|index| format!("grouped.dimension_{index}"))
        .collect::<Vec<_>>();
    let result_columns = std::iter::once("grouped.period_code".to_owned())
        .chain(grouped_columns)
        .chain(std::iter::once("grouped.cell_count".to_owned()))
        .collect::<Vec<_>>()
        .join(", ");
    if capture_history {
        Ok(format!(
            "WITH {grouped},
             marker AS (
                 SELECT head.latest_position,
                        CASE
                            WHEN head.coverage_ready
                             AND (head.unavailable_after_position IS NULL
                                  OR head.latest_position <= head.unavailable_after_position)
                            THEN commit.snapshot_reference::text
                            ELSE NULL
                        END AS snapshot_reference
                   FROM registry_internal.registry_commit_head AS head
                   JOIN registry_internal.registry_revision_commits AS commit
                     ON commit.commit_position = head.latest_position
                  WHERE head.singleton
             )
             SELECT marker.latest_position, marker.snapshot_reference, {result_columns}
               FROM marker LEFT JOIN grouped ON true
           ORDER BY grouped.period_code, {order_dimensions}",
            order_dimensions = if dataset.dimensions.is_empty() {
                "grouped.period_code".to_owned()
            } else {
                (0..dataset.dimensions.len())
                    .map(|index| format!("grouped.dimension_{index}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        ))
    } else {
        Ok(format!(
            "WITH {grouped}
             SELECT {result_columns} FROM grouped
             ORDER BY grouped.period_code, {order_dimensions}",
            order_dimensions = if dataset.dimensions.is_empty() {
                "grouped.period_code".to_owned()
            } else {
                (0..dataset.dimensions.len())
                    .map(|index| format!("grouped.dimension_{index}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        ))
    }
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn repr_digest(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(bytes);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

fn map_statement_error(error: tokio_postgres::Error) -> StatisticsServiceError {
    if error
        .code()
        .is_some_and(|code| code == &tokio_postgres::error::SqlState::QUERY_CANCELED)
    {
        StatisticsServiceError::Timeout
    } else {
        StatisticsServiceError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_write_deadline_is_a_timeout_only_before_the_commit_is_reached() {
        let commit = CommitReach::default();
        let before: Result<(), _> = write_within_deadline(
            tokio::time::Instant::now() + Duration::from_millis(10),
            &commit,
            std::future::pending(),
        )
        .await;
        assert!(matches!(before, Err(StatisticsServiceError::Timeout)));

        let during: Result<(), _> = write_within_deadline(
            tokio::time::Instant::now() + Duration::from_millis(10),
            &commit,
            async {
                commit.reach();
                std::future::pending().await
            },
        )
        .await;
        assert!(matches!(
            during,
            Err(StatisticsServiceError::CommitUnresolved)
        ));
    }
}
