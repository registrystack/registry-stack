// SPDX-License-Identifier: Apache-2.0

//! Bounded operator controls for change-request upgrade safety and retention.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use registry_platform_audit::AuditProfile;
use serde::Serialize;
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::audit::{append_terminal_audit, TerminalAudit, TerminalAuditOutcome};
use crate::correlation::RequestCorrelation;
use crate::history_commit::{
    allocate_revision_commit, CommitAllocation, HistoryCommitError, RevisionCommitMember,
};
use crate::history_context::CommitOrigin;
use crate::model::{
    CompiledChangeRequestRetentionMode, CompiledEntity, CompiledRegistry, HttpMethod,
};
use crate::postgres::{
    verify_catalog_identity_for_catalog, verify_migration_role, ConnectionConfig,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey, SqlIdentifier,
};
use crate::runtime_config::load_runtime_config;

const MAX_RETAINED_HISTORY_PAGE_SIZE: u16 = 50;
// Reserve the other half of the client's 2 MiB request-extension budget for
// current decisions, actions, and the remaining request metadata.
const MAX_RETAINED_HISTORY_BYTES: usize = 1_048_576;
const MAX_RETAINED_DECISIONS: usize = 1024;
pub const MAX_REQUEST_RETENTION_OPERATOR_PAGE_SIZE: u16 = 100;
const RETENTION_OPERATION_ID: &str = "records.request.retention.erase";
const RETENTION_REFERENCE: &str = "request-retention-erasure";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RequestRetentionError {
    #[error("active request proposals require explicit rebase or cancellation")]
    ActiveProposalRequiresRebase,
    #[error("request detail is still pinned by an active proposal")]
    ActiveDetailPinned,
    #[error("request retention policy does not permit operator erasure")]
    RetainMode,
    #[error("attachment storage or verification binding differs from the registry pin; restore the original configuration")]
    AttachmentStorageBindingMismatch,
    #[error("request retention state is unavailable")]
    Unavailable,
}

pub type Result<T> = std::result::Result<T, RequestRetentionError>;

#[derive(Clone, Debug)]
pub struct RequestDetailErasureScope<'a> {
    pub request_entity_id: &'a str,
    pub request_id: Uuid,
    pub proposal_version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedHistoryQuery<'a> {
    pub request_entity_id: &'a str,
    pub request_id: Uuid,
    pub after_proposal_version: Option<i64>,
    pub limit: u16,
    pub include_decision_reasons: bool,
    pub authorized_target_entities: &'a BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetainedRequestHistoryPage {
    pub proposals: Vec<RetainedRequestProposal>,
    pub next_after_proposal_version: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetainedRequestProposal {
    pub request_entity_id: String,
    pub request_id: String,
    pub proposal_version: i64,
    pub request_state: String,
    pub current: bool,
    pub contract_fingerprint: String,
    pub effect_digest: String,
    pub detail_erased: bool,
    pub application_id: Option<String>,
    pub result_link_count: u16,
    pub result_links: Vec<RetainedRequestResultLink>,
    pub decisions: Vec<RetainedRequestDecision>,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetainedRequestDecision {
    pub stage_id: String,
    pub kind: String,
    pub decided_at: String,
    #[serde(skip_serializing)]
    pub actor_reference: String,
    pub reason_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl std::fmt::Debug for RetainedRequestDecision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedRequestDecision")
            .field("stage_id", &self.stage_id)
            .field("kind", &self.kind)
            .field("decided_at", &self.decided_at)
            .field("has_actor_reference", &!self.actor_reference.is_empty())
            .field("reason_present", &self.reason_present)
            .field("reason", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetainedRequestResultLink {
    pub target_entity_id: String,
    pub target_record_id: String,
    pub target_revision: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDetailErasure {
    pub proposal_snapshots: u64,
    pub target_snapshots: u64,
    pub decision_reasons: u64,
    pub idempotency_results: u64,
    pub request_revision_snapshots: u64,
    pub outbox_payloads: u64,
    pub current_intake_rows: u64,
    pub attachment_references: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestRetentionListPage {
    pub requests: Vec<RequestRetentionListItem>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestRetentionListItem {
    pub request_entity_id: String,
    pub request_id: String,
    pub proposal_version: i64,
    pub request_state: String,
    pub current: bool,
    pub retention_mode: &'static str,
    pub pinned: bool,
    pub eligible_for_erasure: bool,
    pub detail_erased: bool,
    pub contract_fingerprint: Option<String>,
    pub effect_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestRetentionDryRun {
    pub request_entity_id: String,
    pub request_id: String,
    pub proposal_version: i64,
    pub request_state: String,
    pub retention_mode: &'static str,
    pub pinned: bool,
    pub eligible_for_erasure: bool,
    pub detail_erased: bool,
    pub erasure: RequestDetailErasure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestRetentionErase {
    pub request_entity_id: String,
    pub request_id: String,
    pub proposal_version: i64,
    pub request_state: String,
    pub retention_mode: &'static str,
    pub erasure: RequestDetailErasure,
    /// Registry-wide external blobs still awaiting confirmed physical deletion.
    pub pending_external_deletions: u64,
    /// Confirmed absence observations retained for future delayed-write rechecks.
    pub external_deletion_tombstones: u64,
}

/// Registry-wide cleanup observations without changing request retention.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentCleanup {
    pub pending_external_deletions: u64,
    pub external_deletion_tombstones: u64,
}

/// Package-bound operator boundary used by `bregctl`.
///
/// Construction closes the runtime configuration, package, active database
/// identity, managed catalog, migration role, Registry lock, and audit profile
/// before any retention operation can run. SQL remains product-owned here.
pub struct RequestRetentionOperatorService {
    registry: CompiledRegistry,
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    lock_key: RegistryLockKey,
    migration_connection: ConnectionConfig,
    migration_role: SqlIdentifier,
    runtime_role: SqlIdentifier,
    lock_timeout: Duration,
    statement_timeout: Duration,
    audit_profile: AuditProfile,
    attachment_storage: crate::attachment_storage::AttachmentStorage,
    verification_policy: String,
}

impl RequestRetentionOperatorService {
    pub async fn from_runtime_config(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(RequestRetentionError::Unavailable);
        }
        let config = load_runtime_config(path).map_err(|_| RequestRetentionError::Unavailable)?;
        let package_root = config.package().root().to_path_buf();
        let runtime_connection = config
            .runtime_database_connection_config()
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let pool = runtime_connection
            .build_pool()
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let context = config.package_load_context();
        let startup = crate::startup::prepare_startup(
            &package_root,
            &context,
            &mut client,
            config.database().roles().migration(),
            config.database().roles().runtime(),
        )
        .await
        .map_err(|_| RequestRetentionError::Unavailable)?;
        drop(client);
        let migration_connection = config
            .migration_database_connection_config()
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let audit_profile = config
            .audit_profile()
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let attachment_storage = config
            .activate_attachment_storage(startup.package().registry().registry_id())
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let verification_policy = config
            .activate_attachment_verification()
            .map_err(|_| RequestRetentionError::AttachmentStorageBindingMismatch)?
            .binding_digest();
        Ok(Self {
            verification_policy,
            attachment_storage,
            registry: startup.package().registry().clone(),
            expected: startup.expected_identity().clone(),
            expected_catalog: startup.expected_catalog().clone(),
            lock_key: startup.lock_key(),
            migration_connection,
            migration_role: config.database().roles().migration().clone(),
            runtime_role: config.database().roles().runtime().clone(),
            lock_timeout: config.operational_timeouts().migration_lock,
            statement_timeout: config.operational_timeouts().migration_statement,
            audit_profile,
        })
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)] // Keep distinct migration and runtime identities explicit.
    pub fn new_for_test(
        registry: CompiledRegistry,
        expected: ExpectedRegistryIdentity,
        expected_catalog: ExpectedManagedCatalog,
        lock_key: RegistryLockKey,
        migration_connection: ConnectionConfig,
        migration_role: SqlIdentifier,
        runtime_role: SqlIdentifier,
        audit_profile: AuditProfile,
    ) -> Self {
        Self {
            attachment_storage: crate::attachment_storage::AttachmentStorage::Database,
            verification_policy: "disabled".to_owned(),
            registry,
            expected,
            expected_catalog,
            lock_key,
            migration_connection,
            migration_role,
            runtime_role,
            lock_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(30),
            audit_profile,
        }
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn with_attachment_storage_for_test(
        mut self,
        storage: crate::attachment_storage::AttachmentStorage,
    ) -> Self {
        self.attachment_storage = storage;
        self
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn with_verification_policy_for_test(mut self, policy: String) -> Self {
        self.verification_policy = policy;
        self
    }

    pub async fn list(
        &self,
        request_entity_id: Option<&str>,
        after_cursor: Option<&str>,
        limit: u16,
    ) -> Result<RequestRetentionListPage> {
        if limit == 0 || limit > MAX_REQUEST_RETENTION_OPERATOR_PAGE_SIZE {
            return Err(RequestRetentionError::Unavailable);
        }
        if let Some(entity_id) = request_entity_id {
            self.request_plan(entity_id)?;
        }
        let after = after_cursor.map(parse_retention_cursor).transpose()?;
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let transaction = self.begin_verified_transaction(&mut client).await?;
        let page_limit = i64::from(limit) + 1;
        let rows = transaction
            .query(
                "SELECT s.request_entity_id, s.request_id, s.state,
                        s.proposal_version, s.detail_erased_at IS NOT NULL,
                        p.proposal_version, p.contract_fingerprint, p.effect_digest,
                        p.erased_at IS NOT NULL
                   FROM registry_internal.registry_request_state s
                   LEFT JOIN registry_internal.registry_request_proposals p
                     ON p.request_entity_id = s.request_entity_id
                    AND p.request_id = s.request_id
                  WHERE ($1::text IS NULL OR s.request_entity_id = $1::text)
                    AND (
                        $2::text IS NULL
                        OR (s.request_entity_id, s.request_id, COALESCE(p.proposal_version, s.proposal_version))
                           > ($2::text, $3::uuid, $4::bigint)
                    )
                  ORDER BY s.request_entity_id, s.request_id,
                           COALESCE(p.proposal_version, s.proposal_version)
                  LIMIT $5::bigint",
                &[
                    &request_entity_id,
                    &after.as_ref().map(|cursor| cursor.request_entity_id.as_str()),
                    &after.as_ref().map(|cursor| cursor.request_id),
                    &after.as_ref().map(|cursor| cursor.proposal_version),
                    &page_limit,
                ],
            )
            .await
            .map_err(map_retention_error)?;
        let mut requests = Vec::with_capacity(rows.len().min(usize::from(limit)));
        let mut next_cursor = None;
        let mut last_returned_cursor = None;
        for (index, row) in rows.into_iter().enumerate() {
            let entity_id: String = row.get(0);
            let request_id: Uuid = row.get(1);
            let state: String = row.get(2);
            let current_version: i64 = row.get(3);
            let current_detail_erased: bool = row.get(4);
            let proposal_version = row.get::<_, Option<i64>>(5).unwrap_or(current_version);
            if index >= usize::from(limit) {
                next_cursor = last_returned_cursor;
                break;
            }
            let Some(plan) = self
                .registry
                .entities()
                .get(&entity_id)
                .and_then(|entity| entity.change_request.as_ref())
            else {
                continue;
            };
            let current = current_version == proposal_version;
            let pinned = detail_is_pinned(current, &state);
            let detail_erased = row.get::<_, bool>(8) || current_detail_erased;
            last_returned_cursor = Some(retention_cursor(&entity_id, request_id, proposal_version));
            requests.push(RequestRetentionListItem {
                request_entity_id: entity_id,
                request_id: request_id.to_string(),
                proposal_version,
                request_state: state,
                current,
                retention_mode: retention_mode_name(plan.retention_mode),
                pinned,
                eligible_for_erasure: plan.retention_mode
                    == CompiledChangeRequestRetentionMode::OperatorErase
                    && !pinned,
                detail_erased,
                contract_fingerprint: row.get(6),
                effect_digest: row.get(7),
            });
        }
        transaction
            .commit()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        Ok(RequestRetentionListPage {
            requests,
            next_cursor,
        })
    }

    pub async fn dry_run(
        &self,
        scope: RequestDetailErasureScope<'_>,
    ) -> Result<RequestRetentionDryRun> {
        self.request_plan(scope.request_entity_id)?;
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let transaction = self.begin_verified_transaction(&mut client).await?;
        let plan = load_erasure_plan(&transaction, &self.registry, scope.clone(), false).await?;
        transaction
            .commit()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        Ok(RequestRetentionDryRun {
            request_entity_id: scope.request_entity_id.to_owned(),
            request_id: scope.request_id.to_string(),
            proposal_version: scope.proposal_version,
            request_state: plan.current_state,
            retention_mode: retention_mode_name(plan.retention_mode),
            pinned: plan.pinned,
            eligible_for_erasure: plan.retention_mode
                == CompiledChangeRequestRetentionMode::OperatorErase
                && !plan.pinned,
            detail_erased: plan.detail_erased,
            erasure: plan.erasure,
        })
    }

    pub async fn erase(
        &self,
        scope: RequestDetailErasureScope<'_>,
    ) -> Result<RequestRetentionErase> {
        self.request_plan(scope.request_entity_id)?;
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let transaction = self.begin_verified_transaction(&mut client).await?;
        let plan = load_erasure_plan(&transaction, &self.registry, scope.clone(), true).await?;
        let (erasure, current_revision) =
            erase_request_detail_in_transaction(&transaction, &self.registry, scope.clone(), &plan)
                .await?;
        if let Some(current_revision) = &current_revision {
            let members = [RevisionCommitMember {
                entity_id: current_revision.entity_id.as_str(),
                record_id: current_revision.record_id,
                record_revision: current_revision.record_revision,
            }];
            allocate_revision_commit(
                &transaction,
                CommitAllocation {
                    package_revision: &self.expected.package_revision,
                    origin: CommitOrigin::Migration {
                        system_origin: "breg-request-retention-erasure-v1",
                        migration_reference: Some(RETENTION_OPERATION_ID),
                    },
                    change_context: None,
                    members: &members,
                },
            )
            .await
            .map_err(map_history_commit_error)?;
        }
        append_retention_audit(
            &transaction,
            &self.audit_profile,
            &self.expected,
            scope.clone(),
            erasure,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let (pending_external_deletions, external_deletion_tombstones) =
            self.retry_external_deletions(&mut client).await?;
        Ok(RequestRetentionErase {
            request_entity_id: scope.request_entity_id.to_owned(),
            request_id: scope.request_id.to_string(),
            proposal_version: scope.proposal_version,
            request_state: plan.current_state,
            retention_mode: retention_mode_name(plan.retention_mode),
            erasure,
            pending_external_deletions,
            external_deletion_tombstones,
        })
    }

    /// Retry orphaned external objects even when every request is active or
    /// uses retain mode. Only objects without live references are eligible.
    pub async fn cleanup_attachments(&self) -> Result<AttachmentCleanup> {
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let correlation = Uuid::new_v4().to_string();
        let transaction = self.begin_verified_transaction(&mut client).await?;
        crate::audit::append_envelope(
            &transaction,
            &self.audit_profile,
            serde_json::json!({
                "kind":"attachmentCleanup", "phase":"attempt", "outcome":"started",
                "packageRevision":self.expected.package_revision,
                "actor":"breg:request-retention-operator", "correlation":correlation,
            }),
        )
        .await
        .map_err(|_| RequestRetentionError::Unavailable)?;
        transaction.commit().await.map_err(map_retention_error)?;
        let (pending_external_deletions, external_deletion_tombstones) =
            self.retry_external_deletions(&mut client).await?;
        let result = AttachmentCleanup {
            pending_external_deletions,
            external_deletion_tombstones,
        };
        let transaction = self.begin_verified_transaction(&mut client).await?;
        crate::audit::append_envelope(
            &transaction,
            &self.audit_profile,
            serde_json::json!({
                "kind":"attachmentCleanup", "phase":"terminal", "outcome":"completed",
                "packageRevision":self.expected.package_revision,
                "actor":"breg:request-retention-operator", "correlation":correlation,
                "pendingExternalDeletions":result.pending_external_deletions,
                "externalDeletionTombstones":result.external_deletion_tombstones,
            }),
        )
        .await
        .map_err(|_| RequestRetentionError::Unavailable)?;
        transaction.commit().await.map_err(map_retention_error)?;
        Ok(result)
    }

    /// Each invocation spends at most thirty seconds retrying up to sixteen
    /// objects. Each object commits independently, so an unavailable backend
    /// cannot accumulate locks or roll back earlier confirmed observations.
    async fn retry_external_deletions(
        &self,
        client: &mut deadpool_postgres::Client,
    ) -> Result<(u64, u64)> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let transaction = self.begin_verified_transaction(client).await?;
        let candidates = transaction
            .query(
                "SELECT sha256,backend_id FROM registry_internal.registry_attachment_blobs
             WHERE backend_id <> 'database' AND (state IN ('delete_pending','delete_confirmed')
               OR (state='staged' AND created_at < transaction_timestamp()-interval '10 minutes'))
             ORDER BY deletion_checked_at ASC NULLS FIRST, sha256 LIMIT 16",
                &[],
            )
            .await
            .map_err(map_retention_error)?;
        transaction
            .commit()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        for row in candidates {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let hash: String = row.get(0);
            let backend: String = row.get(1);
            // The overall timeout includes verification, lock acquisition, backend
            // I/O, and commit. Cancellation leaves the durable tombstone intact.
            let attempt = tokio::time::timeout_at(
                deadline,
                self.retry_external_deletion(client, &hash, &backend, deadline),
            )
            .await;
            if !matches!(attempt, Ok(Ok(()))) {
                break;
            }
        }
        let transaction = self.begin_verified_transaction(client).await?;
        let row = transaction
            .query_one(
                "SELECT count(*) FILTER (WHERE state IN ('staged','delete_pending')),
                    count(*) FILTER (WHERE state='delete_confirmed')
             FROM registry_internal.registry_attachment_blobs WHERE backend_id <> 'database'",
                &[],
            )
            .await
            .map_err(map_retention_error)?;
        let pending = count_to_u64(row.get(0))?;
        let tombstones = count_to_u64(row.get(1))?;
        transaction
            .commit()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        Ok((pending, tombstones))
    }

    async fn retry_external_deletion(
        &self,
        client: &mut deadpool_postgres::Client,
        hash: &str,
        backend: &str,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let transaction = self.begin_verified_transaction(client).await?;
        crate::attachment_store::lock_hash(&transaction, hash)
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let eligible = transaction
            .query_opt(
                "SELECT 1 FROM registry_internal.registry_attachment_blobs b
             WHERE sha256=$1 AND backend_id=$2
               AND (state IN ('delete_pending','delete_confirmed')
                 OR (state='staged' AND created_at < transaction_timestamp()-interval '10 minutes'))
               AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_request_attachments a
                   WHERE a.sha256=b.sha256 AND a.erased_at IS NULL)",
                &[&hash, &backend],
            )
            .await
            .map_err(map_retention_error)?
            .is_some();
        if eligible {
            if let crate::attachment_storage::AttachmentStorage::S3(store) =
                &self.attachment_storage
            {
                // Record retry intent before calling the backend; unsuccessful
                // attempts commit as pending, successful ones confirm absence.
                crate::attachment_store::fail_external_delete(&transaction, hash, backend)
                    .await
                    .map_err(|_| RequestRetentionError::Unavailable)?;
                // Fifteen seconds per object also leaves room for durable error
                // recording within the invocation's shared thirty-second budget.
                let budget = deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(Duration::from_secs(15));
                if matches!(
                    tokio::time::timeout(budget, store.delete(hash)).await,
                    Ok(Ok(()))
                ) {
                    crate::attachment_store::finish_external_delete(&transaction, hash, backend)
                        .await
                        .map_err(|_| RequestRetentionError::Unavailable)?;
                }
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        Ok(())
    }

    fn request_plan(&self, request_entity_id: &str) -> Result<()> {
        self.registry
            .entities()
            .get(request_entity_id)
            .and_then(|entity| entity.change_request.as_ref())
            .map(|_| ())
            .ok_or(RequestRetentionError::Unavailable)
    }

    async fn begin_verified_transaction<'a>(
        &self,
        client: &'a mut deadpool_postgres::Client,
    ) -> Result<tokio_postgres::Transaction<'a>> {
        let pg_client: &mut tokio_postgres::Client = client;
        verify_migration_role(pg_client, &self.migration_role)
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let transaction = pg_client
            .transaction()
            .await
            .map_err(|_| RequestRetentionError::Unavailable)?;
        set_local_timeout(&transaction, "lock_timeout", self.lock_timeout).await?;
        set_local_timeout(&transaction, "statement_timeout", self.statement_timeout).await?;
        transaction
            .execute(
                "SELECT pg_catalog.pg_advisory_xact_lock($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(map_retention_error)?;
        verify_catalog_identity_for_catalog(
            &transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await
        .map_err(|_| RequestRetentionError::Unavailable)?;
        transaction
            .execute(
                "SELECT pg_catalog.set_config('registry.active_package_revision', $1, true)",
                &[&self.expected.package_revision],
            )
            .await
            .map_err(map_retention_error)?;
        crate::attachment_store::verify_backend_binding(
            &transaction,
            &self.attachment_storage.binding_digest(),
            &self.verification_policy,
        )
        .await
        .map_err(|error| match error {
            crate::mutation::MutationError::Conflict => {
                RequestRetentionError::AttachmentStorageBindingMismatch
            }
            _ => RequestRetentionError::Unavailable,
        })?;
        Ok(transaction)
    }
}

/// Refuse successor activation when any submitted or approved current proposal
/// would be reinterpreted by the candidate Registry package.
pub async fn guard_successor_activation(
    client: &impl GenericClient,
    candidate: &CompiledRegistry,
) -> Result<()> {
    if !request_tables_exist(client).await? {
        return Ok(());
    }
    let fingerprints = candidate
        .entities()
        .values()
        .filter_map(|entity| {
            entity
                .change_request
                .as_ref()
                .map(|plan| (entity.id.clone(), plan.contract_fingerprint.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let entity_ids = fingerprints.keys().cloned().collect::<Vec<_>>();
    let contract_fingerprints = fingerprints.values().cloned().collect::<Vec<_>>();
    let incompatible = client
        .query_opt(
            "WITH candidate(request_entity_id, contract_fingerprint) AS (
                 SELECT * FROM unnest($1::text[], $2::text[])
             )
             SELECT 1
               FROM registry_internal.registry_request_state s
               LEFT JOIN registry_internal.registry_request_proposals p
                 ON p.request_entity_id = s.request_entity_id
                AND p.request_id = s.request_id
                AND p.proposal_version = s.proposal_version
               LEFT JOIN candidate c
                 ON c.request_entity_id = s.request_entity_id
              WHERE s.state IN ('submitted', 'approved')
                AND (
                    p.request_id IS NULL
                    OR p.snapshot IS NULL
                    OR c.contract_fingerprint IS NULL
                    OR c.contract_fingerprint <> p.contract_fingerprint
                )
              LIMIT 1",
            &[&entity_ids, &contract_fingerprints],
        )
        .await
        .map_err(map_retention_error)?;
    if incompatible.is_some() {
        return Err(RequestRetentionError::ActiveProposalRequiresRebase);
    }
    Ok(())
}

/// Erase payload detail for exactly one request proposal version while keeping
/// protected provenance needed by target revision links.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn erase_request_detail(
    client: &mut tokio_postgres::Client,
    registry: &CompiledRegistry,
    scope: RequestDetailErasureScope<'_>,
) -> Result<RequestDetailErasure> {
    let transaction = client
        .transaction()
        .await
        .map_err(|_| RequestRetentionError::Unavailable)?;
    let plan = load_erasure_plan(&transaction, registry, scope.clone(), true).await?;
    let (erasure, _) =
        erase_request_detail_in_transaction(&transaction, registry, scope, &plan).await?;
    transaction
        .commit()
        .await
        .map_err(|_| RequestRetentionError::Unavailable)?;
    Ok(erasure)
}

/// Load retained proposal history, including decision text only when the caller
/// grants its disclosure. Target identifiers are withheld until the caller can prove exact
/// record-level read authority for each target row.
pub async fn load_retained_history(
    client: &impl GenericClient,
    query: RetainedHistoryQuery<'_>,
) -> Result<RetainedRequestHistoryPage> {
    if query.request_entity_id.is_empty()
        || query.limit == 0
        || query.limit > MAX_RETAINED_HISTORY_PAGE_SIZE
        || query
            .after_proposal_version
            .is_some_and(|version| version < 1)
    {
        return Err(RequestRetentionError::Unavailable);
    }
    let page_limit = i64::from(query.limit) + 1;
    let rows = client
        .query(
            "WITH proposals AS (
                SELECT s.state, s.proposal_version AS current_version, p.proposal_version,
                       p.contract_fingerprint, p.effect_digest, p.erased_at IS NOT NULL AS erased,
                       a.application_id
                  FROM registry_internal.registry_request_state s
                  JOIN registry_internal.registry_request_proposals p
                    ON p.request_entity_id = s.request_entity_id AND p.request_id = s.request_id
                  LEFT JOIN registry_internal.registry_request_applications a
                    ON a.request_entity_id = p.request_entity_id AND a.request_id = p.request_id
                   AND a.proposal_version = p.proposal_version
                 WHERE s.request_entity_id = $1 AND s.request_id = $2
                   AND ($3::bigint IS NULL OR p.proposal_version > $3::bigint)
                 ORDER BY p.proposal_version LIMIT $4::bigint
             )
             SELECT p.*, d.decision_count, d.decision_bytes
               FROM proposals p
               CROSS JOIN LATERAL (
                   SELECT count(*) AS decision_count,
                          COALESCE(sum(octet_length(json_build_object(
                              'stageId', stage_id, 'kind', decision,
                              'decidedAt', to_char(decided_at AT TIME ZONE 'UTC',
                                  'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                              'reasonPresent', reason_present,
                              'reason', CASE WHEN $5::boolean THEN reason ELSE NULL END
                          )::text) + 1), 0)::bigint AS decision_bytes
                     FROM (SELECT stage_id, decision, decided_at, reason_present, reason
                             FROM registry_internal.registry_request_decisions
                            WHERE request_entity_id = $1 AND request_id = $2
                              AND proposal_version = p.proposal_version
                            ORDER BY decision_index LIMIT 1025) bounded
               ) d
              ORDER BY p.proposal_version",
            &[
                &query.request_entity_id,
                &query.request_id,
                &query.after_proposal_version,
                &page_limit,
                &query.include_decision_reasons,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let mut history: Vec<RetainedRequestProposal> =
        Vec::with_capacity(rows.len().min(usize::from(query.limit)));
    let mut next_after_proposal_version = None;
    let mut page_bytes = 64;
    for row in rows {
        let proposal = RetainedRequestProposal {
            request_entity_id: query.request_entity_id.to_owned(),
            request_id: query.request_id.to_string(),
            proposal_version: row.get(2),
            request_state: row.get(0),
            current: row.get::<_, i64>(1) == row.get::<_, i64>(2),
            contract_fingerprint: row.get(3),
            effect_digest: row.get(4),
            detail_erased: row.get(5),
            application_id: row.get::<_, Option<Uuid>>(6).map(|id| id.to_string()),
            result_link_count: 0,
            result_links: Vec::new(),
            decisions: Vec::new(),
        };
        let decision_bytes = usize::try_from(row.get::<_, i64>(8))
            .map_err(|_| RequestRetentionError::Unavailable)?;
        let proposal_bytes = serde_json::to_vec(&proposal)
            .map_err(|_| RequestRetentionError::Unavailable)?
            .len()
            .checked_add(decision_bytes)
            .ok_or(RequestRetentionError::Unavailable)?;
        if history.len() == usize::from(query.limit)
            || page_bytes + proposal_bytes > MAX_RETAINED_HISTORY_BYTES
        {
            // An exclusive cursor is the last returned version, never the
            // first omitted one. Refuse a single oversized proposal explicitly
            // rather than return an empty page that cannot make progress.
            next_after_proposal_version = Some(
                history
                    .last()
                    .ok_or(RequestRetentionError::Unavailable)?
                    .proposal_version,
            );
            break;
        }
        if row.get::<_, i64>(7) > MAX_RETAINED_DECISIONS as i64 {
            return Err(RequestRetentionError::Unavailable);
        }
        page_bytes += proposal_bytes;
        history.push(proposal);
    }
    let versions = history
        .iter()
        .map(|proposal| proposal.proposal_version)
        .collect::<Vec<_>>();
    let mut decisions = load_retained_decisions_for_versions(
        client,
        query.request_entity_id,
        query.request_id,
        &versions,
        query.include_decision_reasons,
    )
    .await?;
    for proposal in &mut history {
        proposal.decisions = decisions
            .remove(&proposal.proposal_version)
            .unwrap_or_default();
    }
    let mut page = RetainedRequestHistoryPage {
        proposals: history,
        next_after_proposal_version,
    };
    // Recheck actual serialized bytes after the batch read in case concurrent
    // decisions changed a proposal since its size was inspected.
    while serde_json::to_vec(&page)
        .map_err(|_| RequestRetentionError::Unavailable)?
        .len()
        > MAX_RETAINED_HISTORY_BYTES
    {
        if page.proposals.len() <= 1 {
            return Err(RequestRetentionError::Unavailable);
        }
        page.proposals.pop();
        page.next_after_proposal_version = page
            .proposals
            .last()
            .map(|proposal| proposal.proposal_version);
    }
    Ok(page)
}

/// Retained decision facts survive detail erasure. The caller supplies current
/// read authority before requesting the optional reason text.
pub async fn load_retained_decisions(
    client: &impl GenericClient,
    request_entity_id: &str,
    request_id: Uuid,
    proposal_version: i64,
    include_reason: bool,
) -> Result<Vec<RetainedRequestDecision>> {
    Ok(load_retained_decisions_for_versions(
        client,
        request_entity_id,
        request_id,
        &[proposal_version],
        include_reason,
    )
    .await?
    .remove(&proposal_version)
    .unwrap_or_default())
}

async fn load_retained_decisions_for_versions(
    client: &impl GenericClient,
    request_entity_id: &str,
    request_id: Uuid,
    proposal_versions: &[i64],
    include_reason: bool,
) -> Result<BTreeMap<i64, Vec<RetainedRequestDecision>>> {
    if proposal_versions.is_empty() {
        return Ok(BTreeMap::new());
    }
    if proposal_versions.len() > usize::from(MAX_RETAINED_HISTORY_PAGE_SIZE) {
        return Err(RequestRetentionError::Unavailable);
    }
    let rows = client.query(
        "SELECT version, d.stage_id, d.decision, d.decided_at, d.actor_reference,
                d.reason_present, d.reason
           FROM unnest($3::bigint[]) version
           CROSS JOIN LATERAL (
               SELECT stage_id, decision,
                      to_char(decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS decided_at,
                      actor_reference, reason_present,
                      CASE WHEN $4::boolean THEN reason ELSE NULL END AS reason,
                      decision_index
                 FROM registry_internal.registry_request_decisions
                WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = version
                ORDER BY decision_index LIMIT 1025
           ) d
          ORDER BY version, d.decision_index",
        &[&request_entity_id, &request_id, &proposal_versions, &include_reason],
    ).await.map_err(map_retention_error)?;
    let mut grouped = BTreeMap::<i64, Vec<RetainedRequestDecision>>::new();
    for row in rows {
        let decisions = grouped.entry(row.get(0)).or_default();
        if decisions.len() == MAX_RETAINED_DECISIONS {
            return Err(RequestRetentionError::Unavailable);
        }
        decisions.push(RetainedRequestDecision {
            stage_id: row.get(1),
            kind: row.get(2),
            decided_at: row.get(3),
            actor_reference: row.get(4),
            reason_present: row.get(5),
            reason: row.get(6),
        });
    }
    Ok(grouped)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestErasurePlan {
    current_state: String,
    retention_mode: CompiledChangeRequestRetentionMode,
    pinned: bool,
    detail_erased: bool,
    erase_current_intake: bool,
    erasure: RequestDetailErasure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetentionCursor {
    request_entity_id: String,
    request_id: Uuid,
    proposal_version: i64,
}

async fn load_erasure_plan(
    transaction: &tokio_postgres::Transaction<'_>,
    registry: &CompiledRegistry,
    scope: RequestDetailErasureScope<'_>,
    enforce_operator_erase: bool,
) -> Result<RequestErasurePlan> {
    if scope.request_entity_id.is_empty() || scope.proposal_version <= 0 {
        return Err(RequestRetentionError::Unavailable);
    }
    let request_entity = registry
        .entities()
        .get(scope.request_entity_id)
        .ok_or(RequestRetentionError::Unavailable)?;
    let request_plan = request_entity
        .change_request
        .as_ref()
        .ok_or(RequestRetentionError::Unavailable)?;
    if enforce_operator_erase
        && request_plan.retention_mode != CompiledChangeRequestRetentionMode::OperatorErase
    {
        return Err(RequestRetentionError::RetainMode);
    }
    let state = transaction
        .query_opt(
            "SELECT state, proposal_version, detail_erased_at
               FROM registry_internal.registry_request_state
              WHERE request_entity_id = $1 AND request_id = $2
              FOR UPDATE",
            &[&scope.request_entity_id, &scope.request_id],
        )
        .await
        .map_err(map_retention_error)?
        .ok_or(RequestRetentionError::Unavailable)?;
    let current_state: String = state.get(0);
    let current_version: i64 = state.get(1);
    let current_detail_already_erased = state.get::<_, Option<std::time::SystemTime>>(2).is_some();
    let current_detail = current_version == scope.proposal_version;
    let pinned = detail_is_pinned(current_detail, &current_state);
    if enforce_operator_erase && pinned {
        return Err(RequestRetentionError::ActiveDetailPinned);
    }
    let proposal = transaction
        .query_opt(
            "SELECT snapshot IS NULL, erased_at IS NOT NULL
               FROM registry_internal.registry_request_proposals
              WHERE request_entity_id = $1
                AND request_id = $2
                AND proposal_version = $3
              FOR UPDATE",
            &[
                &scope.request_entity_id,
                &scope.request_id,
                &scope.proposal_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let proposal_exists = proposal.is_some();
    let inspectable_pinned_current_detail = !enforce_operator_erase && current_detail && pinned;
    let canceled_current_detail = current_detail && current_state == "canceled";
    let erasure_target_exists =
        proposal_exists || canceled_current_detail || inspectable_pinned_current_detail;
    if !erasure_target_exists {
        return Err(RequestRetentionError::Unavailable);
    }
    let erase_current_intake = current_detail
        && matches!(current_state.as_str(), "rejected" | "canceled" | "applied")
        && !current_detail_already_erased;
    let erasure = count_request_detail_erasure(transaction, scope, erase_current_intake).await?;
    let proposal_erased = proposal
        .as_ref()
        .is_some_and(|row| row.get::<_, bool>(0) || row.get::<_, bool>(1));
    Ok(RequestErasurePlan {
        current_state,
        retention_mode: request_plan.retention_mode,
        pinned,
        detail_erased: current_detail_already_erased || proposal_erased,
        erase_current_intake,
        erasure,
    })
}

async fn count_request_detail_erasure(
    transaction: &tokio_postgres::Transaction<'_>,
    scope: RequestDetailErasureScope<'_>,
    erase_current_intake: bool,
) -> Result<RequestDetailErasure> {
    let row = transaction
        .query_one(
            "SELECT
                (SELECT count(*) FROM registry_internal.registry_request_proposals
                  WHERE request_entity_id = $1
                    AND request_id = $2
                    AND proposal_version = $3
                    AND snapshot IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_request_targets
                  WHERE request_entity_id = $1
                    AND request_id = $2
                    AND proposal_version = $3
                    AND (base_snapshot IS NOT NULL OR after_snapshot IS NOT NULL)),
                (SELECT count(*) FROM registry_internal.registry_idempotency
                  WHERE key_reference IN (
                        SELECT key_reference
                          FROM registry_internal.registry_request_idempotency_links
                         WHERE request_entity_id = $1
                           AND request_id = $2
                           AND proposal_version = $3
                    )
                    AND response_body IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_revisions r
                   JOIN registry_internal.registry_request_revision_links l
                     ON l.entity_id = r.entity_id
                    AND l.record_id = r.record_id
                    AND l.record_revision = r.record_revision
                  WHERE l.request_entity_id = $1
                    AND l.request_id = $2
                    AND l.proposal_version = $3
                    AND l.entity_id = $1
                    AND l.record_id = $2
                    AND l.link_kind IN
                        ('request_create','request_patch','request_lifecycle','request_batch')
                    AND r.snapshot IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_outbox o
                   JOIN registry_internal.registry_revisions r
                     ON o.entity_id = r.entity_id
                    AND o.record_reference = r.record_reference
                    AND o.record_revision = r.record_revision
                   JOIN registry_internal.registry_request_revision_links l
                     ON l.entity_id = r.entity_id
                    AND l.record_id = r.record_id
                    AND l.record_revision = r.record_revision
                  WHERE l.request_entity_id = $1
                    AND l.request_id = $2
                    AND l.proposal_version = $3
                    AND l.entity_id = $1
                    AND l.record_id = $2
                    AND l.link_kind IN
                        ('request_create','request_patch','request_lifecycle','request_batch')
                    AND o.payload IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_request_decisions
                  WHERE request_entity_id = $1
                    AND request_id = $2
                    AND proposal_version = $3
                    AND reason IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_request_attachments
                  WHERE request_entity_id=$1 AND request_id=$2 AND proposal_version=$3
                    AND erased_at IS NULL)",
            &[
                &scope.request_entity_id,
                &scope.request_id,
                &scope.proposal_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    Ok(RequestDetailErasure {
        proposal_snapshots: count_to_u64(row.get(0))?,
        target_snapshots: count_to_u64(row.get(1))?,
        idempotency_results: count_to_u64(row.get(2))?,
        request_revision_snapshots: count_to_u64(row.get(3))?,
        outbox_payloads: count_to_u64(row.get(4))?,
        decision_reasons: count_to_u64(row.get(5))?,
        current_intake_rows: u64::from(erase_current_intake),
        attachment_references: count_to_u64(row.get(6))?,
    })
}

async fn erase_request_detail_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
    registry: &CompiledRegistry,
    scope: RequestDetailErasureScope<'_>,
    plan: &RequestErasurePlan,
) -> Result<(RequestDetailErasure, Option<ErasedCurrentRevision>)> {
    let request_entity = registry
        .entities()
        .get(scope.request_entity_id)
        .filter(|entity| entity.change_request.is_some())
        .ok_or(RequestRetentionError::Unavailable)?;

    // Task selectors are proposal detail and must disappear in the same
    // maintenance transaction as the frozen proposal payload.
    transaction
        .execute(
            "DELETE FROM registry_internal.registry_request_task_authority
         WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = $3",
            &[
                &scope.request_entity_id,
                &scope.request_id,
                &scope.proposal_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let proposal_snapshots = transaction
        .execute(
            "UPDATE registry_internal.registry_request_proposals
                SET snapshot = NULL, erased_at = transaction_timestamp()
              WHERE request_entity_id = $1
                AND request_id = $2
                AND proposal_version = $3
                AND snapshot IS NOT NULL",
            &[
                &scope.request_entity_id,
                &scope.request_id,
                &scope.proposal_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let target_snapshots = transaction
        .execute(
            "UPDATE registry_internal.registry_request_targets
                SET base_snapshot = NULL,
                    after_snapshot = NULL,
                    erased_at = transaction_timestamp()
              WHERE request_entity_id = $1
                AND request_id = $2
                AND proposal_version = $3
                AND (base_snapshot IS NOT NULL OR after_snapshot IS NOT NULL)",
            &[
                &scope.request_entity_id,
                &scope.request_id,
                &scope.proposal_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let decision_reasons = transaction
        .execute(
            "UPDATE registry_internal.registry_request_decisions
                SET reason = NULL
              WHERE request_entity_id = $1
                AND request_id = $2
                AND proposal_version = $3
                AND reason IS NOT NULL",
            &[
                &scope.request_entity_id,
                &scope.request_id,
                &scope.proposal_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let idempotency_results = transaction
        .execute(
            "UPDATE registry_internal.registry_idempotency
                SET response_body = NULL,
                    erased_at = transaction_timestamp()
              WHERE key_reference IN (
                    SELECT key_reference
                      FROM registry_internal.registry_request_idempotency_links
                     WHERE request_entity_id = $1
                       AND request_id = $2
                       AND proposal_version = $3
                )
                AND response_body IS NOT NULL",
            &[
                &scope.request_entity_id,
                &scope.request_id,
                &scope.proposal_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let outbox_payloads = transaction
        .execute(
            "UPDATE registry_internal.registry_outbox o
                SET payload = NULL
               FROM registry_internal.registry_revisions r
               JOIN registry_internal.registry_request_revision_links l
                 ON l.entity_id = r.entity_id
                AND l.record_id = r.record_id
                AND l.record_revision = r.record_revision
              WHERE o.entity_id = r.entity_id
                AND o.record_reference = r.record_reference
                AND o.record_revision = r.record_revision
                AND l.request_entity_id = $1
                AND l.request_id = $2
                AND l.proposal_version = $3
                AND l.entity_id = $1
                AND l.record_id = $2
                AND l.link_kind IN
                    ('request_create','request_patch','request_lifecycle','request_batch')
                AND o.payload IS NOT NULL",
            &[
                &scope.request_entity_id,
                &scope.request_id,
                &scope.proposal_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let request_revision_snapshots = transaction
        .execute(
            "UPDATE registry_internal.registry_revisions r
                SET snapshot = NULL,
                    erased_at = transaction_timestamp()
               FROM registry_internal.registry_request_revision_links l
              WHERE r.entity_id = l.entity_id
                AND r.record_id = l.record_id
                AND r.record_revision = l.record_revision
                AND l.request_entity_id = $1
                AND l.request_id = $2
                AND l.proposal_version = $3
                AND l.entity_id = $1
                AND l.record_id = $2
                AND l.link_kind IN
                    ('request_create','request_patch','request_lifecycle','request_batch')
                AND r.snapshot IS NOT NULL",
            &[
                &scope.request_entity_id,
                &scope.request_id,
                &scope.proposal_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let current_revision = if plan.erase_current_intake {
        set_request_table_force_row_security(transaction, request_entity, false).await?;
        let revision =
            erase_current_intake_row(transaction, request_entity, scope.request_id).await?;
        set_request_table_force_row_security(transaction, request_entity, true).await?;
        revision
    } else {
        None
    };
    let attachment_references = crate::attachment_store::erase(
        transaction,
        scope.request_entity_id,
        scope.request_id,
        scope.proposal_version,
    )
    .await
    .map_err(|_| RequestRetentionError::Unavailable)?;
    let current_intake_rows = u64::from(current_revision.is_some());
    let erasure = RequestDetailErasure {
        proposal_snapshots,
        target_snapshots,
        decision_reasons,
        idempotency_results,
        request_revision_snapshots,
        outbox_payloads,
        current_intake_rows,
        attachment_references,
    };
    if erasure != plan.erasure {
        return Err(RequestRetentionError::Unavailable);
    }
    Ok((erasure, current_revision))
}

async fn set_request_table_force_row_security(
    transaction: &tokio_postgres::Transaction<'_>,
    entity: &CompiledEntity,
    forced: bool,
) -> Result<()> {
    let table = SqlIdentifier::parse(&entity.physical_table)
        .map_err(|_| RequestRetentionError::Unavailable)?;
    let action = if forced { "FORCE" } else { "NO FORCE" };
    transaction
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{} {action} ROW LEVEL SECURITY",
            table.quoted()
        ))
        .await
        .map_err(map_retention_error)?;
    Ok(())
}

async fn append_retention_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    profile: &AuditProfile,
    expected: &ExpectedRegistryIdentity,
    scope: RequestDetailErasureScope<'_>,
    erasure: RequestDetailErasure,
) -> Result<()> {
    let record_reference = profile
        .key_hasher()
        .audit_reference_hash(
            "breg-record-v1",
            &expected.package_revision,
            &scope.request_id.to_string(),
        )
        .map_err(|_| RequestRetentionError::Unavailable)?;
    let count = erasure
        .proposal_snapshots
        .checked_add(erasure.target_snapshots)
        .and_then(|count| count.checked_add(erasure.decision_reasons))
        .and_then(|count| count.checked_add(erasure.idempotency_results))
        .and_then(|count| count.checked_add(erasure.request_revision_snapshots))
        .and_then(|count| count.checked_add(erasure.outbox_payloads))
        .and_then(|count| count.checked_add(erasure.current_intake_rows))
        .and_then(|count| count.checked_add(erasure.attachment_references))
        .ok_or(RequestRetentionError::Unavailable)?;
    append_terminal_audit(
        transaction,
        profile,
        TerminalAudit {
            outcome: TerminalAuditOutcome::Committed,
            method: HttpMethod::Delete,
            operation_id: RETENTION_OPERATION_ID.to_owned(),
            entity_id: Some(scope.request_entity_id.to_owned()),
            action_id: None,
            package_revision: expected.package_revision.clone(),
            selected_access_profile: "operator".to_owned(),
            purpose_present: false,
            principal_reference: None,
            record_reference: Some(record_reference),
            record_revision: Some(scope.proposal_version),
            result_count: Some(
                usize::try_from(count).map_err(|_| RequestRetentionError::Unavailable)?,
            ),
            field_set_reference: Some(RETENTION_REFERENCE.to_owned()),
            correlation: RequestCorrelation::breg_created(),
        },
    )
    .await
    .map_err(|_| RequestRetentionError::Unavailable)
}

async fn set_local_timeout(
    transaction: &tokio_postgres::Transaction<'_>,
    name: &str,
    value: Duration,
) -> Result<()> {
    let milliseconds = value.as_millis();
    if milliseconds == 0 || milliseconds > 3_600_000 {
        return Err(RequestRetentionError::Unavailable);
    }
    transaction
        .execute(
            "SELECT pg_catalog.set_config($1, $2, true)",
            &[&name, &format!("{milliseconds}ms")],
        )
        .await
        .map_err(map_retention_error)?;
    Ok(())
}

fn detail_is_pinned(current_detail: bool, state: &str) -> bool {
    current_detail && matches!(state, "draft" | "needs_changes" | "submitted" | "approved")
}

fn retention_mode_name(mode: CompiledChangeRequestRetentionMode) -> &'static str {
    match mode {
        CompiledChangeRequestRetentionMode::Retain => "retain",
        CompiledChangeRequestRetentionMode::OperatorErase => "operator_erase",
    }
}

fn parse_retention_cursor(value: &str) -> Result<RetentionCursor> {
    let mut parts = value.split(':');
    let request_entity_id = parts.next().ok_or(RequestRetentionError::Unavailable)?;
    let request_id = parts.next().ok_or(RequestRetentionError::Unavailable)?;
    let proposal_version = parts.next().ok_or(RequestRetentionError::Unavailable)?;
    if parts.next().is_some() || request_entity_id.is_empty() {
        return Err(RequestRetentionError::Unavailable);
    }
    Ok(RetentionCursor {
        request_entity_id: request_entity_id.to_owned(),
        request_id: Uuid::parse_str(request_id).map_err(|_| RequestRetentionError::Unavailable)?,
        proposal_version: proposal_version
            .parse::<i64>()
            .ok()
            .filter(|version| *version > 0)
            .ok_or(RequestRetentionError::Unavailable)?,
    })
}

fn retention_cursor(request_entity_id: &str, request_id: Uuid, proposal_version: i64) -> String {
    format!("{request_entity_id}:{request_id}:{proposal_version}")
}

fn count_to_u64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| RequestRetentionError::Unavailable)
}

async fn erase_current_intake_row(
    transaction: &tokio_postgres::Transaction<'_>,
    entity: &CompiledEntity,
    request_id: Uuid,
) -> Result<Option<ErasedCurrentRevision>> {
    let table = SqlIdentifier::parse(&entity.physical_table)
        .map_err(|_| RequestRetentionError::Unavailable)?;
    let retained_fields = request_row_boundary_fields(entity);
    let null_assignments = entity
        .fields
        .values()
        .filter(|field| !retained_fields.contains(&field.id))
        .map(|field| {
            let column = SqlIdentifier::parse(&field.physical_name)
                .map_err(|_| RequestRetentionError::Unavailable)?;
            Ok(format!("{} = NULL", column.quoted()))
        })
        .collect::<Result<Vec<_>>>()?;
    let current = transaction
        .query_opt(
            &format!(
                "SELECT record_revision FROM registry_data.{}
                  WHERE record_id = $1::text::uuid
                  FOR UPDATE",
                table.quoted()
            ),
            &[&request_id.to_string()],
        )
        .await
        .map_err(map_retention_error)?
        .ok_or(RequestRetentionError::Unavailable)?;
    let previous_revision: i64 = current.get(0);
    let next_revision = previous_revision
        .checked_add(1)
        .ok_or(RequestRetentionError::Unavailable)?;
    let field_assignment_sql = if null_assignments.is_empty() {
        String::new()
    } else {
        format!(", {}", null_assignments.join(", "))
    };
    let changed = transaction
        .execute(
            &format!(
                "UPDATE registry_data.{}
                    SET record_revision = record_revision + 1,
                        record_lifecycle = 'tombstoned',
                        active_package_revision = DEFAULT,
                        updated_at = transaction_timestamp()
                        {}
                  WHERE record_id = $1
                    AND record_revision = $2",
                table.quoted(),
                field_assignment_sql
            ),
            &[&request_id, &previous_revision],
        )
        .await
        .map_err(map_retention_error)?;
    if changed != 1 {
        return Err(RequestRetentionError::Unavailable);
    }
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot, erased_at)
             VALUES ($1, $2, $3, $4, $5, 'tombstoned',
                     NULLIF(current_setting('registry.active_package_revision', true), ''),
                     $6, 'tombstone', $7, $8, NULL, transaction_timestamp())",
            &[
                &entity.id,
                &request_id,
                &RETENTION_REFERENCE,
                &next_revision,
                &Some(previous_revision),
                &RETENTION_OPERATION_ID,
                &RETENTION_REFERENCE,
                &RETENTION_REFERENCE,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    transaction
        .execute(
            "UPDATE registry_internal.registry_request_state
                SET detail_erased_at = transaction_timestamp(),
                    updated_at = transaction_timestamp()
              WHERE request_entity_id = $1
                AND request_id = $2
                AND detail_erased_at IS NULL",
            &[&entity.id, &request_id],
        )
        .await
        .map_err(map_retention_error)?;
    crate::request_store::erase_authored_intake_fields(transaction, &entity.id, request_id)
        .await
        .map_err(|_| RequestRetentionError::Unavailable)?;
    Ok(Some(ErasedCurrentRevision {
        entity_id: entity.id.clone(),
        record_id: request_id,
        record_revision: next_revision,
    }))
}

struct ErasedCurrentRevision {
    entity_id: String,
    record_id: Uuid,
    record_revision: i64,
}

fn request_row_boundary_fields(entity: &CompiledEntity) -> BTreeSet<String> {
    let mut fields = entity
        .access_profiles
        .values()
        .flat_map(|profile| {
            profile
                .row_boundaries
                .iter()
                .map(|boundary| boundary.field.clone())
        })
        .collect::<BTreeSet<_>>();
    if let Some(request) = &entity.change_request {
        for grant in &request.presence_permissions {
            fields.extend(
                grant
                    .request_row_boundaries
                    .iter()
                    .map(|boundary| boundary.field.clone()),
            );
        }
    }
    fields
}

async fn request_tables_exist(client: &impl GenericClient) -> Result<bool> {
    let row = client
        .query_one(
            "SELECT to_regclass('registry_internal.registry_request_state') IS NOT NULL
                AND to_regclass('registry_internal.registry_request_proposals') IS NOT NULL",
            &[],
        )
        .await
        .map_err(map_retention_error)?;
    Ok(row.get(0))
}

fn map_retention_error(_error: tokio_postgres::Error) -> RequestRetentionError {
    RequestRetentionError::Unavailable
}

fn map_history_commit_error(_error: HistoryCommitError) -> RequestRetentionError {
    RequestRetentionError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::RetainedRequestDecision;

    #[test]
    fn retained_decision_debug_redacts_reason_without_changing_serialization() {
        let reason = "retained-review-reason-debug-canary";
        let decision = RetainedRequestDecision {
            stage_id: "review".to_owned(),
            kind: "reject".to_owned(),
            decided_at: "2026-09-09T12:00:00Z".to_owned(),
            actor_reference: "private-actor-reference-canary".to_owned(),
            reason_present: true,
            reason: Some(reason.to_owned()),
        };
        let debug = format!("{decision:?}");
        assert!(!debug.contains(reason));
        assert!(!debug.contains("private-actor-reference-canary"));
        assert!(debug.contains("reason_present: true"));
        assert!(debug.contains("review"));
        let serialized = serde_json::to_value(&decision).expect("decision serializes");
        assert_eq!(serialized["reason"], reason);
        assert_eq!(serialized["reasonPresent"], true);
        assert!(serialized.get("actorReference").is_none());
    }
}
