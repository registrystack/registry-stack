// SPDX-License-Identifier: Apache-2.0

//! Bounded operator controls for Proposal activation safety and retention.

#[path = "proposal_retention/activation.rs"]
mod activation;
pub(crate) use activation::{
    install_activation_compatibility, submission_is_compatible,
    verify_activation_compatibility_freshness,
};
pub use activation::{
    prepare_proposal_activation_compatibility, ProposalActivationCompatibilityInventory,
};

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use registry_platform_audit::{AuditEntry, AuditProfile};
use serde::Serialize;
use serde_json::{json, Value};
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::audit::{terminal_entry, RegistryAudit, TerminalAudit, TerminalAuditOutcome};
use crate::correlation::RequestCorrelation;
use crate::history_maintenance::{lock_registry, HistoryMaintenanceError};
use crate::model::{
    CompiledActionExecution, CompiledProposalRetentionMode, CompiledRegistry, HttpMethod,
};
use crate::package::PackageError;
use crate::postgres::{
    verify_catalog_identity_for_catalog, verify_migration_role, ConnectionConfig,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey, SqlIdentifier,
};
use crate::runtime_config::load_runtime_config;

const MAX_RETAINED_HISTORY_PAGE_SIZE: u16 = 50;
/// The audit schema of the attachment-cleanup attempt and outcome entries.
pub const ATTACHMENT_CLEANUP_AUDIT_SCHEMA: &str = "breg-attachment-cleanup-audit/v2";
// Reserve the other half of the client's 2 MiB request-extension budget for
// current actions and the remaining request metadata.
const MAX_RETAINED_HISTORY_BYTES: usize = 1_048_576;
pub const MAX_PROPOSAL_RETENTION_OPERATOR_PAGE_SIZE: u16 = 100;
const RETENTION_OPERATION_ID: &str = "proposals.retention.erase";
const RETENTION_REFERENCE: &str = "proposal-retention-erasure";

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProposalRetentionError {
    #[error("active Proposals require explicit rebase or cancellation")]
    ActiveProposalRecoveryUnavailable,
    #[error("Proposal detail is still pinned by an active submission")]
    ActiveDetailPinned,
    #[error("Proposal retention policy does not permit operator erasure")]
    RetainMode,
    #[error(
        "attachment storage or verification binding differs from the registry pin; restore the original configuration"
    )]
    AttachmentStorageBindingMismatch,
    #[error("another session held the exclusive migration lock past the lock timeout")]
    MigrationLockHeld,
    /// The package at `package.root` is not the one the runtime file's
    /// `package.expectedDigest` pins. Both digests are package identities,
    /// not secrets, so the refusal names them.
    #[error("{0}")]
    PackagePinMismatch(registry_platform_config::blocks::PackageDigestMismatch),
    #[error("Proposal retention state is unavailable")]
    Unavailable,
    /// The erasure committed, but the audit destination refused the entry
    /// recording it. The erased detail is gone; restore the destination,
    /// then reconcile the erasure against the database before relying on
    /// the audit journal for it.
    #[error(
        "the Proposal detail erasure committed but its audit entry was not recorded; restore the audit destination"
    )]
    ErasureUnaudited,
}

pub type Result<T> = std::result::Result<T, ProposalRetentionError>;

#[derive(Clone, Debug)]
pub struct ProposalDetailErasureScope<'a> {
    pub action_id: &'a str,
    pub proposal_id: Uuid,
    pub submission_version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedHistoryQuery<'a> {
    pub action_id: &'a str,
    pub proposal_id: Uuid,
    pub after_submission_version: Option<i64>,
    pub limit: u16,
    pub authorized_target_entities: &'a BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetainedProposalHistoryPage {
    pub proposals: Vec<RetainedProposalProposal>,
    pub next_after_submission_version: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetainedProposalProposal {
    pub action_id: String,
    pub proposal_id: String,
    pub submission_version: i64,
    pub proposal_state: String,
    pub current: bool,
    pub contract_fingerprint: String,
    pub effect_digest: String,
    pub detail_erased: bool,
    pub application_id: Option<String>,
    pub result_link_count: u16,
    pub result_links: Vec<RetainedProposalResultLink>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetainedProposalResultLink {
    pub target_entity_id: String,
    pub target_record_id: String,
    pub target_revision: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalDetailErasure {
    pub proposal_snapshots: u64,
    pub target_snapshots: u64,
    pub review_submission_requests: u64,
    pub review_accepted_bindings: u64,
    pub review_result_payloads: u64,
    pub application_reasons: u64,
    pub idempotency_results: u64,
    pub draft_inputs: u64,
    pub attachment_references: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalRetentionListPage {
    pub proposals: Vec<ProposalRetentionListItem>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalRetentionListItem {
    pub action_id: String,
    pub proposal_id: String,
    pub submission_version: i64,
    pub proposal_state: String,
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
pub struct ProposalRetentionDryRun {
    pub action_id: String,
    pub proposal_id: String,
    pub submission_version: i64,
    pub proposal_state: String,
    pub retention_mode: &'static str,
    pub pinned: bool,
    pub eligible_for_erasure: bool,
    pub detail_erased: bool,
    pub erasure: ProposalDetailErasure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalRetentionErase {
    pub action_id: String,
    pub proposal_id: String,
    pub submission_version: i64,
    pub proposal_state: String,
    pub retention_mode: &'static str,
    pub erasure: ProposalDetailErasure,
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
pub struct ProposalRetentionOperatorService {
    registry: CompiledRegistry,
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    lock_key: RegistryLockKey,
    migration_connection: ConnectionConfig,
    migration_role: SqlIdentifier,
    runtime_role: SqlIdentifier,
    lock_timeout: Duration,
    statement_timeout: Duration,
    audit: RegistryAudit,
    attachment_storage: crate::attachment_storage::AttachmentStorage,
    verification_policy: String,
}

impl ProposalRetentionOperatorService {
    pub async fn from_runtime_config(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(ProposalRetentionError::Unavailable);
        }
        let config = load_runtime_config(path).map_err(|_| ProposalRetentionError::Unavailable)?;
        let package = config.load_active_package().map_err(|error| match error {
            PackageError::ExpectedDigestMismatch(mismatch) => {
                ProposalRetentionError::PackagePinMismatch(mismatch)
            }
            _ => ProposalRetentionError::Unavailable,
        })?;
        let runtime_connection = config
            .runtime_database_connection_config()
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let pool = runtime_connection
            .build_pool()
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let startup = crate::startup::prepare_loaded_startup(
            package,
            config.identity().database_id(),
            &mut client,
            config.database().roles().migration(),
            config.database().roles().runtime(),
        )
        .await
        .map_err(|_| ProposalRetentionError::Unavailable)?;
        drop(client);
        let migration_connection = config
            .migration_database_connection_config()
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let audit = RegistryAudit::open_companion(&config)
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let attachment_storage = config
            .activate_attachment_storage(startup.package().registry().registry_id())
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let verification_policy = config
            .activate_attachment_verification()
            .map_err(|_| ProposalRetentionError::AttachmentStorageBindingMismatch)?
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
            audit,
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
        audit: RegistryAudit,
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
            audit,
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
        action_id: Option<&str>,
        after_cursor: Option<&str>,
        limit: u16,
    ) -> Result<ProposalRetentionListPage> {
        if limit == 0 || limit > MAX_PROPOSAL_RETENTION_OPERATOR_PAGE_SIZE {
            return Err(ProposalRetentionError::Unavailable);
        }
        if let Some(entity_id) = action_id {
            self.proposal_policy(entity_id)?;
        }
        let after = after_cursor.map(parse_retention_cursor).transpose()?;
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let transaction = self.begin_verified_transaction(&mut client).await?;
        let page_limit = i64::from(limit) + 1;
        let rows = transaction
            .query(
                "SELECT s.action_id, s.proposal_id, s.state,
                        s.submission_version, s.detail_erased_at IS NOT NULL,
                        p.submission_version, p.contract_fingerprint, p.effect_digest,
                        p.erased_at IS NOT NULL
                   FROM registry_internal.registry_proposal_state s
                   LEFT JOIN registry_internal.registry_proposal_submissions p
                     ON p.action_id = s.action_id
                    AND p.proposal_id = s.proposal_id
                  WHERE ($1::text IS NULL OR s.action_id = $1::text)
                    AND (
                        $2::text IS NULL
                        OR (s.action_id, s.proposal_id, COALESCE(p.submission_version, s.submission_version))
                           > ($2::text, $3::uuid, $4::bigint)
                    )
                  ORDER BY s.action_id, s.proposal_id,
                           COALESCE(p.submission_version, s.submission_version)
                  LIMIT $5::bigint",
                &[
                    &action_id,
                    &after.as_ref().map(|cursor| cursor.action_id.as_str()),
                    &after.as_ref().map(|cursor| cursor.proposal_id),
                    &after.as_ref().map(|cursor| cursor.submission_version),
                    &page_limit,
                ],
            )
            .await
            .map_err(map_retention_error)?;
        let mut proposals = Vec::with_capacity(rows.len().min(usize::from(limit)));
        let mut next_cursor = None;
        let mut last_returned_cursor = None;
        for (index, row) in rows.into_iter().enumerate() {
            let entity_id: String = row.get(0);
            let proposal_id: Uuid = row.get(1);
            let state: String = row.get(2);
            let current_version: i64 = row.get(3);
            let current_detail_erased: bool = row.get(4);
            let submission_version = row.get::<_, Option<i64>>(5).unwrap_or(current_version);
            if index >= usize::from(limit) {
                next_cursor = last_returned_cursor;
                break;
            }
            let Some(plan) = self
                .registry
                .actions()
                .actions
                .iter()
                .find(|action| action.id == entity_id)
                .and_then(|action| match &action.execution {
                    CompiledActionExecution::Proposal { proposal } => Some(proposal),
                    _ => None,
                })
            else {
                continue;
            };
            let current = current_version == submission_version;
            let pinned = detail_is_pinned(current, &state);
            let detail_erased = row.get::<_, bool>(8) || current_detail_erased;
            last_returned_cursor = Some(retention_cursor(
                &entity_id,
                proposal_id,
                submission_version,
            ));
            proposals.push(ProposalRetentionListItem {
                action_id: entity_id,
                proposal_id: proposal_id.to_string(),
                submission_version,
                proposal_state: state,
                current,
                retention_mode: retention_mode_name(plan.retention),
                pinned,
                eligible_for_erasure: plan.retention
                    == CompiledProposalRetentionMode::OperatorErase
                    && !pinned,
                detail_erased,
                contract_fingerprint: row.get(6),
                effect_digest: row.get(7),
            });
        }
        transaction
            .commit()
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        Ok(ProposalRetentionListPage {
            proposals,
            next_cursor,
        })
    }

    pub async fn dry_run(
        &self,
        scope: ProposalDetailErasureScope<'_>,
    ) -> Result<ProposalRetentionDryRun> {
        self.proposal_policy(scope.action_id)?;
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let transaction = self.begin_verified_transaction(&mut client).await?;
        let plan = load_erasure_plan(&transaction, &self.registry, scope.clone(), false).await?;
        transaction
            .commit()
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        Ok(ProposalRetentionDryRun {
            action_id: scope.action_id.to_owned(),
            proposal_id: scope.proposal_id.to_string(),
            submission_version: scope.submission_version,
            proposal_state: plan.current_state,
            retention_mode: retention_mode_name(plan.retention),
            pinned: plan.pinned,
            eligible_for_erasure: plan.retention == CompiledProposalRetentionMode::OperatorErase
                && !plan.pinned,
            detail_erased: plan.detail_erased,
            erasure: plan.erasure,
        })
    }

    pub async fn erase(
        &self,
        scope: ProposalDetailErasureScope<'_>,
    ) -> Result<ProposalRetentionErase> {
        self.proposal_policy(scope.action_id)?;
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        // The request entry is accepted before the erasure transaction opens,
        // so an audit outage erases nothing; the response shares its
        // correlation. An erasure that ends without one writes the
        // unfinished outcome when the held request is dropped.
        let correlation = RequestCorrelation::breg_created();
        let request_entry = retention_request_entry(
            self.audit.profile(),
            &self.expected,
            scope.clone(),
            &correlation,
        )?;
        let unfinished = retention_outcome_record(&request_entry, "unfinished");
        let request_record = request_entry.clone();
        let mut attempt = self
            .audit
            .begin(request_entry, unfinished)
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let erased = self
            .erase_in_transaction(&mut client, scope.clone(), correlation)
            .await;
        let (plan, erasure, entry) = match erased {
            Ok((plan, erasure, entry, true)) => (plan, erasure, entry),
            Ok((plan, erasure, entry, false)) => {
                // A commit that returned an error may still have committed,
                // so the outcome recorded for this destructive operation is
                // the one the database holds, read on a fresh connection.
                match self.erasure_committed(&pool, scope.clone()).await {
                    Some(true) => (plan, erasure, entry),
                    resolved => {
                        let outcome = if resolved == Some(false) {
                            "failed"
                        } else {
                            "unfinished"
                        };
                        let answer = retention_outcome_record(&request_record, outcome);
                        if attempt.respond(answer).await.is_err() {
                            tracing::error!(
                                "the unacknowledged erasure's response audit entry was not recorded"
                            );
                        }
                        return Err(ProposalRetentionError::Unavailable);
                    }
                }
            }
            Err(error) => {
                // The erasure failed before its commit, so nothing
                // committed: answer the request with the refusal or the
                // failure.
                let outcome = if matches!(
                    error,
                    ProposalRetentionError::Unavailable | ProposalRetentionError::MigrationLockHeld
                ) {
                    "failed"
                } else {
                    "refused"
                };
                let answer = retention_outcome_record(&request_record, outcome);
                if attempt.respond(answer).await.is_err() {
                    tracing::error!("the failed erasure's response audit entry was not recorded");
                }
                return Err(error);
            }
        };
        // The committed erasure is recorded before external objects are
        // retried, so a slow or failing backend cannot hold its response
        // back. The result, not the entry, reports the registry-wide
        // external deletions still pending.
        attempt
            .respond(entry.record().clone())
            .await
            .map_err(|_| ProposalRetentionError::ErasureUnaudited)?;
        let (pending_external_deletions, external_deletion_tombstones) =
            self.retry_external_deletions(&mut client).await?;
        Ok(ProposalRetentionErase {
            action_id: scope.action_id.to_owned(),
            proposal_id: scope.proposal_id.to_string(),
            submission_version: scope.submission_version,
            proposal_state: plan.current_state,
            retention_mode: retention_mode_name(plan.retention),
            erasure,
            pending_external_deletions,
            external_deletion_tombstones,
        })
    }

    /// Whether the detail `scope` names is erased, read on a fresh
    /// connection after an erasure commit returned an error. `None` when the
    /// state cannot be read.
    async fn erasure_committed(
        &self,
        pool: &crate::postgres::RuntimePool,
        scope: ProposalDetailErasureScope<'_>,
    ) -> Option<bool> {
        let mut client = pool.get().await.ok()?;
        let transaction = self.begin_verified_transaction(&mut client).await.ok()?;
        let plan = load_erasure_plan(&transaction, &self.registry, scope, false)
            .await
            .ok()?;
        transaction.commit().await.ok()?;
        Some(plan.detail_erased)
    }

    /// Erase one request's detail in one transaction and build the terminal
    /// entry that records it. The flag is false when the commit returned an
    /// error, which does not prove the transaction rolled back; every
    /// earlier error is returned as one.
    async fn erase_in_transaction(
        &self,
        client: &mut deadpool_postgres::Client,
        scope: ProposalDetailErasureScope<'_>,
        correlation: RequestCorrelation,
    ) -> Result<(ProposalErasurePlan, ProposalDetailErasure, AuditEntry, bool)> {
        let transaction = self.begin_verified_transaction(client).await?;
        let plan = load_erasure_plan(&transaction, &self.registry, scope.clone(), true).await?;
        let erasure = erase_proposal_detail_in_transaction(
            &transaction,
            &self.registry,
            scope.clone(),
            &plan,
        )
        .await?;
        let entry = retention_terminal_entry(
            self.audit.profile(),
            &self.expected,
            scope.clone(),
            erasure,
            correlation,
        )?;
        let acknowledged = transaction.commit().await.is_ok();
        Ok((plan, erasure, entry, acknowledged))
    }

    /// Retry orphaned external objects even when every request is active or
    /// uses retain mode. Only objects without live references are eligible.
    pub async fn cleanup_attachments(&self) -> Result<AttachmentCleanup> {
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let correlation = Uuid::new_v4().to_string();
        // The verified transaction proves this process may act on the
        // managed catalog before the request entry is written; it holds no
        // audit state.
        let transaction = self.begin_verified_transaction(&mut client).await?;
        transaction.commit().await.map_err(map_retention_error)?;
        let record = |phase: &str, outcome: &str| {
            serde_json::json!({
                "kind":"attachmentCleanup", "phase":phase, "outcome":outcome,
                "activationId":self.expected.activation_id,
                "actor":"breg:proposal-retention-operator", "correlation":correlation,
            })
        };
        // A cleanup that ends before its response writes the unfinished
        // outcome when the held request is dropped.
        let mut attempt = self
            .audit
            .begin(
                AuditEntry::request(
                    ATTACHMENT_CLEANUP_AUDIT_SCHEMA,
                    correlation.clone(),
                    record("attempt", "started"),
                ),
                record("terminal", "unfinished"),
            )
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let (pending_external_deletions, external_deletion_tombstones) = match self
            .retry_external_deletions(&mut client)
            .await
        {
            Ok(counts) => counts,
            Err(error) => {
                if attempt.respond(record("terminal", "failed")).await.is_err() {
                    tracing::error!("the failed cleanup's response audit entry was not recorded");
                }
                return Err(error);
            }
        };
        let result = AttachmentCleanup {
            pending_external_deletions,
            external_deletion_tombstones,
        };
        let mut completed = record("terminal", "completed");
        completed["pendingExternalDeletions"] =
            serde_json::json!(result.pending_external_deletions);
        completed["externalDeletionTombstones"] =
            serde_json::json!(result.external_deletion_tombstones);
        attempt
            .respond(completed)
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
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
            .map_err(|_| ProposalRetentionError::Unavailable)?;
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
            .map_err(|_| ProposalRetentionError::Unavailable)?;
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
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let eligible = transaction
            .query_opt(
                "SELECT 1 FROM registry_internal.registry_attachment_blobs b
             WHERE sha256=$1 AND backend_id=$2
               AND (state IN ('delete_pending','delete_confirmed')
                 OR (state='staged' AND created_at < transaction_timestamp()-interval '10 minutes'))
               AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_proposal_attachments a
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
                    .map_err(|_| ProposalRetentionError::Unavailable)?;
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
                        .map_err(|_| ProposalRetentionError::Unavailable)?;
                }
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        Ok(())
    }

    /// Opens a migration-role connection for one operator invocation.
    pub(crate) async fn migration_client(&self) -> Result<deadpool_postgres::Client> {
        self.migration_connection
            .build_pool()
            .map_err(|_| ProposalRetentionError::Unavailable)?
            .get()
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)
    }

    pub(crate) fn audit(&self) -> &RegistryAudit {
        &self.audit
    }

    pub(crate) fn package_revision(&self) -> &str {
        &self.expected.activation_id
    }

    pub(crate) fn proposal_policy(&self, action_id: &str) -> Result<()> {
        self.registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == action_id)
            .and_then(|action| match &action.execution {
                CompiledActionExecution::Proposal { proposal } => Some(proposal),
                _ => None,
            })
            .map(|_| ())
            .ok_or(ProposalRetentionError::Unavailable)
    }

    pub(crate) async fn begin_verified_transaction<'a>(
        &self,
        client: &'a mut deadpool_postgres::Client,
    ) -> Result<tokio_postgres::Transaction<'a>> {
        let pg_client: &mut tokio_postgres::Client = client;
        verify_migration_role(pg_client, &self.migration_role)
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        let transaction = pg_client
            .transaction()
            .await
            .map_err(|_| ProposalRetentionError::Unavailable)?;
        set_local_timeout(&transaction, "lock_timeout", self.lock_timeout).await?;
        set_local_timeout(&transaction, "statement_timeout", self.statement_timeout).await?;
        lock_registry(&transaction, self.lock_key)
            .await
            .map_err(|error| match error {
                HistoryMaintenanceError::MigrationLockHeld => {
                    ProposalRetentionError::MigrationLockHeld
                }
                _ => ProposalRetentionError::Unavailable,
            })?;
        verify_catalog_identity_for_catalog(
            &transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await
        .map_err(|_| ProposalRetentionError::Unavailable)?;
        transaction
            .execute(
                "SELECT pg_catalog.set_config('registry.active_package_revision', $1, true)",
                &[&self.expected.activation_id],
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
                ProposalRetentionError::AttachmentStorageBindingMismatch
            }
            _ => ProposalRetentionError::Unavailable,
        })?;
        Ok(transaction)
    }
}

/// Refuse successor activation when any submitted current proposal
/// would be reinterpreted by the candidate Registry package.
pub async fn guard_successor_activation(
    client: &impl GenericClient,
    candidate: &CompiledRegistry,
) -> Result<()> {
    if !proposal_tables_exist(client).await? {
        return Ok(());
    }
    let rows = client
        .query(
            "SELECT DISTINCT action_id FROM registry_internal.registry_proposal_state
        WHERE state IN ('draft','submitted')",
            &[],
        )
        .await
        .map_err(map_retention_error)?;
    for row in rows {
        let id: String = row.get(0);
        let action = candidate
            .actions()
            .actions
            .iter()
            .find(|action| action.id == id)
            .ok_or(ProposalRetentionError::ActiveProposalRecoveryUnavailable)?;
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            return Err(ProposalRetentionError::ActiveProposalRecoveryUnavailable);
        };
        if !proposal.permissions.iter().any(|grant| {
            grant
                .operations
                .contains(&crate::model::ProposalOperation::Get)
        }) || !proposal.permissions.iter().any(|grant| {
            grant
                .operations
                .contains(&crate::model::ProposalOperation::Cancel)
        }) {
            return Err(ProposalRetentionError::ActiveProposalRecoveryUnavailable);
        }
    }
    Ok(())
}

/// Call only inside the successful activation transaction. Rehearsals and
/// refused activation perform the pure guard above without changing work.
pub(crate) async fn mark_incompatible_proposals(
    client: &impl GenericClient,
    candidate: &CompiledRegistry,
    candidate_digest: &str,
    activation_id: &str,
) -> Result<()> {
    if !proposal_tables_exist(client).await? {
        return Ok(());
    }
    let activation =
        Uuid::parse_str(activation_id).map_err(|_| ProposalRetentionError::Unavailable)?;
    for action in &candidate.actions().actions {
        if !action.execution.is_proposal() {
            continue;
        }
        client.execute("UPDATE registry_internal.registry_proposal_state
            SET blocked_reason=CASE WHEN action_revision=$2 OR (state='submitted' AND EXISTS (
                SELECT 1 FROM registry_internal.registry_proposal_activation_compatibility c
                JOIN registry_internal.registry_proposal_submissions p USING(action_id,proposal_id,submission_version)
                WHERE c.action_id=registry_proposal_state.action_id AND c.proposal_id=registry_proposal_state.proposal_id
                  AND c.submission_version=registry_proposal_state.submission_version
                  AND c.frozen_action_revision=registry_proposal_state.action_revision
                  AND c.current_action_revision=$2 AND c.candidate_package_digest=$3 AND c.activation_id=$4
                  AND c.effect_digest=p.snapshot->>'effectDigest' AND p.erased_at IS NULL))
                THEN NULL ELSE 'package-changed' END,
                updated_at=transaction_timestamp()
            WHERE action_id=$1 AND state IN ('draft','submitted')",
            &[&action.id,&action.definition_revision,&candidate_digest,&activation]).await.map_err(map_retention_error)?;
    }
    Ok(())
}

/// Erase payload detail for exactly one Proposal version while keeping
/// protected provenance needed by target revision links.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn erase_proposal_detail(
    client: &mut tokio_postgres::Client,
    registry: &CompiledRegistry,
    scope: ProposalDetailErasureScope<'_>,
) -> Result<ProposalDetailErasure> {
    let transaction = client
        .transaction()
        .await
        .map_err(|_| ProposalRetentionError::Unavailable)?;
    let plan = load_erasure_plan(&transaction, registry, scope.clone(), true).await?;
    let erasure =
        erase_proposal_detail_in_transaction(&transaction, registry, scope, &plan).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ProposalRetentionError::Unavailable)?;
    Ok(erasure)
}

/// Load retained proposal history. Target identifiers are withheld until the
/// caller can prove exact record-level read authority for each target row.
pub async fn load_retained_history(
    client: &impl GenericClient,
    query: RetainedHistoryQuery<'_>,
) -> Result<RetainedProposalHistoryPage> {
    if query.action_id.is_empty()
        || query.limit == 0
        || query.limit > MAX_RETAINED_HISTORY_PAGE_SIZE
        || query
            .after_submission_version
            .is_some_and(|version| version < 1)
    {
        return Err(ProposalRetentionError::Unavailable);
    }
    let page_limit = i64::from(query.limit) + 1;
    let rows = client
        .query(
            "WITH proposals AS (
                SELECT s.state, s.submission_version AS current_version, p.submission_version,
                       p.contract_fingerprint, p.effect_digest, p.erased_at IS NOT NULL AS erased,
                       a.application_id
                  FROM registry_internal.registry_proposal_state s
                  JOIN registry_internal.registry_proposal_submissions p
                    ON p.action_id = s.action_id AND p.proposal_id = s.proposal_id
                  LEFT JOIN registry_internal.registry_proposal_applications a
                    ON a.action_id = p.action_id AND a.proposal_id = p.proposal_id
                   AND a.submission_version = p.submission_version
                 WHERE s.action_id = $1 AND s.proposal_id = $2
                   AND ($3::bigint IS NULL OR p.submission_version > $3::bigint)
                 ORDER BY p.submission_version LIMIT $4::bigint
             )
             SELECT p.* FROM proposals p ORDER BY p.submission_version",
            &[
                &query.action_id,
                &query.proposal_id,
                &query.after_submission_version,
                &page_limit,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let mut history: Vec<RetainedProposalProposal> =
        Vec::with_capacity(rows.len().min(usize::from(query.limit)));
    let mut next_after_submission_version = None;
    let mut page_bytes = 64;
    for row in rows {
        let proposal = RetainedProposalProposal {
            action_id: query.action_id.to_owned(),
            proposal_id: query.proposal_id.to_string(),
            submission_version: row.get(2),
            proposal_state: row.get(0),
            current: row.get::<_, i64>(1) == row.get::<_, i64>(2),
            contract_fingerprint: row.get(3),
            effect_digest: row.get(4),
            detail_erased: row.get(5),
            application_id: row.get::<_, Option<Uuid>>(6).map(|id| id.to_string()),
            result_link_count: 0,
            result_links: Vec::new(),
        };
        let proposal_bytes = serde_json::to_vec(&proposal)
            .map_err(|_| ProposalRetentionError::Unavailable)?
            .len();
        if history.len() == usize::from(query.limit)
            || page_bytes + proposal_bytes > MAX_RETAINED_HISTORY_BYTES
        {
            // An exclusive cursor is the last returned version, never the
            // first omitted one. Refuse a single oversized proposal explicitly
            // rather than return an empty page that cannot make progress.
            next_after_submission_version = Some(
                history
                    .last()
                    .ok_or(ProposalRetentionError::Unavailable)?
                    .submission_version,
            );
            break;
        }
        page_bytes += proposal_bytes;
        history.push(proposal);
    }
    let mut page = RetainedProposalHistoryPage {
        proposals: history,
        next_after_submission_version,
    };
    // Recheck actual serialized bytes after the batch read in case concurrent
    // application state changed a proposal since its size was inspected.
    while serde_json::to_vec(&page)
        .map_err(|_| ProposalRetentionError::Unavailable)?
        .len()
        > MAX_RETAINED_HISTORY_BYTES
    {
        if page.proposals.len() <= 1 {
            return Err(ProposalRetentionError::Unavailable);
        }
        page.proposals.pop();
        page.next_after_submission_version = page
            .proposals
            .last()
            .map(|proposal| proposal.submission_version);
    }
    Ok(page)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProposalErasurePlan {
    current_state: String,
    retention: CompiledProposalRetentionMode,
    pinned: bool,
    detail_erased: bool,
    erase_draft_input: bool,
    erasure: ProposalDetailErasure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetentionCursor {
    action_id: String,
    proposal_id: Uuid,
    submission_version: i64,
}

async fn load_erasure_plan(
    transaction: &tokio_postgres::Transaction<'_>,
    registry: &CompiledRegistry,
    scope: ProposalDetailErasureScope<'_>,
    enforce_operator_erase: bool,
) -> Result<ProposalErasurePlan> {
    if scope.action_id.is_empty() || scope.submission_version <= 0 {
        return Err(ProposalRetentionError::Unavailable);
    }
    let proposal_policy = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == scope.action_id)
        .and_then(|action| match &action.execution {
            CompiledActionExecution::Proposal { proposal } => Some(proposal),
            _ => None,
        })
        .ok_or(ProposalRetentionError::Unavailable)?;
    if enforce_operator_erase
        && proposal_policy.retention != CompiledProposalRetentionMode::OperatorErase
    {
        return Err(ProposalRetentionError::RetainMode);
    }
    let state = transaction
        .query_opt(
            "SELECT state, submission_version, detail_erased_at
               FROM registry_internal.registry_proposal_state
              WHERE action_id = $1 AND proposal_id = $2
              FOR UPDATE",
            &[&scope.action_id, &scope.proposal_id],
        )
        .await
        .map_err(map_retention_error)?
        .ok_or(ProposalRetentionError::Unavailable)?;
    let current_state: String = state.get(0);
    let current_version: i64 = state.get(1);
    let current_detail_already_erased = state.get::<_, Option<std::time::SystemTime>>(2).is_some();
    let current_detail = current_version == scope.submission_version;
    let pinned = detail_is_pinned(current_detail, &current_state);
    if enforce_operator_erase && pinned {
        return Err(ProposalRetentionError::ActiveDetailPinned);
    }
    let proposal = transaction
        .query_opt(
            "SELECT snapshot IS NULL, erased_at IS NOT NULL
               FROM registry_internal.registry_proposal_submissions
              WHERE action_id = $1
                AND proposal_id = $2
                AND submission_version = $3
              FOR UPDATE",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let proposal_exists = proposal.is_some();
    let inspectable_pinned_current_detail = !enforce_operator_erase && current_detail && pinned;
    let cancelled_current_detail = current_detail && current_state == "cancelled";
    let erasure_target_exists =
        proposal_exists || cancelled_current_detail || inspectable_pinned_current_detail;
    if !erasure_target_exists {
        return Err(ProposalRetentionError::Unavailable);
    }
    let erase_draft_input = current_detail
        && matches!(current_state.as_str(), "cancelled" | "applied" | "rejected")
        && !current_detail_already_erased;
    let erasure = count_request_detail_erasure(transaction, scope, erase_draft_input).await?;
    let proposal_erased = proposal
        .as_ref()
        .is_some_and(|row| row.get::<_, bool>(0) || row.get::<_, bool>(1));
    Ok(ProposalErasurePlan {
        current_state,
        retention: proposal_policy.retention,
        pinned,
        detail_erased: current_detail_already_erased || proposal_erased,
        erase_draft_input,
        erasure,
    })
}

async fn count_request_detail_erasure(
    transaction: &tokio_postgres::Transaction<'_>,
    scope: ProposalDetailErasureScope<'_>,
    erase_draft_input: bool,
) -> Result<ProposalDetailErasure> {
    let row = transaction
        .query_one(
            "SELECT
                (SELECT count(*) FROM registry_internal.registry_proposal_submissions
                  WHERE action_id = $1
                    AND proposal_id = $2
                    AND submission_version = $3
                    AND snapshot IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_proposal_targets
                  WHERE action_id = $1
                    AND proposal_id = $2
                    AND submission_version = $3
                    AND (base_snapshot IS NOT NULL OR after_snapshot IS NOT NULL)),
                (SELECT count(*) FROM registry_internal.registry_idempotency
                  WHERE key_reference IN (
                        SELECT key_reference
                          FROM registry_internal.registry_proposal_idempotency_links
                         WHERE action_id = $1
                           AND proposal_id = $2
                           AND submission_version = $3
                    )
                    AND response_body IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_proposal_applications
                  WHERE action_id = $1
                    AND proposal_id = $2
                    AND submission_version = $3
                    AND reason IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_proposal_attachments
                  WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                    AND erased_at IS NULL),
                (SELECT count(*)
                   FROM registry_internal.registry_proposal_review_submissions s
                  WHERE s.action_id=$1 AND s.proposal_id=$2 AND s.submission_version=$3
                    AND s.create_request <> '{}'::jsonb
                    AND (s.state IN ('cancelled','failed') OR (
                        s.state='accepted' AND EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_proposal_review_results r
                             WHERE r.action_id=s.action_id
                               AND r.proposal_id=s.proposal_id
                               AND r.submission_version=s.submission_version
                        )
                    ))),
                (SELECT count(*)
                   FROM registry_internal.registry_proposal_review_submissions s
                  WHERE s.action_id=$1 AND s.proposal_id=$2 AND s.submission_version=$3
                    AND s.accepted_binding IS NOT NULL
                    AND s.accepted_binding <> '{}'::jsonb
                    AND (s.state IN ('cancelled','failed') OR (
                        s.state='accepted' AND EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_proposal_review_results r
                             WHERE r.action_id=s.action_id
                               AND r.proposal_id=s.proposal_id
                               AND r.submission_version=s.submission_version
                        )
                    ))),
                (SELECT count(*) FROM registry_internal.registry_proposal_review_results
                  WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                    AND result <> '{}'::jsonb)",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    Ok(ProposalDetailErasure {
        proposal_snapshots: count_to_u64(row.get(0))?,
        target_snapshots: count_to_u64(row.get(1))?,
        idempotency_results: count_to_u64(row.get(2))?,
        application_reasons: count_to_u64(row.get(3))?,
        draft_inputs: u64::from(erase_draft_input),
        attachment_references: count_to_u64(row.get(4))?,
        review_submission_requests: count_to_u64(row.get(5))?,
        review_accepted_bindings: count_to_u64(row.get(6))?,
        review_result_payloads: count_to_u64(row.get(7))?,
    })
}

async fn erase_proposal_detail_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
    registry: &CompiledRegistry,
    scope: ProposalDetailErasureScope<'_>,
    plan: &ProposalErasurePlan,
) -> Result<ProposalDetailErasure> {
    let _ = registry;
    // Task selectors are proposal detail and must disappear in the same
    // maintenance transaction as the frozen proposal payload.
    transaction
        .execute(
            "DELETE FROM registry_internal.registry_proposal_task_authority
         WHERE action_id = $1 AND proposal_id = $2 AND submission_version = $3",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let proposal_snapshots = transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_submissions
                SET snapshot = NULL, erased_at = transaction_timestamp()
              WHERE action_id = $1
                AND proposal_id = $2
                AND submission_version = $3
                AND snapshot IS NOT NULL",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let target_snapshots = transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_targets
                SET base_snapshot = NULL,
                    after_snapshot = NULL,
                    erased_at = transaction_timestamp()
              WHERE action_id = $1
                AND proposal_id = $2
                AND submission_version = $3
                AND (base_snapshot IS NOT NULL OR after_snapshot IS NOT NULL)",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    // Exact submission recovery still owns create_request until a refusal or
    // cancellation is terminal. Cancellation and result recovery still own
    // accepted_binding until cancellation finishes or a terminal result is
    // durable. The dry-run counts above use this same boundary.
    let review_submission_requests = transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_review_submissions s
                SET create_request = '{}'::jsonb
              WHERE s.action_id = $1
                AND s.proposal_id = $2
                AND s.submission_version = $3
                AND s.create_request <> '{}'::jsonb
                AND (s.state IN ('cancelled','failed') OR (
                    s.state='accepted' AND EXISTS (
                        SELECT 1
                          FROM registry_internal.registry_proposal_review_results r
                         WHERE r.action_id=s.action_id
                           AND r.proposal_id=s.proposal_id
                           AND r.submission_version=s.submission_version
                    )
                ))",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let review_accepted_bindings = transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_review_submissions s
                SET accepted_binding = '{}'::jsonb
              WHERE s.action_id = $1
                AND s.proposal_id = $2
                AND s.submission_version = $3
                AND s.accepted_binding IS NOT NULL
                AND s.accepted_binding <> '{}'::jsonb
                AND (s.state IN ('cancelled','failed') OR (
                    s.state='accepted' AND EXISTS (
                        SELECT 1
                          FROM registry_internal.registry_proposal_review_results r
                         WHERE r.action_id=s.action_id
                           AND r.proposal_id=s.proposal_id
                           AND r.submission_version=s.submission_version
                    )
                ))",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let review_result_payloads = transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_review_results
                SET result = '{}'::jsonb
              WHERE action_id = $1
                AND proposal_id = $2
                AND submission_version = $3
                AND result <> '{}'::jsonb",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let application_reasons = transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_applications
                SET reason = NULL
              WHERE action_id = $1
                AND proposal_id = $2
                AND submission_version = $3
                AND reason IS NOT NULL",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
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
                      FROM registry_internal.registry_proposal_idempotency_links
                     WHERE action_id = $1
                       AND proposal_id = $2
                       AND submission_version = $3
                )
                AND response_body IS NOT NULL",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let draft_inputs = if plan.erase_draft_input {
        transaction
            .execute(
                "UPDATE registry_internal.registry_proposal_state
            SET input=NULL,action_title=NULL,
                detail_erased_at=transaction_timestamp(),updated_at=transaction_timestamp()
            WHERE action_id=$1 AND proposal_id=$2 AND detail_erased_at IS NULL",
                &[&scope.action_id, &scope.proposal_id],
            )
            .await
            .map_err(map_retention_error)?
    } else {
        0
    };
    let attachment_references = crate::attachment_store::erase(
        transaction,
        scope.action_id,
        scope.proposal_id,
        scope.submission_version,
    )
    .await
    .map_err(|_| ProposalRetentionError::Unavailable)?;
    let erasure = ProposalDetailErasure {
        proposal_snapshots,
        target_snapshots,
        review_submission_requests,
        review_accepted_bindings,
        review_result_payloads,
        application_reasons,
        idempotency_results,
        draft_inputs,
        attachment_references,
    };
    if erasure != plan.erasure {
        return Err(ProposalRetentionError::Unavailable);
    }
    Ok(erasure)
}

/// Build the `response` entry for one request-detail erasure. The caller
/// appends it after the erasure transaction commits.
fn retention_record_reference(
    profile: &AuditProfile,
    expected: &ExpectedRegistryIdentity,
    scope: &ProposalDetailErasureScope<'_>,
) -> Result<String> {
    profile
        .key_hasher()
        .audit_reference_hash(
            "breg-record-v1",
            &expected.activation_id,
            &scope.proposal_id.to_string(),
        )
        .map_err(|_| ProposalRetentionError::Unavailable)
}

/// The `request` entry of one request-detail erasure. It names only what the
/// erasure's `response` entry already records: the operation, the package
/// revision, the operator profile, and the keyed record reference.
fn retention_request_entry(
    profile: &AuditProfile,
    expected: &ExpectedRegistryIdentity,
    scope: ProposalDetailErasureScope<'_>,
    correlation: &RequestCorrelation,
) -> Result<AuditEntry> {
    if !crate::audit::profile_is_keyed(profile) {
        return Err(ProposalRetentionError::Unavailable);
    }
    let record_reference = retention_record_reference(profile, expected, &scope)?;
    Ok(AuditEntry::request(
        crate::audit::AUDIT_SCHEMA,
        correlation.request_id().to_string(),
        serde_json::json!({
            "phase": "attempt",
            "method": "DELETE",
            "operationId": RETENTION_OPERATION_ID,
            "actionId": scope.action_id,
            "requestId": correlation.request_id().to_string(),
            "traceId": correlation.trace_id().as_str(),
            "activationId": expected.activation_id,
            "selectedAccessProfile": "operator",
            "purposePresent": false,
            "principalReference": null,
            "recordReference": record_reference,
        }),
    ))
}

/// The `response` of an erasure that did not record its committed terminal:
/// the request's identities with `outcome`, and no count.
fn retention_outcome_record(request: &AuditEntry, outcome: &str) -> Value {
    let mut record = request.record().clone();
    if let Some(fields) = record.as_object_mut() {
        fields.insert("phase".to_owned(), json!("terminal"));
        fields.insert("outcome".to_owned(), json!(outcome));
    }
    record
}

fn retention_terminal_entry(
    profile: &AuditProfile,
    expected: &ExpectedRegistryIdentity,
    scope: ProposalDetailErasureScope<'_>,
    erasure: ProposalDetailErasure,
    correlation: RequestCorrelation,
) -> Result<AuditEntry> {
    let record_reference = retention_record_reference(profile, expected, &scope)?;
    let count = erasure
        .proposal_snapshots
        .checked_add(erasure.target_snapshots)
        .and_then(|count| count.checked_add(erasure.review_submission_requests))
        .and_then(|count| count.checked_add(erasure.review_accepted_bindings))
        .and_then(|count| count.checked_add(erasure.review_result_payloads))
        .and_then(|count| count.checked_add(erasure.application_reasons))
        .and_then(|count| count.checked_add(erasure.idempotency_results))
        .and_then(|count| count.checked_add(erasure.draft_inputs))
        .and_then(|count| count.checked_add(erasure.attachment_references))
        .ok_or(ProposalRetentionError::Unavailable)?;
    terminal_entry(
        profile,
        TerminalAudit {
            grant: None,
            outcome: TerminalAuditOutcome::Committed,
            method: HttpMethod::Delete,
            operation_id: RETENTION_OPERATION_ID.to_owned(),
            entity_id: None,
            action_id: Some(scope.action_id.to_owned()),
            package_revision: expected.activation_id.clone(),
            selected_access_profile: "operator".to_owned(),
            purpose_present: false,
            principal_reference: None,
            record_reference: Some(record_reference),
            record_revision: Some(scope.submission_version),
            result_count: Some(
                usize::try_from(count).map_err(|_| ProposalRetentionError::Unavailable)?,
            ),
            field_set_reference: Some(RETENTION_REFERENCE.to_owned()),
            correlation,
        },
    )
    .map_err(|_| ProposalRetentionError::Unavailable)
}

async fn set_local_timeout(
    transaction: &tokio_postgres::Transaction<'_>,
    name: &str,
    value: Duration,
) -> Result<()> {
    let milliseconds = value.as_millis();
    if milliseconds == 0 || milliseconds > 3_600_000 {
        return Err(ProposalRetentionError::Unavailable);
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
    current_detail && matches!(state, "draft" | "submitted")
}

fn retention_mode_name(mode: CompiledProposalRetentionMode) -> &'static str {
    match mode {
        CompiledProposalRetentionMode::Retain => "retain",
        CompiledProposalRetentionMode::OperatorErase => "operator-erase",
    }
}

fn parse_retention_cursor(value: &str) -> Result<RetentionCursor> {
    let mut parts = value.split(':');
    let action_id = parts.next().ok_or(ProposalRetentionError::Unavailable)?;
    let proposal_id = parts.next().ok_or(ProposalRetentionError::Unavailable)?;
    let submission_version = parts.next().ok_or(ProposalRetentionError::Unavailable)?;
    if parts.next().is_some() || action_id.is_empty() {
        return Err(ProposalRetentionError::Unavailable);
    }
    Ok(RetentionCursor {
        action_id: action_id.to_owned(),
        proposal_id: Uuid::parse_str(proposal_id)
            .map_err(|_| ProposalRetentionError::Unavailable)?,
        submission_version: submission_version
            .parse::<i64>()
            .ok()
            .filter(|version| *version > 0)
            .ok_or(ProposalRetentionError::Unavailable)?,
    })
}

fn retention_cursor(action_id: &str, proposal_id: Uuid, submission_version: i64) -> String {
    format!("{action_id}:{proposal_id}:{submission_version}")
}

fn count_to_u64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| ProposalRetentionError::Unavailable)
}

async fn proposal_tables_exist(client: &impl GenericClient) -> Result<bool> {
    let row = client
        .query_one(
            "SELECT to_regclass('registry_internal.registry_proposal_state') IS NOT NULL
                AND to_regclass('registry_internal.registry_proposal_submissions') IS NOT NULL",
            &[],
        )
        .await
        .map_err(map_retention_error)?;
    Ok(row.get(0))
}

fn map_retention_error(_error: tokio_postgres::Error) -> ProposalRetentionError {
    ProposalRetentionError::Unavailable
}
