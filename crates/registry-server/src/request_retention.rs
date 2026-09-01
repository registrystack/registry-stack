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
    pub idempotency_results: u64,
    pub request_revision_snapshots: u64,
    pub outbox_payloads: u64,
    pub current_intake_rows: u64,
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
}

/// Package-bound operator boundary used by `registry-serverctl`.
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
        Ok(Self {
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
                        system_origin: "registry-server-request-retention-erasure-v1",
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
        Ok(RequestRetentionErase {
            request_entity_id: scope.request_entity_id.to_owned(),
            request_id: scope.request_id.to_string(),
            proposal_version: scope.proposal_version,
            request_state: plan.current_state,
            retention_mode: retention_mode_name(plan.retention_mode),
            erasure,
        })
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

/// Load retained proposal history without materializing erased or live payload
/// copies. Target identifiers are withheld until the caller can prove exact
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
            "SELECT s.state, s.proposal_version, p.proposal_version,
                    p.contract_fingerprint, p.effect_digest, p.erased_at IS NOT NULL,
                    a.application_id
               FROM registry_internal.registry_request_state s
               JOIN registry_internal.registry_request_proposals p
                 ON p.request_entity_id = s.request_entity_id
                AND p.request_id = s.request_id
               LEFT JOIN registry_internal.registry_request_applications a
                 ON a.request_entity_id = p.request_entity_id
                AND a.request_id = p.request_id
                AND a.proposal_version = p.proposal_version
              WHERE s.request_entity_id = $1
                AND s.request_id = $2
                AND ($3::bigint IS NULL OR p.proposal_version > $3::bigint)
              ORDER BY p.proposal_version
              LIMIT $4::bigint",
            &[
                &query.request_entity_id,
                &query.request_id,
                &query.after_proposal_version,
                &page_limit,
            ],
        )
        .await
        .map_err(map_retention_error)?;
    let mut history = Vec::with_capacity(rows.len().min(usize::from(query.limit)));
    let mut next_after_proposal_version = None;
    for (index, row) in rows.into_iter().enumerate() {
        let proposal_version = row.get::<_, i64>(2);
        if index >= usize::from(query.limit) {
            next_after_proposal_version = Some(proposal_version);
            break;
        }
        history.push(RetainedRequestProposal {
            request_entity_id: query.request_entity_id.to_owned(),
            request_id: query.request_id.to_string(),
            proposal_version,
            request_state: row.get(0),
            current: row.get::<_, i64>(1) == proposal_version,
            contract_fingerprint: row.get(3),
            effect_digest: row.get(4),
            detail_erased: row.get(5),
            application_id: row.get::<_, Option<Uuid>>(6).map(|id| id.to_string()),
            result_link_count: 0,
            result_links: Vec::new(),
        });
    }
    Ok(RetainedRequestHistoryPage {
        proposals: history,
        next_after_proposal_version,
    })
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
    if !proposal_exists
        && !(current_detail && current_state == "canceled")
        && !inspectable_pinned_current_detail
    {
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
                    AND o.payload IS NOT NULL)",
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
        current_intake_rows: u64::from(erase_current_intake),
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
    let current_intake_rows = u64::from(current_revision.is_some());
    let erasure = RequestDetailErasure {
        proposal_snapshots,
        target_snapshots,
        idempotency_results,
        request_revision_snapshots,
        outbox_payloads,
        current_intake_rows,
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
            "registry-server-record-v1",
            &expected.package_revision,
            &scope.request_id.to_string(),
        )
        .map_err(|_| RequestRetentionError::Unavailable)?;
    let count = erasure
        .proposal_snapshots
        .checked_add(erasure.target_snapshots)
        .and_then(|count| count.checked_add(erasure.idempotency_results))
        .and_then(|count| count.checked_add(erasure.request_revision_snapshots))
        .and_then(|count| count.checked_add(erasure.outbox_payloads))
        .and_then(|count| count.checked_add(erasure.current_intake_rows))
        .ok_or(RequestRetentionError::Unavailable)?;
    append_terminal_audit(
        transaction,
        profile,
        TerminalAudit {
            outcome: TerminalAuditOutcome::Committed,
            method: HttpMethod::Delete,
            operation_id: RETENTION_OPERATION_ID.to_owned(),
            entity_id: scope.request_entity_id.to_owned(),
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
            correlation: RequestCorrelation::server_created(),
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
        for grant in &request.presence_grants {
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
