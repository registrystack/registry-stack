// SPDX-License-Identifier: Apache-2.0

//! Operator-opened import authorities.
//!
//! An `import` grant loads new records only while an operator has opened a
//! bounded authority for its entity and profile: create only, under the
//! active package revision, before its expiry, and within its item volume.
//! Only the migration role opens or closes one. The runtime role reads it and
//! advances its three mutable columns inside the transaction that observes or
//! consumes it, so no API caller can open its own window.
//!
//! Every transition leaves one audit record: the transaction that makes it
//! collects the record, and the caller appends it through the process audit
//! writer once that transaction commits. Expiry and supersession by a successor package are recorded by
//! the first transaction that observes them: run creation, a chunk, or any
//! operator command. No transaction admits work under an authority whose
//! expiry has passed or whose package revision is no longer active.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use registry_platform_audit::{AuditEntry, AuditProfile};
use serde::Serialize;
use serde_json::{json, Value};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::contract::Operation;
use crate::history_maintenance::{lock_registry, HistoryMaintenanceError};
use crate::model::CompiledRegistry;
use crate::postgres::{
    verify_catalog_identity_for_catalog, verify_migration_role, ConnectionConfig,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey, SqlIdentifier,
};

/// The window an authority stays open for when the operator names none.
pub const DEFAULT_IMPORT_AUTHORITY_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// The longest window one authority may hold. There is no extension: a
/// longer load opens a second authority, which leaves its own record.
pub const MAX_IMPORT_AUTHORITY_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// The most input digests one authority may pin.
pub const MAX_PINNED_INPUT_DIGESTS: usize = 16;
/// The largest volume one authority may admit, the bound ingestion runs use.
pub const MAX_IMPORT_AUTHORITY_ITEMS: i64 = 9_007_199_254_740_991;
/// The bounded page `list` answers with, newest first.
pub const MAX_LISTED_IMPORT_AUTHORITIES: i64 = 100;

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_OPERATOR_REFERENCE_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 1024;

const AUDIT_SCHEMA: &str = "breg-import-authority-audit/v1";
const AUDIT_OPERATION_ID: &str = "breg.import_authority";
const OPERATOR_REFERENCE_DOMAIN: &str = "breg-import-authority-operator-v1";
const REASON_REFERENCE_DOMAIN: &str = "breg-import-authority-reason-v1";

/// The product-owned authority table and the table privileges the runtime
/// role holds on it. Its column-level `UPDATE` grants are
/// [`RUNTIME_UPDATE_COLUMNS`]. Catalog closure consumes both lists.
pub(crate) const IMPORT_AUTHORITY_TABLES: &[(&str, &[&str])] =
    &[("registry_import_authorities", &["SELECT"])];

/// The only columns the runtime role may change: the committed volume, the
/// terminal status, and the moment it was reached.
pub(crate) const RUNTIME_UPDATE_COLUMNS: &[&str] = &["committed_items", "status", "closed_at"];

/// Row security on the authority table, enabled but not forced, so the
/// owning migration role keeps its maintenance boundary while the runtime
/// role reads every row and advances only an open one. The advance policy
/// lets the runtime record `exhausted`, `expired`, and `superseded`; only
/// the migration role closes an authority, and the runtime role cannot
/// reopen one.
pub(crate) const READ_POLICY: &str = "import_authority_runtime_read";
pub(crate) const ADVANCE_POLICY: &str = "import_authority_runtime_advance";

const AUTHORITY_COLUMNS: &str = "authority_id, entity_id, profile_id, operation, max_items,
    committed_items, input_digests, activation_id, opened_at, expires_at, status,
    closed_at";

/// The lifecycle state of one authority. Only `open` admits work; every other
/// state is terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportAuthorityStatus {
    Open,
    Exhausted,
    Expired,
    Closed,
    Superseded,
}

impl ImportAuthorityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Closed => "closed",
            Self::Superseded => "superseded",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "exhausted" => Some(Self::Exhausted),
            "expired" => Some(Self::Expired),
            "closed" => Some(Self::Closed),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }
}

/// One authority as stored. It carries no operator reference or reason: the
/// row holds only their keyed hashes, and this view omits even those.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportAuthority {
    pub authority_id: Uuid,
    pub entity_id: String,
    pub profile_id: String,
    pub operation: String,
    pub max_items: i64,
    pub committed_items: i64,
    pub input_digests: Vec<String>,
    /// The activation the authority was opened under. A later activation
    /// supersedes it.
    pub activation_id: Uuid,
    pub opened_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: ImportAuthorityStatus,
    pub closed_at: Option<DateTime<Utc>>,
}

/// The closed refusal vocabulary of the authority store. It is value-free:
/// no operator reference, reason, or row value travels with it.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ImportAuthorityError {
    #[error("the import authority request is invalid")]
    InvalidInput,
    #[error("the entity and profile do not name an import grant of the active package")]
    NotImportable,
    #[error("an import authority is already open for this entity")]
    AlreadyOpen,
    #[error("no import authority has this identifier")]
    NotFound,
    #[error("the registry is not ready for import authority maintenance")]
    NotReady,
    #[error("another session held the exclusive migration lock past the lock timeout")]
    MigrationLockHeld,
    /// The package at `package.root` is not the one the runtime file's
    /// `package.expectedDigest` pins. Both digests are package identities,
    /// not secrets, so the refusal names them.
    #[error("{0}")]
    PackagePinMismatch(registry_platform_config::blocks::PackageDigestMismatch),
    #[error("the import authority store is unavailable")]
    Unavailable,
}

/// One operator request to open an authority.
pub struct ImportAuthorityOpenRequest<'a> {
    pub entity_id: &'a str,
    pub profile_id: &'a str,
    pub max_items: i64,
    pub expires_in: Duration,
    pub input_digests: &'a [String],
    pub operator_reference: &'a str,
    pub reason: &'a str,
}

/// One operator request to close an open authority.
pub struct ImportAuthorityCloseRequest<'a> {
    pub authority_id: Uuid,
    pub operator_reference: &'a str,
    pub reason: &'a str,
}

impl ImportAuthorityOpenRequest<'_> {
    /// Check the request's bounds without opening any dependency, so a
    /// caller can refuse a malformed request before it connects.
    pub fn validate(&self) -> Result<(), ImportAuthorityError> {
        validate_open(self)
    }
}

impl ImportAuthorityCloseRequest<'_> {
    /// Check the request's bounds without opening any dependency.
    pub fn validate(&self) -> Result<(), ImportAuthorityError> {
        validate_close(self)
    }
}

/// Creates `registry_internal.registry_import_authorities` with its runtime
/// grants and row-level policies. Idempotent.
pub(crate) async fn install(
    migration: &impl tokio_postgres::GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), ImportAuthorityError> {
    let runtime_revoke = crate::postgres::RuntimeRevoke::detect(migration, runtime_role)
        .await
        .map_err(|_| ImportAuthorityError::Unavailable)?;
    migration
        .batch_execute(&format!(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_import_authorities (
                 authority_id uuid PRIMARY KEY,
                 entity_id text NOT NULL
                     CHECK (entity_id <> '' AND octet_length(entity_id) <= {MAX_IDENTIFIER_BYTES}),
                 profile_id text NOT NULL
                     CHECK (profile_id <> '' AND octet_length(profile_id) <= {MAX_IDENTIFIER_BYTES}),
                 operation text NOT NULL
                     CONSTRAINT registry_import_authorities_operation_values
                     CHECK (operation = 'create'),
                 max_items bigint NOT NULL
                     CHECK (max_items BETWEEN 1 AND {MAX_IMPORT_AUTHORITY_ITEMS}),
                 committed_items bigint NOT NULL DEFAULT 0,
                 input_digests text[] NOT NULL DEFAULT '{{}}',
                 activation_id uuid NOT NULL,
                 opened_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 expires_at timestamptz NOT NULL,
                 status text NOT NULL DEFAULT 'open'
                     CONSTRAINT registry_import_authorities_status_values
                     CHECK (status IN ('open', 'exhausted', 'expired', 'closed', 'superseded')),
                 closed_at timestamptz,
                 operator_reference text NOT NULL CHECK (operator_reference <> ''),
                 reason_reference text NOT NULL CHECK (reason_reference <> ''),
                 CONSTRAINT registry_import_authorities_volume CHECK (
                     committed_items >= 0 AND committed_items <= max_items
                     AND (status <> 'exhausted' OR committed_items = max_items)
                 ),
                 CONSTRAINT registry_import_authorities_window CHECK (
                     expires_at > opened_at
                     AND expires_at <= opened_at + interval '{window_days} days'
                 ),
                 CONSTRAINT registry_import_authorities_closed_shape CHECK (
                     (status = 'open') = (closed_at IS NULL)
                 ),
                 CONSTRAINT registry_import_authorities_digests CHECK (
                     cardinality(input_digests) <= {MAX_PINNED_INPUT_DIGESTS}
                     AND array_position(input_digests, NULL) IS NULL
                     AND (cardinality(input_digests) = 0 OR array_ndims(input_digests) = 1)
                     AND array_to_string(input_digests, ',')
                         ~ '^([0-9a-f]{{64}}(,[0-9a-f]{{64}})*)?$'
                 )
             );
             CREATE UNIQUE INDEX IF NOT EXISTS registry_import_authorities_one_open
                 ON registry_internal.registry_import_authorities (entity_id)
                 WHERE status = 'open';
             REVOKE ALL ON registry_internal.registry_import_authorities FROM PUBLIC;
             {runtime_revoke}
             GRANT SELECT ON registry_internal.registry_import_authorities TO \"{role}\";
             GRANT UPDATE ({columns}) ON registry_internal.registry_import_authorities
                 TO \"{role}\";
             ALTER TABLE registry_internal.registry_import_authorities
                 ENABLE ROW LEVEL SECURITY;
             DROP POLICY IF EXISTS {READ_POLICY}
                 ON registry_internal.registry_import_authorities;
             CREATE POLICY {READ_POLICY} ON registry_internal.registry_import_authorities
                 FOR SELECT TO \"{role}\" USING (true);
             DROP POLICY IF EXISTS {ADVANCE_POLICY}
                 ON registry_internal.registry_import_authorities;
             CREATE POLICY {ADVANCE_POLICY} ON registry_internal.registry_import_authorities
                 FOR UPDATE TO \"{role}\"
                 USING (status = 'open')
                 WITH CHECK (status IN ('open', 'exhausted', 'expired', 'superseded'));",
            window_days = MAX_IMPORT_AUTHORITY_WINDOW.as_secs() / (24 * 60 * 60),
            columns = RUNTIME_UPDATE_COLUMNS.join(", "),
            role = runtime_role.as_str(),
            runtime_revoke = runtime_revoke.revoke_all_on("registry_internal.registry_import_authorities"),
        ))
        .await
        .map_err(|_| ImportAuthorityError::Unavailable)?;
    Ok(())
}

fn parse_row(row: &tokio_postgres::Row) -> Result<ImportAuthority, ImportAuthorityError> {
    let status: String = row.get("status");
    Ok(ImportAuthority {
        authority_id: row.get("authority_id"),
        entity_id: row.get("entity_id"),
        profile_id: row.get("profile_id"),
        operation: row.get("operation"),
        max_items: row.get("max_items"),
        committed_items: row.get("committed_items"),
        input_digests: row.get("input_digests"),
        activation_id: row.get("activation_id"),
        opened_at: row.get("opened_at"),
        expires_at: row.get("expires_at"),
        status: ImportAuthorityStatus::parse(&status).ok_or(ImportAuthorityError::Unavailable)?,
        closed_at: row.get("closed_at"),
    })
}

/// The operator references a transition carries in its audit record, as
/// keyed hashes. Runtime-observed transitions carry none.
struct OperatorReferences {
    operator_reference: String,
    reason_reference: String,
}

fn operator_references(
    profile: &AuditProfile,
    package_revision: &str,
    operator_reference: &str,
    reason: &str,
) -> Result<OperatorReferences, ImportAuthorityError> {
    if !crate::audit::profile_is_keyed(profile) {
        return Err(ImportAuthorityError::InvalidInput);
    }
    let hasher = profile.key_hasher();
    Ok(OperatorReferences {
        operator_reference: hasher
            .audit_reference_hash(
                OPERATOR_REFERENCE_DOMAIN,
                package_revision,
                operator_reference,
            )
            .map_err(|_| ImportAuthorityError::InvalidInput)?,
        reason_reference: hasher
            .audit_reference_hash(REASON_REFERENCE_DOMAIN, package_revision, reason)
            .map_err(|_| ImportAuthorityError::InvalidInput)?,
    })
}

fn audit_record(
    transition: ImportAuthorityStatus,
    authority: &ImportAuthority,
    package_revision: &str,
    references: Option<&OperatorReferences>,
) -> Value {
    let mut record = json!({
        "transition": match transition {
            ImportAuthorityStatus::Open => "opened",
            other => other.as_str(),
        },
        "operationId": AUDIT_OPERATION_ID,
        "packageRevision": package_revision,
        "authorityId": authority.authority_id.to_string(),
        "entityId": authority.entity_id,
        "profileId": authority.profile_id,
        "operation": authority.operation,
        "activationId": authority.activation_id.to_string(),
        "maxItems": authority.max_items,
        "committedItems": authority.committed_items,
        "openedAt": authority.opened_at.to_rfc3339(),
        "expiresAt": authority.expires_at.to_rfc3339(),
        "inputDigests": authority.input_digests,
    });
    if let Some(references) = references {
        record["operatorReference"] = json!(references.operator_reference);
        record["reasonReference"] = json!(references.reason_reference);
    }
    record
}

/// Append the transition records a committed transaction collected, oldest
/// first, as `response` entries correlated by their authority id. A caller
/// appends only after the commit that made the transitions, and releases
/// nothing until every append is accepted.
pub(crate) async fn append_transitions(
    audit: &crate::audit::RegistryAudit,
    records: Vec<Value>,
) -> Result<(), ImportAuthorityError> {
    for record in records {
        let correlation = record
            .get("authorityId")
            .and_then(Value::as_str)
            .ok_or(ImportAuthorityError::Unavailable)?
            .to_owned();
        audit
            .append(AuditEntry::response(AUDIT_SCHEMA, correlation, record))
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
    }
    Ok(())
}

/// Move one open authority to a terminal status and collect its transition
/// record into `pending`. A row that is no longer open is returned unchanged
/// with no record.
async fn transition(
    transaction: &Transaction<'_>,
    pending: &mut Vec<Value>,
    authority_id: Uuid,
    to: ImportAuthorityStatus,
    package_revision: &str,
    references: Option<&OperatorReferences>,
) -> Result<Option<ImportAuthority>, ImportAuthorityError> {
    let row = transaction
        .query_opt(
            &format!(
                "UPDATE registry_internal.registry_import_authorities
                    SET status = $2, closed_at = transaction_timestamp()
                  WHERE authority_id = $1 AND status = 'open'
                  RETURNING {AUTHORITY_COLUMNS}"
            ),
            &[&authority_id, &to.as_str()],
        )
        .await
        .map_err(|_| ImportAuthorityError::Unavailable)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let authority = parse_row(&row)?;
    pending.push(audit_record(to, &authority, package_revision, references));
    Ok(Some(authority))
}

/// The terminal status a still-open authority has already reached, if any:
/// a successor package supersedes it, and a passed expiry expires it.
/// Supersession wins, because a model change retires the grant it named.
fn due_transition(
    authority: &ImportAuthority,
    package_revision: &str,
    now: DateTime<Utc>,
) -> Option<ImportAuthorityStatus> {
    if authority.status != ImportAuthorityStatus::Open {
        return None;
    }
    // An activation id that does not parse names no activation this
    // authority was opened under, so it retires the authority.
    if !Uuid::parse_str(package_revision).is_ok_and(|id| id == authority.activation_id) {
        return Some(ImportAuthorityStatus::Superseded);
    }
    if authority.expires_at <= now {
        return Some(ImportAuthorityStatus::Expired);
    }
    None
}

async fn transaction_now(
    transaction: &Transaction<'_>,
) -> Result<DateTime<Utc>, ImportAuthorityError> {
    Ok(transaction
        .query_one("SELECT transaction_timestamp()", &[])
        .await
        .map_err(|_| ImportAuthorityError::Unavailable)?
        .get(0))
}

/// Lock the open authority rows the filter selects, collect every transition
/// already due, and answer the rows that stay open.
async fn settle_open(
    transaction: &Transaction<'_>,
    pending: &mut Vec<Value>,
    package_revision: &str,
    entity_id: Option<&str>,
) -> Result<(Vec<ImportAuthority>, Vec<ImportAuthority>), ImportAuthorityError> {
    let rows = transaction
        .query(
            &format!(
                "SELECT {AUTHORITY_COLUMNS}
                   FROM registry_internal.registry_import_authorities
                  WHERE status = 'open' AND ($1::text IS NULL OR entity_id = $1)
                  ORDER BY authority_id
                  FOR UPDATE"
            ),
            &[&entity_id],
        )
        .await
        .map_err(|_| ImportAuthorityError::Unavailable)?;
    let now = transaction_now(transaction).await?;
    let mut open = Vec::new();
    let mut transitioned = Vec::new();
    for row in &rows {
        let authority = parse_row(row)?;
        match due_transition(&authority, package_revision, now) {
            None => open.push(authority),
            Some(to) => {
                if let Some(done) = transition(
                    transaction,
                    pending,
                    authority.authority_id,
                    to,
                    package_revision,
                    None,
                )
                .await?
                {
                    transitioned.push(done);
                }
            }
        }
    }
    Ok((open, transitioned))
}

/// Supersede every open authority inside the caller's transaction, which
/// holds the registry lock, collecting one transition record for each into
/// `pending` for the caller to append once it commits, and answer the
/// authorities it moved. Every successful activation calls this, and so does
/// adopting a restored copy, so an authority the copy carries from its
/// backup, even one an operator closed after the backup was taken, admits no
/// work until an operator opens a new one.
pub(crate) async fn supersede_every_open(
    transaction: &Transaction<'_>,
    pending: &mut Vec<Value>,
    package_revision: &str,
) -> Result<Vec<Uuid>, ImportAuthorityError> {
    let rows = transaction
        .query(
            "SELECT authority_id
               FROM registry_internal.registry_import_authorities
              WHERE status = 'open'
              ORDER BY authority_id
              FOR UPDATE",
            &[],
        )
        .await
        .map_err(|_| ImportAuthorityError::Unavailable)?;
    let mut superseded = Vec::with_capacity(rows.len());
    for row in &rows {
        let authority_id: Uuid = row.get(0);
        transition(
            transaction,
            pending,
            authority_id,
            ImportAuthorityStatus::Superseded,
            package_revision,
            None,
        )
        .await?
        .ok_or(ImportAuthorityError::Unavailable)?;
        superseded.push(authority_id);
    }
    Ok(superseded)
}

/// Decide whether one import run may be created, inside the run-creation
/// transaction. Every transition already due is collected into `pending`
/// first, so the caller must commit this transaction and append those
/// records even when it refuses the run.
/// Answers the admitting authority, or `None` when no open authority names
/// this entity and profile, admits the run's whole volume, and pins its input.
pub(crate) async fn admit_run(
    transaction: &Transaction<'_>,
    pending: &mut Vec<Value>,
    package_revision: &str,
    entity_id: &str,
    profile_id: &str,
    item_count: i64,
    input_digest: &str,
) -> Result<Option<Uuid>, ImportAuthorityError> {
    let (open, _) = settle_open(transaction, pending, package_revision, Some(entity_id)).await?;
    Ok(open
        .into_iter()
        .find(|authority| {
            authority.profile_id == profile_id
                && authority.operation == "create"
                && item_count <= authority.max_items - authority.committed_items
                && (authority.input_digests.is_empty()
                    || authority
                        .input_digests
                        .iter()
                        .any(|digest| digest == input_digest))
        })
        .map(|authority| authority.authority_id))
}

/// Decide whether one chunk of an import run may commit, inside the chunk
/// transaction and under the run row lock. The authority row is locked
/// `FOR UPDATE` so a close waits for an in-flight chunk and the next chunk
/// sees it. A transition already due is collected into `pending` first, so
/// the caller must commit this transaction and append that record even when
/// it refuses the chunk. Answers whether
/// the authority is still open and has room for `chunk_items`.
///
/// The runtime role's row security admits only open rows to a locking read,
/// so a terminal authority reads as absent, which refuses the chunk exactly
/// as a closed one does.
pub(crate) async fn admit_chunk(
    transaction: &Transaction<'_>,
    pending: &mut Vec<Value>,
    package_revision: &str,
    authority_id: Uuid,
    chunk_items: i64,
) -> Result<bool, ImportAuthorityError> {
    let Some(row) = transaction
        .query_opt(
            &format!(
                "SELECT {AUTHORITY_COLUMNS}
                   FROM registry_internal.registry_import_authorities
                  WHERE authority_id = $1 AND status = 'open'
                  FOR UPDATE"
            ),
            &[&authority_id],
        )
        .await
        .map_err(|_| ImportAuthorityError::Unavailable)?
    else {
        return Ok(false);
    };
    let authority = parse_row(&row)?;
    let now = transaction_now(transaction).await?;
    if let Some(to) = due_transition(&authority, package_revision, now) {
        transition(
            transaction,
            pending,
            authority_id,
            to,
            package_revision,
            None,
        )
        .await?;
        return Ok(false);
    }
    Ok(chunk_items <= authority.max_items - authority.committed_items)
}

/// Count one committed chunk against its authority, in the chunk commit
/// transaction. The authority reaching its volume moves to `exhausted` and
/// collects that transition record into `pending`. The caller has
/// already admitted the chunk under the same row lock, so an authority that
/// no longer counts it is corruption and refuses the commit.
pub(crate) async fn consume(
    transaction: &Transaction<'_>,
    pending: &mut Vec<Value>,
    package_revision: &str,
    authority_id: Uuid,
    chunk_items: i64,
) -> Result<(), ImportAuthorityError> {
    let row = transaction
        .query_opt(
            &format!(
                "UPDATE registry_internal.registry_import_authorities
                    SET committed_items = committed_items + $2,
                        status = CASE WHEN committed_items + $2 = max_items
                                      THEN 'exhausted' ELSE 'open' END,
                        closed_at = CASE WHEN committed_items + $2 = max_items
                                         THEN transaction_timestamp() END
                  WHERE authority_id = $1 AND status = 'open'
                    AND committed_items + $2 <= max_items
                  RETURNING {AUTHORITY_COLUMNS}"
            ),
            &[&authority_id, &chunk_items],
        )
        .await
        .map_err(|_| ImportAuthorityError::Unavailable)?
        .ok_or(ImportAuthorityError::Unavailable)?;
    let authority = parse_row(&row)?;
    if authority.status == ImportAuthorityStatus::Exhausted {
        pending.push(audit_record(
            ImportAuthorityStatus::Exhausted,
            &authority,
            package_revision,
            None,
        ));
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn validate_open(request: &ImportAuthorityOpenRequest<'_>) -> Result<(), ImportAuthorityError> {
    let mut digests = request.input_digests.to_vec();
    digests.sort();
    digests.dedup();
    if !bounded_text(request.entity_id, MAX_IDENTIFIER_BYTES)
        || !bounded_text(request.profile_id, MAX_IDENTIFIER_BYTES)
        || !(1..=MAX_IMPORT_AUTHORITY_ITEMS).contains(&request.max_items)
        || request.expires_in < Duration::from_secs(1)
        || request.expires_in > MAX_IMPORT_AUTHORITY_WINDOW
        || request.input_digests.len() > MAX_PINNED_INPUT_DIGESTS
        || digests.len() != request.input_digests.len()
        || !request.input_digests.iter().all(|digest| is_digest(digest))
        || !bounded_text(request.operator_reference, MAX_OPERATOR_REFERENCE_BYTES)
        || !bounded_text(request.reason, MAX_REASON_BYTES)
    {
        return Err(ImportAuthorityError::InvalidInput);
    }
    Ok(())
}

fn validate_close(request: &ImportAuthorityCloseRequest<'_>) -> Result<(), ImportAuthorityError> {
    if !bounded_text(request.operator_reference, MAX_OPERATOR_REFERENCE_BYTES)
        || !bounded_text(request.reason, MAX_REASON_BYTES)
    {
        return Err(ImportAuthorityError::InvalidInput);
    }
    Ok(())
}

/// Whether the entity and profile name an `import` grant of this package.
fn names_import_grant(registry: &CompiledRegistry, entity_id: &str, profile_id: &str) -> bool {
    crate::data::ingestion_route(registry, entity_id, profile_id)
        .is_some_and(|route| route.operation == Operation::Import)
}

/// The migration-role service that opens, closes, settles, and lists import
/// authorities. Each command verifies the migration identity, the active
/// package binding, and the managed catalog in the same transaction that
/// changes an authority, under the registry's exclusive interlock, so a
/// close serializes with every in-flight chunk.
pub struct ImportAuthorityOperatorService {
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    lock_key: RegistryLockKey,
    migration_connection: ConnectionConfig,
    migration_role: SqlIdentifier,
    runtime_role: SqlIdentifier,
    lock_timeout: Duration,
    statement_timeout: Duration,
    audit: crate::audit::RegistryAudit,
    registry: Arc<CompiledRegistry>,
}

impl ImportAuthorityOperatorService {
    #[cfg(any(
        feature = "postgres-test",
        all(feature = "runtime", feature = "tooling")
    ))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_for_schema_test(
        expected: ExpectedRegistryIdentity,
        expected_catalog: ExpectedManagedCatalog,
        lock_key: RegistryLockKey,
        migration_connection: ConnectionConfig,
        migration_role: SqlIdentifier,
        runtime_role: SqlIdentifier,
        audit: crate::audit::RegistryAudit,
        registry: Arc<CompiledRegistry>,
    ) -> Self {
        Self {
            expected,
            expected_catalog,
            lock_key,
            migration_connection,
            migration_role,
            runtime_role,
            lock_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(10),
            audit,
            registry,
        }
    }

    pub async fn from_runtime_config(path: &Path) -> Result<Self, ImportAuthorityError> {
        if !path.is_absolute() {
            return Err(ImportAuthorityError::InvalidInput);
        }
        let config = crate::runtime_config::load_runtime_config(path)
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        let package = config.load_active_package().map_err(|error| match error {
            crate::package::PackageError::ExpectedDigestMismatch(mismatch) => {
                ImportAuthorityError::PackagePinMismatch(mismatch)
            }
            _ => ImportAuthorityError::Unavailable,
        })?;
        let audit = crate::audit::RegistryAudit::open_companion(&config)
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        if !crate::audit::profile_is_keyed(audit.profile()) {
            return Err(ImportAuthorityError::Unavailable);
        }
        let pool = config
            .runtime_database_connection_config()
            .map_err(|_| ImportAuthorityError::Unavailable)?
            .build_pool()
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        let startup = crate::startup::prepare_loaded_startup(
            package,
            config.identity().database_id(),
            &mut client,
            config.database().roles().migration(),
            config.database().roles().runtime(),
        )
        .await
        .map_err(|_| ImportAuthorityError::Unavailable)?;
        Ok(Self {
            expected: startup.expected_identity().clone(),
            expected_catalog: startup.expected_catalog().clone(),
            lock_key: startup.lock_key(),
            migration_connection: config
                .migration_database_connection_config()
                .map_err(|_| ImportAuthorityError::Unavailable)?,
            migration_role: config.database().roles().migration().clone(),
            runtime_role: config.database().roles().runtime().clone(),
            lock_timeout: config.operational_timeouts().migration_lock,
            statement_timeout: config.operational_timeouts().migration_statement,
            audit,
            registry: Arc::new(startup.package().registry().clone()),
        })
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_test(
        expected: ExpectedRegistryIdentity,
        expected_catalog: ExpectedManagedCatalog,
        lock_key: RegistryLockKey,
        migration_connection: ConnectionConfig,
        migration_role: SqlIdentifier,
        runtime_role: SqlIdentifier,
        audit: crate::audit::RegistryAudit,
        registry: Arc<CompiledRegistry>,
    ) -> Self {
        Self::new_for_schema_test(
            expected,
            expected_catalog,
            lock_key,
            migration_connection,
            migration_role,
            runtime_role,
            audit,
            registry,
        )
    }

    /// Open one authority for an `import` grant of the active package. Any
    /// transition already due on the entity's open authority is recorded
    /// first; a still-open one refuses the request by name.
    pub async fn open(
        &self,
        request: ImportAuthorityOpenRequest<'_>,
    ) -> Result<ImportAuthority, ImportAuthorityError> {
        validate_open(&request)?;
        if !names_import_grant(&self.registry, request.entity_id, request.profile_id) {
            return Err(ImportAuthorityError::NotImportable);
        }
        let package_revision = &self.expected.activation_id;
        let references = operator_references(
            self.audit.profile(),
            package_revision,
            request.operator_reference,
            request.reason,
        )?;
        let mut digests = request.input_digests.to_vec();
        digests.sort();
        let expires_in = i64::try_from(request.expires_in.as_secs())
            .map_err(|_| ImportAuthorityError::InvalidInput)?;
        let pool = self.pool()?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        let transaction = self.begin(&mut client).await?;
        let mut pending = Vec::new();
        let (open, _) = settle_open(
            &transaction,
            &mut pending,
            package_revision,
            Some(request.entity_id),
        )
        .await?;
        if !open.is_empty() {
            // At most one authority is open per entity, so nothing settled
            // here: the refusal rolls back an empty transaction.
            return Err(ImportAuthorityError::AlreadyOpen);
        }
        let row = transaction
            .query_one(
                &format!(
                    "INSERT INTO registry_internal.registry_import_authorities
                         (authority_id, entity_id, profile_id, operation, max_items,
                          input_digests, activation_id, expires_at,
                          operator_reference, reason_reference)
                     VALUES ($1, $2, $3, 'create', $4, $5, $6::text::uuid,
                             transaction_timestamp() + make_interval(secs => $7::bigint),
                             $8, $9)
                     RETURNING {AUTHORITY_COLUMNS}"
                ),
                &[
                    &Uuid::new_v4(),
                    &request.entity_id,
                    &request.profile_id,
                    &request.max_items,
                    &digests,
                    package_revision,
                    &expires_in,
                    &references.operator_reference,
                    &references.reason_reference,
                ],
            )
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        let authority = parse_row(&row)?;
        pending.push(audit_record(
            ImportAuthorityStatus::Open,
            &authority,
            package_revision,
            Some(&references),
        ));
        self.commit(transaction, pending, authority).await
    }

    /// Close one authority. An authority that already reached a terminal
    /// status is answered as it stands with no second record. One whose
    /// expiry or supersession is already due records that transition, not a
    /// close, because it stopped admitting work before this command ran.
    pub async fn close(
        &self,
        request: ImportAuthorityCloseRequest<'_>,
    ) -> Result<ImportAuthority, ImportAuthorityError> {
        validate_close(&request)?;
        let package_revision = &self.expected.activation_id;
        let references = operator_references(
            self.audit.profile(),
            package_revision,
            request.operator_reference,
            request.reason,
        )?;
        let pool = self.pool()?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        let transaction = self.begin(&mut client).await?;
        let row = transaction
            .query_opt(
                &format!(
                    "SELECT {AUTHORITY_COLUMNS}
                       FROM registry_internal.registry_import_authorities
                      WHERE authority_id = $1
                      FOR UPDATE"
                ),
                &[&request.authority_id],
            )
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?
            .ok_or(ImportAuthorityError::NotFound)?;
        let authority = parse_row(&row)?;
        if authority.status != ImportAuthorityStatus::Open {
            return Ok(authority);
        }
        let now = transaction_now(&transaction).await?;
        let to = due_transition(&authority, package_revision, now)
            .unwrap_or(ImportAuthorityStatus::Closed);
        let recorded = (to == ImportAuthorityStatus::Closed).then_some(&references);
        let mut pending = Vec::new();
        let closed = transition(
            &transaction,
            &mut pending,
            authority.authority_id,
            to,
            package_revision,
            recorded,
        )
        .await?
        .ok_or(ImportAuthorityError::Unavailable)?;
        self.commit(transaction, pending, closed).await
    }

    /// Record every expiry and supersession already due, and answer the
    /// authorities this command moved.
    pub async fn close_expired(&self) -> Result<Vec<ImportAuthority>, ImportAuthorityError> {
        let pool = self.pool()?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        let transaction = self.begin(&mut client).await?;
        let mut pending = Vec::new();
        let (_, transitioned) = settle_open(
            &transaction,
            &mut pending,
            &self.expected.activation_id,
            None,
        )
        .await?;
        self.commit(transaction, pending, transitioned).await
    }

    /// Answer the newest authorities, bounded, in a read-only transaction.
    /// It takes no registry lock and needs no ready maintenance state, so it
    /// neither waits for a write nor holds one back, and it still answers
    /// while an apply is interrupted. It records nothing: an open authority
    /// whose expiry has passed, or whose package revision is no longer
    /// active, is listed with the status it has reached, and the next run,
    /// chunk, or `close_expired` records that transition.
    pub async fn list(&self) -> Result<Vec<ImportAuthority>, ImportAuthorityError> {
        let pool = self.pool()?;
        let mut pooled = pool
            .get()
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        let client: &mut tokio_postgres::Client = &mut pooled;
        verify_migration_role(client, &self.migration_role)
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .read_only(true)
            .start()
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        self.set_timeouts(&transaction).await?;
        verify_catalog_identity_for_catalog(
            &transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await
        .map_err(|_| ImportAuthorityError::Unavailable)?;
        let rows = transaction
            .query(
                &format!(
                    "SELECT {AUTHORITY_COLUMNS}
                       FROM registry_internal.registry_import_authorities
                      ORDER BY opened_at DESC, authority_id
                      LIMIT {MAX_LISTED_IMPORT_AUTHORITIES}"
                ),
                &[],
            )
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        let now = transaction_now(&transaction).await?;
        let listed = rows
            .iter()
            .map(|row| {
                let mut authority = parse_row(row)?;
                if let Some(reached) = due_transition(&authority, &self.expected.activation_id, now)
                {
                    authority.status = reached;
                }
                Ok(authority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.commit(transaction, Vec::new(), listed).await
    }

    /// Open one verified maintenance transaction on a fresh migration
    /// connection: the migration role, bounded timeouts, the exclusive
    /// registry interlock, the active package and catalog, and a ready
    /// maintenance state. The caller does its work and commits.
    async fn begin<'c>(
        &self,
        client: &'c mut tokio_postgres::Client,
    ) -> Result<Transaction<'c>, ImportAuthorityError> {
        verify_migration_role(client, &self.migration_role)
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        self.set_timeouts(&transaction).await?;
        lock_registry(&transaction, self.lock_key)
            .await
            .map_err(|error| match error {
                HistoryMaintenanceError::MigrationLockHeld => {
                    ImportAuthorityError::MigrationLockHeld
                }
                _ => ImportAuthorityError::Unavailable,
            })?;
        verify_catalog_identity_for_catalog(
            &transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await
        .map_err(|_| ImportAuthorityError::Unavailable)?;
        let ready: bool = transaction
            .query_one(
                "SELECT maintenance_status = 'ready'
                   FROM registry_internal.registry_state WHERE singleton",
                &[],
            )
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?
            .get(0);
        if !ready {
            return Err(ImportAuthorityError::NotReady);
        }
        Ok(transaction)
    }

    async fn set_timeouts(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<(), ImportAuthorityError> {
        transaction
            .query_one(
                "SELECT set_config('lock_timeout', $1, true),
                        set_config('statement_timeout', $2, true)",
                &[
                    &format!("{}ms", self.lock_timeout.as_millis()),
                    &format!("{}ms", self.statement_timeout.as_millis()),
                ],
            )
            .await
            .map(drop)
            .map_err(|_| ImportAuthorityError::Unavailable)
    }

    fn pool(&self) -> Result<crate::postgres::RuntimePool, ImportAuthorityError> {
        self.migration_connection
            .build_pool()
            .map_err(|_| ImportAuthorityError::Unavailable)
    }

    /// Commit the command's transaction, then append the transition records
    /// it collected before answering. A refused append answers the command
    /// unavailable although its transitions stand.
    async fn commit<T>(
        &self,
        transaction: Transaction<'_>,
        pending: Vec<Value>,
        value: T,
    ) -> Result<T, ImportAuthorityError> {
        transaction
            .commit()
            .await
            .map_err(|_| ImportAuthorityError::Unavailable)?;
        append_transitions(&self.audit, pending).await?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_request<'a>(digests: &'a [String]) -> ImportAuthorityOpenRequest<'a> {
        ImportAuthorityOpenRequest {
            entity_id: "enrollment",
            profile_id: "loader",
            max_items: 10,
            expires_in: DEFAULT_IMPORT_AUTHORITY_WINDOW,
            input_digests: digests,
            operator_reference: "operator-a",
            reason: "initial enrollment load",
        }
    }

    #[test]
    fn open_requests_are_bounded_before_any_database_work() {
        let none: Vec<String> = Vec::new();
        assert!(validate_open(&open_request(&none)).is_ok());
        let pinned = vec!["a".repeat(64)];
        assert!(validate_open(&open_request(&pinned)).is_ok());

        let mut request = open_request(&none);
        request.max_items = 0;
        assert_eq!(
            validate_open(&request),
            Err(ImportAuthorityError::InvalidInput)
        );
        request.max_items = MAX_IMPORT_AUTHORITY_ITEMS + 1;
        assert!(validate_open(&request).is_err());

        let mut request = open_request(&none);
        request.expires_in = MAX_IMPORT_AUTHORITY_WINDOW + Duration::from_secs(1);
        assert!(validate_open(&request).is_err(), "no window above 30 days");
        request.expires_in = Duration::ZERO;
        assert!(validate_open(&request).is_err());

        let too_many = vec!["b".repeat(64); MAX_PINNED_INPUT_DIGESTS + 1];
        assert!(validate_open(&open_request(&too_many)).is_err());
        let duplicated = vec!["c".repeat(64), "c".repeat(64)];
        assert!(validate_open(&open_request(&duplicated)).is_err());
        let uppercase = vec!["C".repeat(64)];
        assert!(validate_open(&open_request(&uppercase)).is_err());
        let short = vec!["c".repeat(63)];
        assert!(validate_open(&open_request(&short)).is_err());

        let mut request = open_request(&none);
        request.reason = "line\nbreak";
        assert!(validate_open(&request).is_err());
        request.reason = "";
        assert!(validate_open(&request).is_err());
        let mut request = open_request(&none);
        let long = "o".repeat(MAX_OPERATOR_REFERENCE_BYTES + 1);
        request.operator_reference = &long;
        assert!(validate_open(&request).is_err());
    }

    #[test]
    fn supersession_wins_over_expiry_and_only_open_rows_move() {
        let now = Utc::now();
        let first = Uuid::from_u128(1);
        let first_revision = first.to_string();
        let second_revision = Uuid::from_u128(2).to_string();
        let mut authority = ImportAuthority {
            authority_id: Uuid::nil(),
            entity_id: "enrollment".to_owned(),
            profile_id: "loader".to_owned(),
            operation: "create".to_owned(),
            max_items: 1,
            committed_items: 0,
            input_digests: Vec::new(),
            activation_id: first,
            opened_at: now - chrono::Duration::days(2),
            expires_at: now - chrono::Duration::days(1),
            status: ImportAuthorityStatus::Open,
            closed_at: None,
        };
        assert_eq!(
            due_transition(&authority, &second_revision, now),
            Some(ImportAuthorityStatus::Superseded)
        );
        assert_eq!(
            due_transition(&authority, &first_revision, now),
            Some(ImportAuthorityStatus::Expired)
        );
        authority.expires_at = now + chrono::Duration::days(1);
        assert_eq!(due_transition(&authority, &first_revision, now), None);
        assert_eq!(
            due_transition(&authority, "not-an-activation-id", now),
            Some(ImportAuthorityStatus::Superseded),
            "an activation id that does not parse retires the authority"
        );
        authority.status = ImportAuthorityStatus::Closed;
        assert_eq!(due_transition(&authority, &second_revision, now), None);
    }
}
