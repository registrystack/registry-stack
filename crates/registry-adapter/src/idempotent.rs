// SPDX-License-Identifier: Apache-2.0

//! The idempotency store behind the `idempotentConsumer` EIP
//! (`products/adapter/CONCEPT.md` section 9).
//!
//! Every route bound to a write operation runs inside
//! `idempotentConsumer` with Camel's `expression`, `eager` (default
//! true), `removeOnFailure` (default true), and `completionEager`
//! (default false) options. The key is namespaced by caller identity and
//! concrete operation, and bound to the request digest: a duplicate
//! replays the recorded facade response instead of being dropped
//! (`skipDuplicate` is not ported), and a duplicate arriving while the
//! first is in flight answers 409. `removeOnFailure` before any
//! upstream effect removes the key; a failure after a non-safe send
//! keeps the key in a failed state and replays the recorded problem, so
//! a sent effect is never re-executed.
//!
//! The store is PostgreSQL, separate from the audit journal, and the one
//! place the adapter retains a response body: the exact facade response,
//! for the key's retention window, then erased by a supervised sweep, as
//! BReg's store does in `crates/registry-breg/src/idempotency.rs`.

use std::fmt;
use std::time::{Duration, SystemTime};

use crate::engine::exchange::MAX_IDEMPOTENCY_KEY_BYTES;
use deadpool_postgres::{GenericClient, Pool, PoolError};
use http::HeaderValue;
use sha2::{Digest, Sha256};
use tokio_postgres::{Error as PgError, Row};

/// Longest accepted verified issuer in bytes.
pub const MAX_CALLER_ISSUER_BYTES: usize = 2_048;
/// Longest accepted verified subject or acting client identifier in bytes.
pub const MAX_CALLER_IDENTITY_BYTES: usize = 512;
/// Longest logical deployment identifier in a key namespace.
pub const MAX_DEPLOYMENT_IDENTITY_BYTES: usize = 256;
/// Longest accepted concrete operation identifier in bytes.
pub const MAX_CONCRETE_OPERATION_BYTES: usize = 256;
/// Longest accepted caller-supplied idempotency key in bytes.
/// Longest exact facade content type retained with a response.
pub const MAX_CONTENT_TYPE_BYTES: usize = 256;
/// Exact lowercase-hex length of an Adapter-generated response request id.
pub const RESPONSE_REQUEST_ID_BYTES: usize = 32;
/// Largest exact facade response body the idempotency store will retain.
///
/// This is the Adapter's v1 per-response ceiling. It matches the largest
/// declared upstream response admitted by the engine and prevents the one
/// body-custody table from becoming unbounded.
pub const MAX_STORED_RESPONSE_BYTES: usize = 1024 * 1024;
/// Longest response-custody horizon accepted by this store API.
pub const MAX_RESPONSE_RETENTION: Duration = Duration::from_secs(365 * 24 * 60 * 60);
/// Largest response-erasure batch one sweep call accepts.
pub const MAX_SWEEP_BATCH: u32 = 1_000;

const MIN_RESPONSE_RETENTION: Duration = Duration::from_secs(1);
const SCOPE_DIGEST_DOMAIN: &[u8] = b"registry-adapter:idempotency-scope:v1\0";

const LOGICAL_DEPLOYMENT_IDENTITY_MIGRATION: i64 = 200;
const RESPONSE_REQUEST_ID_MIGRATION: i64 = 300;
const MIGRATIONS: [(i64, &str); 3] = [
    (
        100,
        include_str!("idempotent/migrations/0100_idempotency_store.sql"),
    ),
    (
        LOGICAL_DEPLOYMENT_IDENTITY_MIGRATION,
        include_str!("idempotent/migrations/0200_logical_deployment_identity.sql"),
    ),
    (
        RESPONSE_REQUEST_ID_MIGRATION,
        include_str!("idempotent/migrations/0300_response_request_id.sql"),
    ),
];
const SUPPORTED_SCHEMA_VERSION: i64 = MIGRATIONS[MIGRATIONS.len() - 1].0;
/// Session advisory-lock key for the idempotency migration. Its bytes spell
/// `adap_idm`, distinct from the audit journal's `adapter_` lock.
const MIGRATION_LOCK_KEY: i64 = 0x6164_6170_5f69_646d;

/// A verified token identity used to namespace an idempotency key.
///
/// Issuer, subject, and acting client id stay in memory. PostgreSQL receives
/// only a domain-separated digest of them with the concrete operation and key.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedCallerIdentity {
    issuer: String,
    subject: String,
    client_id: String,
}

impl VerifiedCallerIdentity {
    /// Construct a bounded verified identity. Callers pass claims only after
    /// the facade has authenticated them; this type does not authenticate.
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Result<Self, IdempotencyError> {
        let issuer = issuer.into();
        let subject = subject.into();
        let client_id = client_id.into();
        validate_component("caller issuer", issuer.as_bytes(), MAX_CALLER_ISSUER_BYTES)?;
        validate_component(
            "caller subject",
            subject.as_bytes(),
            MAX_CALLER_IDENTITY_BYTES,
        )?;
        validate_component(
            "caller client id",
            client_id.as_bytes(),
            MAX_CALLER_IDENTITY_BYTES,
        )?;
        Ok(Self {
            issuer,
            subject,
            client_id,
        })
    }
}

/// One namespaced claim attempt.
pub struct ClaimRequest<'a> {
    /// Authenticated issuer, subject, and acting client id.
    pub caller: &'a VerifiedCallerIdentity,
    /// Stable logical deployment identifier. A database may be shared by
    /// more than one Adapter deployment, whose response custody must not
    /// cross. Artifact revisions belong to `request_digest`, so a changed
    /// revision mismatches rather than opening a fresh effect namespace.
    pub deployment: &'a str,
    /// Concrete facade operation, including its bound record type.
    pub concrete_operation: &'a str,
    /// Caller-supplied `Idempotency-Key` value.
    pub key: &'a str,
    /// Digest of the exact validated facade request bound to this key.
    pub request_digest: [u8; 32],
}

/// Whether a terminal response represents success or a caller-visible
/// failure. Failed responses replay just as exactly as successful responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalOutcome {
    /// The write completed and its successful facade response was recorded.
    Completed,
    /// The write failed and its facade problem response was recorded.
    Failed,
}

impl TerminalOutcome {
    fn stored_state(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// Exact caller-visible facade response held for replay.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredResponse {
    status: u16,
    content_type: Vec<u8>,
    body: Vec<u8>,
    request_id: String,
}

impl StoredResponse {
    /// Validate and take custody of exact response bytes.
    pub fn new(
        status: u16,
        content_type: Vec<u8>,
        body: Vec<u8>,
        request_id: impl Into<String>,
    ) -> Result<Self, IdempotencyError> {
        let request_id = request_id.into();
        if !(100..=599).contains(&status) {
            return Err(IdempotencyError::InvalidInput {
                field: "response status",
            });
        }
        if content_type.is_empty()
            || content_type.len() > MAX_CONTENT_TYPE_BYTES
            || HeaderValue::from_bytes(&content_type).is_err()
        {
            return Err(IdempotencyError::InvalidInput {
                field: "response content type",
            });
        }
        if body.len() > MAX_STORED_RESPONSE_BYTES {
            return Err(IdempotencyError::InvalidInput {
                field: "response body",
            });
        }
        if request_id.len() != RESPONSE_REQUEST_ID_BYTES
            || !request_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(IdempotencyError::InvalidInput {
                field: "response request id",
            });
        }
        Ok(Self {
            status,
            content_type,
            body,
            request_id,
        })
    }

    /// Exact HTTP status to replay.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Exact `Content-Type` bytes to replay.
    #[must_use]
    pub fn content_type(&self) -> &[u8] {
        &self.content_type
    }

    /// Exact facade body bytes to replay.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Adapter-generated request id that accompanied the exact response.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

impl fmt::Debug for StoredResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredResponse")
            .field("status", &self.status)
            .field("content_type_bytes", &self.content_type.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Exclusive permission returned only to the request that inserted a new
/// claim. It is deliberately not cloneable. Dropping it performs no cleanup:
/// cancellation and crashes remain fail-closed until explicit recovery.
pub struct Execution {
    scope_digest: [u8; 32],
    request_digest: [u8; 32],
    effect_attempted: bool,
}

impl fmt::Debug for Execution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Execution")
            .field("effect_attempted", &self.effect_attempted)
            .finish_non_exhaustive()
    }
}

/// Result of atomically claiming a caller, operation, and key namespace.
#[derive(Debug)]
pub enum Claim {
    /// This request alone may execute the route.
    Execute(Execution),
    /// The exact terminal response is available for replay.
    Replay {
        /// Success or caller-visible failure.
        outcome: TerminalOutcome,
        /// Exact response bytes and metadata.
        response: StoredResponse,
    },
    /// The same request has an outstanding claim but no attempted effect.
    InFlight,
    /// A non-safe effect may have happened and no terminal response exists.
    EffectUnknown,
    /// This namespace is already bound to a different request digest.
    Mismatch,
    /// The key remains spent, but response custody has expired.
    ResponseExpired {
        /// The outcome whose response was erased.
        outcome: TerminalOutcome,
    },
}

/// PostgreSQL failures and value-free API refusals.
#[derive(Debug)]
pub enum IdempotencyError {
    /// A bounded public API input was invalid. The field name is fixed and
    /// never repeats its value.
    InvalidInput { field: &'static str },
    /// The database has an idempotency schema newer than this release.
    SchemaNewer { found: i64, supported: i64 },
    /// Opaque v0100 entries cannot be remapped to the logical deployment
    /// namespace without risking a fresh retry of an existing effect.
    LegacyDeploymentIdentityEntries,
    /// Replayable v0200 responses lack the original Adapter response id and
    /// cannot be safely repaired or replayed under the v0300 contract.
    LegacyResponseRequestIdEntries,
    /// The migration advisory lock was not held when released.
    MigrationLock,
    /// An execution token attempted an invalid or already-completed state
    /// transition.
    StateConflict,
    /// A row violated the schema shape expected by this release.
    StoredDataInvalid,
    /// The pool could not provide a connection.
    Pool(PoolError),
    /// PostgreSQL refused a query.
    Query(PgError),
}

impl fmt::Display for IdempotencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { field } => {
                write!(formatter, "adapter.idempotency-invalid: invalid {field}")
            }
            Self::SchemaNewer { found, supported } => write!(
                formatter,
                "adapter.idempotency-schema-newer: database version {found} is newer than supported version {supported}"
            ),
            Self::LegacyDeploymentIdentityEntries => write!(
                formatter,
                "adapter.idempotency-legacy-deployment-entries: existing idempotency entries require operator reconciliation before the logical deployment identity migration"
            ),
            Self::LegacyResponseRequestIdEntries => write!(
                formatter,
                "adapter.idempotency-legacy-response-id: existing replayable responses require operator reconciliation before the response identity migration"
            ),
            Self::MigrationLock => write!(
                formatter,
                "adapter.idempotency-migration-lock: migration lock was not held"
            ),
            Self::StateConflict => write!(
                formatter,
                "adapter.idempotency-state-conflict: invalid execution state transition"
            ),
            Self::StoredDataInvalid => write!(
                formatter,
                "adapter.idempotency-stored-data-invalid: stored response is not readable"
            ),
            Self::Pool(_) => write!(
                formatter,
                "adapter.idempotency-database: connection pool unavailable"
            ),
            Self::Query(_) => write!(formatter, "adapter.idempotency-database: query failed"),
        }
    }
}

impl std::error::Error for IdempotencyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pool(error) => Some(error),
            Self::Query(error) => Some(error),
            Self::InvalidInput { .. }
            | Self::SchemaNewer { .. }
            | Self::LegacyDeploymentIdentityEntries
            | Self::LegacyResponseRequestIdEntries
            | Self::MigrationLock
            | Self::StateConflict
            | Self::StoredDataInvalid => None,
        }
    }
}

impl From<PoolError> for IdempotencyError {
    fn from(error: PoolError) -> Self {
        Self::Pool(error)
    }
}

impl From<PgError> for IdempotencyError {
    fn from(error: PgError) -> Self {
        Self::Query(error)
    }
}

/// PostgreSQL-backed idempotency response store.
#[derive(Clone)]
pub struct PostgresIdempotencyStore {
    pool: Pool,
    response_retention: Duration,
}

impl PostgresIdempotencyStore {
    /// Bind the store to a pool and configure exact response custody.
    pub fn new(pool: Pool, response_retention: Duration) -> Result<Self, IdempotencyError> {
        if !(MIN_RESPONSE_RETENTION..=MAX_RESPONSE_RETENTION).contains(&response_retention) {
            return Err(IdempotencyError::InvalidInput {
                field: "response retention",
            });
        }
        Ok(Self {
            pool,
            response_retention,
        })
    }

    /// Atomically claim a namespaced key or resolve its existing state.
    pub async fn claim(
        &self,
        request: ClaimRequest<'_>,
        now: SystemTime,
    ) -> Result<Claim, IdempotencyError> {
        validate_component(
            "deployment id",
            request.deployment.as_bytes(),
            MAX_DEPLOYMENT_IDENTITY_BYTES,
        )?;
        validate_component(
            "concrete operation",
            request.concrete_operation.as_bytes(),
            MAX_CONCRETE_OPERATION_BYTES,
        )?;
        validate_component(
            "idempotency key",
            request.key.as_bytes(),
            MAX_IDEMPOTENCY_KEY_BYTES,
        )?;
        let scope_digest = scope_digest(&request);
        let client = self.pool.get().await?;
        let inserted = client
            .execute(
                "INSERT INTO adapter_idempotency_entries \
                 (scope_digest, request_digest, state, claimed_at) \
                 VALUES ($1, $2, 'claimed', $3) ON CONFLICT DO NOTHING",
                &[
                    &scope_digest.as_slice(),
                    &request.request_digest.as_slice(),
                    &now,
                ],
            )
            .await?;
        if inserted == 1 {
            return Ok(Claim::Execute(Execution {
                scope_digest,
                request_digest: request.request_digest,
                effect_attempted: false,
            }));
        }

        // Enforce the custody horizon even if the supervised sweep has not
        // reached this row yet. The spent tombstone remains.
        erase_one_if_expired(&client, &scope_digest, now).await?;
        let row = client
            .query_one(
                "SELECT request_digest, state, response_status, \
                        response_content_type, response_body, response_request_id \
                 FROM adapter_idempotency_entries WHERE scope_digest = $1",
                &[&scope_digest.as_slice()],
            )
            .await?;
        claim_from_row(row, request.request_digest)
    }

    /// Persist that a non-safe send is about to be attempted.
    ///
    /// The caller must await this committed update before starting the send.
    /// Any later cancellation leaves `EffectUnknown`, never fresh execution.
    pub async fn mark_effect_attempted(
        &self,
        execution: &mut Execution,
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        if execution.effect_attempted {
            return Err(IdempotencyError::StateConflict);
        }
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                "UPDATE adapter_idempotency_entries \
                 SET state = 'effect_started', effect_started_at = $3 \
                 WHERE scope_digest = $1 AND request_digest = $2 AND state = 'claimed'",
                &[
                    &execution.scope_digest.as_slice(),
                    &execution.request_digest.as_slice(),
                    &now,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(IdempotencyError::StateConflict);
        }
        execution.effect_attempted = true;
        Ok(())
    }

    /// Implement Camel's `removeOnFailure` only while no effect was attempted.
    pub async fn release_before_effect(
        &self,
        execution: Execution,
    ) -> Result<(), IdempotencyError> {
        if execution.effect_attempted {
            return Err(IdempotencyError::StateConflict);
        }
        let client = self.pool.get().await?;
        let deleted = client
            .execute(
                "DELETE FROM adapter_idempotency_entries \
                 WHERE scope_digest = $1 AND request_digest = $2 AND state = 'claimed'",
                &[
                    &execution.scope_digest.as_slice(),
                    &execution.request_digest.as_slice(),
                ],
            )
            .await?;
        if deleted == 1 {
            Ok(())
        } else {
            Err(IdempotencyError::StateConflict)
        }
    }

    /// Record the exact terminal facade response for replay.
    pub async fn finish(
        &self,
        execution: Execution,
        outcome: TerminalOutcome,
        response: StoredResponse,
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        let client = self.pool.get().await?;
        self.finish_with_client(&client, execution, outcome, response, now)
            .await
    }

    /// Record a terminal response through the caller's SQL client. The
    /// served facade passes its journal transaction here so response custody
    /// and terminal audit rows commit or roll back together.
    pub async fn finish_with_client(
        &self,
        client: &impl GenericClient,
        execution: Execution,
        outcome: TerminalOutcome,
        response: StoredResponse,
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        let expires_at =
            now.checked_add(self.response_retention)
                .ok_or(IdempotencyError::InvalidInput {
                    field: "response retention instant",
                })?;
        let expected_state = if execution.effect_attempted {
            "effect_started"
        } else {
            "claimed"
        };
        let status =
            i16::try_from(response.status).map_err(|_| IdempotencyError::InvalidInput {
                field: "response status",
            })?;
        let updated = client
            .execute(
                "UPDATE adapter_idempotency_entries \
                 SET state = $3, terminal_at = $4, expires_at = $5, \
                     response_status = $6, response_content_type = $7, response_body = $8, \
                     response_request_id = $9 \
                 WHERE scope_digest = $1 AND request_digest = $2 AND state = $10",
                &[
                    &execution.scope_digest.as_slice(),
                    &execution.request_digest.as_slice(),
                    &outcome.stored_state(),
                    &now,
                    &expires_at,
                    &status,
                    &response.content_type,
                    &response.body,
                    &response.request_id,
                    &expected_state,
                ],
            )
            .await?;
        if updated == 1 {
            Ok(())
        } else {
            Err(IdempotencyError::StateConflict)
        }
    }

    /// Erase expired exact responses in one bounded, lock-skipping batch.
    ///
    /// Only response custody is erased. Scope and request digests remain as a
    /// spent tombstone, so a completed or uncertain effect is never reopened.
    pub async fn sweep_expired(
        &self,
        now: SystemTime,
        batch_limit: u32,
    ) -> Result<u64, IdempotencyError> {
        if !(1..=MAX_SWEEP_BATCH).contains(&batch_limit) {
            return Err(IdempotencyError::InvalidInput {
                field: "sweep batch limit",
            });
        }
        let limit = i64::from(batch_limit);
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "WITH expired AS ( \
                     SELECT scope_digest FROM adapter_idempotency_entries \
                     WHERE state IN ('completed', 'failed') AND expires_at <= $1 \
                     ORDER BY expires_at, scope_digest \
                     FOR UPDATE SKIP LOCKED LIMIT $2 \
                 ) \
                 UPDATE adapter_idempotency_entries AS entries \
                 SET state = CASE entries.state \
                         WHEN 'completed' THEN 'completed_expired' \
                         ELSE 'failed_expired' END, \
                     response_status = NULL, response_content_type = NULL, response_body = NULL, \
                     response_request_id = NULL \
                 FROM expired WHERE entries.scope_digest = expired.scope_digest \
                 RETURNING entries.scope_digest",
                &[&now, &limit],
            )
            .await?;
        Ok(rows.len() as u64)
    }
}

/// Apply only the idempotency store's schema migrations under its own lock and
/// migration ledger. This does not read or write the audit journal ledger.
/// Each migration commits together with its ledger row, so an interrupted
/// startup leaves both or neither.
pub async fn migrate(client: &mut impl GenericClient) -> Result<(), IdempotencyError> {
    client
        .query_one("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await?;
    let applied = apply_migrations(client).await;
    let released = client
        .query_one("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_KEY])
        .await;
    applied?;
    if released?.get::<_, bool>(0) {
        Ok(())
    } else {
        Err(IdempotencyError::MigrationLock)
    }
}

async fn apply_migrations(client: &mut impl GenericClient) -> Result<(), IdempotencyError> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS adapter_idempotency_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL)",
        )
        .await?;
    let applied = client
        .query(
            "SELECT version FROM adapter_idempotency_schema_migrations",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| row.get::<_, i64>(0))
        .collect::<Vec<_>>();
    if let Some(found) = applied.iter().copied().max() {
        if found > SUPPORTED_SCHEMA_VERSION {
            return Err(IdempotencyError::SchemaNewer {
                found,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
    }
    for (version, migration) in MIGRATIONS {
        if applied.contains(&version) {
            continue;
        }
        let transaction = client.transaction().await?;
        if let Err(error) = transaction.batch_execute(migration).await {
            if version == LOGICAL_DEPLOYMENT_IDENTITY_MIGRATION
                && error.code().is_some_and(|code| code.code() == "P0001")
            {
                return Err(IdempotencyError::LegacyDeploymentIdentityEntries);
            }
            if version == RESPONSE_REQUEST_ID_MIGRATION
                && error.code().is_some_and(|code| code.code() == "P0001")
            {
                return Err(IdempotencyError::LegacyResponseRequestIdEntries);
            }
            return Err(IdempotencyError::Query(error));
        }
        transaction
            .execute(
                "INSERT INTO adapter_idempotency_schema_migrations(version, applied_at) \
                 VALUES($1, now())",
                &[&version],
            )
            .await?;
        transaction.commit().await?;
    }
    Ok(())
}

fn validate_component(
    field: &'static str,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), IdempotencyError> {
    if bytes.is_empty() || bytes.len() > maximum {
        Err(IdempotencyError::InvalidInput { field })
    } else {
        Ok(())
    }
}

fn scope_digest(request: &ClaimRequest<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SCOPE_DIGEST_DOMAIN);
    for component in [
        request.caller.issuer.as_bytes(),
        request.caller.subject.as_bytes(),
        request.caller.client_id.as_bytes(),
        request.deployment.as_bytes(),
        request.concrete_operation.as_bytes(),
        request.key.as_bytes(),
    ] {
        let length = u64::try_from(component.len()).expect("bounded namespace component fits u64");
        digest.update(length.to_be_bytes());
        digest.update(component);
    }
    digest.finalize().into()
}

async fn erase_one_if_expired(
    client: &impl GenericClient,
    scope_digest: &[u8; 32],
    now: SystemTime,
) -> Result<(), IdempotencyError> {
    client
        .execute(
            "UPDATE adapter_idempotency_entries \
             SET state = CASE state \
                     WHEN 'completed' THEN 'completed_expired' \
                     ELSE 'failed_expired' END, \
                 response_status = NULL, response_content_type = NULL, response_body = NULL, \
                 response_request_id = NULL \
             WHERE scope_digest = $1 AND state IN ('completed', 'failed') \
               AND expires_at <= $2",
            &[&scope_digest.as_slice(), &now],
        )
        .await?;
    Ok(())
}

fn claim_from_row(row: Row, request_digest: [u8; 32]) -> Result<Claim, IdempotencyError> {
    let stored_digest: Vec<u8> = row.get("request_digest");
    if stored_digest.as_slice() != request_digest {
        return Ok(Claim::Mismatch);
    }
    let state: String = row.get("state");
    match state.as_str() {
        "claimed" => Ok(Claim::InFlight),
        "effect_started" => Ok(Claim::EffectUnknown),
        "completed" => replay_from_row(&row, TerminalOutcome::Completed),
        "failed" => replay_from_row(&row, TerminalOutcome::Failed),
        "completed_expired" => Ok(Claim::ResponseExpired {
            outcome: TerminalOutcome::Completed,
        }),
        "failed_expired" => Ok(Claim::ResponseExpired {
            outcome: TerminalOutcome::Failed,
        }),
        _ => Err(IdempotencyError::StoredDataInvalid),
    }
}

fn replay_from_row(row: &Row, outcome: TerminalOutcome) -> Result<Claim, IdempotencyError> {
    let status: Option<i16> = row.get("response_status");
    let content_type: Option<Vec<u8>> = row.get("response_content_type");
    let body: Option<Vec<u8>> = row.get("response_body");
    let request_id: Option<String> = row.get("response_request_id");
    let status = status
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(IdempotencyError::StoredDataInvalid)?;
    let response = StoredResponse::new(
        status,
        content_type.ok_or(IdempotencyError::StoredDataInvalid)?,
        body.ok_or(IdempotencyError::StoredDataInvalid)?,
        request_id.ok_or(IdempotencyError::StoredDataInvalid)?,
    )
    .map_err(|_| IdempotencyError::StoredDataInvalid)?;
    Ok(Claim::Replay { outcome, response })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_for(deployment: &str, operation: &str) -> [u8; 32] {
        let caller =
            VerifiedCallerIdentity::new("https://issuer.example.invalid", "subject", "client")
                .expect("the identity is bounded");
        scope_digest(&ClaimRequest {
            caller: &caller,
            deployment,
            concrete_operation: operation,
            key: "key",
            request_digest: [7; 32],
        })
    }

    #[test]
    fn scope_digest_separates_logical_deployments() {
        assert_ne!(
            digest_for("tracker-east", "records-create:person-create:person"),
            digest_for("tracker-west", "records-create:person-create:person")
        );
    }

    #[test]
    fn scope_digest_frames_deployment_and_operation_components() {
        assert_ne!(
            digest_for("deployment-ab", "c"),
            digest_for("deployment-a", "bc")
        );
    }
}
