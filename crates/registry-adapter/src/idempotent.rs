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

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime};

use crate::engine::exchange::MAX_IDEMPOTENCY_KEY_BYTES;
use deadpool_postgres::{GenericClient, Pool, PoolError};
use http::HeaderValue;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_postgres::{Error as PgError, Row};

use crate::engine::route::EXCHANGE_DEADLINE;

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
/// Longest reviewed artifact identifier retained for status recovery.
pub const MAX_ASYNC_IDENTIFIER_BYTES: usize = 256;
/// Exact lowercase-hex length of an optional source-native correlation id.
pub const ASYNC_RECOVERY_ID_BYTES: usize = 64;
/// Random bytes in a non-cloneable per-row recovery lease.
pub const RECOVERY_LEASE_ID_BYTES: usize = 16;

/// The table grants a runtime role needs when its deployment serves any
/// write: claim, effect marking, terminal custody and the expiry sweep.
pub const WRITE_RUNTIME_GRANTS: [(&str, &[&str]); 2] = [
    (
        "adapter_idempotency_entries",
        &["SELECT", "INSERT", "UPDATE", "DELETE"],
    ),
    (
        "adapter_idempotency_resumes",
        &["SELECT", "INSERT", "UPDATE", "DELETE"],
    ),
];
/// The extra grant an asynchronous or resumable write needs: the durable
/// artifact fence its activation and effect precommits lock.
pub const RECOVERY_RUNTIME_GRANTS: (&str, &[&str]) = (
    "adapter_idempotency_async_artifacts",
    &["SELECT", "INSERT", "UPDATE"],
);
/// The extra grant a resumable write needs: its checkpointed identifiers.
pub const RESUME_RUNTIME_GRANTS: (&str, &[&str]) =
    ("adapter_idempotency_resume_bindings", &["SELECT", "INSERT"]);
const MIN_RESPONSE_RETENTION: Duration = Duration::from_secs(1);
const SCOPE_DIGEST_DOMAIN: &[u8] = b"registry-adapter:idempotency-scope:v1\0";
const ASYNC_DEPLOYMENT_DIGEST_DOMAIN: &[u8] = b"registry-adapter:async-deployment:v1\0";
const ASYNC_BINDING_DIGEST_DOMAIN: &[u8] = b"registry-adapter:async-binding:v1\0";

const LOGICAL_DEPLOYMENT_IDENTITY_MIGRATION: i64 = 200;
const RESPONSE_REQUEST_ID_MIGRATION: i64 = 300;
const MIGRATIONS: [(i64, &str); 5] = [
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
    (
        400,
        include_str!("idempotent/migrations/0400_async_completion.sql"),
    ),
    (
        500,
        include_str!("idempotent/migrations/0500_linear_write_resume.sql"),
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

/// Bounded metadata committed before an asynchronous non-safe send.
///
/// Every text value except the source-native correlation id is a reviewed,
/// artifact-defined identifier. The correlation id is host-generated and is
/// never caller-visible. `effect_deadline` is the actual finite route deadline,
/// not an operator-controlled recovery setting.
pub struct AsyncEffectAttempt<'a> {
    /// Existing Adapter response request id reused as the sole status handle.
    pub response_request_id: &'a str,
    /// Digest of the exact loaded project/profile/pack artifact closure.
    pub artifact_digest: [u8; 32],
    /// Original project binding selected for the write.
    pub binding_id: &'a str,
    /// Original profile operation used for current-scope authorization.
    pub profile_operation: &'a str,
    /// Concrete operation used by the write claim and journal.
    pub concrete_operation: &'a str,
    /// Original declared record type.
    pub record_type: &'a str,
    /// Optional source-native, host-generated correlation id.
    pub recovery_id: Option<&'a str>,
    /// Finite deadline of the initial route execution.
    pub effect_deadline: SystemTime,
}

/// Artifact and deadline authority for one closed linear multi-effect write.
pub struct ResumeClaimContext {
    /// Digest of the exact active artifact closure that defines step order.
    pub artifact_digest: [u8; 32],
    /// Actual finite route deadline used as the execution lease ceiling.
    pub effect_deadline: SystemTime,
    /// Number of non-safe sends in the compiled flat route.
    pub step_count: u32,
}

/// Caller and artifact context for resolving one opaque status handle.
pub struct StatusLookupRequest<'a> {
    /// Currently authenticated caller.
    pub caller: &'a VerifiedCallerIdentity,
    /// Stable logical deployment currently serving the request.
    pub deployment: &'a str,
    /// Digest of the artifact currently authorized to interpret the row.
    pub artifact_digest: [u8; 32],
    /// Strict 32-lowercase-hex Adapter response request id.
    pub status_id: &'a str,
}

/// Original artifact-defined authority needed by the facade after a binding
/// digest matches. This is never returned for a wrong caller or artifact.
#[derive(Clone, Eq, PartialEq)]
pub struct StatusMetadata {
    binding_id: String,
    profile_operation: String,
    concrete_operation: String,
    record_type: String,
}

impl StatusMetadata {
    /// Original project binding id.
    #[must_use]
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    /// Original profile operation used for scope admission.
    #[must_use]
    pub fn profile_operation(&self) -> &str {
        &self.profile_operation
    }

    /// Original concrete facade operation.
    #[must_use]
    pub fn concrete_operation(&self) -> &str {
        &self.concrete_operation
    }

    /// Original declared record type.
    #[must_use]
    pub fn record_type(&self) -> &str {
        &self.record_type
    }
}

impl fmt::Debug for StatusMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StatusMetadata { artifact-defined identifiers withheld }")
    }
}

/// A caller-bound accepted lookup. It is deliberately not cloneable: the
/// store uses its private row identity to acquire at most one recovery lease.
pub struct PendingStatusLookup {
    scope_digest: [u8; 32],
    request_digest: [u8; 32],
    binding_digest: [u8; 32],
    artifact_digest: [u8; 32],
    expires_at: SystemTime,
    metadata: StatusMetadata,
    response: StoredResponse,
}

impl PendingStatusLookup {
    /// Exact accepted response already held in custody.
    #[must_use]
    pub fn response(&self) -> &StoredResponse {
        &self.response
    }

    /// Original authority, exposed only after caller/artifact digest match.
    #[must_use]
    pub fn metadata(&self) -> &StatusMetadata {
        &self.metadata
    }
}

impl fmt::Debug for PendingStatusLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingStatusLookup")
            .field("response", &self.response)
            .finish_non_exhaustive()
    }
}

/// One authenticated status lookup.
#[derive(Debug)]
pub enum StatusLookup {
    /// Unknown, expired, malformed, or caller/artifact-mismatched handle.
    NotFound,
    /// The source accepted the write and recovery may acquire its row lease.
    Accepted(PendingStatusLookup),
    /// Terminal response custody is still reachable through the original link.
    Terminal {
        /// Successful or caller-visible failed terminal outcome.
        outcome: TerminalOutcome,
        /// Original authority for current-scope re-authorization.
        metadata: StatusMetadata,
        /// Exact terminal facade response.
        response: StoredResponse,
    },
}

/// Exclusive permission to perform one source-native recovery check.
///
/// Dropping this capability does not clear its database lease. A crash or
/// cancellation therefore remains serialized until the finite deadline.
pub struct RecoveryExecution {
    scope_digest: [u8; 32],
    request_digest: [u8; 32],
    binding_digest: [u8; 32],
    artifact_digest: [u8; 32],
    lease_id: [u8; RECOVERY_LEASE_ID_BYTES],
    state: RecoveryState,
    response_request_id: String,
    metadata: StatusMetadata,
    source_id: Option<String>,
    recovery_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryState {
    Accepted,
    EffectStarted,
}

impl RecoveryState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::EffectStarted => "effect_started",
        }
    }
}

impl RecoveryExecution {
    /// Original artifact-defined authority for the recovery route.
    #[must_use]
    pub fn metadata(&self) -> &StatusMetadata {
        &self.metadata
    }

    /// Validated source operation id for an accepted status route.
    #[must_use]
    pub fn source_id(&self) -> Option<&str> {
        self.source_id.as_deref()
    }

    /// Precommitted source-native correlation for effect uncertainty.
    #[must_use]
    pub fn recovery_id(&self) -> Option<&str> {
        self.recovery_id.as_deref()
    }

    /// Existing response request id reused as the status handle.
    #[must_use]
    pub fn response_request_id(&self) -> &str {
        &self.response_request_id
    }
}

impl fmt::Debug for RecoveryExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryExecution")
            .field("state", &self.state)
            .field("has_source_id", &self.source_id.is_some())
            .field("has_recovery_id", &self.recovery_id.is_some())
            .finish_non_exhaustive()
    }
}

/// Result of atomically trying to acquire a recovery row.
#[derive(Debug)]
pub enum RecoveryLease {
    /// This checker alone may call the source status route.
    Acquired(Box<RecoveryExecution>),
    /// Another live lease owns the row.
    Busy,
    /// The row is expired, terminal, mismatched, or lacks safe correlation.
    Stale,
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
/// once an effect is marked, cancellation and crashes remain fail-closed
/// until explicit recovery. A plain claim that never reached its effect mark
/// is leased for one exchange deadline; after that the next same-request
/// claim takes it over, and this execution can no longer mark, release or
/// finish it.
pub struct Execution {
    scope_digest: [u8; 32],
    request_digest: [u8; 32],
    /// The row's `claimed_at`, the fencing token of this claim. A takeover
    /// sets it at least one exchange deadline later, so it never repeats.
    claimed_at: SystemTime,
    effect_attempted: bool,
    resume: Option<ResumeExecutionState>,
}

struct ResumeExecutionState {
    deployment_digest: [u8; 32],
    artifact_digest: [u8; 32],
    lease_id: [u8; RECOVERY_LEASE_ID_BYTES],
    next_step: u32,
    step_count: u32,
    expires_at: SystemTime,
}

impl fmt::Debug for Execution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Execution")
            .field("effect_attempted", &self.effect_attempted)
            .field("resumable", &self.resume.is_some())
            .finish_non_exhaustive()
    }
}

/// Result of atomically claiming a caller, operation, and key namespace.
#[derive(Debug)]
pub enum Claim {
    /// This request alone may execute the route.
    Execute(Execution),
    /// Resume the first unfinished step under a newly acquired finite lease.
    Resume {
        execution: Execution,
        next_step: u32,
        bindings: BTreeMap<String, String>,
    },
    /// The exact terminal response is available for replay.
    Replay {
        /// Success or caller-visible failure.
        outcome: TerminalOutcome,
        /// Exact response bytes and metadata.
        response: StoredResponse,
    },
    /// The source accepted the write; replay the exact stored 202 without
    /// polling or resending the mutation.
    Accepted {
        /// Exact accepted response bytes and metadata.
        response: StoredResponse,
    },
    /// The same request has an outstanding claim but no attempted effect.
    InFlight,
    /// A non-safe effect may have happened and no terminal response exists.
    EffectUnknown {
        /// When the effect was marked. The attempt that marked it ends within
        /// one exchange deadline of this instant, so until then it may still
        /// record a terminal answer that a retry replays.
        effect_started_at: SystemTime,
    },
    /// This namespace is already bound to a different request digest.
    Mismatch,
    /// The key remains spent, but response custody has expired.
    ResponseExpired {
        /// The outcome whose response was erased.
        outcome: TerminalOutcome,
    },
    /// The accepted-response link and custody expired, but the effect remains
    /// permanently spent.
    AcceptedExpired,
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
    /// A different artifact still owns live asynchronous recovery rows for
    /// this logical deployment.
    AsyncArtifactInUse,
    /// An artifact activation found unfinished asynchronous or resumable
    /// writes of another artifact for this logical deployment. They block it
    /// until they finish under that artifact or expire, by `clears_by`.
    AsyncArtifactActivationRefused {
        unfinished: i64,
        clears_by: SystemTime,
    },
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
            Self::AsyncArtifactInUse => write!(
                formatter,
                "adapter.idempotency-async-artifact-in-use: live asynchronous recoveries belong to another artifact"
            ),
            Self::AsyncArtifactActivationRefused {
                unfinished,
                clears_by,
            } => {
                let clears_by = OffsetDateTime::from(*clears_by)
                    .format(&Rfc3339)
                    .unwrap_or_else(|_| "an instant outside RFC 3339".to_owned());
                write!(
                    formatter,
                    "adapter.idempotency-async-artifact-in-use: {unfinished} unfinished asynchronous or resumable write(s) of this deployment belong to another artifact and expire by {clears_by}; redeploy the previous artifact bytes so they can finish, or wait until {clears_by}"
                )
            }
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
            | Self::AsyncArtifactInUse
            | Self::AsyncArtifactActivationRefused { .. }
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
        validate_claim_request(&request)?;
        let scope_digest = scope_digest(&request);
        let client = self.pool.get().await?;
        let inserted = client
            .query_opt(
                "INSERT INTO adapter_idempotency_entries \
                 (scope_digest, request_digest, state, claimed_at) \
                 VALUES ($1, $2, 'claimed', $3) ON CONFLICT DO NOTHING \
                 RETURNING claimed_at",
                &[
                    &scope_digest.as_slice(),
                    &request.request_digest.as_slice(),
                    &now,
                ],
            )
            .await?;
        if let Some(row) = inserted {
            return Ok(Claim::Execute(Execution {
                scope_digest,
                request_digest: request.request_digest,
                claimed_at: row.get(0),
                effect_attempted: false,
                resume: None,
            }));
        }

        // A claim whose owner never marked an effect within one exchange
        // deadline is abandoned: nothing was sent, so the same request takes
        // it over. Resumable claims keep their own lease and are excluded.
        if let Some(lease_start) = now.checked_sub(EXCHANGE_DEADLINE) {
            if let Some(row) = client
                .query_opt(
                    "UPDATE adapter_idempotency_entries AS entries SET claimed_at = $3 \
                     WHERE scope_digest = $1 AND request_digest = $2 AND state = 'claimed' \
                       AND claimed_at <= $4 \
                       AND NOT EXISTS (SELECT 1 FROM adapter_idempotency_resumes AS resumes \
                                       WHERE resumes.scope_digest = entries.scope_digest) \
                     RETURNING claimed_at",
                    &[
                        &scope_digest.as_slice(),
                        &request.request_digest.as_slice(),
                        &now,
                        &lease_start,
                    ],
                )
                .await?
            {
                return Ok(Claim::Execute(Execution {
                    scope_digest,
                    request_digest: request.request_digest,
                    claimed_at: row.get(0),
                    effect_attempted: false,
                    resume: None,
                }));
            }
        }

        // Enforce the custody horizon even if the supervised sweep has not
        // reached this row yet. The spent tombstone remains.
        erase_one_if_expired(&client, &scope_digest, now).await?;
        let row = client
            .query_one(
                "SELECT request_digest, state, response_status, \
                        response_content_type, response_body, response_request_id, \
                        effect_started_at \
                 FROM adapter_idempotency_entries WHERE scope_digest = $1",
                &[&scope_digest.as_slice()],
            )
            .await?;
        claim_from_row(row, request.request_digest)
    }

    /// Claim or resume one closed linear multi-effect write. The initial
    /// expiry is anchored here and never slides; every execution lease is
    /// bounded by both the physical route deadline and that expiry.
    pub async fn claim_resume(
        &self,
        request: ClaimRequest<'_>,
        context: ResumeClaimContext,
        now: SystemTime,
    ) -> Result<Claim, IdempotencyError> {
        validate_claim_request(&request)?;
        if !(2..=100_000).contains(&context.step_count) {
            return Err(IdempotencyError::InvalidInput {
                field: "resume step count",
            });
        }
        let remaining = context.effect_deadline.duration_since(now).map_err(|_| {
            IdempotencyError::InvalidInput {
                field: "resume effect deadline",
            }
        })?;
        if remaining > EXCHANGE_DEADLINE {
            return Err(IdempotencyError::InvalidInput {
                field: "resume effect deadline",
            });
        }
        let expires_at = checked_retention_expiry(now, self.response_retention)?;
        let lease_until = context.effect_deadline.min(expires_at);
        if lease_until <= now {
            return Err(IdempotencyError::InvalidInput {
                field: "resume effect deadline",
            });
        }
        let scope_digest = scope_digest(&request);
        let deployment_digest = async_deployment_digest(request.deployment);
        let lease_id = new_lease_id()?;
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        lock_async_artifact_fence(
            &transaction,
            deployment_digest,
            context.artifact_digest,
            now,
            false,
        )
        .await?;
        // Expire first, so a key freed by an expired write that sent
        // nothing is claimed fresh below.
        expire_resume_with_client(&transaction, &scope_digest, now).await?;
        let inserted = transaction
            .query_opt(
                "INSERT INTO adapter_idempotency_entries \
                 (scope_digest, request_digest, state, claimed_at) \
                 VALUES ($1, $2, 'claimed', $3) ON CONFLICT DO NOTHING \
                 RETURNING claimed_at",
                &[
                    &scope_digest.as_slice(),
                    &request.request_digest.as_slice(),
                    &now,
                ],
            )
            .await?;
        if let Some(inserted) = inserted {
            transaction
                .execute(
                    "INSERT INTO adapter_idempotency_resumes \
                     (scope_digest, request_digest, deployment_digest, artifact_digest, \
                      next_step, step_count, expires_at, lease_id, lease_until) \
                     VALUES ($1, $2, $3, $4, 0, $5, $6, $7, $8)",
                    &[
                        &scope_digest.as_slice(),
                        &request.request_digest.as_slice(),
                        &deployment_digest.as_slice(),
                        &context.artifact_digest.as_slice(),
                        &i32::try_from(context.step_count).map_err(|_| {
                            IdempotencyError::InvalidInput {
                                field: "resume step count",
                            }
                        })?,
                        &expires_at,
                        &lease_id.as_slice(),
                        &lease_until,
                    ],
                )
                .await?;
            transaction.commit().await?;
            return Ok(Claim::Execute(Execution {
                scope_digest,
                request_digest: request.request_digest,
                claimed_at: inserted.get(0),
                effect_attempted: false,
                resume: Some(ResumeExecutionState {
                    deployment_digest,
                    artifact_digest: context.artifact_digest,
                    lease_id,
                    next_step: 0,
                    step_count: context.step_count,
                    expires_at,
                }),
            }));
        }

        let row = transaction
            .query_one(
                "SELECT request_digest, state, response_status, response_content_type, \
                        response_body, response_request_id, claimed_at, effect_started_at \
                 FROM adapter_idempotency_entries WHERE scope_digest = $1",
                &[&scope_digest.as_slice()],
            )
            .await?;
        let stored_digest = fixed_digest(&row, "request_digest")?;
        if stored_digest != request.request_digest {
            transaction.commit().await?;
            return Ok(Claim::Mismatch);
        }
        let Some(resume) = transaction
            .query_opt(
                "UPDATE adapter_idempotency_resumes \
                 SET lease_id = $4, lease_until = LEAST($5, expires_at) \
                 WHERE scope_digest = $1 AND request_digest = $2 \
                   AND artifact_digest = $3 AND expires_at > $6 AND lease_until <= $6 \
                 RETURNING deployment_digest, artifact_digest, next_step, step_count, \
                           expires_at, lease_until",
                &[
                    &scope_digest.as_slice(),
                    &request.request_digest.as_slice(),
                    &context.artifact_digest.as_slice(),
                    &lease_id.as_slice(),
                    &lease_until,
                    &now,
                ],
            )
            .await?
        else {
            let live = transaction
                .query_opt(
                    "SELECT 1 FROM adapter_idempotency_resumes \
                     WHERE scope_digest = $1 AND request_digest = $2 \
                       AND artifact_digest = $3 AND expires_at > $4",
                    &[
                        &scope_digest.as_slice(),
                        &request.request_digest.as_slice(),
                        &context.artifact_digest.as_slice(),
                        &now,
                    ],
                )
                .await?
                .is_some();
            transaction.commit().await?;
            return if live {
                Ok(Claim::InFlight)
            } else {
                claim_from_row(row, request.request_digest)
            };
        };
        let next_step = u32::try_from(resume.get::<_, i32>("next_step"))
            .map_err(|_| IdempotencyError::StoredDataInvalid)?;
        let step_count = u32::try_from(resume.get::<_, i32>("step_count"))
            .map_err(|_| IdempotencyError::StoredDataInvalid)?;
        if step_count != context.step_count || next_step >= step_count {
            return Err(IdempotencyError::StoredDataInvalid);
        }
        let mut bindings = BTreeMap::new();
        for binding in transaction
            .query(
                "SELECT name, value FROM adapter_idempotency_resume_bindings \
                 WHERE scope_digest = $1 ORDER BY name",
                &[&scope_digest.as_slice()],
            )
            .await?
        {
            let name: String = binding.get("name");
            let value: String = binding.get("value");
            validate_resume_identifier(&name, "resume binding name")?;
            validate_resume_identifier(&value, "resume binding value")?;
            if bindings.insert(name, value).is_some() {
                return Err(IdempotencyError::StoredDataInvalid);
            }
        }
        let execution = Execution {
            scope_digest,
            request_digest: request.request_digest,
            claimed_at: row.get("claimed_at"),
            effect_attempted: false,
            resume: Some(ResumeExecutionState {
                deployment_digest: fixed_digest(&resume, "deployment_digest")?,
                artifact_digest: fixed_digest(&resume, "artifact_digest")?,
                lease_id,
                next_step,
                step_count,
                expires_at: resume.get("expires_at"),
            }),
        };
        transaction.commit().await?;
        Ok(Claim::Resume {
            execution,
            next_step,
            bindings,
        })
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
                 WHERE scope_digest = $1 AND request_digest = $2 AND state = 'claimed' \
                   AND claimed_at = $4",
                &[
                    &execution.scope_digest.as_slice(),
                    &execution.request_digest.as_slice(),
                    &now,
                    &execution.claimed_at,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(IdempotencyError::StateConflict);
        }
        execution.effect_attempted = true;
        Ok(())
    }

    /// Commit the current resumable ordinal before any source bytes leave.
    pub async fn mark_resume_step_attempted(
        &self,
        execution: &mut Execution,
        ordinal: u32,
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        let resume = execution
            .resume
            .as_mut()
            .ok_or(IdempotencyError::StateConflict)?;
        if execution.effect_attempted || resume.next_step != ordinal || now >= resume.expires_at {
            return Err(IdempotencyError::StateConflict);
        }
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        lock_async_artifact_fence(
            &transaction,
            resume.deployment_digest,
            resume.artifact_digest,
            now,
            false,
        )
        .await?;
        let updated_resume = transaction
            .execute(
                "UPDATE adapter_idempotency_resumes SET step_started = true \
                 WHERE scope_digest = $1 AND request_digest = $2 \
                   AND artifact_digest = $3 AND lease_id = $4 \
                   AND next_step = $5 AND expires_at > $6 AND lease_until > $6",
                &[
                    &execution.scope_digest.as_slice(),
                    &execution.request_digest.as_slice(),
                    &resume.artifact_digest.as_slice(),
                    &resume.lease_id.as_slice(),
                    &i32::try_from(ordinal).map_err(|_| IdempotencyError::StateConflict)?,
                    &now,
                ],
            )
            .await?;
        let updated_entry = transaction
            .execute(
                "UPDATE adapter_idempotency_entries \
                 SET state = 'effect_started', effect_started_at = COALESCE(effect_started_at, $3) \
                 WHERE scope_digest = $1 AND request_digest = $2 \
                   AND state IN ('claimed', 'effect_started')",
                &[
                    &execution.scope_digest.as_slice(),
                    &execution.request_digest.as_slice(),
                    &now,
                ],
            )
            .await?;
        if updated_resume != 1 || updated_entry != 1 {
            return Err(IdempotencyError::StateConflict);
        }
        transaction.commit().await?;
        execution.effect_attempted = true;
        Ok(())
    }

    /// Store only the successful non-final step's declared identifiers and
    /// advance its ordinal under the same lease.
    pub async fn checkpoint_resume_step(
        &self,
        execution: &mut Execution,
        ordinal: u32,
        bindings: &[crate::engine::ResumeValue],
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        let resume = execution
            .resume
            .as_mut()
            .ok_or(IdempotencyError::StateConflict)?;
        if !execution.effect_attempted
            || resume.next_step != ordinal
            || ordinal
                .checked_add(1)
                .is_none_or(|next| next >= resume.step_count)
            || bindings.len() > 16
            || now >= resume.expires_at
        {
            return Err(IdempotencyError::StateConflict);
        }
        let mut names = std::collections::HashSet::new();
        for binding in bindings {
            validate_resume_identifier(binding.name(), "resume binding name")?;
            validate_resume_identifier(binding.value(), "resume binding value")?;
            if !names.insert(binding.name()) {
                return Err(IdempotencyError::InvalidInput {
                    field: "resume binding name",
                });
            }
        }
        let next_step = ordinal + 1;
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        for binding in bindings {
            transaction
                .execute(
                    "INSERT INTO adapter_idempotency_resume_bindings \
                     (scope_digest, step_ordinal, name, value) VALUES ($1, $2, $3, $4)",
                    &[
                        &execution.scope_digest.as_slice(),
                        &i32::try_from(ordinal).map_err(|_| IdempotencyError::StateConflict)?,
                        &binding.name(),
                        &binding.value(),
                    ],
                )
                .await?;
        }
        let updated = transaction
            .execute(
                "UPDATE adapter_idempotency_resumes \
                 SET next_step = $5, step_started = false \
                 WHERE scope_digest = $1 AND request_digest = $2 \
                   AND artifact_digest = $3 AND lease_id = $4 \
                   AND next_step = $6 AND step_started \
                   AND expires_at > $7 AND lease_until > $7",
                &[
                    &execution.scope_digest.as_slice(),
                    &execution.request_digest.as_slice(),
                    &resume.artifact_digest.as_slice(),
                    &resume.lease_id.as_slice(),
                    &i32::try_from(next_step).map_err(|_| IdempotencyError::StateConflict)?,
                    &i32::try_from(ordinal).map_err(|_| IdempotencyError::StateConflict)?,
                    &now,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(IdempotencyError::StateConflict);
        }
        transaction.commit().await?;
        execution.effect_attempted = false;
        resume.next_step = next_step;
        Ok(())
    }

    /// End the current resumable lease after a route attempt has returned.
    /// A crash or cancellation never reaches this transition and therefore
    /// keeps the lease until its original finite expiry.
    pub async fn release_resume_lease(
        &self,
        execution: &Execution,
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        let resume = execution
            .resume
            .as_ref()
            .ok_or(IdempotencyError::StateConflict)?;
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                "UPDATE adapter_idempotency_resumes SET lease_until = $5 \
                 WHERE scope_digest = $1 AND request_digest = $2 \
                   AND artifact_digest = $3 AND lease_id = $4 \
                   AND expires_at > $5 AND lease_until > $5",
                &[
                    &execution.scope_digest.as_slice(),
                    &execution.request_digest.as_slice(),
                    &resume.artifact_digest.as_slice(),
                    &resume.lease_id.as_slice(),
                    &now,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(IdempotencyError::StateConflict);
        }
        Ok(())
    }

    /// Persist asynchronous recovery authority before a non-safe send.
    ///
    /// The uncertainty horizon covers the route's remaining finite deadline
    /// plus response retention. A later accepted commit replaces that horizon
    /// with one anchored at acceptance.
    pub async fn mark_async_effect_attempted(
        &self,
        execution: &mut Execution,
        request: ClaimRequest<'_>,
        attempt: AsyncEffectAttempt<'_>,
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        if execution.effect_attempted
            || scope_digest(&request) != execution.scope_digest
            || request.request_digest != execution.request_digest
            || request.concrete_operation != attempt.concrete_operation
        {
            return Err(IdempotencyError::StateConflict);
        }
        validate_claim_request(&request)?;
        validate_response_request_id(attempt.response_request_id)?;
        for (field, value) in [
            ("async binding id", attempt.binding_id),
            ("async profile operation", attempt.profile_operation),
            ("async concrete operation", attempt.concrete_operation),
            ("async record type", attempt.record_type),
        ] {
            validate_component(field, value.as_bytes(), MAX_ASYNC_IDENTIFIER_BYTES)?;
        }
        if let Some(recovery_id) = attempt.recovery_id {
            validate_recovery_id(recovery_id)?;
        }
        let remaining = attempt.effect_deadline.duration_since(now).map_err(|_| {
            IdempotencyError::InvalidInput {
                field: "async effect deadline",
            }
        })?;
        if remaining > EXCHANGE_DEADLINE {
            return Err(IdempotencyError::InvalidInput {
                field: "async effect deadline",
            });
        }
        let async_expires_at = attempt
            .effect_deadline
            .checked_add(self.response_retention)
            .ok_or(IdempotencyError::InvalidInput {
                field: "async recovery expiry",
            })?;
        let deployment_digest = async_deployment_digest(request.deployment);
        let binding_digest = async_binding_digest(&request, &attempt);
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        lock_async_artifact_fence(
            &transaction,
            deployment_digest,
            attempt.artifact_digest,
            now,
            false,
        )
        .await?;
        let updated = transaction
            .execute(
                "UPDATE adapter_idempotency_entries \
                 SET state = 'effect_started', effect_started_at = $3, \
                     response_request_id = $4, artifact_digest = $5, \
                     async_deployment_digest = $6, async_binding_digest = $7, \
                     async_binding_id = $8, async_profile_operation = $9, \
                     async_concrete_operation = $10, async_record_type = $11, \
                     async_recovery_id = $12, async_expires_at = $13 \
                 WHERE scope_digest = $1 AND request_digest = $2 AND state = 'claimed' \
                   AND claimed_at = $14",
                &[
                    &execution.scope_digest.as_slice(),
                    &execution.request_digest.as_slice(),
                    &now,
                    &attempt.response_request_id,
                    &attempt.artifact_digest.as_slice(),
                    &deployment_digest.as_slice(),
                    &binding_digest.as_slice(),
                    &attempt.binding_id,
                    &attempt.profile_operation,
                    &attempt.concrete_operation,
                    &attempt.record_type,
                    &attempt.recovery_id,
                    &async_expires_at,
                    &execution.claimed_at,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(IdempotencyError::StateConflict);
        }
        transaction.commit().await?;
        execution.effect_attempted = true;
        Ok(())
    }

    /// Commit exact accepted response custody.
    pub async fn accept(
        &self,
        execution: Execution,
        source_id: &str,
        response: StoredResponse,
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        let client = self.pool.get().await?;
        self.accept_with_client(&client, execution, source_id, response, now)
            .await
    }

    /// Commit accepted response custody through the caller's journal
    /// transaction so acceptance and `exchangeAccepted` are atomic.
    pub async fn accept_with_client(
        &self,
        client: &impl GenericClient,
        execution: Execution,
        source_id: &str,
        response: StoredResponse,
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        if !execution.effect_attempted || response.status != 202 {
            return Err(IdempotencyError::StateConflict);
        }
        validate_source_id(source_id)?;
        let expires_at = checked_retention_expiry(now, self.response_retention)?;
        let status =
            i16::try_from(response.status).map_err(|_| IdempotencyError::InvalidInput {
                field: "response status",
            })?;
        let updated = client
            .execute(
                "UPDATE adapter_idempotency_entries \
                 SET state = 'accepted', async_source_id = $3, \
                     async_accepted_at = $4, async_expires_at = $5, expires_at = $5, \
                     response_status = $6, response_content_type = $7, response_body = $8 \
                 WHERE scope_digest = $1 AND request_digest = $2 \
                   AND state = 'effect_started' \
                   AND response_request_id = $9 AND async_binding_digest IS NOT NULL \
                   AND async_poll_lease_id IS NULL AND async_expires_at > $4",
                &[
                    &execution.scope_digest.as_slice(),
                    &execution.request_digest.as_slice(),
                    &source_id,
                    &now,
                    &expires_at,
                    &status,
                    &response.content_type,
                    &response.body,
                    &response.request_id,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(IdempotencyError::StateConflict);
        }
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
                 WHERE scope_digest = $1 AND request_digest = $2 AND state = 'claimed' \
                   AND claimed_at = $3",
                &[
                    &execution.scope_digest.as_slice(),
                    &execution.request_digest.as_slice(),
                    &execution.claimed_at,
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
                     response_request_id = $9, async_source_id = NULL, \
                     async_recovery_id = NULL, async_poll_lease_id = NULL, \
                     async_poll_lease_until = NULL \
                 WHERE scope_digest = $1 AND request_digest = $2 AND state = $10 \
                   AND (state <> 'claimed' OR claimed_at = $11) \
                   AND (async_binding_digest IS NULL OR response_request_id = $9)",
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
                    &execution.claimed_at,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(IdempotencyError::StateConflict);
        }
        if execution.resume.is_some() {
            let deleted = client
                .execute(
                    "DELETE FROM adapter_idempotency_resumes \
                     WHERE scope_digest = $1 AND request_digest = $2",
                    &[
                        &execution.scope_digest.as_slice(),
                        &execution.request_digest.as_slice(),
                    ],
                )
                .await?;
            if deleted != 1 {
                return Err(IdempotencyError::StateConflict);
            }
        }
        Ok(())
    }

    /// Resolve one status handle only after its caller, deployment, request
    /// context and artifact binding match. A mismatch is deliberately
    /// indistinguishable from an unknown or expired handle.
    pub async fn lookup_status(
        &self,
        request: StatusLookupRequest<'_>,
        now: SystemTime,
    ) -> Result<StatusLookup, IdempotencyError> {
        validate_component(
            "deployment id",
            request.deployment.as_bytes(),
            MAX_DEPLOYMENT_IDENTITY_BYTES,
        )?;
        if validate_response_request_id(request.status_id).is_err() {
            return Ok(StatusLookup::NotFound);
        }
        let client = self.pool.get().await?;
        let Some(row) = client
            .query_opt(
                "SELECT scope_digest, request_digest, state, artifact_digest, \
                        async_binding_digest, async_binding_id, async_profile_operation, \
                        async_concrete_operation, async_record_type, async_expires_at, \
                        response_status, response_content_type, response_body, \
                        response_request_id \
                 FROM adapter_idempotency_entries \
                 WHERE response_request_id = $1 AND async_binding_digest IS NOT NULL \
                   AND async_expires_at > $2",
                &[&request.status_id, &now],
            )
            .await?
        else {
            return Ok(StatusLookup::NotFound);
        };
        let request_digest = fixed_digest(&row, "request_digest")?;
        let artifact_digest = fixed_digest(&row, "artifact_digest")?;
        if artifact_digest != request.artifact_digest {
            return Ok(StatusLookup::NotFound);
        }
        let metadata = status_metadata_from_row(&row)?;
        let expected = async_binding_digest_from_components(
            request.status_id,
            request.caller,
            request.deployment,
            &metadata,
            &request_digest,
            &artifact_digest,
        );
        let stored = fixed_digest(&row, "async_binding_digest")?;
        if expected != stored {
            return Ok(StatusLookup::NotFound);
        }
        let response = response_from_row(&row)?;
        let state: String = row.get("state");
        match state.as_str() {
            "accepted" => Ok(StatusLookup::Accepted(PendingStatusLookup {
                scope_digest: fixed_digest(&row, "scope_digest")?,
                request_digest,
                binding_digest: stored,
                artifact_digest,
                expires_at: row.get("async_expires_at"),
                metadata,
                response,
            })),
            "completed" => Ok(StatusLookup::Terminal {
                outcome: TerminalOutcome::Completed,
                metadata,
                response,
            }),
            "failed" => Ok(StatusLookup::Terminal {
                outcome: TerminalOutcome::Failed,
                metadata,
                response,
            }),
            _ => Ok(StatusLookup::NotFound),
        }
    }

    /// Acquire the accepted row's short source-poll lease.
    pub async fn acquire_status_recovery(
        &self,
        status: &PendingStatusLookup,
        now: SystemTime,
        requested_deadline: SystemTime,
    ) -> Result<RecoveryLease, IdempotencyError> {
        let lease_until = bounded_recovery_deadline(now, requested_deadline, status.expires_at)?;
        let lease_id = new_lease_id()?;
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "UPDATE adapter_idempotency_entries \
                 SET async_poll_lease_id = $4, async_poll_lease_until = $5 \
                 WHERE scope_digest = $1 AND request_digest = $2 \
                   AND async_binding_digest = $3 AND artifact_digest = $6 \
                   AND state = 'accepted' AND async_expires_at > $7 \
                   AND (async_poll_lease_id IS NULL OR async_poll_lease_until <= $7) \
                 RETURNING scope_digest, request_digest, state, artifact_digest, \
                           async_binding_digest, async_binding_id, async_profile_operation, \
                           async_concrete_operation, async_record_type, response_request_id, \
                           async_source_id, async_recovery_id",
                &[
                    &status.scope_digest.as_slice(),
                    &status.request_digest.as_slice(),
                    &status.binding_digest.as_slice(),
                    &lease_id.as_slice(),
                    &lease_until,
                    &status.artifact_digest.as_slice(),
                    &now,
                ],
            )
            .await?;
        match row {
            Some(row) => Ok(RecoveryLease::Acquired(Box::new(recovery_from_row(
                row, lease_id,
            )?))),
            None => {
                let busy = client
                    .query_opt(
                        "SELECT 1 FROM adapter_idempotency_entries \
                         WHERE scope_digest = $1 AND request_digest = $2 \
                           AND state = 'accepted' AND async_expires_at > $3 \
                           AND async_poll_lease_until > $3",
                        &[
                            &status.scope_digest.as_slice(),
                            &status.request_digest.as_slice(),
                            &now,
                        ],
                    )
                    .await?
                    .is_some();
                Ok(if busy {
                    RecoveryLease::Busy
                } else {
                    RecoveryLease::Stale
                })
            }
        }
    }

    /// Acquire uncertainty recovery only for the exact same key/request and
    /// an optional correlation committed before the non-safe send.
    pub async fn acquire_uncertain_recovery(
        &self,
        request: ClaimRequest<'_>,
        artifact_digest: [u8; 32],
        now: SystemTime,
        requested_deadline: SystemTime,
    ) -> Result<RecoveryLease, IdempotencyError> {
        validate_claim_request(&request)?;
        let lease_until = bounded_recovery_deadline(now, requested_deadline, requested_deadline)?;
        let scope_digest = scope_digest(&request);
        let lease_id = new_lease_id()?;
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "UPDATE adapter_idempotency_entries \
                 SET async_poll_lease_id = $4, \
                     async_poll_lease_until = LEAST($5, async_expires_at) \
                 WHERE scope_digest = $1 AND request_digest = $2 \
                   AND artifact_digest = $3 AND state = 'effect_started' \
                   AND async_recovery_id IS NOT NULL AND async_expires_at > $6 \
                   AND (async_poll_lease_id IS NULL OR async_poll_lease_until <= $6) \
                 RETURNING scope_digest, request_digest, state, artifact_digest, \
                           async_binding_digest, async_binding_id, async_profile_operation, \
                           async_concrete_operation, async_record_type, response_request_id, \
                           async_source_id, async_recovery_id",
                &[
                    &scope_digest.as_slice(),
                    &request.request_digest.as_slice(),
                    &artifact_digest.as_slice(),
                    &lease_id.as_slice(),
                    &lease_until,
                    &now,
                ],
            )
            .await?;
        match row {
            Some(row) => Ok(RecoveryLease::Acquired(Box::new(recovery_from_row(
                row, lease_id,
            )?))),
            None => {
                let busy = client
                    .query_opt(
                        "SELECT 1 FROM adapter_idempotency_entries \
                         WHERE scope_digest = $1 AND request_digest = $2 \
                           AND artifact_digest = $3 AND state = 'effect_started' \
                           AND async_recovery_id IS NOT NULL AND async_expires_at > $4 \
                           AND async_poll_lease_until > $4",
                        &[
                            &scope_digest.as_slice(),
                            &request.request_digest.as_slice(),
                            &artifact_digest.as_slice(),
                            &now,
                        ],
                    )
                    .await?
                    .is_some();
                Ok(if busy {
                    RecoveryLease::Busy
                } else {
                    RecoveryLease::Stale
                })
            }
        }
    }

    /// Release a proved-pending or uncertain recovery check. Dropped
    /// capabilities intentionally keep their lease until its deadline.
    pub async fn release_recovery(
        &self,
        recovery: Box<RecoveryExecution>,
    ) -> Result<(), IdempotencyError> {
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                "UPDATE adapter_idempotency_entries \
                 SET async_poll_lease_id = NULL, async_poll_lease_until = NULL \
                 WHERE scope_digest = $1 AND request_digest = $2 \
                   AND async_binding_digest = $3 AND artifact_digest = $4 \
                   AND state = $5 AND async_poll_lease_id = $6",
                &[
                    &recovery.scope_digest.as_slice(),
                    &recovery.request_digest.as_slice(),
                    &recovery.binding_digest.as_slice(),
                    &recovery.artifact_digest.as_slice(),
                    &recovery.state.as_str(),
                    &recovery.lease_id.as_slice(),
                ],
            )
            .await?;
        if updated == 1 {
            Ok(())
        } else {
            Err(IdempotencyError::StateConflict)
        }
    }

    /// Commit a terminal recovery using an ordinary connection.
    pub async fn finish_recovery(
        &self,
        recovery: Box<RecoveryExecution>,
        outcome: TerminalOutcome,
        response: StoredResponse,
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        let client = self.pool.get().await?;
        self.finish_recovery_with_client(&client, recovery, outcome, response, now)
            .await
    }

    /// Commit terminal response custody through the journal transaction.
    pub async fn finish_recovery_with_client(
        &self,
        client: &impl GenericClient,
        recovery: Box<RecoveryExecution>,
        outcome: TerminalOutcome,
        response: StoredResponse,
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        if response.request_id != recovery.response_request_id {
            return Err(IdempotencyError::StateConflict);
        }
        let expires_at = checked_retention_expiry(now, self.response_retention)?;
        let status =
            i16::try_from(response.status).map_err(|_| IdempotencyError::InvalidInput {
                field: "response status",
            })?;
        let updated = client
            .execute(
                "UPDATE adapter_idempotency_entries \
                 SET state = $7, terminal_at = $8, expires_at = $9, \
                     response_status = $10, response_content_type = $11, \
                     response_body = $12, async_source_id = NULL, \
                     async_recovery_id = NULL, async_poll_lease_id = NULL, \
                     async_poll_lease_until = NULL \
                 WHERE scope_digest = $1 AND request_digest = $2 \
                   AND async_binding_digest = $3 AND artifact_digest = $4 \
                   AND state = $5 AND async_poll_lease_id = $6 \
                   AND response_request_id = $13 \
                   AND async_poll_lease_until > $8 AND async_expires_at > $8",
                &[
                    &recovery.scope_digest.as_slice(),
                    &recovery.request_digest.as_slice(),
                    &recovery.binding_digest.as_slice(),
                    &recovery.artifact_digest.as_slice(),
                    &recovery.state.as_str(),
                    &recovery.lease_id.as_slice(),
                    &outcome.stored_state(),
                    &now,
                    &expires_at,
                    &status,
                    &response.content_type,
                    &response.body,
                    &response.request_id,
                ],
            )
            .await?;
        if updated == 1 {
            Ok(())
        } else {
            Err(IdempotencyError::StateConflict)
        }
    }

    /// Commit recovered acceptance through a journal transaction.
    pub async fn accept_recovery_with_client(
        &self,
        client: &impl GenericClient,
        recovery: Box<RecoveryExecution>,
        source_id: &str,
        response: StoredResponse,
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        if recovery.state != RecoveryState::EffectStarted
            || response.status != 202
            || response.request_id != recovery.response_request_id
        {
            return Err(IdempotencyError::StateConflict);
        }
        validate_source_id(source_id)?;
        let expires_at = checked_retention_expiry(now, self.response_retention)?;
        let status =
            i16::try_from(response.status).map_err(|_| IdempotencyError::InvalidInput {
                field: "response status",
            })?;
        let updated = client
            .execute(
                "UPDATE adapter_idempotency_entries \
                 SET state = 'accepted', async_source_id = $7, \
                     async_accepted_at = $8, async_expires_at = $9, expires_at = $9, \
                     response_status = $10, response_content_type = $11, \
                     response_body = $12, async_poll_lease_id = NULL, \
                     async_poll_lease_until = NULL \
                 WHERE scope_digest = $1 AND request_digest = $2 \
                   AND async_binding_digest = $3 AND artifact_digest = $4 \
                   AND state = 'effect_started' AND async_poll_lease_id = $5 \
                   AND response_request_id = $6 \
                   AND async_poll_lease_until > $8 AND async_expires_at > $8",
                &[
                    &recovery.scope_digest.as_slice(),
                    &recovery.request_digest.as_slice(),
                    &recovery.binding_digest.as_slice(),
                    &recovery.artifact_digest.as_slice(),
                    &recovery.lease_id.as_slice(),
                    &response.request_id,
                    &source_id,
                    &now,
                    &expires_at,
                    &status,
                    &response.content_type,
                    &response.body,
                ],
            )
            .await?;
        if updated == 1 {
            Ok(())
        } else {
            Err(IdempotencyError::StateConflict)
        }
    }

    /// Refuse an artifact activation while another artifact still owns live
    /// asynchronous recovery authority for the same logical deployment.
    pub async fn ensure_async_artifact_compatible(
        &self,
        deployment: &str,
        artifact_digest: [u8; 32],
        now: SystemTime,
    ) -> Result<(), IdempotencyError> {
        validate_component(
            "deployment id",
            deployment.as_bytes(),
            MAX_DEPLOYMENT_IDENTITY_BYTES,
        )?;
        let deployment_digest = async_deployment_digest(deployment);
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        lock_async_artifact_fence(&transaction, deployment_digest, artifact_digest, now, true)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Erase expired exact responses in one bounded, lock-skipping batch.
    ///
    /// Only response custody is erased. Scope and request digests remain as a
    /// spent tombstone, so a completed or uncertain effect is never reopened.
    /// An expired resume write that never marked a step attempted sent
    /// nothing, so its entry is removed and the key is free again.
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
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        let expired_resumes = transaction
            .query(
                "SELECT scope_digest FROM adapter_idempotency_resumes \
                 WHERE expires_at <= $1 ORDER BY expires_at, scope_digest \
                 FOR UPDATE SKIP LOCKED LIMIT $2",
                &[&now, &limit],
            )
            .await?;
        for row in &expired_resumes {
            let scope_digest: Vec<u8> = row.get(0);
            // Marking a step attempted moves the entry to effect_started
            // before any send, so a still-claimed entry sent nothing: its
            // key is freed (the resume row cascades), never spent.
            transaction
                .execute(
                    "DELETE FROM adapter_idempotency_entries \
                     WHERE scope_digest = $1 AND state = 'claimed'",
                    &[&scope_digest],
                )
                .await?;
            transaction
                .execute(
                    "DELETE FROM adapter_idempotency_resumes WHERE scope_digest = $1",
                    &[&scope_digest],
                )
                .await?;
        }
        let remaining = limit
            .checked_sub(i64::try_from(expired_resumes.len()).unwrap_or(limit))
            .unwrap_or(0);
        let rows = transaction
            .query(
                "WITH expired AS ( \
                     SELECT scope_digest FROM adapter_idempotency_entries \
                     WHERE (async_binding_digest IS NOT NULL AND async_expires_at <= $1) \
                        OR (state IN ('completed', 'failed') AND expires_at <= $1) \
                     ORDER BY LEAST(COALESCE(async_expires_at, expires_at), expires_at), \
                              scope_digest \
                     FOR UPDATE SKIP LOCKED LIMIT $2 \
                 ) \
                 UPDATE adapter_idempotency_entries AS entries \
                 SET state = CASE \
                         WHEN entries.state = 'accepted' THEN 'accepted_expired' \
                         WHEN entries.state = 'completed' AND entries.expires_at <= $1 \
                             THEN 'completed_expired' \
                         WHEN entries.state = 'failed' AND entries.expires_at <= $1 \
                             THEN 'failed_expired' \
                         ELSE entries.state END, \
                     response_status = CASE \
                         WHEN entries.state = 'accepted' \
                           OR (entries.state IN ('completed', 'failed') \
                               AND entries.expires_at <= $1) THEN NULL \
                         ELSE entries.response_status END, \
                     response_content_type = CASE \
                         WHEN entries.state = 'accepted' \
                           OR (entries.state IN ('completed', 'failed') \
                               AND entries.expires_at <= $1) THEN NULL \
                         ELSE entries.response_content_type END, \
                     response_body = CASE \
                         WHEN entries.state = 'accepted' \
                           OR (entries.state IN ('completed', 'failed') \
                               AND entries.expires_at <= $1) THEN NULL \
                         ELSE entries.response_body END, \
                     response_request_id = CASE \
                         WHEN entries.state IN ('accepted', 'effect_started') \
                           OR (entries.state IN ('completed', 'failed') \
                               AND entries.expires_at <= $1) THEN NULL \
                         ELSE entries.response_request_id END, \
                     artifact_digest = NULL, async_deployment_digest = NULL, \
                     async_binding_digest = NULL, async_binding_id = NULL, \
                     async_profile_operation = NULL, async_concrete_operation = NULL, \
                     async_record_type = NULL, async_source_id = NULL, \
                     async_recovery_id = NULL, async_accepted_at = NULL, \
                     async_expires_at = NULL, async_poll_lease_id = NULL, \
                     async_poll_lease_until = NULL \
                 FROM expired WHERE entries.scope_digest = expired.scope_digest \
                 RETURNING entries.scope_digest",
                &[&now, &remaining],
            )
            .await?;
        transaction.commit().await?;
        Ok((expired_resumes.len() + rows.len()) as u64)
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

fn validate_claim_request(request: &ClaimRequest<'_>) -> Result<(), IdempotencyError> {
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
    )
}

fn validate_response_request_id(value: &str) -> Result<(), IdempotencyError> {
    if value.len() == RESPONSE_REQUEST_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(IdempotencyError::InvalidInput {
            field: "response request id",
        })
    }
}

fn validate_recovery_id(value: &str) -> Result<(), IdempotencyError> {
    if value.len() == ASYNC_RECOVERY_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(IdempotencyError::InvalidInput {
            field: "async recovery id",
        })
    }
}

fn validate_source_id(value: &str) -> Result<(), IdempotencyError> {
    if value.is_empty()
        || value.len() > MAX_ASYNC_IDENTIFIER_BYTES
        || value.bytes().any(|byte| {
            !byte.is_ascii_graphic() || matches!(byte, b'/' | b'\\' | b'?' | b'#' | b'%' | b':')
        })
    {
        Err(IdempotencyError::InvalidInput {
            field: "async source id",
        })
    } else {
        Ok(())
    }
}

fn checked_retention_expiry(
    now: SystemTime,
    retention: Duration,
) -> Result<SystemTime, IdempotencyError> {
    now.checked_add(retention)
        .ok_or(IdempotencyError::InvalidInput {
            field: "response retention instant",
        })
}

fn bounded_recovery_deadline(
    now: SystemTime,
    requested: SystemTime,
    row_expiry: SystemTime,
) -> Result<SystemTime, IdempotencyError> {
    let remaining = requested
        .duration_since(now)
        .map_err(|_| IdempotencyError::InvalidInput {
            field: "recovery deadline",
        })?;
    if remaining.is_zero() || remaining > EXCHANGE_DEADLINE {
        return Err(IdempotencyError::InvalidInput {
            field: "recovery deadline",
        });
    }
    let lease_until = requested.min(row_expiry);
    if lease_until <= now {
        return Err(IdempotencyError::InvalidInput {
            field: "recovery deadline",
        });
    }
    Ok(lease_until)
}

fn new_lease_id() -> Result<[u8; RECOVERY_LEASE_ID_BYTES], IdempotencyError> {
    let mut lease_id = [0_u8; RECOVERY_LEASE_ID_BYTES];
    getrandom::fill(&mut lease_id).map_err(|_| IdempotencyError::InvalidInput {
        field: "recovery lease randomness",
    })?;
    Ok(lease_id)
}

fn update_framed(digest: &mut Sha256, component: &[u8]) {
    let length = u64::try_from(component.len()).expect("bounded digest component fits u64");
    digest.update(length.to_be_bytes());
    digest.update(component);
}

async fn lock_async_artifact_fence(
    client: &impl GenericClient,
    deployment_digest: [u8; 32],
    artifact_digest: [u8; 32],
    now: SystemTime,
    may_advance: bool,
) -> Result<(), IdempotencyError> {
    let lock_timeout = format!("{}ms", EXCHANGE_DEADLINE.as_millis());
    client
        .query_one(
            "SELECT set_config('lock_timeout', $1, true)",
            &[&lock_timeout],
        )
        .await?;
    client
        .execute(
            "INSERT INTO adapter_idempotency_async_artifacts \
             (deployment_digest, artifact_digest) VALUES ($1, $2) \
             ON CONFLICT (deployment_digest) DO NOTHING",
            &[&deployment_digest.as_slice(), &artifact_digest.as_slice()],
        )
        .await?;
    let row = client
        .query_one(
            "SELECT artifact_digest FROM adapter_idempotency_async_artifacts \
             WHERE deployment_digest = $1 FOR UPDATE",
            &[&deployment_digest.as_slice()],
        )
        .await?;
    let active_artifact: Vec<u8> = row.get(0);
    if !may_advance && active_artifact.as_slice() != artifact_digest {
        return Err(IdempotencyError::AsyncArtifactInUse);
    }
    // Only unfinished work carries recovery authority: an attempted or
    // accepted async effect, or an unexpired resume. A terminal row keeps its
    // binding for status replay, which is bound to its own artifact digest,
    // so it never blocks a hotfix or rollback.
    let incompatible = client
        .query_one(
            "SELECT count(*), max(expires_at) FROM ( \
                 SELECT artifact_digest, async_expires_at AS expires_at \
                 FROM adapter_idempotency_entries \
                 WHERE async_deployment_digest = $1 AND async_binding_digest IS NOT NULL \
                   AND state IN ('effect_started', 'accepted') AND async_expires_at > $3 \
                 UNION ALL \
                 SELECT artifact_digest, expires_at FROM adapter_idempotency_resumes \
                 WHERE deployment_digest = $1 AND expires_at > $3 \
             ) AS live WHERE artifact_digest <> $2",
            &[
                &deployment_digest.as_slice(),
                &artifact_digest.as_slice(),
                &now,
            ],
        )
        .await?;
    let unfinished: i64 = incompatible.get(0);
    if unfinished > 0 {
        let clears_by: Option<SystemTime> = incompatible.get(1);
        return Err(match (may_advance, clears_by) {
            (true, Some(clears_by)) => IdempotencyError::AsyncArtifactActivationRefused {
                unfinished,
                clears_by,
            },
            _ => IdempotencyError::AsyncArtifactInUse,
        });
    }
    if may_advance && active_artifact.as_slice() != artifact_digest {
        client
            .execute(
                "UPDATE adapter_idempotency_async_artifacts SET artifact_digest = $2 \
                 WHERE deployment_digest = $1",
                &[&deployment_digest.as_slice(), &artifact_digest.as_slice()],
            )
            .await?;
    }
    Ok(())
}

fn async_deployment_digest(deployment: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ASYNC_DEPLOYMENT_DIGEST_DOMAIN);
    update_framed(&mut digest, deployment.as_bytes());
    digest.finalize().into()
}

fn async_binding_digest(request: &ClaimRequest<'_>, attempt: &AsyncEffectAttempt<'_>) -> [u8; 32] {
    let metadata = StatusMetadata {
        binding_id: attempt.binding_id.to_owned(),
        profile_operation: attempt.profile_operation.to_owned(),
        concrete_operation: attempt.concrete_operation.to_owned(),
        record_type: attempt.record_type.to_owned(),
    };
    async_binding_digest_from_components(
        attempt.response_request_id,
        request.caller,
        request.deployment,
        &metadata,
        &request.request_digest,
        &attempt.artifact_digest,
    )
}

fn async_binding_digest_from_components(
    response_request_id: &str,
    caller: &VerifiedCallerIdentity,
    deployment: &str,
    metadata: &StatusMetadata,
    request_digest: &[u8; 32],
    artifact_digest: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ASYNC_BINDING_DIGEST_DOMAIN);
    for component in [
        response_request_id.as_bytes(),
        caller.issuer.as_bytes(),
        caller.subject.as_bytes(),
        caller.client_id.as_bytes(),
        deployment.as_bytes(),
        metadata.binding_id.as_bytes(),
        metadata.profile_operation.as_bytes(),
        metadata.concrete_operation.as_bytes(),
        metadata.record_type.as_bytes(),
        request_digest.as_slice(),
        artifact_digest.as_slice(),
    ] {
        update_framed(&mut digest, component);
    }
    digest.finalize().into()
}

fn fixed_digest(row: &Row, column: &str) -> Result<[u8; 32], IdempotencyError> {
    let value: Option<Vec<u8>> = row.get(column);
    value
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(IdempotencyError::StoredDataInvalid)
}

fn status_metadata_from_row(row: &Row) -> Result<StatusMetadata, IdempotencyError> {
    let bounded = |column: &str| -> Result<String, IdempotencyError> {
        let value: Option<String> = row.get(column);
        let value = value.ok_or(IdempotencyError::StoredDataInvalid)?;
        validate_component(
            "stored async identifier",
            value.as_bytes(),
            MAX_ASYNC_IDENTIFIER_BYTES,
        )
        .map_err(|_| IdempotencyError::StoredDataInvalid)?;
        Ok(value)
    };
    Ok(StatusMetadata {
        binding_id: bounded("async_binding_id")?,
        profile_operation: bounded("async_profile_operation")?,
        concrete_operation: bounded("async_concrete_operation")?,
        record_type: bounded("async_record_type")?,
    })
}

fn response_from_row(row: &Row) -> Result<StoredResponse, IdempotencyError> {
    let status: Option<i16> = row.get("response_status");
    let content_type: Option<Vec<u8>> = row.get("response_content_type");
    let body: Option<Vec<u8>> = row.get("response_body");
    let request_id: Option<String> = row.get("response_request_id");
    let status = status
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(IdempotencyError::StoredDataInvalid)?;
    StoredResponse::new(
        status,
        content_type.ok_or(IdempotencyError::StoredDataInvalid)?,
        body.ok_or(IdempotencyError::StoredDataInvalid)?,
        request_id.ok_or(IdempotencyError::StoredDataInvalid)?,
    )
    .map_err(|_| IdempotencyError::StoredDataInvalid)
}

fn recovery_from_row(
    row: Row,
    lease_id: [u8; RECOVERY_LEASE_ID_BYTES],
) -> Result<RecoveryExecution, IdempotencyError> {
    let state: String = row.get("state");
    let state = match state.as_str() {
        "accepted" => RecoveryState::Accepted,
        "effect_started" => RecoveryState::EffectStarted,
        _ => return Err(IdempotencyError::StoredDataInvalid),
    };
    let response_request_id: Option<String> = row.get("response_request_id");
    let response_request_id = response_request_id.ok_or(IdempotencyError::StoredDataInvalid)?;
    validate_response_request_id(&response_request_id)
        .map_err(|_| IdempotencyError::StoredDataInvalid)?;
    let source_id: Option<String> = row.get("async_source_id");
    let recovery_id: Option<String> = row.get("async_recovery_id");
    if state == RecoveryState::Accepted && source_id.is_none()
        || state == RecoveryState::EffectStarted && recovery_id.is_none()
    {
        return Err(IdempotencyError::StoredDataInvalid);
    }
    Ok(RecoveryExecution {
        scope_digest: fixed_digest(&row, "scope_digest")?,
        request_digest: fixed_digest(&row, "request_digest")?,
        binding_digest: fixed_digest(&row, "async_binding_digest")?,
        artifact_digest: fixed_digest(&row, "artifact_digest")?,
        lease_id,
        state,
        response_request_id,
        metadata: status_metadata_from_row(&row)?,
        source_id,
        recovery_id,
    })
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
        update_framed(&mut digest, component);
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
             SET state = CASE \
                     WHEN state = 'accepted' THEN 'accepted_expired' \
                     WHEN state = 'completed' AND expires_at <= $2 THEN 'completed_expired' \
                     WHEN state = 'failed' AND expires_at <= $2 THEN 'failed_expired' \
                     ELSE state END, \
                 response_status = CASE \
                     WHEN state = 'accepted' \
                       OR (state IN ('completed', 'failed') AND expires_at <= $2) THEN NULL \
                     ELSE response_status END, \
                 response_content_type = CASE \
                     WHEN state = 'accepted' \
                       OR (state IN ('completed', 'failed') AND expires_at <= $2) THEN NULL \
                     ELSE response_content_type END, \
                 response_body = CASE \
                     WHEN state = 'accepted' \
                       OR (state IN ('completed', 'failed') AND expires_at <= $2) THEN NULL \
                     ELSE response_body END, \
                 response_request_id = CASE \
                     WHEN state IN ('accepted', 'effect_started') \
                       OR (state IN ('completed', 'failed') AND expires_at <= $2) THEN NULL \
                     ELSE response_request_id END, \
                 artifact_digest = NULL, async_deployment_digest = NULL, \
                 async_binding_digest = NULL, async_binding_id = NULL, \
                 async_profile_operation = NULL, async_concrete_operation = NULL, \
                 async_record_type = NULL, async_source_id = NULL, \
                 async_recovery_id = NULL, async_accepted_at = NULL, \
                 async_expires_at = NULL, async_poll_lease_id = NULL, \
                 async_poll_lease_until = NULL \
             WHERE scope_digest = $1 AND ( \
                 (async_binding_digest IS NOT NULL AND async_expires_at <= $2) \
                 OR (state IN ('completed', 'failed') AND expires_at <= $2))",
            &[&scope_digest.as_slice(), &now],
        )
        .await?;
    Ok(())
}

async fn expire_resume_with_client(
    client: &impl GenericClient,
    scope_digest: &[u8; 32],
    now: SystemTime,
) -> Result<(), IdempotencyError> {
    // A still-claimed entry never marked a step attempted, so it sent
    // nothing: expiry frees its key (the resume row cascades) rather than
    // spending it.
    client
        .execute(
            "DELETE FROM adapter_idempotency_entries AS entries \
             WHERE scope_digest = $1 AND state = 'claimed' \
               AND EXISTS (SELECT 1 FROM adapter_idempotency_resumes AS resumes \
                           WHERE resumes.scope_digest = entries.scope_digest \
                             AND resumes.expires_at <= $2)",
            &[&scope_digest.as_slice(), &now],
        )
        .await?;
    client
        .execute(
            "DELETE FROM adapter_idempotency_resumes \
             WHERE scope_digest = $1 AND expires_at <= $2",
            &[&scope_digest.as_slice(), &now],
        )
        .await?;
    Ok(())
}

fn validate_resume_identifier(value: &str, field: &'static str) -> Result<(), IdempotencyError> {
    if value.is_empty()
        || value.len() > MAX_ASYNC_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(IdempotencyError::InvalidInput { field });
    }
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
        "effect_started" => Ok(Claim::EffectUnknown {
            effect_started_at: row
                .get::<_, Option<SystemTime>>("effect_started_at")
                .ok_or(IdempotencyError::StoredDataInvalid)?,
        }),
        "accepted" => replay_accepted_from_row(&row),
        "accepted_expired" => Ok(Claim::AcceptedExpired),
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

fn replay_accepted_from_row(row: &Row) -> Result<Claim, IdempotencyError> {
    let response = response_from_row(row)?;
    if response.status != 202 {
        return Err(IdempotencyError::StoredDataInvalid);
    }
    Ok(Claim::Accepted { response })
}

fn replay_from_row(row: &Row, outcome: TerminalOutcome) -> Result<Claim, IdempotencyError> {
    let response = response_from_row(row)?;
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
