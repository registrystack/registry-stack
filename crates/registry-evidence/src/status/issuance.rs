//! Status list allocation inside a caller-held issuance transaction.
//!
//! A status-required issuance takes a connection from the issuance pool,
//! allocates one entry per credential member, signs, and commits. Signing
//! happens while the transaction is open, so a credential is never returned
//! for an entry that was not committed. The whole sequence runs under one
//! deadline: past it, or on any failure, the connection is closed rather than
//! returned to the pool, and PostgreSQL rolls the transaction back. The server
//! also ends a session idle in transaction for longer than the deadline plus
//! five seconds, so a process stalled in its signer cannot hold entries. A
//! lock wait inside the transaction gives up when the deadline passes, so a
//! discarded session does not go on waiting while it holds its entries.
//!
//! Entries are written VALID. Just before the commit, under the subject's
//! pseudonym lock, the batch takes the status it inherits from the latest
//! observation for its requirement and subject (concept 5.3 item 4), so a
//! hook processed while the credential was being signed is not lost.

use std::time::Duration;

use chrono::{DateTime, Utc};
use deadpool_postgres::Object;
use rand_core::{OsRng, RngCore};
use tokio::time::{timeout_at, Instant};
use tokio_postgres::error::SqlState;

use super::apply::{entry_status_column, status_column};
use super::error::StatusError;
use super::inheritance::{inherited_status, ObservedStatus, SourceRead};
use super::ledger::{
    version_column, StatusEntry, StatusLedger, StatusListId, StatusReference, STATUS_LIST_BITS,
};
use super::observations::{pseudonym_lock_keys, PSEUDONYM_LOCK_CLASS, SHARE_PSEUDONYMS};
use super::pools::IssuancePool;
use super::pseudonym::{HolderKeyDigest, HolderKeyThumbprint, StatusSubject};
use super::transition::EntryStatus;

/// How long PostgreSQL lets an issuance session sit idle in transaction
/// beyond the signing deadline before it ends the session.
pub const IDLE_IN_TRANSACTION_MARGIN: Duration = Duration::from_secs(5);

/// Longest accepted requirement identifier, in bytes.
const MAXIMUM_REQUIREMENT_ID_BYTES: usize = 256;

/// Refuse a requirement identifier the ledger cannot store.
pub(crate) fn validate_requirement_id(requirement_id: &str) -> Result<(), StatusError> {
    if requirement_id.is_empty() || requirement_id.len() > MAXIMUM_REQUIREMENT_ID_BYTES {
        return Err(StatusError::InvalidInput(
            "the requirement identifier must be 1 to 256 bytes",
        ));
    }
    Ok(())
}

/// Random draws per member before the allocation gives up. Each list takes
/// at most half its entries, so a draw finds a free index at least half the
/// time and 64 failures in a row mean something other than chance.
const MAXIMUM_INDEX_DRAWS: usize = 64;

/// Advisory lock class that serializes list rotation within one schema.
const ROTATION_LOCK_CLASS: i32 = 0x6576_7231;

/// The stored values every member of one credential batch shares.
#[derive(Clone, Debug)]
pub struct AllocationFields<'a> {
    pub requirement_id: &'a str,
    pub subject: &'a StatusSubject,
    pub issued_at: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// When the evaluation behind this issuance read its source, which
    /// decides whether the batch inherits an observed status.
    pub source_read: SourceRead,
}

/// The members of one credential batch: one entry each.
#[derive(Clone, Copy, Debug)]
pub enum CredentialMembers<'a> {
    /// Credentials bound to no holder key.
    Unbound { count: usize },
    /// One credential per holder key, in order.
    HolderBound(&'a [HolderKeyThumbprint]),
}

impl CredentialMembers<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Unbound { count } => *count,
            Self::HolderBound(holders) => holders.len(),
        }
    }
}

enum State {
    /// Holding a connection; nothing allocated yet.
    Idle,
    /// An allocation is under way. If its future is dropped part way, the
    /// connection may be inside a transaction, so it is never reused.
    Allocating,
    /// Inside a database transaction that holds the batch's entries.
    Open,
    /// Committed, rolled back or failed; the connection is gone.
    Ended,
}

/// One status-required issuance: allocate, sign, then commit. Dropping it
/// without committing rolls the allocation back.
pub struct IssuanceTransaction<'l> {
    ledger: &'l StatusLedger,
    client: Option<Object>,
    deadline: Instant,
    idle_timeout: String,
    state: State,
    /// What the commit needs to apply the inherited status to the batch.
    inheritance: Option<Inheritance>,
}

/// The allocated batch and the requirement and subject keys its inherited
/// status is read by.
struct Inheritance {
    list_id: StatusListId,
    indices: Vec<i32>,
    requirement_id: String,
    lookup_pseudonyms: Vec<[u8; 32]>,
    lock_keys: Vec<i32>,
    source_read: SourceRead,
}

impl StatusLedger {
    /// Start an issuance transaction that must commit within `deadline`
    /// ([`super::DEFAULT_SIGNING_TRANSACTION_DEADLINE`] by default). The
    /// deadline covers taking the connection, allocating every member,
    /// signing, and committing.
    pub async fn begin(
        &self,
        pool: &IssuancePool,
        deadline: Duration,
    ) -> Result<IssuanceTransaction<'_>, StatusError> {
        if deadline.is_zero() {
            return Err(StatusError::InvalidInput(
                "the signing transaction deadline must be positive",
            ));
        }
        let idle_timeout = deadline
            .checked_add(IDLE_IN_TRANSACTION_MARGIN)
            .and_then(|timeout| i32::try_from(timeout.as_millis()).ok())
            .ok_or(StatusError::InvalidInput(
                "the signing transaction deadline is too long",
            ))?;
        let deadline = Instant::now()
            .checked_add(deadline)
            .ok_or(StatusError::InvalidInput(
                "the signing transaction deadline is too long",
            ))?;
        let client = timeout_at(deadline, pool.pool().get())
            .await
            .map_err(|_| StatusError::DeadlineExceeded)?
            .map_err(|_| StatusError::Unavailable)?;
        Ok(IssuanceTransaction {
            ledger: self,
            client: Some(client),
            deadline,
            idle_timeout: idle_timeout.to_string(),
            state: State::Idle,
            inheritance: None,
        })
    }
}

impl IssuanceTransaction<'_> {
    /// Allocate one entry per member, all on one list, and return their
    /// references in member order. One transaction allocates once.
    pub async fn allocate(
        &mut self,
        fields: &AllocationFields<'_>,
        members: CredentialMembers<'_>,
    ) -> Result<Vec<StatusReference>, StatusError> {
        match self.state {
            State::Idle => {}
            State::Allocating | State::Open => return Err(StatusError::AlreadyAllocated),
            State::Ended => return Err(StatusError::TransactionEnded),
        }
        let rows = self.rows(fields, members)?;
        let Some(client) = self.client.as_ref() else {
            return Err(StatusError::TransactionEnded);
        };
        self.state = State::Allocating;
        let result = if Instant::now() >= self.deadline {
            Err(StatusError::DeadlineExceeded)
        } else {
            timeout_at(
                self.deadline,
                allocate_rows(
                    self.ledger,
                    client,
                    self.deadline,
                    &self.idle_timeout,
                    &rows,
                ),
            )
            .await
            .unwrap_or(Err(StatusError::DeadlineExceeded))
        };
        match result {
            Ok(allocated) => {
                self.inheritance = Some(Inheritance {
                    list_id: allocated.list_id,
                    indices: allocated.indices,
                    requirement_id: rows.requirement_id,
                    lookup_pseudonyms: rows.lookup_pseudonyms,
                    lock_keys: rows.lock_keys,
                    source_read: fields.source_read,
                });
                self.state = State::Open;
                Ok(allocated.references)
            }
            Err(error) => {
                self.discard();
                Err(error)
            }
        }
    }

    /// Apply the inherited status to the batch, then commit. Past the
    /// deadline this returns [`StatusError::DeadlineExceeded`] and discards
    /// the connection: the transaction may have committed or rolled back;
    /// the signed credentials must not be issued either way.
    pub async fn commit(mut self) -> Result<(), StatusError> {
        match self.state {
            State::Ended => return Err(StatusError::TransactionEnded),
            State::Allocating => {
                self.discard();
                return Err(StatusError::TransactionEnded);
            }
            State::Idle => {
                self.state = State::Ended;
                return Ok(());
            }
            State::Open => {}
        }
        let (Some(client), Some(inheritance)) = (self.client.as_ref(), self.inheritance.as_ref())
        else {
            self.discard();
            return Err(StatusError::TransactionEnded);
        };
        let result = if Instant::now() >= self.deadline {
            Err(StatusError::DeadlineExceeded)
        } else {
            timeout_at(
                self.deadline,
                inherit_and_commit(self.ledger, client, self.deadline, inheritance),
            )
            .await
            .unwrap_or(Err(StatusError::DeadlineExceeded))
        };
        match result {
            Ok(()) => {
                // Back to the pool, outside any transaction.
                self.client = None;
                self.state = State::Ended;
                Ok(())
            }
            Err(error) => {
                self.discard();
                Err(error)
            }
        }
    }

    /// Validate the batch and key every member before touching the database.
    fn rows(
        &self,
        fields: &AllocationFields<'_>,
        members: CredentialMembers<'_>,
    ) -> Result<AllocationRows, StatusError> {
        validate_requirement_id(fields.requirement_id)?;
        if fields.not_after <= fields.issued_at {
            return Err(StatusError::InvalidInput(
                "a credential must expire after it is issued",
            ));
        }
        let source_read_hour = fields
            .source_read
            .read_hour()
            .ok_or(StatusError::InvalidInput(
                "the source read instant cannot be rounded to the hour",
            ))?;
        let count = members.len();
        if count == 0 {
            return Err(StatusError::InvalidInput(
                "a credential batch has at least one member",
            ));
        }
        if count > self.ledger.list_policy.allocation_limit() as usize {
            return Err(StatusError::BatchTooLarge { requested: count });
        }
        let pseudonym = self.ledger.pseudonym_keys.pseudonym(fields.subject)?;
        let lookups = self
            .ledger
            .pseudonym_keys
            .lookup_pseudonyms(fields.subject)?;
        let lock_keys = pseudonym_lock_keys(&lookups);
        let lookup_pseudonyms = lookups.iter().map(|lookup| *lookup.as_bytes()).collect();
        let holder_digests = match members {
            CredentialMembers::Unbound { count } => vec![None; count],
            CredentialMembers::HolderBound(holders) => holders
                .iter()
                .map(|holder| Some(self.ledger.holder_digest_keys.digest(holder)))
                .collect(),
        };
        Ok(AllocationRows {
            requirement_id: fields.requirement_id.to_owned(),
            selector_pseudonym: *pseudonym.as_bytes(),
            pseudonym_key_version: version_column(pseudonym.key_version())?,
            lookup_pseudonyms,
            lock_keys,
            issued_at: fields.issued_at,
            not_after: fields.not_after,
            source_read_hour,
            holder_digests,
        })
    }

    /// Close the connection instead of returning it to the pool, so
    /// PostgreSQL rolls back whatever it held.
    fn discard(&mut self) {
        if let Some(client) = self.client.take() {
            drop(Object::take(client));
        }
        self.state = State::Ended;
    }
}

impl Drop for IssuanceTransaction<'_> {
    fn drop(&mut self) {
        if matches!(self.state, State::Allocating | State::Open) {
            self.discard();
        }
    }
}

/// The keyed, validated values of one batch.
struct AllocationRows {
    requirement_id: String,
    selector_pseudonym: [u8; 32],
    pseudonym_key_version: i32,
    /// The subject's pseudonym under every retained key, for reading
    /// observations.
    lookup_pseudonyms: Vec<[u8; 32]>,
    /// The pseudonym lock keys under every ring key, ascending.
    lock_keys: Vec<i32>,
    issued_at: DateTime<Utc>,
    not_after: DateTime<Utc>,
    /// The source read, rounded down to the hour.
    source_read_hour: DateTime<Utc>,
    holder_digests: Vec<Option<HolderKeyDigest>>,
}

/// The entries one transaction allocated, all on one list.
struct Allocated {
    list_id: StatusListId,
    indices: Vec<i32>,
    references: Vec<StatusReference>,
}

/// The `lock_timeout` setting that ends a lock wait when the deadline
/// passes: the remaining time in milliseconds, at least one, since zero
/// would disable it.
fn remaining_lock_timeout(deadline: Instant) -> String {
    deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .max(1)
        .to_string()
}

/// A lock wait ended by the transaction's lock timeout is the deadline
/// passing; any other failure is the database's.
fn issuance_failure(error: &tokio_postgres::Error) -> StatusError {
    if error.code() == Some(&SqlState::LOCK_NOT_AVAILABLE) {
        StatusError::DeadlineExceeded
    } else {
        StatusError::database(error)
    }
}

async fn allocate_rows(
    ledger: &StatusLedger,
    client: &Object,
    deadline: Instant,
    idle_timeout: &str,
    rows: &AllocationRows,
) -> Result<Allocated, StatusError> {
    let count = rows.holder_digests.len();
    let (list_id, entry_count) = reserve(ledger, client, count).await?;
    let failed = |error: tokio_postgres::Error| issuance_failure(&error);
    client.batch_execute("BEGIN").await.map_err(failed)?;
    client
        .execute(
            "SELECT set_config('idle_in_transaction_session_timeout', $1, true), \
             set_config('lock_timeout', $2, true)",
            &[&idle_timeout, &remaining_lock_timeout(deadline)],
        )
        .await
        .map_err(failed)?;
    // Every entry starts VALID; the commit applies the inherited status.
    let status = status_column(EntryStatus::Valid);
    let mut indices = Vec::with_capacity(count);
    let mut references = Vec::with_capacity(count);
    for digest in &rows.holder_digests {
        let digest_bytes = digest.as_ref().map(|digest| digest.as_bytes().as_slice());
        let digest_version = digest
            .as_ref()
            .map(|digest| version_column(digest.key_version()))
            .transpose()?;
        let mut stored = None;
        for _ in 0..MAXIMUM_INDEX_DRAWS {
            let idx = i32::try_from(draw_index(entry_count)?)
                .map_err(|_| StatusError::IndexDrawExhausted)?;
            let inserted = client
                .query_opt(
                    &ledger.statements.insert_allocation,
                    &[
                        &list_id.as_str(),
                        &idx,
                        &digest_bytes,
                        &digest_version,
                        &rows.requirement_id,
                        &rows.selector_pseudonym.as_slice(),
                        &rows.pseudonym_key_version,
                        &rows.issued_at,
                        &rows.not_after,
                        &status,
                        &None::<i64>,
                        &None::<i32>,
                        &rows.source_read_hour,
                    ],
                )
                .await
                .map_err(failed)?;
            if inserted.is_some() {
                stored = Some(idx);
                break;
            }
        }
        let idx = stored.ok_or(StatusError::IndexDrawExhausted)?;
        indices.push(idx);
        let idx = u32::try_from(idx).map_err(|_| StatusError::IndexDrawExhausted)?;
        references.push(ledger.reference(StatusEntry::new(list_id.clone(), idx)));
    }
    Ok(Allocated {
        list_id,
        indices,
        references,
    })
}

/// Under the subject's shared pseudonym locks, which an observation being
/// recorded holds exclusively, give the batch the status it inherits from
/// the latest observation for its requirement, then commit. An observation,
/// inherited or not, also records its revision and mapping version, so a
/// delivery older than what the evaluation could have read is stale for
/// these entries.
async fn inherit_and_commit(
    ledger: &StatusLedger,
    client: &Object,
    deadline: Instant,
    inheritance: &Inheritance,
) -> Result<(), StatusError> {
    let failed = |error: tokio_postgres::Error| issuance_failure(&error);
    client
        .execute(
            "SELECT set_config('lock_timeout', $1, true)",
            &[&remaining_lock_timeout(deadline)],
        )
        .await
        .map_err(failed)?;
    client
        .execute(
            SHARE_PSEUDONYMS,
            &[&PSEUDONYM_LOCK_CLASS, &inheritance.lock_keys],
        )
        .await
        .map_err(failed)?;
    let lookups: Vec<&[u8]> = inheritance
        .lookup_pseudonyms
        .iter()
        .map(<[u8; 32]>::as_slice)
        .collect();
    let latest = client
        .query_opt(
            &ledger.statements.latest_observation,
            &[&inheritance.requirement_id, &lookups],
        )
        .await
        .map_err(failed)?;
    if let Some(row) = latest {
        let observed = ObservedStatus {
            status: entry_status_column(row.get(0))?,
            captured_at: row.get(2),
        };
        let status = inherited_status(Some(observed), inheritance.source_read, ledger.clock_skew);
        let revision: i64 = row.get(1);
        let mapping_version: i32 = row.get(3);
        client
            .execute(
                &ledger.statements.inherit,
                &[
                    &inheritance.list_id.as_str(),
                    &inheritance.indices,
                    &status_column(status),
                    &revision,
                    &mapping_version,
                ],
            )
            .await
            .map_err(failed)?;
    }
    client.batch_execute("COMMIT").await.map_err(failed)
}

/// Reserve `count` entries on the open list, rotating to a fresh list when
/// the open one would pass half its entries or has reached its age. The
/// reservation commits on its own, so a rolled-back issuance leaves its
/// entries counted and a list is never filled past half.
async fn reserve(
    ledger: &StatusLedger,
    client: &Object,
    count: usize,
) -> Result<(StatusListId, u32), StatusError> {
    let failed = |error: tokio_postgres::Error| StatusError::database(&error);
    let count =
        i32::try_from(count).map_err(|_| StatusError::BatchTooLarge { requested: count })?;
    let maximum_age = i64::try_from(ledger.list_policy.maximum_age().as_millis())
        .map_err(|_| StatusError::Configuration("the status list maximum age is too long"))?;
    if let Some(reserved) = reserve_open(ledger, client, count, maximum_age).await? {
        return Ok(reserved);
    }
    // A failure here discards the connection, which rolls the rotation back.
    client.batch_execute("BEGIN").await.map_err(failed)?;
    let (reserved, rotation) = rotate(ledger, client, count, maximum_age).await?;
    client.batch_execute("COMMIT").await.map_err(failed)?;
    if let Some((closed, opened)) = rotation {
        match closed {
            Some(closed) => tracing::info!(
                closed_list = %closed,
                opened_list = %opened,
                "status list closed and a fresh list opened"
            ),
            None => tracing::info!(opened_list = %opened, "status list opened"),
        }
    }
    Ok(reserved)
}

type Rotation = Option<(Option<StatusListId>, StatusListId)>;

/// Under the schema's rotation lock: reserve on the open list if another
/// issuance already rotated, otherwise close the open list and open a fresh
/// one holding this reservation.
async fn rotate(
    ledger: &StatusLedger,
    client: &Object,
    count: i32,
    maximum_age: i64,
) -> Result<((StatusListId, u32), Rotation), StatusError> {
    let failed = |error: tokio_postgres::Error| StatusError::database(&error);
    client
        .execute(
            "SELECT pg_advisory_xact_lock($1, hashtext($2))",
            &[&ROTATION_LOCK_CLASS, &ledger.schema.as_str()],
        )
        .await
        .map_err(failed)?;
    if let Some(reserved) = reserve_open(ledger, client, count, maximum_age).await? {
        return Ok((reserved, None));
    }
    let closed = client
        .query_opt(&ledger.statements.close_open_list, &[])
        .await
        .map_err(failed)?
        .map(|row| StatusListId::parse(row.get::<_, &str>(0)))
        .transpose()?;
    let opened = StatusListId::generate()?;
    let entry_count = ledger.list_policy.entry_count();
    let entry_count_column = i32::try_from(entry_count)
        .map_err(|_| StatusError::Configuration("the status list entry count is too large"))?;
    client
        .execute(
            &ledger.statements.open_list,
            &[
                &opened.as_str(),
                &entry_count_column,
                &STATUS_LIST_BITS,
                &count,
            ],
        )
        .await
        .map_err(failed)?;
    Ok(((opened.clone(), entry_count), Some((closed, opened))))
}

async fn reserve_open(
    ledger: &StatusLedger,
    client: &Object,
    count: i32,
    maximum_age: i64,
) -> Result<Option<(StatusListId, u32)>, StatusError> {
    let Some(row) = client
        .query_opt(&ledger.statements.reserve, &[&count, &maximum_age])
        .await
        .map_err(|error| StatusError::database(&error))?
    else {
        return Ok(None);
    };
    let list_id = StatusListId::parse(row.get::<_, &str>(0))?;
    let entry_count = u32::try_from(row.get::<_, i32>(1))
        .map_err(|_| StatusError::InvalidInput("stored status list entry count is negative"))?;
    Ok(Some((list_id, entry_count)))
}

/// A uniformly random index below `entry_count` from the operating system's
/// CSPRNG. Draws at or above the largest multiple of `entry_count` that fits
/// in 32 bits are rejected, so no index is more likely than another.
fn draw_index(entry_count: u32) -> Result<u32, StatusError> {
    let modulus = u64::from(entry_count.max(1));
    let zone = (1_u64 << 32) / modulus * modulus;
    loop {
        let mut bytes = [0_u8; 4];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| StatusError::Randomness)?;
        let value = u64::from(u32::from_le_bytes(bytes));
        if value < zone {
            return u32::try_from(value % modulus).map_err(|_| StatusError::Randomness);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::draw_index;

    #[test]
    fn index_draws_stay_below_the_entry_count_and_reach_every_index() {
        for entry_count in [2_u32, 3, 8, 1000] {
            for _ in 0..200 {
                assert!(draw_index(entry_count).unwrap() < entry_count);
            }
        }
        let mut seen = BTreeMap::new();
        for _ in 0..4000 {
            *seen.entry(draw_index(8).unwrap()).or_insert(0_u32) += 1;
        }
        assert_eq!(seen.len(), 8);
        // Each index expects 500 draws; 300 is far outside chance.
        assert!(seen.values().all(|hits| *hits > 300), "{seen:?}");
    }
}
