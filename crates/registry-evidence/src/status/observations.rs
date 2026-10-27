//! The observation store and the staleness clock.
//!
//! The observation store keeps the latest observed mapped status per
//! requirement and selector pseudonym, so an allocation committed after a
//! hook it never saw inherits what the hook observed (concept 5.3 item 4).
//! Source revisions are per record, so two requirements that share a
//! selector profile keep separate observations. Recording an observation and
//! committing an allocation for the same subject serialize on
//! transaction-scoped advisory locks, one for the subject's pseudonym under
//! each key in the ring: an allocation either commits first, and is then
//! visible to whoever applies the observation to live allocations, or reads
//! the observation before it commits. Hook intake therefore records the
//! observation before it looks up live allocations. Two processes meet on a
//! lock only through a pseudonym key both hold, so a pseudonym key rotation
//! deploys the new key as retained on every process before promoting it.
//!
//! The staleness clock holds the last successful source observation time per
//! reconciliation extract, the one place an exact extract `publishedAt` may
//! persist. The status list publisher reads the oldest of the extracts it
//! serves, so one extract's fresh runs never hide another's failing ones.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use tokio_postgres::IsolationLevel;

use super::apply::status_column;
use super::error::StatusError;
use super::issuance::validate_requirement_id;
use super::ledger::{version_column, StatusLedger};
use super::pools::ReservedPool;
use super::provenance::{MappingVersion, SourceRevision};
use super::pseudonym::{StatusPseudonym, StatusSubject};
use super::transition::EntryStatus;

/// Advisory lock class that serializes observations and allocation commits
/// for one subject. The second keys are taken from the subject's pseudonym
/// under every key in the ring; two subjects that share one only wait for
/// each other.
pub(crate) const PSEUDONYM_LOCK_CLASS: i32 = 0x6576_7031;

/// Take the exclusive pseudonym locks ($1 the class, $2 the keys) in the
/// order given, in one statement.
pub(crate) const LOCK_PSEUDONYMS: &str = "SELECT pg_advisory_xact_lock($1, key) \
     FROM unnest($2::integer[]) WITH ORDINALITY AS keys(key, position) ORDER BY position";

/// Take the shared pseudonym locks ($1 the class, $2 the keys) in the order
/// given, in one statement.
pub(crate) const SHARE_PSEUDONYMS: &str = "SELECT pg_advisory_xact_lock_shared($1, key) \
     FROM unnest($2::integer[]) WITH ORDINALITY AS keys(key, position) ORDER BY position";

/// The second advisory lock key for a pseudonym.
pub(crate) fn pseudonym_lock_key(pseudonym: &StatusPseudonym) -> i32 {
    let bytes = pseudonym.as_bytes();
    i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// The lock keys for a subject's pseudonyms under every ring key, ascending
/// and without repeats. Every process takes all of them in this order, so
/// processes whose rings share a key meet on a common lock and never wait
/// on each other in opposite orders.
pub(crate) fn pseudonym_lock_keys(pseudonyms: &[StatusPseudonym]) -> Vec<i32> {
    let mut keys: Vec<i32> = pseudonyms.iter().map(pseudonym_lock_key).collect();
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// One observed mapped status for a subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    /// The status the mapping gives the observed source state.
    pub status: EntryStatus,
    /// The source record revision the observation reflects.
    pub revision: SourceRevision,
    /// The source's capture time of the change, for a hook the CloudEvent
    /// `time`.
    pub captured_at: DateTime<Utc>,
    /// The mapping version the status was mapped under.
    pub mapping_version: MappingVersion,
}

/// What recording an observation did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationOutcome {
    /// The observation is now the latest for its subject.
    Recorded,
    /// The store already holds a newer revision, or this revision under this
    /// mapping version or a newer one, so nothing changed.
    Stale,
}

/// The last successful source observation time. It is extract metadata:
/// `Debug` never shows it, and readiness reports only whether it is within
/// the staleness bound.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SourceObservationTime(DateTime<Utc>);

impl SourceObservationTime {
    #[must_use]
    pub const fn instant(&self) -> DateTime<Utc> {
        self.0
    }
}

impl fmt::Debug for SourceObservationTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceObservationTime([REDACTED])")
    }
}

fn failed(error: &tokio_postgres::Error) -> StatusError {
    StatusError::database(error)
}

/// The longest mapping block identifier the staleness clock stores.
const MAXIMUM_MAPPING_BLOCK_BYTES: usize = 256;

/// Refuse a mapping block identifier the staleness clock cannot store.
fn validate_mapping_block(mapping_block: &str) -> Result<(), StatusError> {
    if mapping_block.is_empty() || mapping_block.len() > MAXIMUM_MAPPING_BLOCK_BYTES {
        return Err(StatusError::InvalidInput(
            "the mapping block identifier must be 1 to 256 bytes",
        ));
    }
    Ok(())
}

impl StatusLedger {
    /// Record an observation of `subject`'s record for `requirement_id` if its
    /// source revision is newer than every one the store holds for that
    /// requirement and subject under any retained pseudonym key, or if it
    /// remaps the latest revision under a higher mapping version. The mapping
    /// version must be the highest registered one.
    pub async fn record_observation(
        &self,
        pool: &ReservedPool,
        requirement_id: &str,
        subject: &StatusSubject,
        observation: &Observation,
    ) -> Result<ObservationOutcome, StatusError> {
        validate_requirement_id(requirement_id)?;
        let pseudonym = self.pseudonym_keys.pseudonym(subject)?;
        let lookups = self.pseudonym_keys.lookup_pseudonyms(subject)?;
        let lock_keys = pseudonym_lock_keys(&lookups);
        let lookups: Vec<&[u8]> = lookups
            .iter()
            .map(|pseudonym| pseudonym.as_bytes().as_slice())
            .collect();
        let mut client = pool.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|error| failed(&error))?;
        self.require_current_mapping(&transaction, observation.mapping_version)
            .await?;
        transaction
            .execute(LOCK_PSEUDONYMS, &[&PSEUDONYM_LOCK_CLASS, &lock_keys])
            .await
            .map_err(|error| failed(&error))?;
        let latest: Option<(i64, i32)> = transaction
            .query_opt(
                &self.statements.latest_observation_provenance,
                &[&requirement_id, &lookups],
            )
            .await
            .map_err(|error| failed(&error))?
            .map(|row| (row.get(0), row.get(1)));
        let incoming = (
            observation.revision.get(),
            observation.mapping_version.column(),
        );
        if latest.is_some_and(|latest| latest >= incoming) {
            transaction
                .rollback()
                .await
                .map_err(|error| failed(&error))?;
            return Ok(ObservationOutcome::Stale);
        }
        transaction
            .execute(
                &self.statements.upsert_observation,
                &[
                    &requirement_id,
                    &pseudonym.as_bytes().as_slice(),
                    &version_column(pseudonym.key_version())?,
                    &status_column(observation.status),
                    &observation.revision.get(),
                    &observation.captured_at,
                    &observation.mapping_version.column(),
                ],
            )
            .await
            .map_err(|error| failed(&error))?;
        transaction.commit().await.map_err(|error| failed(&error))?;
        Ok(ObservationOutcome::Recorded)
    }

    /// Delete observations captured longer ago than `retention`, which the
    /// deployment checks against its floor at startup. Returns how many were
    /// deleted.
    pub async fn purge_observations(
        &self,
        pool: &ReservedPool,
        retention: Duration,
    ) -> Result<u64, StatusError> {
        let retention = i64::try_from(retention.as_millis())
            .ok()
            .filter(|milliseconds| *milliseconds > 0)
            .ok_or(StatusError::InvalidInput(
                "the observation retention must be positive and representable",
            ))?;
        let mut client = pool.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|error| failed(&error))?;
        let purged = transaction
            .execute(&self.statements.purge_observations, &[&retention])
            .await
            .map_err(|error| failed(&error))?;
        transaction.commit().await.map_err(|error| failed(&error))?;
        Ok(purged)
    }

    /// Set the staleness clock of the reconciliation extract that serves
    /// `mapping_block` after a complete run: to the extract's `publishedAt`,
    /// or to the run instant if that is earlier. An extract dated later than
    /// the run instant plus the clock-skew allowance is refused and leaves
    /// the clock where it was. Only a complete run calls this, so the clock
    /// is always the block's last complete run's observation, even when it is
    /// older than the one it replaces.
    pub async fn advance_staleness_clock(
        &self,
        pool: &ReservedPool,
        mapping_block: &str,
        published_at: DateTime<Utc>,
        run_instant: DateTime<Utc>,
    ) -> Result<(), StatusError> {
        validate_mapping_block(mapping_block)?;
        let latest_accepted = TimeDelta::from_std(self.clock_skew)
            .ok()
            .and_then(|skew| run_instant.checked_add_signed(skew));
        if latest_accepted.is_some_and(|latest| published_at > latest) {
            return Err(StatusError::InvalidInput(
                "the extract is dated later than the run instant plus the clock-skew allowance",
            ));
        }
        let observed = published_at.min(run_instant);
        let mut client = pool.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|error| failed(&error))?;
        transaction
            .execute(
                &self.statements.set_staleness_clock,
                &[&mapping_block, &observed],
            )
            .await
            .map_err(|error| failed(&error))?;
        transaction.commit().await.map_err(|error| failed(&error))
    }

    /// The oldest last successful source observation among the
    /// reconciliation extracts serving `mapping_blocks`, the ones a status
    /// list publisher serves. `None` until a complete run has set the clock
    /// of every one of them.
    pub async fn staleness_clock(
        &self,
        pool: &ReservedPool,
        mapping_blocks: &[&str],
    ) -> Result<Option<SourceObservationTime>, StatusError> {
        if mapping_blocks.is_empty() {
            return Err(StatusError::InvalidInput(
                "the staleness clock reads at least one mapping block",
            ));
        }
        for mapping_block in mapping_blocks {
            validate_mapping_block(mapping_block)?;
        }
        let mut blocks = mapping_blocks.to_vec();
        blocks.sort_unstable();
        blocks.dedup();
        let client = pool.client().await?;
        let row = client
            .query_one(&self.statements.staleness_clock, &[&blocks])
            .await
            .map_err(|error| failed(&error))?;
        let observed: i64 = row.get(0);
        let oldest: Option<DateTime<Utc>> = row.get(1);
        if usize::try_from(observed).ok() != Some(blocks.len()) {
            return Ok(None);
        }
        Ok(oldest.map(SourceObservationTime))
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::{pseudonym_lock_key, pseudonym_lock_keys, SourceObservationTime};
    use crate::status::{KeyVersion, StatusPseudonym};

    fn pseudonym(version: u32, prefix: [u8; 4]) -> StatusPseudonym {
        let mut digest = [0_u8; 32];
        digest[..4].copy_from_slice(&prefix);
        StatusPseudonym::from_parts(KeyVersion::new(version).unwrap(), digest)
    }

    #[test]
    fn the_lock_key_is_the_first_four_pseudonym_bytes() {
        assert_eq!(
            pseudonym_lock_key(&pseudonym(1, [0x80, 0x00, 0x00, 0x01])),
            i32::MIN + 1
        );
    }

    #[test]
    fn the_lock_keys_of_a_ring_are_ascending_and_distinct() {
        let keys = pseudonym_lock_keys(&[
            pseudonym(3, [0x00, 0x00, 0x00, 0x07]),
            pseudonym(2, [0x80, 0x00, 0x00, 0x01]),
            pseudonym(1, [0x00, 0x00, 0x00, 0x07]),
        ]);
        assert_eq!(keys, vec![i32::MIN + 1, 7]);
    }

    #[test]
    fn the_observation_time_never_formats() {
        let observed =
            SourceObservationTime(Utc.with_ymd_and_hms(2026, 10, 19, 3, 17, 29).unwrap());
        assert_eq!(format!("{observed:?}"), "SourceObservationTime([REDACTED])");
    }
}
