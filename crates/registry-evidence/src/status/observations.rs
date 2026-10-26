//! The observation store and the staleness clock.
//!
//! The observation store keeps the latest observed mapped status per selector
//! pseudonym, so an allocation committed after a hook it never saw inherits
//! what the hook observed (concept 5.3 item 4). Recording an observation and
//! committing an allocation for the same pseudonym serialize on a
//! transaction-scoped advisory lock: an allocation either commits first, and
//! is then visible to whoever applies the observation to live allocations,
//! or reads the observation before it commits. Hook intake therefore records
//! the observation before it looks up live allocations.
//!
//! The staleness clock holds the last successful source observation time,
//! the one place an exact extract `publishedAt` may persist.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};

use super::apply::status_column;
use super::error::StatusError;
use super::ledger::{version_column, StatusLedger};
use super::pools::ReservedPool;
use super::provenance::{MappingVersion, SourceRevision};
use super::pseudonym::{StatusPseudonym, StatusSubject};
use super::transition::EntryStatus;

/// Advisory lock class that serializes observations and allocation commits
/// for one pseudonym. The second key is taken from the pseudonym under the
/// current key; two pseudonyms that share it only wait for each other.
pub(crate) const PSEUDONYM_LOCK_CLASS: i32 = 0x6576_7031;

/// The second advisory lock key for a pseudonym.
pub(crate) fn pseudonym_lock_key(pseudonym: &StatusPseudonym) -> i32 {
    let bytes = pseudonym.as_bytes();
    i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
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
    /// The store already holds this revision or a newer one for the subject,
    /// so nothing changed.
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

impl StatusLedger {
    /// Record an observation for `subject` if it is newer than every one the
    /// store holds for it, under any retained pseudonym key. The mapping
    /// version must be the highest registered one.
    pub async fn record_observation(
        &self,
        pool: &ReservedPool,
        subject: &StatusSubject,
        observation: &Observation,
    ) -> Result<ObservationOutcome, StatusError> {
        let pseudonym = self.pseudonym_keys.pseudonym(subject)?;
        let lookups = self.pseudonym_keys.lookup_pseudonyms(subject)?;
        let lookups: Vec<&[u8]> = lookups
            .iter()
            .map(|pseudonym| pseudonym.as_bytes().as_slice())
            .collect();
        let mut client = pool.client().await?;
        let transaction = client.transaction().await.map_err(|error| failed(&error))?;
        self.require_current_mapping(&transaction, observation.mapping_version)
            .await?;
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock($1, $2)",
                &[&PSEUDONYM_LOCK_CLASS, &pseudonym_lock_key(&pseudonym)],
            )
            .await
            .map_err(|error| failed(&error))?;
        let latest: Option<i64> = transaction
            .query_one(&self.statements.latest_observed_revision, &[&lookups])
            .await
            .map_err(|error| failed(&error))?
            .get(0);
        if latest.is_some_and(|latest| latest >= observation.revision.get()) {
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
        let client = pool.client().await?;
        client
            .execute(&self.statements.purge_observations, &[&retention])
            .await
            .map_err(|error| failed(&error))
    }

    /// Set the staleness clock after a complete reconciliation run: to the
    /// extract's `publishedAt`, or to the run instant if that is earlier. An
    /// extract dated later than the run instant plus the clock-skew allowance
    /// is refused and leaves the clock where it was. Only a complete run
    /// calls this, so the clock is always the last complete run's
    /// observation, even when it is older than the one it replaces.
    pub async fn advance_staleness_clock(
        &self,
        pool: &ReservedPool,
        published_at: DateTime<Utc>,
        run_instant: DateTime<Utc>,
    ) -> Result<(), StatusError> {
        let latest_accepted = TimeDelta::from_std(self.clock_skew)
            .ok()
            .and_then(|skew| run_instant.checked_add_signed(skew));
        if latest_accepted.is_some_and(|latest| published_at > latest) {
            return Err(StatusError::InvalidInput(
                "the extract is dated later than the run instant plus the clock-skew allowance",
            ));
        }
        let observed = published_at.min(run_instant);
        let client = pool.client().await?;
        client
            .execute(&self.statements.set_staleness_clock, &[&observed])
            .await
            .map_err(|error| failed(&error))?;
        Ok(())
    }

    /// The last successful source observation time, if a complete run has
    /// set it.
    pub async fn staleness_clock(
        &self,
        pool: &ReservedPool,
    ) -> Result<Option<SourceObservationTime>, StatusError> {
        let client = pool.client().await?;
        Ok(client
            .query_opt(&self.statements.staleness_clock, &[])
            .await
            .map_err(|error| failed(&error))?
            .map(|row| SourceObservationTime(row.get(0))))
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::{pseudonym_lock_key, SourceObservationTime};
    use crate::status::{KeyVersion, StatusPseudonym};

    #[test]
    fn the_lock_key_is_the_first_four_pseudonym_bytes() {
        let mut digest = [0_u8; 32];
        digest[..4].copy_from_slice(&[0x80, 0x00, 0x00, 0x01]);
        let pseudonym = StatusPseudonym::from_parts(KeyVersion::new(1).unwrap(), digest);
        assert_eq!(pseudonym_lock_key(&pseudonym), i32::MIN + 1);
    }

    #[test]
    fn the_observation_time_never_formats() {
        let observed =
            SourceObservationTime(Utc.with_ymd_and_hms(2026, 10, 19, 3, 17, 29).unwrap());
        assert_eq!(format!("{observed:?}"), "SourceObservationTime([REDACTED])");
    }
}
