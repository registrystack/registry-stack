// SPDX-License-Identifier: Apache-2.0

//! The operator's replay of a dead-lettered job, shared by the content
//! verification and erasure jobs: what a listing reports, what a replay
//! returns, and how a replay the dispatcher did not finish is told apart.
//!
//! A replay runs through the dispatcher's generation-checked replay, which
//! writes the audit request before it changes the job and the audit
//! response after it commits. The job store keeps a [`ReplayTrace`] of the
//! last replay audit entry it was asked to write, so a replay that did not
//! finish is reported by what it left behind.

use std::sync::{Arc, Mutex, PoisonError};

use registry_platform_dispatch::postgres::{JobState, ReplayOutcome};
use registry_platform_dispatch::ConfigError;
use uuid::Uuid;

use crate::store::{PostgresStore, StoreError};

/// The most dead letters one operator listing returns.
pub const MAXIMUM_DEAD_LETTER_LISTING: u16 = 500;

/// A dead-lettered job, as an operator lists it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadLetter {
    pub version_id: Uuid,
    /// The generation a replay names as `--expected-generation`.
    pub generation: i64,
    pub attempt: i16,
    /// When the job was dead-lettered, in UTC, RFC 3339 to the second.
    pub dead_lettered_at: String,
}

/// A replayed job: pending again, at attempt zero, under a new generation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Replayed {
    pub version_id: Uuid,
    pub generation: i64,
}

/// Why an operator replay was refused. A refused replay changes nothing.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReplayRefusal {
    #[error("the version has no such job")]
    NotFound,
    #[error("the job is {state}; only a dead-lettered job is replayed")]
    NotDeadLettered { state: String },
    #[error("the job is at generation {current}; name it with --expected-generation {current}")]
    StaleGeneration { current: i64 },
    #[error("the job changed while it was replayed; list the dead letters and try again")]
    Changed,
    /// The version's removal was requested, or a rejection armed its
    /// erasure: its content is never verified again.
    #[error("{reason}, so its content is never verified again")]
    RemovalRequested { reason: &'static str },
}

/// A replay the dispatcher did not finish, and what it left behind.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReplayFailure {
    /// The replay's audit request was not written, so nothing was changed.
    #[error("the replay audit request could not be written; the job was not changed")]
    AuditUnavailable,
    /// The replay committed but its audit response was not written: the
    /// change stands.
    #[error("the job of {version_id} is pending at generation {generation}, but the replay's audit response was not written")]
    Unaudited { version_id: Uuid, generation: i64 },
    /// The database did not confirm whether the replay committed.
    #[error("the database did not confirm whether the replay of {version_id} committed")]
    OutcomeUnknown { version_id: Uuid },
    /// The database refused or lost the replay; the job is unchanged.
    #[error("the database did not complete the replay; the job is still dead-lettered")]
    DatabaseUnavailable,
}

/// A replay that was refused, that did not finish, or that could not reach
/// the database.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error(transparent)]
    Refused(#[from] ReplayRefusal),
    #[error(transparent)]
    Failed(ReplayFailure),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("the job dispatcher could not be built: {0}")]
    Dispatch(#[from] ConfigError),
}

impl From<tokio_postgres::Error> for ReplayError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Store(StoreError::Query(error))
    }
}

/// The last replay audit entry a job store was asked to write, and whether
/// it was written.
#[derive(Clone, Debug, Default)]
pub struct ReplayTrace(Arc<Mutex<Option<(ReplayOutcome, bool)>>>);

impl ReplayTrace {
    pub(crate) fn record(&self, outcome: ReplayOutcome, written: bool) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some((outcome, written));
    }

    fn last(&self) -> Option<(ReplayOutcome, bool)> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The state and generation of one job, or `None` when it is gone.
pub(crate) async fn job_state(
    store: &PostgresStore,
    table: &str,
    version_id: Uuid,
    part: &str,
) -> Result<Option<(String, i64)>, ReplayError> {
    let client = store.client().await?;
    let row = client
        .query_opt(
            &format!("SELECT state, generation FROM {table} WHERE version_id = $1 AND part = $2"),
            &[&version_id, &part],
        )
        .await?;
    Ok(match row {
        Some(row) => Some((row.try_get(0)?, row.try_get(1)?)),
        None => None,
    })
}

/// Refuse a replay of a job that is not dead-lettered at
/// `expected_generation`.
pub(crate) fn check_replayable(
    job: Option<(String, i64)>,
    expected_generation: i64,
) -> Result<(), ReplayRefusal> {
    let (state, current) = job.ok_or(ReplayRefusal::NotFound)?;
    if state != JobState::DeadLettered.as_str() {
        return Err(ReplayRefusal::NotDeadLettered { state });
    }
    if current != expected_generation {
        return Err(ReplayRefusal::StaleGeneration { current });
    }
    Ok(())
}

/// What a replay the dispatcher did not finish left behind, told apart by
/// the last audit entry `trace` holds and, when that does not decide it, by
/// reading the job in `table` again: a job still dead-lettered at the
/// expected generation was not changed by anyone, so the database failed
/// it; any other job was changed by someone else.
pub(crate) async fn unfinished(
    store: &PostgresStore,
    trace: &ReplayTrace,
    table: &str,
    version_id: Uuid,
    part: &str,
    expected_generation: i64,
) -> Result<ReplayError, ReplayError> {
    Ok(match trace.last() {
        Some((ReplayOutcome::Requested, false)) => {
            ReplayError::Failed(ReplayFailure::AuditUnavailable)
        }
        Some((ReplayOutcome::Committed, _)) => ReplayError::Failed(ReplayFailure::Unaudited {
            version_id,
            generation: expected_generation + 1,
        }),
        Some((ReplayOutcome::Unfinished, _)) => {
            ReplayError::Failed(ReplayFailure::OutcomeUnknown { version_id })
        }
        _ => {
            let unchanged = job_state(store, table, version_id, part).await?
                == Some((
                    JobState::DeadLettered.as_str().to_owned(),
                    expected_generation,
                ));
            if unchanged {
                ReplayError::Failed(ReplayFailure::DatabaseUnavailable)
            } else {
                ReplayRefusal::Changed.into()
            }
        }
    })
}
