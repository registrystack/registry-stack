//! Applying transitions to allocated entries, and the mapping version
//! registry that decides which process may apply mapped ones.
//!
//! Every transition goes through [`super::transition`] inside one database
//! transaction that locks the entry, changes its status only from the status
//! the table was applied to, and writes the transitions row. Mapped causes
//! (hooks and reconciliation) apply only under the highest registered mapping
//! version.

use deadpool_postgres::Transaction as DatabaseTransaction;
use uuid::Uuid;

use super::error::StatusError;
use super::ledger::{StatusEntry, StatusLedger};
use super::pools::ReservedPool;
use super::provenance::{MappingVersion, Provenance, TransitionOutcome, TransitionRequest};
use super::transition::{transition, EntryStatus, Transition};

/// What registering a mapping version at startup found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingRegistration {
    /// The registered version is the highest; this process may apply mapped
    /// transitions.
    Current,
    /// A higher version is registered. This process applies no hook or
    /// reconciliation transition until it restarts on the current bundle; a
    /// bundle rollback must therefore bump the version.
    Superseded { highest: MappingVersion },
}

fn failed(error: &tokio_postgres::Error) -> StatusError {
    StatusError::database(error)
}

pub(crate) fn entry_status_column(code: i16) -> Result<EntryStatus, StatusError> {
    u8::try_from(code)
        .ok()
        .and_then(EntryStatus::from_code)
        .ok_or(StatusError::InvalidInput(
            "stored status code is not a status",
        ))
}

pub(crate) fn status_column(status: EntryStatus) -> i16 {
    i16::from(status.code())
}

impl StatusLedger {
    /// Record the mapping version this process runs. The ledger keeps the
    /// highest version any process has registered.
    pub async fn register_mapping_version(
        &self,
        pool: &ReservedPool,
        version: MappingVersion,
    ) -> Result<MappingRegistration, StatusError> {
        let client = pool.client().await?;
        let row = client
            .query_one(
                &self.statements.register_mapping_version,
                &[&version.column()],
            )
            .await
            .map_err(|error| failed(&error))?;
        let highest = MappingVersion::from_column(row.get(0))?;
        if highest == version {
            Ok(MappingRegistration::Current)
        } else {
            Ok(MappingRegistration::Superseded { highest })
        }
    }

    /// The highest registered mapping version, if any process registered one.
    pub async fn highest_mapping_version(
        &self,
        pool: &ReservedPool,
    ) -> Result<Option<MappingVersion>, StatusError> {
        let client = pool.client().await?;
        client
            .query_opt(&self.statements.highest_mapping_version, &[])
            .await
            .map_err(|error| failed(&error))?
            .map(|row| MappingVersion::from_column(row.get(0)))
            .transpose()
    }

    /// The current status of one entry.
    pub async fn entry_status(
        &self,
        pool: &ReservedPool,
        entry: &StatusEntry,
    ) -> Result<EntryStatus, StatusError> {
        let client = pool.client().await?;
        let row = client
            .query_opt(
                &self.statements.entry_status,
                &[&entry.list_id().as_str(), &entry.idx_column()?],
            )
            .await
            .map_err(|error| failed(&error))?
            .ok_or(StatusError::UnknownEntry)?;
        entry_status_column(row.get(0))
    }

    /// Apply one transition request under the fixed transition table.
    ///
    /// A hook or reconciliation request whose mapping version is not the
    /// highest registered one is refused with
    /// [`StatusError::MappingVersionNotCurrent`] and changes nothing. A
    /// request reflecting a source revision older than the entry's last
    /// applied one is [`TransitionOutcome::StaleRevision`].
    pub async fn apply_transition(
        &self,
        pool: &ReservedPool,
        request: &TransitionRequest,
    ) -> Result<TransitionOutcome, StatusError> {
        request.provenance.validate()?;
        let idx = request.entry.idx_column()?;
        let mut client = pool.client().await?;
        let transaction = client.transaction().await.map_err(|error| failed(&error))?;
        if let Some(presented) = request.provenance.mapping_version() {
            self.require_current_mapping(&transaction, presented)
                .await?;
        }
        let list_id = request.entry.list_id().as_str();
        let row = transaction
            .query_opt(&self.statements.lock_entry, &[&list_id, &idx])
            .await
            .map_err(|error| failed(&error))?
            .ok_or(StatusError::UnknownEntry)?;
        let from = entry_status_column(row.get(0))?;
        let last_applied: Option<i64> = row.get(1);
        let revision = request.provenance.revision();
        if let (Some(revision), Some(last_applied)) = (revision, last_applied) {
            if revision.get() < last_applied {
                return finish(transaction, TransitionOutcome::StaleRevision).await;
            }
        }
        // The mapping version stored with an entry is the one its last
        // applied source revision was mapped under.
        let revision_column = revision.map(|revision| revision.get());
        let revision_mapping = revision
            .and(request.provenance.mapping_version())
            .map(MappingVersion::column);
        let cause = request.provenance.cause();
        match transition(from, request.to, cause) {
            Err(refusal) => finish(transaction, TransitionOutcome::Refused(refusal)).await,
            Ok(Transition::Unchanged(status)) => {
                if let (Some(revision), Some(mapping)) = (revision_column, revision_mapping) {
                    transaction
                        .execute(
                            &self.statements.record_entry_revision,
                            &[&list_id, &idx, &revision, &mapping],
                        )
                        .await
                        .map_err(|error| failed(&error))?;
                }
                finish(transaction, TransitionOutcome::Unchanged(status)).await
            }
            Ok(Transition::Change { from, to }) => {
                let changed = transaction
                    .execute(
                        &self.statements.change_entry_status,
                        &[
                            &list_id,
                            &idx,
                            &status_column(to),
                            &status_column(from),
                            &revision_column,
                            &revision_mapping,
                        ],
                    )
                    .await
                    .map_err(|error| failed(&error))?;
                if changed != 1 {
                    return Err(StatusError::ConcurrentChange);
                }
                let transition_id = Uuid::new_v4();
                self.insert_transition(&transaction, transition_id, request, from, to)
                    .await?;
                finish(
                    transaction,
                    TransitionOutcome::Applied {
                        transition_id,
                        from,
                        to,
                    },
                )
                .await
            }
        }
    }

    /// Refuse a mapped cause unless `presented` is the highest registered
    /// version. The share lock holds the registry row until the caller's
    /// transaction ends.
    pub(crate) async fn require_current_mapping(
        &self,
        transaction: &DatabaseTransaction<'_>,
        presented: MappingVersion,
    ) -> Result<(), StatusError> {
        let highest = transaction
            .query_opt(&self.statements.share_highest_mapping_version, &[])
            .await
            .map_err(|error| failed(&error))?
            .map(|row| row.get::<_, i32>(0));
        if highest == Some(presented.column()) {
            Ok(())
        } else {
            Err(StatusError::MappingVersionNotCurrent {
                presented: presented.get(),
            })
        }
    }

    async fn insert_transition(
        &self,
        transaction: &DatabaseTransaction<'_>,
        transition_id: Uuid,
        request: &TransitionRequest,
        from: EntryStatus,
        to: EntryStatus,
    ) -> Result<(), StatusError> {
        let mut event_id = None;
        let mut package_revision = None;
        let mut event_source = None;
        let mut principals = None;
        let mut case_reference = None;
        let mut run_id = None;
        let mut extract_digest = None;
        match &request.provenance {
            Provenance::Hook {
                event_id: id,
                package_revision: package,
                source,
                ..
            } => {
                event_id = Some(id.as_str());
                package_revision = Some(package.as_str());
                event_source = Some(source.as_str());
            }
            Provenance::Operator {
                principals: names,
                case_reference: reference,
            } => {
                principals = Some(names.iter().map(|name| name.as_str()).collect::<Vec<_>>());
                case_reference = Some(reference.as_str());
            }
            Provenance::Reconciliation {
                run_id: id,
                extract_digest: digest,
                ..
            } => {
                run_id = Some(*id);
                extract_digest = Some(digest.as_slice());
            }
        }
        let mapping_version = request
            .provenance
            .mapping_version()
            .map(MappingVersion::column);
        let source_revision = request.provenance.revision().map(|revision| revision.get());
        transaction
            .execute(
                &self.statements.insert_transition,
                &[
                    &transition_id,
                    &request.entry.list_id().as_str(),
                    &request.entry.idx_column()?,
                    &status_column(from),
                    &status_column(to),
                    &request.provenance.cause().as_str(),
                    &mapping_version,
                    &request.reason.as_str(),
                    &event_id,
                    &source_revision,
                    &package_revision,
                    &event_source,
                    &principals,
                    &case_reference,
                    &run_id,
                    &extract_digest,
                ],
            )
            .await
            .map_err(|error| failed(&error))?;
        Ok(())
    }
}

/// Commit a transition's database transaction and report its outcome. A
/// request that changed nothing commits nothing it wrote.
async fn finish(
    transaction: DatabaseTransaction<'_>,
    outcome: TransitionOutcome,
) -> Result<TransitionOutcome, StatusError> {
    match outcome {
        TransitionOutcome::StaleRevision | TransitionOutcome::Refused(_) => transaction
            .rollback()
            .await
            .map_err(|error| failed(&error))?,
        TransitionOutcome::Applied { .. } | TransitionOutcome::Unchanged(_) => {
            transaction.commit().await.map_err(|error| failed(&error))?
        }
    }
    Ok(outcome)
}
