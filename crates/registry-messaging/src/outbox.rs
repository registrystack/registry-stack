// SPDX-License-Identifier: Apache-2.0

//! The audit outbox: records written inside the transaction whose change
//! they record, and the publisher that appends them to the keyed journal.
//!
//! A transition and its audit commit together or not at all. The publisher
//! then appends each pending record, oldest first, and marks it published.
//! A crash between the append and the mark leaves the record pending; on
//! startup the publisher reads the event id of the journal's last record
//! and marks that one published before it appends anything, so the record
//! is not appended twice.
//!
//! Every record is built by this crate from identifiers, classes, keyed
//! references, and dispositions. None carries a contact, a part, template
//! data, or provider text, so the journal receives the record as stored.

use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::audit::AuditJournal;
use crate::store::{PostgresStore, StoreError};
use registry_platform_dispatch::DispatchError;

/// How many pending records one publication pass appends at most.
const PUBLICATION_BATCH: i64 = 100;

/// Write `record` into the outbox with a fresh event id.
///
/// # Errors
///
/// [`DispatchError::Unavailable`] when `record` is not an object, already
/// carries an event id, or the insert fails.
pub(crate) async fn write(
    transaction: &Transaction<'_>,
    record: Value,
) -> Result<Uuid, DispatchError> {
    let event_id = Uuid::new_v4();
    let record = with_event_id(event_id, record).ok_or(DispatchError::Unavailable)?;
    let changed = transaction
        .execute(
            "INSERT INTO messaging_audit_outbox (event_id, audit_record) VALUES ($1, $2)",
            &[&event_id, &record],
        )
        .await?;
    if changed != 1 {
        return Err(DispatchError::Unavailable);
    }
    Ok(event_id)
}

fn with_event_id(event_id: Uuid, mut record: Value) -> Option<Value> {
    let fields = record.as_object_mut()?;
    if fields.contains_key("eventId") {
        return None;
    }
    fields.insert("eventId".to_owned(), Value::String(event_id.to_string()));
    Some(record)
}

/// Which step of a publication pass failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationFailure {
    PendingRead,
    JournalAppend,
    PublishedMark,
}

impl PublicationFailure {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingRead => "pending-read",
            Self::JournalAppend => "journal-append",
            Self::PublishedMark => "published-mark",
        }
    }
}

/// Appends the outbox to the journal.
pub struct Publisher {
    store: PostgresStore,
    journal: std::sync::Arc<AuditJournal>,
    /// A record the journal may hold that the outbox does not yet mark.
    unconfirmed: Option<Uuid>,
}

impl std::fmt::Debug for Publisher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Publisher")
            .field("unconfirmed", &self.unconfirmed)
            .finish_non_exhaustive()
    }
}

impl Publisher {
    /// A publisher that first confirms the last outbox record the journal
    /// held when it was opened.
    #[must_use]
    pub fn new(store: PostgresStore, journal: std::sync::Arc<AuditJournal>) -> Self {
        let unconfirmed = journal.last_event_id();
        Self {
            store,
            journal,
            unconfirmed,
        }
    }

    /// Append every pending record, up to one batch, and mark each
    /// published. Returns how many were appended.
    ///
    /// # Errors
    ///
    /// The step that failed. The records it did not mark stay pending for
    /// the next pass.
    pub async fn publish_pass(&mut self) -> Result<usize, PublicationFailure> {
        if let Some(event_id) = self.unconfirmed {
            mark_published(&self.store, event_id)
                .await
                .map_err(|_| PublicationFailure::PublishedMark)?;
            self.unconfirmed = None;
        }
        let pending = pending(&self.store, PUBLICATION_BATCH)
            .await
            .map_err(|_| PublicationFailure::PendingRead)?;
        let count = pending.len();
        for (event_id, record) in pending {
            self.journal
                .append(record)
                .await
                .map_err(|_| PublicationFailure::JournalAppend)?;
            self.unconfirmed = Some(event_id);
            mark_published(&self.store, event_id)
                .await
                .map_err(|_| PublicationFailure::PublishedMark)?;
            self.unconfirmed = None;
        }
        Ok(count)
    }

    /// Publish every `interval` until `shutdown` turns true. A failed pass
    /// is reported once per failing step and retried on the next tick.
    pub async fn run(mut self, interval: Duration, mut shutdown: watch::Receiver<bool>) {
        let mut failing: Option<PublicationFailure> = None;
        loop {
            match self.publish_pass().await {
                Ok(_) => {
                    if failing.take().is_some() {
                        tracing::info!("Messaging audit publication recovered");
                    }
                }
                Err(failure) => {
                    if failing != Some(failure) {
                        tracing::warn!(
                            stage = failure.as_str(),
                            "Messaging audit publication pass did not complete"
                        );
                        failing = Some(failure);
                    }
                }
            }
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        // One last pass so a clean stop leaves nothing
                        // pending that it could have published.
                        if let Err(failure) = self.publish_pass().await {
                            tracing::warn!(
                                stage = failure.as_str(),
                                "Messaging audit publication pass did not complete"
                            );
                        }
                        return;
                    }
                }
            }
        }
    }
}

async fn pending(store: &PostgresStore, maximum: i64) -> Result<Vec<(Uuid, Value)>, StoreError> {
    let client = store.client().await?;
    let rows = client
        .query(
            "SELECT event_id, audit_record FROM messaging_audit_outbox \
              WHERE published_at IS NULL ORDER BY recorded_seq LIMIT $1",
            &[&maximum],
        )
        .await?;
    rows.iter()
        .map(|row| Ok((row.try_get(0)?, row.try_get(1)?)))
        .collect()
}

async fn mark_published(store: &PostgresStore, event_id: Uuid) -> Result<(), StoreError> {
    let client = store.client().await?;
    client
        .execute(
            "UPDATE messaging_audit_outbox SET published_at = transaction_timestamp() \
              WHERE event_id = $1 AND published_at IS NULL",
            &[&event_id],
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_record_gains_one_event_id_and_a_preset_one_is_refused() {
        let id = Uuid::from_u128(1);
        let record = with_event_id(id, json!({"event": "x"})).unwrap();
        assert_eq!(record["eventId"], id.to_string());
        assert!(with_event_id(id, record).is_none());
        assert!(with_event_id(id, json!(["not", "an", "object"])).is_none());
    }
}
