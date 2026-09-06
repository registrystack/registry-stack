// SPDX-License-Identifier: Apache-2.0

//! How PostgreSQL reports stored bytes a statement could not read as JSON.

use tokio_postgres::error::SqlState;

/// The reader that met stored bytes it could not read. The value is closed and
/// names only the reader, so the operational log carries no row, key, byte, or
/// statement text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Site {
    HistoryRead,
    RevisionRead,
    IdempotencyCache,
}

impl Site {
    const fn as_str(self) -> &'static str {
        match self {
            Self::HistoryRead => "history_read",
            Self::RevisionRead => "revision_read",
            Self::IdempotencyCache => "idempotency_cache",
        }
    }
}

/// Report whether a statement failed because stored bytes could not be read as
/// UTF-8 JSON, and warn on the operational log when it did.
///
/// `convert_from(bytes, 'UTF8')` raises `character_not_in_repertoire` when the
/// stored bytes are not valid UTF-8, and the `::jsonb` cast that follows it
/// raises `invalid_text_representation` when the decoded text is not JSON.
/// Every other value the statements that read stored bytes cast is produced by
/// this crate from a value already validated against its declared type, so
/// those statements reach these two states through the stored bytes.
///
/// Callers classify the failure rather than reporting it as an outage. A
/// corrupted row reported as a transport failure is retried and stays hidden,
/// while the classification names the row as the stored state it is. The read
/// surfaces answer the refusal they always answered, so the warning is where an
/// operator sees that the refusal came from a row and not from the database.
#[must_use]
pub(crate) fn unreadable(error: &tokio_postgres::Error, site: Site) -> bool {
    let unreadable = error.code().is_some_and(|code| {
        code == &SqlState::CHARACTER_NOT_IN_REPERTOIRE
            || code == &SqlState::INVALID_TEXT_REPRESENTATION
    });
    if unreadable {
        tracing::warn!(
            target: "registry_breg::storage",
            site = site.as_str(),
            "stored bytes are unreadable as JSON"
        );
    }
    unreadable
}
