// SPDX-License-Identifier: Apache-2.0

//! How PostgreSQL reports stored bytes a statement could not read as JSON.

use tokio_postgres::error::SqlState;

/// Report whether a statement failed because stored bytes could not be read as
/// UTF-8 JSON.
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
/// while the classification names the row as the stored state it is.
#[must_use]
pub(crate) fn unreadable(error: &tokio_postgres::Error) -> bool {
    error.code().is_some_and(|code| {
        code == &SqlState::CHARACTER_NOT_IN_REPERTOIRE
            || code == &SqlState::INVALID_TEXT_REPRESENTATION
    })
}
