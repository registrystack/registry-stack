//! Errors from the status ledger store. No variant carries a selector value,
//! a pseudonym, a holder key value, or PostgreSQL's message or detail text,
//! which can quote the row that failed.

use std::fmt;

use thiserror::Error;

use super::pseudonym::PseudonymError;

/// Why a ledger operation failed.
#[derive(Debug, Error)]
pub enum StatusError {
    /// The ledger's own configuration is unusable.
    #[error("status ledger configuration is invalid: {0}")]
    Configuration(&'static str),
    /// The caller passed a value the ledger cannot store.
    #[error("status ledger input is invalid: {0}")]
    InvalidInput(&'static str),
    /// One batch needs more entries than half a list holds.
    #[error("a batch of {requested} credentials needs more than half a status list")]
    BatchTooLarge { requested: usize },
    /// No connection could be taken from the pool.
    #[error("the status ledger database is unavailable")]
    Unavailable,
    /// PostgreSQL refused or failed a statement.
    #[error("the status ledger database failed ({0})")]
    Database(SqlState),
    /// The issuance transaction's deadline passed; it was rolled back.
    #[error("the signing transaction deadline passed")]
    DeadlineExceeded,
    /// Repeated random draws found no unallocated index.
    #[error("no unallocated status list index was found")]
    IndexDrawExhausted,
    /// The operating system's random source failed.
    #[error("the random source failed")]
    Randomness,
    /// The issuance transaction already committed, rolled back or failed.
    #[error("the issuance transaction has already ended")]
    TransactionEnded,
    /// One issuance transaction allocates once, for every member of its batch.
    #[error("the issuance transaction has already allocated")]
    AlreadyAllocated,
    /// The database holds migrations this build does not know.
    #[error("the status ledger schema has migrations this build does not know")]
    SchemaVersion,
    /// A process presented a mapping version that is not the highest
    /// registered one, so it may not apply mapped status.
    #[error("mapping version {presented} is not the highest registered mapping version")]
    MappingVersionNotCurrent { presented: u32 },
    /// The status entry does not exist.
    #[error("the status entry does not exist")]
    UnknownEntry,
    /// A selector or holder key could not be keyed.
    #[error(transparent)]
    Pseudonym(#[from] PseudonymError),
}

impl StatusError {
    /// Whether the failure lies with a dependency (PostgreSQL, the pool, the
    /// deadline or the random source) and maps to the safe dependency
    /// category, rather than with the caller's input.
    #[must_use]
    pub const fn is_dependency(&self) -> bool {
        matches!(
            self,
            Self::Unavailable
                | Self::Database(_)
                | Self::DeadlineExceeded
                | Self::IndexDrawExhausted
                | Self::Randomness
        )
    }

    pub(crate) fn database(error: &tokio_postgres::Error) -> Self {
        Self::Database(SqlState(error.code().map(|code| code.code().to_owned())))
    }
}

/// The SQLSTATE of a failed statement, the only part of a PostgreSQL error
/// the ledger keeps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlState(Option<String>);

impl SqlState {
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

impl fmt::Display for SqlState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(code) => write!(formatter, "SQLSTATE {code}"),
            None => formatter.write_str("connection error"),
        }
    }
}
