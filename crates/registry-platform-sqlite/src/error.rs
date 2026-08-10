use thiserror::Error;

/// Stable, value-free cause text retained for compatibility adapters.
pub mod cause {
    pub const MULTIPLE_STATEMENTS: &str = "the artifact holds more than one statement";
    pub const INVALID_SQL: &str = "the statement is not valid SQL";
    pub const UNKNOWN_TABLE: &str = "the statement names a table the extract does not have";
    pub const UNKNOWN_COLUMN: &str = "the statement names a column the extract does not have";
    pub const COLUMN_MISMATCH: &str = "the result columns disagree with the declared columns";
    pub const UNDECLARED_PARAMETER: &str = "a statement parameter has no declared binding";
    pub const UNUSED_BINDING: &str = "a declared binding names no statement parameter";
    pub const MISSING_PARAMETER: &str = "a statement parameter has no supplied value";
    pub const AUTHORIZER_REFUSED: &str = "the authorizer refused the statement";
    pub const STEP_BUDGET_EXCEEDED: &str = "the statement exceeded its step budget";
    pub const TIME_BUDGET_EXCEEDED: &str = "the statement exceeded its time budget";
    pub const TOO_MANY_ROWS: &str = "the result exceeded the declared row bound";
    pub const CELL_TOO_LARGE: &str = "a result value exceeded the declared cell size bound";
    pub const RESPONSE_TOO_LARGE: &str = "the result exceeded the declared response size bound";
    pub const VALUE_TYPE_MISMATCH: &str = "a result value disagrees with its declared column type";
    pub const EXECUTION_FAILED: &str = "the statement failed while its result was read";
    pub const DATABASE_UNAVAILABLE: &str = "the database file could not be opened";
    pub const DATABASE_REPLACED: &str = "the database path no longer names the captured file";
    pub const DATABASE_WRITABLE: &str = "the snapshot database file is writable";
    pub const DATABASE_SYMLINK: &str = "the database path is a symbolic link";
    pub const DATABASE_NOT_FILE: &str = "the database path is not a regular file";
    pub const DATABASE_CHANGED: &str = "the database file changed while it was captured";
    pub const UNCHECKPOINTED_SIDECAR: &str = "the snapshot database has an uncheckpointed sidecar";
    pub const SCHEMA_BUDGET_EXCEEDED: &str = "schema inspection exceeded its declared budget";
    pub const SCHEMA_MALFORMED: &str = "the database schema is malformed";
    pub const SCHEMA_MISMATCH: &str = "the database schema fingerprint does not match";
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TextLocation {
    pub line: usize,
    pub column: usize,
}

/// Closed machine-readable SQLite failure categories.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    InvalidPlan,
    MultipleStatements,
    InvalidSql,
    UnknownTable,
    UnknownColumn,
    ColumnMismatch,
    UndeclaredParameter,
    UnusedBinding,
    MissingParameter,
    AuthorizerRefused,
    StepBudgetExceeded,
    TimeBudgetExceeded,
    TooManyRows,
    CellTooLarge,
    ResponseTooLarge,
    ValueTypeMismatch,
    ExecutionFailed,
    DatabaseUnavailable,
    DatabaseReplaced,
    DatabaseWritable,
    DatabaseSymlink,
    DatabaseNotFile,
    DatabaseChanged,
    UncheckpointedSidecar,
    SchemaBudgetExceeded,
    SchemaMalformed,
    SchemaMismatch,
    Concurrency,
    Timeout,
    WorkerUnavailable,
}

impl ErrorKind {
    #[must_use]
    pub const fn cause(self) -> &'static str {
        match self {
            Self::InvalidPlan => "the SQLite read plan is invalid",
            Self::MultipleStatements => cause::MULTIPLE_STATEMENTS,
            Self::InvalidSql => cause::INVALID_SQL,
            Self::UnknownTable => cause::UNKNOWN_TABLE,
            Self::UnknownColumn => cause::UNKNOWN_COLUMN,
            Self::ColumnMismatch => cause::COLUMN_MISMATCH,
            Self::UndeclaredParameter => cause::UNDECLARED_PARAMETER,
            Self::UnusedBinding => cause::UNUSED_BINDING,
            Self::MissingParameter => cause::MISSING_PARAMETER,
            Self::AuthorizerRefused => cause::AUTHORIZER_REFUSED,
            Self::StepBudgetExceeded => cause::STEP_BUDGET_EXCEEDED,
            Self::TimeBudgetExceeded => cause::TIME_BUDGET_EXCEEDED,
            Self::TooManyRows => cause::TOO_MANY_ROWS,
            Self::CellTooLarge => cause::CELL_TOO_LARGE,
            Self::ResponseTooLarge => cause::RESPONSE_TOO_LARGE,
            Self::ValueTypeMismatch => cause::VALUE_TYPE_MISMATCH,
            Self::ExecutionFailed => cause::EXECUTION_FAILED,
            Self::DatabaseUnavailable => cause::DATABASE_UNAVAILABLE,
            Self::DatabaseReplaced => cause::DATABASE_REPLACED,
            Self::DatabaseWritable => cause::DATABASE_WRITABLE,
            Self::DatabaseSymlink => cause::DATABASE_SYMLINK,
            Self::DatabaseNotFile => cause::DATABASE_NOT_FILE,
            Self::DatabaseChanged => cause::DATABASE_CHANGED,
            Self::UncheckpointedSidecar => cause::UNCHECKPOINTED_SIDECAR,
            Self::SchemaBudgetExceeded => cause::SCHEMA_BUDGET_EXCEEDED,
            Self::SchemaMalformed => cause::SCHEMA_MALFORMED,
            Self::SchemaMismatch => cause::SCHEMA_MISMATCH,
            Self::Concurrency => "the SQLite concurrency boundary is unavailable",
            Self::Timeout => "the SQLite read exceeded its time limit",
            Self::WorkerUnavailable => "the SQLite execution worker is unavailable",
        }
    }
}

/// A categorical failure that retains no SQL, path, bound value, or row value.
#[derive(Debug, Clone, Eq, PartialEq, Error)]
#[error("{kind_cause}")]
pub struct SqliteError {
    kind: ErrorKind,
    kind_cause: &'static str,
    location: Option<TextLocation>,
}

impl SqliteError {
    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            kind_cause: kind.cause(),
            location: None,
        }
    }

    pub(crate) const fn at(kind: ErrorKind, location: TextLocation) -> Self {
        Self {
            kind,
            kind_cause: kind.cause(),
            location: Some(location),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn cause(&self) -> &'static str {
        self.kind_cause
    }

    #[must_use]
    pub const fn location(&self) -> Option<TextLocation> {
        self.location
    }
}
