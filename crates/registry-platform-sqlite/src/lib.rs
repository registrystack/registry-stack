//! Bounded read-only SQLite access for Registry Platform consumers.
//!
//! The crate owns the SQLite safety boundary, not a disclosure policy. A
//! consumer still reviews which schema objects and columns a compiled statement
//! may read. Every public failure is categorical and value-free.

mod capture;
mod error;
mod schema;
mod statement;

pub use capture::{CapturedSnapshot, LiveDatabaseFile};
pub use error::{cause, ErrorKind, SqliteError, TextLocation};
pub use schema::{
    inspect_schema, schema_fingerprint, InspectionLimits, SchemaCatalog, SchemaColumn,
    SchemaObject, SchemaObjectKind,
};
pub use statement::{
    check_statement_offline, ColumnContract, ColumnType, DatabaseProfile, DatabaseProfileKind,
    ExecutionProvenance, ParameterContract, ReadOnlyStatement, ResultRow, ResultSet, SchemaBinding,
    StatementContract, StatementLimits, Value,
};

#[cfg(feature = "fixture")]
pub use statement::materialize_fixture;
