// SPDX-License-Identifier: Apache-2.0

//! The value-free part of a PostgreSQL error, shared by the migration
//! rehearsal and `apply`.

use std::fmt;

use tokio_postgres::error::DbError;

/// The value-free part of one PostgreSQL error: its SQLSTATE and the schema
/// objects the server named. The message, detail, hint, and statement text
/// can carry row values and are never retained.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PostgresFailure {
    pub sqlstate: Option<String>,
    pub table: Option<String>,
    pub column: Option<String>,
    pub constraint: Option<String>,
}

impl PostgresFailure {
    /// Retain only the SQLSTATE and object names of one database error.
    #[must_use]
    pub fn from_error(error: &tokio_postgres::Error) -> Self {
        error
            .as_db_error()
            .map(Self::from_db_error)
            .unwrap_or_default()
    }

    fn from_db_error(error: &DbError) -> Self {
        Self {
            sqlstate: Some(error.code().code().to_owned()),
            table: error.table().map(str::to_owned),
            column: error.column().map(str::to_owned),
            constraint: error.constraint().map(str::to_owned),
        }
    }

    /// The SQLSTATE class name, from the first two characters of the code.
    #[must_use]
    pub fn class_name(&self) -> Option<&'static str> {
        self.sqlstate
            .as_deref()
            .and_then(|code| code.get(..2))
            .map(sqlstate_class_name)
    }
}

impl fmt::Display for PostgresFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(sqlstate) = &self.sqlstate else {
            return formatter.write_str("the database refused the statement");
        };
        write!(formatter, "SQLSTATE {sqlstate}")?;
        if let Some(class) = self.class_name() {
            write!(formatter, " ({class})")?;
        }
        for (label, value) in [
            ("table", &self.table),
            ("column", &self.column),
            ("constraint", &self.constraint),
        ] {
            if let Some(value) = value {
                write!(formatter, ", {label} {value}")?;
            }
        }
        Ok(())
    }
}

/// PostgreSQL's documented SQLSTATE class names (Appendix A).
fn sqlstate_class_name(class: &str) -> &'static str {
    match class {
        "08" => "connection exception",
        "0A" => "feature not supported",
        "21" => "cardinality violation",
        "22" => "data exception",
        "23" => "integrity constraint violation",
        "25" => "invalid transaction state",
        "28" => "invalid authorization specification",
        "2B" => "dependent privilege descriptors still exist",
        "40" => "transaction rollback",
        "42" => "syntax error or access rule violation",
        "44" => "WITH CHECK OPTION violation",
        "53" => "insufficient resources",
        "54" => "program limit exceeded",
        "55" => "object not in prerequisite state",
        "57" => "operator intervention",
        "58" => "system error",
        "P0" => "PL/pgSQL error",
        "XX" => "internal error",
        _ => "other PostgreSQL error class",
    }
}
