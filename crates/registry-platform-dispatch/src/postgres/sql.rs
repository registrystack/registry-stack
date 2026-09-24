// SPDX-License-Identifier: Apache-2.0

//! The product-supplied SQL fragments and extra columns, and the checks
//! that keep them inside the statements the core builds.
//!
//! Fragments are `&'static str`: they are the consumer's own source text,
//! never request input. Every value travels as a bind parameter. The checks
//! below refuse a fragment that could end the core's statement or comment
//! out the rest of it, so the fence predicates, lock clauses, and limits the
//! core appends always apply.

use tokio_postgres::types::ToSql;

use super::table::{JobState, JobTable, CORE_COLUMNS};
use crate::identifier::is_plain_identifier;
use crate::outcome::{ConfigError, DispatchError};

/// One consumer-supplied SELECT extension.
///
/// The job table is always aliased `state`. `columns` lists the extra
/// columns the store decodes, in order, after the core columns; `joins`
/// joins the consumer's own tables; `predicate` is a boolean expression the
/// row must also satisfy. Each may name the consumer schema as `{schema}`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectSql {
    pub columns: &'static str,
    pub joins: &'static str,
    pub predicate: &'static str,
}

/// How undispatched jobs expire before they are claimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpirySql {
    /// The states an expiring job may be in. A pending job becomes
    /// `expired`; a job in any other listed state keeps its state and has
    /// `expired_at` stamped. Only [`JobState::Pending`] and
    /// [`JobState::DeadLettered`] are accepted.
    pub states: &'static [JobState],
    /// The selection of jobs that have expired.
    pub select: SelectSql,
    /// The ORDER BY expression list, before the core's key tiebreak.
    pub order_by: &'static str,
    /// The comma-separated aliases to lock, which must include `state`.
    pub lock_of: &'static str,
}

/// Every consumer-supplied extension the core's statements take.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchSql {
    /// The due-job claim. Its columns carry the job's captured policy and
    /// whatever the transport needs.
    pub claim: SelectSql,
    /// The lapsed-lease recovery. Its columns carry the captured policy.
    pub lapsed: SelectSql,
    /// The expiry of undispatched jobs, when the consumer expires any.
    pub expiry: Option<ExpirySql>,
    /// The operator replay and cancel target.
    pub target: SelectSql,
}

/// A rendered SELECT extension: the column list with its leading comma,
/// the joins, and the predicate.
#[derive(Clone, Debug)]
pub(crate) struct RenderedSelect {
    pub columns: String,
    pub joins: String,
    pub predicate: String,
}

impl SelectSql {
    pub(crate) fn render(&self, table: &JobTable) -> Result<RenderedSelect, ConfigError> {
        if !fragment_is_contained(self.columns)
            || !fragment_is_contained(self.joins)
            || !fragment_is_contained(self.predicate)
            || self.predicate.trim().is_empty()
        {
            return Err(ConfigError::SqlFragment);
        }
        let columns = self.columns.trim();
        Ok(RenderedSelect {
            columns: if columns.is_empty() {
                String::new()
            } else {
                format!(", {}", render_schema(columns, table))
            },
            joins: render_schema(self.joins, table),
            predicate: render_schema(self.predicate, table),
        })
    }
}

impl ExpirySql {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.states.is_empty()
            || self
                .states
                .iter()
                .any(|state| !matches!(state, JobState::Pending | JobState::DeadLettered))
        {
            return Err(ConfigError::StateSet);
        }
        let locks: Vec<&str> = self.lock_of.split(',').map(str::trim).collect();
        if !fragment_is_contained(self.order_by)
            || self.order_by.trim().is_empty()
            || !locks.iter().all(|alias| is_plain_identifier(alias, 63))
            || !locks.contains(&"state")
        {
            return Err(ConfigError::SqlFragment);
        }
        Ok(())
    }

    pub(crate) fn state_list(&self) -> String {
        state_list(self.states)
    }
}

/// `'a', 'b'` for a set of states, spelled from the core's own vocabulary.
pub(crate) fn state_list(states: &[JobState]) -> String {
    states
        .iter()
        .map(|state| format!("'{}'", state.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_schema(fragment: &str, table: &JobTable) -> String {
    fragment.replace("{schema}", table.schema())
}

/// Whether a fragment stays inside the statement it is placed in: no
/// statement terminator and no comment opener.
///
/// Fragments are the consumer's own `&'static str` source text, so this is a
/// guard against authoring mistakes, not a sanitizer: it does not parse SQL
/// and must never be relied on to make runtime input safe to interpolate.
fn fragment_is_contained(fragment: &str) -> bool {
    !fragment.contains(';') && !fragment.contains("--") && !fragment.contains("/*")
}

type ColumnValue = Box<dyn ToSql + Sync + Send>;

/// Extra columns a consumer writes in the same UPDATE as a core transition,
/// each as a bind parameter.
#[derive(Default)]
pub struct Columns {
    entries: Vec<(&'static str, ColumnValue)>,
}

impl Columns {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `name` to `value` in the transition UPDATE. The name is checked
    /// when the UPDATE is built: a name that is not a plain identifier,
    /// names a core or key column, or repeats refuses the transition.
    #[must_use]
    pub fn set(mut self, name: &'static str, value: impl ToSql + Sync + Send + 'static) -> Self {
        self.entries.push((name, Box::new(value)));
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The `, name = $n` assignments from parameter `first` onward, and the
    /// values in the same order.
    pub(crate) fn render(
        &self,
        table: &JobTable,
        first: usize,
    ) -> Result<(String, Vec<&(dyn ToSql + Sync)>), DispatchError> {
        let mut assignments = String::new();
        let mut values: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(self.entries.len());
        for (offset, (name, value)) in self.entries.iter().enumerate() {
            let valid = is_plain_identifier(name, 63)
                && !CORE_COLUMNS.contains(name)
                && *name != table.id_column()
                && *name != table.part_column()
                && !self.entries[..offset]
                    .iter()
                    .any(|(earlier, _)| earlier == name);
            if !valid {
                return Err(DispatchError::Unavailable);
            }
            assignments.push_str(&format!(
                ",\n                     {name} = ${}",
                first + offset
            ));
            values.push(value.as_ref());
        }
        Ok((assignments, values))
    }
}

impl std::fmt::Debug for Columns {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Values stay out of debug output; only the column names show.
        formatter
            .debug_list()
            .entries(self.entries.iter().map(|(name, _)| name))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> JobTable {
        JobTable::new("app", "jobs", "job_id", "part").expect("table")
    }

    #[test]
    fn a_fragment_that_could_escape_its_statement_is_refused() {
        for predicate in ["TRUE; DROP TABLE x", "TRUE -- rest", "TRUE /* rest */", " "] {
            let select = SelectSql {
                columns: "",
                joins: "",
                predicate,
            };
            assert_eq!(
                select.render(&table()).map(|_| ()),
                Err(ConfigError::SqlFragment),
                "{predicate}"
            );
        }
        let rendered = SelectSql {
            columns: "other.a, other.b",
            joins: "JOIN {schema}.other AS other ON other.job_id = state.job_id",
            predicate: "other.a > 0",
        }
        .render(&table())
        .expect("a contained fragment");
        assert_eq!(rendered.columns, ", other.a, other.b");
        assert_eq!(
            rendered.joins,
            "JOIN app.other AS other ON other.job_id = state.job_id"
        );
    }

    #[test]
    fn expiry_accepts_only_undispatched_states_and_a_state_lock() {
        let select = SelectSql {
            columns: "",
            joins: "",
            predicate: "TRUE",
        };
        let expiry = ExpirySql {
            states: &[JobState::Pending, JobState::DeadLettered],
            select,
            order_by: "state.updated_at",
            lock_of: "state, other",
        };
        assert_eq!(expiry.validate(), Ok(()));
        assert_eq!(expiry.state_list(), "'pending', 'dead_lettered'");
        for states in [&[][..], &[JobState::Leased][..], &[JobState::Delivered][..]] {
            assert_eq!(
                ExpirySql { states, ..expiry }.validate(),
                Err(ConfigError::StateSet)
            );
        }
        for lock_of in ["other", "state, Other", "state; x"] {
            assert_eq!(
                ExpirySql { lock_of, ..expiry }.validate(),
                Err(ConfigError::SqlFragment)
            );
        }
    }

    #[test]
    fn extra_columns_are_plain_distinct_and_never_core_columns() {
        let columns = Columns::new()
            .set("provider_reference", Some("ref".to_owned()))
            .set("failure_code", None::<String>);
        let (assignments, values) = columns.render(&table(), 6).expect("valid columns");
        assert_eq!(values.len(), 2);
        assert!(assignments.contains("provider_reference = $6"));
        assert!(assignments.contains("failure_code = $7"));
        for columns in [
            Columns::new().set("state", 1_i64),
            Columns::new().set("job_id", 1_i64),
            Columns::new().set("Bad", 1_i64),
            Columns::new().set("a = 1, b", 1_i64),
            Columns::new().set("a", 1_i64).set("a", 2_i64),
        ] {
            assert!(columns.render(&table(), 6).is_err(), "{columns:?}");
        }
    }
}
