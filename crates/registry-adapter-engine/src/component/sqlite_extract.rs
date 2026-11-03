// SPDX-License-Identifier: Apache-2.0

//! Reviewed statement execution over a host-captured immutable extract.
//!
//! The host selects the snapshot and evaluation instant. The platform owns
//! read-only SQL, identity/authorizer checks, bounded execution and cancellation
//! recovery. Routes receive rows and publication metadata, never a file handle.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::artifacts::{ArtifactSource, PackArtifactBytes};
use chrono::{DateTime, SecondsFormat, SubsecRound as _, Utc};
use registry_adapter_core::{ComponentKind, Endpoint, SqliteExtractColumnType};
use registry_platform_sqlite::{
    CapturedSnapshot, ColumnContract, ColumnType, DatabaseProfile, ErrorKind, ParameterContract,
    ReadOnlyStatement, StatementContract, StatementLimits, Value,
};
use serde_json::{json, Map, Number, Value as JsonValue};
use thiserror::Error;

/// A reviewed, digest-checked SQL contract. Construction consumes in-memory
/// pack artifacts only; opening an extract is a separate post-intent action.
#[derive(Clone, Debug)]
pub struct SqliteExtractPlan {
    extract_profile: String,
    statement_artifact: String,
    contract: StatementContract,
    maximum_age: Duration,
}

impl SqliteExtractPlan {
    pub fn compile(
        endpoint: &Endpoint,
        artifacts: &PackArtifactBytes,
    ) -> Result<Self, SqliteExtractError> {
        if endpoint.component != ComponentKind::SqliteExtract {
            return Err(SqliteExtractError::InvalidPlan);
        }
        let declaration = endpoint
            .sqlite_extract
            .as_ref()
            .ok_or(SqliteExtractError::InvalidPlan)?;
        let bytes = artifacts
            .read_bounded(&declaration.statement.path, 1_048_576)
            .map_err(|_| SqliteExtractError::InvalidPlan)?;
        if registry_platform_config::sha256_uri(&bytes) != declaration.statement.digest.as_str() {
            return Err(SqliteExtractError::InvalidPlan);
        }
        let sql = String::from_utf8(bytes).map_err(|_| SqliteExtractError::InvalidPlan)?;
        let columns = declaration
            .columns
            .iter()
            .map(|column| ColumnContract {
                name: column.name.as_str().to_owned(),
                value_type: match column.value_type {
                    SqliteExtractColumnType::String => ColumnType::String,
                    SqliteExtractColumnType::Integer => ColumnType::Integer,
                    SqliteExtractColumnType::Number => ColumnType::Number,
                    SqliteExtractColumnType::Boolean => ColumnType::Boolean,
                },
            })
            .collect::<Vec<_>>();
        let parameters = declaration
            .parameters
            .iter()
            .map(|parameter| ParameterContract {
                name: parameter.name.as_str().to_owned(),
                required: parameter.required,
            })
            .collect::<Vec<_>>();
        if columns.is_empty()
            || columns
                .iter()
                .map(|column| &column.name)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != columns.len()
            || parameters
                .iter()
                .map(|parameter| &parameter.name)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != parameters.len()
            || parameters
                .iter()
                .any(|parameter| parameter.name == EVALUATION_PARAMETER)
        {
            return Err(SqliteExtractError::InvalidPlan);
        }
        let contract = StatementContract {
            sql,
            columns,
            parameters,
            limits: StatementLimits {
                maximum_rows: declaration.maximum_rows.get(),
                maximum_cell_bytes: declaration.maximum_cell_bytes.get() as usize,
                maximum_response_bytes: endpoint.maximum_response_bytes.get() as usize,
                maximum_statement_steps: declaration.maximum_statement_steps.get(),
                timeout: Duration::from_millis(
                    endpoint
                        .attempt_timeout_milliseconds
                        .map(|value| value.get())
                        .unwrap_or(30_000),
                ),
                concurrency: declaration.concurrency.get() as usize,
            },
            schema: None,
        };
        registry_platform_sqlite::check_statement_offline(&contract)
            .map_err(|error| SqliteExtractError::Statement(error.kind()))?;
        Ok(Self {
            extract_profile: declaration.extract_profile.as_str().to_owned(),
            statement_artifact: declaration.statement.path.as_str().to_owned(),
            contract,
            maximum_age: Duration::from_secs(declaration.maximum_extract_age_seconds.get()),
        })
    }

    #[must_use]
    pub fn extract_profile(&self) -> &str {
        &self.extract_profile
    }

    /// The reviewed pack-relative statement artifact, never its SQL text.
    #[must_use]
    pub fn statement_artifact(&self) -> &str {
        &self.statement_artifact
    }

    pub fn open(
        &self,
        snapshot: CapturedSnapshot,
    ) -> Result<SqliteExtractSource, SqliteExtractError> {
        SqliteExtractSource::open(snapshot, self.contract.clone(), self.maximum_age)
    }

    pub(crate) fn open_before(
        &self,
        snapshot: CapturedSnapshot,
        deadline: std::time::Instant,
    ) -> Result<SqliteExtractSource, SqliteExtractError> {
        SqliteExtractSource::open_before(
            snapshot,
            self.contract.clone(),
            self.maximum_age,
            deadline,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_config::sha256_uri;
    use serde_json::json;

    #[test]
    fn offline_compile_preserves_the_closed_statement_cause() {
        let sql = b"SELECT 1; SELECT 'diagnostic-canary';";
        let endpoint: Endpoint = serde_json::from_value(json!({
            "id": "records",
            "component": "sqlite-extract",
            "authentication": {"type": "none"},
            "attemptTimeoutMilliseconds": 1000,
            "maximumResponseBytes": 8192,
            "sqliteExtract": {
                "extractProfile": "records",
                "statement": {
                    "path": "queries/records.sql",
                    "digest": sha256_uri(sql)
                },
                "columns": [{"name": "value", "type": "integer"}],
                "parameters": [],
                "maximumExtractAgeSeconds": 3600,
                "maximumRows": 2,
                "maximumCellBytes": 1024,
                "maximumStatementSteps": 100000,
                "concurrency": 1
            }
        }))
        .expect("SQLite endpoint");
        let error = SqliteExtractPlan::compile(
            &endpoint,
            &PackArtifactBytes::new([("queries/records.sql".to_owned(), sql.to_vec())]),
        )
        .expect_err("two statements are refused");

        assert_eq!(
            error,
            SqliteExtractError::Statement(ErrorKind::MultipleStatements)
        );
        assert!(!error.to_string().contains("diagnostic-canary"));
    }
}

/// Reserved host clock parameter; route-provided parameters cannot replace it.
pub const EVALUATION_PARAMETER: &str = "evidence_now";
const MAXIMUM_METADATA_FIELD_BYTES: usize = 1024;
const MAXIMUM_METADATA_BYTES: usize = 20 * 1024;

/// Value-free failures at the extract boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SqliteExtractError {
    #[error("the extract execution limits are invalid")]
    InvalidPlan,
    #[error("the extract publication metadata is invalid")]
    InvalidMetadata,
    #[error("the extract exceeds its permitted age")]
    Stale,
    #[error("the extract statement parameters are invalid")]
    InvalidParameters,
    #[error("the extract statement was refused: {0:?}")]
    Statement(ErrorKind),
}

impl SqliteExtractError {
    /// A closed, value-free diagnosis that survives the route boundary.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidPlan => "adapter.sqlite.statement-refused",
            Self::InvalidMetadata => "adapter.sqlite.extract-unavailable",
            Self::Stale => "adapter.sqlite.extract-stale",
            Self::InvalidParameters => "adapter.sqlite.statement-parameter",
            Self::Statement(kind) => match kind {
                ErrorKind::MissingParameter | ErrorKind::UndeclaredParameter => {
                    "adapter.sqlite.statement-parameter"
                }
                ErrorKind::StepBudgetExceeded
                | ErrorKind::TimeBudgetExceeded
                | ErrorKind::SchemaBudgetExceeded
                | ErrorKind::Timeout => "adapter.sqlite.statement-budget",
                ErrorKind::TooManyRows
                | ErrorKind::CellTooLarge
                | ErrorKind::ValueTypeMismatch
                | ErrorKind::ExecutionFailed => "adapter.sqlite.statement-result",
                ErrorKind::ResponseTooLarge => "adapter.sqlite.response-too-large",
                ErrorKind::Concurrency => "adapter.sqlite.concurrency",
                ErrorKind::InvalidPlan
                | ErrorKind::MultipleStatements
                | ErrorKind::InvalidSql
                | ErrorKind::UnknownTable
                | ErrorKind::UnknownColumn
                | ErrorKind::ColumnMismatch
                | ErrorKind::UnusedBinding
                | ErrorKind::AuthorizerRefused
                | ErrorKind::SchemaMismatch
                | ErrorKind::SchemaMalformed => "adapter.sqlite.statement-refused",
                ErrorKind::DatabaseUnavailable
                | ErrorKind::DatabaseReplaced
                | ErrorKind::DatabaseWritable
                | ErrorKind::DatabaseSymlink
                | ErrorKind::DatabaseNotFile
                | ErrorKind::DatabaseChanged
                | ErrorKind::UncheckpointedSidecar => "adapter.sqlite.extract-unavailable",
                _ => "adapter.sqlite.statement-unavailable",
            },
        }
    }
}

/// One reviewed query, its read-only pool and captured publication metadata.
pub struct SqliteExtractSource {
    statement: ReadOnlyStatement,
    parameter_names: std::collections::BTreeSet<String>,
    published_at: DateTime<Utc>,
    maximum_age: Duration,
    attempt_timeout: Duration,
    maximum_response_bytes: usize,
    metadata: JsonValue,
}

impl SqliteExtractSource {
    /// Bind to the exact snapshot captured by the host, without accepting a
    /// second pathname capture that could change its authority.
    pub fn open(
        snapshot: CapturedSnapshot,
        contract: StatementContract,
        maximum_age: Duration,
    ) -> Result<Self, SqliteExtractError> {
        let deadline = std::time::Instant::now()
            .checked_add(contract.limits.timeout)
            .ok_or(SqliteExtractError::InvalidPlan)?;
        Self::open_before(snapshot, contract, maximum_age, deadline)
    }

    fn open_before(
        snapshot: CapturedSnapshot,
        mut contract: StatementContract,
        maximum_age: Duration,
        deadline: std::time::Instant,
    ) -> Result<Self, SqliteExtractError> {
        if maximum_age.as_secs() == 0 {
            return Err(SqliteExtractError::InvalidPlan);
        }
        let parameter_names = contract
            .parameters
            .iter()
            .map(|parameter| parameter.name.clone())
            .collect();
        // The host clock is always permitted but need not occur in every SQL
        // query. The platform checks every ordinary required binding exactly.
        if !contract
            .parameters
            .iter()
            .any(|parameter| parameter.name == EVALUATION_PARAMETER)
        {
            contract.parameters.push(ParameterContract {
                name: EVALUATION_PARAMETER.to_owned(),
                required: false,
            });
        }
        let metadata_limits = StatementLimits {
            maximum_rows: 1,
            maximum_cell_bytes: MAXIMUM_METADATA_FIELD_BYTES,
            maximum_response_bytes: MAXIMUM_METADATA_BYTES,
            maximum_statement_steps: contract.limits.maximum_statement_steps,
            timeout: contract.limits.timeout,
            concurrency: 1,
        };
        let attempt_timeout = contract.limits.timeout;
        let maximum_response_bytes = contract.limits.maximum_response_bytes;
        let profile = DatabaseProfile::Snapshot(snapshot);
        let statement = ReadOnlyStatement::open_with_text_value_response_budget_before(
            profile.clone(),
            contract,
            deadline,
        )
        .map_err(|error| SqliteExtractError::Statement(error.kind()))?;
        let metadata_query = ReadOnlyStatement::open_with_text_value_response_budget_before(
            profile,
            StatementContract {
                sql: "SELECT published_at, publisher, extract_id FROM evidence_extract".to_owned(),
                columns: ["published_at", "publisher", "extract_id"]
                    .into_iter()
                    .map(|name| ColumnContract {
                        name: name.to_owned(),
                        value_type: ColumnType::String,
                    })
                    .collect(),
                parameters: Vec::new(),
                limits: metadata_limits,
                schema: None,
            },
            deadline,
        )
        .map_err(|_| SqliteExtractError::InvalidMetadata)?;
        let result = metadata_query
            .execute_at_open_before(&BTreeMap::new(), deadline)
            .map_err(|_| SqliteExtractError::InvalidMetadata)?;
        let row = result
            .rows
            .into_iter()
            .next()
            .ok_or(SqliteExtractError::InvalidMetadata)?;
        let text = |name: &str| -> Result<String, SqliteExtractError> {
            match row.get(name) {
                Some(Value::String(value))
                    if !value.is_empty() && value.len() <= MAXIMUM_METADATA_FIELD_BYTES =>
                {
                    Ok(value.clone())
                }
                _ => Err(SqliteExtractError::InvalidMetadata),
            }
        };
        let published_at = DateTime::parse_from_rfc3339(&text("published_at")?)
            .map_err(|_| SqliteExtractError::InvalidMetadata)?
            .with_timezone(&Utc)
            .trunc_subsecs(0);
        let metadata = json!({
            "publishedAt": published_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            "publisher": text("publisher")?,
            "extractId": text("extract_id")?,
        });
        Ok(Self {
            statement,
            parameter_names,
            published_at,
            maximum_age,
            attempt_timeout,
            maximum_response_bytes,
            metadata,
        })
    }

    /// Apply the same inclusive, whole-second publication-age rule as the
    /// extract publisher contract. Future publication dates are a publisher
    /// policy question and are not silently reinterpreted as stale data.
    pub fn validate_age(
        &self,
        evaluation_instant: DateTime<Utc>,
    ) -> Result<(), SqliteExtractError> {
        let age = (evaluation_instant - self.published_at).num_seconds();
        let maximum = i64::try_from(self.maximum_age.as_secs()).unwrap_or(i64::MAX);
        if age > maximum {
            return Err(SqliteExtractError::Stale);
        }
        Ok(())
    }

    /// Execute the reviewed statement with typed parameters and the host's one
    /// evaluation clock. The enclosing acquisition charges the operation before
    /// invoking this method and gates any later disclosure.
    pub async fn execute(
        &self,
        parameters: &BTreeMap<String, Value>,
        evaluation_instant: DateTime<Utc>,
    ) -> Result<JsonValue, SqliteExtractError> {
        let deadline = std::time::Instant::now()
            .checked_add(self.attempt_timeout)
            .ok_or(SqliteExtractError::InvalidPlan)?;
        self.execute_before(parameters, evaluation_instant, deadline)
            .await
    }

    pub(crate) async fn execute_before(
        &self,
        parameters: &BTreeMap<String, Value>,
        evaluation_instant: DateTime<Utc>,
        deadline: std::time::Instant,
    ) -> Result<JsonValue, SqliteExtractError> {
        self.validate_age(evaluation_instant)?;
        if parameters.contains_key(EVALUATION_PARAMETER)
            || parameters
                .keys()
                .any(|name| !self.parameter_names.contains(name))
            || parameters
                .values()
                .any(|value| matches!(value, Value::Number(number) if !number.is_finite()))
        {
            return Err(SqliteExtractError::InvalidParameters);
        }
        let mut bindings = parameters.clone();
        bindings.insert(
            EVALUATION_PARAMETER.to_owned(),
            Value::String(evaluation_instant.to_rfc3339_opts(SecondsFormat::Secs, true)),
        );
        let result = self
            .statement
            .execute_before(&bindings, deadline)
            .await
            .map_err(|error| SqliteExtractError::Statement(error.kind()))?;
        let rows = result
            .rows
            .into_iter()
            .map(row_json)
            .collect::<Result<Vec<_>, _>>()?;
        let response = json!({"rows": rows, "extract": self.metadata});
        let encoded = serde_json::to_vec(&response)
            .map_err(|_| SqliteExtractError::Statement(ErrorKind::ValueTypeMismatch))?;
        if encoded.len() > self.maximum_response_bytes {
            return Err(SqliteExtractError::Statement(ErrorKind::ResponseTooLarge));
        }
        Ok(response)
    }
}

fn row_json(row: BTreeMap<String, Value>) -> Result<JsonValue, SqliteExtractError> {
    let mut result = Map::new();
    for (name, value) in row {
        let value = match value {
            Value::Null => JsonValue::Null,
            Value::String(value) => JsonValue::String(value),
            Value::Integer(value) => JsonValue::from(value),
            Value::Number(value) => JsonValue::Number(
                Number::from_f64(value)
                    .ok_or(SqliteExtractError::Statement(ErrorKind::ValueTypeMismatch))?,
            ),
            Value::Boolean(value) => JsonValue::Bool(value),
        };
        result.insert(name, value);
    }
    Ok(JsonValue::Object(result))
}
