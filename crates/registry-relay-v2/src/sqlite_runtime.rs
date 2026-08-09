// SPDX-License-Identifier: Apache-2.0
//! Concrete operation-keyed SQLite execution for the Relay V2 runtime.
//!
//! SQL is generated once from the immutable compiler model. Public requests
//! can supply values only for the named parameters already present in that
//! statement. There is deliberately no storage trait or caller-authored SQL.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use registry_platform_sqlite::{
    schema_fingerprint, CapturedSnapshot, ColumnContract, ColumnType, DatabaseProfile,
    InspectionLimits, LiveDatabaseFile, ParameterContract, ReadOnlyStatement, ResultRow,
    SchemaBinding, SqliteError, StatementContract, StatementLimits, Value,
};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::auth::RowAuthority;
use crate::contract::{DataType, SourceProfile};
use crate::model::{CompiledOperation, CompiledRegistry, CompiledResource, OperationKind};

const MAXIMUM_CELL_BYTES: usize = 1024 * 1024;
const MAXIMUM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_STATEMENT_STEPS: u64 = 2_000_000;
const SCHEMA_MAXIMUM_OBJECTS: usize = 10_000;
const SCHEMA_MAXIMUM_SQL_BYTES: usize = 8 * 1024 * 1024;
const SCHEMA_MAXIMUM_STEPS: u64 = 1_000_000;

#[derive(Clone, Debug)]
pub struct SqliteRuntimeLimits {
    pub request_timeout: Duration,
    pub concurrent_queries: usize,
}

#[derive(Clone, Debug)]
pub struct RuntimeSourceBinding {
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceRevision {
    Snapshot(String),
    LiveUnversioned,
}

impl SourceRevision {
    #[must_use]
    pub fn cursor_value(&self) -> String {
        match self {
            Self::Snapshot(value) => value.clone(),
            Self::LiveUnversioned => "live:unversioned".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct OperationQuery {
    pub filters: BTreeMap<String, Value>,
    pub selectors: BTreeMap<String, Value>,
    pub record_identifier: Option<String>,
    pub row_authority: Option<RowAuthority>,
    pub after_order: Option<Vec<Value>>,
    pub fetch_limit: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct OperationResult {
    pub rows: Vec<ResultRow>,
    pub source_revision: SourceRevision,
}

#[derive(Debug, Error)]
pub enum SqliteRuntimeError {
    #[error("runtime source binding is missing")]
    MissingSource,
    #[error("compiled source or operation is unknown")]
    UnknownOperation,
    #[error("source schema does not match the governed contract")]
    SchemaMismatch,
    #[error("compiled SQLite plan is invalid")]
    InvalidPlan,
    #[error("SQLite query admission timed out")]
    AdmissionTimeout,
    #[error("SQLite source operation failed")]
    Source(#[from] SqliteError),
}

struct OperationExecutor {
    statement: Arc<ReadOnlyStatement>,
    operation: CompiledOperation,
    source_revision: SourceRevision,
}

#[derive(Clone)]
struct ReadinessSource {
    profile: DatabaseProfile,
    expected_schema_fingerprint: String,
}

/// Fixed operation inventory over one compiled Registry.
pub struct SqliteRuntime {
    operations: BTreeMap<String, OperationExecutor>,
    readiness_sources: Vec<ReadinessSource>,
    admission: Arc<Semaphore>,
    timeout: Duration,
}

impl SqliteRuntime {
    pub fn open(
        registry: &CompiledRegistry,
        bindings: &BTreeMap<String, RuntimeSourceBinding>,
        limits: SqliteRuntimeLimits,
    ) -> Result<Self, SqliteRuntimeError> {
        if limits.request_timeout.is_zero() || limits.concurrent_queries == 0 {
            return Err(SqliteRuntimeError::InvalidPlan);
        }

        let mut profiles = BTreeMap::new();
        let mut readiness_sources = Vec::new();
        for source in &registry.sources {
            let binding = bindings
                .get(&source.id)
                .ok_or(SqliteRuntimeError::MissingSource)?;
            let (profile, revision) = match source.profile {
                SourceProfile::Snapshot => {
                    let captured = CapturedSnapshot::capture(&binding.path)?;
                    let revision = SourceRevision::Snapshot(captured.digest().to_owned());
                    (DatabaseProfile::Snapshot(captured), revision)
                }
                SourceProfile::LiveReadOnly => {
                    let live = LiveDatabaseFile::bind(&binding.path)?;
                    (
                        DatabaseProfile::LiveReadOnly(live),
                        SourceRevision::LiveUnversioned,
                    )
                }
            };
            let observed = schema_fingerprint(
                &profile,
                &InspectionLimits {
                    maximum_objects: SCHEMA_MAXIMUM_OBJECTS,
                    maximum_sql_bytes: SCHEMA_MAXIMUM_SQL_BYTES,
                    maximum_statement_steps: SCHEMA_MAXIMUM_STEPS,
                    timeout: limits.request_timeout,
                },
            )?;
            if observed != source.expected_schema_fingerprint {
                return Err(SqliteRuntimeError::SchemaMismatch);
            }
            readiness_sources.push(ReadinessSource {
                profile: profile.clone(),
                expected_schema_fingerprint: source.expected_schema_fingerprint.clone(),
            });
            profiles.insert(source.id.clone(), (profile, revision));
        }

        let mut operations = BTreeMap::new();
        for resource in &registry.resources {
            for operation in &resource.operations {
                let (profile, source_revision) = profiles
                    .get(&operation.query.source)
                    .ok_or(SqliteRuntimeError::MissingSource)?;
                let source = registry
                    .sources
                    .iter()
                    .find(|source| source.id == operation.query.source)
                    .ok_or(SqliteRuntimeError::MissingSource)?;
                let contract = statement_contract(
                    resource,
                    operation,
                    &limits,
                    &source.expected_schema_fingerprint,
                )?;
                let statement = ReadOnlyStatement::open(profile.clone(), contract)?;
                if operations
                    .insert(
                        operation.identifier.clone(),
                        OperationExecutor {
                            statement: Arc::new(statement),
                            operation: operation.clone(),
                            source_revision: source_revision.clone(),
                        },
                    )
                    .is_some()
                {
                    return Err(SqliteRuntimeError::InvalidPlan);
                }
            }
        }

        Ok(Self {
            operations,
            readiness_sources,
            admission: Arc::new(Semaphore::new(limits.concurrent_queries)),
            timeout: limits.request_timeout,
        })
    }

    /// Confirm every continuing source release gate without reading row data.
    /// Failures remain categorical so callers cannot expose a source identifier,
    /// path, schema, or value through readiness.
    pub async fn is_ready(&self) -> bool {
        for source in &self.readiness_sources {
            let source = source.clone();
            let timeout = self.timeout;
            let check = tokio::task::spawn_blocking(move || {
                if let DatabaseProfile::Snapshot(snapshot) = &source.profile {
                    snapshot.verify_unchanged()?;
                }
                let observed = schema_fingerprint(
                    &source.profile,
                    &InspectionLimits {
                        maximum_objects: SCHEMA_MAXIMUM_OBJECTS,
                        maximum_sql_bytes: SCHEMA_MAXIMUM_SQL_BYTES,
                        maximum_statement_steps: SCHEMA_MAXIMUM_STEPS,
                        timeout,
                    },
                )?;
                Ok::<bool, SqliteError>(observed == source.expected_schema_fingerprint)
            });
            if !matches!(check.await, Ok(Ok(true))) {
                return false;
            }
        }
        true
    }

    #[must_use]
    pub fn source_revision(&self, operation: &str) -> Option<&SourceRevision> {
        self.operations
            .get(operation)
            .map(|item| &item.source_revision)
    }

    pub async fn execute(
        &self,
        operation: &str,
        query: OperationQuery,
    ) -> Result<OperationResult, SqliteRuntimeError> {
        let executor = self
            .operations
            .get(operation)
            .ok_or(SqliteRuntimeError::UnknownOperation)?;
        let permit = self.acquire().await?;
        let values = bind_operation_values(&executor.operation, query)?;
        let result = executor.statement.execute(&values).await;
        drop(permit);
        Ok(OperationResult {
            rows: result?.rows,
            source_revision: executor.source_revision.clone(),
        })
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, SqliteRuntimeError> {
        tokio::time::timeout(self.timeout, Arc::clone(&self.admission).acquire_owned())
            .await
            .map_err(|_| SqliteRuntimeError::AdmissionTimeout)?
            .map_err(|_| SqliteRuntimeError::InvalidPlan)
    }
}

fn statement_contract(
    resource: &CompiledResource,
    operation: &CompiledOperation,
    limits: &SqliteRuntimeLimits,
    expected_schema_fingerprint: &str,
) -> Result<StatementContract, SqliteRuntimeError> {
    let result_columns = result_columns(operation);
    let columns = result_columns
        .iter()
        .map(|column| ColumnContract {
            name: column.clone(),
            value_type: column_type(resource, column),
        })
        .collect::<Vec<_>>();
    let mut parameters = Vec::new();
    let sql = match &operation.kind {
        OperationKind::List => list_sql(operation, &result_columns, &mut parameters),
        OperationKind::Read => read_sql(resource, operation, &result_columns, &mut parameters),
        OperationKind::Lookup { .. } => lookup_sql(operation, &result_columns, &mut parameters),
    };
    let maximum_rows = match &operation.kind {
        OperationKind::List => u64::from(
            operation
                .query
                .pagination
                .as_ref()
                .ok_or(SqliteRuntimeError::InvalidPlan)?
                .maximum_page_size,
        )
        .saturating_add(1),
        OperationKind::Read | OperationKind::Lookup { .. } => 2,
    };
    Ok(StatementContract {
        sql,
        columns,
        parameters,
        limits: StatementLimits {
            maximum_rows,
            maximum_cell_bytes: MAXIMUM_CELL_BYTES,
            maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            maximum_statement_steps: MAXIMUM_STATEMENT_STEPS,
            timeout: limits.request_timeout,
            // Aggregate process concurrency is owned above. One connection per
            // fixed operation prevents connection count from multiplying again.
            concurrency: 1,
        },
        schema: Some(SchemaBinding {
            expected_fingerprint: expected_schema_fingerprint.to_owned(),
            maximum_objects: SCHEMA_MAXIMUM_OBJECTS,
            maximum_sql_bytes: SCHEMA_MAXIMUM_SQL_BYTES,
        }),
    })
}

fn result_columns(operation: &CompiledOperation) -> Vec<String> {
    let mut columns = operation.query.projected_columns.clone();
    for column in &operation.query.order_by {
        if !columns.contains(column) {
            columns.push(column.clone());
        }
    }
    columns
}

fn column_type(resource: &CompiledResource, column: &str) -> ColumnType {
    resource
        .properties
        .iter()
        .find(|property| property.source_column == column)
        .map(|property| data_type(property.data_type))
        .unwrap_or(ColumnType::String)
}

fn data_type(value: DataType) -> ColumnType {
    match value {
        DataType::Boolean => ColumnType::Boolean,
        DataType::Integer => ColumnType::Integer,
        DataType::String | DataType::Date | DataType::DateTime | DataType::ControlledCode => {
            ColumnType::String
        }
    }
}

fn list_sql(
    operation: &CompiledOperation,
    columns: &[String],
    parameters: &mut Vec<ParameterContract>,
) -> String {
    let mut predicates = Vec::new();
    for (index, filter) in operation.query.filters.iter().enumerate() {
        let present = format!("filter_{index}_present");
        let value = format!("filter_{index}");
        parameters.push(parameter(&present));
        parameters.push(parameter(&value));
        predicates.push(format!(
            "(:{present} = 0 OR {} = :{value})",
            quote_identifier(&filter.source_column)
        ));
    }
    add_row_authority(operation, parameters, &mut predicates);
    parameters.push(parameter("cursor_present"));
    let keyset = keyset_predicate(&operation.query.order_by, parameters);
    predicates.push(format!("(:cursor_present = 0 OR ({keyset}))"));
    parameters.push(parameter("fetch_limit"));
    format!(
        "SELECT {} FROM {} WHERE {} ORDER BY {} LIMIT :fetch_limit",
        select_list(columns),
        quote_identifier(&operation.query.view),
        predicates.join(" AND "),
        operation
            .query
            .order_by
            .iter()
            .map(|column| format!("{} ASC", quote_identifier(column)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn read_sql(
    resource: &CompiledResource,
    operation: &CompiledOperation,
    columns: &[String],
    parameters: &mut Vec<ParameterContract>,
) -> String {
    parameters.push(parameter("record_identifier"));
    let mut predicates = vec![format!(
        "{} = :record_identifier",
        quote_identifier(&resource.record_context.record_identifier_column)
    )];
    add_row_authority(operation, parameters, &mut predicates);
    format!(
        "SELECT {} FROM {} WHERE {} LIMIT 2",
        select_list(columns),
        quote_identifier(&operation.query.view),
        predicates.join(" AND ")
    )
}

fn lookup_sql(
    operation: &CompiledOperation,
    columns: &[String],
    parameters: &mut Vec<ParameterContract>,
) -> String {
    let mut predicates = Vec::new();
    for (index, selector) in operation.query.selectors.iter().enumerate() {
        let name = format!("selector_{index}");
        parameters.push(parameter(&name));
        predicates.push(format!(
            "{} = :{name}",
            quote_identifier(&selector.source_column)
        ));
    }
    add_row_authority(operation, parameters, &mut predicates);
    format!(
        "SELECT {} FROM {} WHERE {} LIMIT 2",
        select_list(columns),
        quote_identifier(&operation.query.view),
        predicates.join(" AND ")
    )
}

fn add_row_authority(
    operation: &CompiledOperation,
    parameters: &mut Vec<ParameterContract>,
    predicates: &mut Vec<String>,
) {
    if let crate::model::CompiledAccess::Protected {
        row_binding: Some(binding),
        ..
    } = &operation.access
    {
        parameters.push(parameter("row_authority"));
        predicates.push(format!(
            "{} = :row_authority",
            quote_identifier(&binding.source_column)
        ));
    }
}

fn keyset_predicate(order: &[String], parameters: &mut Vec<ParameterContract>) -> String {
    let mut alternatives = Vec::new();
    for index in 0..order.len() {
        let mut terms = Vec::new();
        for (prior, column) in order.iter().take(index).enumerate() {
            terms.push(format!("{} = :cursor_{prior}", quote_identifier(column)));
        }
        terms.push(format!(
            "{} > :cursor_{index}",
            quote_identifier(&order[index])
        ));
        alternatives.push(format!("({})", terms.join(" AND ")));
    }
    for index in 0..order.len() {
        parameters.push(parameter(&format!("cursor_{index}")));
    }
    alternatives.join(" OR ")
}

fn parameter(name: &str) -> ParameterContract {
    ParameterContract {
        name: name.to_owned(),
        required: true,
    }
}

fn select_list(columns: &[String]) -> String {
    columns
        .iter()
        .map(|column| quote_identifier(column))
        .collect::<Vec<_>>()
        .join(", ")
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn bind_operation_values(
    operation: &CompiledOperation,
    query: OperationQuery,
) -> Result<BTreeMap<String, Value>, SqliteRuntimeError> {
    let mut values = BTreeMap::new();
    match &operation.kind {
        OperationKind::List => {
            let declared = operation
                .query
                .filters
                .iter()
                .map(|filter| filter.parameter.as_str())
                .collect::<BTreeSet<_>>();
            if query
                .filters
                .keys()
                .any(|name| !declared.contains(name.as_str()))
            {
                return Err(SqliteRuntimeError::InvalidPlan);
            }
            for (index, filter) in operation.query.filters.iter().enumerate() {
                let value = query.filters.get(&filter.parameter).cloned();
                values.insert(
                    format!("filter_{index}_present"),
                    Value::Integer(i64::from(value.is_some())),
                );
                values.insert(format!("filter_{index}"), value.unwrap_or(Value::Null));
            }
            let after = query.after_order.unwrap_or_default();
            if !after.is_empty() && after.len() != operation.query.order_by.len() {
                return Err(SqliteRuntimeError::InvalidPlan);
            }
            values.insert(
                "cursor_present".into(),
                Value::Integer(i64::from(!after.is_empty())),
            );
            for index in 0..operation.query.order_by.len() {
                values.insert(
                    format!("cursor_{index}"),
                    after.get(index).cloned().unwrap_or(Value::Null),
                );
            }
            values.insert(
                "fetch_limit".into(),
                Value::Integer(i64::from(
                    query.fetch_limit.ok_or(SqliteRuntimeError::InvalidPlan)?,
                )),
            );
        }
        OperationKind::Read => {
            values.insert(
                "record_identifier".into(),
                Value::String(
                    query
                        .record_identifier
                        .ok_or(SqliteRuntimeError::InvalidPlan)?,
                ),
            );
        }
        OperationKind::Lookup { .. } => {
            if query.selectors.len() != operation.query.selectors.len() {
                return Err(SqliteRuntimeError::InvalidPlan);
            }
            for (index, selector) in operation.query.selectors.iter().enumerate() {
                values.insert(
                    format!("selector_{index}"),
                    query
                        .selectors
                        .get(&selector.name)
                        .cloned()
                        .ok_or(SqliteRuntimeError::InvalidPlan)?,
                );
            }
        }
    }
    if let crate::model::CompiledAccess::Protected {
        row_binding: Some(binding),
        ..
    } = &operation.access
    {
        let row = query.row_authority.ok_or(SqliteRuntimeError::InvalidPlan)?;
        if row.source_column != binding.source_column {
            return Err(SqliteRuntimeError::InvalidPlan);
        }
        values.insert("row_authority".into(), Value::String(row.value));
    } else if query.row_authority.is_some() {
        return Err(SqliteRuntimeError::InvalidPlan);
    }
    Ok(values)
}
