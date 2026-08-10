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
use crate::model::{
    CompiledOperation, CompiledRegistry, CompiledRepresentation, CompiledResource, OperationKind,
};

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
    #[error("source result shape does not match the governed contract")]
    InvalidSourceShape,
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
    representation: CompiledRepresentation,
    source_revision: SourceRevision,
    list_identifier_count_column: Option<String>,
}

struct OperationInventory {
    source_revision: SourceRevision,
    representations: BTreeMap<String, OperationExecutor>,
}

#[derive(Clone)]
struct ReadinessSource {
    profile: DatabaseProfile,
    expected_schema_fingerprint: String,
}

/// Fixed operation inventory over one compiled Registry.
pub struct SqliteRuntime {
    operations: BTreeMap<String, OperationInventory>,
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
                let mut representations = BTreeMap::new();
                for representation in &operation.representations {
                    let PreparedStatementContract {
                        contract,
                        list_identifier_count_column,
                    } = statement_contract(
                        resource,
                        operation,
                        representation,
                        &limits,
                        &source.expected_schema_fingerprint,
                    )?;
                    let statement = ReadOnlyStatement::open(profile.clone(), contract)?;
                    if representations
                        .insert(
                            representation.id.clone(),
                            OperationExecutor {
                                statement: Arc::new(statement),
                                operation: operation.clone(),
                                representation: representation.clone(),
                                source_revision: source_revision.clone(),
                                list_identifier_count_column,
                            },
                        )
                        .is_some()
                    {
                        return Err(SqliteRuntimeError::InvalidPlan);
                    }
                }
                if representations.is_empty()
                    || operations
                        .insert(
                            operation.identifier.clone(),
                            OperationInventory {
                                source_revision: source_revision.clone(),
                                representations,
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
        representation: &str,
        query: OperationQuery,
    ) -> Result<OperationResult, SqliteRuntimeError> {
        let executor = self
            .operations
            .get(operation)
            .and_then(|inventory| inventory.representations.get(representation))
            .ok_or(SqliteRuntimeError::UnknownOperation)?;
        let permit = self.acquire().await?;
        let values = bind_operation_values(&executor.operation, &executor.representation, query)?;
        let result = executor.statement.execute(&values).await;
        drop(permit);
        let mut rows = result?.rows;
        if let Some(column) = &executor.list_identifier_count_column {
            for row in &mut rows {
                if row.remove(column) != Some(Value::Integer(1)) {
                    return Err(SqliteRuntimeError::InvalidSourceShape);
                }
            }
        }
        Ok(OperationResult {
            rows,
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

struct PreparedStatementContract {
    contract: StatementContract,
    list_identifier_count_column: Option<String>,
}

fn statement_contract(
    resource: &CompiledResource,
    operation: &CompiledOperation,
    representation: &CompiledRepresentation,
    limits: &SqliteRuntimeLimits,
    expected_schema_fingerprint: &str,
) -> Result<PreparedStatementContract, SqliteRuntimeError> {
    let result_columns = result_columns(operation, representation);
    let mut columns = result_columns
        .iter()
        .map(|column| {
            Ok(ColumnContract {
                name: column.clone(),
                value_type: column_type(resource, column)?,
            })
        })
        .collect::<Result<Vec<_>, SqliteRuntimeError>>()?;
    let list_identifier_count_column = matches!(&operation.kind, OperationKind::List)
        .then(|| collision_free_identifier_count_column(&result_columns));
    if let Some(column) = &list_identifier_count_column {
        columns.push(ColumnContract {
            name: column.clone(),
            value_type: ColumnType::Integer,
        });
    }
    let mut parameters = Vec::new();
    let sql = match &operation.kind {
        OperationKind::List => list_sql(
            resource,
            operation,
            representation,
            &result_columns,
            list_identifier_count_column
                .as_deref()
                .ok_or(SqliteRuntimeError::InvalidPlan)?,
            &mut parameters,
        )?,
        OperationKind::Read => read_sql(
            resource,
            operation,
            representation,
            &result_columns,
            &mut parameters,
        ),
        OperationKind::Lookup { .. } => {
            lookup_sql(operation, representation, &result_columns, &mut parameters)
        }
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
    Ok(PreparedStatementContract {
        contract: StatementContract {
            sql,
            columns,
            parameters,
            limits: StatementLimits {
                maximum_rows,
                maximum_cell_bytes: MAXIMUM_CELL_BYTES,
                maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
                maximum_statement_steps: MAXIMUM_STATEMENT_STEPS,
                timeout: limits.request_timeout,
                // Aggregate process concurrency is owned above. Each fixed
                // representation has one connection, and compilation bounds the
                // Registry-wide representation executor inventory.
                concurrency: 1,
            },
            schema: Some(SchemaBinding {
                expected_fingerprint: expected_schema_fingerprint.to_owned(),
                maximum_objects: SCHEMA_MAXIMUM_OBJECTS,
                maximum_sql_bytes: SCHEMA_MAXIMUM_SQL_BYTES,
            }),
        },
        list_identifier_count_column,
    })
}

fn result_columns(
    operation: &CompiledOperation,
    representation: &CompiledRepresentation,
) -> Vec<String> {
    let mut columns = representation.projected_columns.clone();
    for column in &operation.query.order_by {
        if !columns.contains(column) {
            columns.push(column.clone());
        }
    }
    columns
}

fn column_type(
    resource: &CompiledResource,
    column: &str,
) -> Result<ColumnType, SqliteRuntimeError> {
    let record_context = &resource.record_context;
    let core_type = (column == record_context.record_identifier_column
        || column == record_context.revision_identifier_column
        || column == record_context.lifecycle_state_column
        || column == record_context.recorded_at_column)
        .then_some(ColumnType::String);
    resolve_column_type(
        core_type.into_iter().chain(
            resource
                .properties
                .iter()
                .filter(|property| property.source_column == column)
                .map(|property| data_type(property.data_type)),
        ),
    )
}

fn resolve_column_type(
    candidates: impl IntoIterator<Item = ColumnType>,
) -> Result<ColumnType, SqliteRuntimeError> {
    let mut resolved = None;
    for candidate in candidates {
        // A raw column has one SQLite value shape even when several published
        // properties bind it. Never let property order choose that shape.
        if resolved.is_some_and(|value_type| value_type != candidate) {
            return Err(SqliteRuntimeError::InvalidPlan);
        }
        resolved = Some(candidate);
    }

    Ok(resolved.unwrap_or(ColumnType::String))
}

fn data_type(value: DataType) -> ColumnType {
    match value {
        DataType::Boolean => ColumnType::Boolean,
        DataType::Integer => ColumnType::Integer,
        DataType::String
        | DataType::Date
        | DataType::DateTime
        | DataType::Year
        | DataType::YearMonth
        | DataType::ControlledCode => ColumnType::String,
    }
}

fn list_sql(
    resource: &CompiledResource,
    operation: &CompiledOperation,
    representation: &CompiledRepresentation,
    columns: &[String],
    identifier_count_column: &str,
    parameters: &mut Vec<ParameterContract>,
) -> Result<String, SqliteRuntimeError> {
    let order = operation
        .query
        .order_by
        .iter()
        .map(|column| {
            Ok(OrderColumn {
                name: column,
                value_type: column_type(resource, column)?,
            })
        })
        .collect::<Result<Vec<_>, SqliteRuntimeError>>()?;
    let mut scope_predicates = Vec::new();
    for (index, filter) in operation.query.filters.iter().enumerate() {
        let present = format!("filter_{index}_present");
        let value = format!("filter_{index}");
        parameters.push(parameter(&present));
        parameters.push(parameter(&value));
        scope_predicates.push(format!(
            "(:{present} = 0 OR {})",
            exact_equality_predicate(&filter.source_column, &value, filter.data_type)
        ));
    }
    add_row_authority(representation, parameters, &mut scope_predicates);
    parameters.push(parameter("cursor_present"));
    let keyset = keyset_predicate(&order, parameters);
    let cursor_predicate = format!(":cursor_present = 0 OR ({keyset})");
    parameters.push(parameter("fetch_limit"));
    let identifier_count_column = quote_identifier(identifier_count_column);
    let record_identifier = quote_identifier(&resource.record_context.record_identifier_column);
    let scope_where = if scope_predicates.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", scope_predicates.join(" AND "))
    };
    Ok(format!(
        "SELECT {}, {identifier_count_column} FROM (SELECT {}, COUNT(*) OVER (PARTITION BY typeof({record_identifier}), {record_identifier} COLLATE BINARY) AS {identifier_count_column} FROM {}{scope_where}) AS \"__relay_authorized_rows\" WHERE ({cursor_predicate}) ORDER BY {} LIMIT :fetch_limit",
        select_list(columns),
        select_list(columns),
        quote_identifier(&operation.query.view),
        order
            .iter()
            .map(|column| format!("{} ASC", column.sql_expression()))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn collision_free_identifier_count_column(columns: &[String]) -> String {
    const BASE: &str = "__relay_record_identifier_count";
    if !columns
        .iter()
        .any(|column| column.eq_ignore_ascii_case(BASE))
    {
        return BASE.to_owned();
    }
    for suffix in 1..=columns.len() {
        let candidate = format!("{BASE}_{suffix}");
        if !columns
            .iter()
            .any(|column| column.eq_ignore_ascii_case(&candidate))
        {
            return candidate;
        }
    }
    format!("{BASE}_{}", columns.len().saturating_add(1))
}

fn read_sql(
    resource: &CompiledResource,
    operation: &CompiledOperation,
    representation: &CompiledRepresentation,
    columns: &[String],
    parameters: &mut Vec<ParameterContract>,
) -> String {
    parameters.push(parameter("record_identifier"));
    let mut predicates = vec![exact_equality_predicate(
        &resource.record_context.record_identifier_column,
        "record_identifier",
        DataType::String,
    )];
    add_row_authority(representation, parameters, &mut predicates);
    format!(
        "SELECT {} FROM {} WHERE {} LIMIT 2",
        select_list(columns),
        quote_identifier(&operation.query.view),
        predicates.join(" AND ")
    )
}

fn lookup_sql(
    operation: &CompiledOperation,
    representation: &CompiledRepresentation,
    columns: &[String],
    parameters: &mut Vec<ParameterContract>,
) -> String {
    let mut predicates = Vec::new();
    for (index, selector) in operation.query.selectors.iter().enumerate() {
        let name = format!("selector_{index}");
        parameters.push(parameter(&name));
        predicates.push(exact_equality_predicate(
            &selector.source_column,
            &name,
            selector.data_type,
        ));
    }
    add_row_authority(representation, parameters, &mut predicates);
    format!(
        "SELECT {} FROM {} WHERE {} LIMIT 2",
        select_list(columns),
        quote_identifier(&operation.query.view),
        predicates.join(" AND ")
    )
}

fn add_row_authority(
    representation: &CompiledRepresentation,
    parameters: &mut Vec<ParameterContract>,
    predicates: &mut Vec<String>,
) {
    if let crate::model::CompiledAccess::Protected {
        row_binding: Some(binding),
        ..
    } = &representation.access
    {
        parameters.push(parameter("row_authority"));
        predicates.push(exact_equality_predicate(
            &binding.source_column,
            "row_authority",
            DataType::String,
        ));
    }
}

fn exact_equality_predicate(column: &str, parameter: &str, data_type: DataType) -> String {
    // SQLite column affinity can coerce a bound value before equality, and a
    // column's declared collation can widen text equality. Pin both storage
    // classes first, then override text collation without casting either side.
    let column = quote_identifier(column);
    match data_type {
        DataType::Boolean | DataType::Integer => format!(
            "(typeof({column}) = 'integer' AND typeof(:{parameter}) = 'integer' AND {column} = :{parameter})"
        ),
        DataType::String
        | DataType::Date
        | DataType::DateTime
        | DataType::Year
        | DataType::YearMonth
        | DataType::ControlledCode => format!(
            "(typeof({column}) = 'text' AND typeof(:{parameter}) = 'text' AND {column} COLLATE BINARY = :{parameter})"
        ),
    }
}

#[derive(Clone, Copy)]
struct OrderColumn<'a> {
    name: &'a str,
    value_type: ColumnType,
}

impl OrderColumn<'_> {
    fn sql_expression(&self) -> String {
        let column = quote_identifier(self.name);
        if self.value_type == ColumnType::String {
            // A source may declare NOCASE or another collation. Keyset
            // comparison and ordering need one explicit total text order or
            // case-distinct values can disappear between pages.
            format!("{column} COLLATE BINARY")
        } else {
            column
        }
    }

    fn exact_equality(&self, parameter: &str) -> String {
        let column = quote_identifier(self.name);
        match self.value_type {
            ColumnType::String => format!(
                "(typeof({column}) = 'text' AND typeof(:{parameter}) = 'text' AND {column} COLLATE BINARY = :{parameter})"
            ),
            ColumnType::Integer | ColumnType::Boolean => format!(
                "(typeof({column}) = 'integer' AND typeof(:{parameter}) = 'integer' AND {column} = :{parameter})"
            ),
            ColumnType::Number => format!(
                "(typeof({column}) = typeof(:{parameter}) AND typeof({column}) IN ('integer', 'real') AND {column} = :{parameter})"
            ),
        }
    }

    fn greater_than(&self, parameter: &str) -> String {
        let column = quote_identifier(self.name);
        match self.value_type {
            ColumnType::String => format!(
                "(typeof(:{parameter}) = 'text' AND (typeof({column}) != 'text' OR {column} COLLATE BINARY > :{parameter}))"
            ),
            ColumnType::Integer | ColumnType::Boolean => format!(
                "(typeof(:{parameter}) = 'integer' AND (typeof({column}) != 'integer' OR {column} > :{parameter}))"
            ),
            ColumnType::Number => format!(
                "(typeof(:{parameter}) IN ('integer', 'real') AND (typeof({column}) != typeof(:{parameter}) OR typeof({column}) NOT IN ('integer', 'real') OR {column} > :{parameter}))"
            ),
        }
    }
}

fn keyset_predicate(order: &[OrderColumn<'_>], parameters: &mut Vec<ParameterContract>) -> String {
    let mut alternatives = Vec::new();
    for index in 0..order.len() {
        let mut terms = Vec::new();
        for (prior, column) in order.iter().take(index).enumerate() {
            terms.push(column.exact_equality(&format!("cursor_{prior}")));
        }
        terms.push(order[index].greater_than(&format!("cursor_{index}")));
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
    representation: &CompiledRepresentation,
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
    } = &representation.access
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

#[cfg(test)]
mod tests {
    use registry_platform_sqlite::{materialize_fixture, CapturedSnapshot};

    use super::*;
    use crate::contract::Handling;
    use crate::model::{
        CapabilityFamily, CompiledAccess, CompiledFilter, CompiledPagination,
        CompiledRecordContext, CompiledRowBinding, CompiledSelector, ConsultationPattern,
        QueryPlan, RowAuthoritySource,
    };

    #[tokio::test]
    async fn exact_lookup_equality_rejects_collation_and_storage_class_equivalents() {
        let temp = tempfile::tempdir().expect("temporary fixture");
        let database = temp.path().join("exact-equality.sqlite");
        materialize_fixture(
            &database,
            "CREATE TABLE records (\
                 id TEXT NOT NULL,\
                 authority TEXT COLLATE NOCASE NOT NULL,\
                 text_key TEXT COLLATE NOCASE NOT NULL,\
                 integer_key INTEGER NOT NULL\
             );\
             INSERT INTO records VALUES ('record-1', 'area-a', 'key-a', 1);",
        )
        .expect("fixture materializes");

        let mut protected = representation();
        protected.access = CompiledAccess::Protected {
            scope: "registry:read".into(),
            purpose: None,
            row_binding: Some(CompiledRowBinding {
                source: RowAuthoritySource::Claim("authority".into()),
                source_column: "authority".into(),
            }),
        };

        let text_operation = lookup_operation("text_key", DataType::String, protected.clone());
        let mut parameters = Vec::new();
        let text_sql = lookup_sql(&text_operation, &protected, &["id".into()], &mut parameters);
        assert!(text_sql.contains(
            "(typeof(\"text_key\") = 'text' AND typeof(:selector_0) = 'text' AND \"text_key\" COLLATE BINARY = :selector_0)"
        ));
        assert!(text_sql.contains(
            "(typeof(\"authority\") = 'text' AND typeof(:row_authority) = 'text' AND \"authority\" COLLATE BINARY = :row_authority)"
        ));
        let statement = test_statement(&database, text_sql, parameters);
        let wrong_case = statement
            .execute(&BTreeMap::from([
                ("selector_0".into(), Value::String("key-a".into())),
                ("row_authority".into(), Value::String("AREA-A".into())),
            ]))
            .await
            .expect("case-distinct authority lookup executes");
        assert!(wrong_case.rows.is_empty());

        let string_operation = lookup_operation("integer_key", DataType::String, protected.clone());
        let mut parameters = Vec::new();
        let string_sql = lookup_sql(
            &string_operation,
            &protected,
            &["id".into()],
            &mut parameters,
        );
        let statement = test_statement(&database, string_sql, parameters);
        let cross_storage_class = statement
            .execute(&BTreeMap::from([
                ("selector_0".into(), Value::String("01".into())),
                ("row_authority".into(), Value::String("area-a".into())),
            ]))
            .await
            .expect("cross-storage-class lookup executes");
        assert!(cross_storage_class.rows.is_empty());

        let integer_operation = lookup_operation("integer_key", DataType::Integer, protected);
        let mut parameters = Vec::new();
        let integer_sql = lookup_sql(
            &integer_operation,
            &integer_operation.representations[0],
            &["id".into()],
            &mut parameters,
        );
        assert!(integer_sql.contains(
            "(typeof(\"integer_key\") = 'integer' AND typeof(:selector_0) = 'integer' AND \"integer_key\" = :selector_0)"
        ));
        assert!(!integer_sql.contains("\"integer_key\" COLLATE BINARY"));
        let statement = test_statement(&database, integer_sql, parameters);
        let exact_integer = statement
            .execute(&BTreeMap::from([
                ("selector_0".into(), Value::Integer(1)),
                ("row_authority".into(), Value::String("area-a".into())),
            ]))
            .await
            .expect("integer lookup executes");
        assert_eq!(exact_integer.rows.len(), 1);
    }

    #[test]
    fn record_identifiers_are_text_exact_and_boolean_equality_remains_numeric() {
        assert_eq!(
            exact_equality_predicate("record_id", "record_identifier", DataType::String),
            "(typeof(\"record_id\") = 'text' AND typeof(:record_identifier) = 'text' AND \"record_id\" COLLATE BINARY = :record_identifier)"
        );
        assert_eq!(
            exact_equality_predicate("active", "filter_0", DataType::Boolean),
            "(typeof(\"active\") = 'integer' AND typeof(:filter_0) = 'integer' AND \"active\" = :filter_0)"
        );
    }

    #[test]
    fn generated_read_and_filter_predicates_use_declared_equality_families() {
        let resource = resource();
        let mut representation = representation();
        representation.access = CompiledAccess::Protected {
            scope: "registry:read".into(),
            purpose: None,
            row_binding: Some(CompiledRowBinding {
                source: RowAuthoritySource::Claim("authority".into()),
                source_column: "authority".into(),
            }),
        };
        let mut read_parameters = Vec::new();
        let read = read_sql(
            &resource,
            &CompiledOperation {
                identifier: "record.read".into(),
                family: CapabilityFamily::Consultation,
                pattern: ConsultationPattern::Retrieve,
                kind: OperationKind::Read,
                default_representation: representation.id.clone(),
                representations: vec![representation.clone()],
                query: QueryPlan {
                    source: "source".into(),
                    view: "records".into(),
                    filters: Vec::new(),
                    selectors: Vec::new(),
                    order_by: Vec::new(),
                    allow_unfiltered: false,
                    pagination: None,
                    maximum_request_body_bytes: None,
                },
            },
            &representation,
            &["id".into()],
            &mut read_parameters,
        );
        assert!(read.contains(
            "(typeof(\"id\") = 'text' AND typeof(:record_identifier) = 'text' AND \"id\" COLLATE BINARY = :record_identifier)"
        ));

        let mut list = list_operation();
        list.query.filters = vec![
            CompiledFilter {
                parameter: "code".into(),
                property: "code".into(),
                source_column: "code".into(),
                data_type: DataType::ControlledCode,
            },
            CompiledFilter {
                parameter: "active".into(),
                property: "active".into(),
                source_column: "active".into(),
                data_type: DataType::Boolean,
            },
        ];
        let mut list_parameters = Vec::new();
        let list = list_sql(
            &resource,
            &list,
            &representation,
            &["id".into()],
            "__relay_record_identifier_count",
            &mut list_parameters,
        )
        .expect("list SQL compiles");
        assert!(list.contains(
            ":filter_0_present = 0 OR (typeof(\"code\") = 'text' AND typeof(:filter_0) = 'text' AND \"code\" COLLATE BINARY = :filter_0)"
        ));
        assert!(list.contains(
            ":filter_1_present = 0 OR (typeof(\"active\") = 'integer' AND typeof(:filter_1) = 'integer' AND \"active\" = :filter_1)"
        ));
        let counted_scope_end = list
            .find(") AS \"__relay_authorized_rows\"")
            .expect("counted scope ends before cursor selection");
        assert!(list.find(":filter_0_present").unwrap() < counted_scope_end);
        assert!(list.find(":row_authority").unwrap() < counted_scope_end);
        assert!(list.find(":cursor_present").unwrap() > counted_scope_end);
        assert!(list.contains(
            "COUNT(*) OVER (PARTITION BY typeof(\"id\"), \"id\" COLLATE BINARY) AS \"__relay_record_identifier_count\""
        ));
    }

    #[test]
    fn internal_list_column_avoids_governed_column_names() {
        assert_eq!(
            collision_free_identifier_count_column(&[
                "__RELAY_RECORD_IDENTIFIER_COUNT".into(),
                "__relay_record_identifier_count_1".into(),
            ]),
            "__relay_record_identifier_count_2"
        );
    }

    #[tokio::test]
    async fn bounded_keyset_inequality_surfaces_incompatible_source_storage_classes() {
        let temp = tempfile::tempdir().expect("temporary fixture");
        let database = temp.path().join("keyset-storage-classes.sqlite");
        materialize_fixture(
            &database,
            "CREATE TABLE records (id TEXT NOT NULL, sort_key);\
             INSERT INTO records VALUES\
                 ('integer-source', 7),\
                 ('real-source', 7.5),\
                 ('text-source', 'b'),\
                 ('blob-source', X'62');",
        )
        .expect("fixture materializes");

        let text = keyset_test_statement(&database, ColumnType::String);
        assert!(keyset_ids(&text, Value::Integer(0)).await.is_empty());
        assert_eq!(
            keyset_ids(&text, Value::String("a".into())).await,
            ["integer-source", "real-source"]
        );

        let integer = keyset_test_statement(&database, ColumnType::Integer);
        assert!(keyset_ids(&integer, Value::String("0".into()))
            .await
            .is_empty());
        assert_eq!(
            keyset_ids(&integer, Value::Integer(0)).await,
            ["integer-source", "real-source"]
        );

        let number = keyset_test_statement(&database, ColumnType::Number);
        assert_eq!(
            keyset_ids(&number, Value::Integer(0)).await,
            ["integer-source", "real-source"]
        );
        assert_eq!(
            keyset_ids(&number, Value::Number(0.0)).await,
            ["integer-source", "real-source"]
        );
    }

    #[tokio::test]
    async fn binary_keyset_order_does_not_omit_case_distinct_identifiers() {
        let temp = tempfile::tempdir().expect("temporary fixture");
        let database = temp.path().join("case-distinct.sqlite");
        materialize_fixture(
            &database,
            "CREATE TABLE records (id TEXT COLLATE NOCASE NOT NULL);\
             INSERT INTO records VALUES ('a'), ('A'), ('b'), (X'7A');",
        )
        .expect("fixture materializes");

        let resource = resource();
        let operation = list_operation();
        let representation = representation();
        let mut parameters = Vec::new();
        let sql = list_sql(
            &resource,
            &operation,
            &representation,
            &["id".into()],
            "__relay_record_identifier_count",
            &mut parameters,
        )
        .expect("list SQL compiles");
        assert!(sql.contains(
            "(typeof(:cursor_0) = 'text' AND (typeof(\"id\") != 'text' OR \"id\" COLLATE BINARY > :cursor_0))"
        ));
        assert!(sql.contains("ORDER BY \"id\" COLLATE BINARY ASC"));

        let statement = ReadOnlyStatement::open(
            DatabaseProfile::Snapshot(
                CapturedSnapshot::capture(&database).expect("fixture captures"),
            ),
            StatementContract {
                sql,
                columns: vec![
                    ColumnContract {
                        name: "id".into(),
                        value_type: ColumnType::String,
                    },
                    ColumnContract {
                        name: "__relay_record_identifier_count".into(),
                        value_type: ColumnType::Integer,
                    },
                ],
                parameters,
                limits: StatementLimits {
                    maximum_rows: 1,
                    maximum_cell_bytes: 128,
                    maximum_response_bytes: 1_024,
                    maximum_statement_steps: 10_000,
                    timeout: Duration::from_secs(2),
                    concurrency: 1,
                },
                schema: None,
            },
        )
        .expect("statement opens");

        let mut observed = Vec::new();
        let mut malformed_refused = false;
        let mut after = None;
        loop {
            let mut values = BTreeMap::from([
                (
                    "cursor_present".into(),
                    Value::Integer(i64::from(after.is_some())),
                ),
                ("fetch_limit".into(), Value::Integer(1)),
            ]);
            values.insert(
                "cursor_0".into(),
                after.clone().map_or(Value::Null, Value::String),
            );
            let rows = match statement.execute(&values).await {
                Ok(result) => result.rows,
                Err(_) => {
                    malformed_refused = true;
                    break;
                }
            };
            let Some(row) = rows.first() else {
                break;
            };
            let Value::String(identifier) = row.get("id").expect("identifier projects") else {
                panic!("identifier is a string");
            };
            observed.push(identifier.clone());
            after = Some(identifier.clone());
        }

        assert_eq!(observed, ["A", "a", "b"]);
        assert!(malformed_refused);
    }

    #[test]
    fn multiply_bound_raw_columns_must_have_one_runtime_type() {
        assert!(matches!(
            resolve_column_type([ColumnType::String, ColumnType::Integer]),
            Err(SqliteRuntimeError::InvalidPlan)
        ));
    }

    #[test]
    fn every_keyset_inequality_has_the_declared_storage_class_shape() {
        assert_eq!(
            OrderColumn {
                name: "text_key",
                value_type: ColumnType::String,
            }
            .greater_than("cursor_0"),
            "(typeof(:cursor_0) = 'text' AND (typeof(\"text_key\") != 'text' OR \"text_key\" COLLATE BINARY > :cursor_0))"
        );
        assert_eq!(
            OrderColumn {
                name: "integer_key",
                value_type: ColumnType::Integer,
            }
            .greater_than("cursor_0"),
            "(typeof(:cursor_0) = 'integer' AND (typeof(\"integer_key\") != 'integer' OR \"integer_key\" > :cursor_0))"
        );
        assert_eq!(
            OrderColumn {
                name: "boolean_key",
                value_type: ColumnType::Boolean,
            }
            .greater_than("cursor_0"),
            "(typeof(:cursor_0) = 'integer' AND (typeof(\"boolean_key\") != 'integer' OR \"boolean_key\" > :cursor_0))"
        );
        assert_eq!(
            OrderColumn {
                name: "number_key",
                value_type: ColumnType::Number,
            }
            .greater_than("cursor_0"),
            "(typeof(:cursor_0) IN ('integer', 'real') AND (typeof(\"number_key\") != typeof(:cursor_0) OR typeof(\"number_key\") NOT IN ('integer', 'real') OR \"number_key\" > :cursor_0))"
        );
    }

    #[test]
    fn every_text_keyset_term_uses_the_same_binary_collation() {
        let order = [
            OrderColumn {
                name: "group",
                value_type: ColumnType::String,
            },
            OrderColumn {
                name: "id",
                value_type: ColumnType::String,
            },
        ];
        let mut parameters = Vec::new();

        assert_eq!(
            keyset_predicate(&order, &mut parameters),
            "((typeof(:cursor_0) = 'text' AND (typeof(\"group\") != 'text' OR \"group\" COLLATE BINARY > :cursor_0))) OR ((typeof(\"group\") = 'text' AND typeof(:cursor_0) = 'text' AND \"group\" COLLATE BINARY = :cursor_0) AND (typeof(:cursor_1) = 'text' AND (typeof(\"id\") != 'text' OR \"id\" COLLATE BINARY > :cursor_1)))"
        );
        assert_eq!(
            parameters
                .iter()
                .map(|parameter| parameter.name.as_str())
                .collect::<Vec<_>>(),
            ["cursor_0", "cursor_1"]
        );
    }

    fn list_operation() -> CompiledOperation {
        CompiledOperation {
            identifier: "record.list".into(),
            family: CapabilityFamily::Consultation,
            pattern: ConsultationPattern::List,
            kind: OperationKind::List,
            default_representation: "default".into(),
            representations: vec![representation()],
            query: QueryPlan {
                source: "source".into(),
                view: "records".into(),
                filters: Vec::new(),
                selectors: Vec::new(),
                order_by: vec!["id".into()],
                allow_unfiltered: true,
                pagination: Some(CompiledPagination {
                    default_page_size: 1,
                    maximum_page_size: 1,
                }),
                maximum_request_body_bytes: None,
            },
        }
    }

    fn lookup_operation(
        source_column: &str,
        data_type: DataType,
        representation: CompiledRepresentation,
    ) -> CompiledOperation {
        CompiledOperation {
            identifier: "record.lookup.by-key".into(),
            family: CapabilityFamily::Consultation,
            pattern: ConsultationPattern::Search,
            kind: OperationKind::Lookup {
                name: "by-key".into(),
            },
            default_representation: representation.id.clone(),
            representations: vec![representation],
            query: QueryPlan {
                source: "source".into(),
                view: "records".into(),
                filters: Vec::new(),
                selectors: vec![CompiledSelector {
                    name: "key".into(),
                    source_column: source_column.into(),
                    data_type,
                    minimum_bytes: None,
                    maximum_bytes: None,
                    codelist: None,
                }],
                order_by: Vec::new(),
                allow_unfiltered: false,
                pagination: None,
                maximum_request_body_bytes: Some(128),
            },
        }
    }

    fn test_statement(
        database: &std::path::Path,
        sql: String,
        parameters: Vec<ParameterContract>,
    ) -> ReadOnlyStatement {
        ReadOnlyStatement::open(
            DatabaseProfile::Snapshot(
                CapturedSnapshot::capture(database).expect("fixture captures"),
            ),
            StatementContract {
                sql,
                columns: vec![ColumnContract {
                    name: "id".into(),
                    value_type: ColumnType::String,
                }],
                parameters,
                limits: StatementLimits {
                    maximum_rows: 2,
                    maximum_cell_bytes: 128,
                    maximum_response_bytes: 1_024,
                    maximum_statement_steps: 10_000,
                    timeout: Duration::from_secs(2),
                    concurrency: 1,
                },
                schema: None,
            },
        )
        .expect("statement opens")
    }

    fn keyset_test_statement(
        database: &std::path::Path,
        value_type: ColumnType,
    ) -> ReadOnlyStatement {
        let order = [OrderColumn {
            name: "sort_key",
            value_type,
        }];
        let mut parameters = Vec::new();
        let predicate = keyset_predicate(&order, &mut parameters);
        let sql = format!(
            "SELECT \"id\" FROM \"records\" WHERE {predicate} ORDER BY {} ASC LIMIT 2",
            order[0].sql_expression()
        );
        test_statement(database, sql, parameters)
    }

    async fn keyset_ids(statement: &ReadOnlyStatement, cursor: Value) -> Vec<String> {
        statement
            .execute(&BTreeMap::from([("cursor_0".into(), cursor)]))
            .await
            .expect("keyset query executes")
            .rows
            .into_iter()
            .map(|row| match row.get("id") {
                Some(Value::String(identifier)) => identifier.clone(),
                _ => panic!("identifier is a string"),
            })
            .collect()
    }

    fn representation() -> CompiledRepresentation {
        CompiledRepresentation {
            id: "default".into(),
            access: CompiledAccess::Public,
            disclosure_profile: "default".into(),
            selectable_properties: Vec::new(),
            projected_columns: vec!["id".into()],
            processing_handling: Handling::Public,
            disclosure_handling: Handling::Public,
            transform_inventory: Vec::new(),
            schema_reference: "https://example.invalid/schema".into(),
            semantic_model_reference: "https://example.invalid/model".into(),
            context_reference: "https://example.invalid/context".into(),
        }
    }

    fn resource() -> CompiledResource {
        CompiledResource {
            id: "record".into(),
            title: "Record".into(),
            description: "Synthetic record".into(),
            semantic_class: "https://example.invalid/Record".into(),
            source: "source".into(),
            view: "records".into(),
            record_context: CompiledRecordContext {
                record_identifier_column: "id".into(),
                revision_identifier_column: "revision".into(),
                lifecycle_state_column: "lifecycle".into(),
                lifecycle_state_codelist: "codelists/lifecycle.yaml".into(),
                recorded_at_column: "recorded_at".into(),
                schema_reference: "https://example.invalid/schema".into(),
                semantic_model_reference: "https://example.invalid/model".into(),
            },
            properties: Vec::new(),
            disclosure_profiles: Vec::new(),
            operations: Vec::new(),
            column_accounting: Vec::new(),
            processing_descriptions: Vec::new(),
        }
    }
}
