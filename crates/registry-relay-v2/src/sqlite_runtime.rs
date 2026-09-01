// SPDX-License-Identifier: Apache-2.0
//! Concrete operation-keyed SQLite execution for the Relay V2 runtime.
//!
//! SQL is generated once from the immutable compiler model. Public requests
//! can supply values only for the named parameters already present in that
//! statement. There is deliberately no storage trait or caller-authored SQL.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use registry_platform_sqlite::{
    schema_fingerprint, CapturedSnapshot, ColumnContract, ColumnType, DatabaseProfile,
    InspectionLimits, LiveDatabaseFile, ParameterContract, ReadOnlyStatement, ResultRow,
    SchemaBinding, SqliteError, StatementContract, StatementLimits, Value,
};
use thiserror::Error;
use tokio::sync::{watch, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

use crate::auth::RowAuthority;
use crate::contract::{DataType, SourceProfile, StatisticalValueType};
use crate::model::{
    CompiledAccess, CompiledAccessProfile, CompiledOperation, CompiledRegistry, CompiledResource,
    CompiledStatisticalDataset, OperationKind,
};
use crate::sdmx::{DataQuery, StatisticalRow, StatisticalValue};

const MAXIMUM_CELL_BYTES: usize = 1024 * 1024;
const MAXIMUM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
// SQLite accounts for the serialized source rows, while Relay adds its own
// collection metadata and representation-specific envelope. Keep that
// envelope outside the row budget so every Record representation remains
// below the final response serializer ceiling.
const MAXIMUM_RECORD_RESPONSE_ENVELOPE_BYTES: usize = 1024 * 1024;
const MAXIMUM_RECORD_RESULT_BYTES: usize =
    MAXIMUM_RESPONSE_BYTES - MAXIMUM_RECORD_RESPONSE_ENVELOPE_BYTES;
const MAXIMUM_STATEMENT_STEPS: u64 = 2_000_000;
const SCHEMA_MAXIMUM_OBJECTS: usize = 10_000;
const SCHEMA_MAXIMUM_SQL_BYTES: usize = 8 * 1024 * 1024;
const SCHEMA_MAXIMUM_STEPS: u64 = 1_000_000;
const MAXIMUM_STATISTICAL_VALUES_PER_COMPONENT: usize = 16;

pub(crate) type SqlValue = Value;

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
    pub bbox: Option<PointBbox>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PointBbox {
    pub west: f64,
    pub south: f64,
    pub east: f64,
    pub north: f64,
}

impl PointBbox {
    #[must_use]
    pub fn is_valid(self) -> bool {
        [self.west, self.south, self.east, self.north]
            .into_iter()
            .all(f64::is_finite)
            && (-180.0..=180.0).contains(&self.west)
            && (-180.0..=180.0).contains(&self.east)
            && (-90.0..=90.0).contains(&self.south)
            && (-90.0..=90.0).contains(&self.north)
            && self.west <= self.east
            && self.south <= self.north
    }

    #[must_use]
    pub fn is_within(self, spatial: &crate::model::CompiledSpatialBboxQuery) -> bool {
        self.is_valid()
            && self.east - self.west <= f64::from(spatial.maximum_longitude_span_degrees)
            && self.north - self.south <= f64::from(spatial.maximum_latitude_span_degrees)
    }
}

#[derive(Clone, Debug)]
pub struct OperationResult {
    pub rows: Vec<ResultRow>,
    pub source_revision: SourceRevision,
}

#[derive(Clone, Debug)]
pub(crate) struct StatisticalOperationResult {
    pub(crate) rows: Vec<StatisticalRow>,
    pub(crate) source_revision: SourceRevision,
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
    #[error("the statistical result exceeds the governed observation bound")]
    ResultTooLarge,
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
    access_profile: CompiledAccessProfile,
    source_revision: SourceRevision,
    list_identifier_count_column: Option<String>,
}

struct OperationInventory {
    source_revision: SourceRevision,
    access_profiles: BTreeMap<String, OperationExecutor>,
}

struct StatisticalExecutor {
    statement: Arc<ReadOnlyStatement>,
    dataset: CompiledStatisticalDataset,
    source_revision: SourceRevision,
    observation_count_column: String,
}

#[derive(Clone)]
struct ReadinessSource {
    profile: DatabaseProfile,
    expected_schema_fingerprint: String,
}

#[derive(Default)]
struct ReadinessCoordinator {
    in_flight: AsyncMutex<Option<watch::Receiver<Option<bool>>>>,
}

impl ReadinessCoordinator {
    async fn check<F, Fut>(self: &Arc<Self>, check: F) -> bool
    where
        F: FnOnce(watch::Sender<Option<bool>>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut receiver = {
            let mut in_flight = self.in_flight.lock().await;
            if let Some(receiver) = in_flight.as_ref() {
                receiver.clone()
            } else {
                let (sender, receiver) = watch::channel(None);
                *in_flight = Some(receiver.clone());
                let coordinator = Arc::clone(self);
                tokio::spawn(async move {
                    if tokio::spawn(check(sender.clone())).await.is_err() {
                        let _ = sender.send(Some(false));
                    }
                    coordinator.in_flight.lock().await.take();
                });
                receiver
            }
        };

        loop {
            if let Some(result) = *receiver.borrow() {
                return result;
            }
            if receiver.changed().await.is_err() {
                return false;
            }
        }
    }
}

/// Fixed operation inventory over one compiled Registry.
pub struct SqliteRuntime {
    operations: BTreeMap<String, OperationInventory>,
    statistical_operations: BTreeMap<String, StatisticalExecutor>,
    readiness_sources: Vec<ReadinessSource>,
    readiness: Arc<ReadinessCoordinator>,
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
                let mut access_profiles = BTreeMap::new();
                for access_profile in &operation.access_profiles {
                    let PreparedStatementContract {
                        contract,
                        list_identifier_count_column,
                    } = statement_contract(
                        resource,
                        operation,
                        access_profile,
                        &limits,
                        &source.expected_schema_fingerprint,
                    )?;
                    let statement = ReadOnlyStatement::open(profile.clone(), contract)?;
                    if access_profiles
                        .insert(
                            access_profile.id.clone(),
                            OperationExecutor {
                                statement: Arc::new(statement),
                                operation: operation.clone(),
                                access_profile: access_profile.clone(),
                                source_revision: source_revision.clone(),
                                list_identifier_count_column,
                            },
                        )
                        .is_some()
                    {
                        return Err(SqliteRuntimeError::InvalidPlan);
                    }
                }
                if access_profiles.is_empty()
                    || operations
                        .insert(
                            operation.identifier.clone(),
                            OperationInventory {
                                source_revision: source_revision.clone(),
                                access_profiles,
                            },
                        )
                        .is_some()
                {
                    return Err(SqliteRuntimeError::InvalidPlan);
                }
            }
        }

        let mut statistical_operations = BTreeMap::new();
        for dataset in &registry.statistical_datasets {
            let (profile, source_revision) = profiles
                .get(&dataset.source)
                .ok_or(SqliteRuntimeError::MissingSource)?;
            let source = registry
                .sources
                .iter()
                .find(|source| source.id == dataset.source)
                .ok_or(SqliteRuntimeError::MissingSource)?;
            let PreparedStatisticalStatement {
                contract,
                observation_count_column,
            } = statistical_statement_contract(
                dataset,
                &limits,
                &source.expected_schema_fingerprint,
            )?;
            let statement = ReadOnlyStatement::open(profile.clone(), contract)?;
            if statistical_operations
                .insert(
                    dataset.operation_identifier(),
                    StatisticalExecutor {
                        statement: Arc::new(statement),
                        dataset: dataset.clone(),
                        source_revision: source_revision.clone(),
                        observation_count_column,
                    },
                )
                .is_some()
            {
                return Err(SqliteRuntimeError::InvalidPlan);
            }
        }

        Ok(Self {
            operations,
            statistical_operations,
            readiness_sources,
            readiness: Arc::new(ReadinessCoordinator::default()),
            admission: Arc::new(Semaphore::new(limits.concurrent_queries)),
            timeout: limits.request_timeout,
        })
    }

    /// Confirm every continuing source release gate without reading row data.
    /// Failures remain categorical so callers cannot expose a source identifier,
    /// path, schema, or value through readiness.
    pub async fn is_ready(&self) -> bool {
        let sources = self.readiness_sources.clone();
        let timeout = self.timeout;
        self.readiness
            .check(move |sender| verify_readiness_sources(sources, timeout, sender))
            .await
    }

    #[must_use]
    pub fn source_revision(&self, operation: &str) -> Option<&SourceRevision> {
        self.operations
            .get(operation)
            .map(|item| &item.source_revision)
            .or_else(|| {
                self.statistical_operations
                    .get(operation)
                    .map(|item| &item.source_revision)
            })
    }

    pub async fn execute(
        &self,
        operation: &str,
        access_profile: &str,
        query: OperationQuery,
    ) -> Result<OperationResult, SqliteRuntimeError> {
        let executor = self
            .operations
            .get(operation)
            .and_then(|inventory| inventory.access_profiles.get(access_profile))
            .ok_or(SqliteRuntimeError::UnknownOperation)?;
        let deadline = self.request_deadline()?;
        let permit = self.acquire_before(deadline).await?;
        let values = bind_operation_values(&executor.operation, &executor.access_profile, query)?;
        let result = executor.statement.execute_before(&values, deadline).await;
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

    pub(crate) async fn execute_statistical(
        &self,
        operation_identifier: &str,
        query: DataQuery,
        row_authority: Option<SqlValue>,
    ) -> Result<StatisticalOperationResult, SqliteRuntimeError> {
        let executor = self
            .statistical_operations
            .get(operation_identifier)
            .ok_or(SqliteRuntimeError::UnknownOperation)?;
        let deadline = self.request_deadline()?;
        let permit = self.acquire_before(deadline).await?;
        let values = bind_statistical_values(&executor.dataset, &query, row_authority)?;
        let result = executor.statement.execute_before(&values, deadline).await;
        drop(permit);

        let raw_rows = result?.rows;
        let mut rows = Vec::with_capacity(raw_rows.len());
        for mut row in raw_rows {
            if row.remove(&executor.observation_count_column) != Some(Value::Integer(1)) {
                return Err(SqliteRuntimeError::InvalidSourceShape);
            }
            rows.push(normalize_statistical_row(&executor.dataset, row)?);
        }
        if !query.explicit_limit && rows.len() > executor.dataset.maximum_observations as usize {
            return Err(SqliteRuntimeError::ResultTooLarge);
        }
        Ok(StatisticalOperationResult {
            rows,
            source_revision: executor.source_revision.clone(),
        })
    }

    fn request_deadline(&self) -> Result<Instant, SqliteRuntimeError> {
        Instant::now()
            .checked_add(self.timeout)
            .ok_or(SqliteRuntimeError::InvalidPlan)
    }

    async fn acquire_before(
        &self,
        deadline: Instant,
    ) -> Result<OwnedSemaphorePermit, SqliteRuntimeError> {
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            Arc::clone(&self.admission).acquire_owned(),
        )
        .await
        .map_err(|_| SqliteRuntimeError::AdmissionTimeout)?
        .map_err(|_| SqliteRuntimeError::InvalidPlan)
    }
}

async fn verify_readiness_sources(
    sources: Vec<ReadinessSource>,
    timeout: Duration,
    result: watch::Sender<Option<bool>>,
) {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        let _ = result.send(Some(false));
        return;
    };
    let mut check = tokio::task::spawn_blocking(move || {
        for source in sources {
            if let DatabaseProfile::Snapshot(snapshot) = &source.profile {
                if snapshot.verify_unchanged_before(deadline).is_err() {
                    return false;
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            if remaining.is_zero() {
                return false;
            }
            let Ok(observed) = schema_fingerprint(
                &source.profile,
                &InspectionLimits {
                    maximum_objects: SCHEMA_MAXIMUM_OBJECTS,
                    maximum_sql_bytes: SCHEMA_MAXIMUM_SQL_BYTES,
                    maximum_statement_steps: SCHEMA_MAXIMUM_STEPS,
                    timeout: remaining,
                },
            ) else {
                return false;
            };
            if observed != source.expected_schema_fingerprint {
                return false;
            }
        }
        true
    });
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut check).await {
        Ok(Ok(ready)) => {
            let _ = result.send(Some(ready));
        }
        Ok(Err(_)) => {
            let _ = result.send(Some(false));
        }
        Err(_) => {
            // Publish the bounded result immediately, but keep the readiness
            // flight occupied until the worker observes the same deadline and
            // exits. A following probe therefore cannot start a second hash.
            let _ = result.send(Some(false));
            let _ = check.await;
        }
    }
}

struct PreparedStatisticalStatement {
    contract: StatementContract,
    observation_count_column: String,
}

#[derive(Clone)]
struct StatisticalResultColumn {
    name: String,
    value_type: ColumnType,
}

fn statistical_statement_contract(
    dataset: &CompiledStatisticalDataset,
    limits: &SqliteRuntimeLimits,
    expected_schema_fingerprint: &str,
) -> Result<PreparedStatisticalStatement, SqliteRuntimeError> {
    let columns = statistical_result_columns(dataset);
    let names = columns
        .iter()
        .map(|column| column.name.clone())
        .collect::<Vec<_>>();
    let observation_count_column = collision_free_statistical_count_column(&names);
    let mut result_contract = columns
        .iter()
        .map(|column| ColumnContract {
            name: column.name.clone(),
            value_type: column.value_type,
        })
        .collect::<Vec<_>>();
    result_contract.push(ColumnContract {
        name: observation_count_column.clone(),
        value_type: ColumnType::Integer,
    });

    let mut parameters = Vec::new();
    let mut predicates = Vec::new();
    for (index, dimension) in dataset.dimensions.iter().enumerate() {
        add_statistical_exact_predicate(
            index,
            &dimension.source_column,
            dimension.data_type,
            &mut parameters,
            &mut predicates,
        );
    }
    let time_index = dataset.dimensions.len();
    add_statistical_exact_predicate(
        time_index,
        &dataset.time.source_column,
        StatisticalValueType::String,
        &mut parameters,
        &mut predicates,
    );
    for (suffix, operator) in [("lower", ">="), ("upper", "<=")] {
        let present = format!("stat_{time_index}_{suffix}_present");
        let value = format!("stat_{time_index}_{suffix}");
        parameters.push(parameter(&present));
        parameters.push(parameter(&value));
        let column = quote_identifier(&dataset.time.source_column);
        predicates.push(format!(
            "(:{present} = 0 OR (typeof({column}) = 'text' AND typeof(:{value}) = 'text' AND {column} COLLATE BINARY {operator} :{value}))"
        ));
    }
    if let CompiledAccess::Protected {
        row_binding: Some(binding),
        ..
    } = &dataset.access
    {
        parameters.push(parameter("stat_row_authority"));
        predicates.push(statistical_exact_equality_predicate(
            &binding.source_column,
            "stat_row_authority",
            StatisticalValueType::String,
        ));
    }
    parameters.push(parameter("stat_limit"));
    parameters.push(parameter("stat_offset"));

    let partition_key = dataset
        .dimensions
        .iter()
        .map(|dimension| dimension.source_column.as_str())
        .chain(std::iter::once(dataset.time.source_column.as_str()))
        .flat_map(|column| {
            let column = quote_identifier(column);
            [
                format!("typeof({column})"),
                format!("{column} COLLATE BINARY"),
            ]
        })
        .collect::<Vec<_>>()
        .join(", ");
    let order = dataset
        .dimensions
        .iter()
        .map(|dimension| dimension.source_column.as_str())
        .chain(std::iter::once(dataset.time.source_column.as_str()))
        .map(|column| format!("{} COLLATE BINARY ASC", quote_identifier(column)))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "WITH \"__relay_statistical_scope\" AS (SELECT {}, COUNT(*) OVER (PARTITION BY {partition_key}) AS {} FROM {} WHERE {}) SELECT {}, {} FROM \"__relay_statistical_scope\" ORDER BY {order} LIMIT :stat_limit OFFSET :stat_offset",
        select_list(&names),
        quote_identifier(&observation_count_column),
        quote_identifier(&dataset.view),
        predicates.join(" AND "),
        select_list(&names),
        quote_identifier(&observation_count_column),
    );

    Ok(PreparedStatisticalStatement {
        contract: StatementContract {
            sql,
            columns: result_contract,
            parameters,
            limits: StatementLimits {
                maximum_rows: u64::from(dataset.maximum_observations).saturating_add(1),
                maximum_cell_bytes: MAXIMUM_CELL_BYTES,
                maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
                maximum_statement_steps: MAXIMUM_STATEMENT_STEPS,
                timeout: limits.request_timeout,
                concurrency: 1,
            },
            schema: Some(SchemaBinding {
                expected_fingerprint: expected_schema_fingerprint.to_owned(),
                maximum_objects: SCHEMA_MAXIMUM_OBJECTS,
                maximum_sql_bytes: SCHEMA_MAXIMUM_SQL_BYTES,
            }),
        },
        observation_count_column,
    })
}

fn statistical_result_columns(
    dataset: &CompiledStatisticalDataset,
) -> Vec<StatisticalResultColumn> {
    dataset
        .dimensions
        .iter()
        .map(|component| StatisticalResultColumn {
            name: component.source_column.clone(),
            value_type: statistical_column_type(component.data_type),
        })
        .chain(std::iter::once(StatisticalResultColumn {
            name: dataset.time.source_column.clone(),
            value_type: ColumnType::String,
        }))
        .chain(std::iter::once(StatisticalResultColumn {
            name: dataset.measure.source_column.clone(),
            value_type: statistical_column_type(dataset.measure.data_type),
        }))
        .chain(
            dataset
                .attributes
                .iter()
                .map(|component| StatisticalResultColumn {
                    name: component.source_column.clone(),
                    value_type: statistical_column_type(component.data_type),
                }),
        )
        .collect()
}

fn statistical_column_type(value_type: StatisticalValueType) -> ColumnType {
    match value_type {
        StatisticalValueType::Code | StatisticalValueType::String => ColumnType::String,
        StatisticalValueType::Integer => ColumnType::Integer,
        StatisticalValueType::Decimal => ColumnType::Number,
        StatisticalValueType::Boolean => ColumnType::Boolean,
    }
}

fn add_statistical_exact_predicate(
    index: usize,
    column: &str,
    value_type: StatisticalValueType,
    parameters: &mut Vec<ParameterContract>,
    predicates: &mut Vec<String>,
) {
    let present = format!("stat_{index}_exact_present");
    parameters.push(parameter(&present));
    let mut alternatives = Vec::with_capacity(MAXIMUM_STATISTICAL_VALUES_PER_COMPONENT);
    for value_index in 0..MAXIMUM_STATISTICAL_VALUES_PER_COMPONENT {
        let value_present = format!("stat_{index}_exact_{value_index}_present");
        let value = format!("stat_{index}_exact_{value_index}");
        parameters.push(parameter(&value_present));
        parameters.push(parameter(&value));
        alternatives.push(format!(
            "(:{value_present} = 1 AND {})",
            statistical_exact_equality_predicate(column, &value, value_type)
        ));
    }
    predicates.push(format!(
        "(:{present} = 0 OR ({}))",
        alternatives.join(" OR ")
    ));
}

fn statistical_exact_equality_predicate(
    column: &str,
    parameter: &str,
    value_type: StatisticalValueType,
) -> String {
    let column = quote_identifier(column);
    match value_type {
        StatisticalValueType::Code | StatisticalValueType::String => format!(
            "(typeof({column}) = 'text' AND typeof(:{parameter}) = 'text' AND {column} COLLATE BINARY = :{parameter})"
        ),
        StatisticalValueType::Integer | StatisticalValueType::Boolean => format!(
            "(typeof({column}) = 'integer' AND typeof(:{parameter}) = 'integer' AND {column} = :{parameter})"
        ),
        StatisticalValueType::Decimal => format!(
            "(typeof({column}) = typeof(:{parameter}) AND typeof({column}) IN ('integer', 'real') AND {column} = :{parameter})"
        ),
    }
}

fn collision_free_statistical_count_column(columns: &[String]) -> String {
    const BASE: &str = "__relay_observation_key_count";
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

fn bind_statistical_values(
    dataset: &CompiledStatisticalDataset,
    query: &DataQuery,
    row_authority: Option<SqlValue>,
) -> Result<BTreeMap<String, Value>, SqliteRuntimeError> {
    if query.limit == 0
        || query.limit > dataset.maximum_observations
        || query.offset > dataset.maximum_offset
        || (!dataset.allow_unfiltered && query.constraints.is_empty())
    {
        return Err(SqliteRuntimeError::InvalidPlan);
    }
    let declared = dataset
        .dimensions
        .iter()
        .map(|dimension| dimension.id.as_str())
        .chain(std::iter::once(dataset.time.id.as_str()))
        .collect::<BTreeSet<_>>();
    if query
        .constraints
        .keys()
        .any(|identifier| !declared.contains(identifier.as_str()))
    {
        return Err(SqliteRuntimeError::InvalidPlan);
    }

    let mut values = BTreeMap::new();
    for (index, (identifier, value_type)) in dataset
        .dimensions
        .iter()
        .map(|dimension| (dimension.id.as_str(), dimension.data_type))
        .chain(std::iter::once((
            dataset.time.id.as_str(),
            StatisticalValueType::String,
        )))
        .enumerate()
    {
        let constraint = query.constraints.get(identifier);
        let exact = constraint.map_or(&[][..], |constraint| constraint.exact.as_slice());
        if exact.len() > MAXIMUM_STATISTICAL_VALUES_PER_COMPONENT
            || (identifier != dataset.time.id
                && constraint.is_some_and(|constraint| {
                    constraint.lower.is_some() || constraint.upper.is_some()
                }))
        {
            return Err(SqliteRuntimeError::InvalidPlan);
        }
        values.insert(
            format!("stat_{index}_exact_present"),
            Value::Integer(i64::from(!exact.is_empty())),
        );
        for value_index in 0..MAXIMUM_STATISTICAL_VALUES_PER_COMPONENT {
            let value = exact.get(value_index);
            values.insert(
                format!("stat_{index}_exact_{value_index}_present"),
                Value::Integer(i64::from(value.is_some())),
            );
            values.insert(
                format!("stat_{index}_exact_{value_index}"),
                value
                    .map(|value| statistical_query_value(value, value_type))
                    .transpose()?
                    .unwrap_or(Value::Null),
            );
        }
    }
    let time_index = dataset.dimensions.len();
    let time_constraint = query.constraints.get(&dataset.time.id);
    for (suffix, value) in [
        (
            "lower",
            time_constraint.and_then(|constraint| constraint.lower.as_ref()),
        ),
        (
            "upper",
            time_constraint.and_then(|constraint| constraint.upper.as_ref()),
        ),
    ] {
        values.insert(
            format!("stat_{time_index}_{suffix}_present"),
            Value::Integer(i64::from(value.is_some())),
        );
        values.insert(
            format!("stat_{time_index}_{suffix}"),
            value.cloned().map(Value::String).unwrap_or(Value::Null),
        );
    }

    match (&dataset.access, row_authority) {
        (
            CompiledAccess::Protected {
                row_binding: Some(_),
                ..
            },
            Some(Value::String(authority)),
        ) => {
            values.insert("stat_row_authority".into(), Value::String(authority));
        }
        (CompiledAccess::Public, None)
        | (
            CompiledAccess::Protected {
                row_binding: None, ..
            },
            None,
        ) => {}
        _ => return Err(SqliteRuntimeError::InvalidPlan),
    }
    let fetch_limit = if query.explicit_limit {
        query.limit
    } else {
        dataset.maximum_observations.saturating_add(1)
    };
    values.insert("stat_limit".into(), Value::Integer(i64::from(fetch_limit)));
    values.insert(
        "stat_offset".into(),
        Value::Integer(i64::from(query.offset)),
    );
    Ok(values)
}

fn statistical_query_value(
    value: &StatisticalValue,
    expected: StatisticalValueType,
) -> Result<Value, SqliteRuntimeError> {
    match (expected, value) {
        (
            StatisticalValueType::Code | StatisticalValueType::String,
            StatisticalValue::String(value),
        ) => Ok(Value::String(value.clone())),
        (StatisticalValueType::Integer, StatisticalValue::Integer(value)) => {
            Ok(Value::Integer(*value))
        }
        (StatisticalValueType::Decimal, StatisticalValue::Integer(value)) => {
            Ok(Value::Integer(*value))
        }
        (StatisticalValueType::Decimal, StatisticalValue::Decimal(value)) if value.is_finite() => {
            Ok(Value::Number(*value))
        }
        (StatisticalValueType::Boolean, StatisticalValue::Boolean(value)) => {
            Ok(Value::Boolean(*value))
        }
        _ => Err(SqliteRuntimeError::InvalidPlan),
    }
}

fn normalize_statistical_row(
    dataset: &CompiledStatisticalDataset,
    mut row: ResultRow,
) -> Result<StatisticalRow, SqliteRuntimeError> {
    let expected = statistical_result_columns(dataset);
    if row.len() != expected.len() {
        return Err(SqliteRuntimeError::InvalidSourceShape);
    }
    let mut normalized = BTreeMap::new();
    for column in expected {
        let value = row
            .remove(&column.name)
            .ok_or(SqliteRuntimeError::InvalidSourceShape)?;
        let value = match value {
            Value::Null => StatisticalValue::Null,
            Value::String(value) => StatisticalValue::String(value),
            Value::Integer(value) => StatisticalValue::Integer(value),
            Value::Number(value) if value.is_finite() => StatisticalValue::Decimal(value),
            Value::Boolean(value) => StatisticalValue::Boolean(value),
            Value::Number(_) => return Err(SqliteRuntimeError::InvalidSourceShape),
        };
        normalized.insert(column.name, value);
    }
    if !row.is_empty() {
        return Err(SqliteRuntimeError::InvalidSourceShape);
    }
    Ok(normalized)
}

struct PreparedStatementContract {
    contract: StatementContract,
    list_identifier_count_column: Option<String>,
}

fn statement_contract(
    resource: &CompiledResource,
    operation: &CompiledOperation,
    access_profile: &CompiledAccessProfile,
    limits: &SqliteRuntimeLimits,
    expected_schema_fingerprint: &str,
) -> Result<PreparedStatementContract, SqliteRuntimeError> {
    let result_columns = result_columns(operation, access_profile);
    let mut columns = result_columns
        .iter()
        .map(|column| {
            Ok(ColumnContract {
                name: column.clone(),
                value_type: column_type(resource, column)?,
            })
        })
        .collect::<Result<Vec<_>, SqliteRuntimeError>>()?;
    let list_identifier_count_column = matches!(
        &operation.kind,
        OperationKind::List | OperationKind::Search { .. }
    )
    .then(|| collision_free_identifier_count_column(&result_columns));
    if let Some(column) = &list_identifier_count_column {
        columns.push(ColumnContract {
            name: column.clone(),
            value_type: ColumnType::Integer,
        });
    }
    let mut parameters = Vec::new();
    let sql = match &operation.kind {
        OperationKind::List | OperationKind::Search { .. } => list_sql(
            resource,
            operation,
            access_profile,
            &result_columns,
            list_identifier_count_column
                .as_deref()
                .ok_or(SqliteRuntimeError::InvalidPlan)?,
            &mut parameters,
        )?,
        OperationKind::Read => read_sql(
            resource,
            operation,
            access_profile,
            &result_columns,
            &mut parameters,
        ),
        OperationKind::Lookup { .. } => {
            lookup_sql(operation, access_profile, &result_columns, &mut parameters)
        }
    };
    let maximum_rows = match &operation.kind {
        OperationKind::List | OperationKind::Search { .. } => u64::from(
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
                maximum_response_bytes: MAXIMUM_RECORD_RESULT_BYTES,
                maximum_statement_steps: MAXIMUM_STATEMENT_STEPS,
                timeout: limits.request_timeout,
                // Aggregate process concurrency is owned above. Each fixed
                // access profile has one connection, and compilation bounds the
                // Registry-wide access profile executor inventory.
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
    access_profile: &CompiledAccessProfile,
) -> Vec<String> {
    let mut columns = access_profile.projected_columns.clone();
    for column in &operation.query.order_by {
        if !columns.contains(column) {
            columns.push(column.clone());
        }
    }
    if let Some(spatial) = &operation.query.spatial_bbox {
        for column in [&spatial.longitude_column, &spatial.latitude_column] {
            if !columns.contains(column) {
                columns.push(column.clone());
            }
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
        core_type
            .into_iter()
            .chain(resource.properties.iter().filter_map(|property| {
                property.point_binding().and_then(|binding| {
                    (binding.longitude_column == column || binding.latitude_column == column)
                        .then_some(ColumnType::Number)
                })
            }))
            .chain(
                resource
                    .properties
                    .iter()
                    .filter_map(|property| property.scalar_binding())
                    .filter(|binding| binding.source_column == column)
                    .map(|binding| data_type(binding.data_type)),
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
    access_profile: &CompiledAccessProfile,
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
    if let Some(spatial) = &operation.query.spatial_bbox {
        for name in ["bbox_west", "bbox_south", "bbox_east", "bbox_north"] {
            parameters.push(parameter(name));
        }
        let longitude = quote_identifier(&spatial.longitude_column);
        let latitude = quote_identifier(&spatial.latitude_column);
        scope_predicates.push(format!(
            "(typeof({latitude}) IN ('integer', 'real') AND typeof({longitude}) IN ('integer', 'real') AND {latitude} >= :bbox_south AND {latitude} <= :bbox_north AND {longitude} >= :bbox_west AND {longitude} <= :bbox_east)"
        ));
    }
    add_row_authority(access_profile, parameters, &mut scope_predicates);
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
    access_profile: &CompiledAccessProfile,
    columns: &[String],
    parameters: &mut Vec<ParameterContract>,
) -> String {
    parameters.push(parameter("record_identifier"));
    let mut predicates = vec![exact_equality_predicate(
        &resource.record_context.record_identifier_column,
        "record_identifier",
        DataType::String,
    )];
    add_row_authority(access_profile, parameters, &mut predicates);
    format!(
        "SELECT {} FROM {} WHERE {} LIMIT 2",
        select_list(columns),
        quote_identifier(&operation.query.view),
        predicates.join(" AND ")
    )
}

fn lookup_sql(
    operation: &CompiledOperation,
    access_profile: &CompiledAccessProfile,
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
    add_row_authority(access_profile, parameters, &mut predicates);
    format!(
        "SELECT {} FROM {} WHERE {} LIMIT 2",
        select_list(columns),
        quote_identifier(&operation.query.view),
        predicates.join(" AND ")
    )
}

fn add_row_authority(
    access_profile: &CompiledAccessProfile,
    parameters: &mut Vec<ParameterContract>,
    predicates: &mut Vec<String>,
) {
    if let crate::model::CompiledAccess::Protected {
        row_binding: Some(binding),
        ..
    } = &access_profile.access
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
    access_profile: &CompiledAccessProfile,
    query: OperationQuery,
) -> Result<BTreeMap<String, Value>, SqliteRuntimeError> {
    let mut values = BTreeMap::new();
    match &operation.kind {
        OperationKind::List | OperationKind::Search { .. } => {
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
            match (&operation.kind, &operation.query.spatial_bbox, query.bbox) {
                (OperationKind::Search { .. }, Some(spatial), Some(bbox)) => {
                    if !bbox.is_within(spatial) {
                        return Err(SqliteRuntimeError::InvalidPlan);
                    }
                    values.insert("bbox_west".into(), Value::Number(bbox.west));
                    values.insert("bbox_south".into(), Value::Number(bbox.south));
                    values.insert("bbox_east".into(), Value::Number(bbox.east));
                    values.insert("bbox_north".into(), Value::Number(bbox.north));
                }
                (OperationKind::List, None, None) => {}
                _ => return Err(SqliteRuntimeError::InvalidPlan),
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
            if query.bbox.is_some() {
                return Err(SqliteRuntimeError::InvalidPlan);
            }
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
            if query.bbox.is_some() {
                return Err(SqliteRuntimeError::InvalidPlan);
            }
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
    } = &access_profile.access
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use registry_platform_sqlite::{materialize_fixture, CapturedSnapshot};

    use super::*;
    use crate::contract::{Handling, ReviewStatus, StatisticalTimeGranularity};
    use crate::model::{
        CapabilityFamily, CompiledAccess, CompiledFilter, CompiledPagination,
        CompiledRecordContext, CompiledRowBinding, CompiledSdmxBindingProfile, CompiledSelector,
        CompiledSpatialBboxQuery, CompiledStatisticalAttribute, CompiledStatisticalDimension,
        CompiledStatisticalMeasure, CompiledStatisticalTimeDimension, ConsultationPattern,
        EffectiveClassification, QueryPlan, RowAuthoritySource,
    };

    #[tokio::test]
    async fn concurrent_readiness_calls_share_one_in_flight_check() {
        let coordinator = Arc::new(ReadinessCoordinator::default());
        let checks = Arc::new(AtomicUsize::new(0));
        let call = || {
            let coordinator = Arc::clone(&coordinator);
            let checks = Arc::clone(&checks);
            async move {
                coordinator
                    .check(move |result| async move {
                        checks.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        let _ = result.send(Some(true));
                    })
                    .await
            }
        };

        let (first, second, third) = tokio::join!(call(), call(), call());
        assert!(first && second && third);
        assert_eq!(checks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn snapshot_readiness_returns_false_at_the_request_deadline() {
        let temp = tempfile::tempdir().expect("temporary fixture");
        let database = temp.path().join("readiness.sqlite");
        materialize_fixture(&database, "CREATE TABLE records (id TEXT NOT NULL);")
            .expect("fixture materializes");
        let snapshot = CapturedSnapshot::capture(&database).expect("fixture captures");
        let profile = DatabaseProfile::Snapshot(snapshot);
        let expected_schema_fingerprint = schema_fingerprint(
            &profile,
            &InspectionLimits {
                maximum_objects: SCHEMA_MAXIMUM_OBJECTS,
                maximum_sql_bytes: SCHEMA_MAXIMUM_SQL_BYTES,
                maximum_statement_steps: SCHEMA_MAXIMUM_STEPS,
                timeout: Duration::from_secs(1),
            },
        )
        .expect("fixture schema fingerprints");
        let runtime = SqliteRuntime {
            operations: BTreeMap::new(),
            statistical_operations: BTreeMap::new(),
            readiness_sources: vec![ReadinessSource {
                profile,
                expected_schema_fingerprint,
            }],
            readiness: Arc::new(ReadinessCoordinator::default()),
            admission: Arc::new(Semaphore::new(1)),
            timeout: Duration::from_nanos(1),
        };

        let ready = tokio::time::timeout(Duration::from_millis(250), runtime.is_ready())
            .await
            .expect("readiness is request-bounded");
        assert!(!ready);
    }

    #[tokio::test]
    async fn record_and_statistical_execution_share_the_global_admission_deadline() {
        let temp = tempfile::tempdir().expect("temporary fixture");
        let record_database = temp.path().join("records.sqlite");
        materialize_fixture(
            &record_database,
            "CREATE TABLE records (id TEXT NOT NULL); INSERT INTO records VALUES ('record-1');",
        )
        .expect("record fixture materializes");
        let statistical_database = temp.path().join("statistics.sqlite");
        materialize_fixture(
            &statistical_database,
            "CREATE TABLE observations (ref_area TEXT, time_period TEXT, obs_value REAL, unit_measure TEXT);\
             INSERT INTO observations VALUES ('AREA', '2025', 7.0, 'PERCENT');",
        )
        .expect("statistical fixture materializes");

        let timeout = Duration::from_millis(400);
        let record = Arc::new(record_runtime(&record_database, timeout));
        let dataset = statistical_dataset(10);
        let statistical = Arc::new(statistical_runtime_with_timeout(
            &statistical_database,
            dataset.clone(),
            timeout,
        ));
        let record_statement =
            Arc::clone(&record.operations["record.list"].access_profiles["default"].statement);
        let statistical_statement = Arc::clone(
            &statistical.statistical_operations[&dataset.operation_identifier()].statement,
        );
        let record_statement_permit = record_statement
            .hold_all_permits_for_test()
            .await
            .expect("record statement permit is held");
        let statistical_statement_permit = statistical_statement
            .hold_all_permits_for_test()
            .await
            .expect("statistical statement permit is held");
        let record_global_permit = Arc::clone(&record.admission)
            .acquire_owned()
            .await
            .expect("record global permit is held");
        let statistical_global_permit = Arc::clone(&statistical.admission)
            .acquire_owned()
            .await
            .expect("statistical global permit is held");

        let record_call = {
            let runtime = Arc::clone(&record);
            tokio::spawn(async move {
                runtime
                    .execute(
                        "record.list",
                        "default",
                        OperationQuery {
                            fetch_limit: Some(1),
                            ..OperationQuery::default()
                        },
                    )
                    .await
            })
        };
        let statistical_call = {
            let runtime = Arc::clone(&statistical);
            tokio::spawn(async move {
                runtime
                    .execute_statistical(
                        &dataset.operation_identifier(),
                        statistical_query("AREA", 0, 10, true),
                        None,
                    )
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        drop(record_global_permit);
        drop(statistical_global_permit);
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(record_statement_permit);
        drop(statistical_statement_permit);

        for error in [
            record_call.await.expect("record task joins").unwrap_err(),
            statistical_call
                .await
                .expect("statistical task joins")
                .unwrap_err(),
        ] {
            assert!(matches!(
                error,
                SqliteRuntimeError::Source(ref source)
                    if source.kind() == registry_platform_sqlite::ErrorKind::Timeout
            ));
        }
    }

    #[tokio::test]
    async fn sdmx_sqlite_predicates_preserve_declared_storage_classes() {
        let temp = tempfile::tempdir().expect("temporary fixture");
        let database = temp.path().join("statistical-storage.sqlite");
        materialize_fixture(
            &database,
            "CREATE TABLE observations (ref_area, time_period, obs_value, unit_measure);\
             INSERT INTO observations VALUES\
                 ('AREA', '2025', 7, 'PERCENT'),\
                 ('1', '2026', 7.5, 'PERCENT'),\
                 (1, '2027', 8, 'PERCENT');",
        )
        .expect("fixture materializes");
        let dataset = statistical_dataset(10);
        let runtime = statistical_runtime(&database, dataset.clone());
        let prepared = statistical_statement_contract(
            &dataset,
            &SqliteRuntimeLimits {
                request_timeout: Duration::from_secs(2),
                concurrent_queries: 1,
            },
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("statistical SQL compiles");
        assert!(!prepared.contract.sql.contains(" IN ("));
        assert!(prepared.contract.sql.contains(
            "typeof(\"ref_area\") = 'text' AND typeof(:stat_0_exact_0) = 'text' AND \"ref_area\" COLLATE BINARY = :stat_0_exact_0"
        ));
        assert!(prepared.contract.sql.contains(
            "ORDER BY \"ref_area\" COLLATE BINARY ASC, \"time_period\" COLLATE BINARY ASC"
        ));

        let result = runtime
            .execute_statistical(
                &dataset.operation_identifier(),
                statistical_query("1", 0, 10, true),
                None,
            )
            .await
            .expect("text-exact statistical query executes");
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            result.rows[0].get("ref_area"),
            Some(&StatisticalValue::String("1".into()))
        );
        assert_eq!(
            result.rows[0].get("obs_value"),
            Some(&StatisticalValue::Decimal(7.5))
        );

        let integer_measure = runtime
            .execute_statistical(
                &dataset.operation_identifier(),
                statistical_query("AREA", 0, 10, true),
                None,
            )
            .await
            .expect("integer-backed decimal measure executes");
        assert_eq!(
            integer_measure.rows[0].get("obs_value"),
            Some(&StatisticalValue::Integer(7))
        );
    }

    #[tokio::test]
    async fn duplicate_sdmx_observation_keys_fail_closed_across_page_boundaries() {
        let temp = tempfile::tempdir().expect("temporary fixture");
        let database = temp.path().join("statistical-duplicates.sqlite");
        materialize_fixture(
            &database,
            "CREATE TABLE observations (ref_area TEXT, time_period TEXT, obs_value REAL, unit_measure TEXT);\
             INSERT INTO observations VALUES\
                 ('AREA', '2025', 7.0, 'PERCENT'),\
                 ('AREA', '2025', 8.0, 'PERCENT');",
        )
        .expect("fixture materializes");
        let dataset = statistical_dataset(1);
        let runtime = statistical_runtime(&database, dataset.clone());
        let error = runtime
            .execute_statistical(
                &dataset.operation_identifier(),
                statistical_query("AREA", 1, 1, true),
                None,
            )
            .await
            .expect_err("duplicate key split across pages fails closed");
        assert!(matches!(error, SqliteRuntimeError::InvalidSourceShape));
    }

    #[tokio::test]
    async fn implicit_statistical_limit_probes_one_row_and_fails_categorically() {
        let temp = tempfile::tempdir().expect("temporary fixture");
        let database = temp.path().join("statistical-bound.sqlite");
        materialize_fixture(
            &database,
            "CREATE TABLE observations (ref_area TEXT, time_period TEXT, obs_value REAL, unit_measure TEXT);\
             INSERT INTO observations VALUES\
                 ('AREA', '2025', 7.0, 'PERCENT'),\
                 ('AREA', '2026', 8.0, 'PERCENT');",
        )
        .expect("fixture materializes");
        let dataset = statistical_dataset(1);
        let runtime = statistical_runtime(&database, dataset.clone());
        let error = runtime
            .execute_statistical(
                &dataset.operation_identifier(),
                statistical_query("AREA", 0, 1, false),
                None,
            )
            .await
            .expect_err("implicit maximum probes one additional observation");
        assert!(matches!(error, SqliteRuntimeError::ResultTooLarge));
    }

    #[test]
    fn record_statement_reserves_response_envelope_budget() {
        let operation = list_operation();
        let prepared = statement_contract(
            &resource(),
            &operation,
            &operation.access_profiles[0],
            &SqliteRuntimeLimits {
                request_timeout: Duration::from_secs(2),
                concurrent_queries: 1,
            },
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("record statement compiles");

        assert_eq!(
            prepared.contract.limits.maximum_response_bytes,
            MAXIMUM_RECORD_RESULT_BYTES
        );
        assert_eq!(
            MAXIMUM_RECORD_RESULT_BYTES + MAXIMUM_RECORD_RESPONSE_ENVELOPE_BYTES,
            MAXIMUM_RESPONSE_BYTES
        );
    }

    #[test]
    fn statistical_statement_keeps_its_existing_response_budget() {
        let prepared = statistical_statement_contract(
            &statistical_dataset(10),
            &SqliteRuntimeLimits {
                request_timeout: Duration::from_secs(2),
                concurrent_queries: 1,
            },
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("statistical statement compiles");

        assert_eq!(
            prepared.contract.limits.maximum_response_bytes,
            MAXIMUM_RESPONSE_BYTES
        );
    }

    fn statistical_runtime(
        database: &std::path::Path,
        dataset: CompiledStatisticalDataset,
    ) -> SqliteRuntime {
        statistical_runtime_with_timeout(database, dataset, Duration::from_secs(2))
    }

    fn statistical_runtime_with_timeout(
        database: &std::path::Path,
        dataset: CompiledStatisticalDataset,
        timeout: Duration,
    ) -> SqliteRuntime {
        let limits = SqliteRuntimeLimits {
            request_timeout: timeout,
            concurrent_queries: 1,
        };
        let mut prepared = statistical_statement_contract(
            &dataset,
            &limits,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("statistical statement compiles");
        prepared.contract.schema = None;
        let snapshot = CapturedSnapshot::capture(database).expect("fixture captures");
        let revision = SourceRevision::Snapshot(snapshot.digest().to_owned());
        let statement =
            ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot), prepared.contract)
                .expect("statistical statement opens");
        SqliteRuntime {
            operations: BTreeMap::new(),
            statistical_operations: BTreeMap::from([(
                dataset.operation_identifier(),
                StatisticalExecutor {
                    statement: Arc::new(statement),
                    dataset,
                    source_revision: revision,
                    observation_count_column: prepared.observation_count_column,
                },
            )]),
            readiness_sources: Vec::new(),
            readiness: Arc::new(ReadinessCoordinator::default()),
            admission: Arc::new(Semaphore::new(1)),
            timeout: limits.request_timeout,
        }
    }

    fn record_runtime(database: &std::path::Path, timeout: Duration) -> SqliteRuntime {
        let resource = resource();
        let operation = list_operation();
        let access_profile = operation.access_profiles[0].clone();
        let limits = SqliteRuntimeLimits {
            request_timeout: timeout,
            concurrent_queries: 1,
        };
        let mut prepared = statement_contract(
            &resource,
            &operation,
            &access_profile,
            &limits,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("record statement compiles");
        prepared.contract.schema = None;
        let snapshot = CapturedSnapshot::capture(database).expect("fixture captures");
        let revision = SourceRevision::Snapshot(snapshot.digest().to_owned());
        let statement =
            ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot), prepared.contract)
                .expect("record statement opens");
        SqliteRuntime {
            operations: BTreeMap::from([(
                operation.identifier.clone(),
                OperationInventory {
                    source_revision: revision.clone(),
                    access_profiles: BTreeMap::from([(
                        access_profile.id.clone(),
                        OperationExecutor {
                            statement: Arc::new(statement),
                            operation,
                            access_profile,
                            source_revision: revision,
                            list_identifier_count_column: prepared.list_identifier_count_column,
                        },
                    )]),
                },
            )]),
            statistical_operations: BTreeMap::new(),
            readiness_sources: Vec::new(),
            readiness: Arc::new(ReadinessCoordinator::default()),
            admission: Arc::new(Semaphore::new(1)),
            timeout,
        }
    }

    fn statistical_query(area: &str, offset: u32, limit: u32, explicit_limit: bool) -> DataQuery {
        DataQuery {
            constraints: BTreeMap::from([(
                "REF_AREA".into(),
                crate::sdmx::ComponentConstraint {
                    exact: vec![StatisticalValue::String(area.into())],
                    lower: None,
                    upper: None,
                },
            )]),
            offset,
            limit,
            explicit_limit,
            dimension_at_observation: crate::sdmx::DimensionAtObservation::TimePeriod,
        }
    }

    fn statistical_dataset(maximum_observations: u32) -> CompiledStatisticalDataset {
        let classification = public_classification();
        CompiledStatisticalDataset {
            id: "labour-rates".into(),
            title: "Labour rates".into(),
            description: "Reviewed aggregate labour rates".into(),
            sdmx: CompiledSdmxBindingProfile {
                agency_id: "REGISTRY".into(),
                dataflow_id: "LABOUR_RATES".into(),
                version: "1.0.0".into(),
                data_structure_id: "LABOUR_RATES_DSD".into(),
                concept_scheme_id: "LABOUR_RATES_CONCEPTS".into(),
                rest_version: "2.2.2".into(),
                data_json_version: "2.1.0".into(),
                data_csv_version: "2.1.0".into(),
                structure_json_version: "2.1.0".into(),
            },
            release_at: "2026-08-10T00:00:00Z".into(),
            source: "db".into(),
            view: "observations".into(),
            dimensions: vec![CompiledStatisticalDimension {
                id: "REF_AREA".into(),
                label: "Reference area".into(),
                description: "Observation area".into(),
                source_column: "ref_area".into(),
                data_type: StatisticalValueType::Code,
                codelist: Some("codelists/areas.yaml".into()),
                semantic_iri: "https://example.invalid/refArea".into(),
                classification: classification.clone(),
            }],
            time: CompiledStatisticalTimeDimension {
                id: "TIME_PERIOD".into(),
                label: "Time period".into(),
                description: "Annual observation period".into(),
                source_column: "time_period".into(),
                granularity: StatisticalTimeGranularity::Annual,
                semantic_iri: "https://example.invalid/timePeriod".into(),
                classification: classification.clone(),
            },
            measure: CompiledStatisticalMeasure {
                id: "OBS_VALUE".into(),
                label: "Observation value".into(),
                description: "Labour rate".into(),
                source_column: "obs_value".into(),
                data_type: StatisticalValueType::Decimal,
                semantic_iri: "https://example.invalid/obsValue".into(),
                classification: classification.clone(),
            },
            attributes: vec![CompiledStatisticalAttribute {
                id: "UNIT_MEASURE".into(),
                label: "Unit".into(),
                description: "Observation unit".into(),
                source_column: "unit_measure".into(),
                data_type: StatisticalValueType::Code,
                codelist: Some("codelists/units.yaml".into()),
                source_required: true,
                semantic_iri: "https://example.invalid/unitMeasure".into(),
                classification: classification.clone(),
            }],
            access: CompiledAccess::Public,
            allow_unfiltered: true,
            maximum_observations,
            maximum_offset: 100,
            processing_handling: Handling::Public,
            disclosure_handling: Handling::Public,
            column_accounting: Vec::new(),
            processing_descriptions: Vec::new(),
        }
    }

    fn public_classification() -> EffectiveClassification {
        EffectiveClassification {
            privacy: "non-personal".into(),
            privacy_scheme: "https://w3id.org/dpv".into(),
            privacy_version: "2.3".into(),
            institutional: "public".into(),
            institutional_scheme: "urn:example:classification".into(),
            institutional_version: "1".into(),
            handling: Handling::Public,
            handling_scheme: "https://id.registrystack.org/vocab/handling".into(),
            handling_version: "1".into(),
            status: ReviewStatus::Reviewed,
            provenance_ref: "governance/classification-review.yaml".into(),
        }
    }

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

        let mut protected = access_profile();
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
            &integer_operation.access_profiles[0],
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
        let mut access_profile = access_profile();
        access_profile.access = CompiledAccess::Protected {
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
                default_access_profile: access_profile.id.clone(),
                access_profiles: vec![access_profile.clone()],
                query: QueryPlan {
                    source: "source".into(),
                    view: "records".into(),
                    filters: Vec::new(),
                    spatial_bbox: None,
                    selectors: Vec::new(),
                    order_by: Vec::new(),
                    allow_unfiltered: false,
                    pagination: None,
                    maximum_request_body_bytes: None,
                },
            },
            &access_profile,
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
            &access_profile,
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
        let access_profile = access_profile();
        let mut parameters = Vec::new();
        let sql = list_sql(
            &resource,
            &operation,
            &access_profile,
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
            default_access_profile: "default".into(),
            access_profiles: vec![access_profile()],
            query: QueryPlan {
                source: "source".into(),
                view: "records".into(),
                filters: Vec::new(),
                spatial_bbox: None,
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

    #[test]
    fn point_bbox_validation_is_numeric_and_crs84_bounded() {
        assert!(PointBbox {
            west: 100.0,
            south: -20.0,
            east: 101.0,
            north: -16.0,
        }
        .is_valid());
        for bbox in [
            PointBbox {
                west: f64::NAN,
                south: 0.0,
                east: 1.0,
                north: 1.0,
            },
            PointBbox {
                west: -181.0,
                south: 0.0,
                east: 1.0,
                north: 1.0,
            },
            PointBbox {
                west: 0.0,
                south: 2.0,
                east: 1.0,
                north: 1.0,
            },
        ] {
            assert!(!bbox.is_valid());
        }
    }

    #[test]
    fn point_bbox_refuses_dateline_crossing() {
        let spatial = CompiledSpatialBboxQuery {
            longitude_column: "longitude".into(),
            latitude_column: "latitude".into(),
            maximum_longitude_span_degrees: 1,
            maximum_latitude_span_degrees: 1,
        };
        assert!(PointBbox {
            west: 100.0,
            south: 10.0,
            east: 101.0,
            north: 11.0,
        }
        .is_within(&spatial));
        assert!(!PointBbox {
            west: 177.0,
            south: -20.0,
            east: -178.0,
            north: -16.0,
        }
        .is_valid());
    }

    #[test]
    fn named_search_requires_one_valid_bounded_bbox_and_list_refuses_it() {
        let access_profile = access_profile();
        let mut search = list_operation();
        search.identifier = "record.search.within-bbox".into();
        search.kind = OperationKind::Search {
            name: "within-bbox".into(),
        };
        search.pattern = ConsultationPattern::Search;
        search.query.spatial_bbox = Some(CompiledSpatialBboxQuery {
            longitude_column: "longitude".into(),
            latitude_column: "latitude".into(),
            maximum_longitude_span_degrees: 2,
            maximum_latitude_span_degrees: 2,
        });
        let query = OperationQuery {
            fetch_limit: Some(11),
            bbox: Some(PointBbox {
                west: 100.0,
                south: -20.0,
                east: 101.0,
                north: -19.0,
            }),
            ..OperationQuery::default()
        };
        let values = bind_operation_values(&search, &access_profile, query.clone())
            .expect("bounded bbox binds");
        assert_eq!(values.get("bbox_west"), Some(&Value::Number(100.0)));

        let mut oversized = query.clone();
        oversized.bbox = Some(PointBbox {
            west: 100.0,
            south: -20.0,
            east: 103.0,
            north: -19.0,
        });
        assert!(matches!(
            bind_operation_values(&search, &access_profile, oversized),
            Err(SqliteRuntimeError::InvalidPlan)
        ));
        assert!(matches!(
            bind_operation_values(&list_operation(), &access_profile, query),
            Err(SqliteRuntimeError::InvalidPlan)
        ));
    }

    fn lookup_operation(
        source_column: &str,
        data_type: DataType,
        access_profile: CompiledAccessProfile,
    ) -> CompiledOperation {
        CompiledOperation {
            identifier: "record.lookup.by-key".into(),
            family: CapabilityFamily::Consultation,
            pattern: ConsultationPattern::Search,
            kind: OperationKind::Lookup {
                name: "by-key".into(),
            },
            default_access_profile: access_profile.id.clone(),
            access_profiles: vec![access_profile],
            query: QueryPlan {
                source: "source".into(),
                view: "records".into(),
                filters: Vec::new(),
                spatial_bbox: None,
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

    fn access_profile() -> CompiledAccessProfile {
        CompiledAccessProfile {
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
            dataset_identifier: "records".into(),
            entity_type_identifier: "record".into(),
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
            primary_geometry: None,
            disclosure_profiles: Vec::new(),
            operations: Vec::new(),
            column_accounting: Vec::new(),
            processing_descriptions: Vec::new(),
        }
    }
}
