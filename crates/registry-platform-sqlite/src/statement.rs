use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_int;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, ErrorCode, OpenFlags, Row};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Semaphore;

use crate::schema::{collect_schema_with_installed_budget, InspectionLimits};
use crate::{CapturedSnapshot, ErrorKind, LiveDatabaseFile, SqliteError, TextLocation};

const PROGRESS_STEP_INTERVAL: u64 = 1_000;
const MAXIMUM_ENGINE_VALUE_BYTES: i32 = 8 * 1_024 * 1_024;
const MAXIMUM_CONCURRENCY: usize = 1_024;
/// SQL functions the authorizer refuses by name.
///
/// The authorizer sees a function's name but not its arguments, so the whole
/// clock family is denied rather than only its `now` forms. This list is closed
/// against the SQLite amalgamation pinned by the workspace lockfile and must be
/// reviewed whenever that dependency changes.
const DENIED_FUNCTIONS: &[&str] = &[
    "changes",
    "current_date",
    "current_time",
    "current_timestamp",
    "date",
    "datetime",
    "julianday",
    "last_insert_rowid",
    "load_extension",
    "random",
    "randomblob",
    "sqlite_offset",
    "strftime",
    "time",
    "timediff",
    "total_changes",
    "unixepoch",
];

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ColumnType {
    String,
    Integer,
    Number,
    Boolean,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ColumnContract {
    pub name: String,
    pub value_type: ColumnType,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParameterContract {
    pub name: String,
    /// Required parameters must occur in the statement. Optional parameters
    /// are permitted when present and may be supplied as harmless extra values.
    pub required: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StatementLimits {
    pub maximum_rows: u64,
    pub maximum_cell_bytes: usize,
    pub maximum_response_bytes: usize,
    pub maximum_statement_steps: u64,
    pub timeout: Duration,
    pub concurrency: usize,
}

impl StatementLimits {
    fn validate(&self) -> Result<(), SqliteError> {
        if self.maximum_rows == 0
            || self.maximum_cell_bytes == 0
            || self.maximum_response_bytes == 0
            || self.maximum_statement_steps == 0
            || self.timeout.is_zero()
            || self.concurrency == 0
            || self.concurrency > MAXIMUM_CONCURRENCY
            || self.maximum_cell_bytes
                > usize::try_from(MAXIMUM_ENGINE_VALUE_BYTES).unwrap_or(usize::MAX)
            || Instant::now().checked_add(self.timeout).is_none()
        {
            return Err(SqliteError::new(ErrorKind::InvalidPlan));
        }
        Ok(())
    }
}

/// Expected schema identity and the bounds used while re-verifying it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SchemaBinding {
    pub expected_fingerprint: String,
    pub maximum_objects: usize,
    pub maximum_sql_bytes: usize,
}

impl SchemaBinding {
    fn limits(&self, statement: &StatementLimits) -> InspectionLimits {
        InspectionLimits {
            maximum_objects: self.maximum_objects,
            maximum_sql_bytes: self.maximum_sql_bytes,
            maximum_statement_steps: statement.maximum_statement_steps,
            timeout: statement.timeout,
        }
    }

    fn validate(&self, statement: &StatementLimits) -> Result<(), SqliteError> {
        if self.maximum_objects == 0
            || self.maximum_sql_bytes == 0
            || !valid_sha256_label(&self.expected_fingerprint)
        {
            return Err(SqliteError::new(ErrorKind::InvalidPlan));
        }
        self.limits(statement).validate()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StatementContract {
    pub sql: String,
    pub columns: Vec<ColumnContract>,
    pub parameters: Vec<ParameterContract>,
    pub limits: StatementLimits,
    /// Required for live databases and optional for immutable snapshots.
    pub schema: Option<SchemaBinding>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Null,
    String(String),
    Integer(i64),
    Number(f64),
    Boolean(bool),
}

pub type ResultRow = BTreeMap<String, Value>;

#[derive(Debug, Clone, PartialEq)]
pub struct ResultSet {
    pub rows: Vec<ResultRow>,
    pub provenance: ExecutionProvenance,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DatabaseProfileKind {
    Snapshot,
    LiveReadOnly,
}

/// Source facts established for the exact transaction that returned the rows.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionProvenance {
    pub profile: DatabaseProfileKind,
    pub source_revision: Option<String>,
    pub schema_fingerprint: Option<String>,
    pub statement_digest: String,
}

#[derive(Debug, Clone)]
pub enum DatabaseProfile {
    Snapshot(CapturedSnapshot),
    LiveReadOnly(LiveDatabaseFile),
}

impl DatabaseProfile {
    fn path(&self) -> &Path {
        match self {
            Self::Snapshot(value) => value.path(),
            Self::LiveReadOnly(value) => value.path(),
        }
    }
    fn immutable(&self) -> bool {
        matches!(self, Self::Snapshot(_))
    }
    fn kind(&self) -> DatabaseProfileKind {
        match self {
            Self::Snapshot(_) => DatabaseProfileKind::Snapshot,
            Self::LiveReadOnly(_) => DatabaseProfileKind::LiveReadOnly,
        }
    }
    fn source_revision(&self) -> Option<String> {
        match self {
            Self::Snapshot(value) => Some(value.digest().to_owned()),
            Self::LiveReadOnly(_) => None,
        }
    }
    fn confirm(&self) -> Result<(), SqliteError> {
        match self {
            Self::Snapshot(value) => value.confirm_still_bound(),
            Self::LiveReadOnly(value) => value.confirm_still_bound(),
        }
    }
}

#[derive(Debug, Clone)]
struct BoundParameter {
    index: usize,
    name: String,
}

#[derive(Debug)]
struct CompiledPlan {
    sql: String,
    columns: Vec<ColumnContract>,
    parameters: Vec<BoundParameter>,
    limits: StatementLimits,
    schema: Option<SchemaBinding>,
    statement_digest: String,
}

/// One compiled statement and one read-only connection pool.
pub struct ReadOnlyStatement {
    profile: DatabaseProfile,
    plan: Arc<CompiledPlan>,
    connections: Arc<Mutex<Vec<Connection>>>,
    concurrency: Arc<Semaphore>,
}

impl ReadOnlyStatement {
    pub fn open(
        profile: DatabaseProfile,
        contract: StatementContract,
    ) -> Result<Self, SqliteError> {
        contract.limits.validate()?;
        if let Some(schema) = &contract.schema {
            schema.validate(&contract.limits)?;
        }
        if matches!(profile, DatabaseProfile::LiveReadOnly(_)) && contract.schema.is_none() {
            return Err(SqliteError::new(ErrorKind::InvalidPlan));
        }
        if contract.columns.is_empty() {
            return Err(SqliteError::new(ErrorKind::InvalidPlan));
        }
        profile.confirm()?;
        let connections = open_connection_pool(&profile, contract.limits.concurrency)?;
        let first = connections
            .first()
            .ok_or_else(|| SqliteError::new(ErrorKind::InvalidPlan))?;
        let parameters = verify_statement(first, &contract)?;
        verify_schema_at_open(first, contract.schema.as_ref(), &contract.limits)?;
        profile.confirm()?;
        confirm_connection_pool_still_bound(&connections)?;
        let permits = contract.limits.concurrency;
        let statement_digest = statement_digest(&contract.sql);
        Ok(Self {
            profile,
            plan: Arc::new(CompiledPlan {
                sql: contract.sql,
                columns: contract.columns,
                parameters,
                limits: contract.limits,
                schema: contract.schema,
                statement_digest,
            }),
            connections: Arc::new(Mutex::new(connections)),
            concurrency: Arc::new(Semaphore::new(permits)),
        })
    }

    /// Execute with one absolute queue-and-engine deadline.
    pub async fn execute(
        &self,
        values: &BTreeMap<String, Value>,
    ) -> Result<ResultSet, SqliteError> {
        self.profile.confirm()?;
        let bindings = bind_values(&self.plan.parameters, values)?;
        let deadline = deadline(self.plan.limits.timeout)?;
        let async_deadline = tokio::time::Instant::from_std(deadline);
        let permit = tokio::time::timeout_at(
            async_deadline,
            Arc::clone(&self.concurrency).acquire_owned(),
        )
        .await
        .map_err(|_| SqliteError::new(ErrorKind::Timeout))?
        .map_err(|_| SqliteError::new(ErrorKind::Concurrency))?;
        let connection = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
            .ok_or_else(|| SqliteError::new(ErrorKind::WorkerUnavailable))?;
        let plan = Arc::clone(&self.plan);
        let pool = Arc::clone(&self.connections);
        let execution = tokio::task::spawn_blocking(move || {
            let result = confirm_connection_still_bound(&connection)
                .and_then(|()| run_statement(&connection, &plan, &bindings, deadline))
                .and_then(|result| confirm_connection_still_bound(&connection).map(|()| result));
            pool.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(connection);
            drop(permit);
            result
        });
        let (rows, schema_fingerprint) = tokio::time::timeout_at(async_deadline, execution)
            .await
            .map_err(|_| SqliteError::new(ErrorKind::Timeout))?
            .map_err(|_| SqliteError::new(ErrorKind::WorkerUnavailable))??;
        self.profile.confirm()?;
        Ok(ResultSet {
            rows,
            provenance: self.provenance(schema_fingerprint),
        })
    }

    /// Startup-only synchronous execution, under the same engine limits.
    pub fn execute_at_open(
        &self,
        values: &BTreeMap<String, Value>,
    ) -> Result<ResultSet, SqliteError> {
        self.profile.confirm()?;
        let bindings = bind_values(&self.plan.parameters, values)?;
        let deadline = deadline(self.plan.limits.timeout)?;
        let connection = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
            .ok_or_else(|| SqliteError::new(ErrorKind::WorkerUnavailable))?;
        let outcome = confirm_connection_still_bound(&connection)
            .and_then(|()| run_statement(&connection, &self.plan, &bindings, deadline))
            .and_then(|result| confirm_connection_still_bound(&connection).map(|()| result));
        self.connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(connection);
        self.profile.confirm()?;
        let (rows, schema_fingerprint) = outcome?;
        Ok(ResultSet {
            rows,
            provenance: self.provenance(schema_fingerprint),
        })
    }

    #[must_use]
    pub fn statement_digest(&self) -> &str {
        &self.plan.statement_digest
    }

    fn provenance(&self, schema_fingerprint: Option<String>) -> ExecutionProvenance {
        ExecutionProvenance {
            profile: self.profile.kind(),
            source_revision: self.profile.source_revision(),
            schema_fingerprint,
            statement_digest: self.plan.statement_digest.clone(),
        }
    }

    /// Hold every admission permit for a fixture that proves queue deadlines.
    #[cfg(feature = "fixture")]
    #[doc(hidden)]
    pub async fn hold_all_permits_for_test(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, SqliteError> {
        let permits = u32::try_from(self.plan.limits.concurrency)
            .map_err(|_| SqliteError::new(ErrorKind::InvalidPlan))?;
        Arc::clone(&self.concurrency)
            .acquire_many_owned(permits)
            .await
            .map_err(|_| SqliteError::new(ErrorKind::Concurrency))
    }
}

pub fn check_statement_offline(contract: &StatementContract) -> Result<(), SqliteError> {
    contract.limits.validate()?;
    if let Some(schema) = &contract.schema {
        schema.validate(&contract.limits)?;
    }
    if contains_positional_parameter(&contract.sql) {
        return Err(SqliteError::new(ErrorKind::UndeclaredParameter));
    }
    let connection =
        Connection::open_in_memory().map_err(|_| SqliteError::new(ErrorKind::ExecutionFailed))?;
    install_authorizer(&connection).map_err(|_| SqliteError::new(ErrorKind::ExecutionFailed))?;
    match connection.prepare(&contract.sql).map(|_| ()) {
        Ok(()) => Ok(()),
        Err(error) => {
            let classified = classify_prepare(&error, &contract.sql);
            if matches!(
                classified.kind(),
                ErrorKind::UnknownTable | ErrorKind::UnknownColumn
            ) {
                Ok(())
            } else {
                Err(classified)
            }
        }
    }
}

fn open_connection(profile: &DatabaseProfile) -> Result<Connection, SqliteError> {
    let uri = database_uri(profile.path(), profile.immutable())
        .ok_or_else(|| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(uri, flags)
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_LENGTH, MAXIMUM_ENGINE_VALUE_BYTES)
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    install_authorizer(&connection)
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    confirm_connection_still_bound(&connection)?;
    Ok(connection)
}

fn open_connection_pool(
    profile: &DatabaseProfile,
    concurrency: usize,
) -> Result<Vec<Connection>, SqliteError> {
    let mut connections = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        connections.push(open_connection(profile)?);
    }
    Ok(connections)
}

fn confirm_connection_pool_still_bound(connections: &[Connection]) -> Result<(), SqliteError> {
    for connection in connections {
        confirm_connection_still_bound(connection)?;
    }
    Ok(())
}

/// Ask the active SQLite VFS whether the actual `main` handle has moved away
/// from the pathname that opened it. This detects a swap-and-restore attack
/// that pathname metadata checks alone cannot see.
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn confirm_connection_still_bound(connection: &Connection) -> Result<(), SqliteError> {
    let mut moved = 0_i32;
    // SAFETY: `connection.handle()` is valid for the shared borrow, `main` is
    // NUL-terminated, and SQLite writes one `c_int` to the supplied pointer for
    // `SQLITE_FCNTL_HAS_MOVED` without retaining it.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
            std::ptr::addr_of_mut!(moved).cast(),
        )
    };
    if result != rusqlite::ffi::SQLITE_OK || moved != 0 {
        return Err(SqliteError::new(ErrorKind::DatabaseReplaced));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn confirm_connection_still_bound(_connection: &Connection) -> Result<(), SqliteError> {
    Err(SqliteError::new(ErrorKind::DatabaseUnavailable))
}

pub(crate) fn database_uri(path: &Path, immutable: bool) -> Option<String> {
    let text = path.to_str()?;
    let mut uri = String::from("file:");
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                uri.push(char::from(byte))
            }
            other => uri.push_str(&format!("%{other:02X}")),
        }
    }
    uri.push_str("?mode=ro");
    if immutable {
        uri.push_str("&immutable=1");
    }
    Some(uri)
}

pub(crate) fn install_authorizer(connection: &Connection) -> rusqlite::Result<()> {
    connection.authorizer(Some(|context: AuthContext<'_>| authorize(&context.action)))
}

fn authorize(action: &AuthAction<'_>) -> Authorization {
    match action {
        AuthAction::Read { .. } | AuthAction::Select | AuthAction::Recursive => {
            Authorization::Allow
        }
        AuthAction::Function { function_name, .. } => {
            if DENIED_FUNCTIONS
                .iter()
                .any(|denied| function_name.eq_ignore_ascii_case(denied))
            {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }
        AuthAction::Attach { .. }
        | AuthAction::Detach { .. }
        | AuthAction::Pragma { .. }
        | AuthAction::Transaction { .. }
        | AuthAction::Savepoint { .. }
        | AuthAction::CreateIndex { .. }
        | AuthAction::CreateTable { .. }
        | AuthAction::CreateTempIndex { .. }
        | AuthAction::CreateTempTable { .. }
        | AuthAction::CreateTempTrigger { .. }
        | AuthAction::CreateTempView { .. }
        | AuthAction::CreateTrigger { .. }
        | AuthAction::CreateView { .. }
        | AuthAction::Delete { .. }
        | AuthAction::DropIndex { .. }
        | AuthAction::DropTable { .. }
        | AuthAction::DropTempIndex { .. }
        | AuthAction::DropTempTable { .. }
        | AuthAction::DropTempTrigger { .. }
        | AuthAction::DropTempView { .. }
        | AuthAction::DropTrigger { .. }
        | AuthAction::DropView { .. }
        | AuthAction::Insert { .. }
        | AuthAction::AlterTable { .. }
        | AuthAction::Reindex { .. }
        | AuthAction::Analyze { .. }
        | AuthAction::CreateVtable { .. }
        | AuthAction::DropVtable { .. }
        | AuthAction::Update { .. } => Authorization::Deny,
        _ => Authorization::Deny,
    }
}

fn verify_statement(
    connection: &Connection,
    contract: &StatementContract,
) -> Result<Vec<BoundParameter>, SqliteError> {
    if contains_positional_parameter(&contract.sql) {
        return Err(SqliteError::new(ErrorKind::UndeclaredParameter));
    }
    let statement = connection
        .prepare(&contract.sql)
        .map_err(|error| classify_prepare(&error, &contract.sql))?;
    if statement.column_count() != contract.columns.len() {
        return Err(SqliteError::new(ErrorKind::ColumnMismatch));
    }
    for (index, declared) in contract.columns.iter().enumerate() {
        if statement
            .column_name(index)
            .map_err(|_| SqliteError::new(ErrorKind::ColumnMismatch))?
            != declared.name
        {
            return Err(SqliteError::new(ErrorKind::ColumnMismatch));
        }
    }
    let declared: BTreeSet<&str> = contract
        .parameters
        .iter()
        .map(|value| value.name.as_str())
        .collect();
    if declared.len() != contract.parameters.len() {
        return Err(SqliteError::new(ErrorKind::InvalidPlan));
    }
    let mut parameters = Vec::new();
    for index in 1..=statement.parameter_count() {
        let name = statement
            .parameter_name(index)
            .and_then(bare_parameter_name)
            .ok_or_else(|| SqliteError::new(ErrorKind::UndeclaredParameter))?;
        if !declared.contains(name) {
            return Err(SqliteError::new(ErrorKind::UndeclaredParameter));
        }
        parameters.push(BoundParameter {
            index,
            name: name.to_owned(),
        });
    }
    for declared_parameter in &contract.parameters {
        if declared_parameter.required
            && !parameters
                .iter()
                .any(|value| value.name == declared_parameter.name)
        {
            return Err(SqliteError::new(ErrorKind::UnusedBinding));
        }
    }
    Ok(parameters)
}

fn bind_values(
    parameters: &[BoundParameter],
    values: &BTreeMap<String, Value>,
) -> Result<Vec<(usize, Value)>, SqliteError> {
    parameters
        .iter()
        .map(|parameter| {
            values
                .get(&parameter.name)
                .cloned()
                .map(|value| (parameter.index, value))
                .ok_or_else(|| SqliteError::new(ErrorKind::MissingParameter))
        })
        .collect()
}

fn bare_parameter_name(name: &str) -> Option<&str> {
    let mut chars = name.chars();
    match chars.next()? {
        ':' | '@' | '$' => Some(chars.as_str()),
        _ => None,
    }
}

fn contains_positional_parameter(sql: &str) -> bool {
    #[derive(Clone, Copy)]
    enum State {
        Sql,
        Quote(u8),
        Bracket,
        LineComment,
        BlockComment,
    }
    let bytes = sql.as_bytes();
    let mut state = State::Sql;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            State::Sql => match (byte, next) {
                (b'?', _) => return true,
                (b'\'', _) | (b'"', _) | (b'`', _) => state = State::Quote(byte),
                (b'[', _) => state = State::Bracket,
                (b'-', Some(b'-')) => {
                    state = State::LineComment;
                    index += 1;
                }
                (b'/', Some(b'*')) => {
                    state = State::BlockComment;
                    index += 1;
                }
                _ => {}
            },
            State::Quote(quote) if byte == quote => {
                if next == Some(quote) {
                    index += 1;
                } else {
                    state = State::Sql;
                }
            }
            State::Quote(_) => {}
            State::Bracket if byte == b']' => state = State::Sql,
            State::Bracket => {}
            State::LineComment if matches!(byte, b'\n' | b'\r') => state = State::Sql,
            State::LineComment => {}
            State::BlockComment if byte == b'*' && next == Some(b'/') => {
                state = State::Sql;
                index += 1;
            }
            State::BlockComment => {}
        }
        index += 1;
    }
    false
}

const BUDGET_WITHIN: u8 = 0;
const BUDGET_STEPS: u8 = 1;
const BUDGET_TIME: u8 = 2;

fn install_progress_handler(
    connection: &Connection,
    steps: u64,
    deadline: Instant,
) -> Result<Arc<AtomicU8>, SqliteError> {
    let outcome = Arc::new(AtomicU8::new(BUDGET_WITHIN));
    let observed = Arc::clone(&outcome);
    let interval = steps.clamp(1, PROGRESS_STEP_INTERVAL);
    let mut consumed = 0_u64;
    connection
        .progress_handler(
            c_int::try_from(interval).unwrap_or(c_int::MAX),
            Some(move || {
                consumed = consumed.saturating_add(interval);
                if consumed >= steps {
                    observed.store(BUDGET_STEPS, Ordering::Relaxed);
                    true
                } else if Instant::now() >= deadline {
                    observed.store(BUDGET_TIME, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }),
        )
        .map_err(|_| SqliteError::new(ErrorKind::ExecutionFailed))?;
    Ok(outcome)
}

fn run_statement(
    connection: &Connection,
    plan: &CompiledPlan,
    bindings: &[(usize, Value)],
    deadline: Instant,
) -> Result<(Vec<ResultRow>, Option<String>), SqliteError> {
    begin_read_transaction(connection)?;
    let outcome = run_statement_in_transaction(connection, plan, bindings, deadline);
    let closed = end_read_transaction(connection);
    match (outcome, closed) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn run_statement_in_transaction(
    connection: &Connection,
    plan: &CompiledPlan,
    bindings: &[(usize, Value)],
    deadline: Instant,
) -> Result<(Vec<ResultRow>, Option<String>), SqliteError> {
    if Instant::now() >= deadline {
        return Err(SqliteError::new(ErrorKind::TimeBudgetExceeded));
    }
    let budget =
        install_progress_handler(connection, plan.limits.maximum_statement_steps, deadline)?;
    let schema_fingerprint = verify_schema_in_transaction(connection, plan, &budget)?;
    let mut statement = connection
        .prepare(&plan.sql)
        .map_err(|error| classify_prepare(&error, &plan.sql))?;
    for (index, value) in bindings {
        let outcome = match value {
            Value::Null => statement.raw_bind_parameter(*index, rusqlite::types::Null),
            Value::String(value) => statement.raw_bind_parameter(*index, value),
            Value::Integer(value) => statement.raw_bind_parameter(*index, value),
            Value::Number(value) => statement.raw_bind_parameter(*index, value),
            Value::Boolean(value) => statement.raw_bind_parameter(*index, i64::from(*value)),
        };
        outcome.map_err(|_| SqliteError::new(ErrorKind::ExecutionFailed))?;
    }
    let mut rows = statement.raw_query();
    let mut collected = Vec::new();
    // Include the outer collection even when it is empty. This is a
    // conservative serialization/allocation budget, not just cell payload.
    let mut response_bytes = 0_usize;
    charge_response(&mut response_bytes, 2, plan.limits.maximum_response_bytes)?;
    loop {
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(error) => return Err(classify_step(&error, &budget)),
        };
        if collected.len() as u64 >= plan.limits.maximum_rows {
            return Err(SqliteError::new(ErrorKind::TooManyRows));
        }
        charge_response(
            &mut response_bytes,
            if collected.is_empty() { 2 } else { 3 },
            plan.limits.maximum_response_bytes,
        )?;
        collected.push(read_row(row, plan, &mut response_bytes)?);
    }
    Ok((collected, schema_fingerprint))
}

fn begin_read_transaction(connection: &Connection) -> Result<(), SqliteError> {
    connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .map_err(|_| SqliteError::new(ErrorKind::ExecutionFailed))?;
    let begun = connection.execute_batch("BEGIN DEFERRED");
    let authorized = install_authorizer(connection);
    if begun.is_err() || authorized.is_err() {
        return Err(SqliteError::new(ErrorKind::ExecutionFailed));
    }
    Ok(())
}

fn end_read_transaction(connection: &Connection) -> Result<(), SqliteError> {
    connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .map_err(|_| SqliteError::new(ErrorKind::ExecutionFailed))?;
    let rolled_back = connection.execute_batch("ROLLBACK");
    let authorized = install_authorizer(connection);
    if rolled_back.is_err() || authorized.is_err() {
        return Err(SqliteError::new(ErrorKind::ExecutionFailed));
    }
    Ok(())
}

fn verify_schema_at_open(
    connection: &Connection,
    binding: Option<&SchemaBinding>,
    limits: &StatementLimits,
) -> Result<(), SqliteError> {
    let Some(binding) = binding else {
        return Ok(());
    };
    begin_read_transaction(connection)?;
    let deadline = deadline(limits.timeout)?;
    let budget = install_progress_handler(connection, limits.maximum_statement_steps, deadline)?;
    let outcome = schema_fingerprint_with_budget(connection, binding, limits, &budget);
    let closed = end_read_transaction(connection);
    match (outcome, closed) {
        (Ok(_), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn verify_schema_in_transaction(
    connection: &Connection,
    plan: &CompiledPlan,
    budget: &AtomicU8,
) -> Result<Option<String>, SqliteError> {
    plan.schema
        .as_ref()
        .map(|binding| schema_fingerprint_with_budget(connection, binding, &plan.limits, budget))
        .transpose()
}

fn schema_fingerprint_with_budget(
    connection: &Connection,
    binding: &SchemaBinding,
    statement_limits: &StatementLimits,
    budget: &AtomicU8,
) -> Result<String, SqliteError> {
    let limits = binding.limits(statement_limits);
    // The reviewed-statement authorizer denies virtual-table actions used by
    // `pragma_table_xinfo`. Remove it only around this fixed schema-only query.
    // The connection remains engine read-only and inside the request's read
    // transaction, and no caller SQL can run on this worker in the interval.
    connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?;
    let collected = collect_schema_with_installed_budget(connection, &limits);
    if install_authorizer(connection).is_err() {
        return Err(SqliteError::new(ErrorKind::SchemaMalformed));
    }
    let objects = collected.map_err(|error| match budget.load(Ordering::Relaxed) {
        BUDGET_STEPS => SqliteError::new(ErrorKind::StepBudgetExceeded),
        BUDGET_TIME => SqliteError::new(ErrorKind::TimeBudgetExceeded),
        _ => error,
    })?;
    let observed = crate::schema::fingerprint_objects(&objects);
    if observed != binding.expected_fingerprint {
        return Err(SqliteError::new(ErrorKind::SchemaMismatch));
    }
    Ok(observed)
}

fn read_row(
    row: &Row<'_>,
    plan: &CompiledPlan,
    response_bytes: &mut usize,
) -> Result<ResultRow, SqliteError> {
    let mut object = BTreeMap::new();
    for (index, column) in plan.columns.iter().enumerate() {
        charge_response(
            response_bytes,
            usize::from(index > 0)
                .saturating_add(json_string_bytes(column.name.as_bytes()))
                .saturating_add(1),
            plan.limits.maximum_response_bytes,
        )?;
        let raw = row
            .get_ref(index)
            .map_err(|_| SqliteError::new(ErrorKind::ExecutionFailed))?;
        let (value, bytes) = read_value(raw, column.value_type, plan.limits.maximum_cell_bytes)?;
        charge_response(
            response_bytes,
            serialized_value_bytes(&value).max(bytes),
            plan.limits.maximum_response_bytes,
        )?;
        object.insert(column.name.clone(), value);
    }
    Ok(object)
}

fn charge_response(
    consumed: &mut usize,
    additional: usize,
    maximum: usize,
) -> Result<(), SqliteError> {
    *consumed = consumed.saturating_add(additional);
    if *consumed > maximum {
        return Err(SqliteError::new(ErrorKind::ResponseTooLarge));
    }
    Ok(())
}

fn serialized_value_bytes(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::String(value) => json_string_bytes(value.as_bytes()),
        // Conservative bounds avoid allocating temporary number strings while
        // covering every i64 and finite f64 JSON spelling.
        Value::Integer(_) | Value::Number(_) => 32,
        Value::Boolean(_) => 5,
    }
}

fn json_string_bytes(bytes: &[u8]) -> usize {
    bytes.iter().fold(2_usize, |total, byte| {
        total.saturating_add(match byte {
            b'"' | b'\\' | b'\x08' | b'\x09' | b'\x0a' | b'\x0c' | b'\x0d' => 2,
            b'\x00'..=b'\x1f' => 6,
            _ => 1,
        })
    })
}

fn read_value(
    value: ValueRef<'_>,
    declared: ColumnType,
    max: usize,
) -> Result<(Value, usize), SqliteError> {
    match (value, declared) {
        (ValueRef::Null, _) => Ok((Value::Null, 0)),
        (ValueRef::Text(bytes), ColumnType::String) => {
            if bytes.len() > max {
                return Err(SqliteError::new(ErrorKind::CellTooLarge));
            }
            let value = std::str::from_utf8(bytes)
                .map_err(|_| SqliteError::new(ErrorKind::ValueTypeMismatch))?;
            Ok((Value::String(value.to_owned()), bytes.len()))
        }
        (ValueRef::Integer(value), ColumnType::Integer) => Ok((Value::Integer(value), 8)),
        // Preserve SQLite's integer JSON representation for a declared number,
        // matching serde_json's distinction between `1` and `1.0`.
        (ValueRef::Integer(value), ColumnType::Number) => Ok((Value::Integer(value), 8)),
        (ValueRef::Real(value), ColumnType::Number) if value.is_finite() => {
            Ok((Value::Number(value), 8))
        }
        (ValueRef::Integer(0), ColumnType::Boolean) => Ok((Value::Boolean(false), 1)),
        (ValueRef::Integer(1), ColumnType::Boolean) => Ok((Value::Boolean(true), 1)),
        _ => Err(SqliteError::new(ErrorKind::ValueTypeMismatch)),
    }
}

fn classify_prepare(error: &rusqlite::Error, sql: &str) -> SqliteError {
    match error {
        rusqlite::Error::MultipleStatement => SqliteError::new(ErrorKind::MultipleStatements),
        rusqlite::Error::SqliteFailure(failure, message) => {
            SqliteError::new(classify_failure(failure.code, message.as_deref()))
        }
        rusqlite::Error::SqlInputError {
            error, msg, offset, ..
        } => {
            let kind = classify_failure(error.code, Some(msg));
            if kind == ErrorKind::InvalidSql {
                if let Ok(offset) = usize::try_from(*offset) {
                    return SqliteError::at(kind, text_location(sql, offset));
                }
            }
            SqliteError::new(kind)
        }
        _ => SqliteError::new(ErrorKind::InvalidSql),
    }
}

fn classify_failure(code: ErrorCode, message: Option<&str>) -> ErrorKind {
    match code {
        ErrorCode::AuthorizationForStatementDenied => ErrorKind::AuthorizerRefused,
        ErrorCode::Unknown => match message {
            Some(value) if value.starts_with("no such table") => ErrorKind::UnknownTable,
            Some(value) if value.starts_with("no such column") => ErrorKind::UnknownColumn,
            Some(value) if value.starts_with("not authorized") => ErrorKind::AuthorizerRefused,
            _ => ErrorKind::InvalidSql,
        },
        _ => ErrorKind::InvalidSql,
    }
}

fn classify_step(error: &rusqlite::Error, budget: &AtomicU8) -> SqliteError {
    match budget.load(Ordering::Relaxed) {
        BUDGET_STEPS => SqliteError::new(ErrorKind::StepBudgetExceeded),
        BUDGET_TIME => SqliteError::new(ErrorKind::TimeBudgetExceeded),
        _ => match error {
            rusqlite::Error::SqliteFailure(failure, _) if failure.code == ErrorCode::TooBig => {
                SqliteError::new(ErrorKind::CellTooLarge)
            }
            _ => SqliteError::new(ErrorKind::ExecutionFailed),
        },
    }
}

fn text_location(text: &str, offset: usize) -> TextLocation {
    let mut line = 1;
    let mut column = 1;
    for (index, character) in text.char_indices() {
        if index >= offset {
            break;
        }
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    TextLocation { line, column }
}

fn deadline(timeout: Duration) -> Result<Instant, SqliteError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| SqliteError::new(ErrorKind::InvalidPlan))
}

fn valid_sha256_label(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn statement_digest(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-platform-sqlite-statement-v1\0");
    hasher.update(u64::try_from(sql.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(sql.as_bytes());
    let digest = hasher.finalize();
    let mut label = String::with_capacity(71);
    label.push_str("sha256:");
    for byte in digest.as_slice() {
        use std::fmt::Write as _;
        write!(&mut label, "{byte:02x}").expect("writing to a string cannot fail");
    }
    label
}

#[cfg(feature = "fixture")]
pub fn materialize_fixture(target: &Path, seed_sql: &str) -> Result<(), SqliteError> {
    let connection =
        Connection::open(target).map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    connection
        .execute_batch(seed_sql)
        .map_err(|_| SqliteError::new(ErrorKind::InvalidSql))?;
    connection
        .close()
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    let mut permissions = std::fs::metadata(target)
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?
        .permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(target, permissions)
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn database(path: &Path, marker: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        let connection = Connection::open(path).expect("database opens");
        connection
            .execute_batch(&format!(
                "CREATE TABLE records (id TEXT); INSERT INTO records VALUES ('{marker}');"
            ))
            .expect("database materializes");
        connection.close().expect("database closes");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
            .expect("database becomes read-only");
    }

    #[cfg(unix)]
    #[test]
    fn actual_snapshot_and_live_pool_handles_refuse_swap_and_restore() {
        for live in [false, true] {
            let temporary = tempfile::tempdir().expect("temporary root");
            let path = temporary.path().join("source.sqlite");
            database(&path, "governed");
            let profile = if live {
                DatabaseProfile::LiveReadOnly(
                    LiveDatabaseFile::bind(&path).expect("live source binds"),
                )
            } else {
                DatabaseProfile::Snapshot(
                    CapturedSnapshot::capture(&path).expect("snapshot captures"),
                )
            };
            profile.confirm().expect("governed path starts bound");

            let governed = temporary.path().join("governed.sqlite");
            std::fs::rename(&path, &governed).expect("governed source moves");
            database(&path, "substitute");

            // This is the exact old race window: the pre-open pathname check
            // has completed, and every pool member now opens the substitute.
            let connections =
                open_connection_pool(&profile, 3).expect("substitute pool opens by pathname");

            let substitute = temporary.path().join("substitute.sqlite");
            std::fs::rename(&path, substitute).expect("substitute moves away");
            std::fs::rename(governed, &path).expect("governed source is restored");
            if live {
                profile
                    .confirm()
                    .expect("live pathname-only post-check sees the restored inode");
            } else {
                assert_eq!(
                    profile
                        .confirm()
                        .expect_err("snapshot metadata also detects the rename")
                        .kind(),
                    ErrorKind::DatabaseReplaced
                );
            }

            for connection in &connections {
                assert_eq!(
                    confirm_connection_still_bound(connection)
                        .expect_err("actual substitute handle must be refused")
                        .kind(),
                    ErrorKind::DatabaseReplaced
                );
            }
        }
    }

    #[test]
    fn positional_parameter_scan_ignores_literals_identifiers_and_comments() {
        assert!(!contains_positional_parameter(
            "SELECT '?' AS \"?\", `?`, [?] -- ?1\n/* ?2 */"
        ));
        assert!(contains_positional_parameter("SELECT :record, ?1"));
        assert!(contains_positional_parameter("SELECT ?"));
    }

    #[test]
    fn an_engine_failure_while_stepping_is_not_reported_as_invalid_sql() {
        let error = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
            Some("database disk image is malformed around protected-value".to_owned()),
        );
        let budget = AtomicU8::new(BUDGET_WITHIN);
        let classified = classify_step(&error, &budget);
        assert_eq!(classified.kind(), ErrorKind::ExecutionFailed);
        assert!(!classified.to_string().contains("protected-value"));
    }

    #[test]
    fn an_offset_at_or_past_the_end_of_the_text_still_has_a_position() {
        let text = "SELECT id\nFROM person";
        for offset in [text.len(), text.len() + 1, usize::MAX] {
            assert_eq!(
                text_location(text, offset),
                TextLocation {
                    line: 2,
                    column: 12,
                }
            );
        }
        assert_eq!(text_location("", 0), TextLocation { line: 1, column: 1 });
        assert_eq!(
            text_location("SELECT id\n", 10),
            TextLocation { line: 2, column: 1 },
        );
    }
}
