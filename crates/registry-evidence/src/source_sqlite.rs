//! Bounded execution of one reviewed SQL statement against a read-only extract.
//!
//! The transport holds one reviewed statement and one extract file. Review of
//! the statement is the disclosure control: the authorizer below is a safety
//! boundary that refuses whole categories of SQL, not a per-table or
//! per-column declaration of what may be read.
//!
//! Every failure this module reports names the bundle artifact it came from
//! and a cause drawn from [`cause`], so an adopter is told which file to open
//! and what is wrong with it. SQLite's own message text is classified and then
//! discarded: it quotes schema identifiers and stored values, and no error in
//! this crate carries data.

use std::collections::BTreeMap;
use std::ffi::c_int;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, SubsecRound as _, Utc};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, ErrorCode, OpenFlags, Row, Statement};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::bundle::ArtifactFault;
use crate::config::{
    SchemaFault, SourceConfig, SqliteColumn, SqliteColumnType, SqliteRequest, TextLocation,
    RESERVED_SQL_PARAMETER,
};
use crate::model::SelectorValue;

/// The reserved metadata table every extract carries.
pub const EXTRACT_METADATA_TABLE: &str = "evidence_extract";

/// Virtual machine steps between progress callbacks.
///
/// The callback is the only cancellation this transport has, so the interval
/// sets the resolution of both bounds. SQLite runs on the order of a hundred
/// million steps a second here, so a thousand steps is about ten microseconds:
/// fine enough that the smallest legal `timeoutMilliseconds` of 1 is honoured
/// to roughly a percent, and coarse enough that the callback itself is a
/// rounding error against the statement it guards.
const PROGRESS_STEP_INTERVAL: u64 = 1_000;

/// The largest metadata field an extract may declare.
const MAXIMUM_METADATA_FIELD_BYTES: usize = 1_024;

/// The engine's own ceiling on one value and one assembled record.
///
/// `maximumCellBytes` is checked against a value SQLite has already read out of
/// the extract, so it decides what enters the response but not what enters
/// memory. SQLite checks this limit against the length in the record header,
/// before the payload is read, which makes it the only place a single oversized
/// cell can be stopped without first allocating it. Its default is a gigabyte,
/// so a mis-published extract carrying one enormous value in a selected column
/// would otherwise move that value through the process, once per concurrent
/// request, before the declared bound refused it.
///
/// This is a backstop rather than a restatement of the declared bound, which is
/// why it is a constant and not derived from the request. The same limit caps
/// bound parameter values, the startup metadata read, and the intermediate
/// records a sort or a grouping assembles, so deriving it from
/// `maximumCellBytes`, which may legally be as low as 1, would refuse ordinary
/// statements. The value admits the largest result the configuration bounds
/// allow, 64 columns of 65,536 bytes, with room to spare.
const MAXIMUM_ENGINE_VALUE_BYTES: i32 = 8 * 1_024 * 1_024;

/// SQL functions the authorizer refuses by name.
///
/// The authorizer sees a function's name but never its arguments, so the whole
/// clock family is refused rather than only its `'now'` forms. Evidence binds
/// the runtime's evaluation instant to [`RESERVED_SQL_PARAMETER`] instead, so a
/// statement that needs the current time has a deterministic way to ask for it.
///
/// This is a denylist, not an allowlist: an allowlist would refuse ordinary
/// deterministic SQL such as `substr`, `printf` and `coalesce` and would grow a
/// support burden for every adopter. The set below is closed against the
/// vendored SQLite amalgamation, which is pinned by `Cargo.lock` and changes
/// only when the dependency is deliberately raised.
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

/// The closed cause vocabulary a statement source reports.
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
    pub const EXTRACT_UNAVAILABLE: &str = "the extract file could not be opened";
    pub const NO_METADATA_TABLE: &str = "the extract has no metadata table";
    pub const MALFORMED_METADATA: &str = "the extract metadata is malformed";
    pub const METADATA_BUDGET_EXCEEDED: &str =
        "reading the extract metadata exceeded the declared budget";
    pub const EXTRACT_TOO_OLD: &str = "the extract is older than the source allows";
}

/// Closed statement-source failures. No variant retains statement text, an
/// extract value, or a message SQLite wrote.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SqliteSourceError {
    #[error("the statement source plan is invalid")]
    InvalidPlan,
    #[error("an Evidence statement is invalid: {0}")]
    Statement(ArtifactFault),
    #[error("an Evidence extract is unusable: {0}")]
    Extract(ArtifactFault),
    #[error("the statement source concurrency boundary is unavailable")]
    Concurrency,
    #[error("the statement source timed out waiting for a concurrency slot")]
    Timeout,
    #[error("the statement source execution thread is unavailable")]
    Unavailable,
}

impl SqliteSourceError {
    /// The artifact a caller should point an adopter at, where there is one.
    ///
    /// Statement faults name the bundle-relative statement artifact. Extract
    /// faults name the extract itself: its file name before its metadata has
    /// been read, and the publisher's own extract identifier afterwards.
    pub fn artifact_fault(&self) -> Option<&ArtifactFault> {
        match self {
            Self::Statement(fault) | Self::Extract(fault) => Some(fault),
            Self::InvalidPlan | Self::Concurrency | Self::Timeout | Self::Unavailable => None,
        }
    }

    /// The closed cause behind this failure, drawn from [`cause`].
    pub fn cause(&self) -> Option<&'static str> {
        self.artifact_fault().map(|fault| fault.fault().cause())
    }
}

fn statement_fault(artifact: &str, cause: &'static str) -> SqliteSourceError {
    SqliteSourceError::Statement(ArtifactFault::new(artifact, SchemaFault::because(cause)))
}

fn extract_fault(subject: &str, cause: &'static str) -> SqliteSourceError {
    SqliteSourceError::Extract(ArtifactFault::new(subject, SchemaFault::because(cause)))
}

/// Where a byte offset into some text falls, as a one-based line and column.
///
/// A column counts characters rather than bytes, which is what the
/// configuration decoder's own locations count, so one convention holds across
/// every deployment diagnostic and a position is the one an adopter's editor
/// shows them. An offset at or past the end of the text is the position just
/// after the last character.
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

/// The publisher's own statement about one extract file.
///
/// The publication instant is read from the extract's reserved metadata table,
/// never from the file's modification time: an mtime is an artifact of the
/// filesystem the file was copied across, and is not a statement by the
/// publisher about the data inside.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExtractMetadata {
    published_at: DateTime<Utc>,
    publisher: String,
    extract_id: String,
}

impl ExtractMetadata {
    pub fn new(
        published_at: DateTime<Utc>,
        publisher: impl Into<String>,
        extract_id: impl Into<String>,
    ) -> Self {
        Self {
            published_at,
            publisher: publisher.into(),
            extract_id: extract_id.into(),
        }
    }

    pub fn published_at(&self) -> DateTime<Utc> {
        self.published_at
    }

    pub fn publisher(&self) -> &str {
        &self.publisher
    }

    pub fn extract_id(&self) -> &str {
        &self.extract_id
    }

    /// The metadata as it appears in the result handed downstream.
    fn as_json(&self) -> JsonValue {
        let mut object = JsonMap::new();
        object.insert(
            "publishedAt".to_owned(),
            JsonValue::String(self.published_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
        );
        object.insert(
            "publisher".to_owned(),
            JsonValue::String(self.publisher.clone()),
        );
        object.insert(
            "extractId".to_owned(),
            JsonValue::String(self.extract_id.clone()),
        );
        JsonValue::Object(object)
    }
}

/// Refuse an extract the source considers too old.
///
/// The bound is inclusive: an extract published exactly `maximum_age_seconds`
/// before the evaluation instant is still current. An extract published after
/// the evaluation instant is not old, so it passes here; whether a publisher
/// may date an extract into the future is a question for the publisher.
pub fn extract_age_within_bound(
    metadata: &ExtractMetadata,
    evaluation_instant: DateTime<Utc>,
    maximum_age_seconds: u64,
) -> Result<(), SqliteSourceError> {
    let age = (evaluation_instant - metadata.published_at).num_seconds();
    let bound = i64::try_from(maximum_age_seconds).unwrap_or(i64::MAX);
    if age > bound {
        return Err(extract_fault(&metadata.extract_id, cause::EXTRACT_TOO_OLD));
    }
    Ok(())
}

/// Check a statement without an extract to check it against.
///
/// This is the weak check, and it is all `evidence bundle-check` can do.
/// Preparing a statement needs a schema, the schema lives in the extract file,
/// and the extract file sits outside the bundle directory that a bundle load is
/// allowed to read. So the statement is prepared against an empty in-memory
/// database, where a name the extract would have supplied is simply absent.
///
/// It therefore settles only what is settleable without data: that the artifact
/// holds exactly one statement, that the statement parses, and that the
/// authorizer accepts it. It cannot check result columns against the declared
/// `columns`, cannot check statement parameters against the declared
/// `parameterBindings`, and cannot see the extract's metadata or its age. Those
/// are the strong check, and they run in [`SqliteExtractSource::open`].
///
/// One limit is worth naming, because it is not obvious: SQLite stops at the
/// first name it cannot resolve. A statement that reads an extract table fails
/// there, in an empty database, and everything after that point goes unread. So
/// a second statement, a write, or a refused function standing behind an
/// extract-only name passes this check and is caught by the strong one. This
/// check never reports a false failure, only an incomplete pass.
pub fn check_statement_offline(
    source: &SourceConfig,
    statement_sql: &str,
) -> Result<(), SqliteSourceError> {
    let (request, _) = statement_source(source)?;
    let artifact = request.statement.as_str();
    let connection = Connection::open_in_memory()
        .map_err(|_| statement_fault(artifact, cause::EXECUTION_FAILED))?;
    install_authorizer(&connection)
        .map_err(|_| statement_fault(artifact, cause::EXECUTION_FAILED))?;
    // The prepared statement is dropped in `map` so that it cannot outlive the
    // connection it borrows.
    match connection.prepare(statement_sql).map(|_| ()) {
        Ok(()) => Ok(()),
        Err(error) => {
            let fault = classify_prepare(&error);
            match fault.cause {
                // Only the extract can settle these, and the extract is not here.
                cause::UNKNOWN_TABLE | cause::UNKNOWN_COLUMN => Ok(()),
                _ => Err(fault.statement_fault(artifact, statement_sql)),
            }
        }
    }
}

fn statement_source(source: &SourceConfig) -> Result<(&SqliteRequest, u64), SqliteSourceError> {
    match source {
        SourceConfig::SqliteExtract {
            request,
            maximum_extract_age_seconds,
            ..
        } => Ok((request, *maximum_extract_age_seconds)),
        SourceConfig::HttpJson { .. } => Err(SqliteSourceError::InvalidPlan),
    }
}

/// One statement parameter, at the index SQLite assigned it.
#[derive(Debug, Clone)]
struct BoundParameter {
    index: usize,
    name: String,
}

/// A value on its way into a statement. Booleans travel as SQLite integers,
/// which is how SQLite itself stores them.
#[derive(Debug, Clone)]
enum BoundValue {
    Text(String),
    Integer(i64),
}

/// The reviewed statement and the bounds its result is read under.
#[derive(Debug)]
struct StatementPlan {
    artifact: String,
    sql: String,
    columns: Vec<SqliteColumn>,
    parameters: Vec<BoundParameter>,
    maximum_rows: u64,
    maximum_cell_bytes: usize,
    /// The same bound the caller measures the serialized response against, held
    /// here so collection can refuse before the whole result exists. The bounds
    /// above it are per row and per cell, and nothing bounds their product, so
    /// at the schema maxima a result can reach a gibibyte before the caller ever
    /// sees it.
    maximum_response_bytes: usize,
    maximum_statement_steps: u64,
    timeout: Duration,
    maximum_extract_age_seconds: u64,
}

impl StatementPlan {
    fn fault(&self, cause: &'static str) -> SqliteSourceError {
        statement_fault(&self.artifact, cause)
    }
}

/// One reviewed statement, opened against one read-only extract file.
///
/// Opening is a startup step: it holds one SQLite connection per concurrency
/// permit, so a permit carries a connection and no request ever waits on a
/// connection it was not admitted for. A connection that cannot be opened, an
/// extract whose metadata is unusable, and a statement that fails its strong
/// check are all startup failures, never request-time ones.
pub struct SqliteExtractSource {
    plan: Arc<StatementPlan>,
    metadata: ExtractMetadata,
    extract: JsonValue,
    /// The pool and its permits are shared with the blocking task that borrows
    /// from them, because a caller that stops awaiting must not be able to carry
    /// either away. See [`SqliteExtractSource::execute`].
    connections: Arc<Mutex<Vec<Connection>>>,
    concurrency: Arc<Semaphore>,
}

impl SqliteExtractSource {
    /// Open an extract and run the strong check against it.
    ///
    /// `extract_path` must name a file the process cannot write and no other
    /// process will change while this source lives. The caller owns that
    /// precondition, and it is what makes `immutable=1` below sound.
    pub fn open(
        source: &SourceConfig,
        statement_sql: &str,
        extract_path: &Path,
    ) -> Result<Self, SqliteSourceError> {
        let (request, maximum_extract_age_seconds) = statement_source(source)?;
        let artifact = request.statement.as_str();
        let subject = extract_subject(extract_path);
        let uri = extract_uri(extract_path)
            .ok_or_else(|| extract_fault(&subject, cause::EXTRACT_UNAVAILABLE))?;

        let permits = usize::from(request.concurrency_limit);
        let mut connections = Vec::with_capacity(permits);
        for _ in 0..permits {
            connections.push(open_extract(&uri, &subject)?);
        }
        let first = connections.first().ok_or(SqliteSourceError::InvalidPlan)?;

        let timeout = Duration::from_millis(request.timeout_milliseconds);
        let metadata =
            read_extract_metadata(first, &subject, request.maximum_statement_steps, timeout)?;
        let parameters = verify_statement(first, request, statement_sql)?;

        let plan = StatementPlan {
            artifact: artifact.to_owned(),
            sql: statement_sql.to_owned(),
            columns: request.columns.clone(),
            parameters,
            maximum_rows: request.maximum_rows,
            maximum_cell_bytes: usize::try_from(request.maximum_cell_bytes)
                .map_err(|_| SqliteSourceError::InvalidPlan)?,
            maximum_response_bytes: usize::try_from(request.maximum_response_bytes)
                .map_err(|_| SqliteSourceError::InvalidPlan)?,
            maximum_statement_steps: request.maximum_statement_steps,
            timeout,
            maximum_extract_age_seconds,
        };
        Ok(Self {
            plan: Arc::new(plan),
            extract: metadata.as_json(),
            metadata,
            connections: Arc::new(Mutex::new(connections)),
            concurrency: Arc::new(Semaphore::new(permits)),
        })
    }

    /// What the publisher said about the extract this source reads.
    pub fn extract_metadata(&self) -> &ExtractMetadata {
        &self.metadata
    }

    /// Refuse the extract if it is older than the source allows.
    ///
    /// A caller runs this before any row is read, against the same evaluation
    /// instant it later passes to [`Self::execute`].
    pub fn validate_extract_age(
        &self,
        evaluation_instant: DateTime<Utc>,
    ) -> Result<(), SqliteSourceError> {
        extract_age_within_bound(
            &self.metadata,
            evaluation_instant,
            self.plan.maximum_extract_age_seconds,
        )
    }

    /// Run the statement and return its rows beside the extract's metadata.
    ///
    /// `evaluation_instant` is the runtime's one clock. It is bound to
    /// [`RESERVED_SQL_PARAMETER`] where the statement uses it, and this module
    /// reads no clock of its own beyond the monotonic one the time budget needs.
    ///
    /// The result is `{"rows": [...], "extract": {...}}`. Applying the
    /// acquisition projection belongs to the caller, which does it for every
    /// transport, and so does the authoritative response size check, which
    /// measures the serialized bytes. Collection here reads the same bound
    /// against the text payload alone, which is only ever shorter, so it can
    /// refuse sooner but never refuse a result the caller would accept.
    ///
    /// A caller may stop awaiting this at any point: the acquisition deadline
    /// above it expires, or a client disconnects and the handler future is
    /// dropped. A blocking task cannot be cancelled, so the connection and the
    /// permit are given back from inside it rather than from the awaiting
    /// caller's stack, where a cancellation would carry them away. Returning the
    /// connection before releasing the permit is what keeps the two counts from
    /// drifting apart: a permit is never issued for a connection that is not yet
    /// back in the pool.
    pub async fn execute(
        &self,
        parameters: &BTreeMap<String, SelectorValue>,
        evaluation_instant: DateTime<Utc>,
    ) -> Result<JsonValue, SqliteSourceError> {
        let bindings = self.bind_values(parameters, evaluation_instant)?;
        // An owned permit so the blocking task can hold it; a borrowed one would
        // be tied to this future, which is the lifetime being escaped.
        let permit = tokio::time::timeout(
            self.plan.timeout,
            Arc::clone(&self.concurrency).acquire_owned(),
        )
        .await
        .map_err(|_| SqliteSourceError::Timeout)?
        .map_err(|_| SqliteSourceError::Concurrency)?;
        let connection = self.take_connection()?;
        let plan = Arc::clone(&self.plan);
        let connections = Arc::clone(&self.connections);

        let outcome = tokio::task::spawn_blocking(move || {
            let outcome = run_statement(&connection, &plan, &bindings);
            return_connection(&connections, connection);
            drop(permit);
            outcome
        })
        .await
        .map_err(|_| SqliteSourceError::Unavailable)?;

        let rows = outcome.map_err(|cause| self.plan.fault(cause))?;
        let mut result = JsonMap::new();
        result.insert("rows".to_owned(), JsonValue::Array(rows));
        result.insert("extract".to_owned(), self.extract.clone());
        Ok(JsonValue::Object(result))
    }

    fn bind_values(
        &self,
        parameters: &BTreeMap<String, SelectorValue>,
        evaluation_instant: DateTime<Utc>,
    ) -> Result<Vec<(usize, BoundValue)>, SqliteSourceError> {
        // Fixed-width RFC 3339 UTC, so a statement that compares the instant
        // against stored text orders lexically the way it orders in time. Whole
        // seconds, because this is the same rendering the assertion carries: a
        // statement comparing the bound value against a stored `2026-08-08T03:00:00Z`
        // sees the text the runtime reports, not a longer form that sorts after
        // it. The runtime truncates the instant where it reads the clock, so in
        // production this only chooses how an already-whole second is written.
        let instant = evaluation_instant.to_rfc3339_opts(SecondsFormat::Secs, true);
        let mut bound = Vec::with_capacity(self.plan.parameters.len());
        for parameter in &self.plan.parameters {
            let value = if parameter.name == RESERVED_SQL_PARAMETER {
                BoundValue::Text(instant.clone())
            } else {
                match parameters.get(&parameter.name) {
                    Some(SelectorValue::String(text)) => BoundValue::Text(text.clone()),
                    Some(SelectorValue::Integer(number)) => BoundValue::Integer(*number),
                    Some(SelectorValue::Boolean(flag)) => BoundValue::Integer(i64::from(*flag)),
                    None => return Err(self.plan.fault(cause::MISSING_PARAMETER)),
                }
            };
            bound.push((parameter.index, value));
        }
        Ok(bound)
    }

    /// Take the connection this request's permit stands for.
    ///
    /// A poisoned lock is recovered rather than refused, which is the same
    /// choice [`return_connection`] makes: the only operations this pool has are
    /// a push and a pop, so a panic elsewhere cannot have left it half-written,
    /// and refusing to touch it would strand every connection in it.
    fn take_connection(&self) -> Result<Connection, SqliteSourceError> {
        self.connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
            .ok_or(SqliteSourceError::Unavailable)
    }
}

/// Put a connection back where the next admitted request will find it.
///
/// This is a free function rather than a method because it runs inside the
/// blocking task, which holds no reference to the source. A poisoned lock is
/// recovered here rather than propagated, because dropping the connection is
/// exactly the pool drain this path exists to prevent.
fn return_connection(connections: &Mutex<Vec<Connection>>, connection: Connection) {
    connections
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(connection);
}

/// Build an extract file from a reviewed text seed.
///
/// A fixture states the world its cases assert against as SQL text rather than
/// as a committed database file. The text is diffable, it is reviewed with
/// every other bundle artifact, and it keeps table and column names legible to
/// the checks that read this tree, none of which an opaque binary would be.
///
/// The connection opened here has no authorizer, and the contrast with
/// [`open_extract`] is the point. A seed is DDL and `INSERT`, which [`authorize`]
/// denies by design, so the world cannot be built through the posture that
/// reads it. This connection is closed before the extract is opened again,
/// read-only and immutable, for the reviewed statement to run against, so
/// building a fixture world and reading one are two connections apart and
/// neither can be mistaken for the other.
///
/// The finished file is made unwritable, because `immutable=1` on the reading
/// connection is sound only against a file nothing will change.
pub fn materialize_seed_extract(target: &Path, seed_sql: &str) -> Result<(), SqliteSourceError> {
    use std::os::unix::fs::PermissionsExt as _;

    let subject = extract_subject(target);
    let unavailable = || extract_fault(&subject, cause::EXTRACT_UNAVAILABLE);
    let connection = Connection::open(target).map_err(|_| unavailable())?;
    connection
        .execute_batch(seed_sql)
        .map_err(|_| extract_fault(&subject, cause::INVALID_SQL))?;
    connection.close().map_err(|_| unavailable())?;
    std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o444))
        .map_err(|_| unavailable())
}

/// The extract's file name, which is what an extract fault names before the
/// extract has told us its own identifier.
fn extract_subject(extract_path: &Path) -> String {
    extract_path.file_name().map_or_else(
        || "extract".to_owned(),
        |name| name.to_string_lossy().into(),
    )
}

/// The extract as a SQLite URI.
///
/// `mode=ro` refuses the write path outright. `immutable=1` tells SQLite the
/// file will not change while it is open, which lets it skip locking and
/// journal replay. That flag is sound only because the caller has already
/// proven the extract is read-only and stable for the life of this source; it
/// is a correctness precondition, not a tuning knob, and removing the proof
/// would make the flag unsafe rather than merely slower.
fn extract_uri(extract_path: &Path) -> Option<String> {
    let text = extract_path.to_str()?;
    let mut uri = String::from("file:");
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                uri.push(char::from(byte));
            }
            other => uri.push_str(&format!("%{other:02X}")),
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Some(uri)
}

fn open_extract(uri: &str, subject: &str) -> Result<Connection, SqliteSourceError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(uri, flags)
        .map_err(|_| extract_fault(subject, cause::EXTRACT_UNAVAILABLE))?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_LENGTH, MAXIMUM_ENGINE_VALUE_BYTES)
        .map_err(|_| extract_fault(subject, cause::EXTRACT_UNAVAILABLE))?;
    install_authorizer(&connection)
        .map_err(|_| extract_fault(subject, cause::EXTRACT_UNAVAILABLE))?;
    Ok(connection)
}

/// Refuse everything a reviewed read-only statement has no business doing.
///
/// This is a safety boundary, not a disclosure declaration. It says nothing
/// about which tables or columns a statement may read, because review of the
/// statement is what decides that. It says only that the statement may not
/// write, may not reach another database, may not touch a pragma, may not load
/// an extension, and may not read a clock or a random source.
///
/// WARNING: `AuthAction` is `#[non_exhaustive]`, so this match cannot be
/// written without a wildcard arm, and the compiler will not report a variant
/// added by a future `rusqlite`. The wildcard therefore DENIES. A `rusqlite`
/// upgrade that introduces an action will refuse statements that use it rather
/// than allow them, which is the right way round: the failure is visible and
/// recoverable, and the alternative would be a silent widening of this
/// boundary. Whoever raises the `rusqlite` version should revisit this match.
/// The stable toolchain has no lint that would catch the omission
/// (`non_exhaustive_omitted_patterns` remains unstable, rust-lang/rust#89554).
fn authorize(action: &AuthAction<'_>) -> Authorization {
    match action {
        // Reading is what a statement source is for. Which rows and columns it
        // may read is settled by review, not here.
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
        // Every mutating action.
        AuthAction::Insert { .. }
        | AuthAction::Update { .. }
        | AuthAction::Delete { .. }
        | AuthAction::CreateIndex { .. }
        | AuthAction::CreateTable { .. }
        | AuthAction::CreateTempIndex { .. }
        | AuthAction::CreateTempTable { .. }
        | AuthAction::CreateTempTrigger { .. }
        | AuthAction::CreateTempView { .. }
        | AuthAction::CreateTrigger { .. }
        | AuthAction::CreateView { .. }
        | AuthAction::CreateVtable { .. }
        | AuthAction::DropIndex { .. }
        | AuthAction::DropTable { .. }
        | AuthAction::DropTempIndex { .. }
        | AuthAction::DropTempTable { .. }
        | AuthAction::DropTempTrigger { .. }
        | AuthAction::DropTempView { .. }
        | AuthAction::DropTrigger { .. }
        | AuthAction::DropView { .. }
        | AuthAction::DropVtable { .. }
        | AuthAction::AlterTable { .. }
        | AuthAction::Reindex { .. }
        | AuthAction::Analyze { .. }
        // Another database file, and the pragma surface that can reach one.
        | AuthAction::Attach { .. }
        | AuthAction::Detach { .. }
        | AuthAction::Pragma { .. }
        // Transaction control has no place inside one reviewed read.
        | AuthAction::Transaction { .. }
        | AuthAction::Savepoint { .. }
        // An action code this rusqlite does not recognise.
        | AuthAction::Unknown { .. } => Authorization::Deny,
        _ => Authorization::Deny,
    }
}

fn install_authorizer(connection: &Connection) -> rusqlite::Result<()> {
    connection.authorizer(Some(|context: AuthContext<'_>| authorize(&context.action)))
}

/// The extract's reserved metadata table, read before any row of data is.
///
/// Nothing requires the reserved object to be an ordinary table: a view reads
/// as metadata just as well, and a view over a nonterminating recursive query
/// would otherwise step forever and hang startup with nothing to say about it.
/// So this read carries the same declared step and time bounds the statement
/// itself runs under, and reports its own cause when it exceeds them.
fn read_extract_metadata(
    connection: &Connection,
    subject: &str,
    maximum_statement_steps: u64,
    timeout: Duration,
) -> Result<ExtractMetadata, SqliteSourceError> {
    let budget = install_progress_handler(connection, maximum_statement_steps, timeout)
        // A connection that will not take a progress handler cannot be stepped
        // under a bound, so it is not a connection this source can read from.
        .map_err(|_| extract_fault(subject, cause::EXTRACT_UNAVAILABLE))?;
    let sql = format!("SELECT published_at, publisher, extract_id FROM {EXTRACT_METADATA_TABLE}");
    let mut statement = connection.prepare(&sql).map_err(|error| {
        // A missing table and a missing column are different problems for an
        // extract publisher, so they are reported differently.
        match classify_prepare(&error).cause {
            cause::UNKNOWN_TABLE => extract_fault(subject, cause::NO_METADATA_TABLE),
            _ => extract_fault(subject, cause::MALFORMED_METADATA),
        }
    })?;
    let malformed = || extract_fault(subject, cause::MALFORMED_METADATA);
    // A step that failed because a bound stopped it says nothing about whether
    // the metadata is well formed, so the two are told apart.
    let stepped = || match budget.load(Ordering::Relaxed) {
        BUDGET_WITHIN => malformed(),
        _ => extract_fault(subject, cause::METADATA_BUDGET_EXCEEDED),
    };

    let mut rows = statement.raw_query();
    let row = rows.next().map_err(|_| stepped())?.ok_or_else(malformed)?;
    let published_at = metadata_field(row, 0, subject)?;
    let publisher = metadata_field(row, 1, subject)?;
    let extract_id = metadata_field(row, 2, subject)?;
    if rows.next().map_err(|_| stepped())?.is_some() {
        return Err(malformed());
    }

    // The instant is truncated where it is parsed, so the instant the age bound
    // is measured against is the one the response carries. A relying party
    // recomputing the age from `/extract/publishedAt`, which is a projectable
    // leaf and can be signed into an assertion, reaches the runtime's answer
    // rather than one that disagrees by up to a second.
    let published_at = DateTime::parse_from_rfc3339(&published_at)
        .map_err(|_| malformed())?
        .with_timezone(&Utc)
        .trunc_subsecs(0);
    Ok(ExtractMetadata::new(published_at, publisher, extract_id))
}

fn metadata_field(row: &Row<'_>, index: usize, subject: &str) -> Result<String, SqliteSourceError> {
    let malformed = || extract_fault(subject, cause::MALFORMED_METADATA);
    let ValueRef::Text(bytes) = row.get_ref(index).map_err(|_| malformed())? else {
        return Err(malformed());
    };
    if bytes.is_empty() || bytes.len() > MAXIMUM_METADATA_FIELD_BYTES {
        return Err(malformed());
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| malformed())
}

/// The strong check: prepare the statement against the real extract, and prove
/// its result columns and its parameters are the ones the bundle declared.
fn verify_statement(
    connection: &Connection,
    request: &SqliteRequest,
    statement_sql: &str,
) -> Result<Vec<BoundParameter>, SqliteSourceError> {
    let artifact = request.statement.as_str();
    let statement = connection
        .prepare(statement_sql)
        .map_err(|error| classify_prepare(&error).statement_fault(artifact, statement_sql))?;
    verify_columns(&statement, request, artifact)?;
    verify_parameters(&statement, request, artifact)
}

/// The declared `columns` are what `responseSchema`, the extraction script and
/// the fact schema are written against, so a statement whose real result
/// disagrees with them is refused rather than silently reshaped.
fn verify_columns(
    statement: &Statement<'_>,
    request: &SqliteRequest,
    artifact: &str,
) -> Result<(), SqliteSourceError> {
    let mismatch = || statement_fault(artifact, cause::COLUMN_MISMATCH);
    if statement.column_count() != request.columns.len() {
        return Err(mismatch());
    }
    for (index, declared) in request.columns.iter().enumerate() {
        let real = statement.column_name(index).map_err(|_| mismatch())?;
        if real != declared.name {
            return Err(mismatch());
        }
    }
    Ok(())
}

/// The statement's real parameters and the declared `parameterBindings` must
/// name each other exactly, allowing for the reserved evaluation instant.
fn verify_parameters(
    statement: &Statement<'_>,
    request: &SqliteRequest,
    artifact: &str,
) -> Result<Vec<BoundParameter>, SqliteSourceError> {
    let mut parameters = Vec::new();
    for index in 1..=statement.parameter_count() {
        // A positional parameter has no name to match a binding against.
        let name = statement
            .parameter_name(index)
            .and_then(bare_parameter_name)
            .ok_or_else(|| statement_fault(artifact, cause::UNDECLARED_PARAMETER))?;
        if name != RESERVED_SQL_PARAMETER && !request.parameter_bindings.contains_key(name) {
            return Err(statement_fault(artifact, cause::UNDECLARED_PARAMETER));
        }
        parameters.push(BoundParameter {
            index,
            name: name.to_owned(),
        });
    }
    for declared in request.parameter_bindings.keys() {
        if !parameters.iter().any(|bound| bound.name == declared) {
            return Err(statement_fault(artifact, cause::UNUSED_BINDING));
        }
    }
    Ok(parameters)
}

/// `:name`, `@name` and `$name` without the sigil. A numbered `?NNN` keeps its
/// digits, which no declared binding key can match, so it reads as undeclared.
fn bare_parameter_name(name: &str) -> Option<&str> {
    let mut characters = name.chars();
    match characters.next()? {
        ':' | '@' | '$' => Some(characters.as_str()),
        _ => None,
    }
}

const BUDGET_WITHIN: u8 = 0;
const BUDGET_STEPS: u8 = 1;
const BUDGET_TIME: u8 = 2;

/// Install the only cancellation this transport has.
///
/// `tokio::time::timeout` cannot cancel a `spawn_blocking` task, and SQLite has
/// no way to be interrupted from outside a step. The progress callback runs on
/// the same thread as the statement, between virtual machine instructions, and
/// returning `true` aborts the step. Both bounds are checked there.
///
/// The handler is not cleared afterwards. Nothing steps this connection between
/// executions, and every step this transport takes installs its own handler
/// first, so a handler left behind can never fire.
///
/// The bounds arrive as values rather than as a [`StatementPlan`], because the
/// extract's metadata is read at startup before the plan's parameters are known
/// and that read is stepped under the same declared bounds.
fn install_progress_handler(
    connection: &Connection,
    maximum_statement_steps: u64,
    timeout: Duration,
) -> Result<Arc<AtomicU8>, &'static str> {
    let outcome = Arc::new(AtomicU8::new(BUDGET_WITHIN));
    let observed = Arc::clone(&outcome);
    // A budget smaller than the interval would never be checked, so a small
    // budget shortens the interval to itself.
    let interval = maximum_statement_steps.clamp(1, PROGRESS_STEP_INTERVAL);
    let budget = maximum_statement_steps;
    let deadline = Instant::now() + timeout;
    let mut consumed: u64 = 0;
    connection
        .progress_handler(
            c_int::try_from(interval).unwrap_or(c_int::MAX),
            Some(move || {
                consumed = consumed.saturating_add(interval);
                if consumed >= budget {
                    observed.store(BUDGET_STEPS, Ordering::Relaxed);
                    return true;
                }
                if Instant::now() >= deadline {
                    observed.store(BUDGET_TIME, Ordering::Relaxed);
                    return true;
                }
                false
            }),
        )
        .map_err(|_| cause::EXECUTION_FAILED)?;
    Ok(outcome)
}

fn run_statement(
    connection: &Connection,
    plan: &StatementPlan,
    bindings: &[(usize, BoundValue)],
) -> Result<Vec<JsonValue>, &'static str> {
    let budget = install_progress_handler(connection, plan.maximum_statement_steps, plan.timeout)?;
    let mut statement = connection
        .prepare(&plan.sql)
        .map_err(|error| classify_prepare(&error).cause)?;
    for (index, value) in bindings {
        match value {
            BoundValue::Text(text) => statement.raw_bind_parameter(*index, text),
            BoundValue::Integer(number) => statement.raw_bind_parameter(*index, number),
        }
        .map_err(|_| cause::EXECUTION_FAILED)?;
    }

    let mut rows = statement.raw_query();
    let mut collected: Vec<JsonValue> = Vec::new();
    // Text is the only value whose size a row bound and a cell bound do not
    // already settle, so it is the only thing worth running a total on.
    let mut text_bytes: usize = 0;
    loop {
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(error) => return Err(classify_step(&error, &budget)),
        };
        // The statement is never rewritten, so the row bound is enforced by
        // stepping one row past it and refusing that row.
        if collected.len() as u64 >= plan.maximum_rows {
            return Err(cause::TOO_MANY_ROWS);
        }
        collected.push(read_row(row, plan, &mut text_bytes)?);
    }
    Ok(collected)
}

/// Read one row, and carry the running text total the response bound is read
/// against.
///
/// `text_bytes` counts the text payload alone. Serializing the result adds key
/// names, quotes, any escaping, and the extract block, so the total counted here
/// is never more than the length the caller measures. Refusing on it can
/// therefore only refuse sooner than the caller would, never differently, and a
/// result the caller accepts is collected unchanged.
fn read_row(
    row: &Row<'_>,
    plan: &StatementPlan,
    text_bytes: &mut usize,
) -> Result<JsonValue, &'static str> {
    let mut object = JsonMap::with_capacity(plan.columns.len());
    for (index, column) in plan.columns.iter().enumerate() {
        let raw = row.get_ref(index).map_err(|_| cause::EXECUTION_FAILED)?;
        let value = read_value(raw, column.value_type, plan.maximum_cell_bytes)?;
        if let JsonValue::String(text) = &value {
            *text_bytes = text_bytes.saturating_add(text.len());
            if *text_bytes > plan.maximum_response_bytes {
                return Err(cause::RESPONSE_TOO_LARGE);
            }
        }
        object.insert(column.name.clone(), value);
    }
    Ok(JsonValue::Object(object))
}

/// Read one value as the type the bundle declared for its column.
///
/// A value whose real SQLite type cannot be represented as the declared type is
/// a failure, not a coercion: the declared type is what the response schema and
/// the extraction script are written against. The cell bound is checked against
/// the borrowed bytes before an owned value is built, so an oversized value is
/// never copied into the process.
fn read_value(
    value: ValueRef<'_>,
    declared: SqliteColumnType,
    maximum_cell_bytes: usize,
) -> Result<JsonValue, &'static str> {
    match (value, declared) {
        (ValueRef::Null, _) => Ok(JsonValue::Null),
        (ValueRef::Text(bytes), SqliteColumnType::String) => {
            if bytes.len() > maximum_cell_bytes {
                return Err(cause::CELL_TOO_LARGE);
            }
            std::str::from_utf8(bytes)
                .map(|text| JsonValue::String(text.to_owned()))
                .map_err(|_| cause::VALUE_TYPE_MISMATCH)
        }
        (ValueRef::Integer(number), SqliteColumnType::Integer) => Ok(JsonValue::from(number)),
        (ValueRef::Integer(number), SqliteColumnType::Number) => Ok(JsonValue::from(number)),
        (ValueRef::Integer(number), SqliteColumnType::Boolean) => match number {
            0 => Ok(JsonValue::Bool(false)),
            1 => Ok(JsonValue::Bool(true)),
            _ => Err(cause::VALUE_TYPE_MISMATCH),
        },
        (ValueRef::Real(number), SqliteColumnType::Number) => JsonNumber::from_f64(number)
            .map(JsonValue::Number)
            .ok_or(cause::VALUE_TYPE_MISMATCH),
        _ => Err(cause::VALUE_TYPE_MISMATCH),
    }
}

/// A classified preparation failure: one closed cause, and the byte offset
/// SQLite reported when a single character is what went wrong.
struct PrepareFault {
    cause: &'static str,
    offset: Option<usize>,
}

impl PrepareFault {
    fn because(cause: &'static str) -> Self {
        Self {
            cause,
            offset: None,
        }
    }

    /// The failure as it is reported, placed inside the statement where SQLite
    /// pointed at a character.
    ///
    /// `statement_sql` supplies the line breaks the offset is counted against
    /// and nothing else: what travels out of here is a line and a column.
    fn statement_fault(&self, artifact: &str, statement_sql: &str) -> SqliteSourceError {
        match self.offset {
            Some(offset) => SqliteSourceError::Statement(ArtifactFault::at(
                artifact,
                SchemaFault::because(self.cause),
                text_location(statement_sql, offset),
            )),
            None => statement_fault(artifact, self.cause),
        }
    }
}

/// Classify a preparation failure and discard the message SQLite wrote.
///
/// SQLite reports an unknown table, an unknown column and a syntax error under
/// one result code, so its fixed message prefix is the only thing that separates
/// them. The prefix is matched and the remainder, which quotes the identifier
/// that was not found, is thrown away.
///
/// The offset is kept only for a syntax error. SQLite also offers one for an
/// unresolved name, but an unknown table is a fact about the extract rather
/// than about a character of the statement, and a refused statement and an
/// exceeded bound have no character behind them at all.
fn classify_prepare(error: &rusqlite::Error) -> PrepareFault {
    match error {
        rusqlite::Error::MultipleStatement => PrepareFault::because(cause::MULTIPLE_STATEMENTS),
        rusqlite::Error::SqliteFailure(failure, message) => {
            PrepareFault::because(classify_failure(failure.code, message.as_deref()))
        }
        rusqlite::Error::SqlInputError {
            error, msg, offset, ..
        } => {
            let cause = classify_failure(error.code, Some(msg));
            // SQLite writes a negative offset where it has no position to give.
            let offset = (cause == cause::INVALID_SQL)
                .then(|| usize::try_from(*offset).ok())
                .flatten();
            PrepareFault { cause, offset }
        }
        _ => PrepareFault::because(cause::INVALID_SQL),
    }
}

fn classify_failure(code: ErrorCode, message: Option<&str>) -> &'static str {
    match code {
        ErrorCode::AuthorizationForStatementDenied => cause::AUTHORIZER_REFUSED,
        // SQLITE_ERROR, the code every statement-level complaint arrives under.
        ErrorCode::Unknown => match message {
            Some(text) if text.starts_with("no such table") => cause::UNKNOWN_TABLE,
            Some(text) if text.starts_with("no such column") => cause::UNKNOWN_COLUMN,
            // A refused function is reported while names are resolved, under
            // SQLITE_ERROR rather than SQLITE_AUTH, so only the prefix says the
            // authorizer is what stopped it.
            Some(text) if text.starts_with("not authorized") => cause::AUTHORIZER_REFUSED,
            _ => cause::INVALID_SQL,
        },
        _ => cause::INVALID_SQL,
    }
}

/// Which bound stopped the statement, if a bound did.
///
/// The progress callback records why it aborted before SQLite turns the abort
/// into `SQLITE_INTERRUPT`, so the two budgets stay distinguishable without
/// reading any message text.
fn classify_step(error: &rusqlite::Error, budget: &AtomicU8) -> &'static str {
    match budget.load(Ordering::Relaxed) {
        BUDGET_STEPS => cause::STEP_BUDGET_EXCEEDED,
        BUDGET_TIME => cause::TIME_BUDGET_EXCEEDED,
        _ => match error {
            // `SQLITE_TOOBIG` while stepping is [`MAXIMUM_ENGINE_VALUE_BYTES`]
            // refusing to materialize a value, so the row that carries it is
            // over the cell bound whatever the declared bound happens to be.
            // Only stepping may read the code this way: the same code at
            // preparation time means the statement text was too long, which
            // this cause would misname, so it is classified here rather than
            // in the shared [`classify_failure`].
            rusqlite::Error::SqliteFailure(failure, _) if failure.code == ErrorCode::TooBig => {
                cause::CELL_TOO_LARGE
            }
            rusqlite::Error::SqliteFailure(failure, message) => {
                classify_failure(failure.code, message.as_deref())
            }
            _ => cause::EXECUTION_FAILED,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use chrono::TimeZone as _;
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    const STATEMENT_ARTIFACT: &str = "queries/residence-region.sql";

    fn instant(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .expect("the test instant is RFC 3339")
            .with_timezone(&Utc)
    }

    /// The reviewed source document, restated per test around its statement.
    struct Plan {
        columns: String,
        parameter_bindings: String,
        maximum_rows: u64,
        maximum_cell_bytes: u64,
        maximum_statement_steps: u64,
        timeout_milliseconds: u64,
        maximum_response_bytes: u64,
        maximum_extract_age_seconds: u64,
    }

    impl Default for Plan {
        fn default() -> Self {
            Self {
                columns: "[{name: id, type: string}]".to_owned(),
                parameter_bindings: "{}".to_owned(),
                maximum_rows: 8,
                maximum_cell_bytes: 4096,
                maximum_statement_steps: 100_000,
                timeout_milliseconds: 10_000,
                maximum_response_bytes: 65_536,
                maximum_extract_age_seconds: 86_400,
            }
        }
    }

    impl Plan {
        fn columns(mut self, columns: &str) -> Self {
            self.columns = columns.to_owned();
            self
        }

        fn bindings(mut self, bindings: &str) -> Self {
            self.parameter_bindings = bindings.to_owned();
            self
        }

        fn rows(mut self, maximum_rows: u64) -> Self {
            self.maximum_rows = maximum_rows;
            self
        }

        fn cell_bytes(mut self, maximum_cell_bytes: u64) -> Self {
            self.maximum_cell_bytes = maximum_cell_bytes;
            self
        }

        fn steps(mut self, maximum_statement_steps: u64) -> Self {
            self.maximum_statement_steps = maximum_statement_steps;
            self
        }

        fn timeout(mut self, timeout_milliseconds: u64) -> Self {
            self.timeout_milliseconds = timeout_milliseconds;
            self
        }

        fn response_bytes(mut self, maximum_response_bytes: u64) -> Self {
            self.maximum_response_bytes = maximum_response_bytes;
            self
        }

        fn build(&self) -> SourceConfig {
            let Self {
                columns,
                parameter_bindings,
                maximum_rows,
                maximum_cell_bytes,
                maximum_statement_steps,
                timeout_milliseconds,
                maximum_response_bytes,
                maximum_extract_age_seconds,
            } = self;
            let document = format!(
                "transport: sqlite-extract
posture: field-projected
extractProfile: residence-register
request:
  statement: {STATEMENT_ARTIFACT}
  columns: {columns}
  selectorInputs:
    - role: subject
      alternatives:
        - {{profile: person-demographics-v1, fields: [given_name]}}
  parameterBindings: {parameter_bindings}
  maximumRows: {maximum_rows}
  maximumCellBytes: {maximum_cell_bytes}
  maximumStatementSteps: {maximum_statement_steps}
  projection: [/rows/*/id]
  timeoutMilliseconds: {timeout_milliseconds}
  maximumResponseBytes: {maximum_response_bytes}
  concurrencyLimit: 2
maximumExtractAgeSeconds: {maximum_extract_age_seconds}
responseSchema: schemas/response.schema.yaml
extractScript: adapters/source-a.rhai
factSchema: schemas/facts.schema.yaml
"
            );
            serde_norway::from_str(&document).expect("the statement source parses")
        }
    }

    fn selector_binding(field: &str) -> String {
        format!(
            "{{kind: selector, role: subject, profile: person-demographics-v1, field: {field}}}"
        )
    }

    const EXTRACT_SCHEMA: &str = "
        CREATE TABLE region (code TEXT PRIMARY KEY, name TEXT);
        CREATE TABLE person (
            id TEXT PRIMARY KEY,
            region_code TEXT,
            active INTEGER,
            score REAL,
            note TEXT
        );
        INSERT INTO region VALUES ('nw', 'North West'), ('se', 'South East');
        INSERT INTO person VALUES
            ('p-1', 'nw', 1, 1.5, 'short'),
            ('p-2', 'nw', 0, 2, 'a rather longer note than the cell bound allows'),
            ('p-3', 'se', 1, 3.25, NULL);
    ";

    /// An extract carrying the reviewed schema and one metadata row.
    fn extract(directory: &TempDir) -> PathBuf {
        extract_with_metadata(
            directory,
            "INSERT INTO evidence_extract VALUES \
             ('2026-08-07T02:00:00Z', 'urn:example:residence-register', '2026-08-07-full');",
        )
    }

    fn extract_with_metadata(directory: &TempDir, metadata_rows: &str) -> PathBuf {
        let statements = format!(
            "CREATE TABLE {EXTRACT_METADATA_TABLE} \
             (published_at TEXT, publisher TEXT, extract_id TEXT);
             {metadata_rows}
             {EXTRACT_SCHEMA}"
        );
        build_extract(directory, &statements)
    }

    /// An extract without the reserved metadata table at all.
    fn extract_without_metadata(directory: &TempDir) -> PathBuf {
        build_extract(directory, EXTRACT_SCHEMA)
    }

    fn build_extract(directory: &TempDir, statements: &str) -> PathBuf {
        let path = directory.path().join("extract.sqlite");
        let connection = Connection::open(&path).expect("the extract file opens for writing");
        connection
            .execute_batch(statements)
            .expect("the extract fixture is valid SQL");
        drop(connection);
        path
    }

    fn open(plan: &Plan, sql: &str, extract_path: &Path) -> SqliteExtractSource {
        SqliteExtractSource::open(&plan.build(), sql, extract_path)
            .expect("the statement source opens")
    }

    fn open_error(plan: &Plan, sql: &str, extract_path: &Path) -> &'static str {
        let Err(error) = SqliteExtractSource::open(&plan.build(), sql, extract_path) else {
            panic!("the statement source was accepted");
        };
        error.cause().expect("the failure names a cause")
    }

    async fn run(source: &SqliteExtractSource, sql_free_note: &str) -> JsonValue {
        source
            .execute(&BTreeMap::new(), instant("2026-08-07T03:00:00Z"))
            .await
            .unwrap_or_else(|error| panic!("{sql_free_note}: {error}"))
    }

    async fn run_error(source: &SqliteExtractSource) -> &'static str {
        let Err(error) = source
            .execute(&BTreeMap::new(), instant("2026-08-07T03:00:00Z"))
            .await
        else {
            panic!("the statement was accepted");
        };
        error.cause().expect("the failure names a cause")
    }

    /// The seed a fixture commits: the metadata table, the reviewed schema, and
    /// the rows a case asserts against, all as reviewable text.
    fn seed(metadata_rows: &str) -> String {
        format!(
            "CREATE TABLE {EXTRACT_METADATA_TABLE} \
             (published_at TEXT, publisher TEXT, extract_id TEXT);
             {metadata_rows}
             {EXTRACT_SCHEMA}"
        )
    }

    #[test]
    fn a_seed_materializes_an_extract_the_reviewed_statement_reads() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = directory.path().join("seeded.sqlite");
        materialize_seed_extract(
            &path,
            &seed(
                "INSERT INTO evidence_extract VALUES \
                 ('2026-08-07T02:00:00Z', 'urn:example:residence-register', '2026-08-07-full');",
            ),
        )
        .expect("the seed materializes an extract");

        let source = open(&Plan::default(), "SELECT id FROM person ORDER BY id", &path);
        assert_eq!(
            source.extract_metadata().extract_id(),
            "2026-08-07-full",
            "the materialized extract carries the metadata the seed stated"
        );
    }

    #[test]
    fn a_materialized_extract_is_unwritable() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TempDir::new().expect("a temporary directory");
        let path = directory.path().join("seeded.sqlite");
        materialize_seed_extract(&path, &seed("INSERT INTO evidence_extract VALUES ('2026-08-07T02:00:00Z', 'urn:example:register', 'seed');"))
            .expect("the seed materializes an extract");
        let mode = std::fs::metadata(&path)
            .expect("the materialized extract exists")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o222,
            0,
            "a materialized extract must be unwritable, because immutable=1 depends on it"
        );
    }

    #[test]
    fn an_invalid_seed_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = directory.path().join("seeded.sqlite");
        let error = materialize_seed_extract(&path, "CREATE TABLE ;")
            .expect_err("an invalid seed is refused");
        assert_eq!(error.cause(), Some(cause::INVALID_SQL));
    }

    #[test]
    fn every_write_action_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default();
        for statement in [
            "INSERT INTO person (id) VALUES ('p-4') RETURNING id",
            "UPDATE person SET note = 'x' RETURNING id",
            "DELETE FROM person RETURNING id",
            "CREATE TABLE shadow (id TEXT)",
            "DROP TABLE person",
            "ALTER TABLE person RENAME TO people",
            "CREATE INDEX person_region ON person (region_code)",
            "CREATE TRIGGER t AFTER INSERT ON person BEGIN SELECT 1; END",
            "CREATE VIEW v AS SELECT id FROM person",
        ] {
            assert_eq!(
                open_error(&plan, statement, &path),
                cause::AUTHORIZER_REFUSED,
                "a write action was not refused"
            );
        }
    }

    #[test]
    fn attaching_and_detaching_a_database_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default();
        for statement in ["ATTACH DATABASE 'other.sqlite' AS other", "DETACH other"] {
            assert_eq!(
                open_error(&plan, statement, &path),
                cause::AUTHORIZER_REFUSED
            );
        }
    }

    #[test]
    fn a_pragma_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        assert_eq!(
            open_error(&Plan::default(), "PRAGMA table_list", &path),
            cause::AUTHORIZER_REFUSED
        );
    }

    #[test]
    fn a_non_deterministic_function_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default();
        for statement in [
            "SELECT random() AS id",
            "SELECT randomblob(4) AS id",
            "SELECT changes() AS id",
            "SELECT last_insert_rowid() AS id",
            "SELECT total_changes() AS id",
        ] {
            assert_eq!(
                open_error(&plan, statement, &path),
                cause::AUTHORIZER_REFUSED,
                "a non-deterministic function was not refused"
            );
        }
    }

    #[test]
    fn a_clock_function_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default();
        for statement in [
            "SELECT date('now') AS id",
            "SELECT time('now') AS id",
            "SELECT datetime('now') AS id",
            "SELECT julianday('now') AS id",
            "SELECT strftime('%Y', 'now') AS id",
            "SELECT unixepoch('now') AS id",
            "SELECT timediff('now', 'now') AS id",
            "SELECT CURRENT_TIMESTAMP AS id",
            "SELECT CURRENT_DATE AS id",
            "SELECT CURRENT_TIME AS id",
        ] {
            assert_eq!(
                open_error(&plan, statement, &path),
                cause::AUTHORIZER_REFUSED,
                "a clock function was not refused"
            );
        }
    }

    #[tokio::test]
    async fn a_join_with_a_group_by_is_answered() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default()
            .columns("[{name: region, type: string}, {name: people, type: integer}]");
        let source = open(
            &plan,
            "SELECT r.name AS region, COUNT(p.id) AS people
             FROM person p JOIN region r ON r.code = p.region_code
             GROUP BY r.name ORDER BY r.name",
            &path,
        );
        let result = run(&source, "the join is answered").await;
        assert_eq!(
            result["rows"],
            json!([
                {"region": "North West", "people": 2},
                {"region": "South East", "people": 1}
            ])
        );
    }

    #[tokio::test]
    async fn a_common_table_expression_is_answered() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan =
            Plan::default().columns("[{name: id, type: string}, {name: region, type: string}]");
        let source = open(
            &plan,
            "WITH active AS (SELECT id, region_code FROM person WHERE active = 1)
             SELECT id, region_code AS region FROM active ORDER BY id",
            &path,
        );
        let result = run(&source, "the common table expression is answered").await;
        assert_eq!(
            result["rows"],
            json!([{"id": "p-1", "region": "nw"}, {"id": "p-3", "region": "se"}])
        );
    }

    #[tokio::test]
    async fn the_result_carries_the_publisher_metadata() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let source = open(
            &Plan::default(),
            "SELECT id FROM person ORDER BY id LIMIT 1",
            &path,
        );
        let result = run(&source, "the statement is answered").await;
        assert_eq!(
            result["extract"],
            json!({
                "publishedAt": "2026-08-07T02:00:00Z",
                "publisher": "urn:example:residence-register",
                "extractId": "2026-08-07-full"
            })
        );
    }

    #[tokio::test]
    async fn the_step_budget_stops_an_expensive_statement() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default()
            .columns("[{name: total, type: integer}]")
            .steps(1_000);
        let source = open(
            &plan,
            "WITH RECURSIVE counter(n) AS (
                 SELECT 1 UNION ALL SELECT n + 1 FROM counter WHERE n < 50000000
             ) SELECT COUNT(*) AS total FROM counter",
            &path,
        );
        assert_eq!(run_error(&source).await, cause::STEP_BUDGET_EXCEEDED);
    }

    #[tokio::test]
    async fn the_time_budget_stops_a_slow_statement() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default()
            .columns("[{name: total, type: integer}]")
            .steps(1_000_000)
            .timeout(1);
        let source = open(
            &plan,
            "WITH RECURSIVE counter(n) AS (
                 SELECT 1 UNION ALL SELECT n + 1 FROM counter WHERE n < 50000000
             ) SELECT COUNT(*) AS total FROM counter",
            &path,
        );
        assert_eq!(run_error(&source).await, cause::TIME_BUDGET_EXCEEDED);
    }

    /// A caller may stop awaiting at any point, and both things a request holds
    /// have to survive that: the connection it borrowed and the permit it was
    /// admitted on. Losing the connection while the permit comes back drains the
    /// pool by one slot per cancellation, and once it is empty the source
    /// refuses every later request until it is restarted.
    #[tokio::test]
    async fn a_cancelled_request_gives_back_its_connection_and_its_permit() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        // The recursion depth is a parameter, so one source runs a statement
        // slow enough to be cancelled mid-step and then one that answers at once.
        let plan = Plan::default()
            .columns("[{name: total, type: integer}]")
            .bindings(&format!("{{depth: {}}}", selector_binding("given_name")))
            .steps(1_000_000);
        let source = open(
            &plan,
            "WITH RECURSIVE counter(n) AS (
                 SELECT 1 UNION ALL SELECT n + 1 FROM counter WHERE n < :depth
             ) SELECT COUNT(*) AS total FROM counter",
            &path,
        );
        let depth =
            |value: i64| BTreeMap::from([("depth".to_owned(), SelectorValue::Integer(value))]);

        // One cancellation more than the two permits this plan declares, so a
        // pool that loses a connection per cancellation is empty by the last.
        for _ in 0..3 {
            let cancelled = tokio::time::timeout(
                Duration::from_millis(1),
                source.execute(&depth(50_000_000), instant("2026-08-07T03:00:00Z")),
            )
            .await;
            assert!(
                cancelled.is_err(),
                "the request resolved before its deadline, so either the statement \
                 was too fast to cancel or the pool had already lost a connection"
            );
        }

        // Admission waits out the cancelled runs, which end on their own step
        // budget, so this asks for a permit and a connection that only a
        // cancelled request giving both back can supply.
        let answered = source
            .execute(&depth(1), instant("2026-08-07T03:00:00Z"))
            .await
            .expect("a cancelled request left the pool usable");
        assert_eq!(answered["rows"], json!([{"total": 1}]));
    }

    #[tokio::test]
    async fn one_row_beyond_the_row_bound_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default().rows(2);
        let source = open(&plan, "SELECT id FROM person ORDER BY id", &path);
        assert_eq!(run_error(&source).await, cause::TOO_MANY_ROWS);

        let exact = Plan::default().rows(3);
        let source = open(&exact, "SELECT id FROM person ORDER BY id", &path);
        let result = run(&source, "the row bound admits its own count").await;
        assert_eq!(
            result["rows"],
            json!([{"id": "p-1"}, {"id": "p-2"}, {"id": "p-3"}])
        );
    }

    /// The response bound is measured while the result is collected, not only
    /// once the whole result exists. A row bound and a cell bound bound each
    /// value, never their product, so a bundle at the schema maxima could
    /// otherwise assemble a result far past its declared ceiling before anyone
    /// measured it.
    #[tokio::test]
    async fn a_result_beyond_the_response_bound_is_refused_as_it_is_collected() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default().response_bytes(8);
        let source = open(&plan, "SELECT id FROM person ORDER BY id", &path);
        assert_eq!(run_error(&source).await, cause::RESPONSE_TOO_LARGE);

        // The three identifiers are nine bytes of text between them, and the
        // count is of text alone, so a bound of nine admits exactly them.
        let exact = Plan::default().response_bytes(9);
        let source = open(&exact, "SELECT id FROM person ORDER BY id", &path);
        let result = run(&source, "the response bound admits its own size").await;
        assert_eq!(
            result["rows"],
            json!([{"id": "p-1"}, {"id": "p-2"}, {"id": "p-3"}])
        );
    }

    #[tokio::test]
    async fn a_value_beyond_the_cell_bound_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default()
            .columns("[{name: id, type: string}]")
            .cell_bytes(8);
        let source = open(&plan, "SELECT note AS id FROM person ORDER BY id", &path);
        assert_eq!(run_error(&source).await, cause::CELL_TOO_LARGE);
    }

    /// The declared bound is read against a value SQLite has already produced,
    /// so on its own it cannot keep an enormous cell out of memory. This
    /// statement asks for a single character of one, which SQLite answers
    /// happily once the payload is resident. Without the engine limit it
    /// succeeds and returns that character, having first pulled the whole cell
    /// into the process; with it, the step that would read the payload refuses
    /// on the length in the record header, before any of it is read.
    #[tokio::test]
    async fn a_cell_beyond_the_engine_limit_is_refused_before_it_is_read() {
        let directory = TempDir::new().expect("a temporary directory");
        let oversized = format!(
            "{EXTRACT_SCHEMA}
             INSERT INTO person
             SELECT 'p-big', 'nw', 1, 1.0, hex(zeroblob({}));",
            MAXIMUM_ENGINE_VALUE_BYTES
        );
        let path = build_extract(
            &directory,
            &format!(
                "CREATE TABLE {EXTRACT_METADATA_TABLE} \
                 (published_at TEXT, publisher TEXT, extract_id TEXT);
                 INSERT INTO {EXTRACT_METADATA_TABLE} VALUES \
                 ('2026-08-07T02:00:00Z', 'urn:example:residence-register', '2026-08-07-full');
                 {oversized}"
            ),
        );
        let plan = Plan::default().columns("[{name: id, type: string}]");
        let source = open(
            &plan,
            "SELECT substr(note, 1, 1) AS id FROM person WHERE id = 'p-big'",
            &path,
        );
        assert_eq!(run_error(&source).await, cause::CELL_TOO_LARGE);
    }

    #[test]
    fn the_declared_columns_must_match_the_result_columns() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let two =
            Plan::default().columns("[{name: id, type: string}, {name: region, type: string}]");
        assert_eq!(
            open_error(
                &two,
                "SELECT id, region_code AS locality FROM person",
                &path
            ),
            cause::COLUMN_MISMATCH,
            "a renamed result column was accepted"
        );
        assert_eq!(
            open_error(&two, "SELECT region_code AS region, id FROM person", &path),
            cause::COLUMN_MISMATCH,
            "a reordered result was accepted"
        );
        assert_eq!(
            open_error(&two, "SELECT id FROM person", &path),
            cause::COLUMN_MISMATCH,
            "a short result was accepted"
        );
    }

    #[test]
    fn statement_parameters_and_declared_bindings_must_agree() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let none = Plan::default();
        assert_eq!(
            open_error(&none, "SELECT id FROM person WHERE id = :record", &path),
            cause::UNDECLARED_PARAMETER
        );
        assert_eq!(
            open_error(&none, "SELECT id FROM person WHERE id = ?", &path),
            cause::UNDECLARED_PARAMETER,
            "a positional parameter was accepted"
        );
        let declared =
            Plan::default().bindings(&format!("{{record: {}}}", selector_binding("given_name")));
        assert_eq!(
            open_error(&declared, "SELECT id FROM person", &path),
            cause::UNUSED_BINDING
        );
    }

    #[tokio::test]
    async fn a_declared_parameter_carries_its_supplied_value() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan =
            Plan::default().bindings(&format!("{{record: {}}}", selector_binding("given_name")));
        let source = open(&plan, "SELECT id FROM person WHERE id = :record", &path);
        let mut parameters = BTreeMap::new();
        parameters.insert("record".to_owned(), SelectorValue::String("p-2".to_owned()));
        let result = source
            .execute(&parameters, instant("2026-08-07T03:00:00Z"))
            .await
            .expect("the parameterised statement is answered");
        assert_eq!(result["rows"], json!([{"id": "p-2"}]));

        let Err(missing) = source
            .execute(&BTreeMap::new(), instant("2026-08-07T03:00:00Z"))
            .await
        else {
            panic!("an unsupplied parameter was accepted");
        };
        assert_eq!(missing.cause(), Some(cause::MISSING_PARAMETER));
    }

    #[tokio::test]
    async fn the_reserved_parameter_carries_the_evaluation_instant() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default()
            .columns("[{name: id, type: string}, {name: observed_at, type: string}]");
        let source = open(
            &plan,
            "SELECT id, :evidence_now AS observed_at FROM person WHERE id = 'p-1'",
            &path,
        );
        // A fractional instant, rendered as the whole second the assertion
        // reports. A statement comparing the bound value against text stored to
        // the second has to see the same characters, and a longer form would
        // sort after every one of them.
        let result = source
            .execute(&BTreeMap::new(), instant("2026-08-07T03:00:00.750Z"))
            .await
            .expect("the statement reading the evaluation instant is answered");
        assert_eq!(
            result["rows"],
            json!([{"id": "p-1", "observed_at": "2026-08-07T03:00:00Z"}])
        );
    }

    #[test]
    fn a_second_statement_in_the_artifact_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        assert_eq!(
            open_error(
                &Plan::default(),
                "SELECT id FROM person; SELECT id FROM person",
                &path
            ),
            cause::MULTIPLE_STATEMENTS
        );
    }

    #[test]
    fn a_statement_fault_names_its_artifact() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let Err(error) = SqliteExtractSource::open(&Plan::default().build(), "SELCT", &path) else {
            panic!("invalid SQL was accepted");
        };
        let fault = error
            .artifact_fault()
            .expect("the failure names an artifact");
        assert_eq!(fault.artifact(), STATEMENT_ARTIFACT);
        assert_eq!(fault.fault().cause(), cause::INVALID_SQL);
    }

    #[test]
    fn an_unknown_table_and_an_unknown_column_are_told_apart() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default();
        assert_eq!(
            open_error(&plan, "SELECT id FROM absent", &path),
            cause::UNKNOWN_TABLE
        );
        assert_eq!(
            open_error(&plan, "SELECT absent AS id FROM person", &path),
            cause::UNKNOWN_COLUMN
        );
    }

    #[test]
    fn an_extract_without_its_metadata_table_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract_without_metadata(&directory);
        assert_eq!(
            open_error(&Plan::default(), "SELECT id FROM person", &path),
            cause::NO_METADATA_TABLE
        );
    }

    #[test]
    fn a_metadata_table_without_exactly_one_row_is_refused() {
        for rows in [
            "",
            "INSERT INTO evidence_extract VALUES ('2026-08-07T02:00:00Z', 'a', 'b'), \
             ('2026-08-07T03:00:00Z', 'c', 'd');",
        ] {
            let directory = TempDir::new().expect("a temporary directory");
            let path = extract_with_metadata(&directory, rows);
            assert_eq!(
                open_error(&Plan::default(), "SELECT id FROM person", &path),
                cause::MALFORMED_METADATA
            );
        }
    }

    #[test]
    fn malformed_metadata_is_refused() {
        for rows in [
            "INSERT INTO evidence_extract VALUES ('yesterday', 'a', 'b');",
            "INSERT INTO evidence_extract VALUES (NULL, 'a', 'b');",
            "INSERT INTO evidence_extract VALUES ('2026-08-07T02:00:00Z', NULL, 'b');",
            "INSERT INTO evidence_extract VALUES ('2026-08-07T02:00:00Z', 'a', '');",
        ] {
            let directory = TempDir::new().expect("a temporary directory");
            let path = extract_with_metadata(&directory, rows);
            assert_eq!(
                open_error(&Plan::default(), "SELECT id FROM person", &path),
                cause::MALFORMED_METADATA
            );
        }
    }

    #[test]
    fn a_metadata_table_missing_a_column_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = build_extract(
            &directory,
            &format!(
                "CREATE TABLE {EXTRACT_METADATA_TABLE} (published_at TEXT, publisher TEXT);
                 INSERT INTO {EXTRACT_METADATA_TABLE} VALUES ('2026-08-07T02:00:00Z', 'a');
                 {EXTRACT_SCHEMA}"
            ),
        );
        assert_eq!(
            open_error(&Plan::default(), "SELECT id FROM person", &path),
            cause::MALFORMED_METADATA
        );
    }

    /// Nothing makes the reserved metadata object a table, and a view over a
    /// nonterminating recursive query is a read that never ends. Startup has to
    /// refuse it and say so rather than hang with nothing to report.
    #[test]
    fn a_metadata_view_that_never_terminates_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = build_extract(
            &directory,
            &format!(
                "CREATE VIEW {EXTRACT_METADATA_TABLE} AS
                 WITH RECURSIVE forever(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM forever)
                 SELECT '2026-08-07T02:00:00Z' AS published_at,
                        'urn:example:residence-register' AS publisher,
                        CAST(MAX(n) AS TEXT) AS extract_id
                 FROM forever;
                 {EXTRACT_SCHEMA}"
            ),
        );
        assert_eq!(
            open_error(
                &Plan::default().steps(1_000),
                "SELECT id FROM person",
                &path
            ),
            cause::METADATA_BUDGET_EXCEEDED
        );
    }

    /// The publication instant is truncated where it is parsed, so the instant
    /// the age bound is measured against is the instant the response carries and
    /// a relying party recomputing the age cannot reach a different answer.
    #[tokio::test]
    async fn a_fractional_publication_instant_is_compared_as_it_is_emitted() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract_with_metadata(
            &directory,
            "INSERT INTO evidence_extract VALUES \
             ('2026-08-07T02:00:00.750Z', 'urn:example:residence-register', '2026-08-07-full');",
        );
        let source = open(
            &Plan::default(),
            "SELECT id FROM person ORDER BY id LIMIT 1",
            &path,
        );
        let result = run(&source, "the statement is answered").await;
        assert_eq!(
            result["extract"]["publishedAt"],
            json!("2026-08-07T02:00:00Z")
        );
        assert_eq!(
            source.extract_metadata().published_at(),
            instant("2026-08-07T02:00:00Z")
        );

        // The default bound is one day, measured from the emitted second: that
        // second exactly is within it, and the one after is not.
        assert_eq!(
            source.validate_extract_age(instant("2026-08-08T02:00:00Z")),
            Ok(())
        );
        assert_eq!(
            source
                .validate_extract_age(instant("2026-08-08T02:00:01Z"))
                .err()
                .and_then(|error| error.cause()),
            Some(cause::EXTRACT_TOO_OLD)
        );
    }

    #[test]
    fn the_extract_age_bound_is_inclusive() {
        let metadata = ExtractMetadata::new(
            instant("2026-08-07T02:00:00Z"),
            "urn:example:residence-register",
            "2026-08-07-full",
        );
        assert_eq!(
            extract_age_within_bound(&metadata, instant("2026-08-07T03:00:00Z"), 3_600),
            Ok(())
        );
        let refused = extract_age_within_bound(&metadata, instant("2026-08-07T03:00:01Z"), 3_600)
            .expect_err("a stale extract was accepted");
        assert_eq!(refused.cause(), Some(cause::EXTRACT_TOO_OLD));
    }

    #[test]
    fn the_configured_age_bound_refuses_a_stale_extract() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let source = open(&Plan::default(), "SELECT id FROM person", &path);
        assert_eq!(
            source.validate_extract_age(instant("2026-08-08T01:59:00Z")),
            Ok(())
        );
        assert_eq!(
            source
                .validate_extract_age(instant("2026-08-08T02:00:01Z"))
                .err()
                .and_then(|error| error.cause()),
            Some(cause::EXTRACT_TOO_OLD)
        );
        assert_eq!(
            source.extract_metadata().publisher(),
            "urn:example:residence-register"
        );
        assert_eq!(
            source.extract_metadata().published_at(),
            Utc.with_ymd_and_hms(2026, 8, 7, 2, 0, 0).unwrap()
        );
    }

    #[tokio::test]
    async fn each_declared_column_type_reads_its_value() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default().columns(
            "[{name: id, type: string}, {name: active, type: boolean}, \
              {name: score, type: number}, {name: note, type: string}]",
        );
        let source = open(
            &plan,
            "SELECT id, active, score, note FROM person ORDER BY id LIMIT 1",
            &path,
        );
        let result = run(&source, "the typed statement is answered").await;
        assert_eq!(
            result["rows"],
            json!([{"id": "p-1", "active": true, "score": 1.5, "note": "short"}])
        );

        let integral = Plan::default().columns("[{name: id, type: number}]");
        let source = open(&integral, "SELECT COUNT(*) AS id FROM person", &path);
        let result = run(&source, "an integer reads as a number").await;
        assert_eq!(result["rows"], json!([{"id": 3}]));

        let nullable = Plan::default().columns("[{name: id, type: string}]");
        let source = open(
            &nullable,
            "SELECT note AS id FROM person WHERE id = 'p-3'",
            &path,
        );
        let result = run(&source, "a null reads as null").await;
        assert_eq!(result["rows"], json!([{"id": null}]));
    }

    #[tokio::test]
    async fn a_value_of_the_wrong_type_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        for (declared, statement) in [
            ("string", "SELECT active AS id FROM person WHERE id = 'p-1'"),
            ("integer", "SELECT id FROM person WHERE id = 'p-1'"),
            ("number", "SELECT id FROM person WHERE id = 'p-1'"),
            ("boolean", "SELECT score AS id FROM person WHERE id = 'p-1'"),
            ("boolean", "SELECT 2 AS id"),
            (
                "string",
                "SELECT CAST(id AS BLOB) AS id FROM person WHERE id = 'p-1'",
            ),
        ] {
            let plan = Plan::default().columns(&format!("[{{name: id, type: {declared}}}]"));
            let source = open(&plan, statement, &path);
            assert_eq!(
                run_error(&source).await,
                cause::VALUE_TYPE_MISMATCH,
                "a {declared} column accepted a value it cannot represent"
            );
        }
    }

    #[test]
    fn the_offline_check_accepts_what_only_the_extract_can_settle() {
        let plan = Plan::default().build();
        assert_eq!(
            check_statement_offline(&plan, "SELECT id FROM person"),
            Ok(()),
            "the offline check rejected an unknown table"
        );
        assert_eq!(
            check_statement_offline(&plan, "SELECT absent FROM (SELECT 1 AS id)"),
            Ok(()),
            "the offline check rejected an unknown column"
        );
    }

    #[test]
    fn the_offline_check_refuses_what_it_can_settle() {
        let plan = Plan::default().build();
        for (statement, expected) in [
            ("SELCT id FROM person", cause::INVALID_SQL),
            ("SELECT 1 AS id; SELECT 2 AS id", cause::MULTIPLE_STATEMENTS),
            ("CREATE TABLE shadow (id TEXT)", cause::AUTHORIZER_REFUSED),
            (
                "ATTACH DATABASE 'other' AS other",
                cause::AUTHORIZER_REFUSED,
            ),
            ("PRAGMA table_list", cause::AUTHORIZER_REFUSED),
            ("SELECT random() AS id", cause::AUTHORIZER_REFUSED),
            ("SELECT date('now') AS id", cause::AUTHORIZER_REFUSED),
        ] {
            let error = check_statement_offline(&plan, statement)
                .expect_err("the offline check accepted a statement it can settle");
            assert_eq!(error.cause(), Some(expected));
            assert_eq!(
                error
                    .artifact_fault()
                    .expect("the failure names an artifact")
                    .artifact(),
                STATEMENT_ARTIFACT
            );
        }
    }

    /// The weak check stops at the first name it cannot resolve, so a fault
    /// hidden behind an extract-only name survives it. The strong check is what
    /// settles these, and this test pins the boundary between the two.
    #[test]
    fn the_offline_check_cannot_see_past_an_unresolved_name() {
        let plan = Plan::default().build();
        for statement in [
            "SELECT id FROM person; DROP TABLE person",
            "DELETE FROM person",
            "SELECT id FROM person WHERE updated_at > date('now')",
        ] {
            assert_eq!(
                check_statement_offline(&plan, statement),
                Ok(()),
                "the offline check settled something only the extract can"
            );
        }

        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let strong = Plan::default();
        assert_eq!(
            open_error(&strong, "SELECT id FROM person; DROP TABLE person", &path),
            cause::AUTHORIZER_REFUSED
        );
        assert_eq!(
            open_error(&strong, "DELETE FROM person", &path),
            cause::AUTHORIZER_REFUSED
        );
    }

    fn offline_fault(statement_sql: &str) -> SqliteSourceError {
        check_statement_offline(&Plan::default().build(), statement_sql)
            .expect_err("the offline check accepted a statement it can settle")
    }

    fn fault_location(error: &SqliteSourceError) -> Option<TextLocation> {
        error
            .artifact_fault()
            .expect("the failure names an artifact")
            .fault()
            .location()
    }

    /// A syntax error is the one statement fault with a character behind it, so
    /// it is the one fault that says where to look.
    #[test]
    fn a_syntax_error_reports_the_line_and_column_it_is_on() {
        assert_eq!(
            fault_location(&offline_fault("SELCT id FROM person")),
            Some(TextLocation { line: 1, column: 1 }),
        );
        assert_eq!(
            fault_location(&offline_fault("SELECT id\nFROM person\nWHERE id = = 'x'")),
            Some(TextLocation {
                line: 3,
                column: 12
            }),
        );
        // A stray closing token sits on the last character of the statement.
        assert_eq!(
            fault_location(&offline_fault("SELECT id FROM person WHERE id = 'x' )")),
            Some(TextLocation {
                line: 1,
                column: 38
            }),
        );

        // The strong check reports the same position as the weak one.
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let Err(strong) = SqliteExtractSource::open(
            &Plan::default().build(),
            "SELECT id\nFROM person\nWHERE id = = 'x'",
            &path,
        ) else {
            panic!("invalid SQL was accepted");
        };
        assert_eq!(
            fault_location(&strong),
            Some(TextLocation {
                line: 3,
                column: 12
            }),
        );
    }

    /// A column counts characters, the way the configuration decoder's own
    /// locations do, so it is the column an adopter's editor shows.
    #[test]
    fn a_column_counts_characters_rather_than_bytes() {
        assert_eq!(
            fault_location(&offline_fault(
                "SELECT 'eééé' AS id FROM person WHERE id = = 'x'"
            )),
            Some(TextLocation {
                line: 1,
                column: 44
            }),
        );
    }

    /// An offset at or past the end of the text is the position just after the
    /// last character, not a panic.
    #[test]
    fn an_offset_at_or_past_the_end_of_the_text_still_has_a_position() {
        let text = "SELECT id\nFROM person";
        for offset in [text.len(), text.len() + 1, usize::MAX] {
            assert_eq!(
                text_location(text, offset),
                TextLocation {
                    line: 2,
                    column: 12
                },
                "offset {offset} did not land after the last character"
            );
        }
        assert_eq!(text_location("", 0), TextLocation { line: 1, column: 1 });
        assert_eq!(
            text_location("SELECT id\n", 10),
            TextLocation { line: 2, column: 1 },
        );
    }

    /// Every other fault is a property of the statement as a whole, so it names
    /// no character rather than inventing one.
    #[tokio::test]
    async fn a_fault_without_a_character_behind_it_reports_no_location() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let plan = Plan::default();
        for (statement, expected) in [
            ("SELECT id FROM absent", cause::UNKNOWN_TABLE),
            ("SELECT absent AS id FROM person", cause::UNKNOWN_COLUMN),
            ("PRAGMA table_list", cause::AUTHORIZER_REFUSED),
            (
                "SELECT id FROM person; SELECT id FROM person",
                cause::MULTIPLE_STATEMENTS,
            ),
        ] {
            let Err(error) = SqliteExtractSource::open(&plan.build(), statement, &path) else {
                panic!("the statement source was accepted");
            };
            assert_eq!(error.cause(), Some(expected));
            assert_eq!(fault_location(&error), None, "{expected} named a position");
        }

        let bounded = Plan::default().rows(2);
        let source = open(&bounded, "SELECT id FROM person ORDER BY id", &path);
        let Err(exceeded) = source
            .execute(&BTreeMap::new(), instant("2026-08-07T03:00:00Z"))
            .await
        else {
            panic!("the row bound was not enforced");
        };
        assert_eq!(exceeded.cause(), Some(cause::TOO_MANY_ROWS));
        assert_eq!(fault_location(&exceeded), None);
    }

    /// A line and a column are structure. The SQL sitting on that line is
    /// content, and no diagnostic this module renders may carry it.
    #[test]
    fn a_located_syntax_fault_carries_no_statement_text() {
        const CANARY: &str = "s3cr3t-canary-value";
        let error = offline_fault(&format!(
            "SELECT id FROM person\nWHERE note = '{CANARY}' AND id = = 'p-1'"
        ));
        assert_eq!(
            fault_location(&error),
            Some(TextLocation {
                line: 2,
                column: 45
            }),
        );
        let rendered = error.to_string();
        assert!(
            !rendered.contains(CANARY),
            "the diagnostic leaked statement text: {rendered}"
        );
        assert_eq!(
            rendered,
            "an Evidence statement is invalid: artifact queries/residence-region.sql: \
             the statement is not valid SQL (line 2 column 45)",
        );
    }

    #[test]
    fn an_unopenable_extract_is_refused() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = directory.path().join("absent.sqlite");
        assert_eq!(
            open_error(&Plan::default(), "SELECT id FROM person", &path),
            cause::EXTRACT_UNAVAILABLE
        );
    }
}
