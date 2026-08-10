//! Bounded execution of one reviewed SQL statement against a read-only extract.
//!
//! The transport holds one reviewed statement and one extract file. Review of
//! the statement is the disclosure control. `registry-platform-sqlite` supplies
//! the safety boundary that refuses whole categories of SQL; it is not a
//! per-table or per-column declaration of what may be read.
//!
//! Every failure this module reports names the bundle artifact it came from
//! and a cause drawn from [`cause`], so an adopter is told which file to open
//! and what is wrong with it. SQLite's own message text is classified and then
//! discarded: it quotes schema identifiers and stored values, and no error in
//! this crate carries data.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, SubsecRound as _, Utc};
use registry_platform_sqlite::{
    CapturedSnapshot, ColumnContract, ColumnType, DatabaseProfile, ErrorKind as PlatformErrorKind,
    ParameterContract, ReadOnlyStatement, StatementContract, StatementLimits,
    Value as PlatformValue,
};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use thiserror::Error;

use crate::bundle::ArtifactFault;
use crate::config::{
    SchemaFault, SourceConfig, SqliteColumnType, SqliteRequest, TextLocation,
    RESERVED_SQL_PARAMETER,
};
use crate::model::SelectorValue;

/// The reserved metadata table every extract carries.
pub const EXTRACT_METADATA_TABLE: &str = "evidence_extract";

/// The largest metadata field an extract may declare.
const MAXIMUM_METADATA_FIELD_BYTES: usize = 1_024;
/// Worst-case JSON accounting for three maximum-size metadata strings plus
/// their fixed keys and row/collection framing. A one-byte control character
/// can require six JSON bytes, while the frozen metadata contract bounds the
/// original UTF-8 field bytes rather than their serialized representation.
const MAXIMUM_METADATA_RESPONSE_BYTES: usize = 20 * 1_024;

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
#[cfg(test)]
const MAXIMUM_ENGINE_VALUE_BYTES: i32 = 8 * 1_024 * 1_024;

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
    #[error("the statement source exceeded its time limit")]
    Timeout,
    #[error("the statement source execution thread is unavailable")]
    Unavailable,
}

impl SqliteSourceError {
    /// The artifact a caller should point an adopter at, where there is one.
    ///
    /// Statement faults name the bundle-relative statement artifact. Extract
    /// faults name the bundle-governed logical extract profile, never its
    /// operator path or publisher-controlled metadata.
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
    extract_profile: &str,
) -> Result<(), SqliteSourceError> {
    let age = (evaluation_instant - metadata.published_at).num_seconds();
    let bound = i64::try_from(maximum_age_seconds).unwrap_or(i64::MAX);
    if age > bound {
        return Err(extract_fault(extract_profile, cause::EXTRACT_TOO_OLD));
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
    let (request, _, _) = statement_source(source)?;
    let artifact = request.statement.as_str();
    let contract = platform_contract(request, statement_sql)?;
    registry_platform_sqlite::check_statement_offline(&contract)
        .map_err(|error| map_platform_error(error, artifact, "extract"))
}

fn statement_source(
    source: &SourceConfig,
) -> Result<(&SqliteRequest, u64, &str), SqliteSourceError> {
    match source {
        SourceConfig::SqliteExtract {
            request,
            maximum_extract_age_seconds,
            extract_profile,
            ..
        } => Ok((request, *maximum_extract_age_seconds, extract_profile)),
        SourceConfig::HttpJson { .. } => Err(SqliteSourceError::InvalidPlan),
    }
}

/// The reviewed statement and the bounds its result is read under.
#[derive(Debug)]
struct StatementPlan {
    artifact: String,
    parameters: Vec<String>,
    maximum_extract_age_seconds: u64,
    extract_profile: String,
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
    /// The platform boundary owns the connection pool, admission permits, and
    /// cancellation recovery.
    statement: ReadOnlyStatement,
}

impl SqliteExtractSource {
    /// Open an extract and run the strong check against it.
    ///
    /// `extract_path` must name a regular, unwritable, sidecar-free file. The
    /// platform capture enforces that precondition before using `immutable=1`.
    pub fn open(
        source: &SourceConfig,
        statement_sql: &str,
        extract_path: &Path,
    ) -> Result<Self, SqliteSourceError> {
        let (_, _, extract_profile) = statement_source(source)?;
        let captured = CapturedSnapshot::capture(extract_path)
            .map_err(|_| extract_fault(extract_profile, cause::EXTRACT_UNAVAILABLE))?;
        Self::open_captured(source, statement_sql, captured)
    }

    /// Open the exact snapshot already validated and digest-bound by the
    /// runtime document. Re-capturing by path here could accept a replacement
    /// under the old runtime revision.
    pub(crate) fn open_captured(
        source: &SourceConfig,
        statement_sql: &str,
        captured: CapturedSnapshot,
    ) -> Result<Self, SqliteSourceError> {
        let (request, maximum_extract_age_seconds, extract_profile) = statement_source(source)?;
        let artifact = request.statement.as_str();
        let timeout = Duration::from_millis(request.timeout_milliseconds);
        let profile = DatabaseProfile::Snapshot(captured);
        let metadata = read_extract_metadata(
            &profile,
            extract_profile,
            request.maximum_statement_steps,
            timeout,
        )?;
        let statement = ReadOnlyStatement::open_with_text_value_response_budget(
            profile,
            platform_contract(request, statement_sql)?,
        )
        .map_err(|error| map_platform_error(error, artifact, extract_profile))?;
        let parameters = request
            .parameter_bindings
            .keys()
            .map(str::to_owned)
            .collect();

        let plan = StatementPlan {
            artifact: artifact.to_owned(),
            parameters,
            maximum_extract_age_seconds,
            extract_profile: extract_profile.to_owned(),
        };
        Ok(Self {
            plan: Arc::new(plan),
            extract: metadata.as_json(),
            metadata,
            statement,
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
            &self.plan.extract_profile,
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
    /// transport, and so does the authoritative response size check. Collection
    /// here charges the original UTF-8 text payload against that same bound so
    /// the intermediate result is bounded before the caller projects it. This
    /// is the frozen Evidence accounting contract: the caller's later check is
    /// authoritative for the complete serialized result.
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
        let rows = self
            .statement
            .execute(&bindings)
            .await
            .map_err(|error| {
                map_platform_error(error, &self.plan.artifact, &self.plan.extract_profile)
            })?
            .rows
            .into_iter()
            .map(platform_row_json)
            .collect();
        let mut result = JsonMap::new();
        result.insert("rows".to_owned(), JsonValue::Array(rows));
        result.insert("extract".to_owned(), self.extract.clone());
        Ok(JsonValue::Object(result))
    }

    fn bind_values(
        &self,
        parameters: &BTreeMap<String, SelectorValue>,
        evaluation_instant: DateTime<Utc>,
    ) -> Result<BTreeMap<String, PlatformValue>, SqliteSourceError> {
        // Fixed-width RFC 3339 UTC, so a statement that compares the instant
        // against stored text orders lexically the way it orders in time. Whole
        // seconds, because this is the same rendering the assertion carries: a
        // statement comparing the bound value against a stored `2026-08-08T03:00:00Z`
        // sees the text the runtime reports, not a longer form that sorts after
        // it. The runtime truncates the instant where it reads the clock, so in
        // production this only chooses how an already-whole second is written.
        let instant = evaluation_instant.to_rfc3339_opts(SecondsFormat::Secs, true);
        let mut bound = BTreeMap::new();
        for parameter in &self.plan.parameters {
            let value = match parameters.get(parameter) {
                Some(SelectorValue::String(text)) => PlatformValue::String(text.clone()),
                Some(SelectorValue::Integer(number)) => PlatformValue::Integer(*number),
                Some(SelectorValue::Boolean(flag)) => PlatformValue::Boolean(*flag),
                None => return Err(self.plan.fault(cause::MISSING_PARAMETER)),
            };
            bound.insert(parameter.clone(), value);
        }
        bound.insert(
            RESERVED_SQL_PARAMETER.to_owned(),
            PlatformValue::String(instant),
        );
        Ok(bound)
    }
}

fn platform_contract(
    request: &SqliteRequest,
    statement_sql: &str,
) -> Result<StatementContract, SqliteSourceError> {
    let columns = request
        .columns
        .iter()
        .map(|column| ColumnContract {
            name: column.name.clone(),
            value_type: match column.value_type {
                SqliteColumnType::String => ColumnType::String,
                SqliteColumnType::Integer => ColumnType::Integer,
                SqliteColumnType::Number => ColumnType::Number,
                SqliteColumnType::Boolean => ColumnType::Boolean,
            },
        })
        .collect();
    let mut parameters: Vec<_> = request
        .parameter_bindings
        .keys()
        .map(|name| ParameterContract {
            name: name.to_owned(),
            required: true,
        })
        .collect();
    parameters.push(ParameterContract {
        name: RESERVED_SQL_PARAMETER.to_owned(),
        required: false,
    });
    Ok(StatementContract {
        sql: statement_sql.to_owned(),
        columns,
        parameters,
        limits: StatementLimits {
            maximum_rows: request.maximum_rows,
            maximum_cell_bytes: usize::try_from(request.maximum_cell_bytes)
                .map_err(|_| SqliteSourceError::InvalidPlan)?,
            maximum_response_bytes: usize::try_from(request.maximum_response_bytes)
                .map_err(|_| SqliteSourceError::InvalidPlan)?,
            maximum_statement_steps: request.maximum_statement_steps,
            timeout: Duration::from_millis(request.timeout_milliseconds),
            concurrency: usize::from(request.concurrency_limit),
        },
        schema: None,
    })
}

fn map_platform_error(
    error: registry_platform_sqlite::SqliteError,
    artifact: &str,
    extract_profile: &str,
) -> SqliteSourceError {
    let cause = match error.kind() {
        PlatformErrorKind::InvalidPlan => return SqliteSourceError::InvalidPlan,
        PlatformErrorKind::Concurrency => return SqliteSourceError::Concurrency,
        PlatformErrorKind::Timeout | PlatformErrorKind::TimeBudgetExceeded => {
            return SqliteSourceError::Timeout;
        }
        PlatformErrorKind::WorkerUnavailable => return SqliteSourceError::Unavailable,
        PlatformErrorKind::DatabaseUnavailable
        | PlatformErrorKind::DatabaseReplaced
        | PlatformErrorKind::DatabaseWritable
        | PlatformErrorKind::DatabaseSymlink
        | PlatformErrorKind::DatabaseNotFile
        | PlatformErrorKind::DatabaseChanged
        | PlatformErrorKind::UncheckpointedSidecar => {
            return extract_fault(extract_profile, cause::EXTRACT_UNAVAILABLE);
        }
        _ => error.cause(),
    };
    match error.location() {
        Some(location) => SqliteSourceError::Statement(ArtifactFault::at(
            artifact,
            SchemaFault::because(cause),
            TextLocation {
                line: location.line,
                column: location.column,
            },
        )),
        None => statement_fault(artifact, cause),
    }
}

fn platform_row_json(row: BTreeMap<String, PlatformValue>) -> JsonValue {
    JsonValue::Object(
        row.into_iter()
            .map(|(name, value)| {
                let value = match value {
                    PlatformValue::Null => JsonValue::Null,
                    PlatformValue::String(value) => JsonValue::String(value),
                    PlatformValue::Integer(value) => JsonValue::from(value),
                    PlatformValue::Number(value) => {
                        JsonNumber::from_f64(value).map_or(JsonValue::Null, JsonValue::Number)
                    }
                    PlatformValue::Boolean(value) => JsonValue::Bool(value),
                };
                (name, value)
            })
            .collect(),
    )
}

/// Build an extract file from a reviewed text seed.
///
/// A fixture states the world its cases assert against as SQL text rather than
/// as a committed database file. The text is diffable, it is reviewed with
/// every other bundle artifact, and it keeps table and column names legible to
/// the checks that read this tree, none of which an opaque binary would be.
///
/// The fixture connection can execute DDL and `INSERT`; the production reader
/// cannot. This connection is closed before the extract is opened again,
/// read-only and immutable, through `registry-platform-sqlite`, so building a
/// fixture world and reading one are two connections apart and neither can be
/// mistaken for the other.
///
/// The finished file is made unwritable, because `immutable=1` on the reading
/// connection is sound only against a file nothing will change.
pub fn materialize_seed_extract(target: &Path, seed_sql: &str) -> Result<(), SqliteSourceError> {
    let subject = extract_subject(target);
    registry_platform_sqlite::materialize_fixture(target, seed_sql).map_err(|error| {
        let cause = if error.kind() == PlatformErrorKind::InvalidSql {
            cause::INVALID_SQL
        } else {
            cause::EXTRACT_UNAVAILABLE
        };
        extract_fault(&subject, cause)
    })
}

/// A fixture-only extract name used internally while its seed is materialized.
/// Fixture materialization collapses its errors before displaying them, so this
/// value never crosses the diagnostic boundary.
fn extract_subject(extract_path: &Path) -> String {
    extract_path.file_name().map_or_else(
        || "extract".to_owned(),
        |name| name.to_string_lossy().into(),
    )
}

/// The extract's reserved metadata table, read before any row of data is.
///
/// Nothing requires the reserved object to be an ordinary table: a view reads
/// as metadata just as well, and a view over a nonterminating recursive query
/// would otherwise step forever and hang startup with nothing to say about it.
/// So this read carries the same declared step and time bounds the statement
/// itself runs under, and reports its own cause when it exceeds them.
fn read_extract_metadata(
    profile: &DatabaseProfile,
    subject: &str,
    maximum_statement_steps: u64,
    timeout: Duration,
) -> Result<ExtractMetadata, SqliteSourceError> {
    let sql = format!("SELECT published_at, publisher, extract_id FROM {EXTRACT_METADATA_TABLE}");
    let statement = ReadOnlyStatement::open(
        profile.clone(),
        StatementContract {
            sql,
            columns: vec![
                ColumnContract {
                    name: "published_at".to_owned(),
                    value_type: ColumnType::String,
                },
                ColumnContract {
                    name: "publisher".to_owned(),
                    value_type: ColumnType::String,
                },
                ColumnContract {
                    name: "extract_id".to_owned(),
                    value_type: ColumnType::String,
                },
            ],
            parameters: Vec::new(),
            limits: StatementLimits {
                maximum_rows: 1,
                maximum_cell_bytes: MAXIMUM_METADATA_FIELD_BYTES,
                maximum_response_bytes: MAXIMUM_METADATA_RESPONSE_BYTES,
                maximum_statement_steps,
                timeout,
                concurrency: 1,
            },
            schema: None,
        },
    )
    .map_err(|error| map_metadata_error(error, subject))?;
    let result = statement
        .execute_at_open(&BTreeMap::new())
        .map_err(|error| map_metadata_error(error, subject))?;
    let malformed = || extract_fault(subject, cause::MALFORMED_METADATA);
    let row = result.rows.into_iter().next().ok_or_else(malformed)?;
    let published_at = metadata_value(&row, "published_at", subject)?;
    let publisher = metadata_value(&row, "publisher", subject)?;
    let extract_id = metadata_value(&row, "extract_id", subject)?;

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

fn metadata_value(
    row: &BTreeMap<String, PlatformValue>,
    name: &str,
    subject: &str,
) -> Result<String, SqliteSourceError> {
    let malformed = || extract_fault(subject, cause::MALFORMED_METADATA);
    let Some(PlatformValue::String(value)) = row.get(name) else {
        return Err(malformed());
    };
    if value.is_empty() || value.len() > MAXIMUM_METADATA_FIELD_BYTES {
        return Err(malformed());
    }
    Ok(value.clone())
}

fn map_metadata_error(
    error: registry_platform_sqlite::SqliteError,
    subject: &str,
) -> SqliteSourceError {
    let cause = match error.kind() {
        PlatformErrorKind::UnknownTable => cause::NO_METADATA_TABLE,
        PlatformErrorKind::StepBudgetExceeded
        | PlatformErrorKind::TimeBudgetExceeded
        | PlatformErrorKind::Timeout => cause::METADATA_BUDGET_EXCEEDED,
        PlatformErrorKind::DatabaseUnavailable
        | PlatformErrorKind::DatabaseReplaced
        | PlatformErrorKind::DatabaseWritable
        | PlatformErrorKind::DatabaseSymlink
        | PlatformErrorKind::DatabaseNotFile
        | PlatformErrorKind::DatabaseChanged
        | PlatformErrorKind::UncheckpointedSidecar => cause::EXTRACT_UNAVAILABLE,
        _ => cause::MALFORMED_METADATA,
    };
    extract_fault(subject, cause)
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
        let mut permissions = std::fs::metadata(&path)
            .expect("the extract fixture has metadata")
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).expect("the extract fixture is immutable");
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
        let error = source
            .execute(&BTreeMap::new(), instant("2026-08-07T03:00:00Z"))
            .await
            .expect_err("the time limit did not stop the statement");
        assert_eq!(error, SqliteSourceError::Timeout);
    }

    /// Waiting for Tokio to assign a blocking worker belongs to the same source
    /// deadline as permit admission and SQLite execution. The task remains
    /// responsible for returning its connection and permit after the async
    /// caller times out, even when it had not started running yet.
    #[test]
    fn blocking_worker_queue_time_is_bounded_and_the_pool_recovers() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = extract(&directory);
        let source = open(
            &Plan::default().timeout(100),
            "SELECT id FROM person ORDER BY id LIMIT 1",
            &path,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .max_blocking_threads(1)
            .build()
            .expect("a single-blocking-worker runtime");

        runtime.block_on(async {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
            });
            started_rx.await.expect("the blocking worker started");

            // Spend part of the source window in admission, then leave the
            // execution queued behind the occupied blocking worker. A reset
            // after admission would let this call run until the test's much
            // larger safety ceiling instead of enforcing its own 25 ms limit.
            let held = source
                .statement
                .hold_all_permits_for_test()
                .await
                .expect("the test holds every source permit");
            let release_admission = async move {
                tokio::time::sleep(Duration::from_millis(75)).await;
                drop(held);
            };
            let parameters = BTreeMap::new();
            // The 150 ms safety ceiling is longer than the source's one 100 ms
            // deadline but shorter than a fresh 100 ms worker-queue window
            // started after the 75 ms admission wait.
            let source_call = tokio::time::timeout(
                Duration::from_millis(150),
                source.execute(&parameters, instant("2026-08-07T03:00:00Z")),
            );
            let ((), queued) = tokio::join!(release_admission, source_call);

            // Release the worker before asserting so a failing implementation
            // cannot leave the custom runtime waiting forever while it drops.
            release_tx.send(()).expect("the worker can be released");
            blocker.await.expect("the blocking worker exits");

            assert_eq!(
                queued.expect("the source enforced its own deadline"),
                Err(SqliteSourceError::Timeout),
            );

            let answered = tokio::time::timeout(
                Duration::from_millis(250),
                source.execute(&BTreeMap::new(), instant("2026-08-07T03:00:00Z")),
            )
            .await
            .expect("the recovered source answers within the test ceiling")
            .expect("the timed-out queued task returned its connection and permit");
            assert_eq!(answered["rows"], json!([{"id": "p-1"}]));
        });
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
            open_error(
                &declared,
                "SELECT id FROM person WHERE id = :record OR id = ?1",
                &path,
            ),
            cause::UNDECLARED_PARAMETER,
            "a numbered alias of a named parameter was accepted"
        );
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
        let Err(error) =
            SqliteExtractSource::open(&Plan::default().build(), "SELECT id FROM person", &path)
        else {
            panic!("the extract without metadata was accepted");
        };
        let fault = error
            .artifact_fault()
            .expect("the startup failure names the governed extract profile");
        assert_eq!(fault.artifact(), "residence-register");
        assert_eq!(fault.fault().cause(), cause::NO_METADATA_TABLE);
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
    fn maximum_metadata_fields_survive_structural_response_accounting() {
        let directory = TempDir::new().expect("a temporary directory");
        let path = directory.path().join("extract.sqlite");
        let connection = Connection::open(&path).expect("the extract opens for writing");
        connection
            .execute_batch(&format!(
                "CREATE TABLE {EXTRACT_METADATA_TABLE} \
                 (published_at TEXT, publisher TEXT, extract_id TEXT); \
                 {EXTRACT_SCHEMA}"
            ))
            .expect("the extract schema is valid");
        let escaped = "\u{0001}".repeat(MAXIMUM_METADATA_FIELD_BYTES);
        connection
            .execute(
                &format!("INSERT INTO {EXTRACT_METADATA_TABLE} VALUES (?1, ?2, ?3)"),
                rusqlite::params!["2026-08-07T02:00:00Z", &escaped, &escaped],
            )
            .expect("maximum-size metadata inserts");
        drop(connection);
        let mut permissions = std::fs::metadata(&path)
            .expect("the extract fixture has metadata")
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).expect("the extract becomes immutable");

        let source = open(&Plan::default(), "SELECT id FROM person", &path);

        assert_eq!(
            source.extract_metadata().publisher().len(),
            MAXIMUM_METADATA_FIELD_BYTES
        );
        assert_eq!(
            source.extract_metadata().extract_id().len(),
            MAXIMUM_METADATA_FIELD_BYTES
        );
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
            extract_age_within_bound(
                &metadata,
                instant("2026-08-07T03:00:00Z"),
                3_600,
                "residence-register",
            ),
            Ok(())
        );
        let refused = extract_age_within_bound(
            &metadata,
            instant("2026-08-07T03:00:01Z"),
            3_600,
            "residence-register",
        )
        .expect_err("a stale extract was accepted");
        assert_eq!(refused.cause(), Some(cause::EXTRACT_TOO_OLD));
        assert_eq!(
            refused
                .artifact_fault()
                .expect("the stale fault names the governed binding")
                .artifact(),
            "residence-register"
        );
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
