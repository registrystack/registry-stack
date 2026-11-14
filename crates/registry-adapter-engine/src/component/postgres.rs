// SPDX-License-Identifier: Apache-2.0

//! The read-only `postgres` source of the governed-ingestion mode
//! (`products/adapter/CONCEPT.md` sections 8.10 and 17.2), the bounded
//! port of camel-sql's parameterized read
//! (camel-4.23.0:components/camel-sql/src/main/java/org/apache/camel/component/sql/SqlConsumer.java,
//! whose parameter binding and bounded consumption this keeps, and
//! whose `onConsume` progress updates are not ported because they write
//! the source; progress tracking is the item table's original work).
//!
//! The endpoint's digest-pinned query file is parsed at compile
//! (`pg_query`), and exactly one top-level plain `SELECT` with a root
//! `ORDER BY` is served: no data-modifying statement, no data-modifying
//! CTE, no utility command, and no unordered result for offset pages
//! to skip and repeat rows of. Its distinct `$n` parameter references are the send's
//! parameter names: a `to: postgres:<id>` send carries
//! `queryParameters` whose name set is exactly the query's, each
//! engine-evaluated to one scalar and bound typed. Execution opens
//! `BEGIN TRANSACTION READ ONLY`, sets `statement_timeout` to the
//! endpoint's declared attempt timeout, fetches at most the profile's
//! rows bound, and builds the item page itself: one item per row, the
//! configured `keyColumn` scalar's canonical digest as the stable key,
//! the whole row's canonical digest as its change-detecting revision, and
//! `{"offset": cursor offset + rows}` when the page was full. The engine
//! owns the paging: it appends `OFFSET $n+1` to the pinned statement and
//! binds the cursor's offset (zero on the first page) as that last
//! parameter, so a root `LIMIT` or `OFFSET` of the pack's own refuses at
//! compile. The read
//! is read-committed per send; the pack's scan declaration records what
//! that means for the source (PostgreSQL isolation documentation,
//! "Read Committed isolation level": each statement sees a snapshot as
//! of its own start, so one send's page is internally consistent while
//! pages of one scan may straddle commits).
//!
//! The engine carries no client: the boundary (E3) links no PostgreSQL
//! client types. This module compiles the statement, owns the
//! transaction preamble and the statement bound, evaluates and types
//! the parameters, shapes the rows into the item contract, and defines
//! the [`PostgresSource`] seam the host implements
//! (`registry-adapter-job`, over its own pool) and the test fixtures
//! impersonate. Cancel safety: the send's future is dropped with the
//! route's deadline, which ends the read; `statement_timeout` bounds
//! the server's work beside it. No `onConsume`, no cursor updates on
//! the source.

use std::collections::BTreeSet;
use std::io;
use std::time::Duration;

use registry_adapter_core::{ErrorClass, MAXIMUM_POSTGRES_QUERY_PARAMETERS};
use serde::ser::SerializeMap as _;
use serde_json::Value;

use crate::route::RouteFailure;

// The refusal in compile_query names the bound in its text.
const _: () = assert!(MAXIMUM_POSTGRES_QUERY_PARAMETERS == 16);

/// The engine-side plan of one postgres source: its parsed query, the
/// namespace its item keys carry, and its declared attempt bound. The
/// client lives behind the [`PostgresSource`] seam the host supplies.
#[derive(Clone)]
pub struct PostgresPlan {
    pub query: PinnedQuery,
    pub namespace: String,
    pub key_column: String,
    pub attempt: Duration,
}

impl std::fmt::Debug for PostgresPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresPlan")
            .finish_non_exhaustive()
    }
}

/// Compile the engine side of one postgres source: parse the pinned
/// query and hold the plan. The credential, the pool, and the
/// connection are the host's, built from the runtime config's
/// `sources.postgres` block beside this same plan.
pub fn compile_plan(
    namespace: String,
    key_column: String,
    parameter_order: Vec<String>,
    query_text: &str,
    attempt: Duration,
) -> Result<PostgresPlan, QueryRefused> {
    let query = compile_query(query_text, &parameter_order)?;
    Ok(PostgresPlan {
        query,
        namespace,
        key_column,
        attempt,
    })
}

/// One pinned, parsed, and refused-or-admitted query: its text, the
/// paged statement the engine runs, and the parameter names its `$n`
/// references declare, in name order.
#[derive(Debug, Clone)]
pub struct PinnedQuery {
    pub text: String,
    /// The pinned statement followed by `OFFSET $n+1`, where `$n+1` is
    /// the engine-bound page offset after the reviewed parameters.
    pub paged_text: String,
    pub parameter_names: Vec<String>,
}

/// Why a query file was refused at compile. SQL shape failures use
/// `adapter.job.postgres-query-refused`; a missing or mismatched ordered
/// name declaration uses `adapter.job.postgres-parameters-required`.
/// Every message is fixed and value-free.
#[derive(Debug)]
pub enum QueryRefused {
    Query(&'static str),
    Parameters(&'static str),
}

impl QueryRefused {
    pub const fn message(&self) -> &'static str {
        match self {
            Self::Query(message) | Self::Parameters(message) => message,
        }
    }
}

/// Parse one query text and refuse everything but exactly one top-level
/// plain SELECT: no other statement kind, no data-modifying CTE, no
/// utility command, a root `ORDER BY` so offset pages are stable, no
/// root `LIMIT` or `OFFSET` (the engine pages), and a parameter set of
/// `$1` through `$n` with no gap.
pub fn compile_query(text: &str, parameter_order: &[String]) -> Result<PinnedQuery, QueryRefused> {
    let parsed = pg_query::parse(text)
        .map_err(|_| QueryRefused::Query("the query file is not valid SQL"))?;
    // The statement root decides, not a count of SELECT nodes: a
    // utility command (CREATE ... AS SELECT, EXPLAIN) wraps a SELECT
    // node without being one, and nested SELECTs are ordinary
    // subqueries and CTEs of the one root statement.
    let [raw] = parsed.protobuf.stmts.as_slice() else {
        return Err(QueryRefused::Query(
            "the query file must carry exactly one statement",
        ));
    };
    let root = raw
        .stmt
        .as_ref()
        .and_then(|statement| statement.node.as_ref());
    let Some(pg_query::protobuf::node::Node::SelectStmt(select)) = root else {
        return Err(QueryRefused::Query(
            "the query file must carry exactly one SELECT statement",
        ));
    };
    let mut parameter_names: Vec<Option<String>> = Vec::new();
    for (node, _, _, _) in parsed.protobuf.nodes() {
        match node {
            pg_query::NodeRef::SelectStmt(_) => {}
            pg_query::NodeRef::InsertStmt(_)
            | pg_query::NodeRef::UpdateStmt(_)
            | pg_query::NodeRef::DeleteStmt(_)
            | pg_query::NodeRef::MergeStmt(_)
            | pg_query::NodeRef::CopyStmt(_)
            | pg_query::NodeRef::TransactionStmt(_)
            | pg_query::NodeRef::DoStmt(_)
            | pg_query::NodeRef::LockStmt(_)
            | pg_query::NodeRef::NotifyStmt(_)
            | pg_query::NodeRef::ListenStmt(_)
            | pg_query::NodeRef::UnlistenStmt(_)
            | pg_query::NodeRef::CheckPointStmt(_)
            | pg_query::NodeRef::VacuumStmt(_)
            | pg_query::NodeRef::ReindexStmt(_)
            | pg_query::NodeRef::ClusterStmt(_) => {
                return Err(QueryRefused::Query(
                    "the query file carries a statement or command that is not a plain SELECT",
                ));
            }
            pg_query::NodeRef::ParamRef(parameter) => {
                let index = usize::try_from(parameter.number).map_err(|_| {
                    QueryRefused::Query(
                        "the query carries a negative parameter reference; write $1 and up",
                    )
                })?;
                if index == 0 {
                    return Err(QueryRefused::Query(
                        "the query carries a zero parameter reference; write $1 and up",
                    ));
                }
                // Bound the index before it sizes the name list, so one
                // huge reference refuses instead of allocating.
                if index > MAXIMUM_POSTGRES_QUERY_PARAMETERS {
                    return Err(QueryRefused::Query(
                        "the query carries more than 16 parameter positions",
                    ));
                }
                if parameter_names.len() < index {
                    parameter_names.resize(index, None);
                }
                parameter_names[index - 1] = Some(format!("${index}"));
            }
            _ => {}
        }
    }
    // Pages advance by offset, and PostgreSQL returns an unordered
    // result in any order it likes, so pages of an unordered query skip
    // and repeat rows. The root SELECT must order its result; an ordered
    // subquery does not order the root. Whether the order is total (a
    // unique key last) is the pack author's to declare.
    if select.sort_clause.is_empty() {
        return Err(QueryRefused::Query(
            "the query must declare ORDER BY; offset paging needs a stable row order",
        ));
    }
    // The engine appends the page offset itself. A root LIMIT would end
    // the scan silently after its rows, and a root OFFSET would collide
    // with the engine's.
    if select.limit_count.is_some() || select.limit_offset.is_some() {
        return Err(QueryRefused::Query(
            "the query must not declare a root LIMIT, OFFSET or FETCH; the engine pages it by OFFSET",
        ));
    }
    if parameter_names.iter().any(Option::is_none) {
        return Err(QueryRefused::Query(
            "the query's parameter references leave a gap; use $1 through $n with none missing",
        ));
    }
    if parameter_names.len() != parameter_order.len() {
        return Err(QueryRefused::Parameters(
            "parameterOrder must name every contiguous SQL parameter position exactly once",
        ));
    }
    let paged_text = paged_statement(text, raw, parameter_order.len() + 1)?;
    Ok(PinnedQuery {
        text: text.to_owned(),
        paged_text,
        parameter_names: parameter_order.to_vec(),
    })
}

/// The one statement of `text` followed by `OFFSET $offset_position`.
/// The statement ends where the parser says it does, so a trailing
/// semicolon is left out, and the offset starts on its own line, so a
/// trailing line comment cannot swallow it. The result is parsed again
/// and must carry exactly that root offset.
fn paged_statement(
    text: &str,
    raw: &pg_query::protobuf::RawStmt,
    offset_position: usize,
) -> Result<String, QueryRefused> {
    let refused = || QueryRefused::Query("the query cannot take the engine's page OFFSET");
    let start = usize::try_from(raw.stmt_location).map_err(|_| refused())?;
    let end = match usize::try_from(raw.stmt_len).map_err(|_| refused())? {
        0 => text.len(),
        length => start.checked_add(length).ok_or_else(refused)?,
    };
    let statement = text.get(start..end).ok_or_else(refused)?.trim_end();
    let paged = format!("{statement}\nOFFSET ${offset_position}");
    let parsed = pg_query::parse(&paged).map_err(|_| refused())?;
    let [raw] = parsed.protobuf.stmts.as_slice() else {
        return Err(refused());
    };
    let Some(pg_query::protobuf::node::Node::SelectStmt(select)) = raw
        .stmt
        .as_ref()
        .and_then(|statement| statement.node.as_ref())
    else {
        return Err(refused());
    };
    let offset = select
        .limit_offset
        .as_ref()
        .and_then(|node| node.node.as_ref());
    match offset {
        Some(pg_query::protobuf::node::Node::ParamRef(parameter))
            if usize::try_from(parameter.number).ok() == Some(offset_position)
                && select.limit_count.is_none() =>
        {
            Ok(paged)
        }
        _ => Err(refused()),
    }
}

/// The send's named parameters must be exactly the query's own set:
/// the same names, none missing, none extra.
pub(crate) fn parameters_match(
    query: &PinnedQuery,
    carried: &std::collections::BTreeMap<
        registry_platform_yaml::ExternalId,
        registry_adapter_core::Expression,
    >,
) -> Result<(), RouteFailure> {
    let carried: std::collections::BTreeSet<&str> =
        carried.keys().map(|name| name.as_str()).collect();
    let declared: std::collections::BTreeSet<&str> =
        query.parameter_names.iter().map(String::as_str).collect();
    if carried == declared {
        return Ok(());
    }
    Err(failure(
        ErrorClass::EgressRefused,
        "the send's queryParameters are not exactly the query's own parameter names",
    ))
}

fn failure(class: ErrorClass, message: &'static str) -> RouteFailure {
    RouteFailure {
        class,
        message: Some(message.to_owned()),
        data: None,
        auth: None,
        code: None,
        record: None,
        evidence_diagnostic: None,
    }
}

/// A query parameter or a result column in the engine's closed value form.
/// The client's column types stay in the host.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceScalar {
    Text(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    /// A numeric as its text, so precision never crosses the seam
    /// through a float.
    Numeric(String),
    /// A bounded JSONB result. It is never a parameter or a key.
    Jsonb(JsonbColumn),
    /// A SQL NULL column value. It never binds as a parameter and never
    /// serves as an item key.
    Null,
}

/// A result decoded under the PostgreSQL field budget and strict JSON parser.
/// Its value stays private so callers cannot bypass the parser's nesting bound.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonbColumn(Value);

/// One row the host read, with named columns in result order.
#[derive(Debug, Clone)]
pub struct SourceRow {
    pub columns: Vec<(String, SourceScalar)>,
}

/// The byte limits one PostgreSQL source response must retain. The
/// host applies them while streaming rows, and the engine applies them
/// again to rows returned across the untrusted client seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostgresReadBounds {
    pub maximum_response_bytes: usize,
    pub maximum_row_bytes: usize,
    pub maximum_field_bytes: usize,
}

/// Incremental validation of the closed row representation. The
/// response size is the exact JSON size of an array of row objects;
/// page validation separately counts the item keys and cursor that the
/// engine adds after this source boundary.
#[derive(Debug)]
pub struct PostgresRowBudget {
    bounds: PostgresReadBounds,
    maximum_rows: usize,
    rows: usize,
    response_bytes: usize,
}

impl PostgresRowBudget {
    /// Start one response budget. Even an empty response is the JSON
    /// array `[]`, so a smaller response ceiling refuses immediately.
    pub fn new(maximum_rows: u32, bounds: PostgresReadBounds) -> Result<Self, PostgresReadFault> {
        if bounds.maximum_response_bytes < 2 {
            return Err(PostgresReadFault::TooLarge);
        }
        Ok(Self {
            bounds,
            maximum_rows: maximum_rows as usize,
            rows: 0,
            response_bytes: 2,
        })
    }

    /// Check a borrowed column name or string value before the host
    /// gives it an owned allocation.
    pub fn check_field(&self, value: &str) -> Result<(), PostgresReadFault> {
        self.check_field_bytes(value.len())
    }

    fn check_field_bytes(&self, bytes: usize) -> Result<(), PostgresReadFault> {
        if bytes > self.bounds.maximum_field_bytes {
            Err(PostgresReadFault::TooLarge)
        } else {
            Ok(())
        }
    }

    /// Decode the JSON portion of a native JSONB result. Check the borrowed
    /// bytes before parsing allocates, then admit the encoded value separately.
    pub fn decode_jsonb(&self, bytes: &[u8]) -> Result<SourceScalar, PostgresReadFault> {
        self.check_field_bytes(bytes.len())?;
        let value = registry_platform_canonical_json::parse_json_strict(bytes)
            .map_err(|_| PostgresReadFault::Malformed)?;
        Ok(SourceScalar::Jsonb(JsonbColumn(value)))
    }

    /// Admit one row before a host retains it. Duplicate column names
    /// refuse rather than being silently overwritten while the engine
    /// shapes the row object.
    pub fn admit(&mut self, row: &SourceRow) -> Result<(), PostgresReadFault> {
        if self.rows >= self.maximum_rows {
            return Err(PostgresReadFault::TooLarge);
        }
        let mut names = BTreeSet::new();
        for (name, value) in &row.columns {
            self.check_field(name)?;
            if !names.insert(name.as_str()) {
                return Err(PostgresReadFault::Statement);
            }
            match value {
                SourceScalar::Text(value) | SourceScalar::Numeric(value) => {
                    self.check_field(value)?;
                }
                SourceScalar::Jsonb(value) => {
                    bounded_json_bytes(&value.0, self.bounds.maximum_field_bytes)?;
                }
                SourceScalar::Float(value) if !value.is_finite() => {
                    return Err(PostgresReadFault::Malformed);
                }
                SourceScalar::Integer(_)
                | SourceScalar::Float(_)
                | SourceScalar::Boolean(_)
                | SourceScalar::Null => {}
            }
        }
        let row_bytes = bounded_json_bytes(&SerializableRow(row), self.bounds.maximum_row_bytes)?;
        let separator = usize::from(self.rows != 0);
        let response_bytes = self
            .response_bytes
            .checked_add(separator)
            .and_then(|bytes| bytes.checked_add(row_bytes))
            .ok_or(PostgresReadFault::TooLarge)?;
        if response_bytes > self.bounds.maximum_response_bytes {
            return Err(PostgresReadFault::TooLarge);
        }
        self.rows += 1;
        self.response_bytes = response_bytes;
        Ok(())
    }
}

struct SerializableRow<'a>(&'a SourceRow);

impl serde::Serialize for SerializableRow<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.columns.len()))?;
        for (name, value) in &self.0.columns {
            match value {
                SourceScalar::Text(value) | SourceScalar::Numeric(value) => {
                    map.serialize_entry(name, value)?;
                }
                SourceScalar::Integer(value) => map.serialize_entry(name, value)?,
                SourceScalar::Float(value) => map.serialize_entry(name, value)?,
                SourceScalar::Boolean(value) => map.serialize_entry(name, value)?,
                SourceScalar::Jsonb(value) => map.serialize_entry(name, &value.0)?,
                SourceScalar::Null => map.serialize_entry(name, &())?,
            }
        }
        map.end()
    }
}

fn bounded_json_bytes(
    value: &impl serde::Serialize,
    maximum: usize,
) -> Result<usize, PostgresReadFault> {
    let mut writer = BoundedCountingWriter {
        maximum,
        written: 0,
        exceeded: false,
    };
    if serde_json::to_writer(&mut writer, value).is_err() {
        return Err(if writer.exceeded {
            PostgresReadFault::TooLarge
        } else {
            PostgresReadFault::Statement
        });
    }
    Ok(writer.written)
}

struct BoundedCountingWriter {
    maximum: usize,
    written: usize,
    exceeded: bool,
}

impl io::Write for BoundedCountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(written) = self
            .written
            .checked_add(bytes.len())
            .filter(|written| *written <= self.maximum)
        else {
            self.exceeded = true;
            return Err(io::Error::other("postgres JSON byte bound exceeded"));
        };
        self.written = written;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One read the host executes: the engine-compiled statements, the
/// typed parameters, and the fetch bound. The preamble is engine-owned
/// data, so the read-only invariant and the statement bound never
/// depend on the client.
#[derive(Debug, Clone)]
pub struct PostgresRead {
    /// The statements to run, in order, before the query: the read-only
    /// transaction opener and the statement bound.
    pub statements: Vec<String>,
    /// The compiled SELECT.
    pub sql: String,
    /// The parameters, in the query's own `$1`-onward order.
    pub parameters: Vec<SourceScalar>,
    /// The most rows to return; `PostgresRows::complete` says whether
    /// more stood beyond them.
    pub maximum_rows: u32,
    /// The field, row, and aggregate response limits the host applies
    /// before retaining source values.
    pub bounds: PostgresReadBounds,
}

/// The rows one read returned.
#[derive(Debug)]
pub struct PostgresRows {
    pub rows: Vec<SourceRow>,
    /// Whether the fetch returned every row the query produces: true
    /// when no row stood beyond the bound, false when the fetch
    /// stopped at the bound with rows standing beyond it, which gives
    /// the page a `next` cursor.
    pub complete: bool,
}

/// Why a host read failed. The engine maps each kind to the closed
/// class the route hierarchy carries; the client's own error types
/// never cross the seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostgresReadFault {
    /// The statement outlived its bound and the source canceled it.
    Timeout,
    /// The connection or the pool failed before any statement ran.
    Connection,
    /// The source refused the transaction, the bound, or the statement.
    Statement,
    /// The source returned a value outside the closed result form.
    Malformed,
    /// A field, row, row count, or aggregate response exceeded its
    /// authored source bound.
    TooLarge,
    /// The one-based result column has a type outside the closed
    /// result form. A column's type is the same on every row, so the
    /// first row of the page is the one that refuses.
    UnsupportedColumn { column: u32 },
}

/// The source client seam the host supplies
/// (`registry-adapter-job`, over its own pool) and the test fixtures
/// impersonate. The engine compiles; the host connects.
pub trait PostgresSource: std::fmt::Debug + Send + Sync {
    /// Execute one read: the preamble statements in order, then the
    /// query with its parameters, inside one read-only transaction the
    /// host both opens and closes.
    fn read<'a>(
        &'a self,
        read: PostgresRead,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<PostgresRows, PostgresReadFault>> + Send + 'a>,
    >;
}

/// One send: evaluate and type the parameters, hand the compiled read
/// to the host's client, and shape the rows into the item page. The
/// exchange body becomes the page, and the route may shape it further.
pub(crate) async fn send(
    run: &mut crate::route::Run<'_, '_>,
    plan: &PostgresPlan,
    source: &dyn PostgresSource,
    to: &registry_adapter_core::ToStep,
) -> Result<crate::route::Flow, RouteFailure> {
    let parameters = to.parameters.as_ref().ok_or_else(|| {
        failure(
            ErrorClass::EgressRefused,
            "a postgres send declares no parameters",
        )
    })?;
    parameters_match(&plan.query, &parameters.query_parameters)?;
    let mut values: Vec<SourceScalar> = Vec::with_capacity(plan.query.parameter_names.len());
    for name in &plan.query.parameter_names {
        let wire_name = registry_platform_yaml::ExternalId::new(name.as_str()).map_err(|_| {
            failure(
                ErrorClass::EgressRefused,
                "the query's parameter name is not a wire name",
            )
        })?;
        let expression = parameters.query_parameters.get(&wire_name).ok_or_else(|| {
            failure(
                ErrorClass::EgressRefused,
                "the send carries a parameter the query does not declare",
            )
        })?;
        values.push(scalar(run.eval(expression)?)?);
    }
    // The cursor's own offset, zero on the first page, binds as the
    // engine's trailing OFFSET parameter and advances by the rows each
    // page fetched.
    let offset = run
        .exchange
        .property(crate::job::ADAPTER_JOB_CURSOR_PROPERTY)
        .and_then(|cursor| cursor.get("offset"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    values.push(SourceScalar::Integer(i64::try_from(offset).map_err(
        |_| {
            failure(
                ErrorClass::Validation,
                "the cursor offset exceeds the PostgreSQL bigint range",
            )
        },
    )?));
    // The authoring checks require `profile.read` for a route that reaches
    // a PostgreSQL send, so a profile without it only occurs outside a job
    // and takes the platform ceilings like a run with no profile.
    let declared = run
        .context
        .job
        .profile
        .as_ref()
        .and_then(|profile| profile.read.as_ref().map(|read| (profile, read)));
    let (maximum_rows, bounds) = match declared {
        Some((profile, read)) => (
            read.maximum_rows_per_page.get(),
            PostgresReadBounds {
                maximum_response_bytes: profile.maximum_response_bytes.get() as usize,
                maximum_row_bytes: read.maximum_row_bytes.get() as usize,
                maximum_field_bytes: read.maximum_field_bytes.get() as usize,
            },
        ),
        None => (
            registry_adapter_core::MAXIMUM_JOB_ROWS_PER_PAGE,
            PostgresReadBounds {
                maximum_response_bytes: registry_adapter_core::MAXIMUM_JOB_RESPONSE_BYTES as usize,
                maximum_row_bytes: registry_adapter_core::MAXIMUM_JOB_ROW_BYTES as usize,
                maximum_field_bytes: registry_adapter_core::MAXIMUM_JOB_FIELD_BYTES as usize,
            },
        ),
    };
    // The timeout is the endpoint's own declared, bounded attempt
    // timeout, never a value from the page or the pack.
    let bound = plan.attempt.as_millis();
    let read = PostgresRead {
        statements: vec![
            "BEGIN TRANSACTION READ ONLY".to_owned(),
            format!("SET LOCAL statement_timeout = {bound}"),
        ],
        sql: plan.query.paged_text.clone(),
        parameters: values,
        maximum_rows,
        bounds,
    };
    run.ensure_deadline()?;
    let fetch = async {
        let rows = source
            .read(read)
            .await
            .map_err(|fault| read_failure(fault, offset))?;
        validate_source_rows(maximum_rows, bounds, &rows)
            .map_err(|fault| read_failure(fault, offset))?;
        let mut items = Vec::with_capacity(rows.rows.len());
        for (ordinal, row) in (offset..).zip(&rows.rows) {
            items.push(row_item(&plan.namespace, &plan.key_column, row, ordinal)?);
        }
        Ok::<_, RouteFailure>((items, rows))
    };
    let (items, rows) = tokio::time::timeout_at(run.deadline, fetch)
        .await
        .map_err(|_| {
            failure(
                ErrorClass::UpstreamTimeout,
                "the postgres send outlived its deadline",
            )
        })??;
    let mut body = serde_json::json!({ "items": items });
    if !rows.complete {
        body["next"] = serde_json::json!({ "offset": offset + rows.rows.len() as u64 });
    }
    run.exchange.message.body = body;
    Ok(crate::route::Flow::Continue)
}

fn validate_source_rows(
    maximum_rows: u32,
    bounds: PostgresReadBounds,
    rows: &PostgresRows,
) -> Result<(), PostgresReadFault> {
    let mut budget = PostgresRowBudget::new(maximum_rows, bounds)?;
    for row in &rows.rows {
        budget.admit(row)?;
    }
    Ok(())
}

/// The closed code of an unsupported PostgreSQL result column type.
pub const POSTGRES_COLUMN_TYPE_CODE: &str = "adapter.job.postgres-column-type";
/// The closed code of a row whose key column is NULL.
pub const POSTGRES_KEY_NULL_CODE: &str = "adapter.job.postgres-key-null";
/// The closed code of a JSONB column configured as a scalar item key.
pub const POSTGRES_KEY_TYPE_CODE: &str = "adapter.job.postgres-key-type";

/// `offset` is the page's first row ordinal, so a column fault, which the
/// page's first row raises, is located at it.
fn read_failure(fault: PostgresReadFault, offset: u64) -> RouteFailure {
    match fault {
        PostgresReadFault::Timeout => failure(
            ErrorClass::UpstreamTimeout,
            "the source canceled the statement at its bound",
        ),
        PostgresReadFault::Connection => failure(
            ErrorClass::UpstreamConnection,
            "the source pool gave no connection",
        ),
        PostgresReadFault::Statement => {
            failure(ErrorClass::Upstream, "the source refused the statement")
        }
        PostgresReadFault::Malformed => failure(
            ErrorClass::UpstreamMalformed,
            "the source returned a value outside the closed result form",
        ),
        PostgresReadFault::TooLarge => failure(
            ErrorClass::UpstreamTooLarge,
            "the source response exceeded its authored byte bound",
        ),
        PostgresReadFault::UnsupportedColumn { column } => RouteFailure {
            message: Some(format!(
                "result column {column} has a PostgreSQL type the source cannot read; cast it in \
                 the query to text, an integer, double precision, boolean, numeric, date, \
                 timestamp, timestamptz, uuid or jsonb"
            )),
            code: Some(POSTGRES_COLUMN_TYPE_CODE),
            record: Some(Box::new(registry_adapter_core::RecordLocator {
                ordinal: offset,
                column: Some(column),
            })),
            ..failure(ErrorClass::UpstreamMalformed, "")
        },
    }
}

/// The closed scalar form of one engine-evaluated parameter value. A
/// null or a non-scalar value refuses: a page row is what the query
/// returns, never what the route hoped to send.
fn scalar(value: Value) -> Result<SourceScalar, RouteFailure> {
    match value {
        Value::String(text) => Ok(SourceScalar::Text(text)),
        Value::Number(number) => number
            .as_i64()
            .map(SourceScalar::Integer)
            .or_else(|| number.as_f64().map(SourceScalar::Float))
            .ok_or_else(|| {
                failure(
                    ErrorClass::Validation,
                    "a query parameter number has no postgres form",
                )
            }),
        Value::Bool(flag) => Ok(SourceScalar::Boolean(flag)),
        Value::Null => Err(failure(
            ErrorClass::Validation,
            "a query parameter carried null; write a scalar the source can bind",
        )),
        Value::Array(_) | Value::Object(_) => Err(failure(
            ErrorClass::Validation,
            "a query parameter is not a scalar; write a string, number, or boolean",
        )),
    }
}

/// One row as a source item: a map keyed by the column names, the
/// configured scalar column's digest as stable identity, and the whole
/// canonical row's digest as its revision across pages and scans.
fn row_item(
    namespace: &str,
    key_column: &str,
    row: &SourceRow,
    ordinal: u64,
) -> Result<Value, RouteFailure> {
    let mut members = serde_json::Map::new();
    let mut key = None;
    for (index, (name, value)) in row.columns.iter().enumerate() {
        let is_key = name == key_column;
        if is_key && matches!(value, SourceScalar::Jsonb(_)) {
            return Err(RouteFailure {
                code: Some(POSTGRES_KEY_TYPE_CODE),
                record: Some(Box::new(registry_adapter_core::RecordLocator {
                    ordinal,
                    column: Some(u32::try_from(index + 1).unwrap_or(u32::MAX)),
                })),
                ..failure(
                    ErrorClass::UpstreamMalformed,
                    "a row's key column is JSONB; select a stable scalar key column",
                )
            });
        }
        let value = result_value(value)?;
        if is_key {
            key = Some(value.clone());
        }
        members.insert(name.clone(), value);
    }
    let key = key.ok_or_else(|| {
        failure(
            ErrorClass::UpstreamMalformed,
            "a row carries no value for the endpoint's key column",
        )
    })?;
    if key.is_null() {
        return Err(RouteFailure {
            code: Some(POSTGRES_KEY_NULL_CODE),
            record: Some(Box::new(registry_adapter_core::RecordLocator {
                ordinal,
                column: None,
            })),
            ..failure(
                ErrorClass::UpstreamMalformed,
                "a row's key column is NULL; select a key column that is never NULL",
            )
        });
    }
    let canonical_key =
        registry_platform_canonical_json::canonicalize_json(&key).map_err(|_| {
            failure(
                ErrorClass::UpstreamMalformed,
                "a row key has no canonical JSON form",
            )
        })?;
    let row_json = Value::Object(members);
    let canonical =
        registry_platform_canonical_json::canonicalize_json(&row_json).map_err(|_| {
            failure(
                ErrorClass::UpstreamMalformed,
                "a row has no canonical JSON form",
            )
        })?;
    Ok(serde_json::json!({
        "key": format!("{namespace}:{}", registry_platform_config::sha256_uri(&canonical_key)),
        "revision": registry_platform_config::sha256_uri(&canonical),
        "value": row_json,
    }))
}

fn result_value(value: &SourceScalar) -> Result<Value, RouteFailure> {
    Ok(match value {
        SourceScalar::Text(text) => Value::String(text.clone()),
        SourceScalar::Integer(value) => serde_json::json!(value),
        SourceScalar::Float(value) if value.is_finite() => serde_json::json!(value),
        SourceScalar::Float(_) => {
            return Err(failure(
                ErrorClass::UpstreamMalformed,
                "the source returned a non-finite float",
            ))
        }
        SourceScalar::Boolean(value) => serde_json::json!(value),
        SourceScalar::Numeric(text) => Value::String(text.clone()),
        SourceScalar::Jsonb(value) => value.0.clone(),
        SourceScalar::Null => Value::Null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(columns: &[(&str, &str)]) -> SourceRow {
        SourceRow {
            columns: columns
                .iter()
                .map(|(name, value)| ((*name).to_owned(), SourceScalar::Text((*value).to_owned())))
                .collect(),
        }
    }

    #[test]
    fn untrusted_host_rows_retain_field_row_and_aggregate_bounds() {
        let field_bounds = PostgresReadBounds {
            maximum_response_bytes: 128,
            maximum_row_bytes: 64,
            maximum_field_bytes: 3,
        };
        let field = PostgresRows {
            rows: vec![row(&[("id", "wide")])],
            complete: true,
        };
        assert_eq!(
            validate_source_rows(2, field_bounds, &field),
            Err(PostgresReadFault::TooLarge)
        );

        let row_bounds = PostgresReadBounds {
            maximum_response_bytes: 128,
            maximum_row_bytes: 12,
            maximum_field_bytes: 8,
        };
        let wide_row = PostgresRows {
            rows: vec![row(&[("id", "one"), ("state", "two")])],
            complete: true,
        };
        assert_eq!(
            validate_source_rows(2, row_bounds, &wide_row),
            Err(PostgresReadFault::TooLarge)
        );

        let aggregate_bounds = PostgresReadBounds {
            maximum_response_bytes: 25,
            maximum_row_bytes: 24,
            maximum_field_bytes: 8,
        };
        let aggregate = PostgresRows {
            rows: vec![row(&[("id", "one")]), row(&[("id", "two")])],
            complete: true,
        };
        assert_eq!(
            validate_source_rows(2, aggregate_bounds, &aggregate),
            Err(PostgresReadFault::TooLarge)
        );
    }

    #[test]
    fn jsonb_result_must_fit_the_engine_budget_and_cannot_be_a_key() {
        let host = PostgresRowBudget::new(
            1,
            PostgresReadBounds {
                maximum_response_bytes: 256,
                maximum_row_bytes: 128,
                maximum_field_bytes: 64,
            },
        )
        .expect("host budget");
        let value = host
            .decode_jsonb(br#"{"label":"wide contact label"}"#)
            .expect("host can read this result");
        let row = SourceRow {
            columns: vec![("id".to_owned(), value)],
        };
        let error = row_item("sites", "id", &row, 0).expect_err("a JSONB key is refused");
        assert_eq!(error.code, Some(POSTGRES_KEY_TYPE_CODE));
        let bounds = PostgresReadBounds {
            maximum_response_bytes: 256,
            maximum_row_bytes: 128,
            maximum_field_bytes: 16,
        };
        assert_eq!(
            validate_source_rows(
                1,
                bounds,
                &PostgresRows {
                    rows: vec![row],
                    complete: true
                }
            ),
            Err(PostgresReadFault::TooLarge)
        );
    }

    #[test]
    fn untrusted_host_rows_refuse_duplicate_columns_and_excess_count() {
        let bounds = PostgresReadBounds {
            maximum_response_bytes: 128,
            maximum_row_bytes: 64,
            maximum_field_bytes: 16,
        };
        let duplicate = PostgresRows {
            rows: vec![row(&[("id", "one"), ("id", "two")])],
            complete: true,
        };
        assert_eq!(
            validate_source_rows(2, bounds, &duplicate),
            Err(PostgresReadFault::Statement)
        );

        let excess = PostgresRows {
            rows: vec![row(&[("id", "one")]), row(&[("id", "two")])],
            complete: true,
        };
        assert_eq!(
            validate_source_rows(1, bounds, &excess),
            Err(PostgresReadFault::TooLarge)
        );
    }

    #[test]
    fn untrusted_host_rows_refuse_non_finite_float_keys_and_values() {
        let bounds = PostgresReadBounds {
            maximum_response_bytes: 512,
            maximum_row_bytes: 256,
            maximum_field_bytes: 128,
        };
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            for columns in [
                vec![
                    ("id".to_owned(), SourceScalar::Float(value)),
                    ("status".to_owned(), SourceScalar::Text("new".to_owned())),
                ],
                vec![
                    ("id".to_owned(), SourceScalar::Text("001".to_owned())),
                    ("score".to_owned(), SourceScalar::Float(value)),
                ],
            ] {
                let rows = PostgresRows {
                    rows: vec![SourceRow { columns }],
                    complete: true,
                };
                assert_eq!(
                    validate_source_rows(1, bounds, &rows),
                    Err(PostgresReadFault::Malformed),
                    "a non-finite float from an untrusted host refuses as malformed before identity hashing"
                );
            }
        }
    }

    #[test]
    fn reviewed_parameter_order_names_contiguous_sql_positions() {
        let names = vec![
            "status".to_owned(),
            "minimumOrdinal".to_owned(),
            "enabled".to_owned(),
        ];
        let query = compile_query(
            "SELECT id FROM submissions WHERE status = $1::text AND ordinal >= $2::integer AND $3::boolean ORDER BY id",
            &names,
        )
        .expect("the ordered declaration names all positions");
        assert_eq!(query.parameter_names, names);
        assert!(matches!(
            compile_query(
                "SELECT id FROM submissions WHERE status = $1::text ORDER BY id",
                &[],
            ),
            Err(QueryRefused::Parameters(_))
        ));
        assert!(matches!(
            compile_query(
                "SELECT id FROM submissions ORDER BY id",
                &["unused".to_owned()],
            ),
            Err(QueryRefused::Parameters(_))
        ));
        assert!(compile_query("SELECT id FROM submissions ORDER BY id", &[]).is_ok());
    }

    #[test]
    fn the_engine_appends_its_page_offset_after_the_reviewed_parameters() {
        let names = vec!["status".to_owned()];
        let query = compile_query(
            "SELECT id FROM submissions WHERE status = $1 ORDER BY id;",
            &names,
        )
        .expect("an ordered query with a trailing semicolon compiles");
        assert_eq!(
            query.paged_text,
            "SELECT id FROM submissions WHERE status = $1 ORDER BY id\nOFFSET $2"
        );
        let commented = compile_query("SELECT id FROM submissions ORDER BY id -- by id", &[])
            .expect("a trailing line comment compiles");
        assert_eq!(
            commented.paged_text, "SELECT id FROM submissions ORDER BY id -- by id\nOFFSET $1",
            "the offset starts on its own line, past the comment"
        );
        for sql in [
            "SELECT id FROM submissions ORDER BY id LIMIT 500",
            "SELECT id FROM submissions ORDER BY id OFFSET 10",
            "SELECT id FROM submissions ORDER BY id FETCH FIRST 5 ROWS ONLY",
        ] {
            let refused = compile_query(sql, &[]).expect_err(sql);
            assert!(
                refused.message().contains("the engine pages it by OFFSET"),
                "{sql}: {refused:?}"
            );
        }
    }

    #[test]
    fn configured_key_scalar_is_stable_while_row_revision_changes() {
        let first = row(&[("id", "001"), ("status", "new")]);
        let edited = row(&[("id", "001"), ("status", "revised")]);
        let first = row_item("ledger", "id", &first, 0).expect("the first row shapes");
        let edited = row_item("ledger", "id", &edited, 0).expect("the edited row shapes");
        assert_eq!(first["key"], edited["key"]);
        assert_ne!(first["revision"], edited["revision"]);

        let missing = row(&[("external_id", "001")]);
        assert_eq!(
            row_item("ledger", "id", &missing, 0)
                .expect_err("a missing configured key refuses")
                .class,
            ErrorClass::UpstreamMalformed
        );
    }
}
