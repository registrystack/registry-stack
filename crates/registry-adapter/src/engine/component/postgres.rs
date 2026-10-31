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
//! (`pg_query`), and exactly one top-level plain `SELECT` is served: no
//! data-modifying statement, no data-modifying CTE, no utility
//! command. Its distinct `$n` parameter references are the send's
//! parameter names: a `to: postgres:<id>` send carries
//! `queryParameters` whose name set is exactly the query's, each
//! engine-evaluated to one scalar and bound typed. Execution opens
//! `BEGIN TRANSACTION READ ONLY`, sets `statement_timeout` to the
//! endpoint's declared attempt timeout, fetches at most the profile's
//! rows bound, and builds the item page itself: one item per row, the
//! row's canonical JSON digest as the stable key, and
//! `{"offset": cursor offset + rows}` when the page was full. The read
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

use std::time::Duration;

use registry_adapter_core::ErrorClass;
use serde_json::Value;

use crate::engine::route::RouteFailure;

/// The engine-side plan of one postgres source: its parsed query, the
/// namespace its item keys carry, and its declared attempt bound. The
/// client lives behind the [`PostgresSource`] seam the host supplies.
#[derive(Clone)]
pub struct PostgresPlan {
    pub query: PinnedQuery,
    pub namespace: String,
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
    query_text: &str,
    attempt: Duration,
) -> Result<PostgresPlan, String> {
    let query = compile_query(query_text).map_err(|refused| refused.0.to_owned())?;
    Ok(PostgresPlan {
        query,
        namespace,
        attempt,
    })
}

/// One pinned, parsed, and refused-or-admitted query: its text and the
/// parameter names its `$n` references declare, in name order.
#[derive(Debug, Clone)]
pub struct PinnedQuery {
    pub text: String,
    pub parameter_names: Vec<String>,
}

/// Why a query file was refused at compile. The code is the landed
/// `adapter.job.postgres-query-refused`; the message is fixed and
/// value-free.
#[derive(Debug)]
pub struct QueryRefused(pub &'static str);

/// Parse one query text and refuse everything but exactly one top-level
/// plain SELECT: no other statement kind, no data-modifying CTE, no
/// utility command, and a parameter set of `$1` through `$n` with no
/// gap.
pub fn compile_query(text: &str) -> Result<PinnedQuery, QueryRefused> {
    let parsed =
        pg_query::parse(text).map_err(|_| QueryRefused("the query file is not valid SQL"))?;
    // The statement root decides, not a count of SELECT nodes: a
    // utility command (CREATE ... AS SELECT, EXPLAIN) wraps a SELECT
    // node without being one, and nested SELECTs are ordinary
    // subqueries and CTEs of the one root statement.
    let [raw] = parsed.protobuf.stmts.as_slice() else {
        return Err(QueryRefused(
            "the query file must carry exactly one statement",
        ));
    };
    let root = raw
        .stmt
        .as_ref()
        .and_then(|statement| statement.node.as_ref());
    if !matches!(root, Some(pg_query::protobuf::node::Node::SelectStmt(_))) {
        return Err(QueryRefused(
            "the query file must carry exactly one SELECT statement",
        ));
    }
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
                return Err(QueryRefused(
                    "the query file carries a statement or command that is not a plain SELECT",
                ));
            }
            pg_query::NodeRef::ParamRef(parameter) => {
                let index = parameter.number as usize;
                if index == 0 {
                    return Err(QueryRefused(
                        "the query carries a zero parameter reference; write $1 and up",
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
    if parameter_names.iter().any(Option::is_none) {
        return Err(QueryRefused(
            "the query's parameter references leave a gap; use $1 through $n with none missing",
        ));
    }
    Ok(PinnedQuery {
        text: text.to_owned(),
        parameter_names: parameter_names.into_iter().flatten().collect(),
    })
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
    }
}

/// One scalar the engine hands the host or receives from it: the
/// closed value form both sides of the seam speak, so the client's
/// column types never enter the engine.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceScalar {
    Text(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    /// A numeric as its text, so precision never crosses the seam
    /// through a float.
    Numeric(String),
}

/// One row the host read: columns in order, each a name and a scalar.
#[derive(Debug, Clone)]
pub struct SourceRow {
    pub columns: Vec<(String, SourceScalar)>,
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
}

/// The rows one read returned.
#[derive(Debug)]
pub struct PostgresRows {
    pub rows: Vec<SourceRow>,
    /// Whether the fetch stopped at the bound with rows standing
    /// beyond it.
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
    run: &mut crate::engine::route::Run<'_, '_>,
    plan: &PostgresPlan,
    source: &dyn PostgresSource,
    to: &registry_adapter_core::ToStep,
) -> Result<crate::engine::route::Flow, RouteFailure> {
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
    let maximum_rows = run
        .context
        .job
        .profile
        .as_ref()
        .map(|profile| profile.read.maximum_rows_per_page)
        .unwrap_or(registry_adapter_core::MAXIMUM_JOB_ROWS_PER_PAGE);
    // The timeout is the endpoint's own declared, bounded attempt
    // timeout, never a value from the page or the pack.
    let bound = plan.attempt.as_millis();
    let read = PostgresRead {
        statements: vec![
            "BEGIN TRANSACTION READ ONLY".to_owned(),
            format!("SET LOCAL statement_timeout = {bound}"),
        ],
        sql: plan.query.text.clone(),
        parameters: values,
        maximum_rows,
    };
    run.ensure_deadline()?;
    let fetch = async {
        let rows = source.read(read).await.map_err(|fault| match fault {
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
        })?;
        let mut items = Vec::with_capacity(rows.rows.len());
        for row in &rows.rows {
            items.push(row_item(&plan.namespace, row)?);
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
        // The cursor's own offset, which the pack wired into its
        // parameter, advances by the rows this page fetched.
        let offset = run
            .exchange
            .property(crate::engine::job::ADAPTER_JOB_CURSOR_PROPERTY)
            .and_then(|cursor| cursor.get("offset"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        body["next"] = serde_json::json!({ "offset": offset + rows.rows.len() as u64 });
    }
    run.exchange.message.body = body;
    Ok(crate::engine::route::Flow::Continue)
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
/// canonical row JSON's digest as the stable key, so a row is its own
/// identity across pages and scans.
fn row_item(namespace: &str, row: &SourceRow) -> Result<Value, RouteFailure> {
    let mut members = serde_json::Map::new();
    for (name, value) in &row.columns {
        let scalar = match value {
            SourceScalar::Text(text) => serde_json::Value::String(text.clone()),
            SourceScalar::Integer(value) => serde_json::json!(value),
            SourceScalar::Float(value) => serde_json::json!(value),
            SourceScalar::Boolean(value) => serde_json::json!(value),
            SourceScalar::Numeric(text) => serde_json::Value::String(text.clone()),
        };
        members.insert(name.clone(), scalar);
    }
    let row_json = Value::Object(members);
    let canonical =
        registry_platform_canonical_json::canonicalize_json(&row_json).map_err(|_| {
            failure(
                ErrorClass::UpstreamMalformed,
                "a row has no canonical JSON form",
            )
        })?;
    Ok(serde_json::json!({
        "key": format!("{namespace}:{}", registry_platform_config::sha256_uri(&canonical)),
        "value": row_json,
    }))
}
