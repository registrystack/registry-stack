//! Retained SQLite security contracts through Evidence's current shared
//! read-only primitive and Adapter engine extract boundary.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use registry_evidence::source_sqlite::{
    check_statement_offline, CapturedSnapshot, ColumnContract, ColumnType, ParameterContract,
    SqliteExtractError, SqliteExtractSource, StatementContract, StatementLimits, Value,
};
use registry_platform_sqlite::{
    materialize_fixture, DatabaseProfile, ErrorKind, ReadOnlyStatement,
};
use serde_json::{json, Value as JsonValue};
use tempfile::TempDir;

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

const MAXIMUM_ENGINE_VALUE_BYTES: usize = 8 * 1_024 * 1_024;

fn instant(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .expect("the test instant is RFC 3339")
        .with_timezone(&Utc)
}

#[derive(Clone)]
struct Plan {
    columns: Vec<ColumnContract>,
    parameters: Vec<ParameterContract>,
    maximum_rows: u64,
    maximum_cell_bytes: usize,
    maximum_statement_steps: u64,
    timeout: Duration,
    maximum_response_bytes: usize,
    maximum_extract_age: Duration,
    concurrency: usize,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            columns: vec![column("id", ColumnType::String)],
            parameters: Vec::new(),
            maximum_rows: 8,
            maximum_cell_bytes: 4096,
            maximum_statement_steps: 100_000,
            timeout: Duration::from_secs(10),
            maximum_response_bytes: 65_536,
            maximum_extract_age: Duration::from_secs(86_400),
            concurrency: 2,
        }
    }
}

impl Plan {
    fn columns(mut self, columns: Vec<ColumnContract>) -> Self {
        self.columns = columns;
        self
    }

    fn parameters(mut self, parameters: Vec<ParameterContract>) -> Self {
        self.parameters = parameters;
        self
    }

    fn rows(mut self, maximum_rows: u64) -> Self {
        self.maximum_rows = maximum_rows;
        self
    }

    fn cell_bytes(mut self, maximum_cell_bytes: usize) -> Self {
        self.maximum_cell_bytes = maximum_cell_bytes;
        self
    }

    fn steps(mut self, maximum_statement_steps: u64) -> Self {
        self.maximum_statement_steps = maximum_statement_steps;
        self
    }

    fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn response_bytes(mut self, maximum_response_bytes: usize) -> Self {
        self.maximum_response_bytes = maximum_response_bytes;
        self
    }

    fn extract_age(mut self, maximum_extract_age: Duration) -> Self {
        self.maximum_extract_age = maximum_extract_age;
        self
    }

    fn contract(&self, sql: &str) -> StatementContract {
        StatementContract {
            sql: sql.to_owned(),
            columns: self.columns.clone(),
            parameters: self.parameters.clone(),
            limits: StatementLimits {
                maximum_rows: self.maximum_rows,
                maximum_cell_bytes: self.maximum_cell_bytes,
                maximum_response_bytes: self.maximum_response_bytes,
                maximum_statement_steps: self.maximum_statement_steps,
                timeout: self.timeout,
                concurrency: self.concurrency,
            },
            schema: None,
        }
    }
}

fn column(name: &str, value_type: ColumnType) -> ColumnContract {
    ColumnContract {
        name: name.to_owned(),
        value_type,
    }
}

fn parameter(name: &str) -> ParameterContract {
    ParameterContract {
        name: name.to_owned(),
        required: true,
    }
}

fn extract() -> (TempDir, CapturedSnapshot) {
    extract_with_metadata(
        "INSERT INTO evidence_extract VALUES \
         ('2026-08-07T02:00:00Z', 'urn:example:residence-register', '2026-08-07-full');",
    )
}

fn extract_with_metadata(metadata_rows: &str) -> (TempDir, CapturedSnapshot) {
    build_extract(&format!(
        "CREATE TABLE evidence_extract \
         (published_at TEXT, publisher TEXT, extract_id TEXT);
         {metadata_rows}
         {EXTRACT_SCHEMA}"
    ))
}

fn extract_without_metadata() -> (TempDir, CapturedSnapshot) {
    build_extract(EXTRACT_SCHEMA)
}

fn build_extract(statements: &str) -> (TempDir, CapturedSnapshot) {
    let directory = TempDir::new().expect("a temporary directory");
    let path = directory.path().join("extract.sqlite");
    materialize_fixture(&path, statements).expect("the extract fixture is valid SQL");
    let snapshot = CapturedSnapshot::capture(&path).expect("the immutable extract is captured");
    (directory, snapshot)
}

fn open(plan: &Plan, sql: &str, snapshot: &CapturedSnapshot) -> SqliteExtractSource {
    SqliteExtractSource::open(
        snapshot.clone(),
        plan.contract(sql),
        plan.maximum_extract_age,
    )
    .expect("the statement source opens")
}

fn open_error(plan: &Plan, sql: &str, snapshot: &CapturedSnapshot) -> SqliteExtractError {
    match SqliteExtractSource::open(
        snapshot.clone(),
        plan.contract(sql),
        plan.maximum_extract_age,
    ) {
        Ok(_) => panic!("the statement source was accepted"),
        Err(error) => error,
    }
}

async fn run(source: &SqliteExtractSource) -> JsonValue {
    source
        .execute(&BTreeMap::new(), instant("2026-08-07T03:00:00Z"))
        .await
        .expect("the reviewed statement is answered")
}

async fn run_error(source: &SqliteExtractSource) -> SqliteExtractError {
    source
        .execute(&BTreeMap::new(), instant("2026-08-07T03:00:00Z"))
        .await
        .expect_err("the statement was accepted")
}

#[test]
fn every_write_action_is_refused() {
    let (_directory, snapshot) = extract();
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
            open_error(&plan, statement, &snapshot),
            SqliteExtractError::Statement(ErrorKind::AuthorizerRefused),
            "a write action was not refused"
        );
    }
}

#[test]
fn attaching_and_detaching_a_database_is_refused() {
    let (_directory, snapshot) = extract();
    let plan = Plan::default();
    for statement in ["ATTACH DATABASE 'other.sqlite' AS other", "DETACH other"] {
        assert_eq!(
            open_error(&plan, statement, &snapshot),
            SqliteExtractError::Statement(ErrorKind::AuthorizerRefused)
        );
    }
}

#[test]
fn a_pragma_is_refused() {
    let (_directory, snapshot) = extract();
    assert_eq!(
        open_error(&Plan::default(), "PRAGMA table_list", &snapshot),
        SqliteExtractError::Statement(ErrorKind::AuthorizerRefused)
    );
}

#[test]
fn a_non_deterministic_function_is_refused() {
    let (_directory, snapshot) = extract();
    let plan = Plan::default();
    for statement in [
        "SELECT random() AS id",
        "SELECT randomblob(4) AS id",
        "SELECT changes() AS id",
        "SELECT last_insert_rowid() AS id",
        "SELECT total_changes() AS id",
    ] {
        assert_eq!(
            open_error(&plan, statement, &snapshot),
            SqliteExtractError::Statement(ErrorKind::AuthorizerRefused),
            "a non-deterministic function was not refused"
        );
    }
}

#[test]
fn a_clock_function_is_refused() {
    let (_directory, snapshot) = extract();
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
            open_error(&plan, statement, &snapshot),
            SqliteExtractError::Statement(ErrorKind::AuthorizerRefused),
            "a clock function was not refused"
        );
    }
}

#[tokio::test]
async fn the_step_budget_stops_an_expensive_statement() {
    let (_directory, snapshot) = extract();
    let plan = Plan::default()
        .columns(vec![column("total", ColumnType::Integer)])
        .steps(1_000);
    let source = open(
        &plan,
        "WITH RECURSIVE counter(n) AS (
             SELECT 1 UNION ALL SELECT n + 1 FROM counter WHERE n < 50000000
         ) SELECT COUNT(*) AS total FROM counter",
        &snapshot,
    );
    assert_eq!(
        run_error(&source).await,
        SqliteExtractError::Statement(ErrorKind::StepBudgetExceeded)
    );
}

#[tokio::test]
async fn the_time_budget_stops_a_slow_statement() {
    let (_directory, snapshot) = extract();
    // Opening verifies the extract metadata under the same configured budget.
    // Leave setup margin, then make each recursive row expensive so the
    // execution deadline is the first statement limit reached.
    let plan = Plan::default()
        .columns(vec![column("total", ColumnType::Integer)])
        .steps(1_000_000)
        .timeout(Duration::from_millis(50));
    let source = open(
        &plan,
        "WITH RECURSIVE counter(n) AS (
             SELECT 1 UNION ALL SELECT n + 1 FROM counter WHERE n < 50000000
         ) SELECT SUM(length(hex(zeroblob(20000 + n % 2)))) AS total FROM counter",
        &snapshot,
    );
    // The worker and the caller's wait share one deadline. Whichever notices
    // it first names the cause, so a loaded host may report the wait's
    // `Timeout`; both carry the same public budget code.
    let error = run_error(&source).await;
    assert!(
        matches!(
            error,
            SqliteExtractError::Statement(ErrorKind::TimeBudgetExceeded | ErrorKind::Timeout)
        ),
        "{error:?}"
    );
    assert_eq!(error.code(), "adapter.sqlite.statement-budget");
}

/// A caller may stop awaiting at any point. The connection it borrowed and
/// the permit it was admitted on must both return after the blocking work
/// observes its shared-primitive bound.
#[tokio::test]
async fn a_cancelled_request_gives_back_its_connection_and_its_permit() {
    let (_directory, snapshot) = extract();
    let plan = Plan::default()
        .columns(vec![column("total", ColumnType::Integer)])
        .parameters(vec![parameter("depth")])
        .steps(1_000_000);
    let statement = ReadOnlyStatement::open(
        DatabaseProfile::Snapshot(snapshot),
        plan.contract(
            "WITH RECURSIVE counter(n) AS (
                 SELECT 1 UNION ALL SELECT n + 1 FROM counter WHERE n < :depth
             ) SELECT COUNT(*) AS total FROM counter",
        ),
    )
    .expect("the bounded statement opens");
    let depth = |value: i64| BTreeMap::from([("depth".to_owned(), Value::Integer(value))]);

    // One cancellation more than the two permits this plan declares catches a
    // pool that loses one connection per cancelled caller.
    for _ in 0..3 {
        let cancelled = tokio::time::timeout(
            Duration::from_millis(1),
            statement.execute(&depth(50_000_000)),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "the request resolved before cancellation could exercise pool recovery"
        );
    }

    let answered = tokio::time::timeout(Duration::from_secs(5), statement.execute(&depth(1)))
        .await
        .expect("cancelled work returns its admission permit")
        .expect("cancelled work returns a usable connection");
    assert_eq!(answered.rows[0]["total"], Value::Integer(1));
}

#[tokio::test]
async fn one_row_beyond_the_row_bound_is_refused() {
    let (_directory, snapshot) = extract();
    let bounded = open(
        &Plan::default().rows(2),
        "SELECT id FROM person ORDER BY id",
        &snapshot,
    );
    assert_eq!(
        run_error(&bounded).await,
        SqliteExtractError::Statement(ErrorKind::TooManyRows)
    );

    let exact = open(
        &Plan::default().rows(3),
        "SELECT id FROM person ORDER BY id",
        &snapshot,
    );
    assert_eq!(
        run(&exact).await["rows"],
        json!([{"id": "p-1"}, {"id": "p-2"}, {"id": "p-3"}])
    );
}

/// The intermediate response bound is measured while rows are collected. The
/// engine boundary then applies the same ceiling to the final response with
/// publication metadata, so neither representation can exceed the reviewed
/// allocation limit.
#[tokio::test]
async fn a_result_beyond_the_response_bound_is_refused_as_it_is_collected() {
    let (_directory, snapshot) = extract();
    let bounded = open(
        &Plan::default().response_bytes(8),
        "SELECT id FROM person ORDER BY id",
        &snapshot,
    );
    assert_eq!(
        run_error(&bounded).await,
        SqliteExtractError::Statement(ErrorKind::ResponseTooLarge)
    );

    let expected = json!({
        "rows": [{"id":"p-1"}, {"id":"p-2"}, {"id":"p-3"}],
        "extract": {
            "publishedAt":"2026-08-07T02:00:00Z",
            "publisher":"urn:example:residence-register",
            "extractId":"2026-08-07-full"
        }
    });
    let exact_bytes = serde_json::to_vec(&expected)
        .expect("the expected response serializes")
        .len();
    let exact = open(
        &Plan::default().response_bytes(exact_bytes),
        "SELECT id FROM person ORDER BY id",
        &snapshot,
    );
    assert_eq!(run(&exact).await, expected);
}

#[tokio::test]
async fn a_value_beyond_the_cell_bound_is_refused() {
    let (_directory, snapshot) = extract();
    let source = open(
        &Plan::default().cell_bytes(8),
        "SELECT note AS id FROM person ORDER BY id",
        &snapshot,
    );
    assert_eq!(
        run_error(&source).await,
        SqliteExtractError::Statement(ErrorKind::CellTooLarge)
    );
}

/// The declared cell bound is applied after SQLite produces a value. The
/// engine limit additionally rejects an oversized stored value before a SQL
/// expression can pull the full cell into process memory.
#[tokio::test]
async fn a_cell_beyond_the_engine_limit_is_refused_before_it_is_read() {
    let oversized = format!(
        "CREATE TABLE evidence_extract \
         (published_at TEXT, publisher TEXT, extract_id TEXT);
         INSERT INTO evidence_extract VALUES \
         ('2026-08-07T02:00:00Z', 'urn:example:residence-register', '2026-08-07-full');
         {EXTRACT_SCHEMA}
         INSERT INTO person
         SELECT 'p-big', 'nw', 1, 1.0, hex(zeroblob({MAXIMUM_ENGINE_VALUE_BYTES}));"
    );
    let (_directory, snapshot) = build_extract(&oversized);
    let source = open(
        &Plan::default(),
        "SELECT substr(note, 1, 1) AS id FROM person WHERE id = 'p-big'",
        &snapshot,
    );
    assert_eq!(
        run_error(&source).await,
        SqliteExtractError::Statement(ErrorKind::CellTooLarge)
    );
}

#[test]
fn the_declared_columns_must_match_the_result_columns() {
    let (_directory, snapshot) = extract();
    let two = Plan::default().columns(vec![
        column("id", ColumnType::String),
        column("region", ColumnType::String),
    ]);
    for (statement, note) in [
        (
            "SELECT id, region_code AS locality FROM person",
            "a renamed result column was accepted",
        ),
        (
            "SELECT region_code AS region, id FROM person",
            "a reordered result was accepted",
        ),
        ("SELECT id FROM person", "a short result was accepted"),
    ] {
        assert_eq!(
            open_error(&two, statement, &snapshot),
            SqliteExtractError::Statement(ErrorKind::ColumnMismatch),
            "{note}"
        );
    }
}

#[test]
fn statement_parameters_and_declared_bindings_must_agree() {
    let (_directory, snapshot) = extract();
    let none = Plan::default();
    for statement in [
        "SELECT id FROM person WHERE id = :record",
        "SELECT id FROM person WHERE id = ?",
    ] {
        assert_eq!(
            open_error(&none, statement, &snapshot),
            SqliteExtractError::Statement(ErrorKind::UndeclaredParameter)
        );
    }

    let declared = Plan::default().parameters(vec![parameter("record")]);
    assert_eq!(
        check_statement_offline(
            &declared.contract("SELECT id FROM person WHERE id = :record OR id = ?1")
        )
        .expect_err("a numbered alias of a named parameter was accepted")
        .kind(),
        ErrorKind::UndeclaredParameter
    );
    assert_eq!(
        open_error(&declared, "SELECT id FROM person", &snapshot),
        SqliteExtractError::Statement(ErrorKind::UnusedBinding)
    );
}

#[tokio::test]
async fn the_reserved_parameter_carries_the_evaluation_instant() {
    let (_directory, snapshot) = extract();
    let plan = Plan::default().columns(vec![
        column("id", ColumnType::String),
        column("observed_at", ColumnType::String),
    ]);
    let source = open(
        &plan,
        "SELECT id, :evidence_now AS observed_at FROM person WHERE id = 'p-1'",
        &snapshot,
    );
    // The source binds one host-owned whole-second instant. Caller parameters
    // cannot replace the reserved value.
    let result = source
        .execute(&BTreeMap::new(), instant("2026-08-07T03:00:00.750Z"))
        .await
        .expect("the statement reads the host evaluation instant");
    assert_eq!(
        result["rows"],
        json!([{"id": "p-1", "observed_at": "2026-08-07T03:00:00Z"}])
    );
    let attempted_override = BTreeMap::from([(
        "evidence_now".to_owned(),
        Value::String("2099-01-01T00:00:00Z".to_owned()),
    )]);
    assert_eq!(
        source
            .execute(&attempted_override, instant("2026-08-07T03:00:00Z"))
            .await,
        Err(SqliteExtractError::InvalidParameters)
    );
}

#[test]
fn a_second_statement_in_the_artifact_is_refused() {
    let (_directory, snapshot) = extract();
    assert_eq!(
        open_error(
            &Plan::default(),
            "SELECT id FROM person; SELECT id FROM person",
            &snapshot
        ),
        SqliteExtractError::Statement(ErrorKind::MultipleStatements)
    );
}

#[test]
fn an_extract_without_its_metadata_table_is_refused() {
    let (_directory, snapshot) = extract_without_metadata();
    assert_eq!(
        open_error(&Plan::default(), "SELECT id FROM person", &snapshot),
        SqliteExtractError::InvalidMetadata
    );
}

#[test]
fn a_metadata_table_without_exactly_one_row_is_refused() {
    for rows in [
        "",
        "INSERT INTO evidence_extract VALUES ('2026-08-07T02:00:00Z', 'a', 'b'), \
         ('2026-08-07T03:00:00Z', 'c', 'd');",
    ] {
        let (_directory, snapshot) = extract_with_metadata(rows);
        assert_eq!(
            open_error(&Plan::default(), "SELECT id FROM person", &snapshot),
            SqliteExtractError::InvalidMetadata
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
        let (_directory, snapshot) = extract_with_metadata(rows);
        assert_eq!(
            open_error(&Plan::default(), "SELECT id FROM person", &snapshot),
            SqliteExtractError::InvalidMetadata
        );
    }
}

#[test]
fn a_metadata_table_missing_a_column_is_refused() {
    let (_directory, snapshot) = build_extract(&format!(
        "CREATE TABLE evidence_extract (published_at TEXT, publisher TEXT);
         INSERT INTO evidence_extract VALUES ('2026-08-07T02:00:00Z', 'a');
         {EXTRACT_SCHEMA}"
    ));
    assert_eq!(
        open_error(&Plan::default(), "SELECT id FROM person", &snapshot),
        SqliteExtractError::InvalidMetadata
    );
}

/// Nothing makes the reserved metadata object a table. A view over a
/// nonterminating recursive query is still bounded at startup and refused
/// instead of hanging.
#[test]
fn a_metadata_view_that_never_terminates_is_refused() {
    let (_directory, snapshot) = build_extract(&format!(
        "CREATE VIEW evidence_extract AS
         WITH RECURSIVE forever(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM forever)
         SELECT '2026-08-07T02:00:00Z' AS published_at,
                'urn:example:residence-register' AS publisher,
                CAST(MAX(n) AS TEXT) AS extract_id
         FROM forever;
         {EXTRACT_SCHEMA}"
    ));
    let metadata = ReadOnlyStatement::open(
        DatabaseProfile::Snapshot(snapshot.clone()),
        Plan::default()
            .steps(1_000)
            .columns(vec![
                column("published_at", ColumnType::String),
                column("publisher", ColumnType::String),
                column("extract_id", ColumnType::String),
            ])
            .rows(1)
            .contract("SELECT published_at, publisher, extract_id FROM evidence_extract"),
    )
    .expect("the metadata view is structurally readable");
    assert_eq!(
        metadata
            .execute_at_open(&BTreeMap::new())
            .expect_err("the nonterminating metadata view was answered")
            .kind(),
        ErrorKind::StepBudgetExceeded
    );
    assert_eq!(
        open_error(
            &Plan::default().steps(1_000),
            "SELECT id FROM person",
            &snapshot
        ),
        SqliteExtractError::InvalidMetadata
    );
}

/// The publication instant is truncated where it is parsed, so the instant
/// the age bound is measured against is the instant the response carries.
#[tokio::test]
async fn a_fractional_publication_instant_is_compared_as_it_is_emitted() {
    let (_directory, snapshot) = extract_with_metadata(
        "INSERT INTO evidence_extract VALUES \
         ('2026-08-07T02:00:00.750Z', 'urn:example:residence-register', '2026-08-07-full');",
    );
    let source = open(
        &Plan::default(),
        "SELECT id FROM person ORDER BY id LIMIT 1",
        &snapshot,
    );
    let result = run(&source).await;
    assert_eq!(
        result["extract"]["publishedAt"],
        json!("2026-08-07T02:00:00Z")
    );
    assert_eq!(source.validate_age(instant("2026-08-08T02:00:00Z")), Ok(()));
    assert_eq!(
        source.validate_age(instant("2026-08-08T02:00:01Z")),
        Err(SqliteExtractError::Stale)
    );
}

#[test]
fn the_configured_age_bound_refuses_a_stale_extract() {
    let (_directory, snapshot) = extract();
    let source = open(
        &Plan::default().extract_age(Duration::from_secs(86_400)),
        "SELECT id FROM person",
        &snapshot,
    );
    assert_eq!(source.validate_age(instant("2026-08-08T01:59:00Z")), Ok(()));
    assert_eq!(
        source.validate_age(instant("2026-08-08T02:00:01Z")),
        Err(SqliteExtractError::Stale)
    );
}

/// A line and a column are structure. The SQL sitting on that line is content,
/// and no diagnostic rendered by the shared primitive may carry it.
#[test]
fn a_located_syntax_fault_carries_no_statement_text() {
    const CANARY: &str = "s3cr3t-canary-value";
    let sql = format!("SELECT id FROM person\nWHERE note = '{CANARY}' AND id = = 'p-1'");
    let error = check_statement_offline(&Plan::default().contract(&sql))
        .expect_err("the invalid SQL was accepted");
    assert_eq!(
        error.location(),
        Some(registry_platform_sqlite::TextLocation {
            line: 2,
            column: 45
        })
    );
    let rendered = format!("{error:?} {error}");
    assert!(
        !rendered.contains(CANARY),
        "the diagnostic leaked statement text: {rendered}"
    );
    assert_eq!(error.kind(), ErrorKind::InvalidSql);
    assert_eq!(error.to_string(), "the statement is not valid SQL");
}
