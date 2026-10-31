// SPDX-License-Identifier: Apache-2.0

//! The read-only `postgres` source
//! (`products/adapter/CONCEPT.md` sections 8.10 and 17.2): the query
//! compile refusals over `pg_query`, the send flow over a scripted
//! source client, and, behind `postgres-test` and a real server, the
//! read-only authority, the statement bound, and the bounded fetch
//! against PostgreSQL itself. The engine boundary carries no client:
//! the production implementation is the host's
//! (`registry-adapter-job`, over its own pool), and the live cases here
//! drive the seam through a test client over the dependency the facade
//! journal already links.
#![cfg(feature = "job-postgres")]

use std::sync::Arc;
use std::time::Duration;

use registry_adapter::engine::component::postgres::{
    compile_plan, compile_query, PostgresRead, PostgresReadFault, PostgresRows, PostgresSource,
    SourceRow, SourceScalar,
};
use registry_adapter::engine::job::{compile_job, run_job_page};
use registry_platform_config::sha256_uri;
use serde_json::json;

/// The unit compile refusals run without a database: every statement
/// kind but exactly one plain SELECT refuses under its fixed
/// value-free reason.
#[test]
fn the_query_compile_refuses_everything_but_one_plain_select() {
    let refused: [(&str, &str); 9] = [
        ("INSERT INTO t VALUES (1)", "statement"),
        ("UPDATE t SET a = 1", "statement"),
        ("DELETE FROM t", "statement"),
        ("GRANT SELECT ON t TO ledger_reader", "exactly one SELECT"),
        ("COPY t TO STDOUT", "statement"),
        ("CREATE TABLE t (a int)", "statement"),
        ("BEGIN", "statement"),
        ("SELECT 1; SELECT 2", "exactly one SELECT"),
        (
            "WITH w AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM w",
            "not a plain SELECT",
        ),
    ];
    for (sql, why) in refused {
        let fault = compile_query(sql).expect_err(sql).0;
        assert!(fault.contains(why), "{sql} refuses for {why}: {fault}");
    }
    // A plain SELECT with a gap-free parameter set compiles and names
    // its parameters.
    let query = compile_query("SELECT a FROM t WHERE b = $1 AND c = $2 AND d = $1")
        .expect("the plain select compiles");
    assert_eq!(
        query.parameter_names,
        ["$1", "$2"],
        "the names are the distinct references"
    );
    assert!(
        compile_query("SELECT a FROM t WHERE b = $1 AND c = $3").is_err(),
        "a parameter gap refuses"
    );
}

/// The scripted client: the seam impersonated, no database. It records
/// the reads it received and answers from a script.
#[derive(Debug)]
struct ScriptedSource {
    reads: std::sync::Mutex<Vec<PostgresRead>>,
    rows: Vec<SourceRow>,
    complete: bool,
    fault: Option<PostgresReadFault>,
}

impl ScriptedSource {
    fn page(rows: Vec<SourceRow>, complete: bool) -> Arc<Self> {
        Arc::new(Self {
            reads: std::sync::Mutex::new(Vec::new()),
            rows,
            complete,
            fault: None,
        })
    }
}

impl PostgresSource for ScriptedSource {
    fn read<'a>(
        &'a self,
        read: PostgresRead,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<PostgresRows, PostgresReadFault>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.reads.lock().expect("the reads lock").push(read);
            if let Some(fault) = self.fault {
                return Err(fault);
            }
            Ok(PostgresRows {
                rows: self.rows.clone(),
                complete: self.complete,
            })
        })
    }
}

fn row(name: &str, age: i64) -> SourceRow {
    SourceRow {
        columns: vec![
            ("name".to_owned(), SourceScalar::Text(name.to_owned())),
            ("age".to_owned(), SourceScalar::Integer(age)),
        ],
    }
}

/// The job fixture of a postgres-source pack: the pinned query file,
/// the runtime config's sources.postgres block, and the caller's rows
/// bound.
struct Fixture {
    _directory: tempfile::TempDir,
    pack: std::path::PathBuf,
    job: std::path::PathBuf,
    runtime: std::path::PathBuf,
}

fn fixture_pack(query: &str) -> String {
    let digest = sha256_uri(query.as_bytes());
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: ledger-pack
version: "1"
testedVersions: []
endpoints:
  - id: ledger
    component: postgres
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 16777216
    queryFile: queries/ledger.sql
queryFiles:
  - path: queries/ledger.sql
    digest: {digest}
sourceRoutes:
  - id: ledger-page
    scan: ongoing
    nextRecovery: key-deduplicated
    edits: ordered
    steps:
      - to:
          uri: postgres:ledger
          parameters:
            queryParameters:
              "$1":
                constant: 1
              "$2":
                constant: 7
capabilities: {{}}
"#
    )
}

fn fixture_job(pack_digest: &str, rows_per_page: u32) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/job/v1alpha1
kind: AdapterJob
job:
  id: ledger-daily
  version: "1"
source:
  pack:
    id: ledger-pack
    version: "1"
    digest: {pack_digest}
  route: ledger-page
projection:
  fields:
    - name
triggers:
  - kind: interval
    delayMilliseconds: 60000
profile:
  pageDeadlineMilliseconds: 60000
  maximumResponseBytes: 16777216
  maximumPageItems: 100
  maximumPageBytes: 16777216
  maximumUpstreamCalls: 4
  read:
    maximumFileBytes: 1073741824
    maximumRowBytes: 1048576
    maximumFieldBytes: 65536
    maximumRowsPerPage: {rows_per_page}
"#
    )
}

fn fixture_runtime() -> String {
    r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: ledger-deployment
endpoints: []
sources:
  postgres:
    ledger:
      host: 127.0.0.1
      port: 1
      database: ledger
      user: ledger_reader
      passwordRef: secret:env/LEDGER_PASSWORD
      namespace: ledger
      tls:
        type: system-roots
allowedPrivateCidrs:
  - 127.0.0.0/8
"#
    .to_owned()
}

fn write_fixture(query: &str, rows_per_page: u32) -> Fixture {
    let directory = tempfile::tempdir().expect("a scratch workspace");
    let root = directory.path().to_path_buf();
    std::fs::create_dir_all(root.join("queries")).expect("the queries directory");
    let pack_text = fixture_pack(query);
    std::fs::write(root.join("queries/ledger.sql"), query).expect("the query file");
    std::fs::write(root.join("pack.yaml"), &pack_text).expect("the pack");
    let profile = r#"apiVersion: id.registrystack.org/formats/adapter/profile/v1alpha1
kind: AdapterProfile
id: ledger
version: "1"
operations: []
problems:
  - code: ledger.upstream
    status: 502
    title: the source could not be reached
    classes: [upstream, breaker.open, throttle.rejected, loop.maximum-iterations-reached]
  - code: ledger.mapping
    status: 422
    title: the request or its mapping was refused
    classes: [validation, conversion.unmapped, aggregation.duplicate]
  - code: ledger.exhausted
    status: 502
    title: the run exhausted a budget
    classes: [script, budget.exhausted, outcome, facade]
  - code: ledger.boundary
    status: 500
    title: the facade refused the call
    classes: [disclosure.violation, egress.refused, credential.rejected]
problemEnvelope: '{"family": "{{problemCode}}"}'
"#;
    std::fs::write(root.join("profile.yaml"), profile).expect("the profile");
    let pack_digest = sha256_uri(pack_text.as_bytes());
    std::fs::write(
        root.join("project.yaml"),
        format!(
            r#"apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1
kind: AdapterProject
project:
  id: ledger-example
  version: "1"
profile:
  id: ledger
  version: "1"
  digest: {}
pack:
  id: ledger-pack
  version: "1"
  digest: {pack_digest}
recordTypes: []
bindings: []
"#,
            sha256_uri(profile.as_bytes())
        ),
    )
    .expect("the project");
    let job = root.join("job.yaml");
    std::fs::write(&job, fixture_job(&pack_digest, rows_per_page)).expect("the job");
    let runtime = root.join("runtime.yaml");
    std::fs::write(&runtime, fixture_runtime()).expect("the runtime config");
    Fixture {
        _directory: directory,
        pack: root.join("pack.yaml"),
        job,
        runtime,
    }
}

/// The send over the seam: the engine compiles the read, the scripted
/// client records it, the rows shape into stable item keys, and a page
/// stopped at the rows bound carries the advanced offset as `next`.
#[tokio::test]
async fn a_send_over_the_seam_pages_and_shapes_rows() {
    let fixture = write_fixture(
        "SELECT name, age FROM people WHERE kind = $1 AND id > $2",
        2,
    );
    let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the postgres job compiles");
    let source = ScriptedSource::page(vec![row("alice", 7), row("bob", 3)], false);
    let mut program = program;
    program
        .register_postgres_source("ledger", source.clone())
        .expect("the host registers its client");
    let result = run_job_page(&program, Some(json!({"offset": 40})))
        .await
        .expect("the page runs");
    assert_eq!(result.page.items.len(), 2);
    assert_eq!(
        result.page.items[0].value,
        json!({"name": "alice", "age": 7})
    );
    let row_json = json!({"age": 7, "name": "alice"});
    let canonical = registry_platform_canonical_json::canonicalize_json(&row_json)
        .expect("the row canonicalizes");
    assert_eq!(
        result.page.items[0].key,
        format!("ledger:{}", sha256_uri(&canonical)),
        "a row is its own identity across pages"
    );
    assert_eq!(
        result.page.next,
        Some(json!({"offset": 42})),
        "the cursor's offset advances by the rows fetched"
    );
    let reads = source.reads.lock().expect("the reads lock");
    let read = reads.first().expect("the client received one read");
    assert_eq!(
        read.statements,
        [
            "BEGIN TRANSACTION READ ONLY".to_owned(),
            "SET LOCAL statement_timeout = 10000".to_owned(),
        ],
        "the preamble is engine-owned data"
    );
    assert_eq!(
        read.parameters,
        [SourceScalar::Integer(1), SourceScalar::Integer(7)],
        "the send's named parameters bound in the query's order"
    );
    assert_eq!(
        read.maximum_rows, 2,
        "the profile's rows bound rides the read"
    );
}

/// A send whose client the host never registered refuses, uncatchably,
/// never silently.
#[tokio::test]
async fn a_send_without_a_registered_client_refuses() {
    let fixture = write_fixture("SELECT name FROM people", 10);
    let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the postgres job compiles");
    let failure = run_job_page(&program, None)
        .await
        .expect_err("no client registered");
    assert_eq!(
        failure.class.map(|class| class.class().to_owned()),
        Some("egress.refused".to_owned()),
        "the missing client is a boundary refusal"
    );
}

/// The seam's fault kinds keep their closed classes: a timed-out
/// statement is a source timeout, not a page fault.
#[tokio::test]
async fn a_source_timeout_keeps_its_class() {
    let fixture = write_fixture("SELECT name FROM people WHERE id = $1 AND kind = $2", 10);
    let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the postgres job compiles");
    #[derive(Debug)]
    struct TimingOut;
    impl PostgresSource for TimingOut {
        fn read<'a>(
            &'a self,
            _read: PostgresRead,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<PostgresRows, PostgresReadFault>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Err(PostgresReadFault::Timeout) })
        }
    }
    let mut program = program;
    program
        .register_postgres_source("ledger", Arc::new(TimingOut))
        .expect("the host registers its client");
    let failure = run_job_page(&program, None)
        .await
        .expect_err("the timed-out source refuses the page");
    assert_eq!(
        failure.class.map(|class| class.class().to_owned()),
        Some("upstream.timeout".to_owned())
    );
}

/// The host's client carries the read-only authority: behind
/// `postgres-test` and a real server, a read-only transaction that a
/// client tried to write in raises, and the engine's seam carries the
/// preamble that opens it. The test drives the seam over a real
/// connection to prove the statements the engine emits do what they
/// say.
#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn the_read_only_transaction_refuses_a_write() {
    let (client, connection) = tokio_postgres::connect(
        &std::env::var("ADAPTER_TEST_DATABASE_URL")
            .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server"),
        tokio_postgres::NoTls,
    )
    .await
    .expect("connect the adapter test database");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let plan = compile_plan(
        "ledger".to_owned(),
        "SELECT 1",
        Duration::from_millis(10_000),
    )
    .expect("the plan compiles");
    let read = PostgresRead {
        statements: vec![
            "BEGIN TRANSACTION READ ONLY".to_owned(),
            "SET LOCAL statement_timeout = 10000".to_owned(),
        ],
        sql: plan.query.text.clone(),
        parameters: Vec::new(),
        maximum_rows: 1,
    };
    client
        .batch_execute(&read.statements.join("; "))
        .await
        .expect("the read-only transaction opens");
    let write = client
        .batch_execute("CREATE TABLE refused_by_the_engine_boundary (a int)")
        .await;
    let _ = client.batch_execute("ROLLBACK").await;
    let error = write.expect_err("a write inside the read-only transaction raises");
    assert_eq!(
        error.code(),
        Some(&tokio_postgres::error::SqlState::READ_ONLY_SQL_TRANSACTION),
        "the source refuses the write with its own SQL state"
    );
}

/// Behind `postgres-test` and a real server, the bounded fetch stops at
/// the profile's rows bound with `complete` false, and the statement
/// bound cancels a slow statement as a source timeout.
#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn a_real_fetch_bounds_its_rows_and_statement() {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let (client, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect the adapter test database");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute("CREATE TEMP TABLE bounded_people (name text, age int)")
        .await
        .expect("the temp table");
    for index in 0..3 {
        client
            .execute(
                "INSERT INTO bounded_people VALUES ($1, $2)",
                &[&format!("person-{index}"), &(index as i32)],
            )
            .await
            .expect("the row");
    }
    let source = ClientSource { client };
    let plan = compile_plan(
        "ledger".to_owned(),
        "SELECT name, age FROM bounded_people",
        Duration::from_millis(10_000),
    )
    .expect("the plan compiles");
    let rows = source
        .read(PostgresRead {
            statements: vec![
                "BEGIN TRANSACTION READ ONLY".to_owned(),
                "SET LOCAL statement_timeout = 10000".to_owned(),
            ],
            sql: plan.query.text.clone(),
            parameters: Vec::new(),
            maximum_rows: 2,
        })
        .await
        .expect("the bounded read");
    assert_eq!(rows.rows.len(), 2, "the fetch stopped at the bound");
    assert!(!rows.complete, "rows stood beyond the bound");
    let slow = compile_plan(
        "ledger".to_owned(),
        "SELECT pg_sleep(5)",
        Duration::from_millis(200),
    )
    .expect("the slow plan compiles");
    let fault = source
        .read(PostgresRead {
            statements: vec![
                "BEGIN TRANSACTION READ ONLY".to_owned(),
                "SET LOCAL statement_timeout = 200".to_owned(),
            ],
            sql: slow.query.text.clone(),
            parameters: Vec::new(),
            maximum_rows: 10,
        })
        .await
        .expect_err("the statement bound cancels the sleep");
    assert_eq!(
        fault,
        PostgresReadFault::Timeout,
        "the source canceled the statement at its own bound"
    );
}

/// The live client: the seam implemented over the same dependency the
/// facade journal already links, as a test fixture. The production
/// client is the host's own, in `registry-adapter-job`.
#[cfg(feature = "postgres-test")]
#[derive(Debug)]
struct ClientSource {
    client: tokio_postgres::Client,
}

/// The seam's scalar as the client binds it: a local enum, so the
/// test fixture can implement the driver's trait without touching the
/// engine's own types.
#[cfg(feature = "postgres-test")]
#[derive(Debug)]
enum NativeParam {
    Text(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Numeric(String),
}

#[cfg(feature = "postgres-test")]
impl tokio_postgres::types::ToSql for NativeParam {
    fn to_sql(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut tokio_postgres::types::private::BytesMut,
    ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match self {
            NativeParam::Text(text) => text.to_sql(ty, out),
            NativeParam::Integer(value) => value.to_sql(ty, out),
            NativeParam::Float(value) => value.to_sql(ty, out),
            NativeParam::Boolean(value) => value.to_sql(ty, out),
            NativeParam::Numeric(text) => text.to_sql(ty, out),
        }
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool
    where
        Self: Sized,
    {
        use tokio_postgres::types::Type;
        matches!(
            ty,
            &Type::TEXT
                | &Type::VARCHAR
                | &Type::INT8
                | &Type::INT4
                | &Type::FLOAT8
                | &Type::BOOL
                | &Type::NUMERIC
        )
    }

    tokio_postgres::types::to_sql_checked!();
}

#[cfg(feature = "postgres-test")]
impl PostgresSource for ClientSource {
    fn read<'a>(
        &'a self,
        read: PostgresRead,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<PostgresRows, PostgresReadFault>> + Send + 'a>,
    > {
        use futures::StreamExt as _;
        use tokio_postgres::types::Type;
        Box::pin(async move {
            for statement in &read.statements {
                self.client
                    .batch_execute(statement)
                    .await
                    .map_err(|_| PostgresReadFault::Statement)?;
            }
            let bound: Vec<NativeParam> = read
                .parameters
                .iter()
                .map(|scalar| match scalar {
                    SourceScalar::Text(text) => NativeParam::Text(text.clone()),
                    SourceScalar::Integer(value) => NativeParam::Integer(*value),
                    SourceScalar::Float(value) => NativeParam::Float(*value),
                    SourceScalar::Boolean(value) => NativeParam::Boolean(*value),
                    SourceScalar::Numeric(text) => NativeParam::Numeric(text.clone()),
                })
                .collect();
            let stream = self
                .client
                .query_raw(&read.sql, bound.iter())
                .await
                .map_err(|error| {
                    if error.code() == Some(&tokio_postgres::error::SqlState::QUERY_CANCELED) {
                        PostgresReadFault::Timeout
                    } else {
                        PostgresReadFault::Statement
                    }
                })?;
            futures::pin_mut!(stream);
            let mut rows = Vec::new();
            let mut complete = true;
            while let Some(row) = stream.next().await {
                let row = row.map_err(|error| {
                    if error.code() == Some(&tokio_postgres::error::SqlState::QUERY_CANCELED) {
                        PostgresReadFault::Timeout
                    } else {
                        PostgresReadFault::Statement
                    }
                })?;
                if rows.len() == read.maximum_rows as usize {
                    complete = false;
                    break;
                }
                let mut columns = Vec::with_capacity(row.len());
                for (index, column) in row.columns().iter().enumerate() {
                    let scalar = match column.type_() {
                        &Type::TEXT | &Type::VARCHAR => SourceScalar::Text(
                            row.try_get(index)
                                .map_err(|_| PostgresReadFault::Statement)?,
                        ),
                        &Type::INT8 => SourceScalar::Integer(
                            row.try_get(index)
                                .map_err(|_| PostgresReadFault::Statement)?,
                        ),
                        &Type::INT4 => SourceScalar::Integer(i64::from(
                            row.try_get::<_, i32>(index)
                                .map_err(|_| PostgresReadFault::Statement)?,
                        )),
                        &Type::FLOAT8 => SourceScalar::Float(
                            row.try_get(index)
                                .map_err(|_| PostgresReadFault::Statement)?,
                        ),
                        &Type::BOOL => SourceScalar::Boolean(
                            row.try_get(index)
                                .map_err(|_| PostgresReadFault::Statement)?,
                        ),
                        &Type::NUMERIC => SourceScalar::Numeric(
                            row.try_get(index)
                                .map_err(|_| PostgresReadFault::Statement)?,
                        ),
                        _ => return Err(PostgresReadFault::Statement),
                    };
                    columns.push((column.name().to_owned(), scalar));
                }
                rows.push(SourceRow { columns });
            }
            drop(stream);
            let _ = self.client.batch_execute("ROLLBACK").await;
            Ok(PostgresRows { rows, complete })
        })
    }
}

/// The bounded read and the statement bound, proven against the real
/// driver once more for the seam's own documentation.
#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn the_seam_shapes_bounded_rows() {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let (client, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect the adapter test database");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let source = ClientSource { client };
    let plan = compile_plan(
        "ledger".to_owned(),
        "SELECT 1 AS one, 'x' AS flag",
        Duration::from_millis(10_000),
    )
    .expect("the plan compiles");
    let rows = source
        .read(PostgresRead {
            statements: vec![
                "BEGIN TRANSACTION READ ONLY".to_owned(),
                "SET LOCAL statement_timeout = 10000".to_owned(),
            ],
            sql: plan.query.text.clone(),
            parameters: Vec::new(),
            maximum_rows: 2,
        })
        .await
        .expect("the read");
    assert_eq!(rows.rows.len(), 1);
    assert!(rows.complete);
    assert_eq!(
        rows.rows[0].columns,
        vec![
            ("one".to_owned(), SourceScalar::Integer(1)),
            ("flag".to_owned(), SourceScalar::Text("x".to_owned())),
        ]
    );
}

/// A plan whose query carries no parameters names none, and its
/// attempt bound is the endpoint's own.
#[test]
fn a_plan_without_parameters_names_none() {
    let plan = compile_plan(
        "ledger".to_owned(),
        "SELECT 1",
        Duration::from_millis(1_000),
    )
    .expect("the plan compiles");
    assert!(plan.query.parameter_names.is_empty());
    assert_eq!(plan.attempt, Duration::from_millis(1_000));
    assert_eq!(plan.namespace, "ledger");
}
