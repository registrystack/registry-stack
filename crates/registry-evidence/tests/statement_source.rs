//! Contract tests for the reviewed-statement source transport.
//!
//! These drive the public `SourceExecutor` surface, so they cover the transport
//! as a caller reaches it: one clock, one staleness decision, one projection,
//! and value-free diagnostics that still name the artifact to open.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use registry_evidence::config::{OutboundTlsConfig, SourceConfig};
use registry_evidence::model::SelectorValue;
use registry_evidence::rhai_runtime::{
    RhaiRuntime, StatementParameters, StatementParametersLimits,
};
use registry_evidence::secrets::{SecretProvider, SecretResolver};
use registry_evidence::source::{
    PreparedSourceRequest, ResolvedSourceSelector, SourceError, SourceExecutor, StatementExtract,
    StatementInputs,
};
use registry_evidence::source_sqlite::{cause, EXTRACT_METADATA_TABLE};
use rusqlite::Connection;
use serde_json::{json, Value as JsonValue};
use tempfile::TempDir;

/// The bundle artifact every plan below names for its statement.
const STATEMENT_ARTIFACT: &str = "queries/residence-region.sql";
const SUBJECT_PROFILE: &str = "person-demographics-v1";
const PUBLISHED_AT: &str = "2026-08-07T02:00:00Z";
const EVALUATED_AT: &str = "2026-08-07T03:00:00Z";

/// A value that must never reach a rendered diagnostic, placed both in the
/// statement text and in the extract data.
const CANARY: &str = "s3cr3t-canary-value";

/// The wording an adopter sees when preparation oversteps its declared
/// parameters. Restated here so a change to it is a change a test notices.
const PREPARED_PARAMETER_RESERVED: &str =
    "the preparation returned the parameter name the runtime reserves";
const PREPARED_PARAMETER_UNDECLARED: &str =
    "the preparation returned a parameter the statement does not declare";
const PREPARED_PARAMETER_NOT_PREPARED: &str =
    "the preparation returned a parameter the statement fills from a selector";
const MISSING_PREPARED_PARAMETER: &str =
    "the preparation returned no value for a parameter declared prepared";

fn instant(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .expect("the test instant is RFC 3339")
        .with_timezone(&Utc)
}

/// The reviewed source document, restated per test around its statement.
struct Plan {
    columns: String,
    parameter_bindings: String,
    selector_fields: String,
    projection: String,
    maximum_rows: u64,
    maximum_cell_bytes: u64,
    maximum_extract_age_seconds: u64,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            columns: "[{name: id, type: string}]".to_owned(),
            parameter_bindings: "{}".to_owned(),
            selector_fields: "[region_code]".to_owned(),
            projection: "[/rows/*/id]".to_owned(),
            maximum_rows: 8,
            maximum_cell_bytes: 4096,
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

    fn selector_fields(mut self, fields: &str) -> Self {
        self.selector_fields = fields.to_owned();
        self
    }

    fn projection(mut self, projection: &str) -> Self {
        self.projection = projection.to_owned();
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

    fn extract_age(mut self, maximum_extract_age_seconds: u64) -> Self {
        self.maximum_extract_age_seconds = maximum_extract_age_seconds;
        self
    }

    fn build(&self) -> SourceConfig {
        let Self {
            columns,
            parameter_bindings,
            selector_fields,
            projection,
            maximum_rows,
            maximum_cell_bytes,
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
        - {{profile: {SUBJECT_PROFILE}, fields: {selector_fields}}}
  parameterBindings: {parameter_bindings}
  maximumRows: {maximum_rows}
  maximumCellBytes: {maximum_cell_bytes}
  maximumStatementSteps: 100000
  projection: {projection}
  timeoutMilliseconds: 10000
  maximumResponseBytes: 65536
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
    format!("{{kind: selector, role: subject, profile: {SUBJECT_PROFILE}, field: {field}}}")
}

/// A parameter the preparation script fills, which names no selector because
/// its value is derived rather than resolved.
const PREPARED_BINDING: &str = "{kind: prepared}";

/// The extract every test reads, carrying one metadata row and the canary in
/// the data an adopter would never want rendered.
fn extract(directory: &TempDir, published_at: &str) -> PathBuf {
    let path = directory.path().join("extract.sqlite");
    let statements = format!(
        "CREATE TABLE {EXTRACT_METADATA_TABLE} (published_at TEXT, publisher TEXT, extract_id TEXT);
         INSERT INTO {EXTRACT_METADATA_TABLE} VALUES
             ('{published_at}', 'urn:example:residence-register', '2026-08-07-full');
         CREATE TABLE person (
             id TEXT PRIMARY KEY,
             region_code TEXT,
             rank INTEGER,
             note TEXT
         );
         INSERT INTO person VALUES
             ('p-1', 'nw', 1, 'short'),
             ('p-2', 'nw', 2, '{CANARY} and a note long enough to overrun a small cell bound'),
             ('p-3', 'se', 1, 'other');"
    );
    let connection = Connection::open(&path).expect("the extract file opens for writing");
    connection
        .execute_batch(&statements)
        .expect("the extract fixture is valid SQL");
    drop(connection);
    path
}

/// A resolver over an empty root. A statement source holds no credentials, so
/// nothing is ever asked of it.
fn secrets(directory: &TempDir) -> Arc<SecretResolver> {
    SecretResolver::new([SecretProvider::File], directory.path())
        .map(Arc::new)
        .expect("the resolver builds")
}

fn compile(
    directory: &TempDir,
    plan: &Plan,
    statement_sql: &str,
    extract_path: Option<&Path>,
) -> Result<SourceExecutor, SourceError> {
    let source = plan.build();
    let allowed = [vec![("subject".to_owned(), SUBJECT_PROFILE.to_owned())]];
    let outbound_tls = OutboundTlsConfig {
        system_roots: true,
        trust_profiles: Default::default(),
    };
    SourceExecutor::new_with_selector_sets_and_tls(
        &source,
        &allowed,
        &outbound_tls,
        &BTreeMap::new(),
        Some(StatementInputs {
            statement_sql,
            extract: extract_path.map(StatementExtract::Fixture),
        }),
        secrets(directory),
    )
}

fn executor(
    directory: &TempDir,
    plan: &Plan,
    statement_sql: &str,
    extract_path: Option<&Path>,
) -> SourceExecutor {
    compile(directory, plan, statement_sql, extract_path).expect("the statement source compiles")
}

fn compile_error(
    directory: &TempDir,
    plan: &Plan,
    statement_sql: &str,
    extract_path: Option<&Path>,
) -> SourceError {
    let Err(error) = compile(directory, plan, statement_sql, extract_path) else {
        panic!("the statement source was accepted");
    };
    error
}

fn subject(values: &[(&str, SelectorValue)]) -> Vec<ResolvedSourceSelector> {
    vec![ResolvedSourceSelector {
        role: "subject".to_owned(),
        profile: SUBJECT_PROFILE.to_owned(),
        values: values
            .iter()
            .map(|(field, value)| ((*field).to_owned(), value.clone()))
            .collect(),
    }]
}

fn text(value: &str) -> SelectorValue {
    SelectorValue::String(value.to_owned())
}

/// Preparation output in the shape a statement transport consumes.
fn prepared(parameters: &[(&str, SelectorValue)]) -> PreparedSourceRequest {
    PreparedSourceRequest::Statement(StatementParameters {
        parameters: parameters
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect(),
    })
}

/// The same preparation output, produced by running an adopter's own Rhai
/// script under the bounds the runtime compiles for it, so what the statement
/// binds is what a bundle would really have derived.
fn prepared_by_script(source: &str, selectors: &JsonValue) -> PreparedSourceRequest {
    let runtime = RhaiRuntime::new();
    let script = runtime
        .compile_preparation(source)
        .expect("the preparation script compiles");
    let limits = StatementParametersLimits::new(4, 64).expect("the preparation bounds are valid");
    PreparedSourceRequest::Statement(
        runtime
            .prepare_statement(&script, selectors, &json!({}), &limits)
            .expect("the preparation script returns its parameters"),
    )
}

async fn run(
    executor: &SourceExecutor,
    selectors: &[ResolvedSourceSelector],
    request: &PreparedSourceRequest,
    at: &str,
) -> Result<JsonValue, SourceError> {
    executor.execute(selectors, request, instant(at)).await
}

fn artifact_fault_text(error: &SourceError) -> String {
    error
        .artifact_fault()
        .expect("the failure names an artifact")
        .to_string()
}

#[tokio::test]
async fn a_statement_source_executes_and_returns_projected_json() {
    let directory = TempDir::new().expect("a temporary directory");
    let path = extract(&directory, PUBLISHED_AT);
    let plan =
        Plan::default().bindings(&format!("{{region: {}}}", selector_binding("region_code")));
    let executor = executor(
        &directory,
        &plan,
        "SELECT id FROM person WHERE region_code = :region ORDER BY id",
        Some(&path),
    );

    let response = run(
        &executor,
        &subject(&[("region_code", text("nw"))]),
        &prepared(&[]),
        EVALUATED_AT,
    )
    .await
    .expect("the statement runs");

    assert_eq!(response, json!({"rows": [{"id": "p-1"}, {"id": "p-2"}]}));
}

#[tokio::test]
async fn the_reserved_instant_reaches_the_statement_and_a_pinned_instant_repeats() {
    let directory = TempDir::new().expect("a temporary directory");
    let path = extract(&directory, PUBLISHED_AT);
    let plan = Plan::default()
        .columns("[{name: observed, type: string}]")
        .projection("[/rows/*/observed]");
    let executor = executor(
        &directory,
        &plan,
        "SELECT :evidence_now AS observed FROM person WHERE id = 'p-1'",
        Some(&path),
    );
    let selectors = subject(&[("region_code", text("nw"))]);

    let first = run(&executor, &selectors, &prepared(&[]), EVALUATED_AT)
        .await
        .expect("the statement runs");
    let second = run(&executor, &selectors, &prepared(&[]), EVALUATED_AT)
        .await
        .expect("the statement runs again");

    // The runtime's own instant is what the statement saw, in the fixed-width
    // form the transport binds, so a pinned evaluation is reproducible.
    assert_eq!(
        first,
        json!({"rows": [{"observed": "2026-08-07T03:00:00Z"}]})
    );
    assert_eq!(first, second);

    let later = run(
        &executor,
        &selectors,
        &prepared(&[]),
        "2026-08-07T04:30:00Z",
    )
    .await
    .expect("the statement runs at another instant");
    assert_eq!(
        later,
        json!({"rows": [{"observed": "2026-08-07T04:30:00Z"}]})
    );
}

#[tokio::test]
async fn an_extract_older_than_the_source_allows_fails_before_a_row_is_read() {
    let directory = TempDir::new().expect("a temporary directory");
    let path = extract(&directory, PUBLISHED_AT);
    // Three rows against a bound of one, so reading any row has its own
    // distinct failure. Whichever failure comes back says which check ran first.
    let plan = Plan::default().rows(1).extract_age(3_600);
    let executor = executor(
        &directory,
        &plan,
        "SELECT id FROM person ORDER BY id",
        Some(&path),
    );
    let selectors = subject(&[("region_code", text("nw"))]);

    let within_bound = run(&executor, &selectors, &prepared(&[]), EVALUATED_AT)
        .await
        .expect_err("the row bound stops a fresh extract");
    assert!(
        matches!(within_bound, SourceError::StatementResult(_)),
        "a fresh extract is read: {within_bound}"
    );
    assert!(artifact_fault_text(&within_bound).contains(cause::TOO_MANY_ROWS));

    let stale = run(
        &executor,
        &selectors,
        &prepared(&[]),
        "2026-08-07T04:00:01Z",
    )
    .await
    .expect_err("a stale extract is refused");
    assert!(
        matches!(stale, SourceError::ExtractTooOld(_)),
        "the staleness check did not run first: {stale}"
    );
    assert!(artifact_fault_text(&stale).contains(cause::EXTRACT_TOO_OLD));

    // The same fact, asked the way startup asks it. Startup only says it out
    // loud; the refusal above is what withholds an answer, and readiness does
    // not consult either.
    assert!(!executor.extract_is_stale(instant(EVALUATED_AT)));
    assert!(executor.extract_is_stale(instant("2026-08-07T04:00:01Z")));
}

#[tokio::test]
async fn declarative_parameter_bindings_bind_selector_values_by_type() {
    let directory = TempDir::new().expect("a temporary directory");
    let path = extract(&directory, PUBLISHED_AT);
    let plan = Plan::default()
        .selector_fields("[region_code, rank]")
        .bindings(&format!(
            "{{region: {}, rank: {}}}",
            selector_binding("region_code"),
            selector_binding("rank")
        ));
    let statement = "SELECT id FROM person WHERE region_code = :region AND rank = :rank";
    let executor = executor(&directory, &plan, statement, Some(&path));
    let selectors = subject(&[
        ("region_code", text("nw")),
        ("rank", SelectorValue::Integer(2)),
    ]);

    let materialized = executor
        .materialize_request(&selectors, &prepared(&[]))
        .expect("the request materializes");
    assert_eq!(materialized.statement(), Some(statement));
    assert_eq!(
        materialized.parameters(),
        Some(&BTreeMap::from([
            ("rank".to_owned(), SelectorValue::Integer(2)),
            ("region".to_owned(), text("nw")),
        ]))
    );

    let response = run(&executor, &selectors, &prepared(&[]), EVALUATED_AT)
        .await
        .expect("the statement runs");
    assert_eq!(response, json!({"rows": [{"id": "p-2"}]}));
}

/// A prepared parameter carries a value a selector does not hold, produced by
/// the deployment's own script, and the statement runs on it.
#[tokio::test]
async fn a_prepared_parameter_takes_its_value_from_a_real_preparation_script() {
    let directory = TempDir::new().expect("a temporary directory");
    let path = extract(&directory, PUBLISHED_AT);
    let plan = Plan::default()
        .selector_fields("[record_reference]")
        .bindings(&format!("{{reference: {PREPARED_BINDING}}}"));
    let executor = executor(
        &directory,
        &plan,
        "SELECT id FROM person WHERE id = :reference",
        Some(&path),
    );
    // The register stores the bare identifier and the caller presents a URN, so
    // the normalized form exists only because the script derived it. There is
    // no selector field the source could have named for it.
    let request = prepared_by_script(
        "fn prepare(selectors, parameters) {
             let reference = selectors.subject.values.record_reference;
             reference.replace(\"urn:example:person:\", \"\");
             #{ parameters: #{ reference: reference } }
         }",
        &json!({"subject": {"values": {"record_reference": "urn:example:person:p-3"}}}),
    );

    let response = run(
        &executor,
        &subject(&[("record_reference", text("urn:example:person:p-3"))]),
        &request,
        EVALUATED_AT,
    )
    .await
    .expect("the statement runs");

    assert_eq!(response, json!({"rows": [{"id": "p-3"}]}));
}

/// A parameter has one declared origin and exactly one. Preparation fills what
/// the source declared prepared, and every other outcome names the artifact and
/// a closed cause rather than reaching the statement.
#[tokio::test]
async fn a_parameter_is_filled_from_its_one_declared_origin() {
    let directory = TempDir::new().expect("a temporary directory");
    let path = extract(&directory, PUBLISHED_AT);
    let plan = Plan::default().bindings(&format!(
        "{{region: {}, cutoff: {PREPARED_BINDING}}}",
        selector_binding("region_code")
    ));
    let executor = executor(
        &directory,
        &plan,
        "SELECT id FROM person WHERE region_code = :region AND rank <= :cutoff ORDER BY id",
        Some(&path),
    );
    let selectors = subject(&[("region_code", text("nw"))]);

    let response = run(
        &executor,
        &selectors,
        &prepared(&[("cutoff", SelectorValue::Integer(1))]),
        EVALUATED_AT,
    )
    .await
    .expect("the statement runs");
    assert_eq!(response, json!({"rows": [{"id": "p-1"}]}));

    for (parameters, expected) in [
        (
            vec![
                ("evidence_now", text("2000-01-01T00:00:00Z")),
                ("cutoff", SelectorValue::Integer(1)),
            ],
            PREPARED_PARAMETER_RESERVED,
        ),
        (
            vec![
                ("region_code", text("se")),
                ("cutoff", SelectorValue::Integer(1)),
            ],
            PREPARED_PARAMETER_UNDECLARED,
        ),
        (
            vec![
                ("region", text("se")),
                ("cutoff", SelectorValue::Integer(1)),
            ],
            PREPARED_PARAMETER_NOT_PREPARED,
        ),
        (vec![], MISSING_PREPARED_PARAMETER),
    ] {
        let error = executor
            .materialize_request(&selectors, &prepared(&parameters))
            .expect_err("the prepared parameters are refused");
        assert!(
            matches!(error, SourceError::StatementParameter(_)),
            "unexpected failure: {error}"
        );
        let rendered = artifact_fault_text(&error);
        assert!(rendered.contains(STATEMENT_ARTIFACT), "{rendered}");
        assert!(rendered.contains(expected), "{rendered}");
    }
}

#[test]
fn a_refused_statement_names_the_artifact_and_a_closed_cause() {
    let directory = TempDir::new().expect("a temporary directory");
    let path = extract(&directory, PUBLISHED_AT);
    let plan = Plan::default().columns("[{name: missing_column, type: string}]");

    let error = compile_error(
        &directory,
        &plan,
        "SELECT missing_column FROM person",
        Some(&path),
    );

    assert!(
        matches!(error, SourceError::StatementRefused(_)),
        "unexpected failure: {error}"
    );
    let fault = error
        .artifact_fault()
        .expect("the failure names an artifact");
    assert_eq!(fault.artifact(), STATEMENT_ARTIFACT);
    let rendered = fault.to_string();
    assert!(
        rendered.contains(STATEMENT_ARTIFACT) && rendered.contains(cause::UNKNOWN_COLUMN),
        "{rendered}"
    );
    // The request-time rendering stays categorical, so the two carry different
    // amounts of detail on purpose.
    assert_eq!(error.to_string(), "the source statement was refused");
}

#[tokio::test]
async fn no_rendering_carries_statement_text_or_extract_data() {
    let directory = TempDir::new().expect("a temporary directory");
    let path = extract(&directory, PUBLISHED_AT);
    let mut rendered = Vec::new();

    // A statement the engine cannot parse: its own message would quote the text
    // around the fault, and that text holds the canary.
    let broken = compile_error(
        &directory,
        &Plan::default(),
        &format!("SELECT id FROM person WHERE note = '{CANARY}' AND((("),
        Some(&path),
    );
    rendered.push(broken.to_string());
    rendered.push(format!("{broken:?}"));
    rendered.push(artifact_fault_text(&broken));

    // A result value that overruns its cell bound: the value itself is extract
    // data carrying the canary.
    let plan = Plan::default().cell_bytes(8);
    let executor = executor(
        &directory,
        &plan,
        "SELECT note AS id FROM person WHERE region_code = 'nw' ORDER BY id",
        Some(&path),
    );
    let selectors = subject(&[("region_code", text("nw"))]);
    let too_large = run(&executor, &selectors, &prepared(&[]), EVALUATED_AT)
        .await
        .expect_err("the cell bound stops the result");
    rendered.push(too_large.to_string());
    rendered.push(format!("{too_large:?}"));
    rendered.push(artifact_fault_text(&too_large));

    // The materialized request holds both the statement text and a bound value.
    let materialized = executor
        .materialize_request(&subject(&[("region_code", text(CANARY))]), &prepared(&[]))
        .expect("the request materializes");
    rendered.push(format!("{materialized:?}"));

    for text in &rendered {
        assert!(!text.contains(CANARY), "a diagnostic carried data: {text}");
    }
}

#[tokio::test]
async fn a_source_compiled_without_an_extract_materializes_but_refuses_to_run() {
    let directory = TempDir::new().expect("a temporary directory");
    let plan =
        Plan::default().bindings(&format!("{{region: {}}}", selector_binding("region_code")));
    let statement = "SELECT id FROM person WHERE region_code = :region ORDER BY id";
    let executor = executor(&directory, &plan, statement, None);
    let selectors = subject(&[("region_code", text("nw"))]);

    let materialized = executor
        .materialize_request(&selectors, &prepared(&[]))
        .expect("the request materializes without an extract");
    assert_eq!(materialized.statement(), Some(statement));

    assert_eq!(
        run(&executor, &selectors, &prepared(&[]), EVALUATED_AT).await,
        Err(SourceError::StatementUnavailable)
    );
    // Nothing was mounted, so there is no file whose age startup could report.
    assert!(!executor.extract_is_stale(instant("2027-01-01T00:00:00Z")));
}

#[tokio::test]
async fn a_statement_source_needs_no_credentials() {
    let directory = TempDir::new().expect("a temporary directory");
    let path = extract(&directory, PUBLISHED_AT);
    let executor = executor(
        &directory,
        &Plan::default(),
        "SELECT id FROM person ORDER BY id",
        Some(&path),
    );

    assert_eq!(executor.credentials_ready().await, Ok(()));
}
