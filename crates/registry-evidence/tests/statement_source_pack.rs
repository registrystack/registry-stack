//! Retained SQLite source behavior through Evidence's shared Adapter pack path.
//!
//! The legacy `statement_source` suite exercised an Evidence-owned executor.
//! These cases keep the integration-level promises at their current owners:
//! authorized inputs and fixture assets cross the Evidence pack boundary, while
//! statement safety and bounds run through the shared Adapter SQLite component.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use registry_adapter_core::{AdapterEndpointBindings, AdapterPack};
use registry_adapter_engine::{
    artifacts::PackArtifactBytes,
    component::sqlite_extract::{SqliteExtractError, SqliteExtractPlan, SqliteExtractSource},
    evidence::{
        compile_evidence, EvidenceAcquisitionIntent, EvidenceCompileInputs, EvidenceHookFuture,
        EvidenceHostHooks, EvidenceLimits, EvidenceLookup, EvidenceRuntimeBindings,
        EvidenceSendIntent,
    },
};
use registry_evidence::{
    bundle::{evidence_package_limits, Bundle},
    fixture_source::{compile_sources, FixtureAcquisition},
    model::LookupResult,
    selector::resolve_offline_fixture_authorization,
    source_sqlite::{
        CapturedSnapshot, ColumnContract, ColumnType, ParameterContract, StatementContract,
        StatementLimits, Value,
    },
};
use registry_platform_sqlite::{materialize_fixture, ErrorKind};
use serde_json::{json, Map, Value as JsonValue};
use tempfile::TempDir;

const PUBLISHED_AT: &str = "2026-08-01T00:00:00Z";
const EVALUATED_AT: &str = "2026-08-02T00:00:00Z";
const CANARY: &str = "source-private-canary";

fn instant(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .expect("the test instant is RFC 3339")
        .with_timezone(&Utc)
}

fn scratch_root() -> PathBuf {
    let root = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("registry-evidence-statement-source-pack");
    std::fs::create_dir_all(&root).expect("the test scratch root is available");
    root
}

fn scratch_directory() -> TempDir {
    tempfile::Builder::new()
        .prefix("case-")
        .tempdir_in(scratch_root())
        .expect("a test directory on the build volume")
}

fn reference_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/sqlite-extract-evidence/bundle",
    )
}

fn reference_bundle() -> Bundle {
    let root = reference_root();
    let verified = registry_platform_config::verify_package(
        &root,
        &evidence_package_limits(),
        "evidencectl package",
    )
    .expect("the maintained SQLite reference package verifies");
    Bundle::load_as_found(&root, &verified).expect("the maintained SQLite reference bundle loads")
}

fn fixture(bundle: &Bundle) -> JsonValue {
    let requirement = bundle
        .config
        .requirements
        .first()
        .expect("the reference has one requirement");
    let path = requirement
        .fixtures
        .as_ref()
        .expect("the reference requirement has fixtures");
    serde_json::to_value(&bundle.fixtures[path.as_str()]).expect("fixture value")
}

fn fixture_case<'a>(fixture: &'a JsonValue, id: &str) -> &'a Map<String, JsonValue> {
    fixture["cases"]
        .as_array()
        .expect("fixture cases")
        .iter()
        .find(|case| case["id"] == id)
        .and_then(JsonValue::as_object)
        .expect("named fixture case")
}

fn captured_extract(seed_sql: &str) -> (TempDir, CapturedSnapshot) {
    let directory = scratch_directory();
    let path = directory.path().join("extract.sqlite");
    materialize_fixture(&path, seed_sql).expect("the reviewed fixture SQL materializes");
    let captured = CapturedSnapshot::capture(&path).expect("the immutable extract is captured");
    (directory, captured)
}

fn simple_extract() -> (TempDir, CapturedSnapshot) {
    captured_extract(&format!(
        "CREATE TABLE evidence_extract(published_at TEXT, publisher TEXT, extract_id TEXT); \
         INSERT INTO evidence_extract VALUES('{PUBLISHED_AT}', 'synthetic-publisher', 'extract-a'); \
         CREATE TABLE person(id TEXT, region_code TEXT, rank INTEGER, active INTEGER, note TEXT); \
         INSERT INTO person VALUES \
           ('p-1', 'nw', 1, 1, 'short'), \
           ('p-2', 'nw', 2, 0, '{CANARY} and a deliberately long private note'), \
           ('p-3', 'se', 1, 1, 'other');"
    ))
}

fn contract(sql: &str, columns: &[(&str, ColumnType)]) -> StatementContract {
    StatementContract {
        sql: sql.to_owned(),
        columns: columns
            .iter()
            .map(|(name, value_type)| ColumnContract {
                name: (*name).to_owned(),
                value_type: *value_type,
            })
            .collect(),
        parameters: Vec::new(),
        limits: StatementLimits {
            maximum_rows: 8,
            maximum_cell_bytes: 4096,
            maximum_response_bytes: 8192,
            maximum_statement_steps: 100_000,
            timeout: Duration::from_secs(2),
            concurrency: 2,
        },
        schema: None,
    }
}

fn assert_match_count(outcome: LookupResult, expected: i64) {
    assert!(
        matches!(
            outcome,
            LookupResult::Match(ref facts)
                if facts.get("active_licence_count") == Some(&json!(expected))
        ),
        "unexpected lookup outcome: {outcome:?}"
    );
}

#[derive(Default)]
struct AllowAcquisition;

impl EvidenceHostHooks for AllowAcquisition {
    fn before_acquisition<'a>(
        &'a self,
        _intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn before_credentials<'a>(&'a self, _intent: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn derived_parameter_program(
    captured: CapturedSnapshot,
) -> registry_adapter_engine::evidence::EvidenceProgram {
    use registry_platform_config::{sha256_uri, SecretProvider, SecretResolver};

    let sql = b"SELECT id, rank, :evidence_now AS observed FROM person WHERE id = :reference";
    let script = br#"fn derive_reference(exchange) {
        let reference = exchange.body.recordReference;
        reference.replace("urn:example:person:", "");
        reference
    }

    fn facts(exchange) {
        let rows = exchange.body.rows;
        if rows.len() == 0 { return #{lookup: "no-match"}; }
        if rows.len() != 1 { return #{lookup: "ambiguous"}; }
        #{lookup: "matched", facts: #{id: rows[0].id, rank: rows[0].rank, observed: rows[0].observed}}
    }"#;
    let inputs = serde_json::to_vec(&json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"recordReference": {"type": "string"}},
        "required": ["recordReference"]
    }))
    .unwrap();
    let facts = serde_json::to_vec(&json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "id": {"type": "string"},
            "rank": {"type": "integer"},
            "observed": {"type": "string"}
        },
        "required": ["id", "rank", "observed"]
    }))
    .unwrap();
    let pack: AdapterPack = serde_json::from_value(json!({
        "id": "derived-sqlite-parameter",
        "version": "1",
        "testedVersions": [],
        "endpoints": [{
            "id": "people",
            "component": "sqlite-extract",
            "authentication": {"type": "none"},
            "attemptTimeoutMilliseconds": 2000,
            "maximumResponseBytes": 8192,
            "sqliteExtract": {
                "extractProfile": "people",
                "statement": {"path": "queries/people.sql", "digest": sha256_uri(sql)},
                "columns": [
                    {"name": "id", "type": "string"},
                    {"name": "rank", "type": "integer"},
                    {"name": "observed", "type": "string"}
                ],
                "parameters": [{"name": "reference", "required": true}],
                "maximumExtractAgeSeconds": 86400,
                "maximumRows": 1,
                "maximumCellBytes": 256,
                "maximumStatementSteps": 100000,
                "concurrency": 1
            }
        }],
        "scripts": [{"path": "scripts/derived.rhai", "digest": sha256_uri(script)}],
        "sourceRoutes": [{
            "id": "person",
            "evidence": {
                "inputsSchema": {"path": "schemas/inputs.json", "digest": sha256_uri(&inputs)},
                "factsSchema": {"path": "schemas/facts.json", "digest": sha256_uri(&facts)}
            },
            "steps": [
                {"setProperty": {
                    "name": "derived-reference",
                    "value": {"rhai": {"file": "scripts/derived.rhai", "entrypoint": "derive_reference"}}
                }},
                {"to": {
                    "uri": "sqlite-extract:people",
                    "parameters": {"queryParameters": {
                        "reference": {"exchangeProperty": "derived-reference"}
                    }}
                }},
                {"setBody": {"rhai": {"file": "scripts/derived.rhai", "entrypoint": "facts"}}}
            ]
        }]
    }))
    .expect("the reviewed pack parses");
    let bindings: AdapterEndpointBindings = serde_json::from_value(json!({
        "id": "derived-runtime",
        "endpoints": [],
        "allowedPrivateCidrs": []
    }))
    .unwrap();
    let runtime = EvidenceRuntimeBindings::with_captured_sqlite(
        bindings,
        SecretResolver::new([SecretProvider::Environment], "").unwrap(),
        BTreeMap::from([("people".to_owned(), captured)]),
    );
    let artifacts = PackArtifactBytes::new([
        ("queries/people.sql".to_owned(), sql.to_vec()),
        ("scripts/derived.rhai".to_owned(), script.to_vec()),
        ("schemas/inputs.json".to_owned(), inputs),
        ("schemas/facts.json".to_owned(), facts),
    ]);
    compile_evidence(&EvidenceCompileInputs {
        pack: &pack,
        route: "person",
        runtime: &runtime,
        connection_id: None,
        connection: &[],
        pack_artifacts: &artifacts,
        limits: EvidenceLimits::default(),
    })
    .expect("the pinned-script pack compiles")
}

#[tokio::test]
async fn evidence_pack_executes_actual_sql_without_credentials_and_projects_facts() {
    let bundle = reference_bundle();
    let fixture = fixture(&bundle);
    let requirement = bundle.config.requirements.first().unwrap();
    let case = fixture_case(&fixture, "positive");
    let resolved = resolve_offline_fixture_authorization(
        &bundle,
        requirement,
        fixture["common"].as_object(),
        case,
        "urn:registry-evidence:offline-evaluation",
    )
    .expect("the fixture selector is authorized");
    let programs = compile_sources(&bundle).expect("the pack compiles without runtime credentials");
    let program = &programs[requirement.initial_source()];
    let assets = program
        .materialize_single_extract_in(
            &scratch_root(),
            fixture["common"]["extract"]
                .as_str()
                .expect("reviewed fixture SQL"),
        )
        .expect("the reviewed extract materializes");

    let run = program
        .execute_observed(
            &resolved,
            FixtureAcquisition {
                intercepts: Vec::new(),
                exchanges: Vec::new(),
            },
            Some(&assets),
            instant(EVALUATED_AT),
        )
        .await;

    assert_eq!(run.data_operations, 1);
    assert_match_count(run.outcome.expect("the SQLite pack route runs"), 1);
    assert!(bundle
        .config
        .source_connections
        .get("licence-register-extract")
        .expect("the extract connection is declared")
        .endpoints
        .is_empty());
}

#[tokio::test]
async fn evidence_pack_binds_selector_text_and_uses_one_repeatable_host_clock() {
    let bundle = reference_bundle();
    let fixture = fixture(&bundle);
    let requirement = bundle.config.requirements.first().unwrap();
    let programs = compile_sources(&bundle).expect("the source pack compiles");
    let program = &programs[requirement.initial_source()];

    let hostile = resolve_offline_fixture_authorization(
        &bundle,
        requirement,
        fixture["common"].as_object(),
        fixture_case(&fixture, "hostile-reference"),
        "urn:registry-evidence:offline-evaluation",
    )
    .expect("the hostile-shaped selector is still a valid string");
    let maintained_assets = program
        .materialize_single_extract_in(
            &scratch_root(),
            fixture["common"]["extract"].as_str().unwrap(),
        )
        .unwrap();
    assert_eq!(
        program
            .execute_with_assets(
                &hostile,
                FixtureAcquisition {
                    intercepts: Vec::new(),
                    exchanges: Vec::new(),
                },
                &maintained_assets,
                instant(EVALUATED_AT),
            )
            .await
            .expect("selector text is bound rather than parsed as SQL"),
        LookupResult::NoMatch
    );

    let positive = resolve_offline_fixture_authorization(
        &bundle,
        requirement,
        fixture["common"].as_object(),
        fixture_case(&fixture, "positive"),
        "urn:registry-evidence:offline-evaluation",
    )
    .unwrap();
    let clock_assets = program
        .materialize_single_extract_in(
            &scratch_root(),
            &format!(
                "CREATE TABLE evidence_extract(published_at TEXT, publisher TEXT, extract_id TEXT); \
                 INSERT INTO evidence_extract VALUES('{PUBLISHED_AT}', 'fixture', 'clock-window'); \
                 CREATE TABLE registrants(registrant_id TEXT, reference TEXT, contact_reference TEXT); \
                 INSERT INTO registrants VALUES('REG-1', 'REC-0001', '{CANARY}'); \
                 CREATE TABLE licences(licence_id TEXT, registrant_id TEXT, status_code TEXT, valid_from TEXT, valid_until TEXT, issuing_office TEXT); \
                 INSERT INTO licences VALUES('LIC-1', 'REG-1', 'ACTIVE', '{EVALUATED_AT}', '2026-08-02T00:00:01Z', '{CANARY}');"
            ),
        )
        .unwrap();
    let first = program
        .execute_with_assets(
            &positive,
            FixtureAcquisition {
                intercepts: Vec::new(),
                exchanges: Vec::new(),
            },
            &clock_assets,
            instant(EVALUATED_AT),
        )
        .await
        .unwrap();
    let repeated = program
        .execute_with_assets(
            &positive,
            FixtureAcquisition {
                intercepts: Vec::new(),
                exchanges: Vec::new(),
            },
            &clock_assets,
            instant(EVALUATED_AT),
        )
        .await
        .unwrap();
    assert_eq!(first, repeated);
    assert_match_count(first, 1);
    assert_match_count(
        program
            .execute_with_assets(
                &positive,
                FixtureAcquisition {
                    intercepts: Vec::new(),
                    exchanges: Vec::new(),
                },
                &clock_assets,
                instant("2026-08-02T00:00:01Z"),
            )
            .await
            .unwrap(),
        0,
    );
}

#[tokio::test]
async fn pinned_rhai_step_derives_a_typed_sqlite_parameter_before_the_send() {
    let (_directory, captured) = simple_extract();
    let program = derived_parameter_program(captured);
    let acquisition = program
        .begin_acquisition_at(Arc::new(AllowAcquisition), instant(EVALUATED_AT))
        .await
        .expect("the credential-free acquisition begins");

    assert_eq!(
        program
            .execute(
                &acquisition,
                json!({"recordReference": "urn:example:person:p-3"}),
            )
            .await
            .expect("the derived parameter reaches actual SQL"),
        EvidenceLookup::Matched {
            facts: json!({"id": "p-3", "rank": 1, "observed": EVALUATED_AT})
        }
    );

    let override_attempt = program
        .execute(
            &acquisition,
            json!({
                "recordReference": "urn:example:person:p-3",
                "evidence_now": "2099-01-01T00:00:00Z"
            }),
        )
        .await;
    assert!(
        override_attempt.is_err(),
        "a caller-supplied host-clock value must be refused"
    );
}

#[tokio::test]
async fn pack_plan_keeps_the_governed_profile_and_checks_age_before_rows() {
    let bundle = reference_bundle();
    let fixture = fixture(&bundle);
    let closure = bundle
        .source_pack("licence-register")
        .expect("the configured source has a captured pack");
    let pack = closure.pack();
    let endpoint = pack
        .endpoints
        .iter()
        .find(|endpoint| endpoint.id.as_str() == "licence-register")
        .expect("the SQLite endpoint");
    let artifacts = closure.artifacts();
    let plan = SqliteExtractPlan::compile(endpoint, &artifacts).expect("the pinned plan compiles");
    assert_eq!(plan.extract_profile(), "licence-register-extract");

    let (_directory, captured) = captured_extract(fixture["common"]["extract"].as_str().unwrap());
    let source = plan.open(captured).expect("the captured extract opens");
    let parameters = BTreeMap::from([(
        "record_reference".to_owned(),
        Value::String("REC-0007".to_owned()),
    )]);

    assert!(matches!(
        source
            .execute(&parameters, instant("2026-08-08T00:00:00Z"))
            .await,
        Err(SqliteExtractError::Statement(ErrorKind::TooManyRows))
    ));
    assert_eq!(
        source
            .execute(&parameters, instant("2026-08-08T00:00:01Z"))
            .await,
        Err(SqliteExtractError::Stale)
    );
}

#[tokio::test]
async fn shared_engine_binds_typed_parameters_and_reserves_the_host_clock() {
    let (_directory, captured) = simple_extract();
    let mut reviewed = contract(
        "SELECT id, rank, :evidence_now AS observed FROM person WHERE region_code = :region AND rank = :rank",
        &[
            ("id", ColumnType::String),
            ("rank", ColumnType::Integer),
            ("observed", ColumnType::String),
        ],
    );
    reviewed.parameters = vec![
        ParameterContract {
            name: "region".to_owned(),
            required: true,
        },
        ParameterContract {
            name: "rank".to_owned(),
            required: true,
        },
    ];
    let source = SqliteExtractSource::open(captured, reviewed, Duration::from_secs(86_400))
        .expect("the reviewed statement opens");
    let parameters = BTreeMap::from([
        ("region".to_owned(), Value::String("nw".to_owned())),
        ("rank".to_owned(), Value::Integer(2)),
    ]);

    let first = source
        .execute(&parameters, instant(EVALUATED_AT))
        .await
        .expect("typed parameters execute");
    let repeated = source
        .execute(&parameters, instant(EVALUATED_AT))
        .await
        .expect("the pinned evaluation repeats");
    assert_eq!(first, repeated);
    assert_eq!(
        first["rows"],
        json!([{"id":"p-2","rank":2,"observed":EVALUATED_AT}])
    );

    let mut overridden = parameters;
    overridden.insert(
        "evidence_now".to_owned(),
        Value::String("2099-01-01T00:00:00Z".to_owned()),
    );
    assert_eq!(
        source.execute(&overridden, instant(EVALUATED_AT)).await,
        Err(SqliteExtractError::InvalidParameters)
    );
}

#[tokio::test]
async fn shared_engine_enforces_row_cell_step_and_complete_response_bounds() {
    let (_directory, captured) = simple_extract();
    let mut rows = contract(
        "SELECT id FROM person WHERE region_code = 'nw' ORDER BY id",
        &[("id", ColumnType::String)],
    );
    rows.limits.maximum_rows = 1;
    let source = SqliteExtractSource::open(captured.clone(), rows, Duration::from_secs(86_400))
        .expect("row-bounded statement");
    assert_eq!(
        source
            .execute(&BTreeMap::new(), instant(EVALUATED_AT))
            .await,
        Err(SqliteExtractError::Statement(ErrorKind::TooManyRows))
    );

    let mut cell = contract(
        "SELECT note AS id FROM person WHERE id = 'p-2'",
        &[("id", ColumnType::String)],
    );
    cell.limits.maximum_cell_bytes = 8;
    let source = SqliteExtractSource::open(captured.clone(), cell, Duration::from_secs(86_400))
        .expect("cell-bounded statement");
    let cell_error = source
        .execute(&BTreeMap::new(), instant(EVALUATED_AT))
        .await
        .expect_err("the private cell exceeds its bound");
    assert_eq!(
        cell_error,
        SqliteExtractError::Statement(ErrorKind::CellTooLarge)
    );
    assert!(!format!("{cell_error:?} {cell_error}").contains(CANARY));

    let mut steps = contract(
        "WITH RECURSIVE counter(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM counter WHERE n < 50000000) SELECT printf('%d', COUNT(*)) AS id FROM counter",
        &[("id", ColumnType::String)],
    );
    steps.limits.maximum_statement_steps = 1_000;
    let source = SqliteExtractSource::open(captured.clone(), steps, Duration::from_secs(86_400))
        .expect("step-bounded statement");
    assert_eq!(
        source
            .execute(&BTreeMap::new(), instant(EVALUATED_AT))
            .await,
        Err(SqliteExtractError::Statement(ErrorKind::StepBudgetExceeded))
    );

    let mut response = contract(
        "SELECT id FROM person WHERE id = 'p-1'",
        &[("id", ColumnType::String)],
    );
    // The row alone fits. Publication metadata plus the response envelope does
    // not, so this proves the public component charges the complete response.
    response.limits.maximum_response_bytes = 120;
    let source = SqliteExtractSource::open(captured, response, Duration::from_secs(86_400))
        .expect("response-bounded statement");
    assert_eq!(
        source
            .execute(&BTreeMap::new(), instant(EVALUATED_AT))
            .await,
        Err(SqliteExtractError::Statement(ErrorKind::ResponseTooLarge))
    );
}

#[test]
fn shared_engine_refuses_writes_and_invalid_sql_without_rendering_source_values() {
    let (directory, captured) = simple_extract();
    let write = contract(
        "UPDATE person SET note = 'changed' RETURNING id",
        &[("id", ColumnType::String)],
    );
    let write_error =
        SqliteExtractSource::open(captured.clone(), write, Duration::from_secs(86_400))
            .err()
            .expect("mutating SQL is refused");
    assert_eq!(
        write_error,
        SqliteExtractError::Statement(ErrorKind::AuthorizerRefused)
    );

    let invalid = contract(
        &format!("SELECT private_canary_column FROM person WHERE note = '{CANARY}'"),
        &[("id", ColumnType::String)],
    );
    let invalid_error = SqliteExtractSource::open(captured, invalid, Duration::from_secs(86_400))
        .err()
        .expect("an unknown column is refused");
    assert_eq!(
        invalid_error,
        SqliteExtractError::Statement(ErrorKind::UnknownColumn)
    );
    let rendered = format!("{invalid_error:?} {invalid_error}");
    assert!(
        !rendered.contains(CANARY),
        "diagnostic disclosed SQL: {rendered}"
    );
    assert!(
        !rendered.contains(directory.path().to_string_lossy().as_ref()),
        "diagnostic disclosed the extract path: {rendered}"
    );
}
