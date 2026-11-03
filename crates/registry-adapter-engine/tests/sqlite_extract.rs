#![cfg(feature = "sqlite-extract")]

use std::{collections::BTreeMap, time::Duration};

use chrono::{DateTime, Utc};
use registry_adapter_engine::component::sqlite_extract::{SqliteExtractError, SqliteExtractSource};
use registry_platform_sqlite::{
    materialize_fixture, CapturedSnapshot, ColumnContract, ColumnType, ParameterContract,
    StatementContract, StatementLimits, Value,
};
use serde_json::json;

fn instant(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .unwrap()
        .with_timezone(&Utc)
}

fn contract(sql: &str) -> StatementContract {
    StatementContract {
        sql: sql.to_owned(),
        columns: vec![
            ColumnContract {
                name: "id".to_owned(),
                value_type: ColumnType::String,
            },
            ColumnContract {
                name: "active".to_owned(),
                value_type: ColumnType::Boolean,
            },
            ColumnContract {
                name: "observed_at".to_owned(),
                value_type: ColumnType::String,
            },
        ],
        parameters: vec![
            ParameterContract {
                name: "id".to_owned(),
                required: true,
            },
            ParameterContract {
                name: "evidence_now".to_owned(),
                required: false,
            },
        ],
        limits: StatementLimits {
            maximum_rows: 2,
            maximum_cell_bytes: 1024,
            maximum_response_bytes: 8192,
            maximum_statement_steps: 100_000,
            timeout: Duration::from_secs(2),
            concurrency: 2,
        },
        schema: None,
    }
}

fn extract() -> (tempfile::TempDir, CapturedSnapshot) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("extract.sqlite");
    materialize_fixture(&path, "CREATE TABLE evidence_extract(published_at TEXT, publisher TEXT, extract_id TEXT); INSERT INTO evidence_extract VALUES('2026-10-31T12:00:00Z', 'synthetic-publisher', 'extract-a'); CREATE TABLE people(id TEXT, active INTEGER); INSERT INTO people VALUES('0007', 1);").unwrap();
    let captured = CapturedSnapshot::capture(&path).unwrap();
    (directory, captured)
}

fn slow_metadata_extract() -> (tempfile::TempDir, CapturedSnapshot) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("extract.sqlite");
    materialize_fixture(
        &path,
        "CREATE TABLE people(id TEXT, active INTEGER); \
         INSERT INTO people VALUES('0007', 1); \
         CREATE VIEW evidence_extract AS \
         WITH RECURSIVE counter(n) AS ( \
             SELECT 1 UNION ALL SELECT n + 1 FROM counter WHERE n < 50000000 \
         ) \
         SELECT '2026-10-31T12:00:00Z' AS published_at, \
                'synthetic-publisher' AS publisher, \
                'slow-extract' AS extract_id \
         FROM counter WHERE n = 50000000;",
    )
    .unwrap();
    let captured = CapturedSnapshot::capture(&path).unwrap();
    (directory, captured)
}

#[tokio::test]
async fn executes_reviewed_sql_with_typed_parameters_and_one_host_clock() {
    let (_directory, captured) = extract();
    let source = SqliteExtractSource::open(
        captured,
        contract("SELECT id, active, :evidence_now AS observed_at FROM people WHERE id = :id"),
        Duration::from_secs(3600),
    )
    .unwrap();
    let parameters = BTreeMap::from([("id".to_owned(), Value::String("0007".to_owned()))]);
    let result = source
        .execute(&parameters, instant("2026-10-31T12:30:00Z"))
        .await
        .unwrap();
    assert_eq!(
        result,
        json!({"rows":[{"id":"0007","active":true,"observed_at":"2026-10-31T12:30:00Z"}],"extract":{"publishedAt":"2026-10-31T12:00:00Z","publisher":"synthetic-publisher","extractId":"extract-a"}})
    );
}

#[tokio::test]
async fn stale_extract_and_attempted_clock_override_are_refused() {
    let (_directory, captured) = extract();
    let source = SqliteExtractSource::open(
        captured,
        contract("SELECT id, active, :evidence_now AS observed_at FROM people WHERE id = :id"),
        Duration::from_secs(3600),
    )
    .unwrap();
    let mut parameters = BTreeMap::from([("id".to_owned(), Value::String("0007".to_owned()))]);
    assert!(matches!(
        source
            .execute(&parameters, instant("2026-10-31T13:00:01Z"))
            .await,
        Err(SqliteExtractError::Stale)
    ));
    parameters.insert(
        "evidence_now".to_owned(),
        Value::String("2099-01-01T00:00:00Z".to_owned()),
    );
    assert!(matches!(
        source
            .execute(&parameters, instant("2026-10-31T12:30:00Z"))
            .await,
        Err(SqliteExtractError::InvalidParameters)
    ));
}

#[test]
fn write_statement_is_refused_by_the_platform_authorizer() {
    let (_directory, captured) = extract();
    let result = SqliteExtractSource::open(captured, contract("UPDATE people SET active = 0 WHERE id = :id RETURNING id, active, :evidence_now AS observed_at"), Duration::from_secs(3600));
    assert!(result.is_err());
}

#[tokio::test]
async fn response_limit_includes_publication_metadata_and_row_framing() {
    let (_directory, captured) = extract();
    let mut reviewed =
        contract("SELECT id, active, :evidence_now AS observed_at FROM people WHERE id = :id");
    reviewed.limits.maximum_response_bytes = 150;
    let source = SqliteExtractSource::open(captured, reviewed, Duration::from_secs(3600)).unwrap();
    let parameters = BTreeMap::from([("id".to_owned(), Value::String("0007".to_owned()))]);
    assert!(matches!(
        source
            .execute(&parameters, instant("2026-10-31T12:30:00Z"))
            .await,
        Err(SqliteExtractError::Statement(
            registry_platform_sqlite::ErrorKind::ResponseTooLarge
        ))
    ));
}

#[test]
fn reviewed_plan_checks_pinned_sql_before_any_extract_read() {
    use registry_adapter_core::Endpoint;
    use registry_adapter_engine::{
        artifacts::PackArtifactBytes, component::sqlite_extract::SqliteExtractPlan,
    };
    let sql = b"SELECT id FROM people WHERE id = :id";
    let endpoint: Endpoint = serde_json::from_value(json!({
        "id":"people", "component":"sqlite-extract", "authentication":{"type":"none"},
        "attemptTimeoutMilliseconds":2000,"maximumResponseBytes":8192,
        "sqliteExtract":{
            "extractProfile":"people", "statement":{"path":"queries/people.sql","digest":registry_platform_config::sha256_uri(sql)},
            "columns":[{"name":"id","type":"string"}],"parameters":[{"name":"id","required":true}],
            "maximumExtractAgeSeconds":3600,"maximumRows":2,"maximumCellBytes":1024,"maximumStatementSteps":100000,"concurrency":4
        }
    })).unwrap();
    let exact = PackArtifactBytes::new([("queries/people.sql".to_owned(), sql.to_vec())]);
    assert!(SqliteExtractPlan::compile(&endpoint, &exact).is_ok());
    let changed = PackArtifactBytes::new([(
        "queries/people.sql".to_owned(),
        b"UPDATE people SET id = 'other'".to_vec(),
    )]);
    assert!(matches!(
        SqliteExtractPlan::compile(&endpoint, &changed),
        Err(SqliteExtractError::InvalidPlan)
    ));
}

use registry_adapter_engine::evidence::{
    compile_evidence, EvidenceAcquisitionIntent, EvidenceBeginError, EvidenceCompileInputs,
    EvidenceHookError, EvidenceHookFuture, EvidenceHostHooks, EvidenceLimits, EvidenceLookup,
    EvidenceProgram, EvidenceRuntimeBindings, EvidenceSendIntent, EvidenceTerminalError,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Default)]
struct AuditGate {
    acquisitions: AtomicUsize,
    sends: AtomicUsize,
    refuse: bool,
}
impl EvidenceHostHooks for AuditGate {
    fn before_acquisition<'a>(&'a self, _: EvidenceAcquisitionIntent) -> EvidenceHookFuture<'a> {
        Box::pin(async {
            self.acquisitions.fetch_add(1, Ordering::SeqCst);
            if self.refuse {
                Err(EvidenceHookError::Audit)
            } else {
                Ok(())
            }
        })
    }
    fn before_credentials<'a>(&'a self, _: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
        Box::pin(async {
            self.sends.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

fn sqlite_program(captured: CapturedSnapshot, limits: EvidenceLimits) -> EvidenceProgram {
    use registry_adapter_core::{AdapterEndpointBindings, AdapterPack};
    use registry_adapter_engine::artifacts::PackArtifactBytes;
    use registry_platform_config::{sha256_uri, SecretProvider, SecretResolver};
    let sql = b"SELECT id, active, :evidence_now AS observed_at FROM people WHERE id = :id";
    let script = br#"fn facts(exchange) {
        let rows = exchange.body.rows;
        if rows.len() == 0 { return #{lookup: "no-match"}; }
        if rows.len() != 1 { return #{lookup: "ambiguous"}; }
        #{lookup: "matched", facts: #{id: rows[0].id, active: rows[0].active, observed_at: rows[0].observed_at}}
    }"#;
    let inputs = serde_json::to_vec(&json!({"type":"object","additionalProperties":false,"properties":{"id":{"type":"string"}},"required":["id"]})).unwrap();
    let facts = serde_json::to_vec(&json!({"type":"object","additionalProperties":false,"properties":{"id":{"type":"string"},"active":{"type":"boolean"},"observed_at":{"type":"string"}},"required":["id","active","observed_at"]})).unwrap();
    let pack: AdapterPack = serde_json::from_value(json!({
        "id":"extract-evidence","version":"0.1.0","testedVersions":[],
        "endpoints":[{"id":"people","component":"sqlite-extract","authentication":{"type":"none"},
            "attemptTimeoutMilliseconds":2000,"maximumResponseBytes":8192,
            "sqliteExtract":{"extractProfile":"people","statement":{"path":"queries/people.sql","digest":sha256_uri(sql)},
                "columns":[{"name":"id","type":"string"},{"name":"active","type":"boolean"},{"name":"observed_at","type":"string"}],
                "parameters":[{"name":"id","required":true}],"maximumExtractAgeSeconds":3600,"maximumRows":2,
                "maximumCellBytes":1024,"maximumStatementSteps":100000,"concurrency":4}}],
        "scripts":[{"path":"scripts/facts.rhai","digest":sha256_uri(script)}],
        "sourceRoutes":[{"id":"person","evidence":{
            "inputsSchema":{"path":"schemas/inputs.json","digest":sha256_uri(&inputs)},
            "factsSchema":{"path":"schemas/facts.json","digest":sha256_uri(&facts)}},"steps":[
                {"to":{"uri":"sqlite-extract:people","parameters":{"queryParameters":{"id":{"jsonpath":"$.id"}}}}},
                {"setBody":{"rhai":{"file":"scripts/facts.rhai","entrypoint":"facts"}}}
            ]}]
    })).unwrap();
    let bindings: AdapterEndpointBindings = serde_json::from_value(
        json!({"id":"extract-runtime","endpoints":[],"allowedPrivateCidrs":[]}),
    )
    .unwrap();
    let runtime = EvidenceRuntimeBindings::with_captured_sqlite(
        bindings,
        SecretResolver::new([SecretProvider::Environment], "").unwrap(),
        BTreeMap::from([("people".to_owned(), captured)]),
    );
    let artifacts = PackArtifactBytes::new([
        ("queries/people.sql".to_owned(), sql.to_vec()),
        ("scripts/facts.rhai".to_owned(), script.to_vec()),
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
        limits,
    })
    .unwrap()
}

#[tokio::test]
async fn program_preflight_reports_age_but_readiness_ignores_staleness_and_runs_no_query() {
    let (_directory, captured) = extract();
    let program = sqlite_program(captured, EvidenceLimits::default());

    assert!(!program
        .probe_extract_freshness(instant("2026-10-31T12:30:00Z"))
        .expect("fresh metadata opens"));
    assert!(program
        .probe_extract_freshness(instant("2026-10-31T13:00:01Z"))
        .expect("stale metadata remains readable"));
    // The reviewed statement requires `id`. Readiness succeeding without
    // fabricated inputs proves it opened metadata and did not run the Source
    // data query; staleness remains a separate operator decision.
    program
        .credentials_ready()
        .await
        .expect("metadata-only SQLite readiness succeeds even when stale");
}

#[tokio::test]
async fn evidence_route_reads_captured_sqlite_under_one_audit_and_aggregate_budget() {
    let (_directory, captured) = extract();
    let program = sqlite_program(captured, EvidenceLimits::try_new(1, 30_000, 8192).unwrap());
    let audit = Arc::new(AuditGate::default());
    let acquisition = program
        .begin_acquisition_at(audit.clone(), instant("2026-10-31T12:30:00Z"))
        .await
        .unwrap();
    assert_eq!(
        program
            .execute(&acquisition, json!({"id":"0007"}))
            .await
            .unwrap(),
        EvidenceLookup::Matched {
            facts: json!({"id":"0007","active":true,"observed_at":"2026-10-31T12:30:00Z"})
        }
    );
    assert!(program
        .execute(&acquisition, json!({"id":"0007"}))
        .await
        .is_err());
    assert_eq!(audit.acquisitions.load(Ordering::SeqCst), 1);
    assert_eq!(audit.sends.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn audit_refusal_precedes_extract_open_and_no_match_is_explicit() {
    let (_directory, captured) = extract();
    let program = sqlite_program(captured, EvidenceLimits::default());
    let audit = Arc::new(AuditGate::default());
    let acquisition = program
        .begin_acquisition_at(audit, instant("2026-10-31T12:30:00Z"))
        .await
        .unwrap();
    assert_eq!(
        program
            .execute(&acquisition, json!({"id":"absent"}))
            .await
            .unwrap(),
        EvidenceLookup::NoMatch
    );
    let (other, captured) = extract();
    let unopened = sqlite_program(captured, EvidenceLimits::default());
    std::fs::rename(
        other.path().join("extract.sqlite"),
        other.path().join("captured-before-replacement.sqlite"),
    )
    .unwrap();
    std::fs::write(
        other.path().join("extract.sqlite"),
        b"invalidated synthetic snapshot",
    )
    .unwrap();
    let denied = Arc::new(AuditGate {
        refuse: true,
        ..AuditGate::default()
    });
    assert!(matches!(
        unopened
            .begin_acquisition_at(denied.clone(), instant("2026-10-31T12:30:00Z"))
            .await,
        Err(EvidenceBeginError::Terminal(EvidenceTerminalError::Audit))
    ));
    assert_eq!(denied.sends.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stale_route_keeps_an_actionable_value_free_failure_category() {
    use registry_adapter_engine::evidence::EvidenceExecutionError;
    let (_directory, captured) = extract();
    let program = sqlite_program(captured, EvidenceLimits::default());
    let acquisition = program
        .begin_acquisition_at(
            Arc::new(AuditGate::default()),
            instant("2026-10-31T13:00:01Z"),
        )
        .await
        .unwrap();
    let Err(EvidenceExecutionError::Sqlite(error)) =
        program.execute(&acquisition, json!({"id":"0007"})).await
    else {
        panic!("a stale extract must refuse the route");
    };
    assert_eq!(error.code(), "adapter.sqlite.extract-stale");
    assert_eq!(error.artifact(), "people");
    assert!(!format!("{error:?} {error}").contains("people"));
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_slow_metadata_initialization_is_nonblocking_and_budget_wins() {
    let (_directory, captured) = slow_metadata_extract();
    let program = sqlite_program(
        captured,
        EvidenceLimits::try_new(1, 1, 8192).expect("one-millisecond acquisition budget"),
    );
    let ticks = Arc::new(AtomicUsize::new(0));
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let observed_ticks = Arc::clone(&ticks);
    let observed_running = Arc::clone(&running);
    let ticker = tokio::spawn(async move {
        while observed_running.load(Ordering::SeqCst) {
            observed_ticks.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
        }
    });
    tokio::task::yield_now().await;
    let before = ticks.load(Ordering::SeqCst);
    let first_hooks = Arc::new(AuditGate::default());
    let second_hooks = Arc::new(AuditGate::default());

    let (first, second) = tokio::join!(
        program.begin_acquisition_at(first_hooks.clone(), instant("2026-10-31T12:30:00Z")),
        program.begin_acquisition_at(second_hooks.clone(), instant("2026-10-31T12:30:00Z"))
    );
    let budget = |result: Result<_, EvidenceBeginError>| {
        assert!(matches!(
            result,
            Err(EvidenceBeginError::Terminal(EvidenceTerminalError::Budget))
        ));
    };
    budget(first);
    budget(second);
    assert!(
        ticks.load(Ordering::SeqCst) > before,
        "SQLite metadata initialization blocked the Tokio worker"
    );
    assert_eq!(first_hooks.sends.load(Ordering::SeqCst), 0);
    assert_eq!(second_hooks.sends.load(Ordering::SeqCst), 0);
    running.store(false, Ordering::SeqCst);
    ticker.await.expect("ticker stops");
}

#[tokio::test]
async fn concurrent_initialization_runs_one_verification_sequence_and_requests_do_not_rescan() {
    let (_directory, captured) = extract();
    let digest_probe = captured.clone();
    let program = sqlite_program(captured, EvidenceLimits::default());
    assert_eq!(digest_probe.digest_verification_count_for_test(), 0);
    let first_hooks = Arc::new(AuditGate::default());
    let second_hooks = Arc::new(AuditGate::default());

    let (first, second) = tokio::join!(
        program.begin_acquisition_at(first_hooks.clone(), instant("2026-10-31T12:30:00Z")),
        program.begin_acquisition_at(second_hooks.clone(), instant("2026-10-31T12:30:00Z"))
    );
    let first = first.expect("first acquisition");
    let second = second.expect("second acquisition");
    assert_eq!(
        digest_probe.digest_verification_count_for_test(),
        2,
        "one concurrent initialization verifies the data and metadata statements once"
    );

    let (first_lookup, second_lookup) = tokio::join!(
        program.execute(&first, json!({"id":"0007"})),
        program.execute(&second, json!({"id":"0007"}))
    );
    assert!(first_lookup.is_ok());
    assert!(second_lookup.is_ok());
    assert_eq!(first_hooks.sends.load(Ordering::SeqCst), 1);
    assert_eq!(second_hooks.sends.load(Ordering::SeqCst), 1);
    assert_eq!(
        digest_probe.digest_verification_count_for_test(),
        2,
        "request execution retains cheap binding checks without a full rescan"
    );
}
