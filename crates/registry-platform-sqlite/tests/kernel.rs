use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use registry_platform_sqlite::{
    inspect_schema, CapturedSnapshot, ColumnContract, ColumnType, DatabaseProfile,
    DatabaseProfileKind, ErrorKind, InspectionLimits, LiveDatabaseFile, ParameterContract,
    ReadOnlyStatement, SchemaBinding, StatementContract, StatementLimits, Value,
};
use rusqlite::Connection;
use tempfile::TempDir;

fn database(directory: &TempDir) -> std::path::PathBuf {
    let path = directory.path().join("source.sqlite");
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TABLE records (id TEXT, active INTEGER); INSERT INTO records VALUES ('one', 1), ('two', 0);").unwrap();
    connection.close().unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[cfg(unix)]
fn make_writable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn make_writable(path: &std::path::Path) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).unwrap();
}

fn contract(sql: &str) -> StatementContract {
    StatementContract {
        sql: sql.to_owned(),
        columns: vec![ColumnContract {
            name: "id".to_owned(),
            value_type: ColumnType::String,
        }],
        parameters: vec![ParameterContract {
            name: "active".to_owned(),
            required: true,
        }],
        limits: StatementLimits {
            maximum_rows: 2,
            maximum_cell_bytes: 32,
            maximum_response_bytes: 64,
            maximum_statement_steps: 100_000,
            timeout: Duration::from_secs(1),
            concurrency: 1,
        },
        schema: None,
    }
}

#[tokio::test]
async fn a_snapshot_is_digest_bound_and_read_immutably() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    assert!(snapshot.digest().starts_with("sha256:"));
    let expected_revision = snapshot.digest().to_owned();
    let statement = ReadOnlyStatement::open(
        DatabaseProfile::Snapshot(snapshot),
        contract("SELECT id FROM records WHERE active = :active ORDER BY id"),
    )
    .unwrap();
    let rows = statement
        .execute(&BTreeMap::from([(
            "active".to_owned(),
            Value::Boolean(true),
        )]))
        .await
        .unwrap();
    assert_eq!(rows.rows[0]["id"], Value::String("one".to_owned()));
    assert_eq!(rows.provenance.profile, DatabaseProfileKind::Snapshot);
    assert_eq!(
        rows.provenance.source_revision.as_deref(),
        Some(expected_revision.as_str())
    );
    assert!(rows.provenance.statement_digest.starts_with("sha256:"));
}

#[test]
fn every_mutating_or_connection_widening_action_is_refused() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    for sql in [
        "DELETE FROM records RETURNING id",
        "SELECT id FROM records; ATTACH ':memory:' AS extra",
        "PRAGMA table_info(records)",
    ] {
        let error =
            ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot.clone()), contract(sql))
                .err()
                .unwrap();
        assert!(matches!(
            error.kind(),
            ErrorKind::AuthorizerRefused | ErrorKind::MultipleStatements
        ));
    }
}

#[test]
fn clock_and_random_functions_are_refused() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    for sql in [
        "SELECT random() AS id FROM records",
        "SELECT datetime('now') AS id FROM records",
    ] {
        assert_eq!(
            ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot.clone()), contract(sql))
                .err()
                .unwrap()
                .kind(),
            ErrorKind::AuthorizerRefused
        );
    }
}

#[tokio::test]
async fn row_cell_and_response_bounds_are_enforced() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    let mut bounded = contract("SELECT id FROM records WHERE active >= :active ORDER BY id");
    bounded.limits.maximum_rows = 1;
    let statement =
        ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot.clone()), bounded).unwrap();
    assert_eq!(
        statement
            .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(0))]))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::TooManyRows
    );
    let mut bounded = contract("SELECT id FROM records WHERE active >= :active ORDER BY id");
    bounded.limits.maximum_cell_bytes = 2;
    let statement =
        ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot.clone()), bounded).unwrap();
    assert_eq!(
        statement
            .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(0))]))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::CellTooLarge
    );
    let mut bounded = contract("SELECT id FROM records WHERE active >= :active ORDER BY id");
    bounded.limits.maximum_response_bytes = 4;
    let statement = ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot), bounded).unwrap();
    assert_eq!(
        statement
            .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(0))]))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::ResponseTooLarge
    );
}

#[tokio::test]
async fn null_and_column_structure_count_toward_the_response_bound() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    let mut bounded = contract(
        "WITH RECURSIVE rows(n) AS (\
             SELECT 1 UNION ALL SELECT n + 1 FROM rows WHERE n < 20\
         ) SELECT NULL AS a_deliberately_long_structural_column_name FROM rows \
         WHERE :active = :active",
    );
    bounded.columns[0] = ColumnContract {
        name: "a_deliberately_long_structural_column_name".to_owned(),
        value_type: ColumnType::String,
    };
    bounded.limits.maximum_rows = 100;
    bounded.limits.maximum_response_bytes = 128;
    let statement =
        ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot.clone()), bounded).unwrap();
    assert_eq!(
        statement
            .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(1))]))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::ResponseTooLarge
    );

    let mut empty = contract("SELECT id FROM records WHERE active > :active");
    empty.limits.maximum_response_bytes = 1;
    let statement = ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot), empty).unwrap();
    assert_eq!(
        statement
            .execute(&BTreeMap::from([(
                "active".to_owned(),
                Value::Integer(i64::MAX),
            )]))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::ResponseTooLarge
    );
}

#[test]
fn snapshot_sidecars_and_path_replacement_fail_closed() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    fs::write(format!("{}-wal", path.display()), b"sidecar").unwrap();
    assert_eq!(
        CapturedSnapshot::capture(&path).unwrap_err().kind(),
        ErrorKind::UncheckpointedSidecar
    );
    fs::remove_file(format!("{}-wal", path.display())).unwrap();
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    fs::write(format!("{}-journal", path.display()), b"sidecar").unwrap();
    assert_eq!(
        snapshot.confirm_still_bound().unwrap_err().kind(),
        ErrorKind::UncheckpointedSidecar
    );
    fs::remove_file(format!("{}-journal", path.display())).unwrap();
    fs::rename(&path, directory.path().join("old.sqlite")).unwrap();
    let replacement = database(&directory);
    assert_eq!(replacement, path);
    assert_eq!(
        snapshot.confirm_still_bound().unwrap_err().kind(),
        ErrorKind::DatabaseReplaced
    );
}

#[test]
fn snapshot_readiness_rehashes_the_exact_captured_bytes() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    snapshot.verify_unchanged().unwrap();

    make_writable(&path);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute("UPDATE records SET active = 0 WHERE id = 'one'", [])
        .unwrap();
    connection.close().unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).unwrap();

    let error = snapshot.verify_unchanged().unwrap_err();
    assert!(matches!(
        error.kind(),
        ErrorKind::DatabaseChanged | ErrorKind::DatabaseReplaced
    ));
    assert!(!error.to_string().contains(path.to_string_lossy().as_ref()));
    assert!(!error.to_string().contains("one"));
}

#[tokio::test]
async fn the_step_budget_interrupts_an_expensive_statement_and_the_pool_recovers() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    let mut bounded = contract(
        "WITH RECURSIVE counter(n) AS (\
             SELECT 1 UNION ALL SELECT n + 1 FROM counter \
             WHERE n < CASE WHEN :active = 1 THEN 50000000 ELSE 1 END\
         ) SELECT printf('%d', COUNT(*)) AS id FROM counter WHERE :active = :active",
    );
    bounded.limits.maximum_statement_steps = 1_000;
    let statement = ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot), bounded).unwrap();
    let error = statement
        .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(1))]))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::StepBudgetExceeded);
    let recovered = statement
        .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(0))]))
        .await
        .expect("the interrupted connection returns cleanly to the pool");
    assert_eq!(recovered.rows[0]["id"], Value::String("1".to_owned()));
}

#[tokio::test]
async fn the_time_budget_interrupts_an_expensive_statement_and_the_pool_recovers() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    let mut bounded = contract(
        "WITH RECURSIVE counter(n) AS (\
             SELECT 1 UNION ALL SELECT n + 1 FROM counter \
             WHERE n < CASE WHEN :active = 1 THEN 50000000 ELSE 1 END\
         ) SELECT printf('%d', COUNT(*)) AS id FROM counter WHERE :active = :active",
    );
    bounded.limits.maximum_statement_steps = 100_000_000;
    bounded.limits.timeout = Duration::from_millis(25);
    let statement = ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot), bounded).unwrap();
    let error = statement
        .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(1))]))
        .await
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        ErrorKind::TimeBudgetExceeded | ErrorKind::Timeout
    ));
    let recovered = statement
        .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(0))]))
        .await
        .expect("the timed-out connection returns cleanly to the pool");
    assert_eq!(recovered.rows[0]["id"], Value::String("1".to_owned()));
}

#[cfg(feature = "fixture")]
#[tokio::test]
async fn queue_time_is_bounded_and_admission_recovers() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    let mut bounded = contract("SELECT id FROM records WHERE active = :active ORDER BY id");
    bounded.limits.timeout = Duration::from_millis(10);
    let statement = ReadOnlyStatement::open(DatabaseProfile::Snapshot(snapshot), bounded).unwrap();
    let held = statement.hold_all_permits_for_test().await.unwrap();
    let error = statement
        .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(1))]))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Timeout);

    drop(held);
    let result = statement
        .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(1))]))
        .await
        .unwrap();
    assert_eq!(result.rows.len(), 1);
}

#[test]
fn live_reads_allow_content_updates_but_refuse_path_replacement() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let live = LiveDatabaseFile::bind(&path).unwrap();
    live.confirm_still_bound().unwrap();
    fs::rename(&path, directory.path().join("old.sqlite")).unwrap();
    let replacement = database(&directory);
    assert_eq!(replacement, path);
    assert_eq!(
        live.confirm_still_bound().unwrap_err().kind(),
        ErrorKind::DatabaseReplaced
    );
}

#[tokio::test]
async fn live_reads_require_and_reverify_the_schema_inside_each_read() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    make_writable(&path);

    let live = LiveDatabaseFile::bind(&path).unwrap();
    let profile = DatabaseProfile::LiveReadOnly(live);
    let limits = InspectionLimits {
        maximum_objects: 16,
        maximum_sql_bytes: 4096,
        maximum_statement_steps: 100_000,
        timeout: Duration::from_secs(1),
    };
    let catalog = inspect_schema(&profile, &limits).unwrap();

    let missing = ReadOnlyStatement::open(
        profile.clone(),
        contract("SELECT id FROM records WHERE active = :active ORDER BY id"),
    )
    .err()
    .unwrap();
    assert_eq!(missing.kind(), ErrorKind::InvalidPlan);

    let mut bound = contract("SELECT id FROM records WHERE active = :active ORDER BY id");
    bound.schema = Some(SchemaBinding {
        expected_fingerprint: catalog.fingerprint.clone(),
        maximum_objects: limits.maximum_objects,
        maximum_sql_bytes: limits.maximum_sql_bytes,
    });
    let statement = ReadOnlyStatement::open(profile, bound).unwrap();

    let connection = Connection::open(&path).unwrap();
    connection
        .execute("INSERT INTO records VALUES ('three', 1)", [])
        .unwrap();
    connection.close().unwrap();
    let result = statement
        .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(1))]))
        .await
        .unwrap();
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.provenance.profile, DatabaseProfileKind::LiveReadOnly);
    assert_eq!(result.provenance.source_revision, None);
    assert_eq!(
        result.provenance.schema_fingerprint.as_deref(),
        Some(catalog.fingerprint.as_str())
    );

    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("ALTER TABLE records ADD COLUMN protected_value TEXT")
        .unwrap();
    connection.close().unwrap();
    let error = statement
        .execute(&BTreeMap::from([("active".to_owned(), Value::Integer(1))]))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::SchemaMismatch);
    assert!(!error.to_string().contains("protected_value"));
}

#[test]
fn schema_inspection_is_ordered_bounded_and_fingerprinted() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    let catalog = inspect_schema(
        &DatabaseProfile::Snapshot(snapshot),
        &InspectionLimits {
            maximum_objects: 16,
            maximum_sql_bytes: 4096,
            maximum_statement_steps: 100_000,
            timeout: Duration::from_secs(1),
        },
    )
    .unwrap();
    assert!(catalog.fingerprint.starts_with("sha256:"));
    assert_eq!(catalog.objects[0].name, "records");
    assert_eq!(
        catalog.objects[0]
            .columns
            .iter()
            .map(|column| (
                column.name.as_str(),
                column.declared_type.as_str(),
                column.nullable,
                column.primary_key,
            ))
            .collect::<Vec<_>>(),
        vec![
            ("id", "TEXT", true, false),
            ("active", "INTEGER", true, false),
        ]
    );
    let rendered = format!("{catalog:?}");
    assert!(!rendered.contains("one"));
    assert!(!rendered.contains("two"));
}

#[test]
fn errors_never_render_sql_paths_or_values() {
    let directory = TempDir::new().unwrap();
    let path = database(&directory);
    let snapshot = CapturedSnapshot::capture(&path).unwrap();
    let error = ReadOnlyStatement::open(
        DatabaseProfile::Snapshot(snapshot),
        contract("SELECT secret_column FROM records WHERE id = 'protected-value'"),
    )
    .err()
    .unwrap();
    let rendered = error.to_string();
    assert!(!rendered.contains("secret_column"));
    assert!(!rendered.contains("protected-value"));
    assert!(!rendered.contains(path.to_string_lossy().as_ref()));
}
