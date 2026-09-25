// SPDX-License-Identifier: Apache-2.0

//! Conformance gate for the versioned `caseworkctl --format json` reports.

use super::*;
use jsonschema::{Draft, Validator};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root resolves")
}

fn invoke(arguments: impl IntoIterator<Item = OsString>) -> (ExitCode, Value) {
    let mut args = vec![
        OsString::from("caseworkctl"),
        OsString::from("--format=json"),
    ];
    args.extend(arguments);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = main_entry_from(args, &mut stdout, &mut stderr);
    assert!(
        stderr.is_empty(),
        "JSON command wrote stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    let report = serde_json::from_slice(&stdout).unwrap_or_else(|error| {
        panic!(
            "command stdout is JSON: {error}: {}",
            String::from_utf8_lossy(&stdout)
        )
    });
    (exit, report)
}

fn arguments(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn project_arguments(command: &str, project: &Path) -> Vec<OsString> {
    vec![OsString::from(command), project.as_os_str().to_owned()]
}

fn assert_matches_contract(label: &str, kind: &str, report: &Value) {
    assert_eq!(
        report["apiVersion"], CLI_API_VERSION,
        "{label}: {report:#?}"
    );
    assert_eq!(report["kind"], kind, "{label}: {report:#?}");
    let path = repo_root()
        .join("products/casework/contracts/cli")
        .join(format!("{kind}.schema.json"));
    let schema: Value = serde_json::from_slice(
        &std::fs::read(&path).unwrap_or_else(|error| panic!("schema {path:?} reads: {error}")),
    )
    .unwrap_or_else(|error| panic!("schema {path:?} parses: {error}"));
    let compiled = Validator::options()
        .with_draft(Draft::Draft202012)
        .build(&schema)
        .unwrap_or_else(|error| panic!("schema {path:?} compiles: {error}"));
    let validation = compiled.validate(report);
    if let Err(errors) = validation {
        let details = errors
            .map(|error| format!("  - {}: {error}", error.instance_path))
            .collect::<Vec<_>>()
            .join("\n");
        panic!("{label}: {kind} does not satisfy its schema:\n{details}\n{report:#?}");
    }
}

#[test]
fn generated_schemas_are_current() {
    let status = ProcessCommand::new("python3")
        .arg(repo_root().join("products/casework/scripts/generate_cli_schemas.py"))
        .arg("--check")
        .status()
        .expect("Python starts for the schema freshness check");
    assert!(status.success(), "generated caseworkctl schemas are stale");
}

#[test]
fn every_public_json_report_matches_its_schema() {
    let root = tempfile::tempdir().expect("temporary contract fixture root");
    let project = root.path().join("standalone");
    let missing = root.path().join("missing");
    let mut reports = Vec::new();

    let (exit, init) = invoke(vec![
        OsString::from("init"),
        project.as_os_str().to_owned(),
        OsString::from("--template"),
        OsString::from("standalone-decision"),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS);
    reports.push(("init", "InitReport", init));

    for (label, kind, command) in [
        ("check", "CheckReport", "check"),
        ("explain", "ExplainReport", "explain"),
        ("test", "TestReport", "test"),
    ] {
        let (exit, report) = invoke(project_arguments(command, &project));
        assert_eq!(exit, ExitCode::SUCCESS, "{label}: {report:#?}");
        reports.push((label, kind, report));
    }

    let (exit, lifecycle) = invoke(arguments(&["lifecycle"]));
    assert_eq!(exit, ExitCode::SUCCESS);
    reports.push(("lifecycle", "LifecycleReport", lifecycle));

    let (exit, package) = invoke(vec![
        OsString::from("package"),
        project.as_os_str().to_owned(),
        OsString::from("--dry-run"),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{package:#?}");
    reports.push(("package", "PackageReport", package));

    let example = repo_root().join("products/casework/examples/multi-stage-routing-clocks");
    let (exit, simulation) = invoke(vec![
        OsString::from("simulate"),
        example.as_os_str().to_owned(),
        OsString::from("--fixture"),
        example
            .join("simulations/friday-review.yaml")
            .into_os_string(),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{simulation:#?}");
    reports.push(("simulate", "SimulationReport", simulation));

    let (exit, identity) = invoke(arguments(&["dev", "identity", "contract-reader"]));
    assert_eq!(exit, ExitCode::SUCCESS, "{identity:#?}");
    reports.push(("dev identity", "DevIdentityReport", identity));

    let failure_commands = [
        (
            "attempt settle",
            "AttemptSettlementReport",
            vec![
                "attempt",
                "settle",
                missing.to_str().unwrap(),
                "--attempt-id",
                "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                "--outcome",
                "not-applied",
                "--reason",
                "contract fixture",
                "--decided-by",
                "contract test",
            ],
        ),
        (
            "attempt mark-uncertain",
            "AttemptUncertainMarkingReport",
            vec![
                "attempt",
                "mark-uncertain",
                missing.to_str().unwrap(),
                "--attempt-id",
                "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                "--reason",
                "contract fixture",
                "--decided-by",
                "contract test",
            ],
        ),
        (
            "db migrate",
            "DatabaseMigrationReport",
            vec!["db", "migrate", missing.to_str().unwrap()],
        ),
        (
            "doctor",
            "DoctorReport",
            vec!["doctor", "--runtime-config", missing.to_str().unwrap()],
        ),
        (
            "retention erase",
            "RetentionEraseReport",
            vec![
                "retention",
                "erase",
                missing.to_str().unwrap(),
                "--source-id",
                "source",
                "--request-kind",
                "request",
                "--request-id",
                "request-1",
            ],
        ),
        (
            "source add",
            "SourceAddReport",
            vec![
                "source",
                "add",
                missing.to_str().unwrap(),
                "--project",
                project.to_str().unwrap(),
                "--source-id",
                "source",
            ],
        ),
        (
            "dev",
            "DevReport",
            vec!["dev", "start", missing.to_str().unwrap()],
        ),
        (
            "dev events",
            "DevEventsReport",
            vec!["dev", "events", missing.to_str().unwrap()],
        ),
        (
            "dev grant",
            "DevGrantReport",
            vec![
                "dev",
                "grant",
                "agent",
                "--grant",
                "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                "--connection",
                missing.to_str().unwrap(),
                missing.to_str().unwrap(),
            ],
        ),
        (
            "dev token",
            "DevTokenReport",
            vec!["dev", "token", "staff", missing.to_str().unwrap()],
        ),
    ];
    for (label, kind, command) in failure_commands {
        let (exit, report) = invoke(command.into_iter().map(OsString::from));
        assert_ne!(exit, ExitCode::SUCCESS, "{label}: {report:#?}");
        reports.push((label, kind, report));
    }

    let (exit, usage) = invoke(arguments(&["--not-a-real-argument"]));
    assert_eq!(exit, ExitCode::from(2));
    reports.push(("usage", "UsageReport", usage));

    assert_eq!(reports.len(), 19);
    for (label, kind, report) in reports {
        assert_matches_contract(label, kind, &report);
    }
}

/// Runs statements against the dedicated test database at `url`.
#[cfg(feature = "postgres-test")]
fn execute_in_test_database(url: &str, statements: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    runtime.block_on(async {
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .expect("connect dedicated test database");
        let connection = tokio::spawn(connection);
        client
            .batch_execute(statements)
            .await
            .expect("test database statements");
        drop(client);
        connection
            .await
            .expect("test connection task")
            .expect("test connection");
    });
}

#[cfg(feature = "postgres-test")]
#[test]
fn db_migrate_reports_a_schema_newer_than_this_binary_with_its_own_refusal() {
    let base = std::env::var("CASEWORK_TEST_DATABASE_URL")
        .expect("CASEWORK_TEST_DATABASE_URL is required for the real PostgreSQL test");
    // A schema of its own, so this test never races a suite that resets the
    // public schema of the same database.
    let schema = format!("caseworkctl_newer_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    execute_in_test_database(&base, &format!("CREATE SCHEMA {schema}"));
    let secret = format!("CASEWORKCTL_TEST_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&secret, &scoped);

    let root = tempfile::tempdir().expect("temporary project root");
    let project = root.path().join("standalone");
    let (exit, _) = invoke(vec![
        OsString::from("init"),
        project.as_os_str().to_owned(),
        OsString::from("--template"),
        OsString::from("standalone-decision"),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS);
    std::fs::create_dir(project.join("secrets")).expect("secret root");
    let mut runtime: Value = serde_norway::from_slice(
        &std::fs::read(project.join("runtime.example.yaml")).expect("runtime example reads"),
    )
    .expect("runtime example parses");
    runtime["secretProviders"]["environment"] = json!({});
    runtime["database"] = json!({
        "runtimeUrlRef": format!("secret:env/{secret}"),
        "migrationUrlRef": format!("secret:env/{secret}"),
        "testOnlyPlaintext": true,
    });
    std::fs::write(
        project.join("runtime.yaml"),
        serde_norway::to_string(&runtime).expect("runtime config renders"),
    )
    .expect("runtime config writes");
    let migrate = vec![
        OsString::from("db"),
        OsString::from("migrate"),
        project.as_os_str().to_owned(),
    ];

    let (exit, migrated) = invoke(migrate.clone());
    assert_eq!(exit, ExitCode::SUCCESS, "{migrated:#?}");
    assert_eq!(migrated["status"], "migrated");
    execute_in_test_database(
        &scoped,
        "INSERT INTO casework_schema_migrations(version,applied_at) VALUES(17,now())",
    );

    let refusal = "the Casework database schema version 17 is newer than this binary supports (16); run a casework release that supports it";
    let (exit, report) = invoke(migrate.clone());
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report:#?}");
    assert_eq!(report["ok"], false);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "casework.migration.refused"
    );
    assert_eq!(report["diagnostics"][0]["path"], "database");
    assert_eq!(report["diagnostics"][0]["message"], refusal);
    assert_matches_contract("db migrate refusal", "DatabaseMigrationReport", &report);

    let mut human = vec![OsString::from("caseworkctl")];
    human.extend(migrate);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = main_entry_from(human, &mut stdout, &mut stderr);
    let stderr = String::from_utf8(stderr).expect("stderr is UTF-8");
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{stderr}");
    assert!(
        stderr.starts_with(&format!(
            "error[casework.migration.refused] database: {refusal}\n  next: "
        )),
        "{stderr}"
    );

    std::env::remove_var(&secret);
    execute_in_test_database(&base, &format!("DROP SCHEMA {schema} CASCADE"));
}
