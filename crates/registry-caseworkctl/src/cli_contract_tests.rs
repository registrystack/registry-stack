// SPDX-License-Identifier: Apache-2.0

//! Conformance gate for the versioned `caseworkctl --format json` reports.

use super::*;
use jsonschema::{Draft, JSONSchema};
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
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
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
    let root = crate::canonical_tempdir();
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
            "apply",
            "ApplyReport",
            vec!["apply", "--runtime-config", missing.to_str().unwrap()],
        ),
        (
            "plan",
            "PlanReport",
            vec!["plan", "--runtime-config", missing.to_str().unwrap()],
        ),
        (
            "status",
            "StatusReport",
            vec!["status", "--runtime-config", missing.to_str().unwrap()],
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

    let (exit, removed) = invoke(arguments(&["db", "migrate", "."]));
    assert_eq!(exit, ExitCode::from(2));
    reports.push(("removed command", "UsageReport", removed));

    assert_eq!(reports.len(), 22);
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
fn apply_reports_a_schema_newer_than_this_binary_with_its_own_refusal() {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

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

    let root = crate::canonical_tempdir();
    let project = root.path().join("standalone");
    let (exit, _) = invoke(vec![
        OsString::from("init"),
        project.as_os_str().to_owned(),
        OsString::from("--template"),
        OsString::from("standalone-decision"),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS);
    package_locally(&project);
    let secrets = project.join("secrets");
    std::fs::create_dir(&secrets).expect("secret root");
    let audit_key = secrets.join("casework-audit-key");
    std::fs::write(&audit_key, "0".repeat(64)).expect("audit key writes");
    std::fs::set_permissions(&audit_key, std::fs::Permissions::from_mode(0o600))
        .expect("audit key is owner-only");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(project.join("state"))
        .expect("audit directory");
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
    let runtime_config = project.join("runtime.yaml");
    std::fs::write(
        &runtime_config,
        serde_norway::to_string(&runtime).expect("runtime config renders"),
    )
    .expect("runtime config writes");
    let command = |name: &str| {
        vec![
            OsString::from(name),
            OsString::from("--runtime-config"),
            runtime_config.as_os_str().to_owned(),
        ]
    };

    let (exit, plan) = invoke(command("plan"));
    assert_eq!(exit, ExitCode::SUCCESS, "{plan:#?}");
    assert_eq!(plan["planKind"], "initial");
    assert_eq!(plan["changesPending"], true);
    assert_eq!(plan["active"], Value::Null);
    assert_matches_contract("plan", "PlanReport", &plan);

    let raw_reference = "CHANGE-REQUEST-8431";
    let mut apply = command("apply");
    apply.extend(arguments(&[
        "--operator-reference",
        raw_reference,
        "--backup",
        "snapshot-before-initial-apply",
    ]));
    let (exit, applied) = invoke(apply.clone());
    assert_eq!(exit, ExitCode::SUCCESS, "{applied:#?}");
    assert_eq!(applied["roleMode"], "single");
    assert_eq!(applied["packageDigest"], plan["candidatePackageDigest"]);
    assert_eq!(applied["predecessorPackageDigest"], Value::Null);
    assert!(!applied["schemaVersionsApplied"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(
        !applied.to_string().contains(raw_reference),
        "the raw operator reference is never reported"
    );
    assert_matches_contract("apply", "ApplyReport", &applied);

    let (exit, status) = invoke(command("status"));
    assert_eq!(exit, ExitCode::SUCCESS, "{status:#?}");
    assert_eq!(status["active"]["activationId"], applied["activationId"]);
    assert_eq!(status["history"].as_array().unwrap().len(), 1);
    assert_eq!(status["roleMode"], "single");
    assert_eq!(
        status["singleRoleStatement"],
        registry_casework::SINGLE_ROLE_STATEMENT
    );
    assert!(!status.to_string().contains(raw_reference));
    assert_matches_contract("status", "StatusReport", &status);

    // The active package plans as nothing to do, and applying it again is
    // refused naming the active digest.
    let (exit, replan) = invoke(command("plan"));
    assert_eq!(exit, ExitCode::SUCCESS, "{replan:#?}");
    assert_eq!(replan["changesPending"], false);
    assert_eq!(
        replan["refusals"][0]["code"],
        "casework.activation.already-active"
    );
    let (exit, reapplied) = invoke(apply.clone());
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{reapplied:#?}");
    assert_eq!(
        reapplied["diagnostics"][0]["code"],
        "casework.activation.already-active"
    );
    assert!(reapplied["diagnostics"][0]["message"]
        .as_str()
        .unwrap()
        .contains(applied["packageDigest"].as_str().unwrap()));
    assert_matches_contract("apply refusal", "ApplyReport", &reapplied);

    let supported = status["supportedSchemaVersion"].as_i64().unwrap();
    execute_in_test_database(
        &scoped,
        &format!(
            "INSERT INTO casework_schema_migrations(version,applied_at) VALUES({},now())",
            supported + 1
        ),
    );

    let refusal = format!(
        "the Casework database schema version {} is newer than this binary supports ({supported}); run a casework release that supports it",
        supported + 1
    );
    let (exit, report) = invoke(apply.clone());
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report:#?}");
    assert_eq!(report["ok"], false);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "casework.activation.schema-newer"
    );
    assert_eq!(report["diagnostics"][0]["path"], "database");
    assert_eq!(report["diagnostics"][0]["message"], refusal);
    assert_matches_contract("apply refusal", "ApplyReport", &report);

    let (exit, planned) = invoke(command("plan"));
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{planned:#?}");
    assert_eq!(
        planned["refusals"][0]["code"],
        "casework.activation.schema-newer"
    );
    assert_matches_contract("plan refusal", "PlanReport", &planned);

    let mut human = vec![OsString::from("caseworkctl")];
    human.extend(apply);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = main_entry_from(human, &mut stdout, &mut stderr);
    let stderr = String::from_utf8(stderr).expect("stderr is UTF-8");
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{stderr}");
    assert!(
        stderr.starts_with(&format!(
            "error[casework.activation.schema-newer] database: {refusal}\n  next: "
        )),
        "{stderr}"
    );

    std::env::remove_var(&secret);
    execute_in_test_database(&base, &format!("DROP SCHEMA {schema} CASCADE"));
}

/// Package an initialized project where its generated runtime example
/// selects the package.
#[cfg(feature = "postgres-test")]
fn package_locally(project: &Path) {
    let (exit, report) = invoke(vec![
        OsString::from("package"),
        project.as_os_str().to_owned(),
        OsString::from("--output"),
        project
            .join(crate::project::LOCAL_PACKAGE_DIRECTORY)
            .into_os_string(),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report:#?}");
}
