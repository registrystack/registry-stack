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
    assert_envelope(&stdout, &report, exit);
    (exit, report)
}

/// Every JSON report opens with `ok`, `command`, and `status` in that order;
/// `ok` is true exactly when the process exits zero, and a report that is not
/// ok carries at least one diagnostic naming the next step.
fn assert_envelope(stdout: &[u8], report: &Value, exit: ExitCode) {
    let text = String::from_utf8_lossy(stdout);
    let head = text
        .lines()
        .filter_map(|line| line.strip_prefix("  \""))
        .filter_map(|line| line.split_once('"').map(|(key, _)| key))
        .take(3)
        .collect::<Vec<_>>();
    assert_eq!(head, ["ok", "command", "status"], "{text}");
    assert_eq!(report["ok"], json!(exit == ExitCode::SUCCESS), "{text}");
    if exit != ExitCode::SUCCESS {
        let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
        assert!(!diagnostics.is_empty(), "{text}");
        for diagnostic in diagnostics {
            assert!(
                diagnostic["suggestedAction"]
                    .as_str()
                    .is_some_and(|action| !action.is_empty()),
                "{text}"
            );
        }
    }
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
    // A report that carries part of the authored project refers to the
    // project schema's definitions of it.
    let project_path = repo_root().join("products/casework/generated/project/project.schema.json");
    let project_schema: Value = serde_json::from_slice(
        &std::fs::read(&project_path)
            .unwrap_or_else(|error| panic!("schema {project_path:?} reads: {error}")),
    )
    .unwrap_or_else(|error| panic!("schema {project_path:?} parses: {error}"));
    let project_id = project_schema["$id"]
        .as_str()
        .expect("the project schema names its identifier")
        .to_owned();
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .with_document(project_id, project_schema)
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
fn the_files_checked_bound_is_the_most_files_a_check_reads() {
    // The project file, the runtime configuration, `dev-clients.yaml`, and the
    // retained session state, then the sources and the three directories.
    let most =
        4 + registry_casework_core::MAXIMUM_SOURCES + 3 * crate::offline::MAXIMUM_DIRECTORY_FILES;
    for kind in ["CheckReport", "TestReport"] {
        let path = repo_root()
            .join("products/casework/contracts/cli")
            .join(format!("{kind}.schema.json"));
        let schema: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            schema["oneOf"][0]["properties"]["filesChecked"]["maximum"], most,
            "{kind}"
        );
    }
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

    // A refused project carries the reader's diagnostics unchanged, with
    // their positions and the places they relate to.
    let refused = root.path().join("refused");
    let (exit, _) = invoke(vec![
        OsString::from("init"),
        refused.as_os_str().to_owned(),
        OsString::from("--template"),
        OsString::from("standalone-decision"),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS);
    let policy = refused.join("casework.yaml");
    let text = std::fs::read_to_string(&policy).unwrap();
    std::fs::write(
        &policy,
        text.replace("    recoveryDays: 30\n", "    recoveryDays: 91\n"),
    )
    .unwrap();
    let (exit, check) = invoke(project_arguments("check", &refused));
    assert_eq!(exit, ExitCode::from(1), "{check:#?}");
    assert!(
        check["diagnostics"][0]["source"]["line"].is_u64(),
        "{check:#?}"
    );
    assert!(
        check["diagnostics"][0]["related"][0]["line"].is_u64(),
        "{check:#?}"
    );
    reports.push(("refused check", "CheckReport", check));

    let (exit, usage) = invoke(arguments(&["--not-a-real-argument"]));
    assert_eq!(exit, ExitCode::from(2));
    reports.push(("usage", "UsageReport", usage));

    let (exit, removed) = invoke(arguments(&["db", "migrate", "."]));
    assert_eq!(exit, ExitCode::from(2));
    reports.push(("removed command", "UsageReport", removed));

    assert_eq!(reports.len(), 23);
    for (label, kind, report) in reports {
        assert_matches_contract(label, kind, &report);
    }
}

#[test]
fn every_report_names_its_command_and_status() {
    let root = crate::canonical_tempdir();
    let project = root.path().join("standalone");
    let missing = root.path().join("missing");
    let (_, init) = invoke(vec![
        OsString::from("init"),
        project.as_os_str().to_owned(),
        OsString::from("--template"),
        OsString::from("standalone-decision"),
    ]);
    assert_eq!(
        (&init["command"], &init["status"]),
        (&json!("init"), &json!("complete"))
    );
    let (_, check) = invoke(project_arguments("check", &project));
    assert_eq!(check["status"], "complete");
    let (_, test) = invoke(project_arguments("test", &project));
    assert_eq!(test["status"], "passed");

    let (exit, usage) = invoke(arguments(&["--not-a-real-argument"]));
    assert_eq!(exit, ExitCode::from(2));
    assert_eq!(
        (&usage["command"], &usage["status"]),
        (&json!("usage"), &json!("usage-error"))
    );

    let (exit, status) = invoke(arguments(&[
        "status",
        "--runtime-config",
        missing.to_str().unwrap(),
    ]));
    assert_eq!(status["command"], "status");
    let expected = if exit == ExitCode::from(OPERATIONAL_FAILURE_EXIT) {
        "operational-failure"
    } else {
        "domain-refusal"
    };
    assert_eq!(status["status"], expected, "{status:#?}");

    let (exit, attempt) = invoke(arguments(&[
        "attempt",
        "mark-uncertain",
        missing.to_str().unwrap(),
        "--attempt-id",
        "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "--reason",
        "contract fixture",
        "--decided-by",
        "contract test",
    ]));
    assert_ne!(exit, ExitCode::SUCCESS);
    assert_eq!(attempt["command"], "attempt mark-uncertain");
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
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(report["diagnostics"][0]["path"], "database");
    assert_eq!(report["diagnostics"][0]["message"], refusal);
    assert_matches_contract("apply refusal", "ApplyReport", &report);

    let (exit, planned) = invoke(command("plan"));
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{planned:#?}");
    assert_eq!(
        planned["refusals"][0]["code"],
        "casework.activation.schema-newer"
    );
    assert_eq!(planned["status"], "refused");
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

/// A stand-in for the public `bregctl` of this release: it answers
/// `--version`, records the arguments of every other call, and prints the
/// report it was handed with the exit code it was handed.
#[cfg(unix)]
struct FakeBregctl {
    directory: tempfile::TempDir,
}

#[cfg(unix)]
impl FakeBregctl {
    fn new(version: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let directory = crate::canonical_tempdir();
        let binary = directory.path().join("bregctl");
        std::fs::write(
            &binary,
            format!(
                "#!/bin/sh\nhere=$(dirname \"$0\")\nif [ \"$1\" = --version ]; then echo 'bregctl {version}'; exit 0; fi\nprintf '%s\\n' \"$@\" > \"$here/arguments\"\ncat \"$here/report.json\"\nexit \"$(cat \"$here/exit\")\"\n"
            ),
        )
        .expect("fake bregctl writes");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
            .expect("fake bregctl is executable");
        let fake = Self { directory };
        fake.answer(0, &json!({}));
        fake
    }

    fn answer(&self, exit: u8, report: &Value) {
        std::fs::write(self.directory.path().join("exit"), exit.to_string()).unwrap();
        std::fs::write(
            self.directory.path().join("report.json"),
            serde_json::to_vec(report).unwrap(),
        )
        .unwrap();
    }

    fn verifies(&self, registry_revision: &str) {
        self.answer(
            0,
            &json!({
                "ok": true,
                "command": "check",
                "profile": "production",
                "revision": registry_revision,
                "registryRevision": registry_revision,
                "packageDigest": "sha256:0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
                "findings": []
            }),
        );
    }

    fn binary(&self) -> PathBuf {
        self.directory.path().join("bregctl")
    }

    fn arguments(&self) -> Vec<String> {
        std::fs::read_to_string(self.directory.path().join("arguments"))
            .expect("fake bregctl was called")
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

#[cfg(unix)]
fn check_against_breg_package(
    fake: &FakeBregctl,
    package: &Path,
    extra: &[&str],
) -> (ExitCode, Value) {
    let example = repo_root().join("products/casework/examples/multi-stage-routing-clocks");
    let mut arguments = vec![
        OsString::from("check"),
        example.into_os_string(),
        OsString::from("--against-breg-package"),
        package.as_os_str().to_owned(),
        OsString::from("--bregctl-bin"),
        fake.binary().into_os_string(),
    ];
    arguments.extend(extra.iter().map(OsString::from));
    invoke(arguments)
}

#[cfg(unix)]
#[test]
fn check_against_a_breg_package_reports_a_pin_the_package_rederives_as_current() {
    let fake = FakeBregctl::new(registry_platform_buildinfo::DISPLAY_VERSION);
    fake.verifies("sha256:regional-source-revision");
    let package = crate::canonical_tempdir();

    let (exit, report) =
        check_against_breg_package(&fake, package.path(), &["--source-id", "regional-register"]);

    assert_eq!(exit, ExitCode::SUCCESS, "{report:#?}");
    assert_eq!(
        fake.arguments(),
        vec![
            "--format".to_owned(),
            "json".to_owned(),
            "check".to_owned(),
            "--package".to_owned(),
            package.path().display().to_string(),
        ]
    );
    assert_eq!(report["status"], "complete");
    assert_eq!(
        report["bregPackage"],
        json!({
            "package": package.path(),
            "packageDigest": "sha256:0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            "registryRevision": "sha256:regional-source-revision",
            "sourceId": "regional-register",
            "sourceRevision": "sha256:regional-source-revision",
            "pin": "current"
        })
    );
    assert_matches_contract("check against a BReg package", "CheckReport", &report);
}

#[cfg(unix)]
#[test]
fn check_against_a_breg_package_refuses_a_stale_pin_naming_the_check_and_the_repin() {
    let fake = FakeBregctl::new(registry_platform_buildinfo::DISPLAY_VERSION);
    fake.verifies("sha256:rederived-by-the-package");
    let package = crate::canonical_tempdir();

    let (exit, report) =
        check_against_breg_package(&fake, package.path(), &["--source-id", "regional-register"]);

    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report:#?}");
    assert_eq!(report["ok"], false);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "casework.source-revision.stale");
    assert_eq!(diagnostic["artifact"], "CaseworkProject");
    assert_eq!(diagnostic["path"], "/sources/0/description");
    assert_eq!(diagnostic["related"][0]["path"], "/sourceRevision");
    // Neither revision is repeated (CFG-SEC-3); the related entry names
    // where the pinned one is written.
    let message = diagnostic["message"].as_str().unwrap();
    assert!(!message.contains("sha256:"), "{message}");
    let action = diagnostic["suggestedAction"].as_str().unwrap();
    assert!(
        action.contains("caseworkctl source add BREG_PROJECT --project ")
            && action.contains(" --source-id regional-register --apply"),
        "{action}"
    );
    assert!(
        action.contains("caseworkctl check ")
            && action.contains(&format!(
                " --against-breg-package {}",
                package.path().display()
            )),
        "{action}"
    );
    assert_matches_contract("stale pin refusal", "CheckReport", &report);
}

#[cfg(unix)]
#[test]
fn check_against_a_breg_package_selects_one_source_and_never_guesses() {
    let fake = FakeBregctl::new(registry_platform_buildinfo::DISPLAY_VERSION);
    fake.verifies("sha256:regional-source-revision");
    let package = crate::canonical_tempdir();

    let (exit, report) = check_against_breg_package(&fake, package.path(), &[]);
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report:#?}");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "casework.source.ambiguous");
    assert_eq!(diagnostic["path"], "/sources");
    let message = diagnostic["message"].as_str().unwrap();
    assert!(message.contains("--source-id"), "{message}");
    let action = diagnostic["suggestedAction"].as_str().unwrap();
    assert!(
        action.contains("regional-register") && action.contains("response-register"),
        "{action}"
    );

    let (exit, report) =
        check_against_breg_package(&fake, package.path(), &["--source-id", "undeclared"]);
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report:#?}");
    let message = report["diagnostics"][0]["message"].as_str().unwrap();
    assert!(message.contains("undeclared"), "{message}");

    let example = repo_root().join("products/casework/examples/multi-stage-routing-clocks");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = main_entry_from(
        [
            OsString::from("caseworkctl"),
            OsString::from("check"),
            example.into_os_string(),
            OsString::from("--source-id"),
            OsString::from("regional-register"),
        ],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, ExitCode::from(2));
}

#[cfg(unix)]
#[test]
fn check_against_a_breg_package_carries_the_bregctl_refusal_and_its_release() {
    let fake = FakeBregctl::new(registry_platform_buildinfo::DISPLAY_VERSION);
    fake.answer(
        1,
        &json!({
            "ok": false,
            "command": "check",
            "diagnostics": [{
                "severity": "error",
                "code": "check.package.integrity_refused",
                "artifact": "verified_package",
                "path": "package",
                "message": "the package was refused",
                "suggestedAction": "verify_package_integrity"
            }]
        }),
    );
    let package = crate::canonical_tempdir();
    let (exit, report) =
        check_against_breg_package(&fake, package.path(), &["--source-id", "regional-register"]);
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report:#?}");
    let message = report["diagnostics"][0]["message"].as_str().unwrap();
    assert!(
        message.contains("check.package.integrity_refused"),
        "{message}"
    );

    let other_release = FakeBregctl::new("0.0.1");
    other_release.verifies("sha256:regional-source-revision");
    let (exit, report) = check_against_breg_package(
        &other_release,
        package.path(),
        &["--source-id", "regional-register"],
    );
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report:#?}");
    let message = report["diagnostics"][0]["message"].as_str().unwrap();
    assert!(
        message.contains(&format!(
            "bregctl {}",
            registry_platform_buildinfo::DISPLAY_VERSION
        )),
        "{message}"
    );
}

#[test]
fn source_add_refuses_a_casework_endpoint_without_echoing_it() {
    let root = crate::canonical_tempdir();
    let registry = root.path().join("registry");
    let project = root.path().join("project");
    std::fs::create_dir(&registry).unwrap();
    crate::project::init(&project, "professional-review").unwrap();

    let (exit, report) = invoke(arguments(&[
        "source",
        "add",
        registry.to_str().unwrap(),
        "--project",
        project.to_str().unwrap(),
        "--source-id",
        "professional-licences",
        "--casework-endpoint",
        "http://reader:hunter2@127.0.0.1:18095",
        "--bregctl-bin",
        root.path().join("absent-bregctl").to_str().unwrap(),
    ]));

    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report:#?}");
    let text = report.to_string();
    assert!(!text.contains("hunter2"), "{text}");
    assert!(!text.contains("reader:"), "{text}");
    let message = report["diagnostics"][0]["message"].as_str().unwrap();
    assert!(message.contains("--casework-endpoint"), "{message}");
    assert_matches_contract("casework endpoint refusal", "SourceAddReport", &report);
}
