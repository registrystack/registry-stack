// SPDX-License-Identifier: Apache-2.0

//! `messagingctl provision` without a database: print mode reads the runtime
//! file and writes the script without connecting or printing a password, and
//! the administrator flags refuse the combinations the shared command
//! refuses.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};

const MIGRATION_PASSWORD: &str = "migration-password-for-print-mode";
const RUNTIME_PASSWORD: &str = "runtime-password-for-print-mode";

/// A runtime file over a built package, whose secret files name a migration
/// and a runtime login on one server that does not exist, so a connection
/// attempt could only fail.
fn write_runtime(directory: &Path) -> String {
    write_runtime_for(directory, "messaging")
}

/// [`write_runtime`] with the database name both URLs end in, written as the
/// URL path holds it (percent-encoded where a name needs it).
fn write_runtime_for(directory: &Path, database: &str) -> String {
    let secrets = directory.join("secrets");
    std::fs::create_dir(&secrets).unwrap();
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (name, value) in [
        (
            "migration-database-url",
            format!(
                "postgresql://messaging_migration:{MIGRATION_PASSWORD}@db.invalid:5432/{database}"
            ),
        ),
        (
            "runtime-database-url",
            format!("postgresql://messaging_runtime:{RUNTIME_PASSWORD}@db.invalid:5432/{database}"),
        ),
        ("audit-key", "5a".repeat(16)),
        (
            "jwks.json",
            r#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#.to_owned(),
        ),
    ] {
        let path = secrets.join(name);
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    // The loader verifies the package the file names, as `apply` does.
    let project = directory.join("project");
    let package = directory.join("package");
    for arguments in [
        vec!["init", project.to_str().unwrap()],
        vec![
            "package",
            project.to_str().unwrap(),
            "--output",
            package.to_str().unwrap(),
        ],
    ] {
        let output = ctl(&arguments);
        assert_eq!(output.status.code(), Some(0), "{arguments:?}");
    }
    let runtime = directory.join("runtime.yaml");
    std::fs::write(
        &runtime,
        format!(
            "\
apiVersion: id.registrystack.org/formats/messaging/runtime/v1alpha1
kind: MessagingRuntimeConfig
identity:
  databaseId: registry-messaging-ctl-test
package:
  root: {package}
listener:
  bind: 127.0.0.1:0
  tlsTermination: development-loopback
secretProviders:
  file:
    root: {secrets}
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
authentication:
  oidc:
    issuer: https://identity.example.test
    audience: urn:example:messaging
    allowedClients: [case-system, operations-console]
    jwksSource:
      type: static
      documentRef: secret:file/jwks.json
audit:
  destination: file
  path: {audit}
  hashKeyRef: secret:file/audit-key
",
            package = package.display(),
            secrets = secrets.display(),
            audit = directory.join("audit.ndjson").display(),
        ),
    )
    .unwrap();
    runtime.display().to_string()
}

fn ctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_messagingctl"))
        .args(arguments)
        .output()
        .unwrap()
}

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}

#[test]
fn a_database_name_that_is_a_connection_uri_is_refused_in_print_mode() {
    let directory = scratch();
    let runtime = write_runtime_for(directory.path(), "postgresql%3A%2F%2Fevil.example%2Fx");
    let (code, report) = refusal(&runtime);
    assert_eq!(code, Some(2), "{report:#}");
    let diagnostic = first_diagnostic(&report);
    assert_eq!(
        diagnostic["code"], "platform.provision.target-invalid",
        "{report:#}"
    );
    assert_eq!(report["executed"], false, "{report:#}");
    assert!(
        !report.to_string().contains("evil.example"),
        "the refused name is not repeated: {report:#}"
    );
}

#[test]
fn print_sql_uses_the_declared_posture() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let text = std::fs::read_to_string(&runtime).unwrap();
    std::fs::write(
        &runtime,
        text.replace(
            "database:\n",
            "database:\n  transport: private-network-plaintext\n",
        ),
    )
    .unwrap();
    let run = |posture: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_messagingctl"));
        command.env_remove("REGISTRY_STACK_POSTURE").args([
            "provision",
            "--runtime-config",
            &runtime,
            "--print-sql",
        ]);
        if let Some(posture) = posture {
            command.args(["--posture", posture]);
        }
        command.output().unwrap()
    };
    let default = run(None);
    assert!(!default.status.success());
    let diagnostic = String::from_utf8_lossy(&default.stderr);
    assert!(
        diagnostic.contains("platform.posture.database-private-plaintext"),
        "{diagnostic}"
    );
    let development = run(Some("development"));
    assert!(development.status.success(), "{development:?}");
}

#[test]
fn print_sql_writes_the_script_and_no_password() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let output = ctl(&["provision", "--runtime-config", &runtime, "--print-sql"]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    for name in ["messaging_migration", "messaging_runtime"] {
        assert!(stdout.contains(name), "the script names {name}: {stdout}");
    }
    assert!(stdout.contains("CREATE DATABASE \"messaging\""), "{stdout}");
    assert!(stdout.contains("CREATE ROLE"), "{stdout}");
    assert!(stdout.contains("\\password"), "{stdout}");
    for secret in [MIGRATION_PASSWORD, RUNTIME_PASSWORD] {
        assert!(!stdout.contains(secret), "the script holds no password");
    }
}

#[test]
fn print_sql_as_json_reports_nothing_executed() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let output = ctl(&[
        "--format",
        "json",
        "provision",
        "--runtime-config",
        &runtime,
        "--print-sql",
    ]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["command"], "provision");
    assert_eq!(report["product"], "messaging");
    assert_eq!(report["executed"], false);
    assert_eq!(report["status"], "complete");
    assert_eq!(report["database"], "messaging");
    for statement in report["statements"].as_array().unwrap() {
        assert_eq!(statement["outcome"], "not-run", "{statement}");
    }
    for secret in [MIGRATION_PASSWORD, RUNTIME_PASSWORD] {
        assert!(!stdout.contains(secret), "the report holds no password");
    }

    // The tool's global flag, after the verb, selects the same report.
    let after = ctl(&[
        "provision",
        "--runtime-config",
        &runtime,
        "--print-sql",
        "--format",
        "json",
    ]);
    assert_eq!(after.status.code(), Some(0));
    assert_eq!(String::from_utf8(after.stdout).unwrap(), stdout);
}

#[test]
fn both_administrator_flags_are_refused() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    for (arguments, message) in [
        (
            vec![
                "provision",
                "--runtime-config",
                &runtime,
                "--admin-url-file",
                "/nonexistent/admin-url",
                "--admin-url-env",
                "MESSAGING_ADMIN_URL",
            ],
            "conflicting use of --admin-url-file",
        ),
        (
            vec![
                "provision",
                "--runtime-config",
                &runtime,
                "--print-sql",
                "--admin-url-env",
                "MESSAGING_ADMIN_URL",
            ],
            "conflicting use of --print-sql",
        ),
        (
            vec!["provision", "--runtime-config", &runtime],
            "missing required argument --admin-url-file, --admin-url-env",
        ),
    ] {
        let output = ctl(&arguments);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert!(stderr.contains(message), "{arguments:?}: {stderr}");
    }
}

/// The refusal `provision --print-sql --format json` reports, with the exit
/// code. The reports carry no password, so neither does their text.
fn refusal(runtime: &str) -> (Option<i32>, serde_json::Value) {
    let output = ctl(&[
        "--format",
        "json",
        "provision",
        "--runtime-config",
        runtime,
        "--print-sql",
    ]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    for secret in [MIGRATION_PASSWORD, RUNTIME_PASSWORD] {
        assert!(
            !stdout.contains(secret),
            "stdout holds no password: {stdout}"
        );
        assert!(
            !stderr.contains(secret),
            "stderr holds no password: {stderr}"
        );
    }
    let report = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("a JSON report: {error}: {stdout}{stderr}"));
    (output.status.code(), report)
}

fn first_diagnostic(report: &serde_json::Value) -> &serde_json::Value {
    &report["diagnostics"][0]
}

#[test]
fn a_missing_runtime_url_secret_is_refused_at_its_member() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    std::fs::remove_file(directory.path().join("secrets/runtime-database-url")).unwrap();
    let (code, report) = refusal(&runtime);
    assert_eq!(code, Some(1), "{report:#}");
    let diagnostic = first_diagnostic(&report);
    assert_eq!(diagnostic["code"], "config.refused", "{report:#}");
    assert_eq!(diagnostic["path"], "/database/runtimeUrlRef", "{report:#}");
}

#[test]
fn a_migration_url_secret_that_is_not_text_is_refused_at_its_member() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let secret = directory.path().join("secrets/migration-database-url");
    std::fs::write(&secret, [0xff, 0xfe, 0xfd]).unwrap();
    let (code, report) = refusal(&runtime);
    assert_eq!(code, Some(1), "{report:#}");
    let diagnostic = first_diagnostic(&report);
    assert_eq!(diagnostic["code"], "config.refused", "{report:#}");
    assert_eq!(
        diagnostic["path"], "/database/migrationUrlRef",
        "{report:#}"
    );
    assert!(
        diagnostic["message"]
            .as_str()
            .unwrap()
            .contains("not UTF-8"),
        "{report:#}"
    );
}

#[test]
fn a_runtime_file_that_does_not_load_is_refused_before_any_database_work() {
    let directory = scratch();
    let missing = directory.path().join("no-such-runtime.yaml");
    let (code, report) = refusal(missing.to_str().unwrap());
    assert_eq!(code, Some(1), "{report:#}");
    assert_eq!(report["executed"], false, "{report:#}");
    assert!(
        !first_diagnostic(&report)["code"]
            .as_str()
            .unwrap()
            .is_empty(),
        "{report:#}"
    );
}
