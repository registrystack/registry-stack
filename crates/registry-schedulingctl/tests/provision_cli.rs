// SPDX-License-Identifier: Apache-2.0

//! `schedulingctl provision` without a database: print mode reads the runtime
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
    let secrets = directory.join("secrets");
    std::fs::create_dir(&secrets).unwrap();
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (name, value) in [
        (
            "migration-database-url",
            format!(
                "postgresql://scheduling_migration:{MIGRATION_PASSWORD}@db.invalid:5432/scheduling"
            ),
        ),
        (
            "runtime-database-url",
            format!(
                "postgresql://scheduling_runtime:{RUNTIME_PASSWORD}@db.invalid:5432/scheduling"
            ),
        ),
        ("audit-key", "0123456789abcdef0123456789abcdef".to_owned()),
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
        vec![
            "init",
            project.to_str().unwrap(),
            "--template",
            "standalone-exact-time",
        ],
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
apiVersion: id.registrystack.org/formats/scheduling/runtime/v1alpha1
kind: SchedulingRuntimeConfig
package:
  root: {package}
identity:
  databaseId: registry-scheduling-ctl-test
listener:
  bind: 127.0.0.1:0
  tlsTermination: development-loopback
secretProviders:
  file:
    root: {secrets}
authentication:
  oidc:
    issuer: https://identity.example.test
    audience: urn:example:scheduling
    allowedClients: [scheduling-test-client]
    jwksSource:
      type: static
      documentRef: secret:file/jwks.json
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
taskGrantStatus: unchecked-final-fifteen-minutes
audit:
  path: {audit}
  hashKeyRef: secret:file/audit-key
retention:
  receiptRetentionDays: 2
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
    Command::new(env!("CARGO_BIN_EXE_schedulingctl"))
        .args(arguments)
        .output()
        .unwrap()
}

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
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
    for name in ["scheduling_migration", "scheduling_runtime"] {
        assert!(stdout.contains(name), "the script names {name}: {stdout}");
    }
    assert!(
        stdout.contains("CREATE DATABASE \"scheduling\""),
        "{stdout}"
    );
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
    assert_eq!(report["product"], "scheduling");
    assert_eq!(report["executed"], false);
    assert_eq!(report["status"], "complete");
    assert_eq!(report["database"], "scheduling");
    for statement in report["statements"].as_array().unwrap() {
        assert_eq!(statement["outcome"], "not-run", "{statement}");
    }
    for secret in [MIGRATION_PASSWORD, RUNTIME_PASSWORD] {
        assert!(!stdout.contains(secret), "the report holds no password");
    }

    // The command's own flag, after the verb, selects the same report.
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
                "SCHEDULING_ADMIN_URL",
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
                "SCHEDULING_ADMIN_URL",
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

/// Runs `provision --print-sql --format json` over the runtime file and
/// returns the exit code, the first diagnostic and the whole output.
fn refusal(runtime: &str) -> (Option<i32>, serde_json::Value, String) {
    let output = ctl(&[
        "provision",
        "--runtime-config",
        runtime,
        "--print-sql",
        "--format",
        "json",
    ]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let report: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("{error}: {stdout}{stderr}"));
    let diagnostic = report["diagnostics"][0].clone();
    (
        output.status.code(),
        diagnostic,
        format!("{stdout}{stderr}"),
    )
}

fn assert_refused_at(
    (code, diagnostic, output): (Option<i32>, serde_json::Value, String),
    path: &str,
) {
    assert_eq!(code, Some(1), "{output}");
    assert_eq!(diagnostic["code"], "config.refused", "{output}");
    assert_eq!(diagnostic["path"], path, "{output}");
    for secret in [MIGRATION_PASSWORD, RUNTIME_PASSWORD] {
        assert!(!output.contains(secret), "the refusal holds no password");
    }
}

#[test]
fn a_missing_runtime_url_secret_is_refused_without_a_password() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    std::fs::remove_file(directory.path().join("secrets/runtime-database-url")).unwrap();
    assert_refused_at(refusal(&runtime), "/database/runtimeUrlRef");
}

#[test]
fn a_missing_migration_url_secret_is_refused_without_a_password() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    std::fs::remove_file(directory.path().join("secrets/migration-database-url")).unwrap();
    assert_refused_at(refusal(&runtime), "/database/migrationUrlRef");
}

#[test]
fn a_runtime_url_secret_that_is_not_text_is_refused_without_a_password() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let path = directory.path().join("secrets/runtime-database-url");
    let mut bytes = RUNTIME_PASSWORD.as_bytes().to_vec();
    bytes.extend([0xff, 0xfe]);
    std::fs::write(&path, bytes).unwrap();
    assert_refused_at(refusal(&runtime), "/database/runtimeUrlRef");
}

#[test]
fn a_missing_ca_bundle_secret_is_refused_without_a_password() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let document = std::fs::read_to_string(&runtime).unwrap();
    let with_ca = document.replace(
        "  migrationUrlRef: secret:file/migration-database-url\n",
        "  migrationUrlRef: secret:file/migration-database-url\n  caBundleRef: secret:file/postgres-ca.pem\n",
    );
    assert_ne!(document, with_ca, "the runtime file names the CA bundle");
    std::fs::write(&runtime, with_ca).unwrap();
    assert_refused_at(refusal(&runtime), "/database/caBundleRef");
}
