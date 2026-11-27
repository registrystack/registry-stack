// SPDX-License-Identifier: Apache-2.0

//! `adapterctl provision` without a database: print mode reads the runtime
//! file and writes the script without connecting or printing a password, and
//! the administrator flags refuse the combinations the shared command
//! refuses.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};

const MIGRATION_PASSWORD: &str = "migration-password-for-print-mode";
const RUNTIME_PASSWORD: &str = "runtime-password-for-print-mode";

/// A runtime file whose secret files name a migration and a runtime login on
/// one server that does not exist, so a connection attempt could only fail.
fn write_runtime(directory: &Path) -> String {
    let secrets = directory.join("secrets");
    std::fs::create_dir(&secrets).unwrap();
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (name, value) in [
        (
            "migration-database-url",
            format!("postgresql://adapter_migration:{MIGRATION_PASSWORD}@db.invalid:5432/adapter"),
        ),
        (
            "runtime-database-url",
            format!("postgresql://adapter_runtime:{RUNTIME_PASSWORD}@db.invalid:5432/adapter"),
        ),
        (
            "jwks.json",
            r#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#.to_owned(),
        ),
        ("cursor-key", "0123456789abcdef0123456789abcdef".to_owned()),
    ] {
        let path = secrets.join(name);
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let runtime = directory.join("runtime.yaml");
    std::fs::write(
        &runtime,
        format!(
            "\
apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: adapter-provision-cli-test
endpoints:
  - endpoint: tracker
    baseUrl: https://192.168.1.10
    credential:
      type: basic
      usernameRef: secret:file/jwks.json
      passwordRef: secret:file/jwks.json
secretProviders:
  file:
    root: {secrets}
listener:
  bind: 127.0.0.1:0
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
oidc:
  issuer: https://identity.example.test
  audience: urn:example:adapter
  jwksSource:
    type: static
    documentRef: secret:file/jwks.json
allowedClients:
  - provision-test-client
allowedPrivateCidrs:
  - 192.168.0.0/16
audit:
  retentionDays: 90
idempotency:
  responseRetentionSeconds: 86400
cursorKeyRef: secret:file/cursor-key
",
            secrets = secrets.display(),
        ),
    )
    .unwrap();
    runtime.display().to_string()
}

fn ctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_adapterctl"))
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
    for name in ["adapter_migration", "adapter_runtime", "adapter"] {
        assert!(stdout.contains(name), "the script names {name}: {stdout}");
    }
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
    assert_eq!(report["product"], "adapter");
    assert_eq!(report["executed"], false);
    assert_eq!(report["status"], "complete");
    assert_eq!(report["database"], "adapter");
    for statement in report["statements"].as_array().unwrap() {
        assert_eq!(statement["outcome"], "not-run", "{statement}");
    }
    for secret in [MIGRATION_PASSWORD, RUNTIME_PASSWORD] {
        assert!(!stdout.contains(secret), "the report holds no password");
    }
}

#[test]
fn a_runtime_file_the_loader_refuses_is_reported_without_connecting() {
    let directory = scratch();
    let runtime = directory.path().join("runtime.yaml");
    std::fs::write(&runtime, "kind: AdapterRuntimeConfig\n").unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = ctl(&[
        "provision",
        "--runtime-config",
        runtime.to_str().unwrap(),
        "--print-sql",
    ]);
    assert_ne!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[test]
fn both_administrator_flags_are_refused() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    for arguments in [
        vec![
            "provision",
            "--runtime-config",
            &runtime,
            "--admin-url-file",
            "/nonexistent/admin-url",
            "--admin-url-env",
            "ADAPTER_ADMIN_URL",
        ],
        vec![
            "provision",
            "--runtime-config",
            &runtime,
            "--print-sql",
            "--admin-url-env",
            "ADAPTER_ADMIN_URL",
        ],
        vec!["provision", "--runtime-config", &runtime],
    ] {
        let output = ctl(&arguments);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{arguments:?}");
    }
}
