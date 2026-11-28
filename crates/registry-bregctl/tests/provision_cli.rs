// SPDX-License-Identifier: Apache-2.0

//! `bregctl provision` without a database: print mode reads the runtime file
//! and writes the script without connecting or printing a password, and the
//! administrator flags refuse the combinations the shared command refuses.

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
            format!("postgresql://breg_migration:{MIGRATION_PASSWORD}@db.invalid:5432/registry"),
        ),
        (
            "runtime-database-url",
            format!("postgresql://breg_runtime:{RUNTIME_PASSWORD}@db.invalid:5432/registry"),
        ),
        (
            "audit-key",
            "synthetic-audit-key-of-at-least-32-bytes".to_owned(),
        ),
        (
            "cursor-key",
            "synthetic-cursor-key-of-at-least-32-bytes".to_owned(),
        ),
    ] {
        let path = secrets.join(name);
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    // The runtime file's loader requires the package root to be a readable
    // directory, though provision reads nothing from it.
    std::fs::create_dir(directory.join("package")).unwrap();
    let runtime = directory.join("runtime.yaml");
    std::fs::write(
        &runtime,
        format!(
            "\
apiVersion: id.registrystack.org/formats/breg/runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:0
identity:
  environment: test
  instanceId: provision-cli-test
  databaseId: provision-cli-test-db
  databaseInitializationEnvironment: test
secretProviders:
  file:
    root: {secrets}
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maximumConnections: 4
  roles:
    migration: breg_migration
    runtime: breg_runtime
package:
  root: {package}
authentication:
  oidc:
    issuer: https://issuer.example.test
    audience: urn:breg:provision-cli-test
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: \" \"
    allowedClients: [directory-client]
    maximumTokenLifetimeSeconds: 3600
    leewayMilliseconds: 60000
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:file/audit-key
  path: {audit}
cursor:
  secretRef: secret:file/cursor-key
",
            package = directory.join("package").display(),
            secrets = secrets.display(),
            audit = directory.join("audit.jsonl").display(),
        ),
    )
    .unwrap();
    runtime.display().to_string()
}

fn ctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
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
    for name in [
        "breg_migration",
        "breg_runtime",
        "registry",
        "registry_internal",
        "registry_data",
        "registry_source",
        "registry_derived",
        "registry_context",
        "btree_gist",
    ] {
        assert!(stdout.contains(name), "the script names {name}: {stdout}");
    }
    assert!(stdout.contains("CREATE ROLE"), "{stdout}");
    assert!(stdout.contains("\\password"), "{stdout}");
    assert!(
        !stdout.contains("postgis"),
        "no package, so no PostGIS step: {stdout}"
    );
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
    assert_eq!(report["product"], "breg");
    assert_eq!(report["executed"], false);
    assert_eq!(report["status"], "complete");
    assert_eq!(report["database"], "registry");
    assert_eq!(report["migrationRole"], "breg_migration");
    assert_eq!(report["runtimeRole"], "breg_runtime");
    for statement in report["statements"].as_array().unwrap() {
        assert_eq!(statement["outcome"], "not-run", "{statement}");
    }
    for secret in [MIGRATION_PASSWORD, RUNTIME_PASSWORD] {
        assert!(!stdout.contains(secret), "the report holds no password");
    }
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
            "BREG_ADMIN_URL",
        ],
        vec![
            "provision",
            "--runtime-config",
            &runtime,
            "--print-sql",
            "--admin-url-env",
            "BREG_ADMIN_URL",
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

#[test]
fn a_package_that_is_not_a_package_is_refused_before_any_connection() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let missing = directory.path().join("no-such-package");
    let output = ctl(&[
        "--format",
        "json",
        "provision",
        "--runtime-config",
        &runtime,
        "--print-sql",
        "--package",
        missing.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["ok"], false, "{stdout}");
    assert_eq!(report["executed"], false, "{stdout}");
}

/// Runs `provision --print-sql --format json`, asserts the runtime file was
/// refused with exit 1 and no password anywhere in the output, and returns the
/// first diagnostic's code and path. The loader makes the checks `apply`
/// makes before it resolves the URLs itself, so these are the runtime file's
/// own codes.
fn loader_refusal(runtime: &str) -> (String, String) {
    let output = ctl(&[
        "--format",
        "json",
        "provision",
        "--runtime-config",
        runtime,
        "--print-sql",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(1), "{stdout}{stderr}");
    for secret in [MIGRATION_PASSWORD, RUNTIME_PASSWORD] {
        assert!(
            !stdout.contains(secret) && !stderr.contains(secret),
            "a refusal prints no password"
        );
    }
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["ok"], false, "{stdout}");
    assert_eq!(report["executed"], false, "{stdout}");
    let diagnostic = &report["diagnostics"][0];
    (
        diagnostic["code"].as_str().unwrap().to_owned(),
        diagnostic["path"].as_str().unwrap().to_owned(),
    )
}

#[test]
fn a_missing_runtime_url_secret_is_refused() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    std::fs::remove_file(directory.path().join("secrets/runtime-database-url")).unwrap();
    assert_eq!(
        loader_refusal(&runtime),
        ("breg.runtime.secret".to_owned(), String::new())
    );
}

#[test]
fn a_runtime_url_that_is_not_utf8_is_refused() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let secret = directory.path().join("secrets/runtime-database-url");
    std::fs::write(&secret, [0xff, 0xfe, 0xfd]).unwrap();
    assert_eq!(
        loader_refusal(&runtime),
        ("breg.runtime.secret".to_owned(), String::new())
    );
}

#[test]
fn a_url_user_that_differs_from_the_runtime_role_is_refused() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let secret = directory.path().join("secrets/runtime-database-url");
    std::fs::write(
        &secret,
        format!("postgresql://someone_else:{RUNTIME_PASSWORD}@db.invalid:5432/registry"),
    )
    .unwrap();
    let (code, path) = loader_refusal(&runtime);
    assert_eq!(code, "breg.runtime.invalid-database");
    assert_eq!(path, "/database");
}

#[test]
fn a_missing_ca_bundle_is_refused() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let text = std::fs::read_to_string(&runtime).unwrap();
    let with_ca = text.replace(
        "  pool:\n",
        "  caBundleRef: secret:file/no-such-ca.pem\n  pool:\n",
    );
    assert_ne!(text, with_ca, "the runtime file gains the CA reference");
    std::fs::write(&runtime, with_ca).unwrap();
    assert_eq!(
        loader_refusal(&runtime),
        ("breg.runtime.secret".to_owned(), String::new())
    );
}
