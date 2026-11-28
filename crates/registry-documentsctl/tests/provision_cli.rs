// SPDX-License-Identifier: Apache-2.0

//! `documentsctl provision` without a database: print mode reads the runtime
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
            format!(
                "postgresql://documents_migration:{MIGRATION_PASSWORD}@db.invalid:5432/documents"
            ),
        ),
        (
            "runtime-database-url",
            format!("postgresql://documents_runtime:{RUNTIME_PASSWORD}@db.invalid:5432/documents"),
        ),
        (
            "documents-audit-key",
            "documentsctl-test-audit-key-not-a-secret".to_owned(),
        ),
        (
            "hook-key",
            "documentsctl-test-hook-key-not-a-secret-0123456789".to_owned(),
        ),
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
apiVersion: id.registrystack.org/formats/documents/runtime/v1alpha1
kind: DocumentsRuntimeConfig
identity:
  databaseId: registry-documents-ctl-test
package:
  root: {package}
listener:
  bind: 127.0.0.1:0
  tlsTermination: loopback-plaintext
  networkExposure: private-address
secretProviders:
  file:
    root: {secrets}
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
authentication:
  oidc:
    issuers:
      main:
        issuer: https://identity.example.test/realms/registry
        audience: urn:example:documents
        scopeClaim: scope
        allowedClients: [civil-registry-app]
audit:
  destination: file
  path: {audit}
  hashKeyRef: secret:file/documents-audit-key
storage:
  type: database
contentVerification:
  type: http
  url: http://127.0.0.1:9/verify
  authorizationRef: secret:file/hook-key
  policyId: documents-test
cleanup:
  erasure: active
destinations:
  hooks:
    owning-system-events:
      url: http://127.0.0.1:9/document-events
      hmacSha256KeyRef: secret:file/hook-key
",
            package = directory.join("package").display(),
            secrets = secrets.display(),
            audit = directory.join("audit.ndjson").display(),
        ),
    )
    .unwrap();
    runtime.display().to_string()
}

fn ctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_documentsctl"))
        .args(arguments)
        .env_remove("REGISTRY_STACK_POSTURE")
        .output()
        .unwrap()
}

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}

#[test]
fn print_sql_requires_declared_development_for_disabled_verification() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let document = std::fs::read_to_string(&runtime).unwrap();
    let start = document.find("contentVerification:").unwrap();
    let end = document.find("cleanup:").unwrap();
    std::fs::write(
        &runtime,
        format!(
            "{}contentVerification:\n  type: disabled\n{}",
            &document[..start],
            &document[end..]
        ),
    )
    .unwrap();
    let output = ctl(&["provision", "--runtime-config", &runtime, "--print-sql"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("documents.posture.content-verification-disabled"),
        "{stderr}"
    );
    assert!(stderr.contains("/contentVerification"), "{stderr}");
    assert!(stderr.contains("rstack dev"), "{stderr}");
    assert!(
        stderr.contains("REGISTRY_STACK_POSTURE=development"),
        "{stderr}"
    );
    assert!(stderr.contains("--posture development"), "{stderr}");
    let output = ctl(&[
        "provision",
        "--runtime-config",
        &runtime,
        "--print-sql",
        "--posture",
        "development",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn check_reports_the_declared_posture() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    for (flags, posture, source) in [
        (&[][..], "production", "default"),
        (&["--posture", "development"][..], "development", "flag"),
    ] {
        let mut args = vec!["--format", "json", "check", "--runtime-config", &runtime];
        args.extend(flags);
        let output = ctl(&args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["posture"],
            serde_json::json!({"value": posture, "source": source})
        );
    }
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
    for name in ["documents_migration", "documents_runtime"] {
        assert!(stdout.contains(name), "the script names {name}: {stdout}");
    }
    assert!(stdout.contains("CREATE DATABASE \"documents\""), "{stdout}");
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
    assert_eq!(
        report["posture"],
        serde_json::json!({"value": "production", "source": "default"})
    );
    assert_eq!(report["command"], "provision");
    assert_eq!(report["product"], "documents");
    assert_eq!(report["executed"], false);
    assert_eq!(report["status"], "complete");
    assert_eq!(report["database"], "documents");
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
    for arguments in [
        vec![
            "provision",
            "--runtime-config",
            &runtime,
            "--admin-url-file",
            "/nonexistent/admin-url",
            "--admin-url-env",
            "DOCUMENTS_ADMIN_URL",
        ],
        vec![
            "provision",
            "--runtime-config",
            &runtime,
            "--print-sql",
            "--admin-url-env",
            "DOCUMENTS_ADMIN_URL",
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
    // A missing administrator flag is a usage error of the provision verb,
    // not clap's answer to an unknown verb.
    let stderr =
        String::from_utf8(ctl(&["provision", "--runtime-config", &runtime]).stderr).unwrap();
    assert!(stderr.contains("--admin-url"), "{stderr}");
    assert!(!stderr.contains("unrecognized subcommand"), "{stderr}");
    let stderr = String::from_utf8(
        ctl(&[
            "provision",
            "--runtime-config",
            &runtime,
            "--admin-url-file",
            "/nonexistent/admin-url",
            "--admin-url-env",
            "DOCUMENTS_ADMIN_URL",
        ])
        .stderr,
    )
    .unwrap();
    assert!(
        stderr.contains("conflicting use of --admin-url-file"),
        "{stderr}"
    );
}

/// The first diagnostic of a refused `provision --print-sql` over `runtime`,
/// after checking the exit status and that no password reached either stream.
fn loader_refusal(runtime: &str) -> serde_json::Value {
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
    assert_eq!(output.status.code(), Some(1), "{stdout}{stderr}");
    for secret in [MIGRATION_PASSWORD, RUNTIME_PASSWORD] {
        assert!(
            !stdout.contains(secret) && !stderr.contains(secret),
            "a refusal holds no password"
        );
    }
    let report: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("{error}: {stdout}{stderr}"));
    report["diagnostics"][0].clone()
}

#[test]
fn a_missing_database_secret_is_refused_at_its_member() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    std::fs::remove_file(directory.path().join("secrets/runtime-database-url")).unwrap();
    let diagnostic = loader_refusal(&runtime);
    assert_eq!(diagnostic["code"], "config.refused", "{diagnostic}");
    assert_eq!(
        diagnostic["path"], "/database/runtimeUrlRef",
        "{diagnostic}"
    );
}

#[test]
fn a_database_secret_that_is_not_text_is_refused_at_its_member() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let secret = directory.path().join("secrets/migration-database-url");
    std::fs::write(&secret, [0xff, 0xfe, 0xfd]).unwrap();
    let diagnostic = loader_refusal(&runtime);
    assert_eq!(diagnostic["code"], "config.refused", "{diagnostic}");
    assert_eq!(
        diagnostic["path"], "/database/migrationUrlRef",
        "{diagnostic}"
    );
}

#[test]
fn a_missing_ca_bundle_secret_is_refused_at_its_member() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let text = std::fs::read_to_string(&runtime)
        .unwrap()
        .replace(
            "  migrationUrlRef: secret:file/migration-database-url\n",
            "  migrationUrlRef: secret:file/migration-database-url\n  caBundleRef: secret:file/database-ca\n",
        );
    std::fs::write(&runtime, text).unwrap();
    let diagnostic = loader_refusal(&runtime);
    assert_eq!(diagnostic["code"], "config.refused", "{diagnostic}");
    assert_eq!(diagnostic["path"], "/database/caBundleRef", "{diagnostic}");
}

#[test]
fn a_runtime_file_the_runtime_refuses_is_refused_with_its_diagnostic() {
    let directory = scratch();
    let runtime = write_runtime(directory.path());
    let text = std::fs::read_to_string(&runtime).unwrap().replace(
        "allowedClients: [civil-registry-app]",
        "allowedClients: unrestricted",
    );
    std::fs::write(&runtime, text).unwrap();
    let diagnostic = loader_refusal(&runtime);
    assert_eq!(
        diagnostic["code"], "documents.runtime.allowed-clients-required",
        "{diagnostic}"
    );
}

#[test]
fn check_production_refuses_development_settings_and_conflicting_declarations() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("runtime.yaml");
    let contents =
        include_str!("../../../products/documents/examples/starter/runtime.example.yaml");
    let contents = contents.replace("  type: http\n  url: https://scanner.example.test/v1/verify\n  authorizationRef: secret:file/content-verifier-authorization\n  policyId: documents-default\n  attemptTimeoutMilliseconds: 10000", "  type: disabled");
    std::fs::write(&config, contents).unwrap();
    let development = ctl(&[
        "--format",
        "json",
        "check",
        "--runtime-config",
        config.to_str().unwrap(),
        "--deny-warnings",
        "--posture",
        "development",
    ]);
    let report: serde_json::Value = serde_json::from_slice(&development.stdout).unwrap();
    assert_eq!(development.status.code(), Some(0), "{report}");
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["code"] == "documents.posture.content-verification-disabled"
                    && finding["severity"] == "warning"
            }),
        "{report}"
    );
    for (flags, environment, exit, code) in [
        (
            &["--posture", "development"][..],
            None,
            2,
            "platform.posture.conflict",
        ),
        (&[][..], Some("development"), 2, "platform.posture.conflict"),
        (
            &[][..],
            None,
            1,
            "documents.posture.content-verification-disabled",
        ),
    ] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_documentsctl"));
        command.env_remove("REGISTRY_STACK_POSTURE");
        if let Some(value) = environment {
            command.env("REGISTRY_STACK_POSTURE", value);
        }
        let output = command
            .args([
                "--format",
                "json",
                "check",
                "--production",
                "--runtime-config",
            ])
            .arg(&config)
            .args(flags)
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(exit), "{report}");
        assert!(
            report["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["code"] == code),
            "{report}"
        );
    }
}

#[test]
fn conflict_with_environment_names_the_production_flag() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_documentsctl"))
        .args([
            "--format",
            "json",
            "check",
            "--production",
            "--runtime-config",
            "/nonexistent/runtime.yaml",
        ])
        .env("REGISTRY_STACK_POSTURE", "development")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["diagnostics"][0]["code"], "platform.posture.conflict",
        "{report}"
    );
    assert_eq!(
        report["diagnostics"][0]["message"],
        "--production and REGISTRY_STACK_POSTURE declare different postures",
        "{report}"
    );
}
