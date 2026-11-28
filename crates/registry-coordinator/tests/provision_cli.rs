// SPDX-License-Identifier: Apache-2.0
//! `coordinatorctl provision` without a server: the printed plan and the
//! usage refusals.
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

const RUNTIME: &str =
    include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml");
const MIGRATION_PASSWORD: &str = "migration-password-canary";
const RUNTIME_PASSWORD: &str = "runtime-password-canary";
const ADMIN_URL_VARIABLE: &str = "COORDINATOR_TEST_ADMIN_URL";
/// Nothing listens here, so a command that reached the connection step would
/// fail with a connection error instead of the loader's refusal.
const ADMIN_URL: &str =
    "postgres://admin:admin-password-canary@127.0.0.1:1/postgres?sslmode=verify-full";

/// A runtime file the loader accepts, whose database references resolve from
/// the environment the command is given.
fn runtime_file(directory: &Path) -> std::path::PathBuf {
    let root = directory.canonicalize().unwrap();
    let secrets = root.join("secrets");
    fs::create_dir(&secrets).unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
    let root_pem = secrets.join("postgres-root.pem");
    fs::write(&root_pem, "unused in print mode").unwrap();
    fs::set_permissions(&root_pem, fs::Permissions::from_mode(0o600)).unwrap();
    let path = root.join("runtime.yaml");
    fs::write(
        &path,
        RUNTIME.replace(
            "/run/registry-coordinator/secrets",
            secrets.to_str().unwrap(),
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn database_url(user: &str, password: &str) -> String {
    format!("postgres://{user}:{password}@db.example.org:5432/coordinator")
}

/// Runs `provision` with the given database URLs in the environment. `None`
/// leaves the variable unset, so its secret reference cannot resolve.
fn provision_with(
    runtime: &Path,
    extra: &[&str],
    migration_url: Option<String>,
    runtime_url: Option<String>,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"));
    command
        .env_remove("REGISTRY_STACK_POSTURE")
        .arg("provision")
        .arg("--runtime-config")
        .arg(runtime)
        .args(extra)
        .env_remove("COORDINATOR_MIGRATION_URL")
        .env_remove("COORDINATOR_DATABASE_URL")
        .env(ADMIN_URL_VARIABLE, ADMIN_URL);
    if let Some(url) = migration_url {
        command.env("COORDINATOR_MIGRATION_URL", url);
    }
    if let Some(url) = runtime_url {
        command.env("COORDINATOR_DATABASE_URL", url);
    }
    command.output().unwrap()
}

fn provision(runtime: &Path, extra: &[&str]) -> std::process::Output {
    provision_with(
        runtime,
        extra,
        Some(database_url("coordinator_migration", MIGRATION_PASSWORD)),
        Some(database_url("coordinator_runtime", RUNTIME_PASSWORD)),
    )
}

/// Asserts a loader refusal: exit 1, nothing on stdout, the code and the
/// pointer on stderr, and no password or URL anywhere.
fn assert_refused(output: &std::process::Output, code: &str, pointer: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stdout}{stderr}");
    assert!(stdout.is_empty(), "a refusal prints no plan: {stdout}");
    assert!(stderr.contains(code), "{stderr}");
    assert!(stderr.contains(pointer), "{stderr}");
    for secret in [
        MIGRATION_PASSWORD,
        RUNTIME_PASSWORD,
        "admin-password-canary",
        "postgres://",
    ] {
        assert!(!stderr.contains(secret), "stderr leaked a secret");
    }
}

#[test]
fn check_reports_the_declared_posture() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    for (flags, posture, source) in [
        (&[][..], "production", "default"),
        (&["--posture", "development"][..], "development", "flag"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
            .args(["--format", "json", "check", "--runtime-config"])
            .arg(&runtime)
            .args(flags)
            .output()
            .unwrap();
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
fn print_sql_requires_declared_development_for_private_plaintext() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    let text = fs::read_to_string(&runtime).unwrap();
    let text = text.replace(
        "database:\n",
        "database:\n  transport: private-network-plaintext\n",
    );
    fs::write(&runtime, text).unwrap();
    let default = provision(&runtime, &["--print-sql"]);
    assert_refused(
        &default,
        "platform.posture.database-private-plaintext",
        "/database/transport",
    );
    let development = provision(&runtime, &["--print-sql", "--posture", "development"]);
    assert!(
        development.status.success(),
        "{}",
        String::from_utf8_lossy(&development.stderr)
    );
}

#[test]
fn provision_json_reports_the_declaration() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    let output = provision(
        &runtime,
        &["--print-sql", "--posture", "production", "--format", "json"],
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert_eq!(
        report["posture"],
        serde_json::json!({"value": "production", "source": "flag"})
    );
}

#[test]
fn print_sql_prints_the_plan_without_a_connection_or_a_password() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    let output = provision(&runtime, &["--print-sql"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}{stderr}");
    assert!(
        stdout.contains("CREATE ROLE \"coordinator_migration\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("CREATE ROLE \"coordinator_runtime\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("GRANT CREATE ON DATABASE \"coordinator\" TO \"coordinator_migration\""),
        "the migration role creates the namespace schema: {stdout}"
    );
    assert!(stdout.contains("\\password"), "{stdout}");
    for secret in [MIGRATION_PASSWORD, RUNTIME_PASSWORD, "postgres://"] {
        assert!(!stdout.contains(secret), "the script leaked a secret");
        assert!(!stderr.contains(secret), "stderr leaked a secret");
    }
}

#[test]
fn both_administrator_sources_are_a_usage_error() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    let output = provision(
        &runtime,
        &[
            "--admin-url-file",
            "/nonexistent/admin.url",
            "--admin-url-env",
            "ADMIN_URL",
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(output.stdout.is_empty());
    assert!(
        stderr.contains("--admin-url"),
        "the refusal names the flags: {stderr}"
    );
}

#[test]
fn an_administrator_source_is_required_unless_printing() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    let output = provision(&runtime, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--admin-url"),
        "the refusal names the flags: {stderr}"
    );
}

#[test]
fn a_runtime_url_user_that_is_not_the_deployment_runtime_role_is_refused_before_connecting() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    // With an administrator URL that could not connect, only the loader's
    // refusal explains exit 1 with this code.
    let output = provision_with(
        &runtime,
        &["--admin-url-env", ADMIN_URL_VARIABLE],
        Some(database_url("coordinator_migration", MIGRATION_PASSWORD)),
        Some(database_url("coord_rt", RUNTIME_PASSWORD)),
    );
    assert_refused(
        &output,
        "coordinator.runtime-config.runtime-role-mismatch",
        "/database/runtimeUrlRef",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("coordinator_runtime"),
        "the refusal names the configured role: {stderr}"
    );
    assert!(
        !stderr.contains("coord_rt:") && !stderr.contains("@db.example.org"),
        "the refusal does not echo the URL: {stderr}"
    );

    let printed = provision_with(
        &runtime,
        &["--print-sql"],
        Some(database_url("coordinator_migration", MIGRATION_PASSWORD)),
        Some(database_url("coord_rt", RUNTIME_PASSWORD)),
    );
    assert_refused(
        &printed,
        "coordinator.runtime-config.runtime-role-mismatch",
        "/database/runtimeUrlRef",
    );
}

#[test]
fn a_runtime_url_that_names_no_user_is_refused_as_missing_its_user() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    for url in [
        "postgres://db.example.org:5432/coordinator",
        "not a postgresql url",
    ] {
        let output = provision_with(
            &runtime,
            &["--print-sql"],
            Some(database_url("coordinator_migration", MIGRATION_PASSWORD)),
            Some(url.to_owned()),
        );
        assert_refused(
            &output,
            "coordinator.runtime-config.runtime-role-mismatch",
            "/database/runtimeUrlRef",
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("names no user"),
            "the refusal says the URL has no user: {stderr}"
        );
        assert!(
            !stderr.contains("does not log in as"),
            "a missing user is not reported as another user: {stderr}"
        );
    }
}

/// Every other verb takes `--runtime-config` before or after its name, and
/// `provision` does too.
#[test]
fn the_runtime_file_may_be_given_before_the_verb() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    let run = |arguments: &[&std::ffi::OsStr]| {
        Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
            .args(arguments)
            .env(
                "COORDINATOR_MIGRATION_URL",
                database_url("coordinator_migration", MIGRATION_PASSWORD),
            )
            .env(
                "COORDINATOR_DATABASE_URL",
                database_url("coordinator_runtime", RUNTIME_PASSWORD),
            )
            .output()
            .unwrap()
    };
    let before = run(&[
        "--runtime-config".as_ref(),
        runtime.as_os_str(),
        "provision".as_ref(),
        "--print-sql".as_ref(),
    ]);
    let after = run(&[
        "provision".as_ref(),
        "--runtime-config".as_ref(),
        runtime.as_os_str(),
        "--print-sql".as_ref(),
    ]);
    assert_eq!(
        before.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&before.stderr)
    );
    assert_eq!(before.stdout, after.stdout, "the same plan either way");

    let missing = run(&["provision".as_ref(), "--print-sql".as_ref()]);
    assert_eq!(missing.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(
        stderr.contains("missing required argument") && stderr.contains("provision --help"),
        "the usage error says an argument is missing and where to read: {stderr}"
    );
}

#[test]
fn an_unreadable_runtime_url_secret_is_refused_without_a_password() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    let output = provision_with(
        &runtime,
        &["--print-sql"],
        Some(database_url("coordinator_migration", MIGRATION_PASSWORD)),
        None,
    );
    assert_refused(
        &output,
        "coordinator.runtime-config.refused",
        "/database/runtimeUrlRef",
    );
}

#[test]
fn an_unreadable_migration_url_secret_is_refused_without_a_password() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    let output = provision_with(
        &runtime,
        &["--print-sql"],
        None,
        Some(database_url("coordinator_runtime", RUNTIME_PASSWORD)),
    );
    assert_refused(
        &output,
        "coordinator.runtime-config.refused",
        "/database/migrationUrlRef",
    );
}

#[test]
fn a_certificate_authority_file_that_is_not_text_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    let root_pem = directory.path().join("secrets/postgres-root.pem");
    fs::write(&root_pem, [0xff, 0xfe, 0xfd]).unwrap();
    let output = provision(&runtime, &["--print-sql"]);
    assert_refused(
        &output,
        "coordinator.runtime-config.refused",
        "/database/caBundleRef",
    );
}

#[test]
fn a_missing_certificate_authority_file_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    fs::remove_file(directory.path().join("secrets/postgres-root.pem")).unwrap();
    let output = provision(&runtime, &["--print-sql"]);
    assert_refused(
        &output,
        "coordinator.runtime-config.refused",
        "/database/caBundleRef",
    );
}

#[test]
fn a_runtime_file_the_service_would_refuse_is_refused_with_its_own_diagnostic() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime_file(directory.path());
    fs::write(&runtime, "kind: NotARuntimeFile\n").unwrap();
    let output = provision(&runtime, &["--print-sql"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(!stderr.is_empty());
    assert!(!stderr.contains("postgres://"));
}

#[test]
fn provision_refuses_conflicting_global_and_local_posture_flags() {
    assert_provision_posture_refusal("production", "development", "platform.posture.conflict");
}

#[test]
fn provision_reports_an_invalid_global_posture_even_with_a_valid_local_flag() {
    assert_provision_posture_refusal("Production", "production", "platform.posture.invalid-value");
}

fn assert_provision_posture_refusal(global: &str, local: &str, code: &str) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .env_remove("REGISTRY_STACK_POSTURE")
        .args([
            "--format",
            "json",
            "--posture",
            global,
            "provision",
            "--posture",
            local,
            "--runtime-config=unused.yaml",
            "--print-sql",
        ])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(2), "{report}");
    assert_eq!(report["diagnostics"][0]["code"], code, "{report}");
}
