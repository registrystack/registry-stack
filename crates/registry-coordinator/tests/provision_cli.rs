// SPDX-License-Identifier: Apache-2.0
//! `coordinatorctl provision` without a server: the printed plan and the
//! usage refusals.
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

const RUNTIME: &str =
    include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml");
const MIGRATION_PASSWORD: &str = "migration-password-canary";
const RUNTIME_PASSWORD: &str = "runtime-password-canary";

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

fn provision(runtime: &Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .arg("provision")
        .arg("--runtime-config")
        .arg(runtime)
        .args(extra)
        .env(
            "COORDINATOR_MIGRATION_URL",
            format!("postgres://coordinator_migration:{MIGRATION_PASSWORD}@db.example.org:5432/coordinator"),
        )
        .env(
            "COORDINATOR_DATABASE_URL",
            format!("postgres://coordinator_runtime:{RUNTIME_PASSWORD}@db.example.org:5432/coordinator"),
        )
        .output()
        .unwrap()
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
