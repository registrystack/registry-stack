// SPDX-License-Identifier: Apache-2.0

//! The `scheduling` binary keeps its operational logs off stdout, so a
//! `stdout` audit destination carries audit entries alone.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use registry_platform_config::package::write_sum_file;
use registry_scheduling::config::{package_limits, PACKAGE_COMMAND};

/// A temporary directory named by its canonical path: the loader refuses a
/// runtime configuration reached through a symbolic link.
fn canonical_tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).expect("temp dir"))
        .expect("temporary directory")
}

fn stage_package(root: &Path) -> PathBuf {
    let package = root.join("package");
    std::fs::create_dir_all(&package).expect("package directory");
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/scheduling/examples/standalone-exact-time/scheduling.yaml");
    std::fs::copy(example, package.join("scheduling.yaml")).expect("policy");
    write_sum_file(&package, None, &package_limits(), PACKAGE_COMMAND).expect("package");
    package
}

/// Run `scheduling serve` over a `stdout` audit destination with `RUST_LOG`
/// set to `rust_log`, or removed when it is `None`.
fn serve_with_stdout_audit(rust_log: Option<&str>) -> std::process::Output {
    let root = canonical_tempdir();
    let package = stage_package(root.path());
    let runtime = serde_json::json!({
        "apiVersion": registry_scheduling_core::SCHEDULING_RUNTIME_API_VERSION,
        "kind": "SchedulingRuntimeConfig",
        "package": {"root": package},
        "identity": {"databaseId": "scheduling-operational-logging"},
        "listener": {"bind": "127.0.0.1:0", "tlsTermination": "development-loopback"},
        "secretProviders": {"environment": {}},
        "database": {
            "runtimeUrlRef": "secret:env/SCHEDULING_TEST_RUNTIME_URL",
            "migrationUrlRef": "secret:env/SCHEDULING_TEST_MIGRATION_URL"
        },
        "authentication": {"oidc": {
            "issuer": "https://identity.example.test",
            "audience": "urn:example:scheduling",
            "allowedClients": ["scheduling-test-client"]
        }},
        "audit": {"destination": "stdout", "hashKeyRef": "secret:env/SCHEDULING_TEST_AUDIT_KEY"},
        "destinations": {},
        "retention": {"attemptReceiptRetentionDays": 7}
    });
    let runtime_path = root.path().join("runtime.yaml");
    std::fs::write(
        &runtime_path,
        serde_norway::to_string(&runtime).expect("runtime renders"),
    )
    .expect("runtime writes");

    // Serving logs the verified package, then stops at the database, which
    // nothing listens for; no PostgreSQL is needed to see where logs go.
    let mut command = Command::new(env!("CARGO_BIN_EXE_scheduling"));
    match rust_log {
        Some(filter) => command.env("RUST_LOG", filter),
        None => command.env_remove("RUST_LOG"),
    };
    command
        .arg("--runtime-config")
        .arg(&runtime_path)
        .arg("serve")
        .env(
            "SCHEDULING_TEST_RUNTIME_URL",
            "postgres://scheduling@127.0.0.1:1/scheduling",
        )
        .env(
            "SCHEDULING_TEST_MIGRATION_URL",
            "postgres://scheduling@127.0.0.1:1/scheduling",
        )
        .env(
            "SCHEDULING_TEST_AUDIT_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .output()
        .expect("scheduling runs")
}

#[test]
fn a_stdout_audit_destination_never_carries_operational_logs() {
    let output = serve_with_stdout_audit(Some("info"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("verified Scheduling package"),
        "the operational log reaches stderr: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "stdout carried non-audit output: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn info_records_reach_stderr_when_rust_log_is_unset() {
    let output = serve_with_stdout_audit(None);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("verified Scheduling package"),
        "an info record reaches stderr without RUST_LOG: {stderr}"
    );
}

#[test]
fn an_invalid_rust_log_falls_back_to_info() {
    let output = serve_with_stdout_audit(Some("=not a filter="));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("verified Scheduling package"),
        "an info record reaches stderr with an invalid RUST_LOG: {stderr}"
    );
}
