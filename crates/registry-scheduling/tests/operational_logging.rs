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

#[test]
fn a_stdout_audit_destination_never_carries_operational_logs() {
    let root = canonical_tempdir();
    let package = stage_package(root.path());
    let runtime = serde_json::json!({
        "apiVersion": "registry.registrystack.org/scheduling-runtime/v1alpha1",
        "kind": "SchedulingRuntimeConfig",
        "package": {"root": package},
        "listener": {"bind": "127.0.0.1:0", "tlsTermination": "development-loopback"},
        "secretProviders": {"environment": {}},
        "database": {
            "runtimeUrlRef": "secret:env/SCHEDULING_TEST_RUNTIME_URL",
            "migrationUrlRef": "secret:env/SCHEDULING_TEST_MIGRATION_URL"
        },
        "authentication": {"oidc": {
            "issuer": "https://identity.example.test",
            "audience": "urn:example:scheduling"
        }},
        "audit": {"destination": "stdout", "hashKeyRef": "secret:env/SCHEDULING_TEST_AUDIT_KEY"},
        "destinations": {},
        "retention": {"attemptReceiptDays": 7}
    });
    let runtime_path = root.path().join("runtime.yaml");
    std::fs::write(
        &runtime_path,
        serde_norway::to_string(&runtime).expect("runtime renders"),
    )
    .expect("runtime writes");

    // Serving logs the verified package, then stops at the database, which
    // nothing listens for; no PostgreSQL is needed to see where logs go.
    let output = Command::new(env!("CARGO_BIN_EXE_scheduling"))
        .arg("--runtime-config")
        .arg(&runtime_path)
        .arg("serve")
        .env("RUST_LOG", "info")
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
        .expect("scheduling runs");

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
