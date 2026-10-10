// SPDX-License-Identifier: Apache-2.0

//! The shipped feature set refuses the test-only PostgreSQL transport switch.
#![cfg(not(feature = "postgres-test"))]

use std::{path::Path, process::Command};

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the test edits a maintained fixture, not operator configuration"
)]
fn the_default_feature_runtime_refuses_test_only_plaintext() {
    let root = tempfile::tempdir_in(
        std::fs::canonicalize(std::env::temp_dir()).expect("canonical temporary root"),
    )
    .expect("temporary directory");
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/messaging/examples/starter/runtime.example.yaml");
    let mut runtime: serde_json::Value =
        serde_norway::from_str(&std::fs::read_to_string(example).expect("runtime example"))
            .expect("the maintained example is YAML");
    runtime["database"]["testOnlyPlaintext"] = serde_json::json!(true);
    runtime["secretProviders"]["file"]["root"] = serde_json::json!(root.path());
    runtime["package"]["root"] = serde_json::json!(root.path().join("unused-package"));
    let path = root.path().join("runtime.yaml");
    std::fs::write(
        &path,
        serde_json::to_vec(&runtime).expect("runtime serializes"),
    )
    .expect("runtime writes");

    let output = Command::new(env!("CARGO_BIN_EXE_messaging"))
        .arg("--runtime-config")
        .arg(&path)
        .arg("serve")
        .env_remove("RUST_LOG")
        .output()
        .expect("the default-feature runtime executes");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("messaging.runtime.plaintext-database"),
        "{stderr}"
    );
    assert!(stderr.contains("testOnlyPlaintext"), "{stderr}");
}
