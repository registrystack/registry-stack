// SPDX-License-Identifier: Apache-2.0
use std::{fs, process::Command};

#[test]
fn production_refuses_hosted_development_start_before_writing() {
    let root = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["rstack-dev", "start"])
        .arg(root.path())
        .env("REGISTRY_STACK_POSTURE", "production")
        .env("RSTACK_DEV_STATE_DIR", root.path().join("state"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("platform.posture.conflict"), "{stderr}");
    assert!(output.stdout.is_empty());
    assert!(root.path().read_dir().unwrap().next().is_none());
}

#[test]
fn serve_defaults_to_production_and_refuses_a_test_issuer() {
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime.yaml");
    let example = include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml");
    let config = example.replace(
        "type: discovery",
        "type: test-issuer\n          documentRef: secret:file/jwks.json",
    );
    assert_ne!(config, example);
    fs::write(&runtime, config).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["serve", "--coordinator-bin"])
        .arg(env!("CARGO_BIN_EXE_coordinator"))
        .arg("--runtime-config")
        .arg(runtime)
        .env_remove("REGISTRY_STACK_POSTURE")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("platform.posture.test-issuer"), "{stderr}");
}
