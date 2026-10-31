// SPDX-License-Identifier: Apache-2.0
use serde_json::Value;
use std::{path::PathBuf, process::Command};

#[test]
fn help_and_version_answer_without_runtime_configuration() {
    for flag in ["--help", "--version"] {
        let result = Command::new(env!("CARGO_BIN_EXE_registry-mcp"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{flag}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stderr.is_empty(), "{flag}");
        assert!(!result.stdout.is_empty(), "{flag}");
    }

    let result = Command::new(env!("CARGO_BIN_EXE_registry-mcp"))
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(result.stdout).unwrap(),
        format!(
            "registry-mcp {}\n",
            registry_platform_buildinfo::DISPLAY_VERSION
        )
    );
}

fn example() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/platform/examples/mcp-runtime/runtime.example.yaml")
        .canonicalize()
        .unwrap()
}
#[test]
fn offline_example_check_does_not_resolve_referenced_credentials() {
    let staff = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/platform/examples/mcp-runtime/casework.example.yaml")
        .canonicalize()
        .unwrap();
    for path in [example(), staff] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_registry-mcp"));
        command.env_clear();
        // Cargo supplies native linker paths on platforms with a shared FIPS module.
        for name in [
            "DYLD_LIBRARY_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "LD_LIBRARY_PATH",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let result = command
            .args([
                "--runtime-config",
                path.to_str().unwrap(),
                "check",
                "--format",
                "json",
            ])
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["status"], "complete");
        assert_eq!(report["errors"], 0);
        assert!(result.stderr.is_empty());
    }
}
#[test]
fn unreadable_configuration_is_an_operational_failure_with_exit_three() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .canonicalize()
        .unwrap()
        .join("missing.yaml");
    let result = Command::new(env!("CARGO_BIN_EXE_registry-mcp"))
        .args([
            "--runtime-config",
            path.to_str().unwrap(),
            "check",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["status"], "operational-failure");
    assert!(report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|diagnostic| diagnostic["code"] == "platform.runtime-config.unavailable"));
    assert!(result.stderr.is_empty());
}

#[test]
fn missing_staff_authority_is_refused_without_credentials() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/casework-missing-authority.yaml")
        .canonicalize()
        .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-mcp"));
    command.env_clear();
    // Only retain Cargo's native linker paths, not credential configuration.
    for name in [
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "LD_LIBRARY_PATH",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let result = command
        .args([
            "--runtime-config",
            path.to_str().unwrap(),
            "check",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stderr.is_empty());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(report["errors"], 1);
    let diagnostics = report["diagnostics"].as_array().unwrap();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0]["code"], "config.missing-key");
    assert_eq!(diagnostics[0]["path"], "/bindings/0/provider");
}
#[test]
fn human_check_refusals_use_stderr_and_a_headline() {
    let directory = tempfile::tempdir().unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_registry-mcp"))
        .args([
            "--runtime-config",
            directory.path().join("missing.yaml").to_str().unwrap(),
            "check",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr)
        .contains("registry-mcp check could not read all of its input."));
}

#[test]
fn offline_check_resolves_a_relative_config_path_without_resolving_secrets() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::copy(example(), directory.path().join("runtime.yaml")).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_registry-mcp"))
        .current_dir(directory.path())
        .args([
            "--runtime-config",
            "runtime.yaml",
            "check",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stdout).unwrap()["ok"],
        true
    );
    assert!(result.stderr.is_empty());
}
