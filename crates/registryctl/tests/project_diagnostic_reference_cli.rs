// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::process::{Command, Output};

use tempfile::TempDir;

const AUTHORING_FIXTURE: &[u8] =
    include_bytes!("fixtures/project-reports/registryctl.authoring_error_reference.v1.json");
const FIXTURE_FIXTURE: &[u8] =
    include_bytes!("fixtures/project-reports/registryctl.fixture_error_reference.v1.json");
const OPERATOR_FIXTURE: &[u8] =
    include_bytes!("fixtures/project-reports/registryctl.operator_error_reference.v1.json");
const SENTINEL: &str = "COUNTRY_SECRET_SENTINEL_DIAGNOSTIC_CLI";

#[test]
fn json_catalogs_are_workspace_independent_deterministic_and_byte_exact() {
    let directory = hostile_workspace();
    for (catalog, expected) in [
        ("authoring", AUTHORING_FIXTURE),
        ("fixture", FIXTURE_FIXTURE),
        ("operator", OPERATOR_FIXTURE),
    ] {
        let first = run(directory.path(), catalog, "json");
        let second = run(directory.path(), catalog, "json");
        assert!(
            first.status.success(),
            "{catalog} failed: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert!(first.stderr.is_empty());
        assert_eq!(first.stdout, expected);
        assert_eq!(second.status, first.status);
        assert_eq!(second.stdout, first.stdout);
        assert_eq!(second.stderr, first.stderr);
        assert!(!String::from_utf8_lossy(&first.stdout).contains(SENTINEL));
        assert!(
            !String::from_utf8_lossy(&first.stdout).contains(directory.path().to_str().unwrap())
        );
    }
}

#[test]
fn human_catalogs_are_deterministic_static_and_value_free() {
    let directory = hostile_workspace();
    for catalog in ["authoring", "fixture", "operator"] {
        let first = run(directory.path(), catalog, "human");
        let second = run(directory.path(), catalog, "human");
        assert!(first.status.success());
        assert!(first.stderr.is_empty());
        assert_eq!(second.stdout, first.stdout);
        assert_eq!(second.stderr, first.stderr);
        let stdout = String::from_utf8(first.stdout).unwrap();
        assert!(stdout.contains(&format!("Registryctl {catalog} diagnostic catalog:")));
        assert!(!stdout.contains(SENTINEL));
        assert!(!stdout.contains(directory.path().to_str().unwrap()));
    }
}

#[test]
fn unknown_catalog_is_a_usage_error() {
    let directory = hostile_workspace();
    let output = run(directory.path(), "country", "json");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid value 'country'"));
}

fn hostile_workspace() -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("registry-stack.yaml"),
        format!("country_secret: {SENTINEL}\n"),
    )
    .unwrap();
    directory
}

fn run(directory: &std::path::Path, catalog: &str, format: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .current_dir(directory)
        .env_clear()
        .env("REGISTRY_CONFIG", SENTINEL)
        .env("REGISTRY_RELAY_CONFIG", SENTINEL)
        .env("REGISTRY_NOTARY_CONFIG", SENTINEL)
        .env("REGISTRYCTL_UPDATE_ENDPOINT", SENTINEL)
        .env("COUNTRY_SECRET", SENTINEL)
        .args([
            "tooling",
            "diagnostics",
            "--catalog",
            catalog,
            "--format",
            format,
        ])
        .output()
        .unwrap()
}
