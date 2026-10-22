// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn runtime(path: &Path, name: &str, exit: u8) -> PathBuf {
    let binary = path.join(name);
    fs::write(
        &binary,
        format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'runtime-stdout\\n'\nprintf 'runtime-stderr\\n' >&2\nprintf '%s\\n' \"$$\" \"$@\" > \"$RUNTIME_CAPTURE\"\nexit {exit}\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    binary
}

fn run(binary: &Path, capture: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(arguments)
        .env("BREG_BIN", binary)
        .env("RUNTIME_CAPTURE", capture)
        .env_remove("RSTACK_GENERATION_DIR")
        .output()
        .expect("bregctl starts")
}

#[test]
fn unmanaged_serve_preserves_runtime_arguments_streams_process_and_exit() {
    let temp = tempfile::tempdir().unwrap();
    let binary = runtime(temp.path(), "breg", 17);
    let capture = temp.path().join("capture");
    let child = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["serve", "--runtime-config", "/tmp/runtime.yaml"])
        .env("BREG_BIN", &binary)
        .env("RUNTIME_CAPTURE", &capture)
        .env_remove("RSTACK_GENERATION_DIR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("bregctl starts");
    let expected_pid = child.id().to_string();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(17));
    assert_eq!(output.stdout, b"runtime-stdout\n");
    assert_eq!(output.stderr, b"runtime-stderr\n");
    assert_eq!(
        fs::read_to_string(capture).unwrap(),
        format!("{expected_pid}\n--runtime-config\n/tmp/runtime.yaml\n")
    );
}

#[test]
fn unmanaged_serve_falls_back_to_path_without_a_binary_override() {
    let temp = tempfile::tempdir().unwrap();
    runtime(temp.path(), "breg", 21);
    let capture = temp.path().join("capture");
    let path = std::env::join_paths(std::iter::once(temp.path().to_owned()).chain(
        std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set")),
    ))
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["serve", "--runtime-config", "/tmp/path.yaml"])
        .env("PATH", path)
        .env("RUNTIME_CAPTURE", &capture)
        .env_remove("BREG_BIN")
        .env_remove("RSTACK_GENERATION_DIR")
        .output()
        .expect("bregctl starts");

    assert_eq!(output.status.code(), Some(21));
    assert_eq!(
        fs::read_to_string(capture)
            .unwrap()
            .lines()
            .skip(1)
            .collect::<Vec<_>>(),
        ["--runtime-config", "/tmp/path.yaml"]
    );
}

#[test]
fn managed_serve_uses_the_selected_generation_instead_of_path() {
    let temp = tempfile::tempdir().unwrap();
    let generation = temp.path().join("generation");
    let selected_directory = generation.join("components/breg/breg");
    fs::create_dir_all(&selected_directory).unwrap();
    let selected = runtime(&selected_directory, "breg", 19);
    let poisoned_directory = temp.path().join("poisoned");
    fs::create_dir(&poisoned_directory).unwrap();
    let poisoned = runtime(&poisoned_directory, "breg", 97);
    let capture = temp.path().join("capture");
    let poisoned_path = std::env::join_paths(std::iter::once(poisoned_directory.clone()).chain(
        std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set")),
    ))
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["serve", "--runtime-config", "/tmp/managed.yaml"])
        .env("PATH", poisoned_path)
        .env("RUNTIME_CAPTURE", &capture)
        .env("RSTACK_GENERATION_DIR", &generation)
        .env("RSTACK_BREG_BIN", &selected)
        .env("RSTACK_RELEASE_TAG", "v-test")
        .env_remove("BREG_BIN")
        .output()
        .expect("bregctl starts");

    assert_eq!(output.status.code(), Some(19));
    assert_eq!(
        fs::read_to_string(capture)
            .unwrap()
            .lines()
            .skip(1)
            .collect::<Vec<_>>(),
        ["--runtime-config", "/tmp/managed.yaml"]
    );
    assert_ne!(selected, poisoned);
}

#[test]
fn serve_rejects_json_report_format_before_starting_the_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let binary = runtime(temp.path(), "breg", 0);
    let capture = temp.path().join("capture");
    let output = run(
        &binary,
        &capture,
        &[
            "--format",
            "json",
            "serve",
            "--runtime-config",
            "/tmp/runtime.yaml",
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "usage");
    assert!(!capture.exists(), "the runtime must not start");
}

#[test]
fn serve_rejects_explicit_human_report_format_before_starting_the_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let binary = runtime(temp.path(), "breg", 0);
    let capture = temp.path().join("capture");
    let output = run(
        &binary,
        &capture,
        &[
            "serve",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--format",
            "human",
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--format does not apply"));
    assert!(!capture.exists(), "the runtime must not start");
}
