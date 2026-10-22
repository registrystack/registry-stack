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
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'runtime-stdout\\n'\nprintf 'runtime-stderr\\n' >&2\nprintf '%s\\n' \"$$\" \"$@\" > \"$RUNTIME_CAPTURE\"\nif [[ -n \"${{RUNTIME_LEASE_FD:-}}\" ]]; then printf 'lease-inherited\\n' >&\"$RUNTIME_LEASE_FD\"; fi\nexit {exit}\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    binary
}

fn run(binary: &Path, capture: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_discoveryctl"))
        .args(arguments)
        .env("DISCOVERY_BIN", binary)
        .env("RUNTIME_CAPTURE", capture)
        .env_remove("RSTACK_GENERATION_DIR")
        .output()
        .expect("discoveryctl starts")
}

fn restore_dynamic_libraries(command: &mut Command) {
    for (source, backup) in [
        (
            "DYLD_FALLBACK_LIBRARY_PATH",
            "RESTORE_DYLD_FALLBACK_LIBRARY_PATH",
        ),
        ("DYLD_LIBRARY_PATH", "RESTORE_DYLD_LIBRARY_PATH"),
        ("LD_LIBRARY_PATH", "RESTORE_LD_LIBRARY_PATH"),
    ] {
        if let Some(value) = std::env::var_os(source) {
            command.env(backup, value);
        }
    }
}

#[test]
fn unmanaged_serve_preserves_runtime_arguments_streams_process_status_and_lease() {
    let temp = tempfile::tempdir().unwrap();
    let binary = runtime(temp.path(), "discovery", 17);
    let capture = temp.path().join("capture");
    let lease = temp.path().join("lease");
    let mut launcher = Command::new("/bin/bash");
    launcher
        .args([
            "-c",
            "exec 9>\"$RUNTIME_LEASE_CAPTURE\"; export RUNTIME_LEASE_FD=9; export DYLD_FALLBACK_LIBRARY_PATH=\"${RESTORE_DYLD_FALLBACK_LIBRARY_PATH:-}\"; export DYLD_LIBRARY_PATH=\"${RESTORE_DYLD_LIBRARY_PATH:-}\"; export LD_LIBRARY_PATH=\"${RESTORE_LD_LIBRARY_PATH:-}\"; exec \"$CTL_BIN\" \"$@\"",
            "discoveryctl-launcher",
            "serve",
            "--runtime-config",
            "/tmp/runtime.yaml",
        ])
        .env("CTL_BIN", env!("CARGO_BIN_EXE_discoveryctl"))
        .env("DISCOVERY_BIN", &binary)
        .env("RUNTIME_CAPTURE", &capture)
        .env("RUNTIME_LEASE_CAPTURE", &lease)
        .env_remove("RSTACK_GENERATION_DIR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    restore_dynamic_libraries(&mut launcher);
    let child = launcher.spawn().expect("discoveryctl starts");
    let expected_pid = child.id().to_string();
    let output = child.wait_with_output().unwrap();

    assert_eq!(
        output.status.code(),
        Some(17),
        "status={:?}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"runtime-stdout\n");
    assert_eq!(output.stderr, b"runtime-stderr\n");
    assert_eq!(fs::read_to_string(lease).unwrap(), "lease-inherited\n");
    assert_eq!(
        fs::read_to_string(capture).unwrap(),
        format!("{expected_pid}\n--runtime-config\n/tmp/runtime.yaml\n")
    );
}

#[test]
fn unmanaged_serve_falls_back_to_path_without_a_binary_override() {
    let temp = tempfile::tempdir().unwrap();
    runtime(temp.path(), "discovery", 21);
    let capture = temp.path().join("capture");
    let path = std::env::join_paths(std::iter::once(temp.path().to_owned()).chain(
        std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set")),
    ))
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_discoveryctl"))
        .args(["serve", "--runtime-config", "/tmp/path.yaml"])
        .env("PATH", path)
        .env("RUNTIME_CAPTURE", &capture)
        .env_remove("DISCOVERY_BIN")
        .env_remove("RSTACK_GENERATION_DIR")
        .output()
        .expect("discoveryctl starts");

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
    let selected_directory = generation.join("components/discovery/discovery");
    fs::create_dir_all(&selected_directory).unwrap();
    let selected = runtime(&selected_directory, "discovery", 19);
    let poisoned_directory = temp.path().join("poisoned");
    fs::create_dir(&poisoned_directory).unwrap();
    runtime(&poisoned_directory, "discovery", 97);
    let capture = temp.path().join("capture");
    let poisoned_path = std::env::join_paths(std::iter::once(poisoned_directory).chain(
        std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set")),
    ))
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_discoveryctl"))
        .args(["serve", "--runtime-config", "/tmp/managed.yaml"])
        .env("PATH", poisoned_path)
        .env("RUNTIME_CAPTURE", &capture)
        .env("RSTACK_GENERATION_DIR", &generation)
        .env("RSTACK_DISCOVERY_BIN", &selected)
        .env("RSTACK_RELEASE_TAG", "v-test")
        .env_remove("DISCOVERY_BIN")
        .output()
        .expect("discoveryctl starts");

    assert_eq!(output.status.code(), Some(19));
    assert_eq!(
        fs::read_to_string(capture)
            .unwrap()
            .lines()
            .skip(1)
            .collect::<Vec<_>>(),
        ["--runtime-config", "/tmp/managed.yaml"]
    );
}

#[test]
fn serve_rejects_json_report_format_before_starting_the_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let binary = runtime(temp.path(), "discovery", 0);
    let capture = temp.path().join("capture");
    let output = run(
        &binary,
        &capture,
        &[
            "serve",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--format",
            "json",
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
    let binary = runtime(temp.path(), "discovery", 0);
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
    assert!(!output.stderr.is_empty());
    assert!(!capture.exists(), "the runtime must not start");
}
