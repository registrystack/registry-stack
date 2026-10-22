// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[derive(Clone, Copy)]
struct Service {
    command: &'static str,
    binary: &'static str,
    unmanaged_env: &'static str,
    managed_env: &'static str,
}

const MCP: Service = Service {
    command: "mcp",
    binary: "breg-mcp",
    unmanaged_env: "BREG_MCP_BIN",
    managed_env: "RSTACK_BREG_MCP_BIN",
};

const REVIEW: Service = Service {
    command: "review",
    binary: "breg-review",
    unmanaged_env: "BREG_REVIEW_BIN",
    managed_env: "RSTACK_BREG_REVIEW_BIN",
};

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

fn run(service: Service, binary: &Path, capture: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(arguments)
        .env(service.unmanaged_env, binary)
        .env("RUNTIME_CAPTURE", capture)
        .env_remove("RSTACK_GENERATION_DIR")
        .output()
        .expect("bregctl starts")
}

#[test]
fn unmanaged_service_serve_preserves_arguments_streams_process_status_and_lease() {
    for service in [MCP, REVIEW] {
        let temp = tempfile::tempdir().unwrap();
        let binary = runtime(temp.path(), service.binary, 17);
        let capture = temp.path().join("capture");
        let lease = temp.path().join("lease");
        let mut launcher = Command::new("/bin/bash");
        launcher
            .args([
                "-c",
                "exec 9>\"$RUNTIME_LEASE_CAPTURE\"; export RUNTIME_LEASE_FD=9; export DYLD_FALLBACK_LIBRARY_PATH=\"${RESTORE_DYLD_FALLBACK_LIBRARY_PATH:-}\"; export DYLD_LIBRARY_PATH=\"${RESTORE_DYLD_LIBRARY_PATH:-}\"; export LD_LIBRARY_PATH=\"${RESTORE_LD_LIBRARY_PATH:-}\"; exec \"$CTL_BIN\" \"$@\"",
                "bregctl-launcher",
                service.command,
                "serve",
                "--runtime-config",
                "/tmp/runtime.yaml",
            ])
            .env("CTL_BIN", env!("CARGO_BIN_EXE_bregctl"))
            .env(service.unmanaged_env, &binary)
            .env("RUNTIME_CAPTURE", &capture)
            .env("RUNTIME_LEASE_CAPTURE", &lease)
            .env_remove("RSTACK_GENERATION_DIR")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (source, backup) in [
            (
                "DYLD_FALLBACK_LIBRARY_PATH",
                "RESTORE_DYLD_FALLBACK_LIBRARY_PATH",
            ),
            ("DYLD_LIBRARY_PATH", "RESTORE_DYLD_LIBRARY_PATH"),
            ("LD_LIBRARY_PATH", "RESTORE_LD_LIBRARY_PATH"),
        ] {
            if let Some(value) = std::env::var_os(source) {
                launcher.env(backup, value);
            }
        }
        let child = launcher.spawn().expect("bregctl starts");
        let expected_pid = child.id().to_string();
        let output = child.wait_with_output().unwrap();

        assert_eq!(output.status.code(), Some(17), "{}", service.binary);
        assert_eq!(output.stdout, b"runtime-stdout\n");
        assert_eq!(output.stderr, b"runtime-stderr\n");
        assert_eq!(fs::read_to_string(lease).unwrap(), "lease-inherited\n");
        assert_eq!(
            fs::read_to_string(capture).unwrap(),
            format!("{expected_pid}\n--runtime-config\n/tmp/runtime.yaml\nserve\n")
        );
    }
}

#[test]
fn unmanaged_service_serve_falls_back_to_path() {
    for service in [MCP, REVIEW] {
        let temp = tempfile::tempdir().unwrap();
        runtime(temp.path(), service.binary, 21);
        let capture = temp.path().join("capture");
        let path = std::env::join_paths(std::iter::once(temp.path().to_owned()).chain(
            std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set")),
        ))
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
            .args([
                service.command,
                "serve",
                "--runtime-config",
                "/tmp/path.yaml",
            ])
            .env("PATH", path)
            .env("RUNTIME_CAPTURE", &capture)
            .env_remove(service.unmanaged_env)
            .env_remove("RSTACK_GENERATION_DIR")
            .output()
            .expect("bregctl starts");

        assert_eq!(output.status.code(), Some(21), "{}", service.binary);
        assert_eq!(
            fs::read_to_string(capture)
                .unwrap()
                .lines()
                .skip(1)
                .collect::<Vec<_>>(),
            ["--runtime-config", "/tmp/path.yaml", "serve"]
        );
    }
}

#[test]
fn managed_service_serve_uses_the_selected_generation_instead_of_path() {
    for service in [MCP, REVIEW] {
        let temp = tempfile::tempdir().unwrap();
        let generation = temp.path().join("generation");
        let selected_directory = generation.join("components/breg").join(service.binary);
        fs::create_dir_all(&selected_directory).unwrap();
        let selected = runtime(&selected_directory, service.binary, 19);
        let poisoned_directory = temp.path().join("poisoned");
        fs::create_dir(&poisoned_directory).unwrap();
        runtime(&poisoned_directory, service.binary, 97);
        let capture = temp.path().join("capture");
        let poisoned_path = std::env::join_paths(std::iter::once(poisoned_directory).chain(
            std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set")),
        ))
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
            .args([
                service.command,
                "serve",
                "--runtime-config",
                "/tmp/managed.yaml",
            ])
            .env("PATH", poisoned_path)
            .env("RUNTIME_CAPTURE", &capture)
            .env("RSTACK_GENERATION_DIR", &generation)
            .env(service.managed_env, &selected)
            .env("RSTACK_RELEASE_TAG", "v-test")
            .env_remove(service.unmanaged_env)
            .output()
            .expect("bregctl starts");

        assert_eq!(output.status.code(), Some(19), "{}", service.binary);
        assert_eq!(
            fs::read_to_string(capture)
                .unwrap()
                .lines()
                .skip(1)
                .collect::<Vec<_>>(),
            ["--runtime-config", "/tmp/managed.yaml", "serve"]
        );
    }
}

#[test]
fn managed_service_does_not_fall_back_when_the_optional_binary_is_absent() {
    for service in [MCP, REVIEW] {
        let temp = tempfile::tempdir().unwrap();
        let generation = temp.path().join("generation");
        fs::create_dir(&generation).unwrap();
        let poisoned_directory = temp.path().join("poisoned");
        fs::create_dir(&poisoned_directory).unwrap();
        runtime(&poisoned_directory, service.binary, 97);
        let capture = temp.path().join("capture");
        let path = std::env::join_paths(std::iter::once(poisoned_directory).chain(
            std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set")),
        ))
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
            .args([
                service.command,
                "serve",
                "--runtime-config",
                "/tmp/managed.yaml",
            ])
            .env("PATH", path)
            .env("RUNTIME_CAPTURE", &capture)
            .env("RSTACK_GENERATION_DIR", &generation)
            .env("RSTACK_RELEASE_TAG", "v-test")
            .env_remove(service.managed_env)
            .env_remove(service.unmanaged_env)
            .output()
            .expect("bregctl starts");

        assert_eq!(output.status.code(), Some(3), "{}", service.binary);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(service.binary), "{stderr}");
        assert!(stderr.contains("rstack install breg"), "{stderr}");
        assert!(!capture.exists(), "a PATH runtime must not start");
    }
}

#[test]
fn managed_service_refuses_a_same_version_unmanaged_override() {
    for service in [MCP, REVIEW] {
        let temp = tempfile::tempdir().unwrap();
        let generation = temp.path().join("generation");
        let selected_directory = generation.join("components/breg").join(service.binary);
        fs::create_dir_all(&selected_directory).unwrap();
        let selected = runtime(&selected_directory, service.binary, 19);
        let outside = runtime(temp.path(), "same-version-outside", 97);
        fs::write(&outside, fs::read(&selected).unwrap()).unwrap();
        let capture = temp.path().join("capture");
        let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
            .args([
                service.command,
                "serve",
                "--runtime-config",
                "/tmp/managed.yaml",
            ])
            .env(service.unmanaged_env, &outside)
            .env("RUNTIME_CAPTURE", &capture)
            .env("RSTACK_GENERATION_DIR", &generation)
            .env(service.managed_env, &selected)
            .env("RSTACK_RELEASE_TAG", "v-test")
            .output()
            .expect("bregctl starts");

        assert_eq!(output.status.code(), Some(3), "{}", service.binary);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("selected generation"), "{stderr}");
        assert!(stderr.contains("matching version string"), "{stderr}");
        assert!(!capture.exists(), "the unmanaged override must not start");
    }
}

#[test]
fn service_check_forwards_report_format_and_check_options() {
    for service in [MCP, REVIEW] {
        let temp = tempfile::tempdir().unwrap();
        let binary = runtime(temp.path(), service.binary, 23);
        let capture = temp.path().join("capture");
        let output = run(
            service,
            &binary,
            &capture,
            &[
                "--format",
                "json",
                service.command,
                "check",
                "--runtime-config",
                "/tmp/check.yaml",
                "--deny-warnings",
                "--environment",
            ],
        );

        assert_eq!(output.status.code(), Some(23), "{}", service.binary);
        assert_eq!(
            fs::read_to_string(capture)
                .unwrap()
                .lines()
                .skip(1)
                .collect::<Vec<_>>(),
            [
                "--runtime-config",
                "/tmp/check.yaml",
                "check",
                "--format",
                "json",
                "--deny-warnings",
                "--environment"
            ]
        );
    }
}

#[test]
fn service_serve_rejects_explicit_json_report_format_before_launch() {
    for service in [MCP, REVIEW] {
        let temp = tempfile::tempdir().unwrap();
        let binary = runtime(temp.path(), service.binary, 0);
        let capture = temp.path().join("capture");
        let output = run(
            service,
            &binary,
            &capture,
            &[
                service.command,
                "serve",
                "--runtime-config",
                "/tmp/runtime.yaml",
                "--format",
                "json",
            ],
        );

        assert_eq!(output.status.code(), Some(2), "{}", service.binary);
        assert!(output.stderr.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["ok"], false);
        assert_eq!(report["command"], "usage");
        assert!(!capture.exists(), "the service must not start");
    }
}

#[test]
fn service_serve_rejects_explicit_human_report_format_before_launch() {
    for service in [MCP, REVIEW] {
        let temp = tempfile::tempdir().unwrap();
        let binary = runtime(temp.path(), service.binary, 0);
        let capture = temp.path().join("capture");
        let output = run(
            service,
            &binary,
            &capture,
            &[
                "--format",
                "human",
                service.command,
                "serve",
                "--runtime-config",
                "/tmp/runtime.yaml",
            ],
        );

        assert_eq!(output.status.code(), Some(2), "{}", service.binary);
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("--format does not apply"));
        assert!(!capture.exists(), "the service must not start");
    }
}
