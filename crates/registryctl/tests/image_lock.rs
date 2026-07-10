// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::process::Command;

use serde_json::json;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

const RELAY_IMAGE: &str = "ghcr.io/registrystack/registry-relay@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NOTARY_IMAGE: &str = "ghcr.io/registrystack/registry-notary@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn write_image_lock(temp: &TempDir) -> std::path::PathBuf {
    let path = temp.path().join("release-image-lock.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "registryctl.release_image_lock.v1",
            "release_tag": format!("v{}", env!("CARGO_PKG_VERSION")),
            "manifest_source_ref": "a".repeat(40),
            "tag_target": "b".repeat(40),
            "platform": "linux/amd64",
            "images": {
                "registry-relay": RELAY_IMAGE,
                "registry-notary": NOTARY_IMAGE,
            }
        }))
        .unwrap(),
    )
    .unwrap();
    path
}

#[test]
fn init_uses_explicit_release_image_lock_without_registry_lookup() {
    let temp = TempDir::new().unwrap();
    let image_lock = write_image_lock(&temp);
    let project = temp.path().join("my-first-api");

    let output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "init",
            "relay",
            project.to_str().unwrap(),
            "--sample",
            "benefits",
        ])
        .env("REGISTRYCTL_IMAGE_LOCK", &image_lock)
        .env("REGISTRYCTL_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest = fs::read_to_string(project.join("registryctl.yaml")).unwrap();
    let compose = fs::read_to_string(project.join("compose.yaml")).unwrap();
    assert!(manifest.contains(RELAY_IMAGE));
    assert!(compose.contains(RELAY_IMAGE));
    assert!(!manifest.contains("registry-notary"));
}

#[test]
fn missing_release_image_lock_fails_before_init_mutates_target() {
    let temp = TempDir::new().unwrap();
    let missing_lock = temp.path().join("missing-image-lock.json");
    let project = temp.path().join("must-not-exist");

    let output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "init",
            "relay",
            project.to_str().unwrap(),
            "--sample",
            "benefits",
        ])
        .env("REGISTRYCTL_IMAGE_LOCK", &missing_lock)
        .env("REGISTRYCTL_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        !project.exists(),
        "init mutated the target before lock validation"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("registryctl image lock is missing"),
        "{stderr}"
    );
    assert!(stderr.contains("REGISTRYCTL_IMAGE_LOCK"), "{stderr}");
}

#[test]
fn init_does_not_search_current_working_directory_for_image_lock() {
    let temp = TempDir::new().unwrap();
    let explicit_lock = write_image_lock(&temp);
    let cwd_lock = temp.path().join(format!(
        "registryctl-v{}-image-lock.json",
        env!("CARGO_PKG_VERSION")
    ));
    fs::rename(explicit_lock, &cwd_lock).unwrap();
    let project = temp.path().join("must-not-exist");

    let output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "init",
            "relay",
            project.to_str().unwrap(),
            "--sample",
            "benefits",
        ])
        .current_dir(temp.path())
        .env_remove("REGISTRYCTL_IMAGE_LOCK")
        .env("REGISTRYCTL_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!project.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("registryctl image lock is missing"),
        "{stderr}"
    );
    assert!(!stderr.contains(cwd_lock.to_str().unwrap()), "{stderr}");
}

#[cfg(unix)]
#[test]
fn existing_project_runtime_command_does_not_consult_image_lock() {
    let temp = TempDir::new().unwrap();
    let image_lock = write_image_lock(&temp);
    let project = temp.path().join("my-first-api");
    let init = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "init",
            "relay",
            project.to_str().unwrap(),
            "--sample",
            "benefits",
        ])
        .env("REGISTRYCTL_IMAGE_LOCK", &image_lock)
        .env("REGISTRYCTL_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    assert!(init.status.success());

    let fake_bin = temp.path().join("fake-bin");
    fs::create_dir(&fake_bin).unwrap();
    let docker = fake_bin.join("docker");
    fs::write(&docker, b"#!/usr/bin/env sh\nexit 0\n").unwrap();
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let missing_lock = temp.path().join("missing-image-lock.json");

    let output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .arg("stop")
        .current_dir(&project)
        .env("PATH", path)
        .env("REGISTRYCTL_IMAGE_LOCK", missing_lock)
        .env("REGISTRYCTL_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stop failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("image lock"));
}
