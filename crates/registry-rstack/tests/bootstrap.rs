use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch() -> tempfile::TempDir {
    if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
        tempfile::tempdir_in(target).unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_release_launcher(path: &Path) {
    fs::write(
        path,
        b"#!/usr/bin/env bash\nset -euo pipefail\n[[ \"${1:-}\" == --version ]]\nprintf 'rstack 0.44.0\\n'\n",
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn release_fixture(directory: &Path, schema_version: &str) -> (PathBuf, PathBuf, PathBuf) {
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("macos", "aarch64") => "macos-arm64",
        other => panic!("unsupported test platform: {other:?}"),
    };
    let archive = platform == "macos-arm64";
    let asset_name = format!(
        "rstack-v0.44.0-{platform}{}",
        if archive { ".tar.gz" } else { "" }
    );
    let launcher = directory.join(&asset_name);
    if archive {
        let contents = directory.join("archive");
        fs::create_dir(&contents).unwrap();
        write_release_launcher(&contents.join("rstack-v0.44.0-macos-arm64"));
        fs::write(contents.join("THIRD_PARTY_NOTICES"), "test fixture\n").unwrap();
        let result = Command::new("tar")
            .args(["-czf"])
            .arg(&launcher)
            .arg("-C")
            .arg(&contents)
            .args(["rstack-v0.44.0-macos-arm64", "THIRD_PARTY_NOTICES"])
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
    } else {
        write_release_launcher(&launcher);
    }
    let binary = fs::read(&launcher).unwrap();
    let manifest_name = "registry-stack-v0.44.0-release-manifest.json";
    let manifest_path = directory.join(manifest_name);
    let mut manifest = json!({
        "schema_version": schema_version,
        "repository": "registrystack/registry-stack",
        "release": {
            "tag": "v0.44.0",
            "version": "0.44.0",
            "source_sha": "a".repeat(40),
            "release_id": "test"
        },
        "payloads": [{
            "name": asset_name,
            "kind": "binary",
            "size": binary.len(),
            "sha256": digest(&binary)
        }],
        "components": {
            "schema_version": "registry-stack.components.v1",
            "release": "v0.44.0",
            "launcher": {(platform): {
                "name": asset_name,
                "size": binary.len(),
                "sha256": digest(&binary)
            }},
            "components": {}
        }
    });
    if schema_version == "registry-stack.release-candidate.v3" {
        manifest["payloads"].as_array_mut().unwrap().extend([
            json!({"name": "docs.tar.gz", "kind": "docs", "size": 1, "sha256": "b".repeat(64)}),
            json!({"name": "sbom.json", "kind": "sbom", "size": 1, "sha256": "c".repeat(64)}),
            json!({"name": "security-evidence.tar.gz", "kind": "security-evidence", "size": 1, "sha256": "d".repeat(64)}),
            json!({"name": "distribution.json", "kind": "distribution", "size": 1, "sha256": "e".repeat(64)}),
        ]);
        manifest["workflow"] = json!({
            "path": ".github/workflows/release-candidate.yml",
            "revision": "a".repeat(40),
            "run_id": 123,
            "run_attempt": 1
        });
        manifest["validity"] = json!({
            "created_at": "2026-10-23T00:00:00Z",
            "expires_at": "2026-10-24T00:00:00Z"
        });
        manifest["images"] = json!([{
            "name": "breg",
            "candidate_ref": format!("ghcr.io/registrystack/breg-candidate@sha256:{}", "f".repeat(64)),
            "digest": format!("sha256:{}", "f".repeat(64)),
            "final_ref": "ghcr.io/registrystack/breg:v0.44.0"
        }]);
        manifest["docs"] = json!({"name": "docs.tar.gz", "sha256": "b".repeat(64)});
        manifest["sbom"] = json!({"name": "sbom.json", "sha256": "c".repeat(64)});
        manifest["scans"] = json!([{
            "image": "breg",
            "name": "breg.grype.json",
            "sha256": "1".repeat(64),
            "status": "passed"
        }]);
        manifest["advisory"] = json!({
            "name": "advisory.json",
            "sha256": "2".repeat(64),
            "verdict": "passed"
        });
        manifest["bundle"] = json!({
            "name": "candidate.tar.gz",
            "size": 1,
            "sha256": "3".repeat(64)
        });
        manifest["distribution_components"] = json!([{
            "unit": "discovery",
            "version": "1.2.3",
            "release_tag": "discovery/v1.2.3",
            "source_sha": "4".repeat(40),
            "manifest": {"name": "discovery-manifest.json", "sha256": "5".repeat(64)},
            "payloads": [],
            "images": []
        }]);
    }
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    fs::write(&manifest_path, &manifest_bytes).unwrap();
    let checksums = directory.join("SHA256SUMS");
    fs::write(
        &checksums,
        format!(
            "{}  {asset_name}\n{}  {manifest_name}\n",
            digest(&binary),
            digest(&manifest_bytes)
        ),
    )
    .unwrap();
    (manifest_path, checksums, launcher)
}

#[test]
fn launcher_only_bootstrap_activates_one_owned_generation() {
    let workspace = scratch();
    let assets = workspace.path().join("assets");
    fs::create_dir(&assets).unwrap();
    let (manifest, checksums, launcher) =
        release_fixture(&assets, "registry-stack.release-candidate.v2");
    let install_root = workspace.path().join("lib");
    let bin_dir = workspace.path().join("bin");
    let result = Command::new(env!("CARGO_BIN_EXE_rstack"))
        .arg("bootstrap")
        .arg("--release-manifest")
        .arg(&manifest)
        .arg("--checksum-file")
        .arg(&checksums)
        .arg("--launcher-asset")
        .arg(&launcher)
        .arg("--asset-dir")
        .arg(&assets)
        .arg("--install-root")
        .arg(&install_root)
        .arg("--bin-dir")
        .arg(&bin_dir)
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    assert!(fs::symlink_metadata(bin_dir.join("rstack"))
        .unwrap()
        .file_type()
        .is_symlink());
    let version = Command::new(bin_dir.join("rstack"))
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(version.stdout).unwrap(),
        "rstack 0.44.0\n"
    );
    assert!(install_root.join("current").exists());
}

#[test]
fn stack_v3_launcher_only_bootstrap_activates() {
    let workspace = scratch();
    let assets = workspace.path().join("assets");
    fs::create_dir(&assets).unwrap();
    let (manifest, checksums, launcher) =
        release_fixture(&assets, "registry-stack.release-candidate.v3");
    let install_root = workspace.path().join("lib");
    let bin_dir = workspace.path().join("bin");

    let result = Command::new(env!("CARGO_BIN_EXE_rstack"))
        .arg("bootstrap")
        .arg("--release-manifest")
        .arg(&manifest)
        .arg("--checksum-file")
        .arg(&checksums)
        .arg("--launcher-asset")
        .arg(&launcher)
        .arg("--asset-dir")
        .arg(&assets)
        .arg("--install-root")
        .arg(&install_root)
        .arg("--bin-dir")
        .arg(&bin_dir)
        .output()
        .unwrap();

    assert!(result.status.success(), "{result:?}");
    assert!(install_root.join("current").exists());
    assert!(bin_dir.join("rstack").exists());
}

#[test]
fn relative_installation_paths_create_a_working_public_launcher() {
    let workspace = scratch();
    let assets = workspace.path().join("assets");
    fs::create_dir(&assets).unwrap();
    let (manifest, checksums, launcher) =
        release_fixture(&assets, "registry-stack.release-candidate.v2");
    let working_directory = workspace.path().join("working");
    fs::create_dir(&working_directory).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_rstack"))
        .current_dir(&working_directory)
        .arg("bootstrap")
        .arg("--release-manifest")
        .arg(&manifest)
        .arg("--checksum-file")
        .arg(&checksums)
        .arg("--launcher-asset")
        .arg(&launcher)
        .arg("--asset-dir")
        .arg(&assets)
        .args(["--install-root", "state", "--bin-dir", "public-bin"])
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");

    let public_launcher = working_directory.join("public-bin/rstack");
    assert!(fs::symlink_metadata(&public_launcher)
        .unwrap()
        .file_type()
        .is_symlink());
    let invocation_directory = workspace.path().join("elsewhere");
    fs::create_dir(&invocation_directory).unwrap();
    let version = Command::new(public_launcher)
        .current_dir(invocation_directory)
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success(), "{version:?}");
    assert_eq!(version.stdout, b"rstack 0.44.0\n");
}

#[test]
fn corrupted_public_manifest_refuses_before_activation() {
    let workspace = scratch();
    let assets = workspace.path().join("assets");
    fs::create_dir(&assets).unwrap();
    let (manifest, checksums, launcher) =
        release_fixture(&assets, "registry-stack.release-candidate.v2");
    let mut bytes = fs::read(&manifest).unwrap();
    bytes.push(b' ');
    fs::write(&manifest, bytes).unwrap();
    let install_root = workspace.path().join("lib");
    let bin_dir = workspace.path().join("bin");
    let result = Command::new(env!("CARGO_BIN_EXE_rstack"))
        .arg("bootstrap")
        .arg("--release-manifest")
        .arg(&manifest)
        .arg("--checksum-file")
        .arg(&checksums)
        .arg("--launcher-asset")
        .arg(&launcher)
        .arg("--asset-dir")
        .arg(&assets)
        .arg("--install-root")
        .arg(&install_root)
        .arg("--bin-dir")
        .arg(&bin_dir)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3), "{result:?}");
    assert!(!install_root.join("current").exists());
    assert!(!bin_dir.join("rstack").exists());
}
