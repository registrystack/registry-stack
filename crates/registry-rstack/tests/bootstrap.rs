use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
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

fn release_fixture(directory: &Path) -> (PathBuf, PathBuf, PathBuf) {
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
        fs::copy(
            env!("CARGO_BIN_EXE_rstack"),
            contents.join("rstack-v0.44.0-macos-arm64"),
        )
        .unwrap();
        fs::write(contents.join("THIRD_PARTY_NOTICES"), "test fixture\n").unwrap();
        fs::write(contents.join("libaws_lc_fips_test.dylib"), "test fixture\n").unwrap();
        let result = Command::new("tar")
            .args(["-czf"])
            .arg(&launcher)
            .arg("-C")
            .arg(&contents)
            .args([
                "rstack-v0.44.0-macos-arm64",
                "THIRD_PARTY_NOTICES",
                "libaws_lc_fips_test.dylib",
            ])
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
    } else {
        fs::copy(env!("CARGO_BIN_EXE_rstack"), &launcher).unwrap();
    }
    let binary = fs::read(&launcher).unwrap();
    let manifest_name = "registry-stack-v0.44.0-release-manifest.json";
    let manifest_path = directory.join(manifest_name);
    let manifest = json!({
        "schema_version": "registry-stack.release-candidate.v2",
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
    let (manifest, checksums, launcher) = release_fixture(&assets);
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
fn relative_installation_paths_create_a_working_public_launcher() {
    let workspace = scratch();
    let assets = workspace.path().join("assets");
    fs::create_dir(&assets).unwrap();
    let (manifest, checksums, launcher) = release_fixture(&assets);
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
    let (manifest, checksums, launcher) = release_fixture(&assets);
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
