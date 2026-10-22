use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("macos", "aarch64") => "macos-arm64",
        other => panic!("unsupported test platform: {other:?}"),
    }
}

fn fixture(directory: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let platform = platform();
    let archived = platform == "macos-arm64";
    let suffix = if archived { ".tar.gz" } else { "" };
    let launcher_name = format!("rstack-v0.44.0-{platform}{suffix}");
    let evidence_name = format!("evidencectl-v0.44.0-{platform}{suffix}");
    let launcher = directory.join(&launcher_name);
    let evidence = directory.join(&evidence_name);
    let script = b"#!/usr/bin/env bash\nset -euo pipefail\nif [[ \"${1:-}\" == '--version' ]]; then printf 'evidencectl 0.44.0\\n'; exit 0; fi\nif [[ \"${1:-}\" == 'hold' ]]; then printf 'ready\\n'; sleep 5; exit 0; fi\nprintf 'generation:%s\\n' \"${RSTACK_GENERATION_DIR:-}\"\nprintf 'release:%s\\n' \"${RSTACK_RELEASE_TAG:-}\"\nprintf 'selected-evidencectl:%s\\n' \"${RSTACK_EVIDENCECTL_BIN:-}\"\nprintf 'selected-bregctl:%s\\n' \"${RSTACK_BREGCTL_BIN:-}\"\nprintf 'cwd:%s\\n' \"$PWD\"\nprintf 'arg:%s\\n' \"$@\"\nexit 7\n";
    if archived {
        for (asset, binary, executable) in [
            (&launcher, "rstack-v0.44.0-macos-arm64", None),
            (
                &evidence,
                "evidencectl-v0.44.0-macos-arm64",
                Some(script.as_slice()),
            ),
        ] {
            let contents = directory.join(binary);
            fs::create_dir(&contents).unwrap();
            let target = contents.join(binary);
            if let Some(bytes) = executable {
                fs::write(&target, bytes).unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
            } else {
                fs::copy(env!("CARGO_BIN_EXE_rstack"), &target).unwrap();
            }
            fs::write(contents.join("THIRD_PARTY_NOTICES"), "fixture\n").unwrap();
            fs::write(contents.join("libaws_lc_fips_test.dylib"), "fixture\n").unwrap();
            let output = Command::new("tar")
                .arg("-czf")
                .arg(asset)
                .arg("-C")
                .arg(&contents)
                .args([binary, "THIRD_PARTY_NOTICES", "libaws_lc_fips_test.dylib"])
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
        }
    } else {
        fs::copy(env!("CARGO_BIN_EXE_rstack"), &launcher).unwrap();
        fs::write(&evidence, script).unwrap();
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let launcher_bytes = fs::read(&launcher).unwrap();
    let evidence_bytes = fs::read(&evidence).unwrap();
    let manifest_name = "registry-stack-v0.44.0-release-manifest.json";
    let manifest_path = directory.join(manifest_name);
    let manifest = json!({
        "schema_version": "registry-stack.release-candidate.v2",
        "repository": "registrystack/registry-stack",
        "release": {"tag":"v0.44.0","version":"0.44.0","source_sha":"a".repeat(40),"release_id":"test"},
        "payloads": [
            {"name":launcher_name,"kind":"binary","size":launcher_bytes.len(),"sha256":digest(&launcher_bytes)},
            {"name":evidence_name,"kind":"binary","size":evidence_bytes.len(),"sha256":digest(&evidence_bytes)}
        ],
        "components": {
            "schema_version":"registry-stack.components.v1",
            "release":"v0.44.0",
            "launcher":{(platform):{"name":launcher_name,"size":launcher_bytes.len(),"sha256":digest(&launcher_bytes)}},
            "components":{"evidence":{
                "entrypoint":"evidencectl","dependencies":[],
                "platforms":{(platform):{
                    "assets":[{"name":evidence_name,"size":evidence_bytes.len(),"sha256":digest(&evidence_bytes)}],
                    "capabilities":{"tooling":true}
                }}
            }}
        }
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    fs::write(&manifest_path, &manifest_bytes).unwrap();
    let checksums = directory.join("SHA256SUMS");
    fs::write(
        &checksums,
        format!(
            "{}  {launcher_name}\n{}  {evidence_name}\n{}  {manifest_name}\n",
            digest(&launcher_bytes),
            digest(&evidence_bytes),
            digest(&manifest_bytes)
        ),
    )
    .unwrap();
    (manifest_path, checksums, launcher)
}

#[test]
fn old_invocation_keeps_its_generation_while_new_one_activates() {
    let scratch = tempfile::tempdir().unwrap();
    let assets = scratch.path().join("assets");
    fs::create_dir(&assets).unwrap();
    let (manifest, checksums, launcher) = fixture(&assets);
    let root = scratch.path().join("lib");
    let bin = scratch.path().join("bin");
    let bootstrap = || {
        Command::new(env!("CARGO_BIN_EXE_rstack"))
            .args(["bootstrap", "--release-manifest"])
            .arg(&manifest)
            .arg("--checksum-file")
            .arg(&checksums)
            .arg("--launcher-asset")
            .arg(&launcher)
            .arg("--asset-dir")
            .arg(&assets)
            .arg("--install-root")
            .arg(&root)
            .arg("--bin-dir")
            .arg(&bin)
            .arg("evidence")
            .output()
            .unwrap()
    };
    let first = bootstrap();
    assert!(first.status.success(), "{first:?}");
    let old_target = fs::read_link(root.join("current")).unwrap();
    let old_name = old_target.file_name().unwrap().to_str().unwrap().to_owned();
    let mut child = Command::new(bin.join("rstack"))
        .arg("--install-root")
        .arg(&root)
        .arg("--bin-dir")
        .arg(&bin)
        .args(["evidence", "hold"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    let second = bootstrap();
    assert!(second.status.success(), "{second:?}");
    assert_ne!(fs::read_link(root.join("current")).unwrap(), old_target);
    let store = registry_rstack::store::GenerationStore::new(&root, &bin);
    let mutation = store.lock_mutation().unwrap();
    let report = mutation.cleanup().unwrap();
    assert_eq!(
        report.reason_for(&old_name),
        Some(registry_rstack::store::PreserveReason::InUse)
    );
    drop(mutation);
    assert!(child.wait().unwrap().success());
    let report = store.lock_mutation().unwrap().cleanup().unwrap();
    assert!(report.removed.contains(&old_name));
}

#[test]
fn selected_product_preserves_arguments_directory_and_exit_status() {
    let scratch = if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
        tempfile::tempdir_in(target).unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let assets = scratch.path().join("assets");
    fs::create_dir(&assets).unwrap();
    let (manifest, checksums, launcher) = fixture(&assets);
    let root = scratch.path().join("lib");
    let bin = scratch.path().join("bin");
    let installed = Command::new(env!("CARGO_BIN_EXE_rstack"))
        .args(["bootstrap", "--release-manifest"])
        .arg(manifest)
        .arg("--checksum-file")
        .arg(checksums)
        .arg("--launcher-asset")
        .arg(launcher)
        .arg("--asset-dir")
        .arg(&assets)
        .arg("--install-root")
        .arg(&root)
        .arg("--bin-dir")
        .arg(&bin)
        .arg("evidence")
        .output()
        .unwrap();
    assert!(installed.status.success(), "{installed:?}");
    let listed = Command::new(bin.join("rstack"))
        .arg("--install-root")
        .arg(&root)
        .arg("--bin-dir")
        .arg(&bin)
        .args(["components", "list", "--format", "json"])
        .output()
        .unwrap();
    assert!(listed.status.success(), "{listed:?}");
    let listing: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listing["schema_version"], "registry.rstack.components.v1");
    assert_eq!(listing["release"], "v0.44.0");
    let components = listing["components"].as_array().unwrap();
    assert_eq!(components.len(), 9);
    let evidence = components
        .iter()
        .find(|component| component["name"] == "evidence")
        .unwrap();
    assert_eq!(evidence["installed"], true);
    assert_eq!(evidence["available"], true);
    assert_eq!(evidence["version"], "0.44.0");
    assert!(evidence["path"]
        .as_str()
        .unwrap()
        .ends_with("/components/evidence/evidencectl/evidencectl"));
    let coordinator = components
        .iter()
        .find(|component| component["name"] == "coordinator")
        .unwrap();
    assert_eq!(coordinator["installed"], false);
    assert_eq!(coordinator["available"], false);
    assert!(coordinator["version"].is_null());
    assert!(coordinator["path"].is_null());

    let human = Command::new(bin.join("rstack"))
        .arg("--install-root")
        .arg(&root)
        .arg("--bin-dir")
        .arg(&bin)
        .args(["components", "list"])
        .output()
        .unwrap();
    assert!(human.status.success(), "{human:?}");
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("evidence: installed, version 0.44.0, path "));
    assert!(human.contains("coordinator: unavailable, version unavailable, path none"));
    let output = Command::new(bin.join("rstack"))
        .args([
            "--install-root",
            root.to_str().unwrap(),
            "--bin-dir",
            bin.to_str().unwrap(),
            "evidence",
            "check",
            "a b",
            "--format",
            "json",
        ])
        .current_dir(scratch.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let current = root.join("current").canonicalize().unwrap();
    assert!(stdout.contains(&format!("generation:{}\n", current.display())));
    assert!(stdout.contains("release:v0.44.0\n"));
    assert!(stdout.contains(&format!(
        "selected-evidencectl:{}\n",
        current
            .join("components/evidence/evidencectl/evidencectl")
            .display()
    )));
    assert!(stdout.contains("selected-bregctl:\n"));
    assert!(
        stdout.contains(&format!(
            "cwd:{}\n",
            scratch.path().canonicalize().unwrap().display()
        )),
        "{stdout}"
    );
    assert!(
        stdout.ends_with("arg:check\narg:a b\narg:--format\narg:json\n"),
        "{stdout}"
    );

    let delimited = Command::new(bin.join("rstack"))
        .args([
            "--install-root",
            root.to_str().unwrap(),
            "--bin-dir",
            bin.to_str().unwrap(),
            "--format",
            "json",
            "evidence",
            "check",
            "--",
            "literal",
        ])
        .output()
        .unwrap();
    assert_eq!(delimited.status.code(), Some(7), "{delimited:?}");
    let stdout = String::from_utf8(delimited.stdout).unwrap();
    assert!(
        stdout.ends_with("arg:check\narg:--format\narg:json\narg:--\narg:literal\n"),
        "{stdout}"
    );
}
