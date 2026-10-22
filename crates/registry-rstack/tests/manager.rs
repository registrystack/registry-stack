// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use registry_rstack::install::{
    bootstrap, install, read_selection, uninstall, uninstall_all, update, BootstrapOptions,
    ManagerErrorClass, ManagerOptions,
};
use registry_rstack::GenerationStore;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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

fn target_platform() -> &'static str {
    registry_rstack::install::platform().unwrap()
}

fn other_platform() -> &'static str {
    match target_platform() {
        "linux-amd64" => "linux-arm64",
        _ => "linux-amd64",
    }
}

fn asset_name(binary: &str, platform: &str) -> String {
    asset_name_for(binary, "v0.44.0", platform)
}

fn asset_name_for(binary: &str, release: &str, platform: &str) -> String {
    format!(
        "{binary}-{release}-{platform}{}",
        if platform == "macos-arm64" {
            ".tar.gz"
        } else {
            ""
        }
    )
}

fn write_versioned_executable(path: &Path, binary: &str, version: &str) {
    fs::write(
        path,
        format!("#!/usr/bin/env sh\nprintf '%s\\n' '{binary} {version}'\n"),
    )
    .unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn component_asset(directory: &Path, binary: &str, platform: &str) -> (String, Vec<u8>) {
    component_asset_for(directory, binary, "v0.44.0", platform)
}

fn component_asset_for(
    directory: &Path,
    binary: &str,
    release: &str,
    platform: &str,
) -> (String, Vec<u8>) {
    let name = asset_name_for(binary, release, platform);
    let path = directory.join(&name);
    if platform == "macos-arm64" {
        let contents = directory.join(format!("archive-{binary}-{release}"));
        fs::create_dir(&contents).unwrap();
        let archived_binary = name.strip_suffix(".tar.gz").unwrap();
        write_versioned_executable(
            &contents.join(archived_binary),
            binary,
            release.strip_prefix('v').unwrap(),
        );
        fs::write(contents.join("THIRD_PARTY_NOTICES"), "test fixture\n").unwrap();
        fs::write(
            contents.join(format!("libaws_lc_fips_{binary}.dylib")),
            "test fixture\n",
        )
        .unwrap();
        let result = Command::new("tar")
            .args(["-czf"])
            .arg(&path)
            .arg("-C")
            .arg(&contents)
            .args([
                archived_binary,
                "THIRD_PARTY_NOTICES",
                &format!("libaws_lc_fips_{binary}.dylib"),
            ])
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
    } else {
        write_versioned_executable(&path, binary, release.strip_prefix('v').unwrap());
    }
    (name, fs::read(path).unwrap())
}

struct Fixture {
    _workspace: tempfile::TempDir,
    assets: PathBuf,
    install_root: PathBuf,
    bin_dir: PathBuf,
    manifest: PathBuf,
    checksums: PathBuf,
    launcher: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let workspace = scratch();
        let assets = workspace.path().join("assets");
        fs::create_dir(&assets).unwrap();
        let platform = target_platform();
        let launcher_name = asset_name("rstack", platform);
        let launcher = assets.join(&launcher_name);
        if platform == "macos-arm64" {
            let contents = assets.join("archive-rstack");
            fs::create_dir(&contents).unwrap();
            fs::copy(
                env!("CARGO_BIN_EXE_rstack"),
                contents.join(launcher_name.strip_suffix(".tar.gz").unwrap()),
            )
            .unwrap();
            fs::write(contents.join("THIRD_PARTY_NOTICES"), "test fixture\n").unwrap();
            fs::write(
                contents.join("libaws_lc_fips_rstack.dylib"),
                "test fixture\n",
            )
            .unwrap();
            let result = Command::new("tar")
                .args(["-czf"])
                .arg(&launcher)
                .arg("-C")
                .arg(&contents)
                .args([
                    launcher_name.strip_suffix(".tar.gz").unwrap(),
                    "THIRD_PARTY_NOTICES",
                    "libaws_lc_fips_rstack.dylib",
                ])
                .output()
                .unwrap();
            assert!(result.status.success(), "{result:?}");
        } else {
            fs::copy(env!("CARGO_BIN_EXE_rstack"), &launcher).unwrap();
        }

        let mut payloads = Vec::new();
        let launcher_bytes = fs::read(&launcher).unwrap();
        payloads.push(json!({
            "name": launcher_name,
            "kind": "binary",
            "size": launcher_bytes.len(),
            "sha256": digest(&launcher_bytes),
        }));

        let mut component_documents = BTreeMap::new();
        for (component, binary, dependencies, component_platform) in [
            ("breg", "bregctl", Vec::<&str>::new(), platform),
            ("casework", "caseworkctl", vec!["breg"], platform),
            ("evidence", "evidencectl", Vec::<&str>::new(), platform),
            (
                "scheduling",
                "schedulingctl",
                Vec::<&str>::new(),
                other_platform(),
            ),
        ] {
            let (name, bytes) = component_asset(&assets, binary, component_platform);
            payloads.push(json!({
                "name": name,
                "kind": "binary",
                "size": bytes.len(),
                "sha256": digest(&bytes),
            }));
            component_documents.insert(
                component,
                json!({
                    "entrypoint": binary,
                    "dependencies": dependencies,
                    "platforms": {(component_platform): {
                        "assets": [{
                            "name": name,
                            "size": bytes.len(),
                            "sha256": digest(&bytes),
                        }],
                        "capabilities": {"tooling": true, "runtime": false},
                    }},
                }),
            );
        }

        let manifest_name = "registry-stack-v0.44.0-release-manifest.json";
        let manifest = assets.join(manifest_name);
        let document = json!({
            "schema_version": "registry-stack.release-candidate.v2",
            "repository": "registrystack/registry-stack",
            "release": {
                "tag": "v0.44.0",
                "version": "0.44.0",
                "source_sha": "a".repeat(40),
                "release_id": "test",
            },
            "payloads": payloads,
            "components": {
                "schema_version": "registry-stack.components.v1",
                "release": "v0.44.0",
                "launcher": {(platform): {
                    "name": launcher_name,
                    "size": launcher_bytes.len(),
                    "sha256": digest(&launcher_bytes),
                }},
                "components": component_documents,
            },
        });
        let manifest_bytes = serde_json::to_vec(&document).unwrap();
        fs::write(&manifest, &manifest_bytes).unwrap();
        let checksums = assets.join("SHA256SUMS");
        let mut checksum_lines = Vec::new();
        for payload in document["payloads"].as_array().unwrap() {
            checksum_lines.push(format!(
                "{}  {}",
                payload["sha256"].as_str().unwrap(),
                payload["name"].as_str().unwrap()
            ));
        }
        checksum_lines.push(format!("{}  {manifest_name}", digest(&manifest_bytes)));
        fs::write(&checksums, format!("{}\n", checksum_lines.join("\n"))).unwrap();
        let install_root = workspace.path().join("lib/registrystack");
        let bin_dir = workspace.path().join("bin");
        Self {
            _workspace: workspace,
            assets,
            install_root,
            bin_dir,
            manifest,
            checksums,
            launcher,
        }
    }

    fn bootstrap(&self, components: &[&str]) {
        bootstrap(BootstrapOptions {
            release_manifest: self.manifest.clone(),
            checksum_file: self.checksums.clone(),
            launcher_asset: self.launcher.clone(),
            asset_dir: Some(self.assets.clone()),
            install_root: self.install_root.clone(),
            bin_dir: self.bin_dir.clone(),
            components: components.iter().map(|name| (*name).to_owned()).collect(),
            all: false,
        })
        .unwrap();
    }

    fn manager_options(&self) -> ManagerOptions {
        ManagerOptions {
            install_root: self.install_root.clone(),
            bin_dir: self.bin_dir.clone(),
            asset_dir: Some(self.assets.clone()),
        }
    }

    fn store(&self) -> GenerationStore {
        GenerationStore::new(&self.install_root, &self.bin_dir)
    }

    fn write_release(
        &self,
        release: &str,
        evidence_depends_on_breg: bool,
        evidence_available: bool,
    ) {
        let platform = target_platform();
        let launcher_name = asset_name_for("rstack", release, platform);
        let (_, launcher_bytes) = component_asset_for(&self.assets, "rstack", release, platform);
        let mut payloads = vec![json!({
            "name": launcher_name,
            "kind": "binary",
            "size": launcher_bytes.len(),
            "sha256": digest(&launcher_bytes),
        })];
        let mut components = BTreeMap::new();
        for (component, binary, dependencies, available) in [
            ("breg", "bregctl", Vec::<&str>::new(), true),
            ("casework", "caseworkctl", vec!["breg"], true),
            (
                "evidence",
                "evidencectl",
                if evidence_depends_on_breg {
                    vec!["breg"]
                } else {
                    Vec::new()
                },
                evidence_available,
            ),
        ] {
            let component_platform = if available {
                platform
            } else {
                other_platform()
            };
            let (name, bytes) =
                component_asset_for(&self.assets, binary, release, component_platform);
            payloads.push(json!({
                "name": name,
                "kind": "binary",
                "size": bytes.len(),
                "sha256": digest(&bytes),
            }));
            components.insert(
                component,
                json!({
                    "entrypoint": binary,
                    "dependencies": dependencies,
                    "platforms": {(component_platform): {
                        "assets": [{
                            "name": name,
                            "size": bytes.len(),
                            "sha256": digest(&bytes),
                        }],
                        "capabilities": {"tooling": true, "runtime": false},
                    }},
                }),
            );
        }
        let manifest_name = format!("registry-stack-{release}-release-manifest.json");
        let manifest = json!({
            "schema_version": "registry-stack.release-candidate.v2",
            "repository": "registrystack/registry-stack",
            "release": {
                "tag": release,
                "version": release.strip_prefix('v').unwrap(),
                "source_sha": "b".repeat(40),
                "release_id": format!("test-{release}"),
            },
            "payloads": payloads,
            "components": {
                "schema_version": "registry-stack.components.v1",
                "release": release,
                "launcher": {(platform): {
                    "name": launcher_name,
                    "size": launcher_bytes.len(),
                    "sha256": digest(&launcher_bytes),
                }},
                "components": components,
            },
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(self.assets.join(&manifest_name), &manifest_bytes).unwrap();
        let mut checksum_lines = Vec::new();
        for payload in manifest["payloads"].as_array().unwrap() {
            checksum_lines.push(format!(
                "{}  {}",
                payload["sha256"].as_str().unwrap(),
                payload["name"].as_str().unwrap()
            ));
        }
        checksum_lines.push(format!("{}  {manifest_name}", digest(&manifest_bytes)));
        fs::write(
            self.assets.join("SHA256SUMS"),
            format!("{}\n", checksum_lines.join("\n")),
        )
        .unwrap();
    }
}

#[test]
fn update_without_an_active_installation_is_a_domain_refusal() {
    let fixture = Fixture::new();

    for preview in [true, false] {
        let error = update(&fixture.manager_options(), "v0.45.0", preview).unwrap_err();
        assert_eq!(error.class, ManagerErrorClass::Domain);
        assert!(error.message.contains("no installation is selected"));
    }
}

#[test]
fn install_adds_dependency_closure_and_retains_installed_components() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["evidence"]);
    let before = fixture.store().acquire_current().unwrap();
    let before_name = before.generation().name().to_owned();
    drop(before);
    fs::remove_file(
        fixture
            .assets
            .join(asset_name("evidencectl", target_platform())),
    )
    .unwrap();

    let report = install(fixture.manager_options(), vec!["casework".into()], false).unwrap();

    assert_ne!(report.generation, before_name);
    assert_eq!(report.release, "v0.44.0");
    assert_eq!(report.components, vec!["breg", "casework", "evidence"]);
    let current = fixture.store().acquire_current().unwrap();
    assert_eq!(
        read_selection(current.path()).unwrap().components,
        report.components
    );
    assert!(current
        .path()
        .join("components/breg/bregctl/bregctl")
        .exists());
    assert!(current
        .path()
        .join("components/casework/caseworkctl/caseworkctl")
        .exists());
    assert!(current
        .path()
        .join("components/evidence/evidencectl/evidencectl")
        .exists());
}

#[test]
fn unavailable_mixed_install_refuses_before_staging_or_activation() {
    let fixture = Fixture::new();
    fixture.bootstrap(&[]);
    let before = fixture.store().acquire_current().unwrap();
    let before_name = before.generation().name().to_owned();
    drop(before);

    let error = install(
        fixture.manager_options(),
        vec!["breg".into(), "scheduling".into()],
        false,
    )
    .unwrap_err();

    assert_eq!(error.class, ManagerErrorClass::Domain);
    assert!(
        error.message.contains("unavailable"),
        "unexpected error: {error}"
    );
    let current = fixture.store().acquire_current().unwrap();
    assert_eq!(current.generation().name(), before_name);
    assert_eq!(
        fs::read_dir(fixture.store().generations_dir())
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn failed_asset_fetch_preserves_the_active_generation() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["evidence"]);
    let before = fixture.store().acquire_current().unwrap();
    let before_name = before.generation().name().to_owned();
    drop(before);
    fs::write(
        fixture
            .assets
            .join(asset_name("caseworkctl", target_platform())),
        "corrupt",
    )
    .unwrap();

    let error = install(fixture.manager_options(), vec!["casework".into()], false).unwrap_err();

    assert_eq!(error.class, ManagerErrorClass::Operational);
    assert!(
        error.message.contains("does not match"),
        "unexpected error: {error}"
    );
    let current = fixture.store().acquire_current().unwrap();
    assert_eq!(current.generation().name(), before_name);
    assert_eq!(
        read_selection(current.path()).unwrap().components,
        vec!["evidence"]
    );
}

#[test]
fn uninstall_refuses_a_dependency_of_a_retained_component() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["casework", "evidence"]);
    let before = fixture.store().acquire_current().unwrap();
    let before_name = before.generation().name().to_owned();
    drop(before);

    let error = uninstall(fixture.manager_options(), vec!["breg".into()]).unwrap_err();

    assert_eq!(error.class, ManagerErrorClass::Domain);
    assert!(
        error.message.contains("required by casework"),
        "unexpected error: {error}"
    );
    assert_eq!(
        fixture
            .store()
            .acquire_current()
            .unwrap()
            .generation()
            .name(),
        before_name
    );
}

#[test]
fn uninstall_activates_a_complete_generation_without_the_component() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["casework", "evidence"]);
    let before = fixture.store().acquire_current().unwrap();
    let before_name = before.generation().name().to_owned();
    drop(before);

    let report = uninstall(fixture.manager_options(), vec!["evidence".into()]).unwrap();

    assert_ne!(report.generation, before_name);
    assert_eq!(report.removed, vec!["evidence"]);
    assert_eq!(report.components, vec!["breg", "casework"]);
    let current = fixture.store().acquire_current().unwrap();
    assert_eq!(
        read_selection(current.path()).unwrap().components,
        report.components
    );
    assert!(current.path().join("components/breg").exists());
    assert!(current.path().join("components/casework").exists());
    assert!(!current.path().join("components/evidence").exists());
}

#[test]
fn full_uninstall_refuses_while_an_invocation_holds_a_generation_lease() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["evidence"]);
    let invocation = fixture.store().acquire_current().unwrap();

    let error = uninstall_all(fixture.manager_options()).unwrap_err();

    assert_eq!(error.class, ManagerErrorClass::Domain);
    assert!(
        error.message.contains("in use"),
        "unexpected error: {error}"
    );
    assert!(fixture.bin_dir.join("rstack").exists());
    assert!(fixture.install_root.join("current").exists());
    assert!(invocation.path().exists());
}

#[test]
fn full_uninstall_removes_only_owned_installation_entries() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["evidence"]);
    fs::write(fixture.bin_dir.join("keep"), "unrelated").unwrap();
    let project = fixture._workspace.path().join("project");
    fs::create_dir(&project).unwrap();
    fs::write(project.join("credentials.json"), "keep").unwrap();

    let report = uninstall_all(fixture.manager_options()).unwrap();

    assert_eq!(report.removed_generations.len(), 1);
    assert!(!fixture.bin_dir.join("rstack").exists());
    assert!(!fixture.install_root.join("current").exists());
    assert!(!fixture.install_root.join("generations").exists());
    assert_eq!(
        fs::read(fixture.bin_dir.join("keep")).unwrap(),
        b"unrelated"
    );
    assert_eq!(fs::read(project.join("credentials.json")).unwrap(), b"keep");
}

#[test]
fn full_uninstall_refuses_changed_or_unrelated_managed_paths_before_removal() {
    let modified = Fixture::new();
    modified.bootstrap(&["evidence"]);
    let current = modified.store().acquire_current().unwrap();
    let changed = current
        .path()
        .join("components/evidence/evidencectl/evidencectl");
    drop(current);
    fs::write(&changed, "changed").unwrap();

    let error = uninstall_all(modified.manager_options()).unwrap_err();

    assert_eq!(error.class, ManagerErrorClass::Operational);
    assert!(
        error.message.contains("changed"),
        "unexpected error: {error}"
    );
    assert!(modified.bin_dir.join("rstack").exists());
    assert!(modified.install_root.join("current").exists());
    assert_eq!(fs::read(changed).unwrap(), b"changed");

    let unrelated = Fixture::new();
    unrelated.bootstrap(&[]);
    fs::write(unrelated.install_root.join("keep"), "unrelated").unwrap();

    let error = uninstall_all(unrelated.manager_options()).unwrap_err();

    assert_eq!(error.class, ManagerErrorClass::Operational);
    assert!(
        error.message.contains("unrelated"),
        "unexpected error: {error}"
    );
    assert_eq!(
        fs::read(unrelated.install_root.join("keep")).unwrap(),
        b"unrelated"
    );
    assert!(unrelated.bin_dir.join("rstack").exists());
    assert!(unrelated.install_root.join("current").exists());
}

#[test]
fn full_uninstall_recovers_an_interrupted_owned_removal() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["evidence"]);
    let current = fixture.store().acquire_current().unwrap();
    let generation_name = current.generation().name().to_owned();
    let generation_path = current.path().to_owned();
    drop(current);
    let removal_root = fixture.install_root.join(".removing");
    fs::create_dir(&removal_root).unwrap();
    fs::remove_file(fixture.bin_dir.join("rstack")).unwrap();
    fs::remove_file(fixture.install_root.join("current")).unwrap();
    let recovery_path = removal_root.join(&generation_name);
    fs::rename(generation_path, &recovery_path).unwrap();
    fs::remove_file(recovery_path.join("components/evidence/evidencectl/evidencectl")).unwrap();

    let report = uninstall_all(fixture.manager_options()).unwrap();

    assert_eq!(report.removed_generations, vec![generation_name]);
    assert!(!fixture.install_root.join("generations").exists());
    assert!(!fixture.install_root.join(".removing").exists());
}

#[test]
fn update_preview_reports_dependency_changes_without_mutation() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["evidence"]);
    let before = fixture.store().acquire_current().unwrap();
    let before_name = before.generation().name().to_owned();
    drop(before);
    fixture.write_release("v0.45.0", true, true);

    let report = update(&fixture.manager_options(), "v0.45.0", true).unwrap();

    assert_eq!(report.current_release, "v0.44.0");
    assert_eq!(report.target_release, "v0.45.0");
    assert_eq!(report.components, vec!["breg", "evidence"]);
    assert_eq!(report.added_components, vec!["breg"]);
    assert!(report.download_bytes > 0);
    assert!(report.preview);
    assert!(!report.activated);
    assert_eq!(report.generation, None);
    assert_eq!(
        fixture
            .store()
            .acquire_current()
            .unwrap()
            .generation()
            .name(),
        before_name
    );
    assert_eq!(
        fs::read_dir(fixture.store().generations_dir())
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn update_preview_of_the_selected_release_reports_no_download() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["evidence"]);
    let before = fixture.store().acquire_current().unwrap();
    let before_name = before.generation().name().to_owned();
    drop(before);

    let report = update(&fixture.manager_options(), "v0.44.0", true).unwrap();

    assert_eq!(report.current_release, "v0.44.0");
    assert_eq!(report.target_release, "v0.44.0");
    assert_eq!(report.components, vec!["evidence"]);
    assert!(report.added_components.is_empty());
    assert_eq!(report.download_bytes, 0);
    assert!(report.preview);
    assert!(!report.activated);
    assert_eq!(report.generation, None);
    assert_eq!(
        fixture
            .store()
            .acquire_current()
            .unwrap()
            .generation()
            .name(),
        before_name
    );
}

#[test]
fn update_activates_complete_target_release_with_installed_set_and_new_dependencies() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["evidence"]);
    fixture.write_release("v0.45.0", true, true);

    let report = update(&fixture.manager_options(), "v0.45.0", false).unwrap();

    assert_eq!(report.current_release, "v0.44.0");
    assert_eq!(report.target_release, "v0.45.0");
    assert_eq!(report.components, vec!["breg", "evidence"]);
    assert_eq!(report.added_components, vec!["breg"]);
    assert!(report.activated);
    assert!(!report.preview);
    let current = fixture.store().acquire_current().unwrap();
    assert_eq!(current.generation().name(), report.generation.unwrap());
    let selection = read_selection(current.path()).unwrap();
    assert_eq!(selection.release, "v0.45.0");
    assert_eq!(selection.components, vec!["breg", "evidence"]);
    assert!(current
        .path()
        .join("components/breg/bregctl/bregctl")
        .exists());
    assert!(current
        .path()
        .join("components/evidence/evidencectl/evidencectl")
        .exists());
    let version = Command::new(current.path().join("rstack"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert_eq!(version.stdout, b"rstack 0.45.0\n");
}

#[test]
fn update_refuses_downgrade_and_unavailable_installed_component() {
    let downgrade = Fixture::new();
    downgrade.bootstrap(&["evidence"]);
    let before = downgrade.store().acquire_current().unwrap();
    let before_name = before.generation().name().to_owned();
    drop(before);

    let error = update(&downgrade.manager_options(), "v0.43.0", false).unwrap_err();

    assert_eq!(error.class, ManagerErrorClass::Domain);
    assert!(
        error.message.contains("downgrade"),
        "unexpected error: {error}"
    );
    assert_eq!(
        downgrade
            .store()
            .acquire_current()
            .unwrap()
            .generation()
            .name(),
        before_name
    );

    let unavailable = Fixture::new();
    unavailable.bootstrap(&["evidence"]);
    unavailable.write_release("v0.45.0", false, false);

    let error = update(&unavailable.manager_options(), "v0.45.0", false).unwrap_err();

    assert_eq!(error.class, ManagerErrorClass::Domain);
    assert!(
        error.message.contains("unavailable"),
        "unexpected error: {error}"
    );
    assert_eq!(
        read_selection(unavailable.store().acquire_current().unwrap().path())
            .unwrap()
            .release,
        "v0.44.0"
    );
}

#[test]
fn bootstrap_refuses_to_replace_a_newer_selected_release() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["evidence"]);
    let original_checksums = fs::read(&fixture.checksums).unwrap();
    fixture.write_release("v0.45.0", false, true);
    update(&fixture.manager_options(), "v0.45.0", false).unwrap();
    let before = fixture.store().acquire_current().unwrap();
    let before_name = before.generation().name().to_owned();
    drop(before);
    let generation_count = fs::read_dir(fixture.store().generations_dir())
        .unwrap()
        .count();
    fs::write(&fixture.checksums, original_checksums).unwrap();

    let error = bootstrap(BootstrapOptions {
        release_manifest: fixture.manifest.clone(),
        checksum_file: fixture.checksums.clone(),
        launcher_asset: fixture.launcher.clone(),
        asset_dir: Some(fixture.assets.clone()),
        install_root: fixture.install_root.clone(),
        bin_dir: fixture.bin_dir.clone(),
        components: vec!["evidence".to_owned()],
        all: false,
    })
    .unwrap_err();

    assert!(error.contains("downgrade"), "unexpected error: {error}");
    let current = fixture.store().acquire_current().unwrap();
    assert_eq!(current.generation().name(), before_name);
    assert_eq!(read_selection(current.path()).unwrap().release, "v0.45.0");
    assert_eq!(
        fs::read_dir(fixture.store().generations_dir())
            .unwrap()
            .count(),
        generation_count
    );
}

#[test]
fn corrupt_target_payload_preserves_current_release() {
    let fixture = Fixture::new();
    fixture.bootstrap(&["evidence"]);
    let before = fixture.store().acquire_current().unwrap();
    let before_name = before.generation().name().to_owned();
    drop(before);
    fixture.write_release("v0.45.0", false, true);
    fs::write(
        fixture
            .assets
            .join(asset_name_for("evidencectl", "v0.45.0", target_platform())),
        "corrupt",
    )
    .unwrap();

    let error = update(&fixture.manager_options(), "v0.45.0", false).unwrap_err();

    assert_eq!(error.class, ManagerErrorClass::Operational);
    assert!(
        error.message.contains("does not match"),
        "unexpected error: {error}"
    );
    assert_eq!(
        fixture
            .store()
            .acquire_current()
            .unwrap()
            .generation()
            .name(),
        before_name
    );
}
