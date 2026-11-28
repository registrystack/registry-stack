// SPDX-License-Identifier: Apache-2.0

use registry_rstack::{install, GenerationStore};
use serde_json::json;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output};

const PACKAGE: &str = "application/node_modules/@registrystack/client";
const VALID_PACKAGE: &str =
    r#"{"name":"@registrystack/client","bin":{"registry-generate":"./registry-generate.js"}}"#;

fn generate(node: bool, manifest: Option<&str>, help: bool) -> Output {
    invoke(node, manifest, help, |_| {}, |_| {})
}

fn invoke(
    node: bool,
    manifest: Option<&str>,
    help: bool,
    prepare: impl FnOnce(&Path),
    configure: impl FnOnce(&mut Command),
) -> Output {
    let project = tempfile::tempdir().unwrap();
    let bin = project.path().join("path-bin");
    fs::create_dir(&bin).unwrap();
    if node {
        fs::copy("/bin/sh", bin.join("node")).unwrap();
    }
    let decoy = bin.join("registry-generate");
    fs::write(&decoy, "#!/bin/sh\nexit 9").unwrap();
    fs::set_permissions(&decoy, fs::Permissions::from_mode(0o755)).unwrap();
    if let Some(manifest) = manifest {
        let modules = project.path().join("application/node_modules");
        let real_package = modules.join(".pnpm/client/node_modules/@registrystack/client");
        fs::create_dir_all(&real_package).unwrap();
        fs::create_dir(modules.join("@registrystack")).unwrap();
        symlink(&real_package, project.path().join(PACKAGE)).unwrap();
        fs::create_dir(modules.join(".bin")).unwrap();
        fs::write(modules.join(".bin/registry-generate"), "#!/bin/sh\nexit 8").unwrap();
        fs::write(real_package.join("package.json"), manifest).unwrap();
        fs::write(
            real_package.join("registry-generate.js"),
            r#"printf '%s\n' "$RSTACK_BREGCTL_BIN" "$@"; exit 7"#,
        )
        .unwrap();
        symlink(&decoy, real_package.join("escaped.js")).unwrap();
        fs::write(real_package.join("../outside.js"), "exit 10").unwrap();
    }
    prepare(project.path());
    let bregctl = bin.join("bregctl");
    fs::write(&bregctl, "").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rstack"));
    command
        .current_dir(project.path())
        .env("PATH", &bin)
        .env("RSTACK_BREGCTL_BIN", &bregctl)
        .arg("--install-root")
        .arg(project.path().join("install"))
        .arg("--bin-dir")
        .arg(&bin)
        .args(["client", "generate"]);
    if help {
        command.arg("--help");
    } else {
        command.args([
            "--register",
            "first=register one",
            "--register",
            "second=register-two",
            "--author-profile",
            "first=-writer profile",
            "--route-prefix",
            "first=/first route",
            "--products=-documents,casework with space",
        ]);
    }
    configure(&mut command);
    if !help && !command.get_args().any(|arg| arg == "--output") {
        command.args(["--output", "application/src/generated/service.ts"]);
    }
    command.output().unwrap()
}

#[test]
fn forwards_to_the_local_generator_from_a_nested_output_path() {
    let output = generate(true, Some(VALID_PACKAGE), false);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout
        .lines()
        .next()
        .unwrap()
        .ends_with("/path-bin/bregctl"));
    assert_eq!(
        stdout.lines().skip(1).collect::<Vec<_>>(),
        [
            "--register",
            "first=register one",
            "--register",
            "second=register-two",
            "--author-profile",
            "first=-writer profile",
            "--route-prefix",
            "first=/first route",
            "--products",
            "-documents,casework with space",
            "--output",
            "application/src/generated/service.ts",
        ]
    );
}

#[test]
fn names_each_missing_prerequisite_and_the_install_command() {
    for (node, generator, code) in [
        (false, Some(VALID_PACKAGE), "rstack.client.node-missing"),
        (true, None, "rstack.client.generator-missing"),
    ] {
        let output = generate(node, generator, false);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(code), "{stderr}");
        assert!(
            stderr.contains("npm install @registrystack/client in the application project"),
            "{stderr}"
        );
    }
}

#[test]
fn help_works_without_node_or_the_generator() {
    let output = generate(false, None, true);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    for option in [
        "--register",
        "--author-profile",
        "--route-prefix",
        "--products",
        "--output",
        "RSTACK_BREGCTL_BIN",
    ] {
        assert!(stdout.contains(option), "{stdout}");
    }
}

#[test]
fn refuses_wrong_package_and_escaping_bins() {
    for manifest in [
        VALID_PACKAGE.replace("@registrystack/client", "another-package"),
        VALID_PACKAGE.replace("./registry-generate.js", "../outside.js"),
        VALID_PACKAGE.replace("./registry-generate.js", "./escaped.js"),
    ] {
        let output = generate(true, Some(&manifest), false);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("rstack.client.generator-missing"),
            "{stderr}"
        );
    }
}

#[test]
fn does_not_lookup_from_the_working_directory() {
    let output = invoke(
        true,
        Some(VALID_PACKAGE),
        false,
        |root| {
            fs::create_dir(root.join("elsewhere")).unwrap();
        },
        |command| {
            let root = command.get_current_dir().unwrap().to_owned();
            command.current_dir(root.join("application"));
            command
                .arg("--output")
                .arg(root.join("elsewhere/service.ts"));
        },
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("rstack.client.generator-missing"),
        "{stderr}"
    );
}

fn activate_release(root: &Path, with_breg: bool) {
    let store = GenerationStore::new(root.join("install"), root.join("path-bin"));
    let mutation = store.lock_mutation().unwrap();
    let stage = mutation.stage_generation("v0.49.0-test").unwrap();
    let path = stage.path();
    fs::copy(env!("CARGO_BIN_EXE_rstack"), path.join("rstack")).unwrap();
    fs::create_dir(path.join("components")).unwrap();
    let platform = install::platform().unwrap();
    let suffix = if platform == "macos-arm64" {
        ".tar.gz"
    } else {
        ""
    };
    let asset = json!({
        "name": format!("bregctl-v0.49.0-{platform}{suffix}"),
        "size": 1,
        "sha256": "a".repeat(64)
    });
    let mut components = json!({});
    let mut payloads = Vec::new();
    let mut selected = Vec::new();
    if with_breg {
        let directory = path.join("components/breg/bregctl");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("bregctl"), "fixture").unwrap();
        components["breg"] = json!({
            "entrypoint": "bregctl", "dependencies": [],
            "platforms": { (platform): { "assets": [asset], "capabilities": {} }}
        });
        let mut payload = asset;
        payload["kind"] = json!("binary");
        payloads.push(payload);
        selected.push("breg");
    }
    fs::write(path.join("manifest.json"), json!({
        "schema_version": "registry-stack.release-candidate.v2",
        "repository": "registrystack/registry-stack",
        "release": {"tag":"v0.49.0","version":"0.49.0","source_sha":"a".repeat(40),"release_id":"test"},
        "payloads": payloads,
        "components": {
            "schema_version": "registry-stack.components.v1",
            "release": "v0.49.0", "launcher": {}, "components": components
        }
    }).to_string()).unwrap();
    fs::write(
        path.join("selection.json"),
        json!({
            "schema_version": "registry-stack.install-selection.v1",
            "release": "v0.49.0", "platform": platform, "components": selected
        })
        .to_string(),
    )
    .unwrap();
    let generation = stage.publish_preverified().unwrap();
    mutation.activate(&generation).unwrap();
}

#[test]
fn passes_the_selected_release_bregctl_instead_of_the_override() {
    let output = invoke(
        true,
        Some(VALID_PACKAGE),
        false,
        |root| {
            activate_release(root, true);
        },
        |_| {},
    );
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout
            .lines()
            .next()
            .unwrap()
            .ends_with("/v0.49.0-test/components/breg/bregctl/bregctl"),
        "{stdout}"
    );
}

#[test]
fn names_missing_bregctl_with_and_without_a_selected_release() {
    for selected in [true, false] {
        let output = invoke(
            true,
            Some(VALID_PACKAGE),
            false,
            |root| {
                if selected {
                    activate_release(root, false);
                }
            },
            |command| {
                if !selected {
                    command.env_remove("RSTACK_BREGCTL_BIN");
                }
            },
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("rstack.client.bregctl-missing"), "{stderr}");
        assert!(stderr.contains("rstack install breg"), "{stderr}");
    }
}
