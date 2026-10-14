// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Workspace(PathBuf);

impl Workspace {
    fn create() -> Self {
        // Use the ordinary temporary directory, including the system aliases
        // macOS uses for /tmp and /var, just as an adopter would.
        let root = std::env::temp_dir().join(format!(
            "bregctl-authoring-paths-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.0.join(relative)
    }

    fn initialize(&self) -> PathBuf {
        let project = self.path("project");
        let output = ctl(&["init", path(&project)]);
        assert!(output.status.success(), "{output:?}");
        project
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn ctl(arguments: &[&str]) -> Output {
    ctl_from(Path::new("."), arguments)
}

fn ctl_from(directory: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .current_dir(directory)
        .args(["--format", "json"])
        .args(arguments)
        .output()
        .unwrap()
}

fn refused(output: &Output, code: &str) {
    assert!(!output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == code),
        "{report}"
    );
}

#[test]
fn authoring_accepts_explicit_project_and_output_parent_aliases() {
    let workspace = Workspace::create();
    let real = workspace.path("real");
    fs::create_dir(&real).unwrap();
    let alias = workspace.path("workspace-alias");
    symlink(&real, &alias).unwrap();
    let project = alias.join("project");

    let initialized = ctl(&["init", path(&project)]);
    assert!(initialized.status.success(), "{initialized:?}");
    assert!(real.join("project/registry.yaml").is_file());
    let project_alias = workspace.path("project-alias");
    symlink(real.join("project"), &project_alias).unwrap();
    for root in [&project, &project_alias] {
        let checked = ctl(&["check", path(root)]);
        assert!(checked.status.success(), "{checked:?}");
    }
    // Adding a source forces lock to rewrite registry.yaml through the chosen
    // root, rather than proving only the already-current no-write branch.
    fs::create_dir_all(real.join("project/modules/extension")).unwrap();
    fs::write(
        real.join("project/modules/extension/module.yaml"),
        b"apiVersion: id.registrystack.org/formats/breg/module/v1alpha1\nkind: BRegModule\nid: extension\nversion: '1'\n",
    )
    .unwrap();
    let locked = ctl(&["project", "lock", path(&project_alias)]);
    assert!(locked.status.success(), "{locked:?}");
    let report: serde_json::Value = serde_json::from_slice(&locked.stdout).unwrap();
    assert_eq!(report["explanation"]["changed"], true);

    let output = alias.join("generated");
    let generated = ctl(&[
        "generate",
        "openapi",
        path(&project_alias),
        "--output",
        path(&output),
    ]);
    assert!(generated.status.success(), "{generated:?}");
    assert!(real.join("generated/generated/openapi.json").is_file());
    let original = fs::read(real.join("generated/generated/openapi.json")).unwrap();
    let working = workspace.path("working");
    fs::create_dir(&working).unwrap();
    let checked = ctl_from(&working, &["check", "../real/project"]);
    assert!(checked.status.success(), "{checked:?}");
    let relative_generated = ctl_from(
        &working,
        &[
            "generate",
            "openapi",
            "../project-alias",
            "--output",
            "../workspace-alias/relative-generated",
        ],
    );
    assert!(
        relative_generated.status.success(),
        "{relative_generated:?}"
    );
    assert_eq!(
        fs::read(real.join("relative-generated/generated/openapi.json")).unwrap(),
        original
    );
    let repeated = ctl(&[
        "generate",
        "openapi",
        path(&project),
        "--output",
        path(&output),
    ]);
    refused(&repeated, "output.destination.invalid");
    assert_eq!(
        fs::read(real.join("generated/generated/openapi.json")).unwrap(),
        original
    );
    assert!(fs::read_dir(&real).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".bregctl-stage-")));
}

#[test]
fn selected_root_alias_does_not_allow_governed_source_symlinks() {
    let workspace = Workspace::create();
    let project = workspace.initialize();
    let alias = workspace.path("project-alias");
    symlink(&project, &alias).unwrap();
    let source = project.join("registry.yaml");
    let saved = workspace.path("saved-registry.yaml");
    fs::rename(&source, &saved).unwrap();
    symlink(&saved, &source).unwrap();

    let checked = ctl(&["check", path(&alias)]);
    refused(&checked, "breg.source.file-invalid");
    let output = workspace.path("generated");
    let generated = ctl(&[
        "generate",
        "openapi",
        path(&alias),
        "--output",
        path(&output),
    ]);
    refused(&generated, "breg.source.file-invalid");
    assert!(!output.exists());

    fs::remove_file(&source).unwrap();
    fs::rename(&saved, &source).unwrap();
    let outside = workspace.path("outside-modules");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, project.join("modules")).unwrap();
    let checked = ctl(&["check", path(&alias)]);
    refused(&checked, "breg.source.modules-invalid");
}

#[test]
fn output_parent_alias_does_not_allow_an_existing_symlink_leaf() {
    let workspace = Workspace::create();
    let project = workspace.initialize();
    let real = workspace.path("real-output-parent");
    fs::create_dir(&real).unwrap();
    let alias = workspace.path("output-parent-alias");
    symlink(&real, &alias).unwrap();
    let target = workspace.path("kept");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("canary"), b"preserved").unwrap();
    symlink(&target, real.join("generated")).unwrap();
    let output = alias.join("generated");

    let generated = ctl(&[
        "generate",
        "openapi",
        path(&project),
        "--output",
        path(&output),
    ]);
    refused(&generated, "output.destination.invalid");
    assert!(fs::symlink_metadata(&output)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(target.join("canary")).unwrap(), b"preserved");
    assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
    assert_eq!(fs::read_dir(&real).unwrap().count(), 1);
    for destination in ["real-output-parent/.", "real-output-parent/.."] {
        let initialized = ctl_from(&workspace.0, &["init", destination]);
        refused(&initialized, "output.destination.invalid");
    }
}
