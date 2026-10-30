// SPDX-License-Identifier: Apache-2.0
//! Public CLI composition against BReg's compiler-owned native package fixture.

use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Output,
};

#[path = "../../../registry-caseworkctl/tests/support/cli.rs"]
mod cli;
use cli::caseworkctl;

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn read_yaml(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap();
    registry_platform_yaml::Reader::new(path.display().to_string())
        .scan(&bytes)
        .unwrap()
        .unwrap()
        .to_json_value()
}

fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(directory)
            .expect("generated project directory is readable")
            .collect::<Result<Vec<_>, _>>()
            .expect("generated project entries are readable");
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if entry.file_type().expect("generated file type").is_dir() {
                visit(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(path).expect("generated file is readable"),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("copy destination exists");
    for entry in fs::read_dir(source).expect("copy source is readable") {
        let entry = entry.expect("copy source entry is readable");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("copy source type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy source file succeeds");
        }
    }
}

#[test]
fn sealed_authority_and_runtime_bindings_agree_with_the_inspected_project() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    assert!(
        std::env::var_os("CASEWORKCTL_BIN").is_some(),
        "CASEWORKCTL_BIN must name the matching candidate"
    );
    let bregctl = PathBuf::from(bregctl);
    let facility =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/examples/facility");
    // A temporary child of the test's working directory lets the public CLI
    // receive equivalent relative and absolute paths without changing cwd.
    let working_directory = std::env::current_dir().unwrap().canonicalize().unwrap();
    let temporary = tempfile::tempdir_in(&working_directory).unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let source = root.join("facility");
    copy_tree(&facility, &source);
    let registry_path = source.join("registry.yaml");
    let mut registry = read_yaml(&registry_path);
    let reviewer = registry["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "proposal-reviewer")
        .unwrap();
    reviewer["actorKind"] = json!("human");
    reviewer["requesterClients"] = json!(["review-ui"]);
    fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();
    // Build an integrity-valid native fixture through BReg's owning package
    // API. The public CLI below rederives its source and authority; this test
    // does not claim a schema-test receipt or deployment rehearsal.
    let seal = |output: &Path| {
        let prepared = registry_breg::package::prepare_package_with_project_assets(
            registry_breg::package::PackageBuildRequest {
                from_package_digest: None,
                compiler_source_revision: read_yaml(&source.join("registry.yaml"))["package"]
                    ["sourceRevision"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                schema_fingerprint: format!("sha256:{}", "0".repeat(64)),
                project: registry_breg::package::PackageSourceFile {
                    path: "source/registry.yaml".to_owned(),
                    bytes: fs::read(source.join("registry.yaml")).unwrap(),
                },
                modules: Vec::new(),
                fixture_journeys: registry_breg::package::PackageSourceFile {
                    path: "tests/journeys.yaml".to_owned(),
                    bytes: fs::read(source.join("tests/journeys.yaml")).unwrap(),
                },
                migration_plan:
                    registry_breg::package::PackageMigrationPlanInput::InitialCompiledDdl,
            },
            vec![registry_breg::package::PackageSourceFile {
                path: "plans/correct-address.rhai".to_owned(),
                bytes: fs::read(source.join("plans/correct-address.rhai")).unwrap(),
            }],
        )
        .expect("native BReg fixture prepares");
        prepared
            .publish_to_directory(output)
            .expect("native BReg fixture seals");
    };
    let compose = |project: &Path, package: Option<&Path>, output: Option<&Path>| {
        let mut arguments = vec![
            "--format",
            "json",
            "provider",
            "add",
            project.to_str().unwrap(),
            "--breg-project",
            source.to_str().unwrap(),
            "--action",
            "correct-address",
            "--pattern",
            "single-reviewer-approval",
            "--bregctl-bin",
            bregctl.to_str().unwrap(),
        ];
        if let Some(package) = package {
            arguments.extend(["--breg-package", package.to_str().unwrap()]);
        }
        if let Some(output) = output {
            arguments.extend(["--package-output", output.to_str().unwrap()]);
        }
        caseworkctl(&arguments)
    };
    let stale_package = root.join("old-breg-package");
    seal(&stale_package);
    let registry_path = source.join("registry.yaml");
    let mut registry = read_yaml(&registry_path);
    let status = registry["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "casework-review-status")
        .unwrap();
    status["requiredScopes"] = json!("unrestricted");
    fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();
    let source_before = files(&source);
    let package_before = files(&stale_package);

    let existing = root.join("existing-review");
    let created = compose(&existing, None, None);
    assert!(
        created.status.success(),
        "changed source remains ready for review"
    );
    assert_eq!(
        fs::read(existing.join("schemas/correct-address.schema.json")).unwrap(),
        fs::read(
            stale_package.join("generated/review-context-schemas/correct-address.schema.json")
        )
        .unwrap(),
        "the authority change must leave the native context schema unchanged"
    );
    let existing_before = files(&existing);
    let absent = root.join("absent-review");
    for project in [&existing, &absent] {
        let output = project.join("custom/package");
        let requested_output = (project == &absent).then_some(output.as_path());
        let refused = compose(project, Some(&stale_package), requested_output);
        assert!(!refused.status.success(), "stale authority must be refused");
        assert_eq!(
            json(&refused)["diagnostics"][0]["code"],
            "casework.provider-add.breg-package-mismatch"
        );
        assert!(!output.exists());
    }
    assert!(!absent.exists());
    assert_eq!(files(&existing), existing_before);
    assert_eq!(files(&source), source_before);
    assert_eq!(files(&stale_package), package_before);

    let matching_package = root.join("current-breg-package");
    seal(&matching_package);
    for layout in [
        "absolute",
        "relative",
        "relative-project",
        "relative-output",
        "external",
        "external-missing-parent",
        "relative-external-missing-parent",
    ] {
        let project = root.join(format!("{layout}-review"));
        let output = if layout == "external" {
            root.join("external-sealed")
        } else if layout.ends_with("external-missing-parent") {
            let output = root.join(layout).join("new/build/package");
            assert!(!output.parent().unwrap().exists());
            output
        } else {
            project.join("custom/sealed")
        };
        let project_argument = if matches!(layout, "relative" | "relative-project") {
            project.strip_prefix(&working_directory).unwrap()
        } else {
            &project
        };
        let output_argument = if matches!(
            layout,
            "relative" | "relative-output" | "relative-external-missing-parent"
        ) {
            output.strip_prefix(&working_directory).unwrap()
        } else {
            &output
        };
        let created = compose(
            project_argument,
            Some(&matching_package),
            Some(output_argument),
        );
        assert!(
            created.status.success(),
            "{layout}: matching authority must compose: {}",
            json(&created)
        );
        assert_eq!(json(&created)["outcome"], "created");
        let runtime = read_yaml(&project.join("runtime.example.yaml"));
        assert_eq!(runtime["package"]["root"], json!(output));
        assert!(output.join("SHA256SUMS").is_file());
        let loaded = registry_casework::RuntimeConfig::load(project.join("runtime.example.yaml"))
            .expect("the generated runtime document loads its selected sealed package");
        loaded
            .load_package()
            .expect("the runtime captures and checks the selected package");
        assert!(
            runtime["contextProviders"]["correct-address-context"]
                .get("scopes")
                .is_none(),
            "an unrestricted source profile needs no invented OAuth scope"
        );
        let before = files(&project);
        let output_before = files(&output);
        let repeated = compose(
            project_argument,
            Some(&matching_package),
            Some(output_argument),
        );
        assert!(
            repeated.status.success(),
            "matching sealed rerun must succeed"
        );
        assert_eq!(json(&repeated)["outcome"], "in-agreement");
        assert_eq!(files(&project), before);
        assert_eq!(files(&output), output_before);
    }

    let blocked_parent = root.join("blocked-output");
    fs::write(&blocked_parent, b"preserve this file").unwrap();
    let refused_project = root.join("refused-external-review");
    let refused_output = blocked_parent.join("build/package");
    let before = files(&root);
    let entry_count = fs::read_dir(&root).unwrap().count();
    let refused = compose(
        &refused_project,
        Some(&matching_package),
        Some(&refused_output),
    );
    assert!(
        !refused.status.success(),
        "a file in the parent path must be refused"
    );
    assert!(!refused_project.exists());
    assert!(!refused_output.exists());
    assert_eq!(files(&root), before);
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        entry_count,
        "failed external staging must leave no temporary directories"
    );
}
