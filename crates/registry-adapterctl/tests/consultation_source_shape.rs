// SPDX-License-Identifier: Apache-2.0

//! Consultation authoring refuses source read shapes that the fixed target
//! cannot execute, before either check or contract compilation can succeed.

use serde_json::Value;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const INPUT_INCOMPATIBLE: &str = "adapter.project.consultation-input-incompatible";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn copy_fs(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_fs(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

struct ConsultationWorkspace {
    _root: tempfile::TempDir,
    project: PathBuf,
    pack: PathBuf,
}

fn copied_consultation() -> ConsultationWorkspace {
    let root = tempfile::tempdir().unwrap();
    let example = root.path().join("dhis2-consultation");
    let pack_directory = root.path().join("dhis2-tracker");
    copy_fs(
        &repo_root().join("products/adapter/examples/dhis2-consultation"),
        &example,
    );
    copy_fs(
        &repo_root().join("products/adapter/packs/dhis2-tracker"),
        &pack_directory,
    );
    ConsultationWorkspace {
        _root: root,
        project: example.join("project.yaml"),
        pack: pack_directory.join("pack.yaml"),
    }
}

fn replace_once(file: &Path, from: &str, to: &str) {
    let contents = std::fs::read_to_string(file).unwrap();
    let edited = contents.replacen(from, to, 1);
    assert_ne!(contents, edited, "the test mutation must change {file:?}");
    std::fs::write(file, edited).unwrap();
}

fn refresh_pack_pin(project: &Path, pack: &Path) {
    let digest = registry_platform_config::sha256_uri(&std::fs::read(pack).unwrap());
    let mut project_text = std::fs::read_to_string(project).unwrap();
    let pack_start = project_text.find("pack:\n").expect("pack reference");
    let digest_marker = "  digest: ";
    let digest_start = project_text[pack_start..]
        .find(digest_marker)
        .map(|offset| pack_start + offset + digest_marker.len())
        .expect("pack digest");
    let digest_end = project_text[digest_start..]
        .find('\n')
        .map(|offset| digest_start + offset)
        .expect("pack digest line");
    project_text.replace_range(digest_start..digest_end, &digest);
    std::fs::write(project, project_text).unwrap();
}

fn give_retrieve_a_two_input_route(workspace: &ConsultationWorkspace) {
    let mut pack = std::fs::read_to_string(&workspace.pack).unwrap();
    let template_start = pack
        .find("  - id: read-tracked-entity\n")
        .expect("exact-read template");
    let next_template = pack[template_start..]
        .find("  - id: page-tracked-entities\n")
        .map(|offset| template_start + offset)
        .expect("following page template");
    let clone = pack[template_start..next_template]
        .replacen(
            "  - id: read-tracked-entity\n",
            "  - id: read-tracked-entity-two-inputs\n",
            1,
        )
        .replacen(
            "      inputs: [record-id]\n",
            "      inputs: [record-id, tenant-id]\n",
            1,
        );
    assert!(clone.contains("inputs: [record-id, tenant-id]"));
    pack.insert_str(next_template, &clone);
    std::fs::write(&workspace.pack, pack).unwrap();

    replace_once(
        &workspace.project,
        "  - routeTemplate: read-tracked-entity\n    routeId: person-read\n",
        "  - routeTemplate: read-tracked-entity\n    routeId: person-read\n  - routeTemplate: read-tracked-entity-two-inputs\n    routeId: person-read-two-inputs\n",
    );
    replace_once(
        &workspace.project,
        "    route: person-read\n",
        "    route: person-read-two-inputs\n",
    );
    refresh_pack_pin(&workspace.project, &workspace.pack);
}

fn give_list_a_nonempty_equality_input(workspace: &ConsultationWorkspace) {
    replace_once(
        &workspace.pack,
        "  - id: page-tracked-entities\n    readSupport:\n      type: read-page\n      order:\n",
        "  - id: page-tracked-entities\n    readSupport:\n      type: read-page\n      inputs:\n        - name: org-unit\n          comparisons: [equality]\n      order:\n",
    );
    refresh_pack_pin(&workspace.project, &workspace.pack);
}

fn give_retrieve_a_route_without_read_support(workspace: &ConsultationWorkspace) {
    let mut pack = std::fs::read_to_string(&workspace.pack).unwrap();
    let template_start = pack
        .find("  - id: read-tracked-entity\n")
        .expect("exact-read template");
    let next_template = pack[template_start..]
        .find("  - id: page-tracked-entities\n")
        .map(|offset| template_start + offset)
        .expect("following page template");
    let clone = pack[template_start..next_template]
        .replacen(
            "  - id: read-tracked-entity\n",
            "  - id: read-tracked-entity-without-support\n",
            1,
        )
        .replacen(
            "    readSupport:\n      type: read-one\n      inputs: [record-id]\n",
            "",
            1,
        );
    assert!(!clone.contains("readSupport:"));
    pack.insert_str(next_template, &clone);
    std::fs::write(&workspace.pack, pack).unwrap();

    replace_once(
        &workspace.project,
        "  - routeTemplate: read-tracked-entity\n    routeId: person-read\n",
        "  - routeTemplate: read-tracked-entity\n    routeId: person-read\n  - routeTemplate: read-tracked-entity-without-support\n    routeId: person-read-without-support\n",
    );
    replace_once(
        &workspace.project,
        "    route: person-read\n",
        "    route: person-read-without-support\n",
    );
    refresh_pack_pin(&workspace.project, &workspace.pack);
}

fn run_json(arguments: &[OsString]) -> (ExitCode, Value, Vec<u8>) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut all = vec![
        OsString::from("adapterctl"),
        OsString::from("--format=json"),
    ];
    all.extend_from_slice(arguments);
    let exit = registry_adapterctl::main_entry_from(all, &mut stdout, &mut stderr);
    let report = serde_json::from_slice(&stdout).unwrap();
    (exit, report, stderr)
}

fn check(workspace: &ConsultationWorkspace) -> (ExitCode, Value, Vec<u8>) {
    run_json(&[
        OsString::from("check"),
        workspace.project.as_os_str().to_owned(),
        OsString::from("--pack"),
        workspace.pack.as_os_str().to_owned(),
    ])
}

fn compile(workspace: &ConsultationWorkspace, output: &Path) -> (ExitCode, Value, Vec<u8>) {
    run_json(&[
        OsString::from("compile"),
        workspace.project.as_os_str().to_owned(),
        OsString::from("--pack"),
        workspace.pack.as_os_str().to_owned(),
        OsString::from("--output"),
        output.as_os_str().to_owned(),
    ])
}

fn assert_accepted(result: &(ExitCode, Value, Vec<u8>)) {
    let (exit, report, stderr) = result;
    assert_eq!(*exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(stderr));
}

fn assert_only_source_shape_refusals(result: &(ExitCode, Value, Vec<u8>)) {
    let (exit, report, stderr) = result;
    assert_eq!(*exit, ExitCode::from(1), "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(stderr));
    assert_eq!(report["status"], "domain-refusal", "{report}");
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
    assert!(!diagnostics.is_empty(), "{report}");
    assert!(
        diagnostics
            .iter()
            .all(|diagnostic| diagnostic["code"] == INPUT_INCOMPATIBLE),
        "the otherwise-valid workspace must fail only at the target source-shape boundary: {report}"
    );
}

#[test]
fn check_and_compile_refuse_retrieve_with_two_source_inputs() {
    let workspace = copied_consultation();
    assert_accepted(&check(&workspace));

    give_retrieve_a_two_input_route(&workspace);

    assert_only_source_shape_refusals(&check(&workspace));
    let output = workspace
        .project
        .parent()
        .unwrap()
        .join("refused-retrieve-openapi.json");
    assert_only_source_shape_refusals(&compile(&workspace, &output));
    assert!(!output.exists(), "a refused compile must write no contract");
}

#[test]
fn check_and_compile_refuse_list_with_a_nonempty_source_input() {
    let workspace = copied_consultation();
    assert_accepted(&check(&workspace));

    give_list_a_nonempty_equality_input(&workspace);

    assert_only_source_shape_refusals(&check(&workspace));
    let output = workspace
        .project
        .parent()
        .unwrap()
        .join("refused-list-openapi.json");
    assert_only_source_shape_refusals(&compile(&workspace, &output));
    assert!(!output.exists(), "a refused compile must write no contract");
}

#[test]
fn check_and_compile_refuse_retrieve_without_source_read_support() {
    let workspace = copied_consultation();
    assert_accepted(&check(&workspace));

    give_retrieve_a_route_without_read_support(&workspace);

    assert_only_source_shape_refusals(&check(&workspace));
    let output = workspace
        .project
        .parent()
        .unwrap()
        .join("refused-missing-support-openapi.json");
    assert_only_source_shape_refusals(&compile(&workspace, &output));
    assert!(!output.exists(), "a refused compile must write no contract");
}
