// SPDX-License-Identifier: Apache-2.0

//! The authoring commands refuse a Consultation contract whose selected
//! transformation or input closure cannot be loaded by the runtime.

use serde_json::Value;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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

fn copied_consultation() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let copy = root.path().join("dhis2-consultation");
    copy_fs(
        &repo_root().join("products/adapter/examples/dhis2-consultation"),
        &copy,
    );
    let project = copy.join("project.yaml");
    (root, project)
}

fn edit(file: &Path, from: &str, to: &str) {
    let contents = std::fs::read_to_string(file).unwrap();
    let edited = contents.replacen(from, to, 1);
    assert_ne!(contents, edited, "the test mutation must change {file:?}");
    std::fs::write(file, edited).unwrap();
}

fn mutate_schema(project: &Path, relative: &str, mutate: impl FnOnce(&mut serde_json::Value)) {
    let schema_path = project.parent().unwrap().join(relative);
    let mut schema: Value = serde_json::from_slice(&std::fs::read(&schema_path).unwrap()).unwrap();
    mutate(&mut schema);
    let mut bytes = serde_json::to_vec_pretty(&schema).unwrap();
    bytes.push(b'\n');
    std::fs::write(&schema_path, &bytes).unwrap();

    let mut project_text = std::fs::read_to_string(project).unwrap();
    let marker = format!("      file: {relative}\n      digest: ");
    let digest_start = project_text.find(&marker).expect("schema inventory") + marker.len();
    let digest_end = project_text[digest_start..]
        .find('\n')
        .map(|offset| digest_start + offset)
        .expect("digest line");
    project_text.replace_range(
        digest_start..digest_end,
        &registry_platform_config::sha256_uri(&bytes),
    );
    std::fs::write(project, project_text).unwrap();
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

fn check(project: &Path) -> (ExitCode, Value, Vec<u8>) {
    run_json(&[
        OsString::from("check"),
        project.as_os_str().to_owned(),
        OsString::from("--pack"),
        repo_root()
            .join("products/adapter/packs/dhis2-tracker/pack.yaml")
            .into_os_string(),
    ])
}

fn compile(project: &Path, output: &Path) -> (ExitCode, Value, Vec<u8>) {
    run_json(&[
        OsString::from("compile"),
        project.as_os_str().to_owned(),
        OsString::from("--pack"),
        repo_root()
            .join("products/adapter/packs/dhis2-tracker/pack.yaml")
            .into_os_string(),
        OsString::from("--output"),
        output.as_os_str().to_owned(),
    ])
}

fn assert_refused(result: &(ExitCode, Value, Vec<u8>), code: &str) {
    let (exit, report, stderr) = result;
    assert_eq!(*exit, ExitCode::from(1), "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(stderr));
    assert_eq!(report["status"], "domain-refusal", "{report}");
    let codes = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|diagnostic| diagnostic["code"].as_str())
        .collect::<Vec<_>>();
    assert!(codes.contains(&code), "expected {code} among {codes:?}");
}

#[test]
fn check_and_compile_refuse_a_consultation_binding_without_a_transform() {
    let (root, project) = copied_consultation();
    edit(
        &project,
        "  people-retrieve: {script: person-public, entrypoint: project_person_public}\n",
        "",
    );

    assert_refused(&check(&project), "adapter.project.transform-missing");
    let output = root.path().join("refused-openapi.json");
    assert_refused(
        &compile(&project, &output),
        "adapter.project.transform-missing",
    );
    assert!(!output.exists(), "a refused compile must write no contract");
}

#[test]
fn check_and_compile_refuse_an_uncompilable_transform_entrypoint() {
    let (root, project) = copied_consultation();
    edit(
        &project,
        "entrypoint: project_person_public",
        "entrypoint: missing_project_person_public",
    );

    assert_refused(&check(&project), "adapter.project.transform-uncompilable");
    let output = root.path().join("refused-openapi.json");
    assert_refused(
        &compile(&project, &output),
        "adapter.project.transform-uncompilable",
    );
    assert!(!output.exists(), "a refused compile must write no contract");
}

#[test]
fn check_and_compile_refuse_changed_transform_bytes() {
    let (root, project) = copied_consultation();
    let script = project.parent().unwrap().join("scripts/person-public.rhai");
    let mut contents = std::fs::read_to_string(&script).unwrap();
    contents.push_str("\n// changed after the reviewed pin\n");
    std::fs::write(script, contents).unwrap();

    assert_refused(&check(&project), "adapter.project.digest-pin-required");
    let output = root.path().join("refused-openapi.json");
    assert_refused(
        &compile(&project, &output),
        "adapter.project.digest-pin-required",
    );
    assert!(!output.exists(), "a refused compile must write no contract");
}

#[test]
fn check_and_compile_refuse_a_nullable_lookup_scalar_the_runtime_cannot_capture() {
    let (root, project) = copied_consultation();
    mutate_schema(&project, "schemas/record-id.schema.json", |schema| {
        schema["properties"]["record-id"]["type"] = serde_json::json!(["string", "null"])
    });

    assert_refused(
        &check(&project),
        "adapter.project.consultation-input-incompatible",
    );
    let output = root.path().join("refused-openapi.json");
    assert_refused(
        &compile(&project, &output),
        "adapter.project.consultation-input-incompatible",
    );
    assert!(!output.exists(), "a refused compile must write no contract");
}

#[test]
fn check_and_compile_refuse_an_optional_lookup_input_the_runtime_requires() {
    let (root, project) = copied_consultation();
    mutate_schema(&project, "schemas/record-id.schema.json", |schema| {
        schema["required"] = serde_json::json!([])
    });

    assert_refused(
        &check(&project),
        "adapter.project.consultation-input-incompatible",
    );
    let output = root.path().join("refused-openapi.json");
    assert_refused(
        &compile(&project, &output),
        "adapter.project.consultation-input-incompatible",
    );
    assert!(!output.exists(), "a refused compile must write no contract");
}

#[test]
fn check_and_compile_refuse_input_names_the_source_route_does_not_support() {
    let (root, project) = copied_consultation();
    mutate_schema(&project, "schemas/record-id.schema.json", |schema| {
        let property = schema["properties"]
            .as_object_mut()
            .unwrap()
            .remove("record-id")
            .unwrap();
        schema["properties"]["other-id"] = property;
        schema["required"] = serde_json::json!(["other-id"]);
    });

    assert_refused(
        &check(&project),
        "adapter.project.consultation-input-incompatible",
    );
    let output = root.path().join("refused-openapi.json");
    assert_refused(
        &compile(&project, &output),
        "adapter.project.consultation-input-incompatible",
    );
    assert!(!output.exists(), "a refused compile must write no contract");
}
