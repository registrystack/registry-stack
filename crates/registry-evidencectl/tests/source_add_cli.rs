//! `source add` composes a local Evidence source through the public
//! `bregctl` binary of the same version found on PATH. When that binary
//! answers with a different version, the refusal must be as legible in
//! `--format json` as it already is in the human renderer.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output},
};

use serde_json::Value;

#[test]
fn json_source_add_names_the_bregctl_version_mismatch_and_both_versions() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let expected = format!("bregctl {}", registry_platform_buildinfo::DISPLAY_VERSION);
    let bregctl = script(workspace.path(), "bregctl", "bregctl 0.0.0-other");

    let output = evidencectl(&[
        "--format".to_owned(),
        "json".to_owned(),
        "source".to_owned(),
        "add".to_owned(),
        path_argument(&workspace.path().join("registry")),
        "--bregctl-bin".to_owned(),
        path_argument(&bregctl),
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr_of(&output).is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).expect("one JSON failure");
    assert_eq!(report["status"], "domain-refusal");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "evidencectl.bregctl.version-mismatch");
    assert_eq!(diagnostic["foundVersion"], "bregctl 0.0.0-other");
    assert_eq!(diagnostic["requiredVersion"], expected);
    let message = diagnostic["message"].as_str().expect("message");
    assert!(message.contains("bregctl 0.0.0-other"), "{message}");
    assert!(message.contains(&expected), "{message}");
}

fn evidencectl(arguments: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("running evidencectl")
}

fn script(root: &Path, name: &str, reported: &str) -> std::path::PathBuf {
    let path = root.join(name);
    fs::write(&path, format!("#!/bin/sh\necho '{reported}'\n")).expect("writing a fake bregctl");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("making it executable");
    path
}

fn path_argument(path: &Path) -> String {
    path.to_str()
        .expect("test paths are valid UTF-8")
        .to_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf8 stderr")
}
