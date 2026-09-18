//! Process-level acceptance tests for `--format json` surfaces that are not
//! owned by a single command module: machine-readable help and the check
//! report envelope.

use std::{fs, process::Command};

use serde_json::Value;

fn evidencectl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn json_of(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON on stdout: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn help_honours_the_global_json_format_with_the_catalog_schema() {
    for arguments in [
        vec!["--format", "json", "help"],
        vec!["help", "--format", "json"],
        vec!["--format", "json", "--help"],
        vec!["--format", "json", "target", "--help"],
    ] {
        let output = evidencectl()
            .args(&arguments)
            .output()
            .expect("run evidencectl");
        assert_eq!(output.status.code(), Some(0), "arguments: {arguments:?}");
        assert!(
            output.stderr.is_empty(),
            "JSON help wrote to stderr for {arguments:?}"
        );
        let catalog = json_of(&output);
        assert_eq!(
            catalog["schema_version"], "registry.cli-reference/v2",
            "arguments: {arguments:?}"
        );
        let binaries = catalog["binaries"].as_array().expect("binaries array");
        assert_eq!(binaries.len(), 1, "arguments: {arguments:?}");
        assert_eq!(binaries[0]["name"], "evidencectl");
        let names: Vec<&str> = binaries[0]["subcommands"]
            .as_array()
            .expect("subcommands")
            .iter()
            .map(|command| command["name"].as_str().expect("name"))
            .collect();
        for expected in ["check", "target", "dev", "source"] {
            assert!(names.contains(&expected), "missing {expected}: {names:?}");
        }
    }
}

/// The refused report answers the same key set a passing report answers, so a
/// reader inspects one shape instead of branching on the outcome.
#[test]
fn a_refused_check_report_keeps_the_passing_report_top_level_keys() {
    let workspace = tempfile::tempdir().expect("temporary workspace");
    let project = workspace.path().join("project");
    let output = evidencectl()
        .args([
            "init",
            &project.display().to_string(),
            "--transport",
            "sqlite-extract",
            "--profile",
            "local",
        ])
        .output()
        .expect("scaffold project");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let questions = fs::read_dir(project.join("questions")).expect("questions directory");
    let mut corrupted = false;
    for entry in questions {
        let path = entry.expect("question entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "yaml")
        {
            let text = fs::read_to_string(&path).expect("question text");
            fs::write(&path, text.replacen("purpose:", "purpose: [unclosed", 1))
                .expect("corrupt question");
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "the scaffold must ship at least one question");

    let output = evidencectl()
        .args(["--format", "json", "check", &project.display().to_string()])
        .output()
        .expect("run check");
    assert_eq!(output.status.code(), Some(1));
    let report = json_of(&output);
    for key in ["command", "ok", "status", "proof", "project", "findings"] {
        assert!(
            report.get(key).is_some(),
            "refused report lacks {key}: {report}"
        );
    }
    assert_eq!(report["ok"], Value::Bool(false));
    assert_eq!(report["status"], "refused");
    assert!(report["findings"].as_array().is_some_and(|f| !f.is_empty()));
}

/// `tooling editor` reuses its versioned setup report inside the shared JSON
/// envelope, so a tool reading the terminal and a tool reading stdout see the
/// same managed set.
#[test]
fn tooling_editor_publishes_its_setup_report_in_json() {
    let workspace = tempfile::tempdir().expect("temporary workspace");
    let project = workspace.path().join("project");
    fs::create_dir(&project).expect("project directory");
    fs::write(
        project.join("evidence-project.yaml"),
        registry_evidence_authoring::default_project_marker_document(),
    )
    .expect("project marker");

    let output = evidencectl()
        .args(["--format", "json", "tooling", "editor", "--project"])
        .arg(&project)
        .output()
        .expect("run tooling editor");
    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stderr.is_empty(),
        "JSON mode wrote human diagnostics: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json_of(&output);
    assert_eq!(report["command"], "tooling editor");
    assert_eq!(report["ok"], Value::Bool(true));
    assert_eq!(report["status"], "complete");
    assert_eq!(report["schemaVersion"], "evidencectl.editor.v1");
    assert_eq!(report["editorStatus"], "configured");
    assert_eq!(
        report["projectDirectory"],
        Value::String(
            project
                .canonicalize()
                .expect("canonical")
                .display()
                .to_string()
        )
    );
    let mut files = report["files"].as_array().expect("files").clone();
    files.sort_by_key(|file| file.as_str().expect("path").to_owned());
    assert_eq!(
        files
            .iter()
            .map(|file| file.as_str().expect("path"))
            .collect::<Vec<_>>(),
        [
            ".evidence-editor/manifest.json",
            ".evidence-editor/schemas/project-marker.schema.json",
            ".evidence-editor/schemas/question.schema.json",
            ".vscode/extensions.json",
            ".vscode/settings.json",
            ".zed/settings.json",
        ]
    );
}
