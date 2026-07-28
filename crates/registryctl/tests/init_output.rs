// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

fn run_registryctl(args: &[&str], image_lock: Option<&std::path::Path>) -> Output {
    run_registryctl_in(None, args, image_lock)
}

fn run_registryctl_in(
    current_directory: Option<&std::path::Path>,
    args: &[&str],
    image_lock: Option<&std::path::Path>,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registryctl"));
    command.args(args).env("REGISTRYCTL_NO_UPDATE_CHECK", "1");
    if let Some(current_directory) = current_directory {
        command.current_dir(current_directory);
    }
    if let Some(image_lock) = image_lock {
        command.env("REGISTRYCTL_IMAGE_LOCK", image_lock);
    }
    command.output().expect("registryctl runs")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "registryctl failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_test_image_lock(temporary: &TempDir) -> std::path::PathBuf {
    let path = temporary.path().join("registryctl-image-lock.json");
    let digest = "a".repeat(64);
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "registryctl.release_image_lock.v2",
            "release_tag": format!("v{}", env!("CARGO_PKG_VERSION")),
            "manifest_source_ref": "b".repeat(40),
            "tag_target": "c".repeat(40),
            "platform": "linux/amd64",
            "images": {
                "registry-relay": format!("ghcr.io/registrystack/registry-relay@sha256:{digest}"),
                "registry-notary": format!("ghcr.io/registrystack/registry-notary@sha256:{digest}"),
                "postgresql": format!("docker.io/library/postgres@sha256:{digest}"),
            }
        }))
        .expect("test image lock renders"),
    )
    .expect("test image lock writes");
    path
}

#[cfg(unix)]
fn control_character_project(temp: &TempDir, leaf: &str) -> std::path::PathBuf {
    temp.path()
        .join("space \\ single' quote\nline\rreturn\ttab\u{1b}escape\u{1}c0\u{7f}del\u{85}c1")
        .join(leaf)
}

#[cfg(unix)]
fn expected_human_path(path: &std::path::Path) -> String {
    let mut escaped = String::new();
    for character in path.to_str().expect("test path is valid UTF-8").chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\'' => escaped.push_str("\\'"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(escaped, "\\u{:04x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    format!("$'{escaped}'")
}

#[cfg(unix)]
fn assert_stdout_has_no_terminal_controls(stdout: &str) {
    for character in stdout.chars() {
        assert!(
            character == '\n' || !character.is_control(),
            "stdout contains raw control U+{:04X}: {stdout:?}",
            character as u32
        );
    }
}

#[cfg(unix)]
fn assert_shell_path_is_usable(rendered: &str) {
    let output = Command::new("bash")
        .args(["-c", &format!("cd {rendered} && test -d .")])
        .output()
        .expect("bash runs rendered next command");
    assert!(
        output.status.success(),
        "rendered path was not reusable by bash: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn starter_init_defaults_to_a_concise_human_result() {
    let temporary = TempDir::new().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    let output = run_registryctl(
        &[
            "init",
            "--from",
            "http",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
        ],
        None,
    );
    assert_success(&output);

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert_eq!(
        stdout,
        format!(
            "Initialized Registry Stack project \"fictional-citizen-registry\".\n  Directory: {}\n  Starter: http (Registry Stack {})\n  Starter content: matches bundled digest\n  Editor support: VS Code and Zed ({})\n\nNext:\n  cd {}\n  registryctl test --project-dir .\n",
            project.display(),
            env!("CARGO_PKG_VERSION"),
            project
                .join(".registry-stack-editor/manifest.json")
                .display(),
            project.display(),
        )
    );
}

#[cfg(unix)]
#[test]
fn starter_init_human_paths_are_line_safe_and_shell_usable() {
    let temporary = TempDir::new().expect("temporary directory");
    let project = control_character_project(&temporary, "registry-project");
    let output = run_registryctl(
        &[
            "init",
            "--from",
            "http",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
        ],
        None,
    );
    assert_success(&output);

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let rendered_project = expected_human_path(&project);
    let rendered_manifest =
        expected_human_path(&project.join(".registry-stack-editor/manifest.json"));
    assert_eq!(
        stdout,
        format!(
            "Initialized Registry Stack project \"fictional-citizen-registry\".\n  Directory: {rendered_project}\n  Starter: http (Registry Stack {})\n  Starter content: matches bundled digest\n  Editor support: VS Code and Zed ({rendered_manifest})\n\nNext:\n  cd {rendered_project}\n  registryctl test --project-dir .\n",
            env!("CARGO_PKG_VERSION"),
        )
    );
    assert_stdout_has_no_terminal_controls(&stdout);
    for escaped in [
        "\\\\", "\\'", "\\n", "\\r", "\\t", "\\u001b", "\\u0001", "\\u007f", "\\u0085",
    ] {
        assert!(stdout.contains(escaped), "missing {escaped:?}: {stdout:?}");
    }
    assert_shell_path_is_usable(&rendered_project);
}

#[test]
fn starter_init_prefixes_relative_leading_dash_paths_for_shell_use() {
    for (arguments, expected) in [
        (
            vec!["init", "--from", "http", "--project-dir=-foo"],
            "./-foo",
        ),
        (vec!["init", "--from", "http", "--project-dir", "-"], "./-"),
    ] {
        let temporary = TempDir::new().expect("temporary directory");
        let output = run_registryctl_in(Some(temporary.path()), &arguments, None);
        assert_success(&output);

        let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
        assert!(
            stdout.contains(&format!("  Directory: {expected}\n")),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!(
                "  Editor support: VS Code and Zed ({expected}/.registry-stack-editor/manifest.json)\n"
            )),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!("\nNext:\n  cd {expected}\n")),
            "{stdout}"
        );
        let shell = Command::new("bash")
            .args(["-c", &format!("cd {expected} && test -d .")])
            .current_dir(temporary.path())
            .output()
            .expect("bash runs leading-dash next command");
        assert!(
            shell.status.success(),
            "rendered leading-dash path was not reusable by bash: {}",
            String::from_utf8_lossy(&shell.stderr)
        );
    }
}

#[test]
fn starter_init_json_is_versioned_and_contains_only_init_facts() {
    let temporary = TempDir::new().expect("temporary directory");
    let project = temporary.path().join("registry-project-json");
    let output = run_registryctl(
        &[
            "init",
            "--from",
            "http",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
            "--format",
            "json",
        ],
        None,
    );
    assert_success(&output);

    let report: Value = serde_json::from_slice(&output.stdout).expect("init emits only JSON");
    assert_eq!(report["schema_version"], "registryctl.init.v1");
    assert_eq!(report["status"], "initialized");
    assert_eq!(report["project"], "fictional-citizen-registry");
    assert_eq!(report["project_kind"], "registry_project");
    assert_eq!(report["output"], project.to_string_lossy().as_ref());
    assert_eq!(report["source"]["kind"], "starter");
    assert_eq!(report["source"]["id"], "http");
    assert_eq!(report["source"]["content_state"], "matches");
    assert_eq!(
        report["artifacts"]["project_file"],
        project
            .join("registry-stack.yaml")
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(
        report["artifacts"]["editor_manifest"],
        project
            .join(".registry-stack-editor/manifest.json")
            .to_string_lossy()
            .as_ref()
    );
    for unrelated in ["environment", "fixtures", "baseline", "explanation"] {
        assert!(report.get(unrelated).is_none(), "unexpected {unrelated}");
    }
}

#[cfg(unix)]
#[test]
fn json_init_rejects_non_utf8_starter_destinations_before_dispatch() {
    use std::os::unix::ffi::OsStringExt as _;

    let temporary = TempDir::new().expect("temporary directory");
    let mut leaf = b"starter-".to_vec();
    leaf.push(0xff);
    let destination = temporary.path().join(std::ffi::OsString::from_vec(leaf));
    let output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args(["init", "--from", "http", "--project-dir"])
        .arg(&destination)
        .args(["--format", "json"])
        .env("REGISTRYCTL_NO_UPDATE_CHECK", "1")
        .output()
        .expect("registryctl runs");

    assert!(
        !output.status.success(),
        "starter init unexpectedly succeeded"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("init --format json requires a UTF-8 destination path"),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !destination.exists(),
        "JSON destination validation must happen before initialization"
    );
}

#[test]
fn relay_init_is_retired_before_image_lock_loading_or_project_mutation() {
    let temporary = TempDir::new().expect("temporary directory");
    let project = temporary.path().join("my-first-api");
    let missing_image_lock = temporary.path().join("missing-image-lock.json");
    let output = run_registryctl(
        &[
            "init",
            "relay",
            project.to_str().expect("UTF-8 project path"),
            "--sample",
            "benefits",
        ],
        Some(&missing_image_lock),
    );

    assert!(
        !output.status.success(),
        "retired command unexpectedly succeeded"
    );
    assert!(output.stdout.is_empty(), "retired command emitted stdout");
    assert_eq!(
        String::from_utf8(output.stderr).expect("UTF-8 stderr"),
        "Error: `registryctl init relay` was retired before 1.0. Reinitialize with \
`registryctl init --from spreadsheet --project-dir <directory>` and re-express the reviewed \
project intent; legacy direct projects are not migrated automatically.\n"
    );
    assert!(
        !project.exists(),
        "retired command must not create a project directory"
    );
}

#[cfg(unix)]
#[test]
fn json_init_paths_preserve_control_characters() {
    let temporary = TempDir::new().expect("temporary directory");

    let starter_project = control_character_project(&temporary, "registry-project-json");
    let starter_output = run_registryctl(
        &[
            "init",
            "--from",
            "http",
            "--project-dir",
            starter_project.to_str().expect("UTF-8 project path"),
            "--format",
            "json",
        ],
        None,
    );
    assert_success(&starter_output);
    let starter: Value =
        serde_json::from_slice(&starter_output.stdout).expect("starter init emits valid JSON");
    assert_eq!(
        starter["output"],
        starter_project.to_str().expect("UTF-8 project path")
    );
    assert_eq!(
        starter["artifacts"]["project_file"],
        starter_project
            .join("registry-stack.yaml")
            .to_str()
            .expect("UTF-8 artifact path")
    );
    assert_eq!(
        starter["artifacts"]["editor_manifest"],
        starter_project
            .join(".registry-stack-editor/manifest.json")
            .to_str()
            .expect("UTF-8 artifact path")
    );
}

#[test]
fn spreadsheet_starter_excludes_generated_runtime_and_private_state_from_git() {
    let temporary = TempDir::new().expect("temporary directory");
    let project = temporary.path().join("spreadsheet-project");
    let output = run_registryctl(
        &[
            "init",
            "--from",
            "spreadsheet",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
        ],
        None,
    );
    assert_success(&output);

    let gitignore =
        fs::read_to_string(project.join(".gitignore")).expect("starter .gitignore reads");
    assert_eq!(gitignore, ".registry-stack/\n");
    assert!(project.join("registry-stack.yaml").is_file());
    assert!(project.join("data/public_works_projects.xlsx").is_file());
}

#[test]
fn first_runtime_start_requires_image_lock_before_writing_generated_state() {
    let temporary = TempDir::new().expect("temporary directory");
    let project = temporary.path().join("spreadsheet-project");
    let init = run_registryctl(
        &[
            "init",
            "--from",
            "spreadsheet",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
        ],
        None,
    );
    assert_success(&init);

    let missing_image_lock = temporary.path().join("missing-image-lock.json");
    let start = run_registryctl_in(Some(&project), &["start"], Some(&missing_image_lock));

    assert!(!start.status.success(), "start unexpectedly succeeded");
    assert!(start.stdout.is_empty(), "failed start emitted stdout");
    assert!(
        String::from_utf8(start.stderr)
            .expect("UTF-8 stderr")
            .contains("registryctl image lock is missing"),
        "failed start did not explain the missing image lock"
    );
    assert!(
        !project.join(".registry-stack/runtime").exists(),
        "failed start wrote generated runtime state"
    );
}

#[test]
fn add_notary_updates_canonical_spreadsheet_idempotently_and_rejects_legacy_projects() {
    let temporary = TempDir::new().expect("temporary directory");
    let image_lock = write_test_image_lock(&temporary);
    let project = temporary.path().join("spreadsheet-project");
    let init_human = run_registryctl(
        &[
            "init",
            "--from",
            "spreadsheet",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
        ],
        None,
    );
    assert_success(&init_human);
    let init_human = String::from_utf8(init_human.stdout).expect("human output is UTF-8");
    assert!(init_human.ends_with(&format!(
        "\nNext:\n  cd {}\n  registryctl doctor --profile local\n  registryctl start\n",
        project.display()
    )));
    fs::remove_dir_all(&project).expect("first initialized project removes");

    let init = run_registryctl(
        &[
            "init",
            "--from",
            "spreadsheet",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
            "--format",
            "json",
        ],
        None,
    );
    assert_success(&init);

    let output = run_registryctl_in(
        Some(&project),
        &["add", "notary", "--format", "json"],
        Some(&image_lock),
    );
    assert_success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).expect("add notary emits JSON");
    assert_eq!(report["schema_version"], "registryctl.add_notary.v1");
    assert_eq!(report["status"], "updated");
    assert!(project
        .join("integrations/project-record-snapshot/integration.yaml")
        .is_file());
    assert!(fs::read_to_string(project.join("registry-stack.yaml"))
        .expect("project reads")
        .contains("subject_type: project"));

    let fixtures = run_registryctl_in(Some(&project), &["test", "--environment", "local"], None);
    assert_success(&fixtures);
    assert!(String::from_utf8_lossy(&fixtures.stdout).contains("PASS: 6/6 fixtures passed"));
    let build = run_registryctl_in(
        Some(&project),
        &["build", "--environment", "local", "--format", "json"],
        None,
    );
    assert_success(&build);
    serde_json::from_slice::<Value>(&build.stdout).expect("build emits JSON");
    let compiled_notary: Value = serde_norway::from_slice(
        &fs::read(project.join(".registry-stack/build/local/private/notary/config/notary.yaml"))
            .expect("compiled Notary config reads"),
    )
    .expect("compiled Notary config parses");
    assert!(compiled_notary["evidence"]["claims"]
        .as_array()
        .expect("compiled claims are an array")
        .iter()
        .all(|claim| claim["subject_type"] == "project"));

    let project_before = fs::read_to_string(project.join("registry-stack.yaml")).unwrap();
    let environment_before = fs::read_to_string(project.join("environments/local.yaml")).unwrap();
    let repeat = run_registryctl_in(Some(&project), &["add", "notary", "--format", "json"], None);
    assert_success(&repeat);
    let repeat_report: Value =
        serde_json::from_slice(&repeat.stdout).expect("repeat add notary emits JSON");
    assert_eq!(repeat_report["status"], "unchanged");
    assert_eq!(
        fs::read_to_string(project.join("registry-stack.yaml")).unwrap(),
        project_before
    );
    assert_eq!(
        fs::read_to_string(project.join("environments/local.yaml")).unwrap(),
        environment_before
    );

    let human = run_registryctl_in(Some(&project), &["add", "notary"], None);
    assert_success(&human);
    let human_stdout = String::from_utf8(human.stdout).expect("human output is UTF-8");
    assert!(human_stdout.starts_with("Verified local Notary add-on.\n"));
    assert!(human_stdout.ends_with(
        "\nNext:\n  registryctl test --environment local\n  registryctl restart\n  registryctl smoke\n"
    ));

    let legacy = temporary.path().join("legacy");
    fs::create_dir(&legacy).expect("legacy dir creates");
    fs::write(
        legacy.join("registryctl.yaml"),
        "schema_version: registryctl/v1\n",
    )
    .expect("legacy marker writes");
    let output = run_registryctl_in(Some(&legacy), &["add", "notary", "--format", "json"], None);

    assert!(
        !output.status.success(),
        "legacy command unexpectedly succeeded"
    );
    assert!(output.stdout.is_empty(), "legacy command emitted stdout");
    assert!(String::from_utf8(output.stderr)
        .expect("UTF-8 stderr")
        .contains("legacy pre-1.0 direct projects are retired"));
}

#[test]
fn project_commands_default_to_human_output_and_keep_versioned_json_opt_in() {
    let temporary = TempDir::new().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    let init = run_registryctl(
        &[
            "init",
            "--from",
            "http",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
        ],
        None,
    );
    assert_success(&init);

    let editor = run_registryctl(
        &[
            "authoring",
            "editor",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
        ],
        None,
    );
    assert_success(&editor);
    let editor = String::from_utf8(editor.stdout).expect("UTF-8 editor output");
    assert!(editor.starts_with("Configured Registry Stack editor support for "));
    assert!(editor.contains("\n  Generated files: "));

    let json_editor = run_registryctl(
        &[
            "authoring",
            "editor",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
            "--format",
            "json",
        ],
        None,
    );
    assert_success(&json_editor);
    let json_editor: Value =
        serde_json::from_slice(&json_editor.stdout).expect("editor setup emits only JSON");
    assert_eq!(
        json_editor["schema_version"],
        "registryctl.project_editor.v1"
    );
    assert_eq!(json_editor["status"], "configured");

    let test = run_registryctl(
        &[
            "test",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
        ],
        None,
    );
    assert_success(&test);
    let test = String::from_utf8(test.stdout).expect("UTF-8 test output");
    assert!(test.starts_with("PASS: "), "{test}");
    assert!(test.ends_with(" fixtures passed\n"), "{test}");

    let json_watch = run_registryctl(
        &[
            "test",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
            "--watch",
            "--format",
            "json",
        ],
        None,
    );
    assert!(!json_watch.status.success());
    assert!(String::from_utf8_lossy(&json_watch.stderr)
        .contains("test --watch supports only human output"));

    let trace = run_registryctl(
        &[
            "test",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
            "--integration",
            "person-record",
            "--fixture",
            "active-person",
            "--trace",
        ],
        None,
    );
    assert_success(&trace);
    let trace = String::from_utf8(trace.stdout).expect("UTF-8 trace output");
    assert!(
        trace.contains("\n  PASS person-record.active-person"),
        "{trace}"
    );
    assert!(trace.contains("\n    inputs: person_id"), "{trace}");
    assert!(trace.contains("\n    outputs: active"), "{trace}");

    let json_test = run_registryctl(
        &[
            "test",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
            "--format",
            "json",
        ],
        None,
    );
    assert_success(&json_test);
    let json_test: Value = serde_json::from_slice(&json_test.stdout).expect("test emits only JSON");
    assert_eq!(
        json_test["schema_version"],
        "registryctl.project_command.v1"
    );
    assert_eq!(json_test["status"], "passed");

    let build = run_registryctl(
        &[
            "build",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
            "--environment",
            "local",
        ],
        None,
    );
    assert_success(&build);
    let build = String::from_utf8(build.stdout).expect("UTF-8 build output");
    assert!(
        build.starts_with("Built Registry Stack project \"fictional-citizen-registry\".\n"),
        "{build}"
    );
    assert!(build.contains("\n  Environment: local\n"), "{build}");
    assert!(build.contains("\n  Output: "), "{build}");

    let json_build = run_registryctl(
        &[
            "build",
            "--project-dir",
            project.to_str().expect("UTF-8 project path"),
            "--environment",
            "local",
            "--format",
            "json",
        ],
        None,
    );
    assert_success(&json_build);
    let json_build: Value =
        serde_json::from_slice(&json_build.stdout).expect("build emits only JSON");
    assert_eq!(
        json_build["schema_version"],
        "registryctl.project_command.v1"
    );
    assert_eq!(json_build["status"], "built");
}
