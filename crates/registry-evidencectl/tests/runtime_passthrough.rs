//! Process-level contract for the Evidence runtime passthrough.

#![cfg(unix)]

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const VERSION: &str = registry_platform_buildinfo::DISPLAY_VERSION;

fn evidencectl() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_evidencectl"));
    command
        .env_remove("EVIDENCE_BIN")
        .env_remove("RSTACK_EVIDENCE_BIN")
        .env_remove("RSTACK_GENERATION_DIR")
        .env_remove("RSTACK_RELEASE_TAG");
    command
}

fn write_evidence_stub(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().expect("stub parent")).expect("create stub directory");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(path)
        .expect("create evidence stub");
    writeln!(
        file,
        "#!/bin/sh\nif [ \"${{1:-}}\" = \"--version\" ]; then\n  printf 'evidence %s\\n' '{VERSION}'\n  exit 0\nfi\n{body}"
    )
    .expect("write evidence stub");
}

fn unmanaged_stub(root: &Path, body: &str) -> PathBuf {
    let path = root.join("evidence");
    write_evidence_stub(&path, body);
    path
}

#[test]
fn runtime_forwards_arguments_stdin_stdout_stderr_and_exit_status() {
    let workspace = tempfile::tempdir().expect("workspace");
    let evidence = unmanaged_stub(
        workspace.path(),
        r#"for argument in "$@"; do
  printf 'arg=<%s>\n' "$argument"
done
IFS= read -r input
printf 'stdin=<%s>\n' "$input"
printf 'runtime-stderr\n' >&2
exit 37"#,
    );

    let mut child = evidencectl()
        .env("EVIDENCE_BIN", evidence)
        .args([
            "runtime",
            "authority",
            "activate",
            "--runtime-config",
            "runtime with spaces.yaml",
            "--document",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start runtime passthrough");
    child
        .stdin
        .take()
        .expect("runtime stdin")
        .write_all(b"operator-input\n")
        .expect("write runtime stdin");
    let output = child
        .wait_with_output()
        .expect("wait for runtime passthrough");

    assert_eq!(output.status.code(), Some(37));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "arg=<authority>\narg=<activate>\narg=<--runtime-config>\narg=<runtime with spaces.yaml>\narg=<--document>\narg=<->\nstdin=<operator-input>\n"
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "runtime-stderr\n");
}

#[test]
fn runtime_uses_the_rstack_selected_generation_instead_of_path() {
    let workspace = tempfile::tempdir().expect("workspace");
    let generation = workspace.path().join("selected-generation");
    let selected = generation.join("components/evidence/evidence/evidence");
    write_evidence_stub(&selected, "printf 'selected-generation\\n'");

    let path_directory = workspace.path().join("path");
    let path_evidence = path_directory.join("evidence");
    write_evidence_stub(&path_evidence, "printf 'path-binary\\n'");

    let output = evidencectl()
        .env("RSTACK_GENERATION_DIR", &generation)
        .env("RSTACK_EVIDENCE_BIN", &selected)
        .env("RSTACK_RELEASE_TAG", "v-test")
        .env("PATH", &path_directory)
        .args(["runtime", "check"])
        .output()
        .expect("run selected Evidence runtime");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "selected-generation\n"
    );
}

#[test]
fn runtime_refuses_an_unmanaged_override_under_rstack() {
    let workspace = tempfile::tempdir().expect("workspace");
    let generation = workspace.path().join("selected-generation");
    let selected = generation.join("components/evidence/evidence/evidence");
    write_evidence_stub(&selected, "printf 'selected-generation\\n'");
    let override_binary = unmanaged_stub(
        &workspace.path().join("override"),
        "printf 'unmanaged-override\\n'",
    );

    let output = evidencectl()
        .env("RSTACK_GENERATION_DIR", &generation)
        .env("RSTACK_EVIDENCE_BIN", &selected)
        .env("RSTACK_RELEASE_TAG", "v-test")
        .env("EVIDENCE_BIN", &override_binary)
        .args(["runtime", "authority", "history"])
        .output()
        .expect("refuse unmanaged override");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("EVIDENCE_BIN"), "{stderr}");
    assert!(stderr.contains("selected generation"), "{stderr}");
    assert!(!stderr.contains("unmanaged-override"), "{stderr}");
}

#[test]
fn runtime_uses_the_unmanaged_override_before_path() {
    let workspace = tempfile::tempdir().expect("workspace");
    let override_binary = unmanaged_stub(
        &workspace.path().join("override"),
        "printf 'environment-override\\n'",
    );
    let path_directory = workspace.path().join("path");
    write_evidence_stub(&path_directory.join("evidence"), "printf 'path-binary\\n'");

    let output = evidencectl()
        .env("EVIDENCE_BIN", override_binary)
        .env("PATH", path_directory)
        .args(["runtime", "serve"])
        .output()
        .expect("run unmanaged Evidence override");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "environment-override\n"
    );
}

#[test]
fn runtime_refuses_a_mismatched_evidence_version_before_delegation() {
    let workspace = tempfile::tempdir().expect("workspace");
    let evidence = workspace.path().join("evidence");
    write_evidence_stub(&evidence, "printf 'delegated-to-mismatch\\n'");
    let text = fs::read_to_string(&evidence).expect("read evidence stub");
    fs::write(&evidence, text.replace(VERSION, "0.0.0-mismatch")).expect("replace stub version");

    let output = evidencectl()
        .env("EVIDENCE_BIN", evidence)
        .args(["runtime", "check"])
        .output()
        .expect("refuse mismatched Evidence runtime");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("reports version 0.0.0-mismatch"),
        "{stderr}"
    );
    assert!(stderr.contains("the two must match"), "{stderr}");
    assert!(!stderr.contains("delegated-to-mismatch"), "{stderr}");
}

#[test]
fn runtime_help_explains_the_passthrough_and_runtime_help_can_be_forwarded() {
    let help = evidencectl()
        .args(["runtime", "--help"])
        .output()
        .expect("show passthrough help");
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("RUNTIME_ARGUMENT"), "{help}");
    assert!(help.contains("runtime -- --help"), "{help}");
    assert!(help.contains("EVIDENCE_BIN"), "{help}");
    assert!(!help.contains("--format"), "{help}");

    let workspace = tempfile::tempdir().expect("workspace");
    let evidence = unmanaged_stub(
        workspace.path(),
        r#"if [ "${1:-}" = "--help" ]; then
  printf 'runtime-help\n'
  exit 0
fi
exit 9"#,
    );
    let forwarded = evidencectl()
        .env("EVIDENCE_BIN", evidence)
        .args(["runtime", "--", "--help"])
        .output()
        .expect("forward runtime help");
    assert!(forwarded.status.success());
    assert_eq!(String::from_utf8_lossy(&forwarded.stdout), "runtime-help\n");
}

#[test]
fn wrapper_format_is_refused_but_runtime_format_is_forwarded_unchanged() {
    let workspace = tempfile::tempdir().expect("workspace");
    let evidence = unmanaged_stub(
        workspace.path(),
        r#"for argument in "$@"; do
  printf '<%s>\n' "$argument"
done"#,
    );

    let refused = evidencectl()
        .env("EVIDENCE_BIN", &evidence)
        .args(["--format", "json", "runtime", "check"])
        .output()
        .expect("refuse wrapper format");
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--format is not supported by runtime"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let forwarded = evidencectl()
        .env("EVIDENCE_BIN", evidence)
        .args(["runtime", "check", "--format", "json"])
        .output()
        .expect("forward runtime format");
    assert!(
        forwarded.status.success(),
        "{}",
        String::from_utf8_lossy(&forwarded.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&forwarded.stdout),
        "<check>\n<--format>\n<json>\n"
    );
}
