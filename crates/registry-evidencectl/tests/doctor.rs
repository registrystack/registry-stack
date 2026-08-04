#![cfg(unix)]

//! `evidencectl doctor` over a real deployment project.
//!
//! Every assertion here is about a mode or an owner the Evidence or Mint
//! runtime refuses at startup. The filesystem is intentionally assembled as a
//! doctor fixture because `evidencectl new` no longer invents a runnable
//! deployment. No `evidence` binary is involved anywhere in this file:
//! `doctor` is a filesystem walk, and an adopter who cannot yet start the
//! service is exactly the one who needs it. Nothing here prints key material.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output},
};

const SIGNING_KID: &str = "doctor-signing-key-1";
const MINT_KID: &str = "doctor-mint-key-1";
const CALLER_KID: &str = "doctor-client-key-1";
const SECRET_FILES: [&str; 2] = ["audit-hmac-key", "subject-binding-hmac-key"];

#[test]
fn doctor_passes_a_frozen_project_and_leaves_the_public_key_beside_it_alone() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);

    // `keygen signing` writes the public half into the secret root at 0644 by
    // design. The runtime never resolves it as a secret, so doctor must not
    // report it. A walk of the secret directory would; a walk of the secret
    // references the bundle actually names does not.
    let public_key = project.join("secrets/signing-ed25519-public.jwk.json");
    assert_eq!(
        mode_of(&public_key),
        0o644,
        "the scaffolded public key is no longer world-readable, so this test proves nothing"
    );

    freeze(&project);
    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        output.status.success(),
        "doctor failed on a correctly provisioned project:\n{stdout}{}",
        stderr_of(&output)
    );
    assert!(
        stdout.contains("0 failed"),
        "unexpected doctor summary: {stdout}"
    );
    assert!(
        !stdout.contains("signing-ed25519-public.jwk.json"),
        "doctor reported the public key that sits beside the private one: {stdout}"
    );
}

#[test]
fn doctor_names_every_artifact_whose_mode_the_runtime_refuses() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    freeze(&project);

    // One artifact per rule the runtimes enforce, each widened past it. A
    // `chmod -R` an operator runs over a project produces exactly this state.
    let refused = [
        "runtime.yaml",
        "bundle/evidence.yaml",
        "secrets",
        "secrets/audit-hmac-key",
        "audit/evidence.jsonl",
        "mint/secrets/signing-ed25519-private-jwk",
        "caller/signing-ed25519-private-jwk",
    ];
    fs::write(project.join("audit/evidence.jsonl"), "").expect("stage an audit chain");
    for path in refused {
        set_mode(&project.join(path), 0o755);
    }

    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        !output.status.success(),
        "doctor passed a project the runtime would refuse:\n{stdout}"
    );
    for path in refused {
        assert!(
            stdout.contains(path),
            "doctor did not report {path}:\n{stdout}"
        );
    }
}

#[test]
fn doctor_reports_a_secret_the_bundle_references_and_the_project_does_not_hold() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);

    // Every secret but the source bearer token, which the README tells an
    // adopter to obtain from the source system rather than generate. Forgetting
    // it is the ordinary way a project reaches this state.
    freeze(&project);
    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        !output.status.success(),
        "doctor passed a project missing a secret the bundle references:\n{stdout}"
    );
    assert!(
        stdout.contains("secrets/source-bearer-token"),
        "doctor did not name the missing secret:\n{stdout}"
    );
}

#[test]
fn doctor_json_puts_one_document_on_stdout_and_the_report_on_stderr() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);

    freeze(&project);
    let output = doctor(&project, &["--json"]);
    unfreeze(&project);

    assert!(
        output.status.success(),
        "doctor --json failed on a correctly provisioned project:\n{}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    let lines: Vec<&str> = stdout.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "stdout must carry exactly one JSON document: {stdout}"
    );
    let report: serde_json::Value = serde_json::from_str(lines[0]).expect("parse the JSON report");
    assert_eq!(report["passed"], serde_json::Value::Bool(true));
    let checks = report["checks"].as_array().expect("checks array");
    assert!(
        checks.iter().all(|check| check["passed"] == true),
        "a check failed in the JSON report: {stdout}"
    );
    assert!(
        stderr_of(&output).contains("0 failed"),
        "the human report did not reach stderr in JSON mode"
    );
}

/// Assemble the smallest filesystem fixture that names every kind of artifact
/// doctor checks, then generate the private material through the public CLI.
fn provision(project: &Path) {
    fs::create_dir_all(project.join("bundle")).expect("bundle directory");
    fs::create_dir_all(project.join("audit")).expect("audit directory");
    fs::create_dir_all(project.join("mint")).expect("mint directory");
    fs::write(
        project.join("runtime.yaml"),
        "bundleDirectory: bundle\nsecretProviders:\n  file:\n    root: secrets\nauditStorage:\n  path: audit/evidence.jsonl\n",
    )
    .expect("runtime fixture");
    fs::write(
        project.join("bundle/evidence.yaml"),
        "signing: secret:file/signing-ed25519-private-jwk\naudit: secret:file/audit-hmac-key\nsubjectBinding: secret:file/subject-binding-hmac-key\nsourceToken: secret:file/source-bearer-token\n",
    )
    .expect("bundle fixture");
    fs::write(
        project.join("mint/mint.yaml"),
        "signing:\n  activeKeyFile: secrets/signing-ed25519-private-jwk\n",
    )
    .expect("Mint fixture");

    let secrets = project.join("secrets");
    run_ok(&[
        "keygen",
        "signing",
        "--out-dir",
        secrets.to_str().expect("secret root"),
        "--kid",
        SIGNING_KID,
    ]);
    for name in SECRET_FILES {
        let out = secrets.join(name);
        run_ok(&["keygen", "secret", "--out", out.to_str().expect("secret")]);
    }

    run_ok(&[
        "keygen",
        "signing",
        "--out-dir",
        project
            .join("mint/secrets")
            .to_str()
            .expect("mint secret root"),
        "--kid",
        MINT_KID,
    ]);
    run_ok(&[
        "keygen",
        "signing",
        "--out-dir",
        project.join("caller").to_str().expect("caller secret root"),
        "--kid",
        CALLER_KID,
    ]);
}

/// The one secret the scaffolded source needs and `provision` leaves out, so a
/// test can choose whether the project is complete.
fn provision_bearer_token(project: &Path) {
    let out = project.join("secrets/source-bearer-token");
    run_ok(&["keygen", "token", "--out", out.to_str().expect("token")]);
}

fn doctor(project: &Path, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "doctor",
        "--project",
        project.to_str().expect("project path"),
    ];
    arguments.extend_from_slice(extra);
    evidencectl(&arguments)
}

fn run_ok(arguments: &[&str]) {
    let output = evidencectl(arguments);
    assert!(
        output.status.success(),
        "evidencectl {} failed: {}",
        arguments[0],
        stderr_of(&output)
    );
}

fn evidencectl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("running evidencectl")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf8 stdout")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf8 stderr")
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("artifact metadata")
        .permissions()
        .mode()
        & 0o7777
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("setting a mode");
}

/// The documented freeze: no write bits anywhere in the bundle, and a read-only
/// runtime file. Evidence refuses a deployment input it could write.
fn freeze(project: &Path) {
    set_tree_mode(&project.join("bundle"), 0o555, 0o444);
    set_mode(&project.join("runtime.yaml"), 0o444);
}

/// Restore write permissions so the temporary directory can be removed.
fn unfreeze(project: &Path) {
    set_tree_mode(&project.join("bundle"), 0o755, 0o644);
    set_mode(&project.join("runtime.yaml"), 0o644);
    set_mode(&project.join("secrets"), 0o700);
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
    let metadata = fs::symlink_metadata(path).expect("tree entry");
    if metadata.is_dir() {
        set_mode(path, 0o755);
        for entry in fs::read_dir(path).expect("reading a directory") {
            set_tree_mode(
                &entry.expect("tree entry").path(),
                directory_mode,
                file_mode,
            );
        }
        set_mode(path, directory_mode);
    } else {
        set_mode(path, file_mode);
    }
}
