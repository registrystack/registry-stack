//! `evidence-oid4vp serve` as an operator runs it: the binary reaches service
//! startup and reports a startup failure as a named stage with a failure exit
//! status, never as a panic.

use std::{
    path::Path,
    process::{Command, Output},
};

/// The committed minimal deployment, with its secret root moved to an empty
/// directory so the service cannot read its key material.
fn deployment_without_secrets(root: &Path) -> std::path::PathBuf {
    let example = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/oid4vp-runtime/runtime.yaml"),
    )
    .expect("the committed example is readable");
    let secrets = root.join("secrets");
    std::fs::create_dir(&secrets).expect("the empty secret root is created");
    let text = example.replace(
        "root: /run/secrets/evidence-oid4vp",
        &format!("root: {}", secrets.display()),
    );
    assert_ne!(text, example, "the example names its secret root");
    let path = root.join("runtime.yaml");
    std::fs::write(&path, text).expect("the runtime file is written");
    path
}

fn serve(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidence-oid4vp"))
        .arg("serve")
        .arg("--runtime-config")
        .arg(path)
        .env_remove("EVIDENCE_OID4VP_CONFIG")
        .env_remove("EVIDENCE_OID4VP_RUNTIME_CONFIG")
        .env("RUST_LOG", "info")
        .output()
        .expect("the binary runs")
}

#[test]
fn serve_installs_its_stop_handlers_and_reports_a_startup_failure_by_stage() {
    // The reader refuses a path through a symbolic link, and the system
    // temporary directory is one on some hosts.
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory resolves");
    let root = tempfile::tempdir_in(base).expect("a temporary directory");
    let path = deployment_without_secrets(root.path());

    let output = serve(&path);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("panicked"),
        "serve must not panic before startup: {stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "a startup failure exits with the failure status\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("the service could not start"),
        "the failure names the startup stage it reached: {stdout}"
    );
}
