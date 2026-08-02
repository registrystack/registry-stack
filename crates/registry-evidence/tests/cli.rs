#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output},
};

#[test]
fn actual_binary_checks_and_evaluates_an_immutable_project() {
    let staged = tempfile::tempdir().expect("temporary deployment");
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence",
    );
    copy_tree(&project.join("bundle"), &staged.path().join("bundle"));
    let secret_root = staged.path().join("secrets");
    fs::create_dir(&secret_root).expect("create private secret root");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("set private secret-root mode");

    let runtime = fs::read_to_string(project.join("runtime.yaml")).expect("read runtime template");
    let bundle_path = staged.path().join("bundle");
    let bundle_directory = bundle_path.to_str().expect("temporary path is UTF-8");
    let audit_path = staged.path().join("audit.jsonl");
    let runtime = runtime
        .replacen("/etc/registry-evidence/bundle", bundle_directory, 1)
        .replacen(
            "/run/secrets/registry-evidence",
            secret_root.to_str().expect("temporary path is UTF-8"),
            1,
        )
        .replacen(
            "/var/lib/registry-evidence/audit/evidence.jsonl",
            audit_path.to_str().expect("temporary path is UTF-8"),
            1,
        );
    let runtime_path = staged.path().join("runtime.yaml");
    fs::write(&runtime_path, runtime).expect("stage runtime");
    set_tree_mode(&bundle_path, 0o555, 0o444);
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
        .expect("set immutable runtime mode");

    let check = invoke(&runtime_path, &["check"]);
    let evaluate = invoke(
        &runtime_path,
        &["evaluate", "--fixture", "fixtures/adult-status-cases.yaml"],
    );

    set_tree_mode(&bundle_path, 0o755, 0o644);
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o644))
        .expect("restore runtime mode");
    assert_success(
        &check,
        "Evidence deployment ",
        " passed check (3 requirements)\n",
    );
    assert_success(
        &evaluate,
        "Evidence fixture passed (",
        " evaluated cases)\n",
    );
}

fn invoke(runtime: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidence"))
        .arg("--runtime")
        .arg(runtime)
        .args(arguments)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .output()
        .expect("evidence binary starts")
}

fn assert_success(output: &Output, prefix: &str, suffix: &str) {
    assert!(output.status.success(), "evidence command failed");
    assert!(
        output.stderr.is_empty(),
        "evidence command wrote diagnostics"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.starts_with(prefix) && stdout.ends_with(suffix),
        "evidence command output shape changed"
    );
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create staged directory");
    for entry in fs::read_dir(source).expect("read source tree") {
        let entry = entry.expect("source entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("source entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy staged artifact");
        }
    }
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
    let metadata = fs::symlink_metadata(path).expect("staged path metadata");
    if metadata.is_dir() {
        for entry in fs::read_dir(path).expect("read staged tree") {
            set_tree_mode(
                &entry.expect("staged entry").path(),
                directory_mode,
                file_mode,
            );
        }
        fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
            .expect("set staged directory mode");
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
            .expect("set staged file mode");
    }
}
