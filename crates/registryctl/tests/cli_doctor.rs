use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn registryctl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_registryctl"))
}

fn initialized_project() -> tempfile::TempDir {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    let output = registryctl()
        .args([
            "init",
            project.to_str().expect("UTF-8 path"),
            "--template",
            "http",
        ])
        .output()
        .expect("registryctl init runs");
    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    temporary
}

fn doctor(project: &Path, path: &Path) -> Output {
    registryctl()
        .args([
            "-C",
            project.to_str().expect("UTF-8 path"),
            "doctor",
            "--format",
            "json",
        ])
        .env("PATH", path)
        .env_remove("REGISTRYCTL_ENVIRONMENT")
        .output()
        .expect("registryctl doctor runs")
}

fn report(output: &Output) -> serde_json::Value {
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("doctor emits one JSON document")
}

fn categories(report: &serde_json::Value) -> Vec<&str> {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .map(|check| check["category"].as_str().expect("category string"))
        .collect()
}

fn tree_snapshot(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    fn visit(root: &Path, directory: &Path, entries: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
        for entry in fs::read_dir(directory).expect("project directory reads") {
            let path = entry.expect("directory entry reads").path();
            let relative = path
                .strip_prefix(root)
                .expect("path is below root")
                .to_path_buf();
            let metadata = fs::symlink_metadata(&path).expect("metadata reads");
            if metadata.is_dir() {
                entries.push((relative, None));
                visit(root, &path, entries);
            } else {
                entries.push((relative, Some(fs::read(&path).expect("file reads"))));
            }
        }
    }

    let mut entries = Vec::new();
    visit(root, root, &mut entries);
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

#[cfg(unix)]
fn fake_docker(directory: &Path, script: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    let path = directory.join("docker");
    fs::write(&path, script).expect("fake Docker writes");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
        .expect("fake Docker becomes executable");
}

#[test]
fn doctor_is_read_only_and_reports_missing_docker_and_release_lock() {
    let temporary = initialized_project();
    let project = temporary.path().join("project");
    let empty_path = temporary.path().join("empty-path");
    fs::create_dir(&empty_path).expect("empty PATH directory writes");
    let before = tree_snapshot(&project);

    let document = report(&doctor(&project, &empty_path));

    assert_eq!(document["schema_version"], "registryctl.doctor.v1");
    assert_eq!(document["status"], "not_ready");
    assert_eq!(document["environment"], "local");
    assert_eq!(document["profile"], "local");
    let reported = categories(&document);
    assert!(reported.contains(&"release_lock_missing_or_invalid"));
    assert!(reported.contains(&"docker_missing"));
    assert_eq!(
        tree_snapshot(&project),
        before,
        "doctor mutated the project"
    );
}

#[cfg(unix)]
#[test]
fn doctor_distinguishes_an_unavailable_daemon() {
    let temporary = initialized_project();
    let project = temporary.path().join("project");
    let bin = temporary.path().join("bin");
    fs::create_dir(&bin).expect("fake bin writes");
    fake_docker(
        &bin,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then exit 0; fi\n\
         if [ \"$1\" = \"info\" ]; then exit 1; fi\n\
         if [ \"$1\" = \"compose\" ]; then echo 2.35.0; exit 0; fi\n\
         exit 1\n",
    );

    let document = report(&doctor(&project, &bin));

    let reported = categories(&document);
    assert!(!reported.contains(&"docker_missing"));
    assert!(reported.contains(&"docker_daemon_unavailable"));
}

#[cfg(unix)]
#[test]
fn doctor_rejects_compose_older_than_2_35_0() {
    let temporary = initialized_project();
    let project = temporary.path().join("project");
    let bin = temporary.path().join("bin");
    fs::create_dir(&bin).expect("fake bin writes");
    fake_docker(
        &bin,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then exit 0; fi\n\
         if [ \"$1\" = \"info\" ]; then exit 0; fi\n\
         if [ \"$1\" = \"compose\" ]; then echo 2.34.9; exit 0; fi\n\
         exit 1\n",
    );

    let document = report(&doctor(&project, &bin));

    let reported = categories(&document);
    assert!(!reported.contains(&"docker_missing"));
    assert!(!reported.contains(&"docker_daemon_unavailable"));
    assert!(reported.contains(&"compose_version_unsupported"));
}
