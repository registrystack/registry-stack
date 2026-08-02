#![cfg(unix)]

//! Full adopter path, end to end.
//!
//! Drives the README-documented flow with the real `evidencectl` and
//! `evidence` binaries and zero manual edits: scaffold a project, provision
//! key material, freeze the deployment inputs the way `evidence` requires on
//! unix, then run every bundle fixture through `evidencectl fixtures run` in
//! both its human and `--json` reporting modes. Nothing in this file prints
//! key material.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::OnceLock,
};

const SIGNING_KID: &str = "scaffold-signing-key-1";
const SECRET_FILES: [&str; 2] = ["audit-hmac-key", "subject-binding-hmac-key"];

#[test]
fn the_documented_adopter_flow_passes_check_and_the_scaffolded_fixture() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");

    let new_output = evidencectl(&["new", project.to_str().expect("project path")]);
    assert!(
        new_output.status.success(),
        "evidencectl new failed: {}",
        stderr_of(&new_output)
    );

    let bin = evidence_binary();

    // Before key material exists and the project is frozen, the same driver
    // must fail. This proves the later pass is not vacuous.
    let premature = evidencectl(&[
        "fixtures",
        "run",
        "--project",
        project.to_str().expect("project path"),
        "--evidence-bin",
        bin.to_str().expect("evidence binary path"),
    ]);
    assert!(
        !premature.status.success(),
        "fixtures run unexpectedly succeeded before key material and freezing were in place"
    );

    let secrets = project.join("secrets");
    let signing_output = evidencectl(&[
        "keygen",
        "signing",
        "--out-dir",
        secrets.to_str().expect("secrets dir"),
        "--kid",
        SIGNING_KID,
    ]);
    assert!(
        signing_output.status.success(),
        "evidencectl keygen signing failed: {}",
        stderr_of(&signing_output)
    );

    for name in SECRET_FILES {
        let out = secrets.join(name);
        let secret_output = evidencectl(&[
            "keygen",
            "secret",
            "--out",
            out.to_str().expect("secret path"),
        ]);
        assert!(
            secret_output.status.success(),
            "evidencectl keygen secret failed for {name}: {}",
            stderr_of(&secret_output)
        );
    }

    freeze(&project);
    let run_output = evidencectl(&[
        "fixtures",
        "run",
        "--project",
        project.to_str().expect("project path"),
        "--evidence-bin",
        bin.to_str().expect("evidence binary path"),
    ]);
    let json_output = evidencectl(&[
        "fixtures",
        "run",
        "--project",
        project.to_str().expect("project path"),
        "--evidence-bin",
        bin.to_str().expect("evidence binary path"),
        "--json",
    ]);
    unfreeze(&project);

    assert!(
        run_output.status.success(),
        "evidencectl fixtures run failed: {}",
        stderr_of(&run_output)
    );
    let stdout = stdout_of(&run_output);
    assert!(
        stdout.contains("2 passed, 0 failed"),
        "unexpected fixtures run summary: {stdout}"
    );

    assert!(
        json_output.status.success(),
        "evidencectl fixtures run --json failed: {}",
        stderr_of(&json_output)
    );
    let json_stdout = stdout_of(&json_output);
    let json_lines: Vec<&str> = json_stdout
        .lines()
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(
        json_lines.len(),
        1,
        "stdout must carry exactly one JSON document: {json_stdout}"
    );
    let report: serde_json::Value = serde_json::from_str(json_lines[0]).expect("parse JSON report");
    assert_eq!(report["passed"], serde_json::Value::Bool(true));
    assert_eq!(report["check"]["passed"], serde_json::Value::Bool(true));
    let fixtures = report["fixtures"].as_array().expect("fixtures array");
    assert_eq!(fixtures.len(), 1);
    assert_eq!(fixtures[0]["path"], "fixtures/cases.yaml");
    assert_eq!(fixtures[0]["passed"], serde_json::Value::Bool(true));
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

/// Locate the `evidence` binary this flow drives.
///
/// `EVIDENCE_BIN` wins when the caller already built one. Otherwise the
/// binary is built once from this workspace and reused for the test.
fn evidence_binary() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        if let Some(path) = std::env::var_os("EVIDENCE_BIN") {
            return PathBuf::from(path);
        }
        let build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(workspace_root())
            .args([
                "build",
                "--locked",
                "-p",
                "registry-evidence",
                "--bin",
                "evidence",
                "--profile",
                &current_test_profile(),
                "--message-format",
                "json-render-diagnostics",
            ])
            .output()
            .expect("building the evidence binary");
        assert!(
            build.status.success(),
            "building the evidence binary failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );
        String::from_utf8_lossy(&build.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|message| {
                message.get("reason").and_then(serde_json::Value::as_str)
                    == Some("compiler-artifact")
            })
            .filter_map(|message| {
                message
                    .get("executable")
                    .and_then(serde_json::Value::as_str)
                    .map(PathBuf::from)
            })
            .find(|executable| {
                executable
                    .file_name()
                    .is_some_and(|name| name == "evidence")
            })
            .expect("the evidence binary path")
    })
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

/// The profile this test binary was itself built with, read from its own
/// path (`target/<profile>/deps/<binary>`) rather than assumed. A nested
/// `cargo build` passes this back with `--profile` so it reuses the artifacts
/// the outer build already produced (e.g. CI's `--profile ci`) instead of
/// triggering a second full build under the default `dev` profile.
fn current_test_profile() -> String {
    let exe = std::env::current_exe().expect("current test executable path");
    let deps_dir = exe
        .parent()
        .expect("test executable has a parent directory");
    let profile_dir = deps_dir
        .parent()
        .expect("the deps directory has a parent directory");
    let profile = profile_dir
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("the profile directory name is valid UTF-8");
    if profile == "debug" {
        "dev".to_owned()
    } else {
        profile.to_owned()
    }
}

/// The documented freeze: no write bits anywhere in the bundle, and a
/// read-only runtime file. Evidence refuses a deployment input it could write.
fn freeze(project: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    set_tree_mode(&project.join("bundle"), 0o555, 0o444);
    fs::set_permissions(
        project.join("runtime.yaml"),
        fs::Permissions::from_mode(0o444),
    )
    .expect("freezing the runtime file");
}

/// Restore write permissions so the temporary directory can be removed.
fn unfreeze(project: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    set_tree_mode(&project.join("bundle"), 0o755, 0o644);
    fs::set_permissions(
        project.join("runtime.yaml"),
        fs::Permissions::from_mode(0o644),
    )
    .expect("unfreezing the runtime file");
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path).expect("tree entry");
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("opening a directory");
        for entry in fs::read_dir(path).expect("reading a directory") {
            set_tree_mode(
                &entry.expect("tree entry").path(),
                directory_mode,
                file_mode,
            );
        }
        fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
            .expect("setting a directory mode");
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
            .expect("setting a file mode");
    }
}
