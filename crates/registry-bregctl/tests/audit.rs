// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::path::Path;

use serde_json::Value;

const PATH_VALUE_CANARY: &str = "audit-runtime-path-value-canary";
const OUTPUT_VALUE_CANARY: &str = "audit-output-path-value-canary";
const BOUNDARY_VALUE_CANARY: &str = "audit-boundary-value-canary";

fn run<I, T>(arguments: I) -> (u8, String, String)
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(arguments, &mut stdout, &mut stderr);
    (
        if status == std::process::ExitCode::SUCCESS {
            0
        } else {
            1
        },
        String::from_utf8(stdout).expect("stdout is UTF-8"),
        String::from_utf8(stderr).expect("stderr is UTF-8"),
    )
}

fn assert_value_free_diagnostic(stdout: &str, stderr: &str, code: &str, path: &str) -> Value {
    assert!(stderr.is_empty());
    assert!(!stdout.contains(PATH_VALUE_CANARY));
    assert!(!stdout.contains(OUTPUT_VALUE_CANARY));
    assert!(!stdout.contains(BOUNDARY_VALUE_CANARY));
    let report: Value = serde_json::from_str(stdout).expect("failure is JSON");
    assert_eq!(report["diagnostics"][0]["code"], code);
    assert_eq!(report["diagnostics"][0]["path"], path);
    assert_eq!(report["diagnostics"][0]["artifact"], "audit_journal");
    assert_eq!(
        report["diagnostics"][0]["suggestedAction"],
        "verify_audit_journal"
    );
    report
}

fn assert_value_free_refusal(stdout: &str, stderr: &str) {
    assert_value_free_diagnostic(stdout, stderr, "audit.operation.refused", "audit");
}

#[test]
fn audit_commands_share_one_value_free_refusal() {
    let relative = Path::new(PATH_VALUE_CANARY);
    let relative_output = Path::new(OUTPUT_VALUE_CANARY);
    let cases = [
        vec![
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("audit"),
            OsStr::new("verify"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
        ],
        vec![
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("audit"),
            OsStr::new("export"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
            OsStr::new("--output"),
            relative_output.as_os_str(),
        ],
        vec![
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("audit"),
            OsStr::new("prune"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
            OsStr::new("--before"),
            OsStr::new("2024-03-01T00:00:00Z"),
        ],
        vec![
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("audit"),
            OsStr::new("prune"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
            OsStr::new("--before"),
            OsStr::new(BOUNDARY_VALUE_CANARY),
            OsStr::new("--dry-run"),
        ],
    ];

    for arguments in cases {
        let (status, stdout, stderr) = run(arguments);
        assert_eq!(status, 1);
        assert_value_free_refusal(&stdout, &stderr);
    }
}

#[test]
fn a_boundary_that_is_not_one_rfc_3339_instant_is_refused_before_any_dependency() {
    let (status, stdout, stderr) = run([
        "bregctl",
        "--format",
        "json",
        "audit",
        "prune",
        "--runtime-config",
        "/registry/audit-runtime-that-does-not-exist.yaml",
        "--before",
        BOUNDARY_VALUE_CANARY,
    ]);

    assert_eq!(status, 1);
    assert_value_free_refusal(&stdout, &stderr);
}

#[test]
fn export_refuses_a_destination_that_already_holds_a_file() {
    let root = std::env::temp_dir().join(format!("bregctl-audit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).expect("test directory is created");
    let output = root.join("audit.jsonl");
    std::fs::write(&output, b"occupied\n").expect("destination writes");

    let (status, stdout, stderr) = run([
        OsStr::new("bregctl"),
        OsStr::new("--format"),
        OsStr::new("json"),
        OsStr::new("audit"),
        OsStr::new("export"),
        OsStr::new("--runtime-config"),
        OsStr::new("/registry/audit-runtime-that-does-not-exist.yaml"),
        OsStr::new("--output"),
        output.as_os_str(),
    ]);

    assert_eq!(status, 1);
    assert_value_free_diagnostic(&stdout, &stderr, "audit.output.exists", "output");
    assert!(!stdout.contains(&display(&output)));
    assert_eq!(
        std::fs::read(&output).expect("destination is readable"),
        b"occupied\n"
    );

    std::fs::remove_dir_all(&root).expect("test directory is removed");
}

#[cfg(unix)]
#[test]
fn export_reports_a_symbolic_link_ancestor_by_its_own_code() {
    use std::os::unix::fs::symlink;

    let root = std::env::temp_dir().join(format!("bregctl-audit-symlink-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).expect("test directory is created");
    let root = root.canonicalize().expect("test directory canonicalizes");
    let real = root.join("real-parent");
    let linked = root.join("linked-parent");
    std::fs::create_dir(&real).expect("real parent creates");
    symlink(&real, &linked).expect("symlink parent creates");
    let output = linked.join("audit.jsonl");

    let (status, stdout, stderr) = run([
        OsStr::new("bregctl"),
        OsStr::new("--format"),
        OsStr::new("json"),
        OsStr::new("audit"),
        OsStr::new("export"),
        OsStr::new("--runtime-config"),
        OsStr::new("/registry/audit-runtime-that-does-not-exist.yaml"),
        OsStr::new("--output"),
        output.as_os_str(),
    ]);

    assert_eq!(status, 1);
    let report = assert_value_free_diagnostic(&stdout, &stderr, "audit.output.invalid", "output");
    assert!(report["diagnostics"][0]["message"]
        .as_str()
        .expect("message is a string")
        .contains("output"));
    assert!(!real.join("audit.jsonl").exists());

    std::fs::remove_dir_all(&root).expect("test directory is removed");
}

#[test]
fn audit_help_describes_the_bounded_operator_contract() {
    let (status, stdout, stderr) = run(["bregctl", "audit", "--help"]);
    assert_eq!(status, 0);
    assert!(stderr.is_empty());
    for subcommand in ["verify", "export", "prune"] {
        assert!(stdout
            .lines()
            .any(|line| line.trim_start().starts_with(subcommand)));
    }

    let (status, stdout, stderr) = run(["bregctl", "audit", "verify", "--help"]);
    assert_eq!(status, 0);
    assert!(stderr.is_empty());
    assert!(stdout.contains("--runtime-config <ABSOLUTE_FILE>"));

    let (status, stdout, stderr) = run(["bregctl", "audit", "export", "--help"]);
    assert_eq!(status, 0);
    assert!(stderr.is_empty());
    assert!(stdout.contains("--runtime-config <ABSOLUTE_FILE>"));
    assert!(stdout.contains("--output <ABSOLUTE_FILE>"));

    let (status, stdout, stderr) = run(["bregctl", "audit", "prune", "--help"]);
    assert_eq!(status, 0);
    assert!(stderr.is_empty());
    assert!(stdout.contains("--runtime-config <ABSOLUTE_FILE>"));
    assert!(stdout.contains("--before <RFC3339>"));
    assert!(stdout.contains("--dry-run"));
}

fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
