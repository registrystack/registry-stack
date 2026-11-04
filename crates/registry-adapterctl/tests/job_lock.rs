// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `adapterctl job lock`: the digest pins of a job's
//! mapping script (and, on request, its pack) are rewritten in place from the
//! bytes of the files beside the job, and a refusal leaves the job document
//! byte for byte as it was.

use serde_json::{json, Value};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const STALE: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const SHIPPED_MAPPING_PIN: &str =
    "sha256:2c7fc6f8827a68158686d4e22180c316232f1516a7ca72a22427afcd8b3f4bdb";
const SHIPPED_PACK_PIN: &str =
    "sha256:cb1c31044611e3f23464291f6dd2697b00be427da0b9523d0b717fe776e5d667";

fn products() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter")
}

fn copy_tree(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A copy of the Kobo job example and of the Kobo pack it pins.
fn workspace() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    copy_tree(&products().join("examples/kobotoolbox-job"), root.path());
    std::fs::create_dir_all(root.path().join("pack")).unwrap();
    copy_tree(
        &products().join("packs/kobotoolbox"),
        &root.path().join("pack"),
    );
    root
}

fn path(root: &tempfile::TempDir, name: &str) -> String {
    root.path().join(name).to_str().unwrap().to_owned()
}

fn run_json(arguments: &[&str]) -> (ExitCode, Value) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut all = vec![
        OsString::from("adapterctl"),
        OsString::from("--format=json"),
    ];
    all.extend(arguments.iter().map(OsString::from));
    let exit = registry_adapterctl::main_entry_from(all, &mut stdout, &mut stderr);
    let report = serde_json::from_slice(&stdout).unwrap_or(Value::Null);
    assert_eq!(
        exit == ExitCode::SUCCESS,
        report["ok"] == json!(true),
        "ok must track the exit code: {report}"
    );
    (exit, report)
}

fn codes(report: &Value) -> Vec<String> {
    report["diagnostics"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|d| d["code"].as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn stale_job(root: &tempfile::TempDir) -> String {
    let job = path(root, "job.yaml");
    let text = std::fs::read_to_string(&job).unwrap();
    assert!(text.contains(SHIPPED_MAPPING_PIN));
    std::fs::write(&job, text.replace(SHIPPED_MAPPING_PIN, STALE)).unwrap();
    job
}

fn job_check(root: &tempfile::TempDir, extra: &[&str]) -> (ExitCode, Value) {
    std::env::set_var("KOBO_USERNAME", "check-contracts");
    std::env::set_var("KOBO_PASSWORD", "check-contracts");
    let pack = path(root, "pack/pack.yaml");
    let job = path(root, "job.yaml");
    let runtime = path(root, "job-runtime.example.yaml");
    let profile = path(root, "profile.yaml");
    let project = path(root, "project.yaml");
    let mut arguments = vec![
        "job",
        "check",
        pack.as_str(),
        job.as_str(),
        "--runtime",
        runtime.as_str(),
        "--profile",
        profile.as_str(),
        "--project",
        project.as_str(),
    ];
    arguments.extend_from_slice(extra);
    run_json(&arguments)
}

#[test]
fn lock_rewrites_a_stale_mapping_pin_and_the_job_then_checks_clean() {
    let root = workspace();
    let job = stale_job(&root);
    let before = std::fs::read_to_string(&job).unwrap();
    let (exit, report) = run_json(&["job", "lock", &job]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["command"], "job lock");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["mapping"], "updated");
    assert!(report.get("pack").is_none(), "{report}");
    assert_eq!(report["filesChecked"], 2, "{report}");
    // Only the digest value changed: comments, order and every other byte stay.
    assert_eq!(
        std::fs::read_to_string(&job).unwrap(),
        before.replace(STALE, SHIPPED_MAPPING_PIN)
    );
    let (exit, report) = job_check(&root, &["--deny-warnings"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
}

#[cfg(unix)]
#[test]
fn lock_keeps_the_file_mode_of_the_job() {
    use std::os::unix::fs::PermissionsExt;
    let root = workspace();
    let job = stale_job(&root);
    std::fs::set_permissions(&job, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (exit, report) = run_json(&["job", "lock", &job]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["mapping"], "updated");
    let mode = std::fs::metadata(&job).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn lock_of_a_current_job_changes_nothing() {
    let root = workspace();
    let job = path(&root, "job.yaml");
    let before = std::fs::read(&job).unwrap();
    let (exit, report) = run_json(&["job", "lock", &job]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["mapping"], "unchanged");
    assert_eq!(std::fs::read(&job).unwrap(), before);
    assert!(
        std::fs::read_dir(root.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")),
        "no temporary file is left behind"
    );
}

#[test]
fn lock_keeps_a_trailing_comment_on_the_digest_line() {
    let root = workspace();
    let job = stale_job(&root);
    let text = std::fs::read_to_string(&job).unwrap();
    std::fs::write(&job, text.replace(STALE, &format!("{STALE} # generated"))).unwrap();
    let (exit, report) = run_json(&["job", "lock", &job]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let text = std::fs::read_to_string(&job).unwrap();
    assert!(
        text.contains(&format!("digest: {SHIPPED_MAPPING_PIN} # generated")),
        "{text}"
    );
}

#[test]
fn lock_with_a_pack_also_repins_the_pack_and_without_it_leaves_it() {
    let root = workspace();
    let job = path(&root, "job.yaml");
    let text = std::fs::read_to_string(&job).unwrap();
    std::fs::write(&job, text.replace(SHIPPED_PACK_PIN, STALE)).unwrap();
    let (exit, report) = run_json(&["job", "lock", &job]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["mapping"], "unchanged");
    assert!(std::fs::read_to_string(&job).unwrap().contains(STALE));

    let pack = path(&root, "pack/pack.yaml");
    let (exit, report) = run_json(&["job", "lock", &job, "--pack", &pack]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["pack"], "updated");
    assert_eq!(report["mapping"], "unchanged");
    assert_eq!(std::fs::read_to_string(&job).unwrap(), text);
}

#[test]
fn lock_refuses_a_pack_whose_identity_differs_from_the_job_pin() {
    let root = workspace();
    let job = path(&root, "job.yaml");
    let before = std::fs::read(&job).unwrap();
    let other = products().join("packs/dhis2-tracker/pack.yaml");
    let (exit, report) = run_json(&["job", "lock", &job, "--pack", other.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert!(
        codes(&report).contains(&"adapterctl.job-lock-pack-mismatch".to_owned()),
        "{report}"
    );
    assert_eq!(std::fs::read(&job).unwrap(), before);
}

#[test]
fn lock_of_a_job_with_no_job_owned_pin_reports_no_mapping() {
    let root = workspace();
    let job = path(&root, "job.coordinator.yaml");
    let before = std::fs::read(&job).unwrap();
    let (exit, report) = run_json(&["job", "lock", &job]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(report.get("mapping").is_none(), "{report}");
    assert_eq!(std::fs::read(&job).unwrap(), before);
}

#[test]
fn lock_refuses_a_missing_pinned_file_and_leaves_the_job_untouched() {
    let root = workspace();
    let job = stale_job(&root);
    let before = std::fs::read(&job).unwrap();
    std::fs::remove_file(root.path().join("mappings/register-household.rhai")).unwrap();
    let (exit, report) = run_json(&["job", "lock", &job]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert!(
        codes(&report).contains(&"adapterctl.job-lock-pinned-file-missing".to_owned()),
        "{report}"
    );
    assert_eq!(std::fs::read(&job).unwrap(), before);
}

#[test]
fn lock_refuses_a_mapping_path_that_leaves_the_job_directory() {
    let root = workspace();
    let job = stale_job(&root);
    let text = std::fs::read_to_string(&job).unwrap();
    std::fs::write(
        &job,
        text.replace(
            "mappings/register-household.rhai",
            "../register-household.rhai",
        ),
    )
    .unwrap();
    let before = std::fs::read(&job).unwrap();
    let (exit, report) = run_json(&["job", "lock", &job]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert!(
        codes(&report).contains(&"adapterctl.job-lock-path-invalid".to_owned()),
        "{report}"
    );
    assert_eq!(std::fs::read(&job).unwrap(), before);
}

#[test]
fn lock_refuses_an_invalid_job_and_leaves_it_untouched() {
    let root = workspace();
    let job = stale_job(&root);
    let text = std::fs::read_to_string(&job).unwrap();
    std::fs::write(&job, text.replace("kind: AdapterJob", "kind: NotAJob")).unwrap();
    let before = std::fs::read(&job).unwrap();
    let (exit, report) = run_json(&["job", "lock", &job]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert!(!codes(&report).is_empty(), "{report}");
    assert_eq!(std::fs::read(&job).unwrap(), before);
}

#[test]
fn lock_refuses_a_pin_it_cannot_rewrite_in_place() {
    let root = workspace();
    let job = stale_job(&root);
    let text = std::fs::read_to_string(&job).unwrap();
    std::fs::write(&job, text.replace(STALE, &format!("\"{STALE}\""))).unwrap();
    let before = std::fs::read(&job).unwrap();
    let (exit, report) = run_json(&["job", "lock", &job]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert!(
        codes(&report).contains(&"adapterctl.job-lock-layout".to_owned()),
        "{report}"
    );
    assert_eq!(std::fs::read(&job).unwrap(), before);
}

#[test]
fn lock_of_a_missing_job_is_an_operational_failure() {
    let root = workspace();
    let (exit, report) = run_json(&["job", "lock", &path(&root, "none.yaml")]);
    assert_eq!(exit, ExitCode::from(3), "{report}");
}
