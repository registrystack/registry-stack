// SPDX-License-Identifier: Apache-2.0
//! Every `caseworkctl --format json` report format registers a committed
//! output of the command that writes it as its example. This test runs each
//! command and fails when its output differs from the committed example.
//!
//! The commands run from the repository root with relative paths, so a report
//! names no checkout path; `init` runs in a fresh directory. `package` reports
//! the project's absolute path, so the checkout's path is removed from every
//! output before the comparison. A command whose successful report needs a
//! database, an issuer, a BReg project, or a running development session is
//! given an argument it refuses before it reaches any of them, so its example
//! is that refusal.
//!
//! Regenerate the examples after an intentional report change:
//!
//! ```sh
//! CASEWORKCTL_WRITE_REPORT_EXAMPLES=1 cargo test -p registry-caseworkctl --test report_examples
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

const STANDALONE: &str = "products/casework/examples/standalone-decision";
const MULTI_STAGE: &str = "products/casework/examples/multi-stage-routing-clocks";
const SIMULATION: &str =
    "products/casework/examples/multi-stage-routing-clocks/simulations/friday-review.yaml";
const ATTEMPT: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root resolves")
}

/// The report format each example registers, and the arguments of the
/// command that writes it.
fn examples() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "apply-report",
            vec!["apply", "--runtime-config", "runtime.yaml"],
        ),
        (
            "attempt-settlement-report",
            vec![
                "attempt",
                "settle",
                "no-such-project",
                "--attempt-id",
                ATTEMPT,
                "--outcome",
                "not-applied",
                "--reason",
                "the source holds no record of the change",
                "--decided-by",
                "operator",
            ],
        ),
        (
            "attempt-uncertain-marking-report",
            vec![
                "attempt",
                "mark-uncertain",
                "no-such-project",
                "--attempt-id",
                ATTEMPT,
                "--reason",
                "the source did not answer",
                "--decided-by",
                "operator",
            ],
        ),
        ("check-report", vec!["check", STANDALONE]),
        (
            "dev-events-report",
            vec!["dev", "events", "no-such-project"],
        ),
        (
            "dev-grant-report",
            vec![
                "dev",
                "grant",
                "agent",
                "--grant",
                ATTEMPT,
                "--connection",
                "no-such-connection.json",
                "no-such-project",
            ],
        ),
        ("dev-identity-report", vec!["dev", "identity", "reviewer"]),
        ("dev-report", vec!["dev", "start", "no-such-project"]),
        (
            "dev-token-report",
            vec!["dev", "token", "staff", "no-such-project"],
        ),
        (
            "doctor-report",
            vec!["doctor", "--runtime-config", "runtime.yaml"],
        ),
        ("explain-report", vec!["explain", STANDALONE]),
        (
            "init-report",
            vec!["init", "project", "--template", "standalone-decision"],
        ),
        ("lifecycle-report", vec!["lifecycle"]),
        ("package-report", vec!["package", STANDALONE, "--dry-run"]),
        (
            "plan-report",
            vec!["plan", "--runtime-config", "runtime.yaml"],
        ),
        (
            "retention-erase-report",
            vec![
                "retention",
                "erase",
                "no-such-project",
                "--source-id",
                "regional-register",
                "--request-kind",
                "application",
                "--request-id",
                "application-1",
            ],
        ),
        (
            "simulation-report",
            vec!["simulate", MULTI_STAGE, "--simulation", SIMULATION],
        ),
        (
            "source-add-report",
            vec![
                "source",
                "add",
                "no-such-breg-project",
                "--project",
                STANDALONE,
                "--source-id",
                "regional-register",
            ],
        ),
        (
            "status-report",
            vec!["status", "--runtime-config", "runtime.yaml"],
        ),
        ("test-report", vec!["test", STANDALONE]),
        ("usage-report", vec!["--not-a-real-argument"]),
    ]
}

/// Copies the tracked example projects into a temporary directory at the
/// same relative path, leaving out any `.casework` development state a local
/// session wrote beside them, so the commands see only tracked files.
fn stage_examples(repository: &Path, staging: &Path) {
    fn copy(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).expect("the staging directory is created");
        for entry in std::fs::read_dir(from).expect("the example directory reads") {
            let entry = entry.expect("the example entry reads");
            if entry.file_name() == ".casework" {
                continue;
            }
            let target = to.join(entry.file_name());
            if entry.file_type().expect("the entry type reads").is_dir() {
                copy(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).expect("the example file is copied");
            }
        }
    }
    let examples = "products/casework/examples";
    copy(&repository.join(examples), &staging.join(examples));
}

fn output(root: &Path, arguments: &[&str]) -> Vec<u8> {
    let scratch = tempfile::tempdir().expect("temporary directory");
    stage_examples(root, scratch.path());
    let directory = scratch.path();
    let output = Command::new(env!("CARGO_BIN_EXE_caseworkctl"))
        .arg("--format")
        .arg("json")
        .args(arguments)
        .current_dir(directory)
        .output()
        .expect("caseworkctl starts");
    assert!(
        output.stderr.is_empty(),
        "caseworkctl {arguments:?} wrote stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("the report is UTF-8");
    let staged = scratch
        .path()
        .canonicalize()
        .expect("staging path resolves");
    text.replace(&format!("\"{}/", staged.display()), "\"")
        .replace(&format!("\"{}/", scratch.path().display()), "\"")
        .into_bytes()
}

#[test]
fn every_report_format_example_is_the_output_of_its_command() {
    let root = repo_root();
    let directory = root.join("products/casework/examples/formats/reports");
    let write = std::env::var_os("CASEWORKCTL_WRITE_REPORT_EXAMPLES").is_some();
    if write {
        std::fs::create_dir_all(&directory).expect("the examples directory is created");
    }
    let examples = examples();
    assert_eq!(examples.len(), 21);
    let mut stale = Vec::new();
    for (format, arguments) in examples {
        let path = directory.join(format!("{format}.json"));
        let produced = output(&root, &arguments);
        if write {
            std::fs::write(&path, &produced).expect("the example is written");
            continue;
        }
        let committed = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("example {} reads: {error}", path.display()));
        if committed != produced {
            stale.push(format);
        }
    }
    assert!(
        stale.is_empty(),
        "the committed report examples {stale:?} differ from what caseworkctl writes; \
         regenerate them with CASEWORKCTL_WRITE_REPORT_EXAMPLES=1 cargo test -p \
         registry-caseworkctl --test report_examples, and review the difference"
    );
}
