// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `adapterctl fixtures replay`: the offline replay
//! of a project's fixture suites against its compiled contract
//! (`products/adapter/CONCEPT.md` section 13.3).

use serde_json::{json, Value};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The minimal fixture project's directory.
fn minimal_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/minimal")
        .to_path_buf()
}

/// Run one invocation in JSON mode and return its exit code, its report
/// (null when stdout carried no report), and its stderr.
fn run_json(arguments: &[&str]) -> (ExitCode, Value, Vec<u8>) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut all = vec![
        OsString::from("adapterctl"),
        OsString::from("--format=json"),
    ];
    all.extend(arguments.iter().map(OsString::from));
    let exit = registry_adapterctl::main_entry_from(all, &mut stdout, &mut stderr);
    let report = serde_json::from_slice(&stdout).unwrap_or(Value::Null);
    assert_envelope(&stdout, &report, exit);
    (exit, report, stderr)
}

/// Every JSON report opens with `ok`, `command`, and `status` in that
/// order, then names its format; `ok` is true exactly when the process
/// exits zero, and a report that is not ok carries at least one
/// diagnostic naming the next step.
fn assert_envelope(stdout: &[u8], report: &Value, exit: ExitCode) {
    let text = String::from_utf8_lossy(stdout);
    let head = text
        .lines()
        .filter_map(|line| line.strip_prefix("  \""))
        .filter_map(|line| line.split_once('"').map(|(key, _)| key))
        .take(5)
        .collect::<Vec<_>>();
    assert_eq!(
        head,
        ["ok", "command", "status", "apiVersion", "kind"],
        "{text}"
    );
    assert_eq!(
        report["apiVersion"],
        "id.registrystack.org/formats/adapter/ctl-report/v1alpha1"
    );
    assert_eq!(report["kind"], "AdapterCtlReport");
    assert!(report["command"].as_str().is_some_and(|c| !c.is_empty()));
    assert!(report["status"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(report["ok"], json!(exit == ExitCode::SUCCESS), "{text}");
    if exit != ExitCode::SUCCESS {
        let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
        assert!(!diagnostics.is_empty(), "{text}");
        for diagnostic in diagnostics {
            assert!(
                diagnostic["suggestedAction"]
                    .as_str()
                    .is_some_and(|action| !action.is_empty()),
                "{text}"
            );
        }
    }
}

/// Recursively copy a fixture tree (a handful of small files).
fn copy_fs(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_fs(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Copy one fixture tree into a fresh directory, rewrite its fixture file
/// with the given edit, and hand the copy's `project.yaml` back with the
/// directory guard that keeps it alive.
fn edited_tree(edit: fn(&str) -> String) -> (tempfile::TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    let copy = root.path().join("project");
    copy_fs(&minimal_dir(), &copy);
    let fixtures = copy.join("fixtures/records.yaml");
    let text = std::fs::read_to_string(&fixtures).unwrap();
    std::fs::write(&fixtures, edit(&text)).unwrap();
    let project = copy.join("project.yaml").to_str().unwrap().to_owned();
    (root, project)
}

fn edited_tree_with_pack(
    edit_pack: fn(&str) -> String,
    edit_fixture: fn(&str) -> String,
) -> (tempfile::TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    let copy = root.path().join("project");
    copy_fs(&minimal_dir(), &copy);
    let pack = copy.join("pack.yaml");
    let text = std::fs::read_to_string(&pack).unwrap();
    std::fs::write(&pack, edit_pack(&text)).unwrap();
    let fixture = copy.join("fixtures/records.yaml");
    let text = std::fs::read_to_string(&fixture).unwrap();
    std::fs::write(&fixture, edit_fixture(&text)).unwrap();
    let project = copy.join("project.yaml").to_str().unwrap().to_owned();
    (root, project)
}

/// The codes one refusal carries, in report order.
fn codes(report: &Value) -> Vec<&str> {
    report["diagnostics"]
        .as_array()
        .map(|diagnostics| {
            diagnostics
                .iter()
                .map(|diagnostic| diagnostic["code"].as_str().unwrap_or_default())
                .collect()
        })
        .unwrap_or_default()
}

/// The minimal suite replays clean against its compiled contract: both
/// entries, the ordered token and read exchanges, the response expectation
/// with its headers, and the problem expectation by class and code
/// (G-FIXTURES, CONCEPT 13.3). `drive: completed` is emitted only after the
/// actual runtime interpreter consumes every recorded send.
#[test]
fn the_minimal_suite_replays_against_its_compiled_contract() {
    let project = minimal_dir().join("project.yaml");
    let (exit, report, stderr) = run_json(&["fixtures", "replay", project.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["command"], "fixtures replay");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["drive"], "completed");
    assert_eq!(report["fixtures"], json!(1));
    assert_eq!(report["entries"], json!(4));
    assert_eq!(report["upstreamExchanges"], json!(8));
    assert_eq!(report["writesSimulated"], json!(1));
    assert_eq!(report["journalDurability"], "not-run");
    assert!(!report
        .to_string()
        .contains("MUST_NOT_LEAK_FROM_DISCLOSURE_PROBLEM"));
    assert!(!String::from_utf8_lossy(&stderr).contains("MUST_NOT_LEAK_FROM_DISCLOSURE_PROBLEM"));
}

#[test]
fn an_upstream_202_write_stays_a_conflict_when_a_handler_maps_a_valid_record() {
    let (_root, project) = edited_tree_with_pack(
        |text| {
            text.replacen(
                "    steps:\n      - idempotentConsumer:\n",
                "    steps:\n      - onException:\n          exception:\n            - upstream.http\n          steps:\n            - setBody:\n                rhai:\n                  file: scripts/map.rhai\n                  entrypoint: map\n      - idempotentConsumer:\n",
                1,
            )
            .replacen(
                "  eips:\n    - setBody\n",
                "  eips:\n    - onException\n    - setBody\n",
                1,
            )
        },
        |text| {
            text.replacen(
                "        response:\n          status: 201\n          body:\n            id: \"456\"\n    expected:\n      type: response\n      status: 201\n      headers:\n        cache-control: no-store\n        content-type: application/json\n      body:\n        record:\n          national_id: \"456\"\n",
                "        response:\n          status: 202\n          body:\n            id: \"456\"\n    expected:\n      type: problem\n      class: facade.conflict\n      code: cases.boundary\n",
                1,
            )
        },
    );
    let (lock_exit, lock_report, _) = run_json(&["project", "lock", &project]);
    assert_eq!(lock_exit, ExitCode::SUCCESS, "{lock_report}");

    let (exit, report, stderr) = run_json(&["fixtures", "replay", &project]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["drive"], "completed");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
}

/// The human form says the actual engine completed the offline drive.
#[test]
fn a_passed_replay_names_its_limits_in_the_human_lead() {
    let project = minimal_dir().join("project.yaml");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let all = vec![
        OsString::from("adapterctl"),
        OsString::from("fixtures"),
        OsString::from("replay"),
        OsString::from(project.to_str().unwrap()),
    ];
    let exit = registry_adapterctl::main_entry_from(all, &mut stdout, &mut stderr);
    assert_eq!(exit, ExitCode::SUCCESS);
    let human = String::from_utf8_lossy(&stdout);
    assert!(human.contains("Fixture replay completed through the runtime engine"));
    assert!(human.contains("upstream sends were intercepted offline"));
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
}

#[test]
fn an_exact_facade_mismatch_names_the_structural_member() {
    let (_root, project) = edited_tree(|text| {
        text.replacen(
            "        content-type: application/json\n        cache-control: no-store",
            "        content-type: application/json\n        cache-control: public",
            1,
        )
    });
    let (exit, report, _) = run_json(&["fixtures", "replay", &project]);
    assert_eq!(exit, ExitCode::FAILURE, "{report}");
    let diagnostic = report["diagnostics"]
        .as_array()
        .and_then(|diagnostics| {
            diagnostics
                .iter()
                .find(|diagnostic| diagnostic["code"] == "adapterctl.fixtures.facade-mismatch")
        })
        .expect("the exact facade comparison refuses");
    assert_eq!(diagnostic["path"], "/fixtures/0/entries/0/expected/headers");
}

/// A 2xx expectation the compiled operation does not declare refuses only
/// at replay: the check-level body validation passes (the status is 2xx,
/// the body derives), and the compiled contract carries no such response
/// (the success status is the operation's, the error statuses the
/// profile's).
#[test]
fn replay_refuses_a_status_the_compiled_contract_does_not_declare() {
    let (_root, project) = edited_tree(|text| {
        text.replacen(
            "    expected:\n      type: response\n      status: 200",
            "    expected:\n      type: response\n      status: 202",
            1,
        )
    });
    let (exit, report, _) = run_json(&["fixtures", "replay", &project]);
    assert_eq!(exit, ExitCode::FAILURE, "{report}");
    assert_eq!(codes(&report), ["adapterctl.fixtures.contract-status"]);
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/fixtures/0/entries/0/expected"
    );
}

/// A recorded exchange no declared intercept answers refuses at replay:
/// the replay runs the same checks `check` does, so dropping the endpoint
/// intercept strands the read exchange (CONCEPT 10.2, 13.3).
#[test]
fn replay_refuses_an_exchange_no_intercept_answers() {
    let (_root, project) = edited_tree(|text| {
        text.replacen(
            "intercepts:\n  - type: endpoint\n    endpoint: case-api\n",
            "intercepts:\n",
            1,
        )
    });
    let (exit, report, _) = run_json(&["fixtures", "replay", &project]);
    assert_eq!(exit, ExitCode::FAILURE, "{report}");
    assert!(codes(&report).contains(&"adapter.fixture.uncovered-exchange"));
    // All three read exchanges and the write exchange are stranded; the
    // token ones stay answered.
    assert_eq!(
        codes(&report)
            .iter()
            .filter(|code| **code == "adapter.fixture.uncovered-exchange")
            .count(),
        4
    );
}

/// An entry that records no upstream exchange refuses at replay under the
/// fixture code, at its upstream list: the reader accepts an empty list,
/// the replay does not.
#[test]
fn replay_refuses_an_entry_without_upstream_exchanges() {
    let (_root, project) = edited_tree(|text| {
        text.replace(
            "    upstream:\n      - request:\n          endpoint: case-api\n          tokenRequest: true\n          method: POST\n          path: /oauth/token\n        response:\n          status: 200\n          body:\n            access_token: synthetic-replay-token\n            token_type: Bearer\n            expires_in: 300\n      - request:\n          endpoint: case-api\n          method: GET\n          path: /api/cases/case\n        response:\n          status: 503\n          body: null\n",
            "    upstream: []\n",
        )
    });
    let (exit, report, _) = run_json(&["fixtures", "replay", &project]);
    assert_eq!(exit, ExitCode::FAILURE, "{report}");
    assert!(codes(&report).contains(&"adapter.fixture.empty-upstream"));
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/fixtures/0/entries/1/upstream"
    );
}

/// A problem expectation no declared problem answers by class and code
/// refuses at replay, under the fixture problem code at the expectation.
#[test]
fn replay_refuses_an_unresolved_problem_expectation() {
    let (_root, project) = edited_tree(|text| {
        text.replacen("      class: upstream\n", "      class: validation\n", 1)
    });
    let (exit, report, _) = run_json(&["fixtures", "replay", &project]);
    assert_eq!(exit, ExitCode::FAILURE, "{report}");
    assert!(codes(&report).contains(&"adapter.fixture.unknown-problem-code"));
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/fixtures/0/entries/1/expected"
    );
}
