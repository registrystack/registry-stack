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
    assert!(
        human.contains("Fixture files: 1; entries replayed: "),
        "the lead counts what ran: {human}"
    );
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

/// The maintained BReg-backed GovStack example in a fresh directory, as
/// authored (Consultation Retrieve beside Write Create and Update) or with
/// its Consultation section removed so the Write companion read is a
/// `writable-read` binding. Returns the directory guard, the copied
/// `project.yaml`, and the maintained BReg pack.
fn copied_breg_govstack(write_only: bool) -> (tempfile::TempDir, String, String) {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = tempfile::tempdir().unwrap();
    let copy = root.path().join("breg-govstack");
    copy_fs(
        &repository.join("products/adapter/examples/breg-govstack"),
        &copy,
    );
    let project = copy.join("project.yaml");
    if write_only {
        let mut text = std::fs::read_to_string(&project).unwrap();
        let start = text.find("consultation:\n").expect("Consultation block");
        let end = text.find("write:\n").expect("Write block");
        text.replace_range(start..end, "");
        text = text
            .replace(
                "    - recordType: contacts\n      create:",
                "    - recordType: contacts\n      registry: https://registry.example/registries/contacts\n      view: contact-public\n      readDataSchema: contact-public\n      create:",
            )
            .replace(
                "id: contacts-retrieve\n    operation: retrieve",
                "id: contacts-writable-read\n    operation: writable-read",
            )
            .replace(
                "contacts-retrieve: {script:",
                "contacts-writable-read: {script:",
            )
            .replace("operations: [retrieve]", "operations: [writable-read]");
        std::fs::write(&project, text).unwrap();
    }
    let pack = repository.join("products/adapter/packs/breg-records/pack.yaml");
    (
        root,
        project.to_str().unwrap().to_owned(),
        pack.to_str().unwrap().to_owned(),
    )
}

/// A built-in GovStack project that serves Write operations replays
/// through the same composed profile and contract `check` and `compile`
/// use: its Create and Update bindings are operations of that profile,
/// not unknown ones.
#[test]
fn a_read_write_govstack_project_replays_with_the_composed_profile() {
    let (_root, project, pack) = copied_breg_govstack(false);
    let (exit, report, stderr) = run_json(&["fixtures", "replay", &project, "--pack", &pack]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert!(
        !codes(&report).contains(&"adapter.project.unknown-operation"),
        "{report}"
    );
    assert_eq!(report["command"], "fixtures replay");
    assert_eq!(report["status"], "complete");
}

/// A Write-only GovStack project has no authored profile: replay reads no
/// `profile.yaml` for it, exactly as `check` and `compile` do.
#[test]
fn a_write_only_govstack_project_replays_without_a_profile_file() {
    let (_root, project, pack) = copied_breg_govstack(true);
    let (exit, report, stderr) = run_json(&["fixtures", "replay", &project, "--pack", &pack]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(report["status"], "complete");
}

/// One Create entry over the maintained BReg pack: the facade request, the
/// exact native batch it sends (the source key is the replay's fixed claim
/// generation under the request's key scope), the BReg receipt, and the
/// 201 the facade renders with its sealed ETag. `{operation}` names the
/// bound operation the entry claims to exercise.
const BREG_CREATE_FIXTURE: &str = r#"apiVersion: id.registrystack.org/formats/adapter/fixture/v1alpha1
kind: AdapterFixture
id: breg-contact-write
pack: breg-records
upstreamVersion: "0.45"
provenance:
  type: documented
  reference: https://example.invalid/breg-records#batch
intercepts:
  - type: endpoint
    endpoint: registry
entries:
  - facadeRequest:
      operation: {operation}
      path: /v1/collections/contacts/records
      headers:
        content-type: application/json
        idempotency-key: '"replay-create"'
      body:
        data:
          name: Ada
          email: ada@example.test
    upstream:
      - request:
          endpoint: registry
          method: POST
          path: /v1/records/contacts:batch
          query: accessProfile=directory-editor
          headers:
            idempotency-key: c24474db4d0957f85667376f76e4a25cd1d5d71a4e2b206ce8aab12a06137a5a
          body:
            items:
              - operation: create
                data:
                  name: Ada
                  email: ada@example.test
                  jurisdiction: zone-a
        response:
          status: 200
          body:
            results:
              - operation: create
                recordIdentifier: contact-1
                etag: '"breg-1"'
                domainData:
                  name: Ada
                  email: ada@example.test
                  jurisdiction: zone-a
    expected:
      type: response
      status: 201
      headers:
        cache-control: no-store
        content-type: application/json
        etag: '"w2.AbN1Q5_-XrTglRb9xER6qwJEBeg99kERkGn_ny2NRfrNN3QF-j_G-k6zdkrb0yTxZg"'
        location: /govstack/registries/v1/collections/contacts/records/contact-1
      body:
        collectionId: contacts
        recordId: contact-1
        etag: '"w2.AbN1Q5_-XrTglRb9xER6qwJEBeg99kERkGn_ny2NRfrNN3QF-j_G-k6zdkrb0yTxZg"'
"#;

/// The maintained BReg-backed GovStack example with one Create fixture
/// entry beside it, naming the given bound operation.
fn breg_govstack_with_create_entry(operation: &str) -> (tempfile::TempDir, String, String) {
    let (root, project, pack) = copied_breg_govstack(false);
    let fixtures = Path::new(&project).with_file_name("fixtures");
    std::fs::create_dir_all(&fixtures).unwrap();
    std::fs::write(
        fixtures.join("create.yaml"),
        BREG_CREATE_FIXTURE.replace("{operation}", operation),
    )
    .unwrap();
    (root, project, pack)
}

/// A GovStack Create fixture entry replays through the real BReg route and
/// is held against the compiled Create operation: its 201, headers and
/// receipt body are the ones the contract declares.
#[test]
fn a_govstack_create_entry_replays_against_its_compiled_operation() {
    let (_root, project, pack) = breg_govstack_with_create_entry("create");
    let (exit, report, stderr) = run_json(&["fixtures", "replay", &project, "--pack", &pack]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(report["status"], "complete");
    assert!(codes(&report).is_empty(), "{report}");
}

/// The same entry named as the Update binding is held against the compiled
/// Update operation, which declares no 201, so replay refuses it at the
/// expectation instead of passing it as a Create.
#[test]
fn a_govstack_write_entry_under_the_wrong_operation_is_refused_by_the_contract() {
    let (_root, project, pack) = breg_govstack_with_create_entry("update");
    let (exit, report, _) = run_json(&["fixtures", "replay", &project, "--pack", &pack]);
    assert_eq!(exit, ExitCode::FAILURE, "{report}");
    assert_eq!(codes(&report), ["adapterctl.fixtures.contract-status"]);
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/fixtures/0/entries/0/expected"
    );
}
