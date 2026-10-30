// SPDX-License-Identifier: Apache-2.0

use registry_cli_report::{json_requested, Report, Status};
use serde_json::{json, Value};

fn members() -> Value {
    json!({"ok":true,"command":"check","status":"complete","apiVersion":"format/v1","kind":"CtlReport","filesChecked":2})
}

#[test]
fn every_report_has_the_same_order_diagnostics_and_binary_version() {
    let value = members();
    let rendered = serde_json::to_string(&Report::new(&value, "1.0.0-dev").unwrap()).unwrap();
    assert!(
        rendered.starts_with(concat!(
            r#"{"ok":true,"command":"check","status":"complete","#,
            r#""apiVersion":"format/v1","kind":"CtlReport","#
        )),
        "{rendered}"
    );
    let report: Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(report["diagnostics"], json!([]));
    assert_eq!(report["version"], "1.0.0-dev");
    assert_eq!(report["filesChecked"], 2);
    assert!(report.get("data").is_none());
}

#[test]
fn command_words_are_outcomes_and_status_follows_the_exit_class() {
    for (ok, word, expected) in [
        (true, "declined", "complete"),
        (false, "failed", "domain-refusal"),
    ] {
        let mut value = members();
        value["ok"] = json!(ok);
        value["status"] = json!(word);
        value["diagnostics"] = if ok {
            json!([])
        } else {
            json!([{"code":"ctl.refused"}])
        };
        let report = serde_json::to_value(Report::new(&value, "1.0.0").unwrap()).unwrap();
        assert_eq!(report["status"], expected);
        assert_eq!(report["outcome"], word);
    }
    for (exit, expected) in [
        (0, "complete"),
        (1, "domain-refusal"),
        (2, "usage-error"),
        (3, "operational-failure"),
    ] {
        assert_eq!(Status::from_exit(exit).as_str(), expected);
    }
}

#[test]
fn a_malformed_envelope_is_an_explicit_programming_error() {
    for key in ["ok", "command", "apiVersion", "kind"] {
        let mut value = members();
        value.as_object_mut().unwrap().remove(key);
        assert!(Report::new(&value, "1.0.0").is_err(), "{key}");
    }
    let mut value = members();
    value["diagnostics"] = json!({});
    assert!(Report::new(&value, "1.0.0").is_err());
    value["diagnostics"] = json!([]);
    value["status"] = json!("usage-error");
    assert!(Report::new(&value, "1.0.0").is_err());
}

#[test]
fn panic_output_selection_understands_both_format_spellings_and_the_terminator() {
    for args in [
        vec!["ctl", "--format", "json"],
        vec!["ctl", "--format=json"],
        vec!["ctl", "--json"],
    ] {
        assert!(json_requested(
            args.into_iter().map(std::ffi::OsString::from)
        ));
    }
    for args in [
        vec!["ctl", "--format", "human"],
        vec!["ctl", "--", "--format=json"],
        vec!["ctl", "--output=json"],
    ] {
        assert!(!json_requested(
            args.into_iter().map(std::ffi::OsString::from)
        ));
    }
}
