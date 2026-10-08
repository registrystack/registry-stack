//! The one report contract every `--format json` command shares.
//!
//! A report is one JSON object on standard output. It opens with `ok`,
//! `command`, and `status`, in that order, followed by the command's own
//! camelCase members. `ok` is true exactly when the process exits
//! [`SUCCESS_EXIT`]; `status` names what happened, including an incomplete
//! but accepted result. Refusals use the same envelope with `ok: false` and a
//! `diagnostics` array. Under `--format json` nothing else is written to
//! either stream, so a caller parses standard output and reads the exit code.

use std::io::Write as _;

use serde::ser::{Serialize, SerializeMap as _, Serializer};
use serde_json::{Map, Value};

/// The operation completed. A report may still carry warnings or an
/// incomplete status; the exit class says the command did what was asked.
pub(crate) const SUCCESS_EXIT: u8 = 0;
/// The command refused authored, configuration, or selected input, or its
/// verdict was a failure, such as a failing fixture. Correct the named input.
pub(crate) const DOMAIN_REFUSAL_EXIT: u8 = 1;
/// The command line was incomplete, conflicting, or unsupported.
pub(crate) const USAGE_EXIT: u8 = 2;
/// A file, process, or service the command depends on was unavailable.
pub(crate) const OPERATIONAL_FAILURE_EXIT: u8 = 3;

/// The members every report opens with, in the order they are written.
const HEAD: [&str; 3] = ["ok", "command", "status"];

/// A successful report: `ok: true`, the command path, its status, then the
/// command's own members.
pub(crate) fn success(command: &str, status: &str, members: Value) -> Value {
    envelope(true, command, status, members)
}

/// A report whose command ran but whose verdict refused, such as a denied
/// check or a failing fixture run. The caller exits [`DOMAIN_REFUSAL_EXIT`].
/// Its members carry a non-empty `diagnostics` array, so a caller reading
/// only the envelope still finds the next step.
pub(crate) fn refused(command: &str, status: &str, members: Value) -> Value {
    assert!(
        members["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| !diagnostics.is_empty()),
        "a refused {command} report carries diagnostics"
    );
    envelope(false, command, status, members)
}

fn envelope(ok: bool, command: &str, status: &str, members: Value) -> Value {
    let members = match members {
        Value::Object(members) => members,
        Value::Null => Map::new(),
        other => unreachable!(
            "command report members are always a JSON object, got {}",
            kind(&other)
        ),
    };
    let mut report = Map::new();
    report.insert("ok".to_owned(), Value::Bool(ok));
    report.insert("command".to_owned(), Value::String(command.to_owned()));
    report.insert("status".to_owned(), Value::String(status.to_owned()));
    for (key, value) in members {
        debug_assert!(
            !HEAD.contains(&key.as_str()),
            "{key} is an envelope member and cannot be supplied by a command"
        );
        report.insert(key, value);
    }
    Value::Object(report)
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// The status a failure envelope carries for each exit class.
pub(crate) fn failure_status(exit: u8) -> &'static str {
    match exit {
        USAGE_EXIT => "usage-error",
        OPERATIONAL_FAILURE_EXIT => "operational-failure",
        _ => "domain-refusal",
    }
}

/// A refusal report for a command that did not produce its own: the exit
/// class decides the status, and the diagnostics say what to do next.
pub(crate) fn failure(command: &str, exit: u8, diagnostics: Vec<Value>) -> Value {
    envelope(
        false,
        command,
        failure_status(exit),
        serde_json::json!({ "diagnostics": diagnostics }),
    )
}

/// Render one report on a single line, envelope members first.
pub(crate) fn render(report: &Value) -> String {
    serde_json::to_string(&Ordered(report)).expect("a JSON value always serializes")
}

/// Write one report and its trailing newline to standard output.
pub(crate) fn print(report: &Value) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{}", render(report))?;
    stdout.flush()
}

/// Serialize the top-level object with the envelope members first, whatever
/// order the underlying map keeps.
struct Ordered<'a>(&'a Value);

impl Serialize for Ordered<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Value::Object(members) = self.0 else {
            return self.0.serialize(serializer);
        };
        let mut map = serializer.serialize_map(Some(members.len()))?;
        for key in HEAD {
            if let Some(value) = members.get(key) {
                map.serialize_entry(key, value)?;
            }
        }
        for (key, value) in members {
            if !HEAD.contains(&key.as_str()) {
                map.serialize_entry(key, value)?;
            }
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_report_opens_with_ok_command_and_status_in_that_order() {
        let rendered = render(&success(
            "keygen signing",
            "complete",
            json!({"alpha": 1, "zulu": 2}),
        ));
        assert!(
            rendered.starts_with(r#"{"ok":true,"command":"keygen signing","status":"complete","#),
            "{rendered}"
        );
    }

    #[test]
    fn failure_status_follows_the_exit_class() {
        for (exit, status) in [
            (DOMAIN_REFUSAL_EXIT, "domain-refusal"),
            (USAGE_EXIT, "usage-error"),
            (OPERATIONAL_FAILURE_EXIT, "operational-failure"),
        ] {
            let report = failure("check", exit, vec![json!({"code": "x"})]);
            assert_eq!(report["ok"], false);
            assert_eq!(report["command"], "check");
            assert_eq!(report["status"], status);
            assert_eq!(report["diagnostics"][0]["code"], "x");
        }
    }

    #[test]
    #[should_panic(expected = "carries diagnostics")]
    fn a_refused_report_without_diagnostics_is_a_programming_error() {
        let _ = refused("check", "refused", json!({"diagnostics": []}));
    }

    #[test]
    fn a_refused_report_keeps_the_diagnostics_its_command_supplied() {
        let report = refused(
            "fixtures run",
            "failed",
            json!({"diagnostics": [{"code": "x", "suggestedAction": "rerun"}]}),
        );
        assert_eq!(report["ok"], false);
        assert_eq!(report["diagnostics"][0]["code"], "x");
    }

    #[test]
    #[should_panic(expected = "always a JSON object")]
    fn members_that_are_not_an_object_are_a_programming_error() {
        let _ = success("jwks", "complete", json!(["not", "an", "object"]));
    }
}
