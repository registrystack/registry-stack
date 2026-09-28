// SPDX-License-Identifier: Apache-2.0

//! The report envelope every `--format json` command shares, aligned with the
//! sibling ctls.
//!
//! A report is one JSON object on standard output. It opens with `ok`,
//! `command`, and `status`, in that order, followed by the command's own
//! camelCase members. `ok` is true exactly when the process exits zero;
//! `status` names what happened. A report that is not ok carries a non-empty
//! `diagnostics` array whose entries each name a `suggestedAction`.

use std::io;

use serde::ser::{Serialize, SerializeMap as _, Serializer};
use serde_json::{json, Value};

/// The command refused authored, configuration, or selected input, or its
/// verdict was a failure, such as a failing fixture. Correct the named input.
pub(crate) const DOMAIN_REFUSAL_EXIT: u8 = 1;
/// The command line was incomplete, conflicting, or unsupported.
pub(crate) const USAGE_EXIT: u8 = 2;
/// A file, process, or service the command depends on was unavailable.
pub(crate) const OPERATIONAL_FAILURE_EXIT: u8 = 3;

/// The members every report opens with, in the order they are written.
const HEAD: [&str; 3] = ["ok", "command", "status"];

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
    assert!(
        !diagnostics.is_empty(),
        "a failed {command} report carries diagnostics"
    );
    json!({
        "ok": false,
        "command": command,
        "status": failure_status(exit),
        "diagnostics": diagnostics,
    })
}

/// Describe a command line clap refused by the error kind and the argument
/// name only. Clap's own message is never repeated because it quotes the
/// rejected token, which may carry an operator value such as a change
/// reference that is otherwise recorded only as a hash.
pub(crate) fn usage_message(error: &clap::Error) -> String {
    use clap::error::ErrorKind;
    let argument = refused_argument(error);
    let named = |text: &str| match &argument {
        Some(argument) => format!("{text} {argument}"),
        None => text.to_owned(),
    };
    match error.kind() {
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => named("invalid value for"),
        ErrorKind::UnknownArgument => named("unexpected argument"),
        ErrorKind::InvalidSubcommand => "unrecognized subcommand".to_owned(),
        ErrorKind::NoEquals => named("an equals sign is required for"),
        ErrorKind::TooManyValues | ErrorKind::TooFewValues | ErrorKind::WrongNumberOfValues => {
            named("wrong number of values for")
        }
        ErrorKind::ArgumentConflict => named("conflicting use of"),
        ErrorKind::MissingRequiredArgument => named("missing required argument"),
        ErrorKind::MissingSubcommand | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            "missing subcommand".to_owned()
        }
        ErrorKind::InvalidUtf8 => "invalid UTF-8 in the command arguments".to_owned(),
        _ => "invalid command arguments".to_owned(),
    }
}

/// The name of the argument clap refused, without any value. An unknown
/// argument is the operator's own token, so it is named only when it has the
/// shape of a long option and only up to any `=`.
fn refused_argument(error: &clap::Error) -> Option<String> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let names = match error.get(ContextKind::InvalidArg)? {
        ContextValue::String(name) => vec![name.as_str()],
        ContextValue::Strings(names) => names.iter().map(String::as_str).collect(),
        _ => return None,
    };
    let names = names
        .into_iter()
        .filter_map(|name| {
            if error.kind() == ErrorKind::UnknownArgument {
                let option = name.split('=').next()?;
                let flag = option.strip_prefix("--")?;
                let shaped = !flag.is_empty()
                    && flag.chars().all(|character| {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '-'
                    });
                shaped.then(|| option.to_owned())
            } else {
                name.split_whitespace().next().map(str::to_owned)
            }
        })
        .collect::<Vec<_>>();
    (!names.is_empty()).then(|| names.join(", "))
}

/// Write one report, envelope members first, and its trailing newline.
pub(crate) fn write(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *stdout, &Ordered(report)).map_err(io::Error::other)?;
    writeln!(stdout)
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

    #[test]
    fn a_report_opens_with_ok_command_and_status_in_that_order() {
        let mut out = Vec::new();
        write(
            &json!({"alpha": 1, "status": "complete", "command": "check", "ok": true}),
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with("{\n  \"ok\": true,\n  \"command\": \"check\",\n  \"status\": \"complete\",\n  \"alpha\": 1"),
            "{text}"
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
    fn a_failure_without_diagnostics_is_a_programming_error() {
        let _ = failure("check", DOMAIN_REFUSAL_EXIT, Vec::new());
    }
}
