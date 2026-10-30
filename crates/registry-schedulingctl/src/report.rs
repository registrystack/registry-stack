// SPDX-License-Identifier: Apache-2.0

//! The report envelope every `--format json` command shares, aligned with the
//! sibling ctls.
//!
//! A report is one JSON object on standard output. It opens with `ok`,
//! `command`, and `status`, in that order, then names its own format with
//! `apiVersion` and `kind`, followed by the command's own camelCase members.
//! `ok` is true exactly when the process exits zero;
//! `status` names what happened. A report that is not ok carries a non-empty
//! `diagnostics` array whose entries each name a `suggestedAction`.

use std::io;

use registry_scheduling_core::{SCHEDULING_CTL_REPORT_API_VERSION, SCHEDULING_CTL_REPORT_KIND};
use serde_json::{json, Value};

/// The command refused authored, configuration, or selected input, or its
/// verdict was a failure, such as a failing fixture. Correct the named input.
pub(crate) const DOMAIN_REFUSAL_EXIT: u8 = 1;
/// The command line was incomplete, conflicting, or unsupported.
pub(crate) const USAGE_EXIT: u8 = 2;
/// A file, process, or service the command depends on was unavailable.
pub(crate) const OPERATIONAL_FAILURE_EXIT: u8 = 3;

/// The product-owned format identity attached before common serialization.
const FORMAT: [(&str, &str); 2] = [
    ("apiVersion", SCHEDULING_CTL_REPORT_API_VERSION),
    ("kind", SCHEDULING_CTL_REPORT_KIND),
];

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
/// reference that is otherwise recorded only as a hash. A value one of our
/// own parsers refused is described by that parser's reason instead, as
/// long as the reason does not repeat the value; a reason that does not name
/// the argument follows it.
pub(crate) fn usage_message(error: &clap::Error) -> String {
    use clap::error::ErrorKind;
    let argument = refused_argument(error);
    let named = |text: &str| match &argument {
        Some(argument) => format!("{text} {argument}"),
        None => text.to_owned(),
    };
    match error.kind() {
        ErrorKind::ValueValidation => {
            let general = named("invalid value for");
            match validator_reason(error) {
                Some(reason) if argument.as_deref().is_none_or(|name| reason.contains(name)) => {
                    reason
                }
                Some(reason) => format!("{general}: {reason}"),
                None => general,
            }
        }
        ErrorKind::InvalidValue => named("invalid value for"),
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

/// The reason one of our own value parsers gave, kept only while it does not
/// repeat the rejected value.
fn validator_reason(error: &clap::Error) -> Option<String> {
    use clap::error::{ContextKind, ContextValue};
    let reason = std::error::Error::source(error)?.to_string();
    let rejected = match error.get(ContextKind::InvalidValue) {
        Some(ContextValue::String(value)) => value.as_str(),
        _ => return None,
    };
    let repeats = !rejected.is_empty() && reason.contains(rejected);
    (!reason.is_empty() && !repeats).then_some(reason)
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

fn envelope(report: &Value) -> io::Result<Value> {
    let mut members = report
        .as_object()
        .cloned()
        .ok_or_else(|| io::Error::other("a CLI report must be an object"))?;
    for (key, value) in FORMAT {
        members.insert(key.to_owned(), Value::String(value.to_owned()));
    }
    Ok(Value::Object(members))
}

/// Write one report, envelope members first, and its trailing newline.
pub(crate) fn write(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    let value = envelope(report)?;
    let report =
        registry_cli_report::Report::new(&value, registry_platform_buildinfo::DISPLAY_VERSION)
            .map_err(io::Error::other)?;
    serde_json::to_writer_pretty(&mut *stdout, &report).map_err(io::Error::other)?;
    writeln!(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validation_error(parser: fn(&str) -> Result<String, String>, value: &str) -> clap::Error {
        clap::Command::new("ctl")
            .arg(
                clap::Arg::new("reference")
                    .long("reference")
                    .value_parser(parser),
            )
            .try_get_matches_from(["ctl", "--reference", value])
            .unwrap_err()
    }

    #[test]
    fn a_reason_that_does_not_name_the_argument_is_prefixed_with_it() {
        let port = |value: &str| {
            clap::Command::new("ctl")
                .arg(
                    clap::Arg::new("port")
                        .long("port")
                        .value_parser(clap::value_parser!(u16)),
                )
                .try_get_matches_from(["ctl", "--port", value])
                .unwrap_err()
        };
        assert_eq!(
            usage_message(&port("x1")),
            "invalid value for --port: invalid digit found in string"
        );
        assert_eq!(usage_message(&port("70000")), "invalid value for --port");
    }

    #[test]
    fn a_validator_reason_is_the_message_unless_it_repeats_the_value() {
        let empty = validation_error(|_| Err("--reference must not be empty".to_owned()), "");
        assert_eq!(usage_message(&empty), "--reference must not be empty");
        let control = validation_error(
            |_| Err("--reference must not contain control characters".to_owned()),
            "change\n42",
        );
        assert_eq!(
            usage_message(&control),
            "--reference must not contain control characters"
        );
        let echoing = validation_error(
            |value| Err(format!("--reference refused {value}")),
            "sentinel-7f3a9c",
        );
        assert_eq!(usage_message(&echoing), "invalid value for --reference");
    }

    #[test]
    fn a_report_opens_with_ok_command_and_status_then_names_its_format() {
        let mut out = Vec::new();
        write(
            &json!({"alpha":1,"status":"complete","command":"check","ok":true}),
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with(concat!(
            "{\n  \"ok\": true,\n  \"command\": \"check\",\n  \"status\": \"complete\",\n",
            "  \"apiVersion\": \"id.registrystack.org/formats/scheduling/ctl-report/v1alpha1\",\n",
            "  \"kind\": \"SchedulingCtlReport\","
        )),
            "{text}"
        );
        let report: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            report["version"],
            registry_platform_buildinfo::DISPLAY_VERSION
        );
        assert_eq!(report["diagnostics"], json!([]));
        assert_eq!(report["alpha"], 1);
    }

    #[test]
    fn a_command_cannot_rename_the_report_format() {
        let mut out = Vec::new();
        write(
            &json!({"ok": true, "command": "check", "status": "complete", "kind": "Other", "apiVersion": "other/v1"}),
            &mut out,
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(report["apiVersion"], SCHEDULING_CTL_REPORT_API_VERSION);
        assert_eq!(report["kind"], SCHEDULING_CTL_REPORT_KIND);
        assert_eq!(report.as_object().unwrap().len(), 7);
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
