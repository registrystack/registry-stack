// SPDX-License-Identifier: Apache-2.0

//! The report envelope every `--format json` command shares, aligned with the
//! sibling ctls.
//!
//! A report is one JSON object on standard output. It opens with `ok`,
//! `command`, and `status`, in that order, followed by the command's own
//! camelCase members, `apiVersion` and `kind` among them. `ok` is true
//! exactly when the process exits zero; `status` names what happened. A
//! report that is not ok carries a non-empty `diagnostics` array whose
//! entries each name a `suggestedAction`.

use std::io;

use serde::ser::{Serialize, SerializeMap as _, Serializer};
use serde_json::Value;

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
    use serde_json::json;

    #[test]
    fn a_report_opens_with_ok_command_and_status_in_that_order() {
        let mut out = Vec::new();
        write(
            &json!({"apiVersion": "v", "status": "complete", "command": "check", "ok": true}),
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with(
                "{\n  \"ok\": true,\n  \"command\": \"check\",\n  \"status\": \"complete\",\n  \"apiVersion\""
            ),
            "{text}"
        );
    }

    #[test]
    fn failure_status_follows_the_exit_class() {
        assert_eq!(failure_status(1), "domain-refusal");
        assert_eq!(failure_status(USAGE_EXIT), "usage-error");
        assert_eq!(
            failure_status(OPERATIONAL_FAILURE_EXIT),
            "operational-failure"
        );
    }
}
