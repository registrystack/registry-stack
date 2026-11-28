// SPDX-License-Identifier: Apache-2.0
//! Common CLI output mechanics. Products own payloads and failure decisions.

use std::io::{self, Write};

#[doc(hidden)]
pub use registry_platform_posture::declared_from;
/// The declaration used by CLI report producers.
pub use registry_platform_posture::DeclaredPosture;
use serde::ser::{Serialize, SerializeMap as _, Serializer};
use serde_json::{json, Map, Value};

const EXPLICIT_SETTINGS_MEMBER: &str = "explicitProductionSettings";

const HEAD: [&str; 5] = ["ok", "command", "status", "apiVersion", "kind"];

/// The four process result classes shared by operator CLIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Complete,
    DomainRefusal,
    UsageError,
    OperationalFailure,
}

impl Status {
    /// Classify a process result. An unexpected nonzero code is operational.
    #[must_use]
    pub const fn from_exit(exit: u8) -> Self {
        match exit {
            0 => Self::Complete,
            1 => Self::DomainRefusal,
            2 => Self::UsageError,
            _ => Self::OperationalFailure,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::DomainRefusal => "domain-refusal",
            Self::UsageError => "usage-error",
            Self::OperationalFailure => "operational-failure",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "complete" => Some(Self::Complete),
            "domain-refusal" => Some(Self::DomainRefusal),
            "usage-error" => Some(Self::UsageError),
            "operational-failure" => Some(Self::OperationalFailure),
            _ => None,
        }
    }
}

/// A programming error in a command's report, without command values.
#[derive(Debug)]
pub struct InvalidReport(&'static str);

impl std::fmt::Display for InvalidReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for InvalidReport {}

/// The single serialized report envelope, borrowing the product's flat payload.
pub struct Report<'a> {
    members: &'a Map<String, Value>,
    version: &'a str,
    status: Status,
    outcome: Option<&'a Value>,
    posture: Option<DeclaredPosture>,
    explicit_settings: Option<Vec<ExplicitSettingLine>>,
}

/// One explicit production setting an operator stated, as a `check` report
/// lists it: a setting valid in every posture that relaxes something and is
/// worth a reviewer's attention. It is a list of facts, not a diagnostic, so
/// `--deny-warnings` is unaffected. The summary is value-free.
///
/// `file` names the document `pointer` refers to, such as the runtime file or
/// the package, and is left out when absent. `pointer`, `line` and `column`
/// are left out when unknown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitSettingLine {
    pub code: String,
    pub file: Option<String>,
    pub pointer: Option<String>,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub summary: String,
}

impl Serialize for ExplicitSettingLine {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("code", &self.code)?;
        if let Some(file) = &self.file {
            map.serialize_entry("file", file)?;
        }
        if let Some(pointer) = &self.pointer {
            map.serialize_entry("pointer", pointer)?;
        }
        if let Some(line) = self.line {
            map.serialize_entry("line", &line)?;
        }
        if let Some(column) = self.column {
            map.serialize_entry("column", &column)?;
        }
        map.serialize_entry("summary", &self.summary)?;
        map.end()
    }
}

impl<'a> Report<'a> {
    /// Check the product's envelope and attach the binary's build identity.
    /// Command-specific status words become outcomes; result classes stay fixed.
    pub fn new(value: &'a Value, version: &'a str) -> Result<Self, InvalidReport> {
        let members = value
            .as_object()
            .ok_or(InvalidReport("a CLI report must be an object"))?;
        let ok = members
            .get("ok")
            .and_then(Value::as_bool)
            .ok_or(InvalidReport("a CLI report must carry a boolean ok"))?;
        for key in ["command", "apiVersion", "kind"] {
            if members
                .get(key)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(InvalidReport(
                    "a CLI report is missing its command or format",
                ));
            }
        }
        if version.is_empty() {
            return Err(InvalidReport("a CLI report must carry a binary version"));
        }
        if members
            .get("diagnostics")
            .is_some_and(|value| !value.is_array())
        {
            return Err(InvalidReport("CLI report diagnostics must be an array"));
        }
        let raw_status = members.get("status");
        let (status, outcome) = match raw_status {
            None => (Status::from_exit(u8::from(!ok)), members.get("outcome")),
            Some(value) => {
                let word = value
                    .as_str()
                    .ok_or(InvalidReport("CLI report status must be a string"))?;
                match Status::parse(word) {
                    Some(status) => (status, members.get("outcome")),
                    None => {
                        if members
                            .get("outcome")
                            .is_some_and(|outcome| outcome != value)
                        {
                            return Err(InvalidReport(
                                "a CLI report has conflicting command outcomes",
                            ));
                        }
                        (Status::from_exit(u8::from(!ok)), Some(value))
                    }
                }
            }
        };
        if ok != (status == Status::Complete) {
            return Err(InvalidReport("CLI report ok and status disagree"));
        }
        Ok(Self {
            members,
            version,
            status,
            outcome,
            posture: None,
            explicit_settings: None,
        })
    }

    /// Report the declared posture as a `posture` member holding `value` and
    /// `source`, placed after the command members. A command member named
    /// `posture` is not written, so the key appears once. Without this call the
    /// body is unchanged.
    #[must_use]
    pub fn with_posture(self, declared: DeclaredPosture) -> Self {
        Self {
            posture: Some(declared),
            ..self
        }
    }

    /// Report the explicit production settings as an `explicitProductionSettings`
    /// list placed after `posture`. An empty list is written, so a reader can
    /// tell "none stated" from "not reported". A command member of that name
    /// is not written, so the key appears once. Without this call the body is
    /// unchanged.
    #[must_use]
    pub fn explicit_settings(self, settings: Vec<ExplicitSettingLine>) -> Self {
        Self {
            explicit_settings: Some(settings),
            ..self
        }
    }
}

impl Serialize for Report<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for key in HEAD {
            if key == "status" {
                map.serialize_entry(key, self.status.as_str())?;
            } else {
                map.serialize_entry(key, &self.members[key])?;
            }
        }
        map.serialize_entry("version", self.version)?;
        for (key, value) in self.members {
            let replaced = (self.posture.is_some() && key == "posture")
                || (self.explicit_settings.is_some() && key == EXPLICIT_SETTINGS_MEMBER);
            if !HEAD.contains(&key.as_str())
                && !matches!(key.as_str(), "version" | "diagnostics" | "outcome")
                && !replaced
            {
                map.serialize_entry(key, value)?;
            }
        }
        if let Some(declared) = self.posture {
            map.serialize_entry("posture", &PostureMember(declared))?;
        }
        if let Some(settings) = &self.explicit_settings {
            map.serialize_entry(EXPLICIT_SETTINGS_MEMBER, settings)?;
        }
        if let Some(outcome) = self.outcome {
            map.serialize_entry("outcome", outcome)?;
        }
        match self.members.get("diagnostics") {
            Some(diagnostics) => map.serialize_entry("diagnostics", diagnostics)?,
            None => map.serialize_entry("diagnostics", &[] as &[Value])?,
        }
        map.end()
    }
}

/// The `posture` member, written with `value` before `source`.
struct PostureMember(DeclaredPosture);

impl Serialize for PostureMember {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("value", self.0.posture.as_str())?;
        map.serialize_entry("source", self.0.source.as_str())?;
        map.end()
    }
}

/// Static binary identity used when a command cannot finish normally.
#[derive(Clone, Copy)]
pub struct Identity {
    pub binary: &'static str,
    pub api_version: &'static str,
    pub kind: &'static str,
    pub version: &'static str,
}

/// Select panic output before ordinary parsing, including usage-error paths.
/// Stops at the positional-argument terminator and does not print arguments.
pub fn json_requested(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> bool {
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            break;
        }
        if argument == "--format=json" || argument == "--json" {
            return true;
        }
        if argument == "--format" && arguments.next().is_some_and(|value| value == "json") {
            return true;
        }
    }
    false
}

/// Install at a binary entry point, after determining its requested output.
/// Never repeat the panic payload, location, arguments, or environment.
pub fn install_panic_hook(identity: Identity, json_output: bool) {
    std::panic::set_hook(Box::new(move |_| {
        let code = format!("{}.internal-error", identity.binary);
        let message = "The command stopped because of an internal error.";
        let action =
            "Preserve the input, check for a corrected release, and report the diagnostic code.";
        let written = if json_output {
            let value = json!({
                "ok":false,"command":"internal","status":"operational-failure",
                "apiVersion":identity.api_version,"kind":identity.kind,
                "diagnostics":[{"severity":"error","code":code,"path":"","message":message,"suggestedAction":action}]
            });
            let mut output = io::stdout().lock();
            Report::new(&value, identity.version)
                .map_err(io::Error::other)
                .and_then(|report| {
                    serde_json::to_writer(&mut output, &report).map_err(io::Error::other)
                })
                .and_then(|()| writeln!(output))
                .and_then(|()| output.flush())
        } else {
            writeln!(
                io::stderr().lock(),
                "error[{code}]\n  {message}\n  next: {action}"
            )
        };
        if written.is_err() {
            eprintln!(
                "{}: the internal-error report could not be written",
                identity.binary
            );
        }
        std::process::exit(3);
    }));
}
