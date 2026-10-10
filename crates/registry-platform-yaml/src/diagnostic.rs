// SPDX-License-Identifier: Apache-2.0
//! The one diagnostic shape (CFG-DIAG-1) and its human rendering (CFG-DIAG-2).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Whether a diagnostic refuses the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

/// Where a diagnostic points. `file` is the path exactly as the caller gave
/// it; `line` and `column` are 1-based and absent when the problem concerns
/// the file as a whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
}

/// A second place that explains a diagnostic, such as the first occurrence
/// of a duplicate. Human output prints it as a `note:` line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Related {
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    pub path: String,
    pub message: String,
}

/// One problem, in the shape every checking command reports (CFG-DIAG-1).
///
/// A diagnostic names keys, the path, accepted values, bounds, and the
/// expected envelope. It never repeats a scalar value read from a file or the
/// environment (CFG-SEC-3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: String,
    /// The document's `kind`, or the expected kind when the document's own is
    /// absent or wrong and the reader expected exactly one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    /// RFC 6901 JSON pointer into the document as written; `""` is the root.
    pub path: String,
    pub message: String,
    pub suggested_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<Related>,
}

impl Diagnostic {
    /// An error with no position yet.
    pub fn error(
        code: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
        suggested_action: impl Into<String>,
    ) -> Diagnostic {
        Diagnostic {
            severity: Severity::Error,
            code: code.into(),
            artifact: None,
            path: path.into(),
            message: message.into(),
            suggested_action: suggested_action.into(),
            source: None,
            related: Vec::new(),
        }
    }

    /// A warning with no position yet.
    pub fn warning(
        code: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
        suggested_action: impl Into<String>,
    ) -> Diagnostic {
        Diagnostic {
            severity: Severity::Warning,
            ..Diagnostic::error(code, path, message, suggested_action)
        }
    }

    /// Human output for this diagnostic alone (CFG-DIAG-2): position first,
    /// then the message, the fix, and any related notes, each line ending in
    /// a newline. [`Report::render_human`] adds the summary line.
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(self.severity.as_str());
        out.push('[');
        out.push_str(&clean(&self.code));
        out.push(']');
        if let Some(source) = &self.source {
            out.push(' ');
            out.push_str(&location(&source.file, source.line, source.column));
        }
        if !self.path.is_empty() {
            out.push(' ');
            out.push_str(&shown_path(&self.path));
        }
        out.push('\n');
        out.push_str("  ");
        out.push_str(&clean(&self.message));
        out.push('\n');
        out.push_str("  next: ");
        out.push_str(&clean(&self.suggested_action));
        out.push('\n');
        for related in &self.related {
            out.push_str("  note: ");
            out.push_str(&location(&related.file, related.line, related.column));
            if !related.path.is_empty() {
                out.push(' ');
                out.push_str(&shown_path(&related.path));
            }
            out.push(' ');
            out.push_str(&clean(&related.message));
            out.push('\n');
        }
        out
    }

    fn sort_key(&self) -> (usize, usize, usize) {
        match &self.source {
            Some(Source {
                line: Some(line),
                column,
                ..
            }) => (1, *line, column.unwrap_or(0)),
            _ => (0, 0, 0),
        }
    }
}

/// A set of diagnostics returned when a reader or check refuses its input.
///
/// A report from the reader always holds at least one error. Warnings travel
/// with the errors they were found beside.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Report {
    diagnostics: Vec<Diagnostic>,
    files_checked: Option<usize>,
}

impl Report {
    pub fn new(diagnostics: Vec<Diagnostic>) -> Report {
        Report {
            diagnostics,
            files_checked: None,
        }
    }

    /// Record how many files the report covers, for the summary line. A
    /// report from the reader covers one file; [`Report::extend`] adds the
    /// counts.
    pub fn set_files_checked(&mut self, files: usize) {
        self.files_checked = Some(files);
    }

    /// The number of files the report covers, when it was recorded.
    pub fn files_checked(&self) -> Option<usize> {
        self.files_checked
    }

    pub fn push(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    /// Append another report, so one command can report every file it read.
    pub fn extend(&mut self, other: Report) {
        self.diagnostics.extend(other.diagnostics);
        self.files_checked = match (self.files_checked, other.files_checked) {
            (None, None) => None,
            (left, right) => Some(left.unwrap_or(0) + right.unwrap_or(0)),
        };
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn into_diagnostics(self) -> Vec<Diagnostic> {
        self.diagnostics
    }

    pub fn is_empty(&self) -> bool {
        self.diagnostics.is_empty()
    }

    pub fn has_errors(&self) -> bool {
        self.error_count() > 0
    }

    pub fn error_count(&self) -> usize {
        self.count(Severity::Error)
    }

    pub fn warning_count(&self) -> usize {
        self.count(Severity::Warning)
    }

    fn count(&self, severity: Severity) -> usize {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == severity)
            .count()
    }

    /// Order diagnostics by position, file-level ones first, keeping the
    /// order in which equal positions were found.
    pub(crate) fn sort_by_position(&mut self) {
        self.diagnostics.sort_by_key(Diagnostic::sort_key);
    }

    /// Keep the first `maximum` diagnostics and return the rest.
    pub(crate) fn split_off(&mut self, maximum: usize) -> Vec<Diagnostic> {
        if self.diagnostics.len() <= maximum {
            return Vec::new();
        }
        self.diagnostics.split_off(maximum)
    }

    /// The diagnostics as a JSON array, ready for a ctl report envelope.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.diagnostics
                .iter()
                .map(|diagnostic| {
                    serde_json::to_value(diagnostic)
                        .expect("a diagnostic has only string and integer members")
                })
                .collect(),
        )
    }

    /// Human output (CFG-DIAG-2): position first, then the message, the fix,
    /// any related notes, and a closing summary line.
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        for diagnostic in &self.diagnostics {
            out.push_str(&diagnostic.render_human());
        }
        out.push_str(&self.summary());
        out.push('\n');
        out
    }

    /// `2 errors, 1 warning in 3 files`. The file count is the number of
    /// files checked when it was recorded, and otherwise the number of files
    /// the diagnostics name.
    pub fn summary(&self) -> String {
        let errors = self.error_count();
        let warnings = self.warning_count();
        let files = self.files_checked.unwrap_or_else(|| {
            self.diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic.source.as_ref())
                .map(|source| source.file.as_str())
                .collect::<BTreeSet<&str>>()
                .len()
        });
        let mut summary = format!(
            "{} {}, {} {}",
            errors,
            plural(errors, "error", "errors"),
            warnings,
            plural(warnings, "warning", "warnings")
        );
        if files > 0 {
            summary.push_str(&format!(" in {} {}", files, plural(files, "file", "files")));
        }
        summary
    }
}

impl fmt::Display for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.render_human())
    }
}

impl std::error::Error for Report {}

fn plural(count: usize, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 {
        one
    } else {
        many
    }
}

fn location(file: &str, line: Option<usize>, column: Option<usize>) -> String {
    let mut out = clean(file);
    if let Some(line) = line {
        out.push_str(&format!(":{line}"));
        if let Some(column) = column {
            out.push_str(&format!(":{column}"));
        }
    }
    out
}

/// Paths longer than this are shortened in human output; JSON output
/// carries the whole path.
const PATH_DISPLAY_CHARS: usize = 120;

/// A path as human output shows it: when longer than
/// [`PATH_DISPLAY_CHARS`], its first and last halves of that length joined
/// by `...`, so both the root's members and the last key stay readable.
fn shown_path(path: &str) -> String {
    let count = path.chars().count();
    if count <= PATH_DISPLAY_CHARS {
        return clean(path);
    }
    let half = PATH_DISPLAY_CHARS / 2;
    let head: String = path.chars().take(half).collect();
    let tail: String = path.chars().skip(count - half).collect();
    format!("{}...{}", clean(&head), clean(&tail))
}

/// Escape control characters so a key or file name cannot rewrite a
/// terminal line.
pub(crate) fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}
