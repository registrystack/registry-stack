// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::{Deserialize, Serialize};

/// Severity of one deterministic compiler diagnostic.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Finding,
    Error,
}

/// Another authored compiler path that explains a diagnostic.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelatedDiagnostic {
    pub path: String,
    pub message: String,
}

/// A stable, value-free diagnostic addressed to a source field.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub path: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<RelatedDiagnostic>,
}

impl Diagnostic {
    pub(crate) fn error(code: &str, path: impl Into<String>, message: &str) -> Self {
        Self {
            severity: DiagnosticSeverity::Error,
            code: code.to_owned(),
            path: path.into(),
            message: message.to_owned(),
            related: Vec::new(),
        }
    }

    pub(crate) fn finding(code: &str, path: impl Into<String>, message: &str) -> Self {
        Self {
            severity: DiagnosticSeverity::Finding,
            code: code.to_owned(),
            path: path.into(),
            message: message.to_owned(),
            related: Vec::new(),
        }
    }

    pub(crate) fn with_related(mut self, path: impl Into<String>, message: &str) -> Self {
        self.related.push(RelatedDiagnostic {
            path: path.into(),
            message: message.to_owned(),
        });
        self
    }
}

/// All diagnostics from one failed compile, with errors before findings and
/// each severity sorted independently of input order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CompileFailure {
    diagnostics: Vec<Diagnostic>,
}

impl CompileFailure {
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub(crate) fn from_one(diagnostic: Diagnostic) -> Self {
        Self {
            diagnostics: vec![diagnostic],
        }
    }

    pub(crate) fn from_errors(mut diagnostics: Vec<Diagnostic>) -> Self {
        sort_failure_diagnostics(&mut diagnostics);
        diagnostics.dedup();
        Self { diagnostics }
    }

    pub(crate) fn with_findings(mut self, findings: &[Diagnostic]) -> Self {
        self.diagnostics.extend_from_slice(findings);
        sort_failure_diagnostics(&mut self.diagnostics);
        self.diagnostics.dedup();
        self
    }
}

fn sort_failure_diagnostics(diagnostics: &mut [Diagnostic]) {
    diagnostics.sort_by(|left, right| {
        let rank = |severity| match severity {
            DiagnosticSeverity::Error => 0,
            DiagnosticSeverity::Finding => 1,
        };
        rank(left.severity)
            .cmp(&rank(right.severity))
            .then_with(|| left.cmp(right))
    });
}

impl fmt::Display for CompileFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "registry compilation failed with {} diagnostic(s)",
            self.diagnostics.len()
        )
    }
}

impl std::error::Error for CompileFailure {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn diagnostic_wire_shape_keeps_related_optional() {
        let legacy = json!({
            "severity":"error",
            "code":"breg.test",
            "path":"recordTypes[id=entry].id",
            "message":"refused"
        });
        let diagnostic: Diagnostic = serde_json::from_value(legacy).unwrap();
        assert!(diagnostic.related.is_empty());

        let serialized = serde_json::to_value(diagnostic).unwrap();
        assert!(serialized.get("related").is_none());
    }

    #[test]
    fn compile_failure_keeps_errors_before_retained_findings() {
        let failure =
            CompileFailure::from_one(Diagnostic::error("breg.error", "project", "refused"))
                .with_findings(&[Diagnostic::finding(
                    "breg.finding",
                    "project",
                    "review this",
                )]);

        assert_eq!(failure.diagnostics[0].severity, DiagnosticSeverity::Error);
        assert_eq!(failure.diagnostics[1].severity, DiagnosticSeverity::Finding);
    }
}
