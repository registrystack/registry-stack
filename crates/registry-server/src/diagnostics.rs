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

/// A stable, value-free diagnostic addressed to a source field.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub path: String,
    pub message: String,
}

impl Diagnostic {
    pub(crate) fn error(code: &str, path: impl Into<String>, message: &str) -> Self {
        Self {
            severity: DiagnosticSeverity::Error,
            code: code.to_owned(),
            path: path.into(),
            message: message.to_owned(),
        }
    }

    pub(crate) fn finding(code: &str, path: impl Into<String>, message: &str) -> Self {
        Self {
            severity: DiagnosticSeverity::Finding,
            code: code.to_owned(),
            path: path.into(),
            message: message.to_owned(),
        }
    }
}

/// All errors from one compile, sorted independently of input order.
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
        diagnostics.sort();
        diagnostics.dedup();
        Self { diagnostics }
    }
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
