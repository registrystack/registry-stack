// SPDX-License-Identifier: Apache-2.0
//! Semantic findings in an authored Casework file, each located by an RFC
//! 6901 pointer into the document as written (CFG-DIAG-1, CFG-DIAG-5).

use std::collections::BTreeMap;

use registry_platform_yaml::{Diagnostic, Document, Related, Report, Severity};

/// The grammar of an access profile, queue, review producer, task template,
/// clock, calendar, review kind, stage, outcome, and routing rule identifier.
pub(crate) const IDENTIFIER_MESSAGE: &str =
    "expected 1 to 64 characters: a lowercase letter, then lowercase letters, digits, '-', or '_'";
pub(crate) const IDENTIFIER_ACTION: &str = "Write a lowercase identifier, such as first-review.";
/// The grammar of a team and a subject claim identifier.
pub(crate) const DIRECTORY_IDENTIFIER_MESSAGE: &str =
    "expected 1 to 128 ASCII letters, digits, '-', '_', or '.'";
pub(crate) const DIRECTORY_IDENTIFIER_ACTION: &str =
    "Write an identifier of letters, digits, '-', '_', or '.', such as case-review.";
pub(crate) const ELAPSED_MESSAGE: &str =
    "expected PT followed by a positive whole number and H, M, or S";
pub(crate) const ELAPSED_ACTION: &str = "Write the duration as PT48H, PT30M, or PT90S.";

/// One problem a semantic check found. The message and the action name keys,
/// pointers, accepted values, and bounds, and never repeat a value read from
/// the file (CFG-SEC-3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigFinding {
    /// A `casework.<area>.<condition>` code (CFG-DIAG-3).
    pub code: &'static str,
    /// RFC 6901 pointer into the document as written; `""` is the root.
    pub pointer: String,
    pub message: String,
    pub suggested_action: String,
    /// Another place that explains the finding, such as the first occurrence
    /// of a repeated identifier.
    pub related: Option<RelatedFinding>,
}

/// A second place a finding names, reported as a `related` entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedFinding {
    pub pointer: String,
    pub message: String,
}

impl ConfigFinding {
    #[must_use]
    pub fn new(
        code: &'static str,
        pointer: impl Into<String>,
        message: impl Into<String>,
        suggested_action: impl Into<String>,
    ) -> Self {
        Self {
            code,
            pointer: pointer.into(),
            message: message.into(),
            suggested_action: suggested_action.into(),
            related: None,
        }
    }

    #[must_use]
    pub fn with_related(mut self, pointer: impl Into<String>, message: impl Into<String>) -> Self {
        self.related = Some(RelatedFinding {
            pointer: pointer.into(),
            message: message.into(),
        });
        self
    }

    /// The same finding with every pointer placed below `prefix`.
    #[must_use]
    pub fn under(mut self, prefix: &str) -> Self {
        self.pointer = format!("{prefix}{}", self.pointer);
        if let Some(related) = &mut self.related {
            related.pointer = format!("{prefix}{}", related.pointer);
        }
        self
    }

    /// This finding as a CFG-DIAG-1 error placed in `document`: at the value
    /// the pointer names, or, for a member the file does not write, at the
    /// key of the nearest enclosing member it does write, as for a missing
    /// member.
    #[must_use]
    pub fn to_diagnostic(&self, document: &Document) -> Diagnostic {
        let mut diagnostic = place(
            document,
            self.code,
            &self.pointer,
            &self.message,
            &self.suggested_action,
        );
        if let Some(related) = &self.related {
            let placed = place(document, self.code, &related.pointer, "", "");
            let source = placed.source.as_ref();
            diagnostic.related.push(Related {
                file: document.file().to_owned(),
                line: source.and_then(|source| source.line),
                column: source.and_then(|source| source.column),
                path: related.pointer.clone(),
                message: related.message.clone(),
            });
        }
        diagnostic
    }
}

fn place(
    document: &Document,
    code: &str,
    pointer: &str,
    message: &str,
    suggested_action: &str,
) -> Diagnostic {
    if document.span_of(pointer).is_some() {
        return document.diagnostic_at_value(
            Severity::Error,
            code,
            pointer,
            message,
            suggested_action,
        );
    }
    let mut ancestor = pointer;
    while let Some(index) = ancestor.rfind('/') {
        ancestor = &ancestor[..index];
        if document.span_of(ancestor).is_some() {
            let mut diagnostic = document.diagnostic_at_key(
                Severity::Error,
                code,
                ancestor,
                message,
                suggested_action,
            );
            pointer.clone_into(&mut diagnostic.path);
            return diagnostic;
        }
    }
    document.diagnostic_at_value(Severity::Error, code, pointer, message, suggested_action)
}

/// Every finding of one document, as the report a check command prints.
#[must_use]
pub fn findings_report(document: &Document, findings: &[ConfigFinding]) -> Report {
    let mut report = document.warnings();
    for finding in findings {
        report.push(finding.to_diagnostic(document));
    }
    report
}

/// Collects every finding of one check, in the order the check finds them.
#[derive(Debug, Default)]
pub(crate) struct Findings {
    items: Vec<ConfigFinding>,
}

impl Findings {
    pub(crate) fn push(
        &mut self,
        code: &'static str,
        pointer: impl Into<String>,
        message: impl Into<String>,
        suggested_action: impl Into<String>,
    ) {
        self.items
            .push(ConfigFinding::new(code, pointer, message, suggested_action));
    }

    pub(crate) fn add(&mut self, finding: ConfigFinding) {
        self.items.push(finding);
    }

    pub(crate) fn extend_under(
        &mut self,
        prefix: &str,
        findings: impl IntoIterator<Item = ConfigFinding>,
    ) {
        self.items
            .extend(findings.into_iter().map(|finding| finding.under(prefix)));
    }

    /// Report every occurrence of a key after its first, naming the first
    /// as related.
    pub(crate) fn repeated<K: Ord>(
        &mut self,
        items: impl IntoIterator<Item = (String, K)>,
        code: &'static str,
        message: &str,
        suggested_action: &str,
    ) {
        let mut first: BTreeMap<K, String> = BTreeMap::new();
        for (pointer, key) in items {
            if let Some(earlier) = first.get(&key) {
                self.items.push(
                    ConfigFinding::new(code, pointer, message, suggested_action)
                        .with_related(earlier.clone(), "first written here"),
                );
            } else {
                first.insert(key, pointer);
            }
        }
    }

    pub(crate) fn into_vec(self) -> Vec<ConfigFinding> {
        self.items
    }
}
