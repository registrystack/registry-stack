// SPDX-License-Identifier: Apache-2.0
use registry_platform_yaml::{Diagnostic, Report, Severity};
use std::path::{Path, PathBuf};

/// A category, authored location and repair action, without runtime values.
#[derive(Debug, thiserror::Error)]
#[error("{}", self.render())]
pub struct PocError {
    pub code: String,
    pub message: String,
    pub file: Option<Box<Path>>,
    pub field: Option<Box<str>>,
    pub suggested_action: Option<Box<str>>,
    pub diagnostics: Box<[Diagnostic]>,
    pub exit_code: u8,
}

impl PocError {
    /// `code` is written in the one form every surface carries:
    /// `coordinator.<area>.<condition>`, each segment kebab-case.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        debug_assert!(is_product_code(code), "malformed code {code}");
        Self {
            code: code.into(),
            message: message.into(),
            file: None,
            field: None,
            suggested_action: None,
            diagnostics: Box::default(),
            exit_code: match code {
                "coordinator.command.service-unavailable"
                | "coordinator.command.output-unavailable"
                | "coordinator.definition.read" => 3,
                _ => 1,
            },
        }
    }
    /// Preserve all shared-reader findings and their authored positions.
    pub fn from_report(report: Report) -> Self {
        Self::from_diagnostics(report.diagnostics())
    }
    pub fn from_diagnostics(diagnostics: &[Diagnostic]) -> Self {
        let Some(deciding) = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity == Severity::Error)
            .or_else(|| diagnostics.first())
        else {
            return Self::new("coordinator.config.refused", "configuration was refused");
        };
        Self {
            code: deciding.code.clone(),
            message: deciding.message.clone(),
            file: deciding
                .source
                .as_ref()
                .map(|source| PathBuf::from(&source.file).into_boxed_path()),
            field: Some(deciding.path.clone().into_boxed_str()),
            suggested_action: Some(deciding.suggested_action.clone().into_boxed_str()),
            diagnostics: diagnostics.into(),
            exit_code: if diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == registry_platform_config::UNAVAILABLE_CODE)
            {
                3
            } else {
                1
            },
        }
    }
    pub(crate) fn with_exit(mut self, exit_code: u8) -> Self {
        self.exit_code = exit_code;
        self
    }
    pub(crate) fn report(&self) -> Report {
        if !self.diagnostics.is_empty() {
            return Report::new(self.diagnostics.to_vec());
        }
        let field = self.field.as_deref().unwrap_or("");
        let source_position = field
            .strip_prefix("line ")
            .and_then(|value| value.split_once(" column "))
            .and_then(|(line, column)| {
                Some((line.parse::<usize>().ok()?, column.parse::<usize>().ok()?))
            });
        let pointer =
            if field.is_empty() || source_position.is_some() || field.starts_with("function ") {
                String::new()
            } else if field.starts_with('/') {
                field.to_owned()
            } else {
                format!("/{}", field.replace(['.', '['], "/").replace(']', ""))
            };
        let mut diagnostic = Diagnostic::error(
            &self.code,
            pointer,
            &self.message,
            self.suggested_action.as_deref().unwrap_or(
                "Inspect the command inputs and current service state before trying again.",
            ),
        );
        if let Some(file) = &self.file {
            diagnostic.source = Some(registry_platform_yaml::Source {
                file: file.display().to_string(),
                line: source_position
                    .map(|(line, _)| line)
                    .filter(|line| *line > 0),
                column: source_position
                    .map(|(_, column)| column)
                    .filter(|column| *column > 0),
            });
        }
        Report::new(vec![diagnostic])
    }
    pub fn at(mut self, file: impl Into<PathBuf>, field: impl Into<String>) -> Self {
        self.file = Some(file.into().into_boxed_path());
        self.field = Some(field.into().into_boxed_str());
        self
    }
    pub fn suggest(mut self, action: impl Into<String>) -> Self {
        self.suggested_action = Some(action.into().into_boxed_str());
        self
    }
    fn render(&self) -> String {
        if !self.diagnostics.is_empty() {
            return Report::new(self.diagnostics.to_vec()).render_human();
        }
        let mut text = match (&self.file, &self.field) {
            (Some(file), Some(field)) => format!(
                "{}: {field}: {}: {}",
                file.display(),
                self.code,
                self.message
            ),
            _ => format!("{}: {}", self.code, self.message),
        };
        if let Some(action) = &self.suggested_action {
            text.push('\n');
            text.push_str(action);
        }
        text
    }
}

pub type Result<T> = std::result::Result<T, PocError>;

fn is_product_code(code: &str) -> bool {
    let mut segments = code.split('.');
    segments.next() == Some("coordinator")
        && segments.clone().count() == 2
        && segments.all(|segment| {
            segment.split('-').all(|word| {
                !word.is_empty()
                    && word
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_names_the_product_an_area_and_a_condition_in_kebab_case() {
        for code in [
            "coordinator.access.denied",
            "coordinator.definition.snapshot-limit",
            "coordinator.command.database-tls-required",
        ] {
            assert!(is_product_code(code), "{code}");
        }
        for code in [
            "access.denied",
            "run-absent",
            "coordinator.run-absent",
            "coordinator.definition.snapshot_limit",
            "coordinator.definition.snapshot.limit",
            "coordinator.definition.",
            "coordinator.Definition.read",
            "coordinator.definition.-read",
        ] {
            assert!(!is_product_code(code), "{code}");
        }
    }

    #[test]
    fn a_report_carries_the_code_exactly_as_it_was_written() {
        let error = PocError::new("coordinator.command.run-absent", "no such run");
        assert_eq!(error.report().diagnostics()[0].code, error.code);
        assert!(error
            .to_string()
            .starts_with("coordinator.command.run-absent: "));
    }
}
