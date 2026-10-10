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
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            file: None,
            field: None,
            suggested_action: None,
            diagnostics: Box::default(),
            exit_code: match code {
                "service-unavailable" | "output-unavailable" | "definition.read" => 3,
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
        let code = if self.code.matches('.').count() == 1 {
            format!("coordinator.{}", self.code.replace('_', "-"))
        } else if self.code.contains('.') {
            self.code.clone()
        } else {
            format!("coordinator.command.{}", self.code.replace('_', "-"))
        };
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
            code,
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
