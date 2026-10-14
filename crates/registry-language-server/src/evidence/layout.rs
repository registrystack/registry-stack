// SPDX-License-Identifier: Apache-2.0
//! Closed Evidence editor file roles. Secret and generated runtime state are never read.
use registry_evidence_authoring::project::PROJECT_FILE;
use std::path::{Component, Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DocumentRole {
    Project,
    Authority,
    Function,
    Generated,
    Schema,
    Fixture,
}
impl DocumentRole {
    pub(crate) fn max_bytes(self) -> u64 {
        1_048_576
    }
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Project => "Evidence project",
            Self::Authority => "target authority",
            Self::Function => "Function",
            Self::Generated => "generated project types",
            Self::Schema => "schema",
            Self::Fixture => "fixture",
        }
    }
    pub(crate) fn is_indexed(self) -> bool {
        !matches!(self, Self::Schema | Self::Fixture)
    }
}
pub(crate) fn document_role(relative: &Path) -> Option<DocumentRole> {
    let names = relative
        .components()
        .map(|part| match part {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    if names.iter().any(|name| name.starts_with('.')) || names.first() == Some(&"secrets") {
        return None;
    }
    match names.as_slice() {
        [file] if *file == PROJECT_FILE => Some(DocumentRole::Project),
        [file] if *file == "authority.yaml" || file.ends_with("-authority.yaml") => {
            Some(DocumentRole::Authority)
        }
        ["targets", ..] if relative.extension().is_some_and(|x| x == "yaml") => {
            Some(DocumentRole::Authority)
        }
        _ if relative.extension().is_some_and(|x| x == "rhai") => Some(DocumentRole::Function),
        _ if relative.extension().is_some_and(|x| x == "ts" || x == "py") => {
            Some(DocumentRole::Generated)
        }
        _ if names.first() == Some(&"schemas") => Some(DocumentRole::Schema),
        _ if names.first() == Some(&"fixtures") => Some(DocumentRole::Fixture),
        _ => None,
    }
}
pub(crate) fn watched_globs() -> Vec<String> {
    [
        "**/evidence.yaml",
        "**/targets/*/authority.yaml",
        "**/*.rhai",
        "**/*.ts",
        "**/*.py",
        "**/schemas/**/*",
        "**/fixtures/**/*",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
