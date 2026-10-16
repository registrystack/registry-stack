// SPDX-License-Identifier: Apache-2.0
//! Closed Evidence editor file roles. Secret and generated runtime state are never read.
use registry_evidence_authoring::project::PROJECT_FILE;
use std::path::{Component, Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DocumentRole {
    Project,
    Target,
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
            Self::Target => "Evidence target",
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
    if names
        .iter()
        .any(|name| name.starts_with('.') || *name == "secrets")
    {
        return None;
    }
    match names.as_slice() {
        [file] if *file == PROJECT_FILE => Some(DocumentRole::Project),
        [file] | ["targets", .., file]
            if *file == "target.yaml" || file.ends_with("-target.yaml") =>
        {
            Some(DocumentRole::Target)
        }
        [file] | ["targets", .., file]
            if *file == "authority.yaml" || file.ends_with("-authority.yaml") =>
        {
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
        "**/target.yaml",
        "**/*-target.yaml",
        "**/authority.yaml",
        "**/*-authority.yaml",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_and_flat_targets_have_distinct_watched_roles() {
        for (file, role) in [
            ("target.yaml", DocumentRole::Target),
            ("local-target.yaml", DocumentRole::Target),
            ("targets/local/target.yaml", DocumentRole::Target),
            ("authority.yaml", DocumentRole::Authority),
            ("local-authority.yaml", DocumentRole::Authority),
            ("targets/local/authority.yaml", DocumentRole::Authority),
        ] {
            assert_eq!(document_role(Path::new(file)), Some(role));
            assert!(role.is_indexed());
        }
        for file in [
            "targets/local/secret.yaml",
            "targets/local/.generated/runtime.yaml",
            "secrets/target.yaml",
            "targets/local/secrets/target.yaml",
        ] {
            assert_eq!(document_role(Path::new(file)), None);
        }
        for glob in [
            "**/target.yaml",
            "**/*-target.yaml",
            "**/authority.yaml",
            "**/*-authority.yaml",
        ] {
            assert!(watched_globs().contains(&glob.to_owned()));
        }
    }
}
