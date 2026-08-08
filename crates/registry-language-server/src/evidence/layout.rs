// SPDX-License-Identifier: Apache-2.0
//! What an authored file is, read from where it sits: the part a root-relative path plays in an
//! Evidence authoring project, and the parts of a project the server must never open.

use std::path::{Component, Path, PathBuf};

use registry_evidence_authoring::{
    layout::{
        ACCESS_DIRECTORY, ACCESS_POLICIES_DIRECTORY, DERIVATIONS_DIRECTORY, FIXTURES_DIRECTORY,
        MAX_ACCESS_POLICY_BYTES, MAX_DERIVATION_BYTES, MAX_OPENAPI_BYTES, MAX_PROJECT_MARKER_BYTES,
        MAX_QUESTION_BYTES, MAX_SOURCE_ARTIFACT_BYTES, OPENAPI_FILE, QUESTIONS_DIRECTORY,
        SCHEMAS_DIRECTORY, SECRETS_DIRECTORY, SELECTORS_DIRECTORY, SOURCES_DIRECTORY,
    },
    marker::PROJECT_MARKER_FILE,
};

/// The part one authored file plays in a project.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DocumentRole {
    Marker,
    OpenApi,
    Question,
    Source,
    Selector,
    Schema,
    Fixture,
    AccessPolicy,
    Derivation,
}

impl DocumentRole {
    /// The largest file the authoring form allows in this role. The ceilings are the authoring
    /// library's, so a document an author's compiler refuses for its size is a document the editor
    /// refuses for the same size.
    pub(crate) fn max_bytes(self) -> u64 {
        match self {
            Self::Marker => MAX_PROJECT_MARKER_BYTES,
            Self::OpenApi => MAX_OPENAPI_BYTES,
            Self::Question => MAX_QUESTION_BYTES,
            Self::Source | Self::Selector | Self::Schema | Self::Fixture => {
                MAX_SOURCE_ARTIFACT_BYTES
            }
            Self::AccessPolicy => MAX_ACCESS_POLICY_BYTES,
            Self::Derivation => MAX_DERIVATION_BYTES,
        }
    }

    /// The name this role goes by in a message an author reads.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Marker => "project marker",
            Self::OpenApi => "OpenAPI description",
            Self::Question => "question",
            Self::Source => "source",
            Self::Selector => "selector profile",
            Self::Schema => "schema",
            Self::Fixture => "fixture",
            Self::AccessPolicy => "access policy",
            Self::Derivation => "derivation",
        }
    }

    /// Whether the server reads this role's document into the index.
    ///
    /// The OpenAPI description and the authored derivations are classified because a path that
    /// reaches them is still part of the authoring form and its role is the honest answer, but
    /// neither is read: nothing indexes Rhai, and the walk that turns a published operation into
    /// the leaves a question may select belongs to the OpenAPI phase. Reading the description
    /// before then would also put a document allowed to reach 16 MiB through the YAML tree on
    /// every keystroke, for symbols no walker asks for yet.
    pub(crate) fn is_indexed(self) -> bool {
        match self {
            Self::Marker
            | Self::Question
            | Self::Source
            | Self::Selector
            | Self::Schema
            | Self::Fixture
            | Self::AccessPolicy => true,
            Self::OpenApi | Self::Derivation => false,
        }
    }
}

/// The project directories that hold `<name>.yaml` documents, each with the role its documents
/// play. One table serves both the reading of a path and the loader that scans those directories,
/// so the two can never disagree about which directory means what.
pub(crate) const YAML_DIRECTORIES: &[(&str, DocumentRole)] = &[
    (QUESTIONS_DIRECTORY, DocumentRole::Question),
    (SOURCES_DIRECTORY, DocumentRole::Source),
    (SELECTORS_DIRECTORY, DocumentRole::Selector),
    (SCHEMAS_DIRECTORY, DocumentRole::Schema),
    (FIXTURES_DIRECTORY, DocumentRole::Fixture),
];

/// Where a project keeps its access policies, which sit one directory deeper than the rest.
pub(crate) fn access_policies_directory(root: &Path) -> PathBuf {
    root.join(ACCESS_DIRECTORY).join(ACCESS_POLICIES_DIRECTORY)
}

/// The role a root-relative path plays, or `None` when the path is not part of the authoring form.
///
/// Two refusals here are not layout rules but safety rules, so they are stated before anything
/// else can reach them. `secrets/` holds the key material a project signs with, and an editor that
/// reads a private key has already lost whatever the key protected, whatever it does with the
/// bytes afterwards. A dot-prefixed name is tooling state rather than authored input: `.evidence/`
/// holds the deployment a local run compiles, and reading it back would report a generated file's
/// problems to the author of the source it was generated from.
pub(crate) fn document_role(relative: &Path) -> Option<DocumentRole> {
    let names = normal_names(relative)?;
    if names.first() == Some(&SECRETS_DIRECTORY) {
        return None;
    }
    if names.iter().any(|name| name.starts_with('.')) {
        return None;
    }

    match names.as_slice() {
        [file] if *file == PROJECT_MARKER_FILE => Some(DocumentRole::Marker),
        [file] if *file == OPENAPI_FILE => Some(DocumentRole::OpenApi),
        [directory, file] if has_extension(file, "yaml") => YAML_DIRECTORIES
            .iter()
            .find(|(name, _)| name == directory)
            .map(|(_, role)| *role),
        [directory, file] if *directory == DERIVATIONS_DIRECTORY && has_extension(file, "rhai") => {
            Some(DocumentRole::Derivation)
        }
        [access, policies, file]
            if *access == ACCESS_DIRECTORY
                && *policies == ACCESS_POLICIES_DIRECTORY
                && has_extension(file, "yaml") =>
        {
            Some(DocumentRole::AccessPolicy)
        }
        _ => None,
    }
}

/// The path's components as plain names, or `None` if any of them is not one. A `..`, an absolute
/// path, a Windows prefix, or a name that is not UTF-8 all leave here: none of them can be a name
/// the authoring form gives to a part of a project.
fn normal_names(relative: &Path) -> Option<Vec<&str>> {
    relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect()
}

fn has_extension(file: &str, extension: &str) -> bool {
    Path::new(file)
        .extension()
        .is_some_and(|found| found == extension)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_every_part_of_the_authoring_form_from_its_path() {
        for (path, role) in [
            ("evidence-project.yaml", DocumentRole::Marker),
            ("source.openapi.yaml", DocumentRole::OpenApi),
            ("questions/adult-status.yaml", DocumentRole::Question),
            ("sources/people.yaml", DocumentRole::Source),
            ("selectors/person.yaml", DocumentRole::Selector),
            ("schemas/person.schema.yaml", DocumentRole::Schema),
            ("fixtures/adult.yaml", DocumentRole::Fixture),
            (
                "access/policies/adult-status.yaml",
                DocumentRole::AccessPolicy,
            ),
            ("derivations/adult-status.rhai", DocumentRole::Derivation),
        ] {
            assert_eq!(document_role(Path::new(path)), Some(role), "{path}");
        }
    }

    #[test]
    fn reads_nothing_from_a_path_outside_the_authoring_form() {
        for path in [
            "notes.yaml",
            "questions/adult-status.json",
            "questions/nested/adult-status.yaml",
            "derivations/adult-status.yaml",
            "access/clients/local.yaml",
            "access/policies/nested/adult-status.yaml",
            "evidence-project.yaml/child.yaml",
        ] {
            assert_eq!(document_role(Path::new(path)), None, "{path}");
        }
    }

    #[test]
    fn refuses_key_material_under_the_secrets_directory() {
        for path in [
            "secrets/signing.jwk.json",
            "secrets/local-signing-public.jwk.json",
            "secrets/questions/adult-status.yaml",
        ] {
            assert_eq!(document_role(Path::new(path)), None, "{path}");
        }
    }

    #[test]
    fn refuses_generated_state_under_a_dot_directory() {
        for path in [
            ".evidence/dev/bundle.yaml",
            ".evidence/questions/adult-status.yaml",
            ".git/config",
        ] {
            assert_eq!(document_role(Path::new(path)), None, "{path}");
        }
    }

    #[test]
    fn refuses_a_path_that_does_not_stay_inside_the_project() {
        for path in [
            "../questions/adult-status.yaml",
            "questions/../secrets/signing.jwk.json",
            "/etc/passwd",
            "/questions/adult-status.yaml",
            "./questions/adult-status.yaml",
        ] {
            assert_eq!(document_role(Path::new(path)), None, "{path}");
        }
    }

    #[test]
    fn every_role_is_held_to_the_authoring_form_s_own_ceiling() {
        for (role, ceiling) in [
            (DocumentRole::Marker, MAX_PROJECT_MARKER_BYTES),
            (DocumentRole::OpenApi, MAX_OPENAPI_BYTES),
            (DocumentRole::Question, MAX_QUESTION_BYTES),
            (DocumentRole::Source, MAX_SOURCE_ARTIFACT_BYTES),
            (DocumentRole::Selector, MAX_SOURCE_ARTIFACT_BYTES),
            (DocumentRole::Schema, MAX_SOURCE_ARTIFACT_BYTES),
            (DocumentRole::Fixture, MAX_SOURCE_ARTIFACT_BYTES),
            (DocumentRole::AccessPolicy, MAX_ACCESS_POLICY_BYTES),
            (DocumentRole::Derivation, MAX_DERIVATION_BYTES),
        ] {
            assert_eq!(role.max_bytes(), ceiling, "{role:?}");
        }
    }
}
