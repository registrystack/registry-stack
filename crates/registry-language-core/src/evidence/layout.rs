// SPDX-License-Identifier: Apache-2.0
//! What an authored file is, read from where it sits: the part a root-relative path plays in an
//! Evidence authoring project, and the parts of a project the server must never open.

use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

use registry_evidence_authoring::{
    layout::{
        ACCESS_DIRECTORY, ACCESS_POLICIES_DIRECTORY, DERIVATIONS_DIRECTORY, FIXTURES_DIRECTORY,
        MAX_ACCESS_POLICY_BYTES, MAX_CONCEPTS, MAX_DERIVATION_BYTES, MAX_OPENAPI_BYTES,
        MAX_PROJECT_MARKER_BYTES, MAX_QUESTIONS, MAX_QUESTION_BYTES, MAX_SOURCE_ARTIFACT_BYTES,
        OPENAPI_FILE, QUESTIONS_DIRECTORY, SCHEMAS_DIRECTORY, SECRETS_DIRECTORY,
        SELECTORS_DIRECTORY, SOURCES_DIRECTORY,
    },
    marker::PROJECT_MARKER_FILE,
};

/// The part one authored file plays in a project.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DocumentRole {
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
    pub fn max_bytes(self) -> u64 {
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

    /// The most documents of this role one project directory holds, for the roles the authoring
    /// form bounds.
    ///
    /// The bound is the compiler's own. `evidencectl` refuses a project that holds more than
    /// [`MAX_QUESTIONS`] questions or more than that many access policies, and reads every
    /// selector, source, schema, and fixture a project holds. The editor stops where the compiler
    /// stops and nowhere else: a ceiling only the editor has turns a name the build resolves into
    /// an unresolved reference on screen, which is a diagnostic the author cannot act on.
    pub fn max_documents(self) -> Option<usize> {
        match self {
            Self::Question | Self::AccessPolicy => Some(MAX_QUESTIONS),
            Self::Marker
            | Self::OpenApi
            | Self::Source
            | Self::Selector
            | Self::Schema
            | Self::Fixture
            | Self::Derivation => None,
        }
    }

    /// The name this role goes by in a message an author reads.
    pub fn label(self) -> &'static str {
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
    ///
    /// A schema and a fixture are classified for the same reason and read for none. Neither is
    /// named by anything written inside it: the document that points at one defines it, from the
    /// path it wrote and the file that sits at that path, so no symbol, reference, or diagnostic in
    /// the index comes from a schema's or a fixture's own content. Reading them would put a
    /// recorded response, which the form allows to reach 1 MiB, through the YAML tree on every
    /// keystroke in an unrelated question.
    ///
    /// Their names are another matter, and [`pointed_directory`] is where they are read: the list an
    /// author picks a path from is the files that directory holds, which is a listing and opens
    /// nothing.
    pub fn is_indexed(self) -> bool {
        match self {
            Self::Marker | Self::Question | Self::Source | Self::Selector | Self::AccessPolicy => {
                true
            }
            Self::OpenApi | Self::Schema | Self::Fixture | Self::Derivation => false,
        }
    }

    /// Whether a build of the index opens this role's file itself.
    ///
    /// The OpenAPI description is the one part of the form that is read at every build and held in
    /// no root: the four edges a compact-form question spells are resolved against the operations
    /// it publishes. So an author who adds an operation to it changes what every question in the
    /// project resolves to, while changing no document a root holds, and nothing they can type in a
    /// question would answer the reports standing over it. A save of a file this answers for has to
    /// be a build.
    ///
    /// A schema, a fixture, and a derivation are read by nothing here, so their files answer no.
    /// What a document pointing at one of them needs is that a file sits there, which the watcher
    /// and the pointer's own definition already settle.
    pub fn is_read_by_a_build(self) -> bool {
        match self {
            Self::OpenApi => true,
            Self::Marker
            | Self::Question
            | Self::Source
            | Self::Selector
            | Self::Schema
            | Self::Fixture
            | Self::AccessPolicy
            | Self::Derivation => false,
        }
    }
}

/// The project directories that hold `<name>.yaml` documents, each with the role its documents
/// play. One table serves both the reading of a path and the loader that scans those directories,
/// so the two can never disagree about which directory means what.
pub const YAML_DIRECTORIES: &[(&str, DocumentRole)] = &[
    (QUESTIONS_DIRECTORY, DocumentRole::Question),
    (SOURCES_DIRECTORY, DocumentRole::Source),
    (SELECTORS_DIRECTORY, DocumentRole::Selector),
    (SCHEMAS_DIRECTORY, DocumentRole::Schema),
    (FIXTURES_DIRECTORY, DocumentRole::Fixture),
];

/// The project directory a role's documents sit in, for the three roles a document points at by
/// writing a path rather than by spelling a name.
///
/// These are the directories a list of the files such a pointer may name is read from. They are the
/// roles [`DocumentRole::is_indexed`] leaves out, so the loader never visits them and the names in
/// them would otherwise reach an author only once some document had already written one.
pub fn pointed_directory(role: DocumentRole) -> Option<&'static str> {
    match role {
        DocumentRole::Schema => Some(SCHEMAS_DIRECTORY),
        DocumentRole::Fixture => Some(FIXTURES_DIRECTORY),
        DocumentRole::Derivation => Some(DERIVATIONS_DIRECTORY),
        DocumentRole::Marker
        | DocumentRole::OpenApi
        | DocumentRole::Question
        | DocumentRole::Source
        | DocumentRole::Selector
        | DocumentRole::AccessPolicy => None,
    }
}

/// The most files one [`pointed_directory`] offers a pointer at that role.
///
/// The number is the authoring form's own, read the way [`DocumentRole::max_documents`] reads its
/// ceilings: a project declares at most [`MAX_QUESTIONS`] questions, one question answers at most
/// [`MAX_CONCEPTS`] concepts, and each of those names at most one file, so no project the compiler
/// accepts can usefully name more files of one role than this.
///
/// It bounds what the editor volunteers and nothing else, which is why it does not fall under the
/// rule that the editor stops where the compiler stops. A pointer at a file past the ceiling still
/// resolves, still navigates, and is still defined by the document that spells it, because the file
/// a pointer names is defined from the pointer. A directory holding more entries than this offers
/// fewer of them and says nothing about it: a list nobody bounded is a list a directory of a million
/// entries gets to build on every keystroke.
pub const MAX_POINTED_FILES_OFFERED: usize = MAX_QUESTIONS * MAX_CONCEPTS;

/// The extensions an authored document may carry: `yaml` for the marker, the OpenAPI description,
/// every directory in [`YAML_DIRECTORIES`], and access policies, and `rhai` for a derivation. This is
/// the list the watcher asks a client about, so a role the index can be read from cannot exist
/// without the session being told when such a file changes, which is what keeps a diagnostic from
/// standing over a project the compiler accepts.
pub const AUTHORED_FILE_EXTENSIONS: &[&str] = &["yaml", "rhai"];

/// Where a source keeps the scripts and schemas its own traffic uses, beside [`SCHEMAS_DIRECTORY`].
/// The authoring library names the second of the two directories the compiler reads a source's
/// artifacts from, so the first is spelled here beside the rule that needs it.
const ADAPTERS_DIRECTORY: &str = "adapters";

/// The project directories the compiler reads a source's own artifacts from. One table serves both
/// the reading of such a path and the watcher registration that asks a client to report those
/// files, so the two can never disagree about which directory means what.
pub const SOURCE_ARTIFACT_DIRECTORIES: &[&str] = &[ADAPTERS_DIRECTORY, SCHEMAS_DIRECTORY];

/// The globs a client is asked to report changes for: one per extension an authored document may
/// carry, and one per directory a source's artifacts sit in.
///
/// The two halves are read from different tables because the form reads the two kinds of path
/// differently. An authored document is found by its role, which is spelled with an extension, so
/// its glob is that extension anywhere. A source's artifact is found by the directory it sits in
/// and may carry any extension at all or none, so nothing about its name would cover it and only
/// the directory does. Each glob's last segment is a single `*`, matching the rule in
/// [`is_source_artifact`] that such a path is two components and not more.
pub fn watched_globs() -> Vec<String> {
    AUTHORED_FILE_EXTENSIONS
        .iter()
        .map(|extension| format!("**/*.{extension}"))
        .chain(
            SOURCE_ARTIFACT_DIRECTORIES
                .iter()
                .map(|directory| format!("**/{directory}/*")),
        )
        .collect()
}

/// Whether a path is one the compiler reads a source's own artifact from: two ordinary components
/// whose first is in [`SOURCE_ARTIFACT_DIRECTORIES`], and any extension at all.
pub fn is_source_artifact(relative: &Path) -> bool {
    let components = relative.components().collect::<Vec<_>>();
    let [Component::Normal(directory), Component::Normal(_)] = components.as_slice() else {
        return false;
    };
    SOURCE_ARTIFACT_DIRECTORIES
        .iter()
        .any(|name| *directory == OsStr::new(name))
}

/// Where a project keeps its access policies, which sit one directory deeper than the rest.
pub fn access_policies_directory(root: &Path) -> PathBuf {
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
pub fn document_role(relative: &Path) -> Option<DocumentRole> {
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

    /// One representative path per [`DocumentRole`], shared by every test that needs to visit each
    /// role once: a role added here without a path is a role no test below can see.
    const ONE_PATH_PER_ROLE: &[(&str, DocumentRole)] = &[
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
    ];

    #[test]
    fn reads_every_part_of_the_authoring_form_from_its_path() {
        for (path, role) in ONE_PATH_PER_ROLE.iter().copied() {
            assert_eq!(document_role(Path::new(path)), Some(role), "{path}");
        }
    }

    /// The tie against drift: a role read from an extension [`AUTHORED_FILE_EXTENSIONS`] does not
    /// list is a role whose watcher silently stopped covering it, which is exactly the gap that let
    /// a derivation file created outside the editor stand behind an unresolved reference. Reusing
    /// [`ONE_PATH_PER_ROLE`] means a role added above without extending the watcher list fails here
    /// instead of only losing its watcher.
    #[test]
    fn every_role_s_path_carries_an_extension_the_watcher_covers() {
        for (path, role) in ONE_PATH_PER_ROLE.iter().copied() {
            assert!(
                AUTHORED_FILE_EXTENSIONS
                    .iter()
                    .any(|extension| has_extension(path, extension)),
                "{role:?} is read from {path}, whose extension the watcher does not cover: \
                 {AUTHORED_FILE_EXTENSIONS:?}"
            );
        }
    }

    /// The same tie for the dependency no role covers. A source's artifact is read from the
    /// directory it sits in and carries any extension at all, so nothing about its name says a
    /// watcher hears about it and only the registration does. A path this rule accepts that no glob
    /// covers is a file an author can create outside the editor while the report over the document
    /// that points at it stands.
    #[test]
    fn every_source_artifact_path_is_covered_by_a_registered_glob() {
        assert!(
            !glob_covers("**/adapters/*", "adapters/nested/people.json"),
            "a single `*` stands for one segment, which is what makes this table meaningful"
        );

        for path in [
            "adapters/people-request.rhai",
            "adapters/people-facts.json",
            "adapters/people-facts",
            "schemas/person.schema.yaml",
            "schemas/person.schema.json",
        ] {
            assert!(is_source_artifact(Path::new(path)), "{path}");
            let globs = watched_globs();
            assert!(
                globs.iter().any(|glob| glob_covers(glob, path)),
                "{path} is read by the compiler and covered by no registered glob: {globs:?}"
            );
        }
    }

    /// Whether one registered glob covers a path. The patterns are the ones [`watched_globs`]
    /// writes and nothing else: a `**/` prefix over segments holding at most one `*` each. A client
    /// answers this question with its own matcher; what is asserted here is that the pattern names
    /// the file at all.
    fn glob_covers(pattern: &str, path: &str) -> bool {
        let Some(tail) = pattern.strip_prefix("**/") else {
            return false;
        };
        let segments = tail.split('/').collect::<Vec<_>>();
        let names = path.split('/').collect::<Vec<_>>();
        let Some(start) = names.len().checked_sub(segments.len()) else {
            return false;
        };
        names[start..]
            .iter()
            .zip(segments)
            .all(|(name, segment)| match segment.split_once('*') {
                None => segment == *name,
                Some((prefix, suffix)) => {
                    name.len() >= prefix.len() + suffix.len()
                        && name.starts_with(prefix)
                        && name.ends_with(suffix)
                }
            })
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

    /// The compiler bounds a project's questions and its access policies and reads every selector,
    /// source, schema, and fixture there is. The editor stops where the compiler stops and nowhere
    /// else, so this table is the compiler's.
    #[test]
    fn only_the_directories_the_authoring_form_bounds_are_bounded() {
        for (role, ceiling) in [
            (DocumentRole::Marker, None),
            (DocumentRole::OpenApi, None),
            (DocumentRole::Question, Some(MAX_QUESTIONS)),
            (DocumentRole::Source, None),
            (DocumentRole::Selector, None),
            (DocumentRole::Schema, None),
            (DocumentRole::Fixture, None),
            (DocumentRole::AccessPolicy, Some(MAX_QUESTIONS)),
            (DocumentRole::Derivation, None),
        ] {
            assert_eq!(role.max_documents(), ceiling, "{role:?}");
        }
    }

    #[test]
    fn only_the_description_is_read_by_a_build_without_being_indexed() {
        for (role, read) in [
            (DocumentRole::Marker, false),
            (DocumentRole::OpenApi, true),
            (DocumentRole::Question, false),
            (DocumentRole::Source, false),
            (DocumentRole::Selector, false),
            (DocumentRole::Schema, false),
            (DocumentRole::Fixture, false),
            (DocumentRole::AccessPolicy, false),
            (DocumentRole::Derivation, false),
        ] {
            assert_eq!(role.is_read_by_a_build(), read, "{role:?}");
            assert!(
                !(role.is_indexed() && read),
                "{role:?} is indexed, so a root already answers for its text"
            );
        }
    }

    /// A directory is listed for exactly the roles a document names by writing a path, and the
    /// directory it names is the one that role's own representative path sits in. A role listed here
    /// that the loader also indexes would be a directory read twice for two answers.
    #[test]
    fn only_the_roles_a_pointer_names_by_path_are_listed() {
        for (role, directory) in [
            (DocumentRole::Marker, None),
            (DocumentRole::OpenApi, None),
            (DocumentRole::Question, None),
            (DocumentRole::Source, None),
            (DocumentRole::Selector, None),
            (DocumentRole::Schema, Some(SCHEMAS_DIRECTORY)),
            (DocumentRole::Fixture, Some(FIXTURES_DIRECTORY)),
            (DocumentRole::AccessPolicy, None),
            (DocumentRole::Derivation, Some(DERIVATIONS_DIRECTORY)),
        ] {
            assert_eq!(pointed_directory(role), directory, "{role:?}");
            assert!(
                !(role.is_indexed() && directory.is_some()),
                "{role:?} is indexed, so the loader already reads the directory it sits in"
            );
        }

        for (path, role) in ONE_PATH_PER_ROLE.iter().copied() {
            let Some(directory) = pointed_directory(role) else {
                continue;
            };
            assert_eq!(
                Path::new(path).parent().and_then(Path::to_str),
                Some(directory),
                "{path}"
            );
        }
    }

    #[test]
    fn every_role_says_whether_the_server_reads_it() {
        for (role, indexed) in [
            (DocumentRole::Marker, true),
            (DocumentRole::OpenApi, false),
            (DocumentRole::Question, true),
            (DocumentRole::Source, true),
            (DocumentRole::Selector, true),
            (DocumentRole::Schema, false),
            (DocumentRole::Fixture, false),
            (DocumentRole::AccessPolicy, true),
            (DocumentRole::Derivation, false),
        ] {
            assert_eq!(role.is_indexed(), indexed, "{role:?}");
        }
    }
}
