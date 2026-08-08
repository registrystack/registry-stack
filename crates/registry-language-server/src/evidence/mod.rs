// SPDX-License-Identifier: Apache-2.0
//! Evidence authoring projects: the shape an adopter writes under a project directory, safe
//! document loading, and the walker that turns those documents into indexed symbols.
//!
//! The names and ceilings come from `registry-evidence-authoring`, the library that holds the
//! single implementation of the authoring form. The editor reads a project the same way the
//! compiler does or it tells authors a story their build will contradict.

pub(crate) mod diagnostics;
pub(crate) mod index;
pub(crate) mod layout;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use registry_evidence_authoring::{
    layout::{OPENAPI_FILE, QUESTIONS_DIRECTORY},
    marker::PROJECT_MARKER_FILE,
};

use crate::{
    refs::document_diagnostic,
    safety::{plain_directory, plain_file, secure_directory, secure_regular_file},
    workspace::{DocumentCeiling, LoadedProjectDocuments},
};

pub(crate) use index::build_index;
use layout::DocumentRole;

/// The file that marks a directory as an Evidence authoring project.
pub(crate) const PROJECT_FILE: &str = PROJECT_MARKER_FILE;

/// Whether a directory is an Evidence authoring project root.
///
/// The marker is the direct answer. The pair below it is the answer for every project written
/// before the marker existed: an authoring project has always had to carry one OpenAPI description
/// and a directory of questions, so a directory with both is one, and requiring a migration before
/// an editor would open it would be a demand made of authors for the editor's convenience.
///
/// A symbolic link declares nothing, at either name. A link is how a directory borrows a shape it
/// does not have, and a borrowed shape must not anchor a root that the loader will then read files
/// from.
pub(crate) fn declares_root(directory: &Path) -> bool {
    plain_file(&directory.join(PROJECT_FILE))
        || (plain_file(&directory.join(OPENAPI_FILE))
            && plain_directory(&directory.join(QUESTIONS_DIRECTORY)))
}

/// Whether a path is a document this root indexes.
pub(crate) fn is_project_document(root: &Path, path: &Path) -> bool {
    document_role(root, path).is_some_and(DocumentRole::is_indexed)
}

/// Whether a path is a file the server may open under this root.
///
/// Containment alone is not the whole answer here, as it is for Relay. A project holds key
/// material and generated state inside its own root, both of them contained and neither of them
/// authored input, so the layout has to agree before the file is opened.
pub(crate) fn is_safe_authored_file(root: &Path, path: &Path) -> bool {
    is_project_document(root, path) && crate::safety::is_safe_authored_file(root, path)
}

/// How large a document at this path may be for the editor to read it, and the sentence an author
/// reads when it is larger.
///
/// A path the authoring form does not name is not a document this root indexes, so the loader never
/// asks about one. A caller that asks anyway is answered with a bound rather than with none.
pub(crate) fn document_ceiling(root: &Path, path: &Path) -> DocumentCeiling {
    document_role(root, path).map_or_else(DocumentCeiling::project_document, role_ceiling)
}

/// The most documents the editor reads from the directory that holds this path, for the directories
/// the authoring form bounds.
pub(crate) fn max_documents_per_directory(root: &Path, path: &Path) -> Option<usize> {
    document_role(root, path).and_then(DocumentRole::max_documents)
}

/// The ceiling one role carries, written once so that the first scan of a project, a buffer the
/// client has open, and a change that arrived from disk all answer a document's size the same way.
fn role_ceiling(role: DocumentRole) -> DocumentCeiling {
    DocumentCeiling {
        max_bytes: role.max_bytes(),
        message: format!(
            "This {} exceeds the {}-byte limit the editor indexes",
            role.label(),
            role.max_bytes()
        ),
    }
}

/// Reads the documents of one Evidence authoring project.
///
/// A missing marker is not a failure, unlike Relay's missing manifest. A project that predates the
/// marker is still an authoring project, and it is discovered from the description and questions
/// every project carries, so the loader has nothing to refuse: the documents it finds are the
/// documents there are.
pub(crate) fn load_project_documents(root: &Path) -> Result<LoadedProjectDocuments> {
    let mut diagnostics = Vec::new();
    let mut candidates = vec![(root.join(PROJECT_FILE), DocumentRole::Marker)];
    for (directory, role) in layout::YAML_DIRECTORIES {
        if !role.is_indexed() {
            continue;
        }
        add_documents(
            root,
            &root.join(directory),
            *role,
            &mut candidates,
            &mut diagnostics,
        )?;
    }
    add_documents(
        root,
        &layout::access_policies_directory(root),
        DocumentRole::AccessPolicy,
        &mut candidates,
        &mut diagnostics,
    )?;

    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    candidates.dedup_by(|left, right| left.0 == right.0);
    let mut documents = BTreeMap::new();
    for (path, role) in candidates {
        let Some(metadata) = secure_regular_file(root, &path)? else {
            continue;
        };
        let ceiling = role_ceiling(role);
        if metadata.len() > ceiling.max_bytes {
            diagnostics.push(document_diagnostic(&path, &ceiling.message));
            continue;
        }
        match fs::read(&path) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(source) => {
                    documents.insert(path, source);
                }
                Err(_) => diagnostics.push(document_diagnostic(
                    &path,
                    "Project document is not valid UTF-8 and cannot be indexed",
                )),
            },
            Err(_) => diagnostics.push(document_diagnostic(
                &path,
                "Project document could not be read; check its permissions",
            )),
        }
    }

    Ok(LoadedProjectDocuments {
        documents,
        diagnostics,
    })
}

/// Adds the documents one project directory holds in `role`. The directory is read once and never
/// descended into: a project's parts are all one directory deep, so a subdirectory holds something
/// the authoring form did not put there.
///
/// Only the roles the authoring form bounds are truncated here, and a directory it does not bound
/// is read whole: a ceiling the editor applies where the compiler applies none turns a definition
/// the build resolves into an unresolved reference on screen.
///
/// The names of a bounded directory are collected into a set that never holds more than one name
/// past its ceiling, because a ceiling on what is read is not a ceiling on what is enumerated. A
/// directory holding a million entries would otherwise be gathered whole and thrown away, and the
/// one name past the ceiling is kept so the first unread file can be named. Whether an entry is a
/// file the server may open is settled once, by the reader, rather than by a second secure walk of
/// every path here.
fn add_documents(
    root: &Path,
    directory: &Path,
    role: DocumentRole,
    candidates: &mut Vec<(PathBuf, DocumentRole)>,
    diagnostics: &mut Vec<crate::refs::IndexedDiagnostic>,
) -> Result<()> {
    if !secure_directory(root, directory)? {
        return Ok(());
    }
    let entries = fs::read_dir(directory).with_context(|| {
        format!(
            "failed to inspect a project directory under {}",
            root.display()
        )
    })?;
    let ceiling = role.max_documents();
    let mut named = BTreeSet::new();
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "failed to inspect an entry in a project directory under {}",
                root.display()
            )
        })?;
        let path = entry.path();
        if document_role(root, &path) != Some(role) {
            continue;
        }
        named.insert(path);
        if let Some(ceiling) = ceiling {
            if named.len() > ceiling + 1 {
                named.pop_last();
            }
        }
    }

    let mut paths = named.into_iter().collect::<Vec<_>>();
    if let Some(ceiling) = ceiling {
        if let Some(first_unread) = paths.get(ceiling) {
            diagnostics.push(document_diagnostic(
                first_unread,
                &format!(
                    "This project directory holds more than the {ceiling} documents the editor indexes; this file and the ones after it are not indexed"
                ),
            ));
            paths.truncate(ceiling);
        }
    }
    candidates.extend(paths.into_iter().map(|path| (path, role)));
    Ok(())
}

/// The role a path plays under `root`, for a path that is under it at all.
fn document_role(root: &Path, path: &Path) -> Option<DocumentRole> {
    layout::document_role(path.strip_prefix(root).ok()?)
}

#[cfg(test)]
mod tests {
    use registry_evidence_authoring::marker::default_project_marker_document;
    use tempfile::TempDir;

    use super::*;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("fixture path has parent")).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// A project with one file in every part of the authoring form, including the two parts the
    /// server must not read.
    fn fixture_project() -> TempDir {
        let temp = TempDir::new().unwrap();
        write(temp.path(), PROJECT_FILE, default_project_marker_document());
        write(temp.path(), OPENAPI_FILE, "openapi: 3.1.0\n");
        write(
            temp.path(),
            "questions/adult-status.yaml",
            "id: adult-status\n",
        );
        write(temp.path(), "sources/people.yaml", "kind: http\n");
        write(temp.path(), "selectors/person.yaml", "kind: exact\n");
        write(temp.path(), "schemas/person.schema.yaml", "type: object\n");
        write(temp.path(), "fixtures/adult.yaml", "name: adult\n");
        write(
            temp.path(),
            "access/policies/adult-status.yaml",
            "version: 1\n",
        );
        write(
            temp.path(),
            "derivations/adult-status.rhai",
            "answer(true)\n",
        );
        write(temp.path(), "secrets/local-signing.jwk.json", "{}\n");
        write(temp.path(), ".evidence/dev/bundle.yaml", "id: generated\n");
        temp
    }

    fn relative_documents(root: &Path, loaded: &LoadedProjectDocuments) -> Vec<String> {
        loaded
            .documents
            .keys()
            .map(|path| {
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    #[test]
    fn loads_the_documents_the_walkers_read_and_leaves_the_rest_on_disk() {
        let temp = fixture_project();
        let root = temp.path().canonicalize().unwrap();

        let loaded = load_project_documents(&root).unwrap();

        assert_eq!(
            relative_documents(&root, &loaded),
            vec![
                "access/policies/adult-status.yaml",
                "evidence-project.yaml",
                "questions/adult-status.yaml",
                "selectors/person.yaml",
                "sources/people.yaml",
            ]
        );
        assert!(loaded.diagnostics.is_empty(), "{:?}", loaded.diagnostics);
    }

    #[test]
    fn key_material_is_neither_a_project_document_nor_a_safe_authored_file() {
        let temp = fixture_project();
        let root = temp.path().canonicalize().unwrap();
        let secret = root.join("secrets/local-signing.jwk.json");
        assert!(
            secret.is_file(),
            "the fixture must place a real file under secrets/"
        );

        assert!(!is_project_document(&root, &secret));
        assert!(!is_safe_authored_file(&root, &secret));
        assert!(!load_project_documents(&root)
            .unwrap()
            .documents
            .contains_key(&secret));
    }

    #[test]
    fn generated_state_is_neither_a_project_document_nor_a_safe_authored_file() {
        let temp = fixture_project();
        let root = temp.path().canonicalize().unwrap();
        let generated = root.join(".evidence/dev/bundle.yaml");
        assert!(
            generated.is_file(),
            "the fixture must place a real file under .evidence/"
        );

        assert!(!is_project_document(&root, &generated));
        assert!(!is_safe_authored_file(&root, &generated));
        assert!(!load_project_documents(&root)
            .unwrap()
            .documents
            .contains_key(&generated));
    }

    #[test]
    fn a_project_without_a_marker_still_loads_its_documents() {
        let temp = TempDir::new().unwrap();
        write(temp.path(), OPENAPI_FILE, "openapi: 3.1.0\n");
        write(
            temp.path(),
            "questions/adult-status.yaml",
            "id: adult-status\n",
        );
        let root = temp.path().canonicalize().unwrap();

        let loaded = load_project_documents(&root).unwrap();

        assert_eq!(
            relative_documents(&root, &loaded),
            vec!["questions/adult-status.yaml"]
        );
        assert!(loaded.diagnostics.is_empty(), "{:?}", loaded.diagnostics);
    }

    #[test]
    fn reports_a_document_it_cannot_index() {
        let temp = TempDir::new().unwrap();
        write(temp.path(), PROJECT_FILE, default_project_marker_document());
        write(
            temp.path(),
            "questions/adult-status.yaml",
            "id: adult-status\n",
        );
        let oversized = vec![b' '; DocumentRole::Question.max_bytes() as usize + 1];
        fs::write(temp.path().join("questions/oversized.yaml"), oversized).unwrap();
        fs::write(temp.path().join("questions/binary.yaml"), [0xff, 0xfe]).unwrap();
        let root = temp.path().canonicalize().unwrap();

        let loaded = load_project_documents(&root).unwrap();

        assert_eq!(
            relative_documents(&root, &loaded),
            vec!["evidence-project.yaml", "questions/adult-status.yaml"]
        );
        let messages = loaded
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect::<Vec<_>>();
        assert!(
            messages.contains(&"This question exceeds the 65536-byte limit the editor indexes"),
            "{messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("is not valid UTF-8")),
            "{messages:?}"
        );
    }

    #[test]
    fn stops_reading_a_directory_at_the_ceiling_the_authoring_form_sets() {
        let ceiling = DocumentRole::Question
            .max_documents()
            .expect("the authoring form bounds a project's questions");
        let temp = TempDir::new().unwrap();
        write(temp.path(), PROJECT_FILE, default_project_marker_document());
        for index in 0..ceiling + 1 {
            write(
                temp.path(),
                &format!("questions/question-{index:03}.yaml"),
                "id: question\n",
            );
        }
        let root = temp.path().canonicalize().unwrap();

        let loaded = load_project_documents(&root).unwrap();

        assert_eq!(loaded.documents.len(), ceiling + 1);
        assert_eq!(loaded.diagnostics.len(), 1, "{:?}", loaded.diagnostics);
        assert_eq!(
            loaded.diagnostics[0].path,
            root.join(format!("questions/question-{ceiling:03}.yaml"))
        );
        assert!(loaded.diagnostics[0]
            .message
            .contains("more than the 128 documents"));
    }

    /// `evidencectl` reads every selector and source a project holds, so the editor does too. A
    /// ceiling only the editor has would leave every question naming the file past it reporting an
    /// unknown selector profile against a project the compiler builds.
    #[test]
    fn reads_every_document_of_a_directory_the_authoring_form_does_not_bound() {
        let beyond_a_bounded_directory = DocumentRole::Question
            .max_documents()
            .expect("the authoring form bounds a project's questions")
            + 1;
        let temp = TempDir::new().unwrap();
        write(temp.path(), PROJECT_FILE, default_project_marker_document());
        for index in 0..beyond_a_bounded_directory {
            write(
                temp.path(),
                &format!("selectors/profile-{index:03}.yaml"),
                "kind: exact\n",
            );
        }
        let root = temp.path().canonicalize().unwrap();

        let loaded = load_project_documents(&root).unwrap();

        assert_eq!(loaded.documents.len(), beyond_a_bounded_directory + 1);
        assert!(loaded.diagnostics.is_empty(), "{:?}", loaded.diagnostics);
    }

    /// A schema and a fixture are defined by the document that points at one, from the path it
    /// wrote, so nothing in the index comes from their own content and the loader leaves them where
    /// they are.
    #[test]
    fn leaves_the_roles_no_walker_reads_on_disk() {
        let temp = fixture_project();
        let root = temp.path().canonicalize().unwrap();

        let loaded = load_project_documents(&root).unwrap();

        assert!(
            root.join("schemas/person.schema.yaml").is_file()
                && root.join("fixtures/adult.yaml").is_file(),
            "the fixture must place a real schema and a real fixture"
        );
        assert!(!relative_documents(&root, &loaded)
            .iter()
            .any(|path| path.starts_with("schemas/") || path.starts_with("fixtures/")));
        assert!(!is_project_document(
            &root,
            &root.join("schemas/person.schema.yaml")
        ));
        assert!(!is_project_document(
            &root,
            &root.join("fixtures/adult.yaml")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_document_reached_through_a_symbolic_link_is_not_loaded() {
        use std::os::unix::fs::symlink;

        let temp = fixture_project();
        let outside = TempDir::new().unwrap();
        write(outside.path(), "question.yaml", "id: outside-question\n");
        symlink(
            outside.path().join("question.yaml"),
            temp.path().join("questions/linked.yaml"),
        )
        .unwrap();
        // A whole directory replaced by a link, which is the other half of the same hazard. The
        // fixture writes a real selectors/ directory, so it has to go before the link can take its
        // name, and the link is unwrapped: a test that cannot build the dangerous artifact proves
        // nothing about refusing it.
        let linked_directory = temp.path().join("selectors");
        fs::remove_dir_all(&linked_directory).unwrap();
        symlink(outside.path(), &linked_directory).unwrap();
        assert!(
            fs::symlink_metadata(&linked_directory)
                .is_ok_and(|metadata| metadata.file_type().is_symlink()),
            "the fixture must replace the directory with a link"
        );
        let root = temp.path().canonicalize().unwrap();

        let loaded = load_project_documents(&root).unwrap();

        assert!(!relative_documents(&root, &loaded)
            .iter()
            .any(|path| path.contains("linked")));
        assert!(!is_safe_authored_file(
            &root,
            &root.join("questions/linked.yaml")
        ));
        assert!(
            !relative_documents(&root, &loaded)
                .iter()
                .any(|path| path.starts_with("selectors")),
            "nothing behind a linked directory is read"
        );
        assert!(!is_safe_authored_file(
            &root,
            &root.join("selectors/question.yaml")
        ));
    }
}
