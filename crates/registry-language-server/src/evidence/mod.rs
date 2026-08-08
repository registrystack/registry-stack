// SPDX-License-Identifier: Apache-2.0
//! Evidence authoring projects: the shape an adopter writes under a project directory, safe
//! document loading, and the walker that turns those documents into indexed symbols.
//!
//! The names and ceilings come from `registry-evidence-authoring`, the library that holds the
//! single implementation of the authoring form. The editor reads a project the same way the
//! compiler does or it tells authors a story their build will contradict.

pub(crate) mod index;
pub(crate) mod layout;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use registry_evidence_authoring::{
    layout::{MAX_QUESTIONS, OPENAPI_FILE, QUESTIONS_DIRECTORY},
    marker::PROJECT_MARKER_FILE,
};

use crate::{
    refs::document_diagnostic,
    safety::{plain_directory, plain_file, secure_directory, secure_regular_file},
    workspace::LoadedProjectDocuments,
};

pub(crate) use index::build_index;
use layout::DocumentRole;

/// The file that marks a directory as an Evidence authoring project.
pub(crate) const PROJECT_FILE: &str = PROJECT_MARKER_FILE;

/// The most documents the server indexes from one project directory.
///
/// A project directory is an author's working area rather than an archive, and the authoring form
/// already holds one project to [`MAX_QUESTIONS`] questions. Past the ceiling the editor stops
/// reading instead of holding an unbounded part of the filesystem open, and names the first file
/// it did not read so that the silence is visible where the author is working.
const MAX_DOCUMENTS_PER_DIRECTORY: usize = MAX_QUESTIONS;

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
        if metadata.len() > role.max_bytes() {
            diagnostics.push(document_diagnostic(
                &path,
                &format!(
                    "This {} exceeds the {}-byte limit the editor indexes",
                    role.label(),
                    role.max_bytes()
                ),
            ));
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
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "failed to inspect an entry in a project directory under {}",
                root.display()
            )
        })?;
        let path = entry.path();
        if document_role(root, &path) == Some(role) && secure_regular_file(root, &path)?.is_some() {
            paths.push(path);
        }
    }

    paths.sort();
    if let Some(first_unread) = paths.get(MAX_DOCUMENTS_PER_DIRECTORY) {
        diagnostics.push(document_diagnostic(
            first_unread,
            &format!(
                "This project directory holds more than the {MAX_DOCUMENTS_PER_DIRECTORY} documents the editor indexes; this file and the ones after it are not indexed"
            ),
        ));
        paths.truncate(MAX_DOCUMENTS_PER_DIRECTORY);
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
                "fixtures/adult.yaml",
                "questions/adult-status.yaml",
                "schemas/person.schema.yaml",
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
    fn stops_reading_a_directory_at_the_document_ceiling() {
        let temp = TempDir::new().unwrap();
        write(temp.path(), PROJECT_FILE, default_project_marker_document());
        for index in 0..MAX_DOCUMENTS_PER_DIRECTORY + 1 {
            write(
                temp.path(),
                &format!("questions/question-{index:03}.yaml"),
                "id: question\n",
            );
        }
        let root = temp.path().canonicalize().unwrap();

        let loaded = load_project_documents(&root).unwrap();

        assert_eq!(loaded.documents.len(), MAX_DOCUMENTS_PER_DIRECTORY + 1);
        assert_eq!(loaded.diagnostics.len(), 1, "{:?}", loaded.diagnostics);
        assert_eq!(
            loaded.diagnostics[0].path,
            root.join(format!(
                "questions/question-{MAX_DOCUMENTS_PER_DIRECTORY:03}.yaml"
            ))
        );
        assert!(loaded.diagnostics[0]
            .message
            .contains("more than the 128 documents"));
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
        symlink(outside.path(), temp.path().join("selectors")).ok();
        let root = temp.path().canonicalize().unwrap();

        let loaded = load_project_documents(&root).unwrap();

        assert!(!relative_documents(&root, &loaded)
            .iter()
            .any(|path| path.contains("linked")));
        assert!(!is_safe_authored_file(
            &root,
            &root.join("questions/linked.yaml")
        ));
    }
}
