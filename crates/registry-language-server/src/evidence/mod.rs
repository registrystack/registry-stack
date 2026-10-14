// SPDX-License-Identifier: Apache-2.0
//! Bounded loading for the single normalized Evidence authoring model.
pub(crate) mod diagnostics;
pub(crate) mod index;
pub(crate) mod layout;
use crate::{
    refs::{
        document_diagnostic, document_rule_diagnostic, DOCUMENT_CEILING_RULE, PROJECT_CEILING_RULE,
    },
    safety::{plain_file, secure_directory, secure_regular_file, SecureFileRead},
    workspace::{
        DocumentCeiling, LoadedProjectDocuments, ProjectFamily, MAX_INDEXED_PROJECT_BYTES,
        MAX_INDEXED_PROJECT_DOCUMENTS, PROJECT_CEILING_MESSAGE,
    },
};
use anyhow::Result;
pub(crate) use index::build_index;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
pub(crate) const PROJECT_FILE: &str = registry_evidence_authoring::project::PROJECT_FILE;
pub(crate) fn declares_root(directory: &Path) -> bool {
    plain_file(&directory.join(PROJECT_FILE))
}
pub(crate) fn is_project_document(root: &Path, path: &Path) -> bool {
    path.strip_prefix(root)
        .ok()
        .and_then(layout::document_role)
        .is_some_and(layout::DocumentRole::is_indexed)
}
pub(crate) fn is_read_by_a_build(_root: &Path, _path: &Path) -> bool {
    false
}
pub(crate) fn is_safe_authored_file(root: &Path, path: &Path) -> bool {
    is_project_document(root, path) && crate::safety::is_safe_authored_file(root, path)
}
pub(crate) fn document_ceiling(root: &Path, path: &Path) -> DocumentCeiling {
    path.strip_prefix(root)
        .ok()
        .and_then(layout::document_role)
        .map_or_else(DocumentCeiling::project_document, |role| DocumentCeiling {
            max_bytes: role.max_bytes(),
            message: format!(
                "This {} exceeds the {}-byte limit the editor indexes",
                role.label(),
                role.max_bytes()
            ),
        })
}
pub(crate) fn bounded_directory_of(_root: &Path, _path: &Path) -> Option<PathBuf> {
    None
}
pub(crate) struct ScannedDirectory {
    pub(crate) admitted: Vec<PathBuf>,
    pub(crate) diagnostics: Vec<crate::refs::IndexedDiagnostic>,
}
pub(crate) fn scan_bounded_directory(
    _root: &Path,
    _path: &Path,
) -> Result<Option<ScannedDirectory>> {
    Ok(None)
}
pub(crate) fn load_project_documents(root: &Path) -> Result<LoadedProjectDocuments> {
    let mut candidates = Vec::new();
    let mut directories = vec![root.to_path_buf()];
    // Bound names as well as bytes, and never follow symbolic links or enter private state.
    let mut enumerated = 0usize;
    while let Some(directory) = directories.pop() {
        if !secure_directory(root, &directory)? {
            continue;
        }
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            enumerated += 1;
            if enumerated > MAX_INDEXED_PROJECT_DOCUMENTS * 16 {
                return Ok(blocked_project(&root.join(PROJECT_FILE)));
            }
            let Some(name) = path.file_name().and_then(|x| x.to_str()) else {
                continue;
            };
            if name.starts_with('.')
                || matches!(name, "secrets" | "node_modules" | "target" | "__pycache__")
            {
                continue;
            }
            if path.symlink_metadata()?.file_type().is_dir() {
                if path.strip_prefix(root)?.components().count() < 16 {
                    directories.push(path);
                }
            } else if is_project_document(root, &path) {
                candidates.push(path);
            }
        }
    }
    candidates.sort();
    if candidates.len() > MAX_INDEXED_PROJECT_DOCUMENTS {
        return Ok(blocked_project(&root.join(PROJECT_FILE)));
    }
    let mut documents = BTreeMap::new();
    let mut diagnostics = Vec::new();
    let mut indexed_bytes = 0usize;
    for path in candidates {
        let Some(file) = secure_regular_file(root, &path)? else {
            continue;
        };
        let ceiling = document_ceiling(root, &path);
        match file.read_bounded(ceiling.max_bytes) {
            Ok(SecureFileRead::Bytes(bytes)) => match String::from_utf8(bytes) {
                Ok(source) => {
                    // Only files emitted by the shared generator are navigable generated code.
                    if path.extension().is_some_and(|x| x == "ts" || x == "py")
                        && !source.lines().next().is_some_and(|line| {
                            line.contains("Generated from the normalized EvidenceProject.")
                        })
                    {
                        continue;
                    }
                    indexed_bytes = indexed_bytes.saturating_add(source.len());
                    if indexed_bytes > MAX_INDEXED_PROJECT_BYTES {
                        return Ok(blocked_project(&path));
                    }
                    documents.insert(path, source);
                }
                Err(_) => diagnostics.push(document_diagnostic(
                    &path,
                    "Project document is not valid UTF-8 and cannot be indexed",
                )),
            },
            Ok(SecureFileRead::TooLarge) => diagnostics.push(document_rule_diagnostic(
                &path,
                ProjectFamily::Evidence.diagnostic_code(DOCUMENT_CEILING_RULE),
                &ceiling.message,
            )),
            Err(_) => diagnostics.push(document_diagnostic(
                &path,
                "Project document could not be read; check its permissions",
            )),
        }
    }
    Ok(LoadedProjectDocuments {
        documents,
        diagnostics,
        indexing_ceiling_path: None,
    })
}
fn blocked_project(path: &Path) -> LoadedProjectDocuments {
    LoadedProjectDocuments {
        documents: BTreeMap::new(),
        diagnostics: vec![document_rule_diagnostic(
            path,
            ProjectFamily::Evidence.diagnostic_code(PROJECT_CEILING_RULE),
            PROJECT_CEILING_MESSAGE,
        )],
        indexing_ceiling_path: Some(path.to_path_buf()),
    }
}
