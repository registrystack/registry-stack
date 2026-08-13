// SPDX-License-Identifier: Apache-2.0
//! Relay V2 authoring projects rooted at `registry.yaml`.

mod index;

pub(crate) const PROJECT_FILE: &str = "registry.yaml";

/// Relay V2 permits governed files at any safe relative path and with any
/// extension, so only a recursive all-files watcher can cover its compiler
/// closure before the contract has been parsed. Watch notifications are
/// filtered through that resolved closure before any file is opened.
pub(crate) fn watched_globs() -> Vec<String> {
    vec!["**/*".to_owned()]
}

pub(crate) use index::{
    build_index, declares_root, is_project_document, load_project_documents,
    load_project_documents_with_overrides, retain_project_documents, RUNTIME_FILE,
};
