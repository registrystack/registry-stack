// SPDX-License-Identifier: Apache-2.0
//! Relay V2 authoring projects rooted at `registry.yaml`.

mod index;

pub(crate) const PROJECT_FILE: &str = "registry.yaml";

/// The `apiVersion` prefix a governed contract carries, and the `kind` it declares.
///
/// `registry.yaml` is a file name Relay V2 shares with the Base Registry Engine, whose project
/// document is also called `registry.yaml`, so the name alone says nothing about which product
/// wrote the directory. These two keys are what the contract grammar makes a Relay V2 document a
/// Relay V2 document by: `RegistryContract::parse_yaml` refuses a document whose `kind` is not
/// `RegistryContract`, and the grammar is versioned under `apiVersion`. The prefix rather than one
/// exact version, because a contract at a later `relay.registrystack.org/` version is still a Relay
/// V2 contract and belongs to this family; what it is at that version is the compiler's answer to
/// give, not root discovery's.
pub(crate) const API_VERSION_PREFIX: &str = "relay.registrystack.org/";
pub(crate) const CONTRACT_KIND: &str = "RegistryContract";

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
