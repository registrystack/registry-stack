// SPDX-License-Identifier: Apache-2.0
//! Relay projects: the `registry-stack.yaml` layout, safe document loading, and the walker
//! that turns those documents into indexed symbols and references.

pub(crate) mod index;

pub(crate) use index::{
    build_index, is_project_document, is_safe_authored_file, load_project_documents,
};
