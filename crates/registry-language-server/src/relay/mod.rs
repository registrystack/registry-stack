// SPDX-License-Identifier: Apache-2.0
//! Relay projects: the `registry-stack.yaml` layout, safe document loading, and the walker
//! that turns those documents into indexed symbols and references.

pub(crate) mod index;

pub(crate) use index::{build_index, declares_root, is_project_document, load_project_documents};
// Every path a Relay project reads is answered by the shared containment rule; Relay adds nothing
// of its own to it.
pub(crate) use crate::safety::is_safe_authored_file;
