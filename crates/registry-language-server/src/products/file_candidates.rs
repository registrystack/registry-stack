// SPDX-License-Identifier: Apache-2.0
//! Contained sibling names for repairing a missing authored file reference.
//!
//! The reference chooses one directory and file role. This module inspects only
//! that directory's entries and file metadata; it never reads candidate bytes.

use std::{
    fs,
    path::{Path, PathBuf},
};

use super::spec::FileRule;
use crate::{
    safety::{is_safe_authored_file, secure_directory},
    workspace::MAX_INDEXED_PROJECT_DOCUMENTS,
};

pub(super) struct FileCandidate {
    pub name: String,
    pub path: PathBuf,
}

pub(super) fn sibling_candidates(
    root: &Path,
    target: &Path,
    authored_value: &str,
    rule: FileRule,
) -> Vec<FileCandidate> {
    // Hierarchical and dynamic transforms need their own role-aware candidates.
    if rule.prefix.contains(['{', '}']) || rule.suffix.contains(['{', '}', '/']) {
        return Vec::new();
    }
    let Some(directory) = target.parent() else {
        return Vec::new();
    };
    if !secure_directory(root, directory).unwrap_or(false) {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let entries = entries
        .take(MAX_INDEXED_PROJECT_DOCUMENTS + 1)
        .collect::<Vec<_>>();
    // Refuse a partial arbitrary set when the directory exceeds the same
    // editor ceiling as indexed documents. Sort the admitted names afterward.
    if entries.len() > MAX_INDEXED_PROJECT_DOCUMENTS {
        return Vec::new();
    }
    let transformed = format!("{}{}{}", rule.prefix, authored_value, rule.suffix);
    let written_parent = transformed.rsplit_once('/').map(|(parent, _)| parent);
    let extension = target.extension();
    let mut candidates = Vec::new();
    for entry in entries.into_iter().flatten() {
        let path = entry.path();
        if extension.is_some() && path.extension() != extension {
            continue;
        }
        if !is_safe_authored_file(root, &path) {
            continue;
        }
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        let written = written_parent.map_or_else(
            || filename.to_owned(),
            |parent| format!("{parent}/{filename}"),
        );
        let Some(name) = written
            .strip_prefix(rule.prefix)
            .and_then(|name| name.strip_suffix(rule.suffix))
        else {
            continue;
        };
        if !name.is_empty() {
            candidates.push(FileCandidate {
                name: name.to_owned(),
                path,
            });
        }
    }
    candidates.sort_by(|left, right| left.name.cmp(&right.name));
    candidates
}
