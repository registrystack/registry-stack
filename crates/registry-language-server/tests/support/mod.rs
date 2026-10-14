// SPDX-License-Identifier: Apache-2.0
//! Building an Evidence authoring project on disk and asking the index about it.
//!
//! Every test here works from real files under a temporary directory rather than from an in-memory
//! filesystem, because the loader's containment rules are filesystem rules: a mocked filesystem
//! would pass the tests and prove nothing about the symbolic link a project may actually hold.
//!
//! Positions come from cursor markers written into the fixture text. A marker is `<|name|>`, it is
//! removed before the file is written, and it records the position of the character that follows
//! it, so a test names the field it points at instead of counting columns.

// Each test binary compiles this module and uses part of it. The rest is used by a sibling binary,
// so it is unreachable here without being dead in the crate.
#![allow(dead_code)]

pub mod lsp;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Product-neutral real-file fixture, shared by the preserved product suites.
#[derive(Clone)]
pub struct ProjectFile {
    pub path: String,
    pub contents: String,
}
use registry_language_server::ProjectIndex;
use tempfile::TempDir;
use tower_lsp_server::ls_types::Position;

/// An Evidence authoring project written to a temporary directory, and the positions its cursor
/// markers named.
pub struct EvidenceProject {
    _temp: TempDir,
    root: PathBuf,
    cursors: BTreeMap<String, BTreeMap<String, Position>>,
}

impl EvidenceProject {
    /// Writes every file, stripping and recording its cursor markers.
    pub fn new(files: &[ProjectFile]) -> Self {
        let temp = TempDir::new().expect("temporary project directory");
        let mut cursors = BTreeMap::new();
        for file in files {
            let (contents, marks) = strip_cursors(&file.contents);
            let path = temp.path().join(&file.path);
            fs::create_dir_all(path.parent().expect("project file has a parent"))
                .expect("project directory");
            fs::write(&path, contents).expect("project file");
            if !marks.is_empty() {
                cursors.insert(file.path.clone(), marks);
            }
        }
        let root = temp.path().canonicalize().expect("canonical project root");
        Self {
            _temp: temp,
            root,
            cursors,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The canonical path of one project file, as the index names it.
    pub fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// The position a named cursor marker pointed at.
    pub fn cursor(&self, relative: &str, name: &str) -> Position {
        *self
            .cursors
            .get(relative)
            .and_then(|marks| marks.get(name))
            .unwrap_or_else(|| panic!("{relative} carries a <|{name}|> cursor marker"))
    }

    pub fn index(&self) -> ProjectIndex {
        ProjectIndex::load_evidence(&self.root).expect("the project loads")
    }
}

/// The text a fixture writes to disk: its cursor markers removed and nothing else changed.
///
/// A test that hands a fixture to the authoring library rather than to the index needs the
/// document an author would have written, which is this and not the marked-up constant.
pub fn without_cursors(text: &str) -> String {
    strip_cursors(text).0
}

/// The text without its cursor markers, and where each marker pointed.
fn strip_cursors(text: &str) -> (String, BTreeMap<String, Position>) {
    let mut stripped = String::with_capacity(text.len());
    let mut cursors = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let mut column = 0;
        let mut rest = line;
        while let Some(start) = rest.find("<|") {
            let (before, marker) = rest.split_at(start);
            stripped.push_str(before);
            column += before.encode_utf16().count();
            let marker = &marker["<|".len()..];
            let end = marker.find("|>").expect("a cursor marker closes with |>");
            let position = Position::new(number as u32, column as u32);
            assert!(
                cursors.insert(marker[..end].to_owned(), position).is_none(),
                "one document names each cursor marker once"
            );
            rest = &marker[end + "|>".len()..];
        }
        stripped.push_str(rest);
        stripped.push('\n');
    }
    (stripped, cursors)
}

/// One project file, for the fixtures below.
pub fn file(path: &str, contents: &str) -> ProjectFile {
    ProjectFile {
        path: path.to_owned(),
        contents: contents.to_owned(),
    }
}

/// The same file set with one path written differently, whether or not it was there before.
pub fn replacing(files: &[ProjectFile], path: &str, contents: &str) -> Vec<ProjectFile> {
    let mut files = files
        .iter()
        .filter(|candidate| candidate.path != path)
        .cloned()
        .collect::<Vec<_>>();
    files.push(file(path, contents));
    files
}

/// The same file set without one path.
pub fn without(files: &[ProjectFile], path: &str) -> Vec<ProjectFile> {
    files
        .iter()
        .filter(|candidate| candidate.path != path)
        .cloned()
        .collect()
}
