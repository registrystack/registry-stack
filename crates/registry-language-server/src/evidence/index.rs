// SPDX-License-Identifier: Apache-2.0
//! Walks the parsed documents of one Evidence authoring project into symbols and references.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::{
    refs::{IndexedDiagnostic, IndexedReference, IndexedSymbol},
    yaml::ParsedDocument,
};

/// Declares nothing yet.
///
/// The walkers that read a question, the concepts it answers, and the source, selector, schema,
/// and fixture files it names arrive in the next change. Until they do, an Evidence root still
/// discovers itself, loads its documents, and reports where one of them stops parsing, which is
/// the part of the surface that has to work before any symbol is worth resolving.
pub(crate) fn build_index(
    _root: &Path,
    _parsed: &BTreeMap<PathBuf, ParsedDocument>,
) -> (
    Vec<IndexedSymbol>,
    Vec<IndexedReference>,
    Vec<IndexedDiagnostic>,
) {
    (Vec::new(), Vec::new(), Vec::new())
}
