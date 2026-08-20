// SPDX-License-Identifier: Apache-2.0
//! Native loading adapter around the shared project index.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use tower_lsp_server::ls_types::Position;

#[cfg(test)]
pub(crate) use registry_language_core::refs::DOCUMENT_START;
pub(crate) use registry_language_core::refs::{document_diagnostic, document_rule_diagnostic};
pub use registry_language_core::refs::{
    CompletionCandidate, EvidenceKind, HoverText, IndexedDiagnostic, IndexedLocation,
    IndexedProject, IndexedReference, IndexedSymbol, RelayV2Kind, SymbolKey, SymbolKind,
    SymbolQuery, DIRECTORY_CEILING_RULE, DOCUMENT_CEILING_RULE, PROJECT_CEILING_RULE,
};

use crate::workspace::ProjectFamily;

#[derive(Debug, Default)]
pub struct ProjectIndex(registry_language_core::refs::ProjectIndex);

impl ProjectIndex {
    pub fn load_evidence(root: &Path) -> Result<Self> {
        Self::load(root, ProjectFamily::Evidence)
    }

    pub fn load_relay_v2(root: &Path) -> Result<Self> {
        Self::load(root, ProjectFamily::RelayV2)
    }

    fn load(root: &Path, family: ProjectFamily) -> Result<Self> {
        let root = root
            .canonicalize()
            .with_context(|| format!("failed to resolve project root {}", root.display()))?;
        let loaded = family.load_documents(&root)?;
        if loaded.indexing_ceiling_path.is_some() {
            return Ok(Self::diagnostics_only(&root, loaded.diagnostics));
        }
        Ok(Self::from_documents_with_diagnostics(
            family,
            &root,
            &loaded.documents,
            loaded.diagnostics,
        ))
    }

    pub(crate) fn from_documents_with_diagnostics(
        family: ProjectFamily,
        root: &Path,
        documents: &BTreeMap<PathBuf, String>,
        mut diagnostics: Vec<IndexedDiagnostic>,
    ) -> Self {
        let mut parsed = BTreeMap::new();
        for (path, source) in documents {
            if !family.parses_as_yaml(path) {
                continue;
            }
            match crate::yaml::parse_yaml(source) {
                Ok(document) => {
                    parsed.insert(path.clone(), document);
                }
                Err(_) => diagnostics.push(document_diagnostic(
                    path,
                    "Project document could not be parsed; the YAML parser is unavailable",
                )),
            }
        }
        let syntax_errors = parsed
            .iter()
            .filter_map(|(path, document)| document.syntax_error.map(|range| (path.clone(), range)))
            .collect::<BTreeMap<_, _>>();
        let dropped = diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.path)
            .filter(|path| !documents.contains_key(*path))
            .cloned()
            .collect::<BTreeSet<_>>();
        let walked = family.build_index(root, documents, &parsed, &dropped);
        Self(registry_language_core::refs::ProjectIndex::from_indexed(
            root,
            documents,
            walked,
            diagnostics,
            syntax_errors,
            family.diagnostic_code("syntax"),
        ))
    }

    pub(crate) fn diagnostics_only(root: &Path, diagnostics: Vec<IndexedDiagnostic>) -> Self {
        Self(registry_language_core::refs::ProjectIndex::diagnostics_only(root, diagnostics))
    }

    pub fn root(&self) -> &Path {
        self.0.root()
    }

    pub fn symbols(&self) -> &[IndexedSymbol] {
        self.0.symbols()
    }

    pub fn document_symbols(&self, path: &Path) -> Vec<&IndexedSymbol> {
        self.0.document_symbols(path)
    }

    pub fn workspace_symbols(&self, query: &str) -> Vec<&IndexedSymbol> {
        self.0.workspace_symbols(query)
    }

    pub fn definitions_at(&self, path: &Path, position: Position) -> Vec<IndexedLocation> {
        self.0.definitions_at(path, position)
    }

    pub fn references_at(
        &self,
        path: &Path,
        position: Position,
        include_declaration: bool,
    ) -> Vec<IndexedLocation> {
        self.0.references_at(path, position, include_declaration)
    }

    pub fn completions_at(&self, path: &Path, position: Position) -> Vec<CompletionCandidate> {
        self.0.completions_at(path, position)
    }

    pub fn hover_at(&self, path: &Path, position: Position) -> Option<HoverText> {
        self.0.hover_at(path, position)
    }

    pub fn diagnostics(&self) -> &[IndexedDiagnostic] {
        self.0.diagnostics()
    }

    pub fn document_paths(&self) -> impl Iterator<Item = &Path> {
        self.0.document_paths()
    }
}
