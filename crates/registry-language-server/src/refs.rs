// SPDX-License-Identifier: Apache-2.0
//! The symbol and reference model shared by every indexed document family.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use tower_lsp_server::ls_types::{
    DiagnosticSeverity, Position, Range, SymbolKind as LspSymbolKind,
};

use crate::{relay, workspace::ProjectFamily};

/// The kind of a symbol, qualified by the document family that declares it. Keys, queries, and
/// diagnostics compare whole kinds, so one family's names never resolve another family's
/// references.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SymbolKind {
    Relay(RelayKind),
    Evidence(EvidenceKind),
}

impl SymbolKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Relay(kind) => kind.label(),
            Self::Evidence(kind) => kind.label(),
        }
    }

    pub fn lsp_kind(self) -> LspSymbolKind {
        match self {
            Self::Relay(kind) => kind.lsp_kind(),
            Self::Evidence(kind) => kind.lsp_kind(),
        }
    }
}

impl From<RelayKind> for SymbolKind {
    fn from(kind: RelayKind) -> Self {
        Self::Relay(kind)
    }
}

impl From<EvidenceKind> for SymbolKind {
    fn from(kind: EvidenceKind) -> Self {
        Self::Evidence(kind)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RelayKind {
    Registry,
    Integration,
    Entity,
    Service,
    Consultation,
    Fixture,
    Environment,
}

impl RelayKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Integration => "integration",
            Self::Entity => "entity",
            Self::Service => "service",
            Self::Consultation => "consultation",
            Self::Fixture => "fixture",
            Self::Environment => "environment",
        }
    }

    pub fn lsp_kind(self) -> LspSymbolKind {
        match self {
            Self::Registry => LspSymbolKind::NAMESPACE,
            Self::Integration | Self::Entity => LspSymbolKind::MODULE,
            Self::Service => LspSymbolKind::INTERFACE,
            Self::Consultation => LspSymbolKind::FUNCTION,
            Self::Fixture => LspSymbolKind::EVENT,
            Self::Environment => LspSymbolKind::PACKAGE,
        }
    }
}

/// What an Evidence authoring project names.
///
/// These are the names one document writes and another document spells back, which is the only
/// reason a name is worth indexing. A question names the concept it answers, the source it reads,
/// the selector profile it picks a subject with, the schema its output is checked against, the
/// derivation file that computes it, and the fixtures that exercise it, and an access policy names
/// the questions it admits.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceKind {
    Question,
    Concept,
    Source,
    SelectorProfile,
    DerivationFile,
    SchemaFile,
    FixtureFile,
    AccessPolicy,
}

impl EvidenceKind {
    /// The word an author reads in "Unknown {label} reference" and "Duplicate {label} definition",
    /// which is why these are the authoring form's own words rather than the variant names.
    pub fn label(self) -> &'static str {
        match self {
            Self::Question => "question",
            Self::Concept => "concept",
            Self::Source => "source",
            Self::SelectorProfile => "selector profile",
            Self::DerivationFile => "derivation file",
            Self::SchemaFile => "schema file",
            Self::FixtureFile => "fixture file",
            Self::AccessPolicy => "access policy",
        }
    }

    /// The icon an editor draws beside the name. A question is asked and answered like a call, a
    /// concept is a property of the subject the assertion is about, a source is a unit the project
    /// reads from, a selector profile is the contract for picking one subject, the three file kinds
    /// are files, and an access policy collects the questions one caller may ask.
    pub fn lsp_kind(self) -> LspSymbolKind {
        match self {
            Self::Question => LspSymbolKind::FUNCTION,
            Self::Concept => LspSymbolKind::FIELD,
            Self::Source => LspSymbolKind::MODULE,
            Self::SelectorProfile => LspSymbolKind::INTERFACE,
            Self::DerivationFile | Self::SchemaFile | Self::FixtureFile => LspSymbolKind::FILE,
            Self::AccessPolicy => LspSymbolKind::PACKAGE,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SymbolKey {
    pub(crate) kind: SymbolKind,
    pub(crate) scope: Option<String>,
    pub(crate) name: String,
}

impl SymbolKey {
    pub(crate) fn global(kind: impl Into<SymbolKind>, name: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            scope: None,
            name: name.into(),
        }
    }

    pub(crate) fn scoped(
        kind: impl Into<SymbolKind>,
        scope: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            scope: Some(scope.into()),
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedLocation {
    pub path: PathBuf,
    pub range: Range,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedSymbol {
    pub name: String,
    pub kind: SymbolKind,
    pub container_name: Option<String>,
    pub location: IndexedLocation,
    pub(crate) key: SymbolKey,
    pub(crate) resolvable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedDiagnostic {
    pub path: PathBuf,
    pub range: Range,
    pub severity: DiagnosticSeverity,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SymbolQuery {
    pub(crate) kind: SymbolKind,
    pub(crate) scope: Option<String>,
    pub(crate) name: String,
}

impl SymbolQuery {
    pub(crate) fn global(kind: impl Into<SymbolKind>, name: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            scope: None,
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedReference {
    pub(crate) target: SymbolQuery,
    pub(crate) location: IndexedLocation,
}

#[derive(Debug, Default)]
pub struct ProjectIndex {
    root: PathBuf,
    symbols: Vec<IndexedSymbol>,
    references: Vec<IndexedReference>,
    diagnostics: Vec<IndexedDiagnostic>,
    document_paths: BTreeSet<PathBuf>,
}

impl ProjectIndex {
    /// Loads and indexes one Relay project. The multi-family path runs through
    /// [`crate::workspace`], which knows which family a root belongs to; this entry point serves
    /// callers that already have a Relay project in hand and asks nothing of them.
    pub fn load(root: &Path) -> Result<Self> {
        let root = root
            .canonicalize()
            .with_context(|| format!("failed to resolve project root {}", root.display()))?;
        let loaded = relay::load_project_documents(&root)?;
        Ok(Self::from_documents_with_diagnostics(
            ProjectFamily::Relay,
            &root,
            &loaded.documents,
            loaded.diagnostics,
        ))
    }

    /// Indexes documents already in memory as a Relay project, for the same reason as [`Self::load`].
    pub fn from_documents(root: &Path, documents: &BTreeMap<PathBuf, String>) -> Self {
        Self::from_documents_with_diagnostics(ProjectFamily::Relay, root, documents, Vec::new())
    }

    pub(crate) fn from_documents_with_diagnostics(
        family: ProjectFamily,
        root: &Path,
        documents: &BTreeMap<PathBuf, String>,
        mut diagnostics: Vec<IndexedDiagnostic>,
    ) -> Self {
        let root = root.to_path_buf();
        let mut parsed = BTreeMap::new();
        for (path, source) in documents {
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

        let (symbols, references, semantic_diagnostics) = family.build_index(&root, &parsed);

        let mut index = Self {
            root,
            symbols,
            references,
            diagnostics: Vec::new(),
            document_paths: documents.keys().cloned().collect(),
        };
        diagnostics.extend(semantic_diagnostics);
        diagnostics.extend(index.build_diagnostics());
        // A document that does not parse cleanly reports where it stops parsing and nothing else.
        // The symbols it still yields stay in the index and keep satisfying other documents, but
        // its own references and definitions are read from text the author has not finished.
        diagnostics.retain(|diagnostic| !syntax_errors.contains_key(&diagnostic.path));
        diagnostics.extend(
            syntax_errors
                .into_iter()
                .map(|(path, range)| IndexedDiagnostic {
                    path,
                    range,
                    severity: DiagnosticSeverity::ERROR,
                    message:
                        "Invalid YAML syntax; this document is indexed only as far as it parses"
                            .to_owned(),
                }),
        );
        diagnostics.sort_by(diagnostic_cmp);
        diagnostics.dedup();
        index.diagnostics = diagnostics;
        index
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn symbols(&self) -> &[IndexedSymbol] {
        &self.symbols
    }

    /// Symbols declared in one document, named by its canonical path.
    pub fn document_symbols(&self, path: &Path) -> Vec<&IndexedSymbol> {
        self.symbols
            .iter()
            .filter(|symbol| symbol.location.path == path)
            .collect()
    }

    pub fn workspace_symbols(&self, query: &str) -> Vec<&IndexedSymbol> {
        let query = query.to_lowercase();
        self.symbols
            .iter()
            .filter(|symbol| {
                query.is_empty()
                    || symbol.name.to_lowercase().contains(&query)
                    || symbol
                        .container_name
                        .as_ref()
                        .is_some_and(|container| container.to_lowercase().contains(&query))
            })
            .collect()
    }

    /// Where the symbol or reference under a position is defined. `path` is canonical.
    pub fn definitions_at(&self, path: &Path, position: Position) -> Vec<IndexedLocation> {
        if let Some(reference) = self.reference_at(path, position) {
            return self
                .definitions_for(&reference.target)
                .into_iter()
                .map(|symbol| symbol.location.clone())
                .collect();
        }

        self.symbol_at(path, position)
            .map(|symbol| vec![symbol.location.clone()])
            .unwrap_or_default()
    }

    /// Every use of the symbol under a position. `path` is canonical.
    pub fn references_at(
        &self,
        path: &Path,
        position: Position,
        include_declaration: bool,
    ) -> Vec<IndexedLocation> {
        let keys = if let Some(symbol) = self
            .symbol_at(path, position)
            .filter(|symbol| symbol.resolvable)
        {
            vec![symbol.key.clone()]
        } else if let Some(reference) = self.reference_at(path, position) {
            self.definitions_for(&reference.target)
                .into_iter()
                .map(|symbol| symbol.key.clone())
                .collect()
        } else {
            Vec::new()
        };

        let mut locations = Vec::new();
        if include_declaration {
            for symbol in &self.symbols {
                if keys.contains(&symbol.key) {
                    locations.push(symbol.location.clone());
                }
            }
        }
        for reference in &self.references {
            if keys
                .iter()
                .any(|key| self.query_can_resolve_to(&reference.target, key))
            {
                locations.push(reference.location.clone());
            }
        }
        locations.sort_by(location_cmp);
        locations.dedup();
        locations
    }

    pub fn diagnostics(&self) -> &[IndexedDiagnostic] {
        &self.diagnostics
    }

    pub fn document_paths(&self) -> impl Iterator<Item = &Path> {
        self.document_paths.iter().map(PathBuf::as_path)
    }

    fn symbol_at(&self, path: &Path, position: Position) -> Option<&IndexedSymbol> {
        self.symbols.iter().find(|symbol| {
            symbol.location.path == path && range_contains(symbol.location.range, position)
        })
    }

    fn reference_at(&self, path: &Path, position: Position) -> Option<&IndexedReference> {
        self.references.iter().find(|reference| {
            reference.location.path == path && range_contains(reference.location.range, position)
        })
    }

    fn definitions_for(&self, query: &SymbolQuery) -> Vec<&IndexedSymbol> {
        self.symbols
            .iter()
            .filter(|symbol| symbol.resolvable && self.query_can_resolve_to(query, &symbol.key))
            .collect()
    }

    fn query_can_resolve_to(&self, query: &SymbolQuery, key: &SymbolKey) -> bool {
        query.kind == key.kind
            && query.name == key.name
            && query
                .scope
                .as_ref()
                .is_none_or(|scope| key.scope.as_ref() == Some(scope))
    }

    fn build_diagnostics(&self) -> Vec<IndexedDiagnostic> {
        let mut diagnostics = Vec::new();
        let mut definitions: BTreeMap<&SymbolKey, Vec<&IndexedSymbol>> = BTreeMap::new();
        for symbol in self.symbols.iter().filter(|symbol| symbol.resolvable) {
            definitions.entry(&symbol.key).or_default().push(symbol);
        }

        for (key, duplicates) in definitions {
            if duplicates.len() < 2 {
                continue;
            }
            for symbol in duplicates {
                diagnostics.push(IndexedDiagnostic {
                    path: symbol.location.path.clone(),
                    range: symbol.location.range,
                    severity: DiagnosticSeverity::ERROR,
                    message: format!(
                        "Duplicate {} definition '{}'{}",
                        key.kind.label(),
                        bounded_value(&key.name),
                        key.scope
                            .as_ref()
                            .map(|scope| format!(" in service '{}'", bounded_value(scope)))
                            .unwrap_or_default()
                    ),
                });
            }
        }

        for reference in &self.references {
            let candidates = self.definitions_for(&reference.target);
            let message = match candidates.len() {
                0 => Some(format!(
                    "Unknown {} reference '{}'{}",
                    reference.target.kind.label(),
                    bounded_value(&reference.target.name),
                    reference
                        .target
                        .scope
                        .as_ref()
                        .map(|scope| format!(" in service '{}'", bounded_value(scope)))
                        .unwrap_or_default()
                )),
                1 => None,
                count => Some(format!(
                    "Ambiguous {} reference '{}': found {count} definitions",
                    reference.target.kind.label(),
                    bounded_value(&reference.target.name)
                )),
            };
            if let Some(message) = message {
                diagnostics.push(IndexedDiagnostic {
                    path: reference.location.path.clone(),
                    range: reference.location.range,
                    severity: DiagnosticSeverity::ERROR,
                    message,
                });
            }
        }

        diagnostics.sort_by(diagnostic_cmp);
        diagnostics
    }
}

pub(crate) fn document_diagnostic(path: &Path, message: &str) -> IndexedDiagnostic {
    IndexedDiagnostic {
        path: path.to_path_buf(),
        range: Range::new(Position::new(0, 0), Position::new(0, 0)),
        severity: DiagnosticSeverity::ERROR,
        message: message.to_owned(),
    }
}

fn diagnostic_cmp(left: &IndexedDiagnostic, right: &IndexedDiagnostic) -> std::cmp::Ordering {
    left.path
        .cmp(&right.path)
        .then_with(|| range_cmp(left.range, right.range))
        .then_with(|| left.message.cmp(&right.message))
}

pub(crate) fn bounded_value(value: &str) -> String {
    const MAX_CHARS: usize = 120;
    let mut bounded = value
        .chars()
        .take(MAX_CHARS)
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect::<String>();
    if value.chars().count() > MAX_CHARS {
        bounded.push('…');
    }
    bounded
}

fn range_contains(range: Range, position: Position) -> bool {
    position_cmp(position, range.start).is_ge() && position_cmp(position, range.end).is_le()
}

fn position_cmp(left: Position, right: Position) -> std::cmp::Ordering {
    left.line
        .cmp(&right.line)
        .then_with(|| left.character.cmp(&right.character))
}

fn range_cmp(left: Range, right: Range) -> std::cmp::Ordering {
    position_cmp(left.start, right.start).then_with(|| position_cmp(left.end, right.end))
}

fn location_cmp(left: &IndexedLocation, right: &IndexedLocation) -> std::cmp::Ordering {
    left.path
        .cmp(&right.path)
        .then_with(|| range_cmp(left.range, right.range))
}
