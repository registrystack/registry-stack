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

    /// The stable identifier a client filters or suppresses `rule` by, for the kinds that publish
    /// one.
    ///
    /// Evidence names every rule it reports, so an author who disagrees with one can silence that
    /// rule rather than the server. Relay's diagnostics have never carried a code, and a client
    /// filtering them today filters on the message; giving them one now would change what that
    /// client sees, which is a decision for the Relay surface rather than a side effect of this one.
    pub(crate) fn diagnostic_code(self, rule: &str) -> Option<String> {
        match self {
            Self::Relay(_) => None,
            Self::Evidence(kind) => Some(format!("evidence/{rule}-{}", kind.slug())),
        }
    }

    /// The word for the thing a scoped name is written inside, which an author reads in
    /// "Duplicate {label} definition '{name}' in {container} '{scope}'".
    ///
    /// A Relay consultation is declared under the service that offers it, and an Evidence concept is
    /// answered by the question that carries it. There are no services in an Evidence authoring
    /// project, so each family names the container in its own vocabulary rather than in the one that
    /// happened to need a scope first.
    fn scope_label(self) -> &'static str {
        match self {
            Self::Relay(_) => "service",
            Self::Evidence(_) => "question",
        }
    }

    /// Whether a name of this kind written twice is reported here.
    ///
    /// A concept is excluded because `registry_evidence_authoring::validate` already refuses a
    /// question that answers one concept twice, at the answer that repeats, and its sentence is the
    /// one the compiler prints. A duplicate reported here would be a second error on one mistake,
    /// and one per occurrence at that, which is what the `disclosure.allow` reference refuses for
    /// the same reason.
    ///
    /// An operation is excluded for the opposite reason: nothing refuses it. `unique_operation`
    /// (`crates/registry-evidencectl/src/authoring.rs:1532-1573`) is asked about one identifier, the
    /// one a question wrote, so a description publishing two operations under an identifier no
    /// question names builds. The sentence for the identifier a question does name belongs at that
    /// question, where the ambiguous reference is, and not at two places in a description the author
    /// may not even own.
    fn reports_duplicates(self) -> bool {
        !matches!(
            self,
            Self::Evidence(EvidenceKind::Concept | EvidenceKind::Operation)
        )
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
///
/// The last two are the names of the compact form, where a question reads the project's own OpenAPI
/// description instead of a source document: it names an operation that description publishes, and
/// it bounds each collection its facts visit.
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
    Operation,
    Collection,
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
            Self::Operation => "operation",
            Self::Collection => "collection",
        }
    }

    /// The icon an editor draws beside the name. A question is asked and answered like a call, a
    /// concept is a property of the subject the assertion is about, a source is a unit the project
    /// reads from, a selector profile is the contract for picking one subject, the three file kinds
    /// are files, and an access policy collects the questions one caller may ask. An operation is
    /// invoked, and a collection is the array a fact path walks through.
    pub fn lsp_kind(self) -> LspSymbolKind {
        match self {
            Self::Question => LspSymbolKind::FUNCTION,
            Self::Concept => LspSymbolKind::FIELD,
            Self::Source => LspSymbolKind::MODULE,
            Self::SelectorProfile => LspSymbolKind::INTERFACE,
            Self::DerivationFile | Self::SchemaFile | Self::FixtureFile => LspSymbolKind::FILE,
            Self::AccessPolicy => LspSymbolKind::PACKAGE,
            Self::Operation => LspSymbolKind::METHOD,
            Self::Collection => LspSymbolKind::ARRAY,
        }
    }

    /// The part of a diagnostic code that names this kind. It is [`Self::label`] without the
    /// spaces, so `evidence/unknown-source` and `evidence/unknown-selector-profile` read as the
    /// sentences they accompany.
    pub(crate) fn slug(self) -> &'static str {
        match self {
            Self::Question => "question",
            Self::Concept => "concept",
            Self::Source => "source",
            Self::SelectorProfile => "selector-profile",
            Self::DerivationFile => "derivation-file",
            Self::SchemaFile => "schema-file",
            Self::FixtureFile => "fixture-file",
            Self::AccessPolicy => "access-policy",
            Self::Operation => "operation",
            Self::Collection => "collection",
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

/// One problem an author can act on, at the place in the document that holds it.
///
/// Severity is [`DiagnosticSeverity::ERROR`] on every diagnostic this server publishes. The channel
/// carries what the compiler refuses and nothing else, so an author who fixes everything the editor
/// underlines has a project that builds, and one who ignores an underline is ignoring a build
/// failure rather than an opinion.
///
/// `code` names the rule for the client that wants to filter or suppress one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedDiagnostic {
    pub path: PathBuf,
    pub range: Range,
    pub severity: DiagnosticSeverity,
    pub code: Option<String>,
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
pub(crate) struct IndexedReference {
    pub(crate) target: SymbolQuery,
    pub(crate) location: IndexedLocation,
    /// Whether a target this reference cannot find is reported here.
    ///
    /// A walker sets this false for the one kind of reference another check already speaks for, so
    /// that navigation works from it without putting a second error on one mistake. It never means
    /// the reference is allowed to dangle.
    pub(crate) reports_unresolved: bool,
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

    /// Loads and indexes one Evidence authoring project, the counterpart to [`Self::load`].
    pub fn load_evidence(root: &Path) -> Result<Self> {
        let root = root
            .canonicalize()
            .with_context(|| format!("failed to resolve project root {}", root.display()))?;
        let loaded = crate::evidence::load_project_documents(&root)?;
        Ok(Self::from_documents_with_diagnostics(
            ProjectFamily::Evidence,
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

        // The documents this root holds no text for, each one already carrying the sentence that
        // says why. A path is one of these exactly when something reported it and nothing read it,
        // which is the only place that pairing is known: the loader and the watcher both admit a
        // document or report it, never both.
        let dropped = diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.path)
            .filter(|path| !documents.contains_key(*path))
            .cloned()
            .collect::<BTreeSet<_>>();

        let (symbols, references, semantic_diagnostics) =
            family.build_index(&root, documents, &parsed, &dropped);

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
                    code: family.diagnostic_code("syntax"),
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
            if duplicates.len() < 2 || !key.kind.reports_duplicates() {
                continue;
            }
            for symbol in duplicates {
                diagnostics.push(IndexedDiagnostic {
                    path: symbol.location.path.clone(),
                    range: symbol.location.range,
                    severity: DiagnosticSeverity::ERROR,
                    code: key.kind.diagnostic_code("duplicate"),
                    message: format!(
                        "Duplicate {} definition '{}'{}",
                        key.kind.label(),
                        bounded_value(&key.name),
                        scope_suffix(key.kind, key.scope.as_deref())
                    ),
                });
            }
        }

        for reference in self
            .references
            .iter()
            .filter(|reference| reference.reports_unresolved)
        {
            let candidates = self.definitions_for(&reference.target);
            let reported = match candidates.len() {
                0 => Some((
                    "unknown",
                    format!(
                        "Unknown {} reference '{}'{}",
                        reference.target.kind.label(),
                        bounded_value(&reference.target.name),
                        scope_suffix(reference.target.kind, reference.target.scope.as_deref())
                    ),
                )),
                1 => None,
                count => Some((
                    "ambiguous",
                    format!(
                        "Ambiguous {} reference '{}': found {count} definitions",
                        reference.target.kind.label(),
                        bounded_value(&reference.target.name)
                    ),
                )),
            };
            if let Some((rule, message)) = reported {
                diagnostics.push(IndexedDiagnostic {
                    path: reference.location.path.clone(),
                    range: reference.location.range,
                    severity: DiagnosticSeverity::ERROR,
                    code: reference.target.kind.diagnostic_code(rule),
                    message,
                });
            }
        }

        diagnostics.sort_by(diagnostic_cmp);
        diagnostics
    }
}

/// The rule a document larger than the ceiling its family holds it to is refused under.
pub(crate) const DOCUMENT_CEILING_RULE: &str = "document-ceiling";

/// The rule a directory holding more documents than the editor indexes is reported under.
pub(crate) const DIRECTORY_CEILING_RULE: &str = "directory-ceiling";

/// A problem with a whole document rather than a place in it, reported at its start.
pub(crate) fn document_diagnostic(path: &Path, message: &str) -> IndexedDiagnostic {
    document_rule_diagnostic(path, None, message)
}

/// The same, for a document the editor refused under a rule of its own.
///
/// The two ceilings are rules of the authoring form that the editor restates, so an author reads
/// them beside the rules the compiler prints and filters them the same way: by name, rather than by
/// silencing everything the server says.
pub(crate) fn document_rule_diagnostic(
    path: &Path,
    code: Option<String>,
    message: &str,
) -> IndexedDiagnostic {
    IndexedDiagnostic {
        path: path.to_path_buf(),
        range: DOCUMENT_START,
        severity: DiagnosticSeverity::ERROR,
        code,
        message: message.to_owned(),
    }
}

/// The empty range at the first character, where a diagnostic goes when the document holds no
/// narrower place to put it.
pub(crate) const DOCUMENT_START: Range = Range {
    start: Position {
        line: 0,
        character: 0,
    },
    end: Position {
        line: 0,
        character: 0,
    },
};

fn diagnostic_cmp(left: &IndexedDiagnostic, right: &IndexedDiagnostic) -> std::cmp::Ordering {
    left.path
        .cmp(&right.path)
        .then_with(|| range_cmp(left.range, right.range))
        .then_with(|| left.message.cmp(&right.message))
}

/// The tail of a message that says where a scoped name is written, in the word its family uses.
fn scope_suffix(kind: SymbolKind, scope: Option<&str>) -> String {
    scope
        .map(|scope| format!(" in {} '{}'", kind.scope_label(), bounded_value(scope)))
        .unwrap_or_default()
}

/// One name an author wrote, made safe to quote inside a message and cut to the width of a name.
pub(crate) fn bounded_value(value: &str) -> String {
    bounded(value, 120)
}

/// A whole sentence another implementation composed, made safe the same way and cut far above the
/// length of any sentence it writes.
///
/// A sentence from the authoring library already carries a name the author wrote inside it, and the
/// instruction the author has to act on comes after that name. Cutting such a sentence to the width
/// of one name removes exactly the part the finding exists to give, so the ceiling here bounds the
/// channel rather than the message.
pub(crate) fn bounded_message(message: &str) -> String {
    bounded(message, 1024)
}

/// What both ceilings share: a control character becomes one no terminal obeys, and text that does
/// not fit ends in the mark that says so.
fn bounded(value: &str, max_chars: usize) -> String {
    let mut bounded = value
        .chars()
        .take(max_chars)
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect::<String>();
    if value.chars().count() > max_chars {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Each family names the container in its own words. A Relay consultation is declared inside the
    /// service that offers it; an Evidence concept is answered by a question, and an Evidence
    /// authoring project has no services at all.
    #[test]
    fn a_scope_is_named_in_the_vocabulary_of_the_family_that_owns_it() {
        assert_eq!(
            scope_suffix(
                SymbolKind::Relay(RelayKind::Consultation),
                Some("person-records")
            ),
            " in service 'person-records'"
        );
        assert_eq!(
            scope_suffix(
                SymbolKind::Evidence(EvidenceKind::Concept),
                Some("adult-status")
            ),
            " in question 'adult-status'"
        );
    }

    /// A name with no scope says nothing about where it is written, in either family.
    #[test]
    fn a_name_with_no_scope_carries_no_suffix() {
        assert_eq!(
            scope_suffix(SymbolKind::Relay(RelayKind::Service), None),
            String::new()
        );
        assert_eq!(
            scope_suffix(SymbolKind::Evidence(EvidenceKind::Question), None),
            String::new()
        );
    }

    /// The two kinds whose duplicates this index leaves alone, and the kinds it is the only one to
    /// see. A concept's duplicates the authoring library already refuses; an operation identifier
    /// two operations publish is refused only where a question names it, so reporting it here would
    /// underline a description the compiler builds.
    /// `tests/evidence_openapi.rs::an_identifier_two_operations_publish_and_no_question_names_is_reported_nowhere`
    /// holds the operation half of that end to end.
    #[test]
    fn a_concept_and_an_operation_leave_their_duplicates_to_another_check() {
        assert!(!SymbolKind::Evidence(EvidenceKind::Concept).reports_duplicates());
        assert!(!SymbolKind::Evidence(EvidenceKind::Operation).reports_duplicates());
        assert!(SymbolKind::Evidence(EvidenceKind::Question).reports_duplicates());
        assert!(SymbolKind::Relay(RelayKind::Consultation).reports_duplicates());
    }

    /// A name is quoted at the width of a name, and a whole sentence at the width of a sentence.
    /// Both replace a control character with one that carries no instruction.
    #[test]
    fn text_that_reaches_a_message_is_bounded_and_stripped_of_control_characters() {
        let name = "n".repeat(200);
        assert_eq!(bounded_value(&name).chars().count(), 121);
        assert_eq!(bounded_message(&name), name);

        let sentence = "s".repeat(2000);
        assert_eq!(bounded_message(&sentence).chars().count(), 1025);

        assert_eq!(bounded_value("one\u{1b}[2Jtwo"), "one�[2Jtwo");
        assert_eq!(bounded_message("one\u{1b}[2Jtwo"), "one�[2Jtwo");
    }
}
