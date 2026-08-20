// SPDX-License-Identifier: Apache-2.0
//! The symbol and reference model shared by indexed project documents.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use ls_types::{
    CompletionItemKind, DiagnosticSeverity, Position, Range, SymbolKind as LspSymbolKind,
};

use crate::yaml::{written_as, ScalarStyle};

/// The kind of a symbol, qualified by the document family that declares it. Keys, queries, and
/// diagnostics compare whole kinds, so one family's names never resolve another family's
/// references.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SymbolKind {
    RelayV2(RelayV2Kind),
    Evidence(EvidenceKind),
}

impl SymbolKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::RelayV2(kind) => kind.label(),
            Self::Evidence(kind) => kind.label(),
        }
    }

    pub fn lsp_kind(self) -> LspSymbolKind {
        match self {
            Self::RelayV2(kind) => kind.lsp_kind(),
            Self::Evidence(kind) => kind.lsp_kind(),
        }
    }

    /// The icon an editor draws beside this kind in a completion list.
    ///
    /// It is the completion vocabulary's nearest word for [`Self::lsp_kind`], which is the icon the
    /// same name already carries in the outline, so one name looks like itself wherever it is drawn.
    /// The completion vocabulary is the narrower of the two: it has no namespace, no package and no
    /// array, and the kinds that would have used one fall back to the word beside it.
    pub fn lsp_completion_kind(self) -> CompletionItemKind {
        match self {
            Self::RelayV2(RelayV2Kind::Registry | RelayV2Kind::Source) => {
                CompletionItemKind::MODULE
            }
            Self::RelayV2(
                RelayV2Kind::Resource
                | RelayV2Kind::StatisticalDataset
                | RelayV2Kind::DisclosureProfile,
            ) => CompletionItemKind::INTERFACE,
            Self::RelayV2(RelayV2Kind::Property | RelayV2Kind::StatisticalComponent) => {
                CompletionItemKind::FIELD
            }
            Self::RelayV2(RelayV2Kind::AccessProfile) => CompletionItemKind::ENUM_MEMBER,
            Self::RelayV2(RelayV2Kind::Operation) => CompletionItemKind::METHOD,
            Self::RelayV2(RelayV2Kind::GovernedFile) => CompletionItemKind::FILE,
            Self::Evidence(EvidenceKind::Question) => CompletionItemKind::FUNCTION,
            Self::Evidence(EvidenceKind::Concept) => CompletionItemKind::FIELD,
            Self::Evidence(EvidenceKind::Source | EvidenceKind::AccessPolicy) => {
                CompletionItemKind::MODULE
            }
            Self::Evidence(EvidenceKind::SelectorProfile) => CompletionItemKind::INTERFACE,
            Self::Evidence(
                EvidenceKind::DerivationFile | EvidenceKind::SchemaFile | EvidenceKind::FixtureFile,
            ) => CompletionItemKind::FILE,
            Self::Evidence(EvidenceKind::Operation) => CompletionItemKind::METHOD,
            Self::Evidence(EvidenceKind::Collection) => CompletionItemKind::VALUE,
        }
    }

    /// The stable identifier a client filters or suppresses `rule` by, for the kinds that publish
    /// one.
    ///
    /// Evidence names every rule it reports, so an author who disagrees with one can silence that
    /// rule rather than the server. Relay's diagnostics have never carried a code, and a client
    /// filtering them today filters on the message; giving them one now would change what that
    /// client sees, which is a decision for the Relay surface rather than a side effect of this one.
    pub fn diagnostic_code(self, rule: &str) -> Option<String> {
        match self {
            Self::RelayV2(kind) => Some(format!("relay-v2/{rule}-{}", kind.slug())),
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
            Self::RelayV2(kind) => kind.scope_label(),
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
            Self::RelayV2(_) | Self::Evidence(EvidenceKind::Concept | EvidenceKind::Operation)
        )
    }
}

impl From<EvidenceKind> for SymbolKind {
    fn from(kind: EvidenceKind) -> Self {
        Self::Evidence(kind)
    }
}

impl From<RelayV2Kind> for SymbolKind {
    fn from(kind: RelayV2Kind) -> Self {
        Self::RelayV2(kind)
    }
}

/// Names written by the governed Relay V2 contract and deployment binding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RelayV2Kind {
    Registry,
    Source,
    Resource,
    StatisticalDataset,
    Property,
    StatisticalComponent,
    DisclosureProfile,
    AccessProfile,
    Operation,
    GovernedFile,
}

impl RelayV2Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Registry => "Relay V2 Registry",
            Self::Source => "Relay V2 source",
            Self::Resource => "Relay V2 resource",
            Self::StatisticalDataset => "Relay V2 statistical dataset",
            Self::Property => "Relay V2 property",
            Self::StatisticalComponent => "Relay V2 statistical component",
            Self::DisclosureProfile => "Relay V2 disclosure profile",
            Self::AccessProfile => "Relay V2 access profile",
            Self::Operation => "Relay V2 operation",
            Self::GovernedFile => "Relay V2 governed file",
        }
    }

    pub fn lsp_kind(self) -> LspSymbolKind {
        match self {
            Self::Registry => LspSymbolKind::NAMESPACE,
            Self::Source => LspSymbolKind::MODULE,
            Self::Resource | Self::StatisticalDataset | Self::DisclosureProfile => {
                LspSymbolKind::INTERFACE
            }
            Self::Property | Self::StatisticalComponent => LspSymbolKind::FIELD,
            Self::AccessProfile => LspSymbolKind::ENUM_MEMBER,
            Self::Operation => LspSymbolKind::METHOD,
            Self::GovernedFile => LspSymbolKind::FILE,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Source => "source",
            Self::Resource => "resource",
            Self::StatisticalDataset => "statistical-dataset",
            Self::Property => "property",
            Self::StatisticalComponent => "statistical-component",
            Self::DisclosureProfile => "disclosure-profile",
            Self::AccessProfile => "access-profile",
            Self::Operation => "operation",
            Self::GovernedFile => "governed-file",
        }
    }

    fn scope_label(self) -> &'static str {
        match self {
            Self::AccessProfile => "operation",
            Self::Property | Self::DisclosureProfile | Self::Operation => "resource or dataset",
            Self::StatisticalComponent => "statistical dataset",
            Self::Registry
            | Self::Source
            | Self::Resource
            | Self::StatisticalDataset
            | Self::GovernedFile => "Registry",
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
    pub fn slug(self) -> &'static str {
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
pub struct SymbolKey {
    pub kind: SymbolKind,
    pub scope: Option<String>,
    pub name: String,
}

impl SymbolKey {
    pub fn global(kind: impl Into<SymbolKind>, name: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            scope: None,
            name: name.into(),
        }
    }

    pub fn scoped(
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
    pub key: SymbolKey,
    pub resolvable: bool,
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
pub struct SymbolQuery {
    pub kind: SymbolKind,
    pub scope: Option<String>,
    pub name: String,
}

impl SymbolQuery {
    pub fn global(kind: impl Into<SymbolKind>, name: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            scope: None,
            name: name.into(),
        }
    }

    pub fn scoped(
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
pub struct IndexedReference {
    pub target: SymbolQuery,
    pub location: IndexedLocation,
    /// Whether a target this reference cannot find is reported here.
    ///
    /// A walker sets this false for the one kind of reference another check already speaks for, so
    /// that navigation works from it without putting a second error on one mistake. It never means
    /// the reference is allowed to dangle.
    pub reports_unresolved: bool,
    /// How the value this reference reads was written, so a name offered here is spelled for the
    /// place it will be written into.
    pub style: ScalarStyle,
    /// The names this field will actually take, where its kind does not say it all. `None` is every
    /// name of the kind, which is what almost every field takes.
    ///
    /// A field's kind answers "what sort of thing goes here", and for most fields that is the whole
    /// rule. A few fields do not match their kind for a reason the kind cannot carry: the compiler
    /// resolves an operation identifier across every HTTP method and then refuses one that is not a
    /// `get`; a derivation file belongs to the one question that names it; an answer's schema is
    /// spelled as a document of the authoring form where a source's artifact is not; a fixture and a
    /// derivation are named by writing a path, so the file the author has just created is the one
    /// they are about to write and the one no document declares. What they have in common is that
    /// the name is what decides, so [`Self::target`] having dropped the name is exactly what loses
    /// the rule.
    ///
    /// This is the list itself and not a filter over the symbol table, which is why a field spelled
    /// as a path can offer a file no document has pointed at yet.
    ///
    /// Resolution is deliberately not narrowed by this. The editor may stay quiet where the compiler
    /// refuses and must never speak where the compiler accepts, so a name outside this list still
    /// resolves, still navigates, and still draws its card: telling an author that a `post` their
    /// description really publishes does not exist is a sentence the compiler never prints. What
    /// this bounds is only what the editor volunteers, so that it stops handing an author a name it
    /// knows the compiler will refuse.
    ///
    /// The list is built by the walker that recorded the reference, so every rule inside one stays
    /// with the family that has it and nothing here has to know which family that is.
    pub offers: Option<Arc<BTreeSet<String>>>,
}

/// One place whose candidates come from somewhere other than the symbol table, and what they are.
///
/// A fact path names a leaf of an operation's response rather than a name another document
/// declares, so there is nothing for the reference machinery to hold: no definition to jump to, and
/// nothing that could be reported unresolved. What an author still needs there is the list, which is
/// this. A family with no such field records none of these and loses nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedChoices {
    pub location: IndexedLocation,
    /// How the value at this place was written. See [`IndexedReference::style`].
    pub style: ScalarStyle,
    pub kind: CompletionItemKind,
    /// The form's own word for what these are, drawn beside each one.
    pub detail: &'static str,
    pub values: Arc<BTreeSet<String>>,
}

/// What one family's walk of a project yields.
#[derive(Debug, Default)]
pub struct IndexedProject {
    pub symbols: Vec<IndexedSymbol>,
    pub references: Vec<IndexedReference>,
    pub diagnostics: Vec<IndexedDiagnostic>,
    pub choices: Vec<IndexedChoices>,
}

/// One name offered where a name is being written, and the text it replaces.
///
/// The range is the value the author already wrote, whole, so picking a candidate leaves the field
/// holding that candidate and nothing of what was there before.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionCandidate {
    /// The name as the menu draws it. This is the one part of a candidate that is a rendered
    /// surface rather than a value, and it is bounded like every other piece of a project's own
    /// text this server draws: a name is cut to the width names are quoted at everywhere else, and
    /// a control character or a display directive inside one becomes a character that carries no
    /// instruction. Without that, a name from a description the reader did not write could reorder
    /// the line it is drawn on or run past the menu.
    pub label: String,
    /// The name as the document will hold it, spelled for the scalar it lands in. This is never
    /// bounded: what an author accepts has to be exactly the name the compiler reads, and a cut one
    /// would write a name that resolves to nothing while looking like the one that was offered.
    pub new_text: String,
    /// The name the client filters the menu against, which is the name itself. It is stated rather
    /// than left to default to the label, because the two differ for a name long enough to be cut.
    pub filter_text: String,
    pub kind: CompletionItemKind,
    pub detail: String,
    pub range: Range,
}

/// What the name under the cursor turns out to be, and the text the card belongs to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoverText {
    pub markdown: String,
    pub range: Range,
}

/// One existing reference edge and the definitions the ordinary resolver accepts for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedRelationship {
    pub source: IndexedLocation,
    pub target_kind: SymbolKind,
    pub target_scope: Option<String>,
    pub target_name: String,
    pub definitions: Vec<IndexedLocation>,
}

#[derive(Debug, Default)]
pub struct ProjectIndex {
    root: PathBuf,
    symbols: Vec<IndexedSymbol>,
    references: Vec<IndexedReference>,
    diagnostics: Vec<IndexedDiagnostic>,
    choices: Vec<IndexedChoices>,
    document_paths: BTreeSet<PathBuf>,
}

impl ProjectIndex {
    /// Assemble one already-walked in-memory project.
    ///
    /// Loading, filesystem safety, and deciding which documents belong to a project are adapter
    /// responsibilities. The shared index owns all resolution, diagnostic, completion, and hover
    /// behavior after the adapter supplies the bounded text snapshot and the family walker result.
    pub fn from_indexed(
        root: &Path,
        documents: &BTreeMap<PathBuf, String>,
        walked: IndexedProject,
        mut diagnostics: Vec<IndexedDiagnostic>,
        syntax_errors: BTreeMap<PathBuf, Range>,
        syntax_code: Option<String>,
    ) -> Self {
        let root = root.to_path_buf();
        let mut index = Self {
            root,
            symbols: walked.symbols,
            references: walked.references,
            diagnostics: Vec::new(),
            choices: walked.choices,
            document_paths: documents.keys().cloned().collect(),
        };
        diagnostics.extend(walked.diagnostics);
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
                    code: syntax_code.clone(),
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

    /// An intentionally empty project index carrying only a root-level operational diagnostic.
    ///
    /// This bypasses every family walker. Evidence therefore does not read the OpenAPI description
    /// or manufacture path-derived symbols from the diagnostic's location while a project is over
    /// its aggregate indexing budget.
    pub fn diagnostics_only(root: &Path, mut diagnostics: Vec<IndexedDiagnostic>) -> Self {
        diagnostics.sort_by(diagnostic_cmp);
        diagnostics.dedup();
        Self {
            root: root.to_path_buf(),
            diagnostics,
            ..Self::default()
        }
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

    /// The names that could stand where one is being written. `path` is canonical.
    ///
    /// The list is derived from the same reference navigation answers from, so there is no second
    /// model of which field takes which kind. A reference already knows the kind it holds and the
    /// scope it holds it in; dropping the name from that query and keeping the rest turns "what does
    /// this resolve to" into "what could this have been", which is the question a list answers.
    ///
    /// Dropping the name is also what loses every rule the name decides, so a field whose names its
    /// kind does not describe hands back the names it will take in [`IndexedReference::offers`] and
    /// this reads them instead of the symbols. That belongs here and not in navigation: a list is
    /// the editor volunteering a name, and volunteering one the compiler is known to refuse is the
    /// editor walking an author into a failure it could see coming, while a field spelled as a path
    /// wants the file the author has just created, which is a file no document declares.
    ///
    /// Nothing here reports anything, and nothing here reads a file. A position holding neither a
    /// reference nor a recorded set of choices is offered nothing, which includes every position in
    /// a document the loader kept out of the project.
    pub fn completions_at(&self, path: &Path, position: Position) -> Vec<CompletionCandidate> {
        if let Some(reference) = self.reference_at(path, position) {
            let mut candidates = reference
                .offers
                .as_ref()
                .map(|offers| {
                    // The field's own list already answers what goes here, so the kind and the card
                    // come from the reference. They are what the symbols would have said anyway: a
                    // symbol is only offered when its kind is the one the reference holds.
                    offers
                        .iter()
                        .filter_map(|name| {
                            candidate(
                                name,
                                reference.style,
                                reference.target.kind.lsp_completion_kind(),
                                reference.target.kind.label().to_owned(),
                                reference.location.range,
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| {
                    self.symbols
                        .iter()
                        .filter(|symbol| {
                            symbol.resolvable
                                && self.query_can_offer(&reference.target, &symbol.key)
                        })
                        .filter_map(|symbol| {
                            candidate(
                                &symbol.name,
                                reference.style,
                                symbol.kind.lsp_completion_kind(),
                                symbol.kind.label().to_owned(),
                                reference.location.range,
                            )
                        })
                        .collect::<Vec<_>>()
                });
            // One entry per name, however many places define it. A name two documents declare is
            // one thing the author may write, and the duplicate that makes it ambiguous is a
            // finding rather than a second menu entry.
            candidates.sort_by(|left, right| left.filter_text.cmp(&right.filter_text));
            candidates.dedup_by(|left, right| left.filter_text == right.filter_text);
            return candidates;
        }

        self.choices_at(path, position)
            .map(|choices| {
                choices
                    .values
                    .iter()
                    .filter_map(|value| {
                        candidate(
                            value,
                            choices.style,
                            choices.kind,
                            choices.detail.to_owned(),
                            choices.location.range,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What the name under a position turns out to be. `path` is canonical.
    ///
    /// A reference describes what it resolves to and where that is; a declaration describes itself.
    /// A reference that resolves to nothing describes nothing: the author is already being told
    /// about it by the diagnostic that owns the mistake, and a card restating it would be a second
    /// voice on one field.
    pub fn hover_at(&self, path: &Path, position: Position) -> Option<HoverText> {
        if let Some(reference) = self.reference_at(path, position) {
            let definitions = self.definitions_for(&reference.target);
            if definitions.is_empty() {
                return None;
            }
            let mut markdown = headline(
                reference.target.kind,
                &reference.target.name,
                reference.target.scope.as_deref(),
            );
            for symbol in definitions {
                markdown.push_str("\n\nDefined in ");
                markdown.push_str(&code_span(&self.relative(&symbol.location.path)));
            }
            return Some(HoverText {
                markdown: bounded_hover(&markdown),
                range: reference.location.range,
            });
        }

        let symbol = self.symbol_at(path, position)?;
        Some(HoverText {
            markdown: bounded_hover(&headline(
                symbol.kind,
                &symbol.name,
                symbol.key.scope.as_deref(),
            )),
            range: symbol.location.range,
        })
    }

    pub fn diagnostics(&self) -> &[IndexedDiagnostic] {
        &self.diagnostics
    }

    /// Existing reference edges, resolved by the same rules as cursor navigation.
    pub fn relationships(&self, maximum: usize) -> Vec<IndexedRelationship> {
        self.references
            .iter()
            .take(maximum)
            .map(|reference| IndexedRelationship {
                source: reference.location.clone(),
                target_kind: reference.target.kind,
                target_scope: reference.target.scope.clone(),
                target_name: reference.target.name.clone(),
                definitions: self
                    .definitions_for(&reference.target)
                    .into_iter()
                    .map(|symbol| symbol.location.clone())
                    .collect(),
            })
            .collect()
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

    fn choices_at(&self, path: &Path, position: Position) -> Option<&IndexedChoices> {
        self.choices.iter().find(|choices| {
            choices.location.path == path && range_contains(choices.location.range, position)
        })
    }

    fn query_can_resolve_to(&self, query: &SymbolQuery, key: &SymbolKey) -> bool {
        query.kind == key.kind
            && query.name == key.name
            && query
                .scope
                .as_ref()
                .is_none_or(|scope| key.scope.as_ref() == Some(scope))
    }

    /// [`Self::query_can_resolve_to`] without the name: everything a reference of this shape is
    /// allowed to hold, rather than the one thing it does hold.
    ///
    /// Kind and scope only. Whatever the name itself decides went out with the name, and comes back
    /// through [`IndexedReference::offers`] for the fields that have such a rule.
    fn query_can_offer(&self, query: &SymbolQuery, key: &SymbolKey) -> bool {
        query.kind == key.kind
            && query
                .scope
                .as_ref()
                .is_none_or(|scope| key.scope.as_ref() == Some(scope))
    }

    /// One project path as an author names it, which is from the root of the project rather than
    /// from the root of the machine.
    fn relative(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .display()
            .to_string()
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
pub const DOCUMENT_CEILING_RULE: &str = "document-ceiling";

/// The rule a directory holding more documents than the editor indexes is reported under.
pub const DIRECTORY_CEILING_RULE: &str = "directory-ceiling";

/// The rule a project exceeding the editor's aggregate indexing budget is reported under.
pub const PROJECT_CEILING_RULE: &str = "project-ceiling";

/// A problem with a whole document rather than a place in it, reported at its start.
pub fn document_diagnostic(path: &Path, message: &str) -> IndexedDiagnostic {
    document_rule_diagnostic(path, None, message)
}

/// The same, for a document the editor refused under a rule of its own.
///
/// The two ceilings are rules of the authoring form that the editor restates, so an author reads
/// them beside the rules the compiler prints and filters them the same way: by name, rather than by
/// silencing everything the server says.
pub fn document_rule_diagnostic(
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
pub const DOCUMENT_START: Range = Range {
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

/// The first line of a card: what this is, what it is called, and the scope it is called that in.
///
/// This composes the same sentence [`scope_suffix`] ends, and does not reuse it, because a card is
/// markup where a message is text: every piece the author wrote is drawn here inside a code span,
/// which is not what a message wants around a name it quotes mid-sentence.
fn headline(kind: SymbolKind, name: &str, scope: Option<&str>) -> String {
    let scope = scope
        .map(|scope| format!(" in {} {}", kind.scope_label(), code_span(scope)))
        .unwrap_or_default();
    format!("**{}** {}{}", kind.label(), code_span(name), scope)
}

/// One piece of author-written text, drawn as the code span a card quotes it in.
///
/// Two adjacent backticks are not an empty code span. They are a backtick string of length two, and
/// nothing of length two closes it, so a client draws both of them literally and the card ends up
/// saying something the author did not write. An empty name is one `evidence check` rejects, so this
/// only has to be honest about it rather than hide it: a span holding one space is drawn as a span
/// holding one space, which is what a name with nothing in it looks like.
fn code_span(value: &str) -> String {
    let span = bounded_span(value);
    if span.is_empty() {
        "` `".to_owned()
    } else {
        format!("`{span}`")
    }
}

/// One piece of text an author wrote, made safe to draw inside the code span a card quotes it in.
///
/// A card is the one thing this server renders as markup rather than states as text, and the names
/// and paths inside one come from a project its reader did not write. [`bounded_value`] makes such a
/// name safe to quote in a sentence a client draws as text, which is a different promise: it leaves
/// markdown's punctuation alone, as a message wants. Inside a code span every one of those characters
/// is inert but the backtick, which closes the span and hands the rest of the line to the author. So
/// the backtick is what this replaces, and replacing it is what keeps a card this crate's sentence
/// rather than the author's markup. A name that reaches a card carrying one is a name `evidence
/// check` rejects; the editor draws it anyway, which is the whole reason the card cannot assume it.
fn bounded_span(value: &str) -> String {
    bounded_value(value).replace('`', "\u{fffd}")
}

/// The ceiling on a whole card, in characters.
///
/// Nothing composed here comes near it: a card is a kind, a name already cut to the width a name is
/// quoted at, and one line per place that name is defined, each of those a path cut the same way.
/// What it bounds is the number of places, so a name a thousand documents declare renders a card
/// rather than a document of its own. A card is rendered UI rather than a message or a log, which is
/// why it has a ceiling of its own rather than either of the two above.
const MAX_HOVER_CHARS: usize = 4096;

/// One card cut to that ceiling, at the last whole line that fits.
///
/// Unlike [`bounded`], this leaves control characters alone, because the newlines separating the
/// lines of a card are its own. Every piece of author-written text inside one has already been
/// through [`code_span`], which replaced both the control characters and the one markdown character
/// that would have let the author draw the rest of the card.
///
/// The cut lands on a line boundary rather than on the ceiling itself, so a card that does not fit
/// is still the lines it is written in: every line the reader is shown is a whole one, and the mark
/// that says lines were dropped is a line of its own. Cutting mid-line is not an injection, because
/// a code span left unclosed is drawn as the backtick it is, but it would leave the reader a half
/// sentence that reads as a whole one.
///
/// What comes back is at most the ceiling in card, plus the break and the mark that say it was cut,
/// the same shape the two ceilings above have: the bound is on what the card is allowed to say, not
/// on the three characters saying it stopped.
fn bounded_hover(markdown: &str) -> String {
    if markdown.chars().count() <= MAX_HOVER_CHARS {
        return markdown.to_owned();
    }
    let ceiling = markdown
        .char_indices()
        .nth(MAX_HOVER_CHARS)
        .map_or(markdown.len(), |(index, _)| index);
    let kept = markdown[..ceiling]
        .rfind('\n')
        .map_or(&markdown[..ceiling], |newline| &markdown[..newline])
        .trim_end_matches('\n');
    format!("{kept}\n\n…")
}

/// One name offered at one place, or nothing when the name cannot be written there.
///
/// The two spellings of a name part company here. What the menu draws is bounded the way every other
/// piece of a project's own text this server renders is bounded, because a name out of a description
/// the reader did not write is drawn on a line beside names they did. What the document will hold is
/// bounded by nothing: it is the name, spelled for the scalar it lands in, and cutting it would
/// write a name the compiler cannot resolve in the moment the author was told it could. This is how
/// a list is presented rather than what a list is allowed to say, and it takes nothing out of the
/// reader's reach: the name is filtered on and written whole.
///
/// A name that cannot be written in that scalar at all is not offered. Shortening a list is
/// something the editor may always do, and the alternative is a keystroke that breaks the document.
fn candidate(
    name: &str,
    style: ScalarStyle,
    kind: CompletionItemKind,
    detail: String,
    range: Range,
) -> Option<CompletionCandidate> {
    Some(CompletionCandidate {
        label: bounded_value(name),
        new_text: written_as(name, style)?,
        filter_text: name.to_owned(),
        kind,
        detail,
        range,
    })
}

/// One name an author wrote, made safe to quote inside a message and cut to the width of a name.
pub fn bounded_value(value: &str) -> String {
    bounded(value, 120)
}

/// A whole sentence another implementation composed, made safe the same way and cut far above the
/// length of any sentence it writes.
///
/// A sentence from the authoring library already carries a name the author wrote inside it, and the
/// instruction the author has to act on comes after that name. Cutting such a sentence to the width
/// of one name removes exactly the part the finding exists to give, so the ceiling here bounds the
/// channel rather than the message.
pub fn bounded_message(message: &str) -> String {
    bounded(message, 1024)
}

/// What both ceilings share: a character that carries an instruction becomes one that carries none,
/// and text that does not fit ends in the mark that says so.
fn bounded(value: &str, max_chars: usize) -> String {
    let mut bounded = value
        .chars()
        .take(max_chars)
        .map(|character| {
            if character.is_control() || is_display_directive(character) {
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

/// The instructions a display obeys that [`char::is_control`] does not name.
///
/// Rust's `is_control` is Unicode general category `Cc`, which is what a *terminal* acts on. Both
/// surfaces this server writes to are drawn rather than printed: a diagnostic is text a client lays
/// out, and a card is markup a client renders. Those obey a second set. The reordering characters
/// are `Cf`, and one inside a name rewrites the sentence quoting it, so a message can be made to
/// read as its own opposite while the name it names stays intact. The two separators are `Zl` and
/// `Zp`, and one inside a name breaks a message across lines where the message has no break. The
/// invisible ones have no width at all, so two names that differ only by one draw as a single name
/// and the reader has no way to see which is which.
///
/// `rustc` refuses the reordering half in a source literal for the same reason, under
/// `text_direction_codepoint_in_literal`. A name carrying any of these is a name `evidence check`
/// rejects, because the authoring form accepts only lowercase ASCII in a name; the editor still has
/// to say so before anyone runs the compiler, which is the whole reason it cannot assume the
/// compiler's answer. Replacing them costs nothing an author can write correctly.
///
/// What this does not buy, and must not be read as buying: two names that differ by a Cyrillic and a
/// Latin `a` still draw as one card, and no substitution can tell them apart. The compiler stays the
/// authority on whether two names are one name.
fn is_display_directive(character: char) -> bool {
    matches!(
        character,
        // Reordering: the marks, the embeddings and overrides, the isolates, and the pops.
        '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        // Separators: LINE SEPARATOR and PARAGRAPH SEPARATOR.
        | '\u{2028}'..='\u{2029}'
        // Invisible: soft hyphen, the zero-width space and joiners, word joiner, byte-order mark.
        | '\u{00ad}' | '\u{200b}'..='\u{200d}' | '\u{2060}' | '\u{feff}'
    )
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

    /// An Evidence concept is answered by the question that owns it.
    #[test]
    fn a_scope_is_named_in_the_vocabulary_of_the_family_that_owns_it() {
        assert_eq!(
            scope_suffix(
                SymbolKind::Evidence(EvidenceKind::Concept),
                Some("adult-status")
            ),
            " in question 'adult-status'"
        );
    }

    /// A name with no scope says nothing about where it is written.
    #[test]
    fn a_name_with_no_scope_carries_no_suffix() {
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

    /// A card is cut at its own ceiling and keeps the newlines that lay it out. Nothing an author
    /// writes reaches one without going through [`bounded_value`] first, so the only control
    /// characters a card can hold are the ones this crate put there.
    ///
    /// The cut lands on a line boundary, so every line the reader is shown is one this crate wrote
    /// whole: the last kept line is a complete `Defined in` line rather than a prefix of one, and
    /// the mark saying lines were dropped is a line of its own.
    #[test]
    fn a_card_is_cut_at_its_ceiling_and_keeps_the_lines_it_is_written_in() {
        let card = format!("**source** `x`{}", "\n\nDefined in `y`".repeat(500));
        assert!(card.chars().count() > MAX_HOVER_CHARS);

        let bounded = bounded_hover(&card);
        assert!(bounded.chars().count() <= MAX_HOVER_CHARS + 3);
        assert!(bounded.ends_with("\n\n…"));
        for line in bounded.lines().filter(|line| !line.is_empty()) {
            assert!(
                line == "**source** `x`" || line == "Defined in `y`" || line == "…",
                "a cut card kept a partial line: {line:?}"
            );
        }
        assert_eq!(bounded_hover("**source** `x`"), "**source** `x`");
    }

    /// A card with one line and nothing else to cut still keeps a whole line when it does not fit,
    /// because there is no boundary to fall back to and the ceiling is what is left.
    #[test]
    fn a_card_of_one_long_line_is_cut_at_the_ceiling_itself() {
        let card = format!("**source** `{}`", "x".repeat(MAX_HOVER_CHARS));
        let bounded = bounded_hover(&card);
        assert_eq!(bounded.chars().count(), MAX_HOVER_CHARS + 3);
        assert!(bounded.ends_with("\n\n…"));
    }

    /// The characters a display obeys and a terminal does not. A name carrying one is a name the
    /// authoring form refuses, and the editor draws its card before anyone runs the compiler, so it
    /// cannot leave the reordering to be discovered by the compiler's answer.
    #[test]
    fn text_that_reaches_a_message_is_stripped_of_what_a_display_obeys() {
        assert_eq!(bounded_value("a\u{202e}b"), "a�b");
        assert_eq!(bounded_value("a\u{2066}b\u{2069}"), "a�b�");
        assert_eq!(bounded_value("a\u{061c}b"), "a�b");
        assert_eq!(bounded_value("a\u{200e}b\u{200f}"), "a�b�");
        assert_eq!(bounded_value("a\u{2028}b\u{2029}"), "a�b�");
        assert_eq!(bounded_value("a\u{00ad}b\u{feff}"), "a�b�");
        assert_eq!(bounded_value("a\u{200b}b\u{200c}c\u{200d}d"), "a�b�c�d");
        assert_eq!(bounded_value("a\u{2060}b"), "a�b");
        assert_eq!(bounded_message("a\u{202e}b"), "a�b");

        // Every one of the twenty, and nothing outside them: an ordinary name is left alone.
        assert_eq!(
            ('\u{0}'..='\u{ffff}')
                .filter(|character| is_display_directive(*character))
                .count(),
            20
        );
        assert_eq!(bounded_value("person.adult-status"), "person.adult-status");
    }

    /// A name with nothing in it is quoted as a span the reader can see, because two adjacent
    /// backticks are a backtick string nothing closes and both are drawn as themselves.
    #[test]
    fn an_empty_name_is_quoted_as_a_span_that_closes() {
        assert_eq!(code_span(""), "` `");
        assert_eq!(code_span("a"), "`a`");
        assert_eq!(
            headline(SymbolKind::Evidence(EvidenceKind::Question), "", None),
            "**question** ` `"
        );
        assert_eq!(
            headline(
                SymbolKind::Evidence(EvidenceKind::Concept),
                "person.adult-status",
                Some("adult")
            ),
            "**concept** `person.adult-status` in question `adult`"
        );
    }
}
