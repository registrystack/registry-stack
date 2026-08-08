// SPDX-License-Identifier: Apache-2.0
//! Walks the parsed documents of one Evidence authoring project into symbols and references.
//!
//! Every edge walked here is an edge `registry-evidencectl` already refuses a project for: a
//! question that names a source with no document, a derivation file that is not there, an access
//! policy that admits a question the project does not hold. The editor draws them earlier, on text
//! that has not been saved yet, and says the same thing about them. It never draws one the compiler
//! would accept, because a diagnostic an author cannot act on teaches them to ignore the channel.
//! Two rules hold that property where it is hardest to keep: a document this root could not read
//! still declares the name its path gives it, so the documents spelling that name are not told it
//! is missing, and a source no question reads has its names resolved for navigation and reported to
//! nobody, because nothing in the build looks inside it either.
//!
//! Four of those edges are drawn against the project's own OpenAPI description rather than against
//! another authored document: `source.operation` names an operation it publishes,
//! `subject.selector` names one of that operation's path parameters, each `source.facts[].path`
//! selects a leaf of its response, and each key of `source.collectionBounds` names a collection some
//! fact path visits. They are walked in [`IndexBuilder::walk_openapi_edges`], in the order
//! `compile_question_plan` (`crates/registry-evidencectl/src/authoring.rs:964-1023`) reaches them,
//! and a rung that reports stops the ones below it: the compiler stops at its first refusal, and an
//! author whose operation name has a typo needs one sentence about the typo rather than a sentence
//! about every field that reads the operation it did not find.
//!
//! One family of edge is absent. A source names the scripts that prepare its request
//! and extract its facts, `request.prepareScript` and `extractScript`, and the compiler reads both
//! files. The reference vocabulary has no kind for an authored script, and calling one a schema or
//! a derivation would put a word in front of the author that means another part of the form, so the
//! two pointers are left alone until there is a kind that names them.
//!
//! Five rules of the authoring form belong to the compiler alone, and every one of them leaves the
//! editor quieter than the build rather than louder. A `sources/` or `selectors/` directory may
//! hold only `<id>.yaml` files whose stem is a lowercase local identifier, so a `sources/README.md`
//! or a `sources/People.yaml` is a project `registry-evidencectl` refuses, while a path is
//! classified here by its directory and its `.yaml` extension and its stem is only ever read as a
//! name. A selector profile has to carry a `fields` object and to declare the field the question
//! selects its subject by, while `selectors/<profile>.yaml` resolves here as soon as a file sits
//! there. A question's subject has to be one its source really uses, and its subjects have to
//! select exactly one alternative for every role the source declares, which is a reading of two
//! documents against each other that nothing here performs. An access policy has to name between
//! one and the 128 questions the form allows, sorted and unique, and only the names themselves are
//! resolved here. Every question has to name its own derivation file, which no single question
//! shows: two questions pointing at one `derivations/shared.rhai` both resolve, because that file
//! is defined once under the path they both spell.
//!
//! The five are recorded rather than closed, so a reader can tell a deliberate silence from a
//! defect. Each one is a sentence the compiler gives the author anyway, and a rule drawn here on
//! less than it needs is exactly the diagnostic over a project that builds that the paragraph above
//! rules out.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

use registry_evidence_authoring::{
    layout::SCHEMAS_DIRECTORY, model::Question, validate::collection_pointers,
};
use tower_lsp_server::ls_types::{CompletionItemKind, DiagnosticSeverity, Range};

use crate::{
    evidence::{
        diagnostics::read_question,
        layout::{document_role, DocumentRole},
        openapi::Description,
    },
    refs::{
        bounded_value, EvidenceKind, IndexedChoices, IndexedDiagnostic, IndexedLocation,
        IndexedProject, IndexedReference, IndexedSymbol, SymbolKey, SymbolQuery, DOCUMENT_START,
    },
    yaml::{ParsedDocument, YamlScalar, YamlValue},
};

/// Where a source keeps the scripts and schemas its own traffic uses, beside
/// [`SCHEMAS_DIRECTORY`]. The authoring library names the second of the two directories the
/// compiler reads a source's artifacts from, so the first is spelled here beside the rule that
/// needs it.
const ADAPTERS_DIRECTORY: &str = "adapters";

pub(crate) fn build_index(
    root: &Path,
    documents: &BTreeMap<PathBuf, String>,
    parsed: &BTreeMap<PathBuf, ParsedDocument>,
    dropped: &BTreeSet<PathBuf>,
) -> IndexedProject {
    let mut builder = IndexBuilder {
        root,
        symbols: Vec::new(),
        references: Vec::new(),
        diagnostics: Vec::new(),
        choices: Vec::new(),
        referenced_files: BTreeSet::new(),
    };
    let read_sources = sources_questions_read(root, parsed);
    // The one project file the loader leaves on disk, read once for the whole build. Every operation
    // it publishes is defined here, whether or not a question names it, so that `Find references` on
    // an operation answers from the description an author is looking at.
    let mut description = Description::read(root);
    if let Some(description) = &description {
        for (operation_id, operation) in description.published() {
            builder.define(
                SymbolKey::global(EvidenceKind::Operation, operation_id),
                None,
                description.path(),
                operation.range,
            );
        }
    }

    for (path, document) in parsed {
        let Some(relative) = path.strip_prefix(root).ok() else {
            continue;
        };
        let Some(role) = document_role(relative) else {
            continue;
        };
        let Some(name) = document_name(relative) else {
            continue;
        };
        match role {
            DocumentRole::Question => {
                builder.walk_question(path, name, &document.value);
                if let Some(source) = documents.get(path) {
                    let reading = read_question(path, source, document);
                    let validated = reading.validated;
                    builder.diagnostics.extend(reading.diagnostics);
                    if let Some(question) = validated {
                        builder.walk_openapi_edges(
                            path,
                            name,
                            &document.value,
                            &question,
                            description.as_mut(),
                        );
                    }
                }
            }
            DocumentRole::Source => {
                builder.walk_source(path, name, &document.value, read_sources.contains(name));
            }
            DocumentRole::Selector => builder.define(
                SymbolKey::global(EvidenceKind::SelectorProfile, name),
                None,
                path,
                DOCUMENT_START,
            ),
            DocumentRole::AccessPolicy => builder.walk_access_policy(path, name, &document.value),
            // A schema and a fixture are named by their path rather than by anything written inside
            // them, so the document that points at one defines it. The marker declares the root, the
            // OpenAPI description belongs to the phase that reads operations, and a derivation is
            // Rhai and never parsed as YAML at all.
            DocumentRole::Schema
            | DocumentRole::Fixture
            | DocumentRole::Marker
            | DocumentRole::OpenApi
            | DocumentRole::Derivation => {}
        }
    }

    for path in dropped {
        builder.define_by_its_place(path);
    }

    IndexedProject {
        symbols: builder.symbols,
        references: builder.references,
        diagnostics: builder.diagnostics,
        choices: builder.choices,
    }
}

struct IndexBuilder<'a> {
    root: &'a Path,
    symbols: Vec<IndexedSymbol>,
    references: Vec<IndexedReference>,
    diagnostics: Vec<IndexedDiagnostic>,
    /// The places an author picks from a set the description holds rather than from a name another
    /// document declares. Only fact paths are such a place today.
    choices: Vec<IndexedChoices>,
    /// The files already defined by a pointer at them, so two documents pointing at one schema
    /// define it once rather than reporting each other as duplicates.
    referenced_files: BTreeSet<SymbolKey>,
}

impl IndexBuilder<'_> {
    /// A question defines itself, the concepts it answers, and the names it spells of other
    /// documents.
    ///
    /// The question is defined under its file name rather than under the `id` it writes, because
    /// that is the name every other document spells and the name the compiler reads it by. When the
    /// two disagree the mismatch is reported here, on the `id`, and the rest of the project keeps
    /// resolving against the file while the author fixes the one document that is wrong.
    fn walk_question(&mut self, path: &Path, name: &str, value: &YamlValue) {
        let written = value.get_scalar("id");
        self.define(
            SymbolKey::global(EvidenceKind::Question, name),
            None,
            path,
            written.map_or(DOCUMENT_START, |scalar| scalar.range),
        );
        self.check_file_name(
            path,
            name,
            written,
            "Question",
            "evidence/question-file-name",
        );

        for subject in subjects(value) {
            if let Some(profile) = subject.get_scalar("profile") {
                self.refer(
                    SymbolQuery::global(EvidenceKind::SelectorProfile, profile.value.as_str()),
                    path,
                    profile.range,
                );
            }
        }

        if let Some(source) = value
            .get("source")
            .and_then(|source| source.get_scalar("ref"))
        {
            self.refer(
                SymbolQuery::global(EvidenceKind::Source, source.value.as_str()),
                path,
                source.range,
            );
        }

        for answer in sequence(value.get("answers")) {
            if let Some(concept) = answer.get_scalar("concept") {
                // A concept belongs to the question that answers it: two questions may answer the
                // same concept of the same subject, and neither one's disclosure may reach the
                // other's answer.
                self.define(
                    SymbolKey::scoped(EvidenceKind::Concept, name, concept.value.as_str()),
                    Some(name.to_owned()),
                    path,
                    concept.range,
                );
            }
            if let Some(schema) = answer.get_scalar("schema") {
                self.refer_to_file(path, schema, EvidenceKind::SchemaFile);
            }
        }

        if let Some(derivation) = value.get_scalar("derivation") {
            self.refer_to_file(path, derivation, EvidenceKind::DerivationFile);
        }

        for allowed in scalars(value.get("disclosure").and_then(|value| value.get("allow"))) {
            // Navigation only. `registry_evidence_authoring::validate` already refuses a disclosure
            // that is not exactly the answered concepts, and its sentence is the one the compiler
            // prints, so reporting a second one here would put two errors on one mistake.
            self.refer_quietly(
                SymbolQuery::scoped(EvidenceKind::Concept, name, allowed.value.as_str()),
                path,
                allowed.range,
            );
        }

        if let Some(fixtures) = value
            .get("governance")
            .and_then(|governance| governance.get_scalar("fixtures"))
        {
            // `evidence/unknown-fixture-file` is paired with a compiler rule that sits two crates
            // from here, so it does not read as an editor invention beside the ones it is listed
            // with. `registry-evidencectl`'s check that this pointer is a project-relative
            // `fixtures/<name>.yaml` runs when it validates production inputs; a local compile
            // reads the same file while it writes the bundle, and the `evidence` binary refuses a
            // fixtures artifact whose path is not under `fixtures/` when it reads that bundle back.
            self.refer_to_file(path, fixtures, EvidenceKind::FixtureFile);
        }
    }

    /// The edges a question written in the compact form draws into the project's own OpenAPI
    /// description.
    ///
    /// `question` has already been accepted by `registry_evidence_authoring::validate`, which is the
    /// state `compile_question_plan` reads it in: it takes the inline source out with
    /// `.expect("inline source was validated")`
    /// (`crates/registry-evidencectl/src/authoring.rs:989`). So a question that is malformed reaches
    /// nothing here, and the malformed field is reported once, by the check that owns it.
    ///
    /// The rungs below run in the compiler's own order and each one stops the rest. That is not
    /// tidiness: an operation name with a typo makes every selector, every fact path and every
    /// collection bound unresolvable against an operation that was never found, and answering one
    /// mistake with four sentences puts the author's attention on three fields that are correct.
    fn walk_openapi_edges(
        &mut self,
        path: &Path,
        name: &str,
        value: &YamlValue,
        question: &Question,
        description: Option<&mut Description>,
    ) {
        // The referenced form: this question reads a source document, so its source names nothing in
        // the description. A question writing both is refused under `source-declaration` before it
        // gets here.
        if question.source.source_ref.is_some() {
            return;
        }
        let (Some(operation_id), Some(description)) =
            (question.source.operation.as_deref(), description)
        else {
            return;
        };
        let source = value.get("source");
        let Some(written) = source.and_then(|source| source.get_scalar("operation")) else {
            return;
        };

        // Edge 1. Resolution, and the sentence for an identifier that resolves to none or to two,
        // both come from the reference machinery: `unique_operation`
        // (`crates/registry-evidencectl/src/authoring.rs:1565-1567`) refuses those two cases with one
        // sentence, and it is the same condition.
        self.refer(
            SymbolQuery::global(EvidenceKind::Operation, operation_id),
            path,
            written.range,
        );
        // What the rungs below need, taken now: reading the response leaves needs the description
        // itself, and holding on to the resolved operation would keep it borrowed.
        let Some((key, selectors)) = description
            .resolved(operation_id)
            .map(|operation| (operation.key.clone(), operation.selectors.clone()))
        else {
            return;
        };

        // Edge 2. `exact_path_selectors` (`crates/registry-evidencectl/src/authoring.rs:1575-1646`)
        // requires the question's selectors to be exactly the operation's required string path
        // parameters, so a selector outside that set refuses the project: at the count check when
        // there are as many selectors as parameters, and at the comparison otherwise.
        //
        // Only that one case is reported. Selectors that are all parameters but too few of them, a
        // selector written twice, and a parameter no selector names are refusals stated in terms of
        // the whole set rather than of one field, and so is the rule that a selector occupies a
        // complete path segment (:1623-1644). The compiler gives the author those sentences; an
        // editor picking a field to underline for them would be picking one.
        let Some(selectors) = selectors else {
            return;
        };
        let mut reported = false;
        for subject in subjects(value) {
            let Some(written) = subject.get_scalar("selector") else {
                continue;
            };
            if selectors.contains(written.value.as_str()) {
                continue;
            }
            reported = true;
            self.report(
                path,
                written.range,
                "evidence/subject-selector",
                format!(
                    "Subject selector '{}' is not a required string path parameter of operation '{}'",
                    bounded_value(&written.value),
                    bounded_value(operation_id)
                ),
            );
        }
        if reported {
            return;
        }

        // Edge 3. The set is the compiler's own: `compile_facts` asks `selectable_leaves` for it at
        // `crates/registry-evidencectl/src/authoring.rs:1661` and refuses a fact whose path is not in
        // it at :1666-1674. A response that cannot be read or flattened answers `None`, and every
        // fact path is then left alone rather than measured against an empty set.
        let Some(leaves) = description.selectable(&key) else {
            return;
        };
        let written_paths = sequence(source.and_then(|source| source.get("facts")))
            .iter()
            .filter_map(|fact| fact.get_scalar("path"))
            .collect::<Vec<_>>();
        // The list an author reads at each fact path, recorded before the rung below can stop on a
        // path that is not a leaf: a path this response does not offer is exactly the moment the
        // list is worth having. This is a set of choices rather than a reference, so it defines
        // nothing, resolves to nothing, and cannot be reported unresolved. The set itself is the
        // compiler's own, so a path offered here is a path the build accepts.
        for written in &written_paths {
            self.choices.push(IndexedChoices {
                location: IndexedLocation {
                    path: path.to_path_buf(),
                    range: written.range,
                },
                kind: CompletionItemKind::VALUE,
                detail: "selectable leaf",
                values: leaves.clone(),
            });
        }
        let mut reported = false;
        for written in &written_paths {
            if leaves.contains(written.value.as_str()) {
                continue;
            }
            reported = true;
            self.report(
                path,
                written.range,
                "evidence/unselectable-fact-path",
                format!(
                    "Fact path '{}' is not a selectable leaf of the 200 application/json response of operation '{}'",
                    bounded_value(&written.value),
                    bounded_value(operation_id)
                ),
            );
        }
        if reported {
            return;
        }

        // Edge 4. `compile_facts` settles `source.collectionBounds` against the collections the fact
        // paths visit and refuses a project where either side names something the other does not
        // (`crates/registry-evidencectl/src/authoring.rs:1681-1705`).
        //
        // Both directions rest on knowing every visited collection, so they are only drawn when the
        // paths found in the text are the paths the accepted question holds. A path this reading
        // missed would hide a collection, and the author's correct bound on it would be reported as
        // naming nothing.
        if written_paths.len() != question.source.facts.len()
            || written_paths
                .iter()
                .zip(&question.source.facts)
                .any(|(written, fact)| written.value != fact.path)
        {
            return;
        }
        // One collection however many facts visit it: the author writes one bound for it, and a
        // collection defined once per fact would answer that bound with "ambiguous reference" over a
        // project that builds. It belongs to the question, because another question's facts walk
        // another operation's response.
        let mut visited: BTreeMap<String, Range> = BTreeMap::new();
        for written in &written_paths {
            for pointer in collection_pointers(&written.value) {
                visited.entry(pointer).or_insert(written.range);
            }
        }
        for (pointer, range) in &visited {
            self.define(
                SymbolKey::scoped(EvidenceKind::Collection, name, pointer.as_str()),
                Some(name.to_owned()),
                path,
                *range,
            );
            if question.source.collection_bounds.contains_key(pointer) {
                continue;
            }
            self.report(
                path,
                *range,
                "evidence/undeclared-collection",
                format!(
                    "This path visits the collection '{}', which source.collectionBounds does not bound",
                    bounded_value(pointer)
                ),
            );
        }
        // The other direction is the reference machinery's: a bound naming a collection no fact
        // visits is a name with no definition, which is the same condition and the same sentence
        // shape as every other unresolved reference in the form.
        for bound in source
            .and_then(|source| source.get("collectionBounds"))
            .and_then(YamlValue::as_mapping)
            .unwrap_or_default()
        {
            self.refer(
                SymbolQuery::scoped(EvidenceKind::Collection, name, bound.key.value.as_str()),
                path,
                bound.key.range,
            );
        }
    }

    /// A source defines itself and names the selector profiles its callers may pick a subject with
    /// and the schemas its own traffic is checked against.
    ///
    /// Nothing inside a source document names it: the project reads a source by its file, which is
    /// also how a question spells it, so the symbol is anchored at the start of the file.
    ///
    /// What it names is only reported when a question reads it. The compile walks the questions and
    /// pulls each one's source out of the set it loaded, so a source no question names is never
    /// looked inside: the build accepts a project holding one that is half written, and the editor
    /// resolves its names for navigation without saying anything about them.
    fn walk_source(
        &mut self,
        path: &Path,
        name: &str,
        value: &YamlValue,
        read_by_a_question: bool,
    ) {
        self.define(
            SymbolKey::global(EvidenceKind::Source, name),
            None,
            path,
            DOCUMENT_START,
        );

        let request = value.get("request");
        for input in sequence(request.and_then(|request| request.get("selectorInputs"))) {
            for alternative in sequence(input.get("alternatives")) {
                if let Some(profile) = alternative.get_scalar("profile") {
                    self.add_reference(
                        SymbolQuery::global(EvidenceKind::SelectorProfile, profile.value.as_str()),
                        path,
                        profile.range,
                        read_by_a_question,
                    );
                }
            }
        }

        if let Some(schema) =
            request.and_then(|request| request.get_scalar("adapterParametersSchema"))
        {
            self.refer_to_source_artifact(path, schema, read_by_a_question);
        }
        for pointer in ["responseSchema", "factSchema"] {
            if let Some(schema) = value.get_scalar(pointer) {
                self.refer_to_source_artifact(path, schema, read_by_a_question);
            }
        }
    }

    /// An access policy defines itself and names the questions it admits.
    fn walk_access_policy(&mut self, path: &Path, name: &str, value: &YamlValue) {
        let written = value.get_scalar("id");
        self.define(
            SymbolKey::global(EvidenceKind::AccessPolicy, name),
            None,
            path,
            written.map_or(DOCUMENT_START, |scalar| scalar.range),
        );
        self.check_file_name(
            path,
            name,
            written,
            "Access policy",
            "evidence/access-policy-file-name",
        );

        for question in scalars(value.get("questions")) {
            self.refer(
                SymbolQuery::global(EvidenceKind::Question, question.value.as_str()),
                path,
                question.range,
            );
        }
    }

    /// Reports a document whose written identifier is not the name of its file.
    fn check_file_name(
        &mut self,
        path: &Path,
        name: &str,
        written: Option<&YamlScalar>,
        label: &str,
        code: &str,
    ) {
        let Some(written) = written.filter(|scalar| scalar.value != name) else {
            return;
        };
        self.report(
            path,
            written.range,
            code,
            format!(
                "{label} '{}' does not match its file name; rename the identifier or the file so both read '{}'",
                bounded_value(&written.value),
                bounded_value(name)
            ),
        );
    }

    /// Records a pointer at another document of the authoring form, and defines what it points at
    /// when a document of that role is really there.
    ///
    /// These targets are spelled the way the form spells the document itself, and the compiler
    /// resolves them the same way: a derivation is `derivations/<name>.rhai`, an answer schema is
    /// `schemas/<name>.yaml`, a fixture file is `fixtures/<name>.yaml`. A target written any other
    /// way is one the compiler refuses too.
    fn refer_to_file(&mut self, path: &Path, pointer: &YamlScalar, kind: EvidenceKind) {
        self.refer(
            SymbolQuery::global(kind, pointer.value.as_str()),
            path,
            pointer.range,
        );

        let Some(role) = referenced_file_role(kind) else {
            return;
        };
        let relative = Path::new(pointer.value.as_str());
        if document_role(relative) != Some(role) {
            return;
        }
        self.define_pointed_file(kind, pointer, relative);
    }

    /// Records a pointer at one of a source's own artifacts, which is read by a rule of its own.
    ///
    /// A question's answer schema is a document of the authoring form and is spelled like one. A
    /// source's artifacts are not: the compiler asks only that the path be `adapters/<file>` or
    /// `schemas/<file>`, imposes no extension, and copies the file into the bundle byte for byte
    /// rather than reading it. So a schema written as JSON, or kept beside the scripts that use it,
    /// is one the build accepts, and resolving these pointers through the layout of authored
    /// documents would draw an error over a project that compiles.
    fn refer_to_source_artifact(&mut self, path: &Path, pointer: &YamlScalar, reported: bool) {
        self.add_reference(
            SymbolQuery::global(EvidenceKind::SchemaFile, pointer.value.as_str()),
            path,
            pointer.range,
            reported,
        );

        let relative = Path::new(pointer.value.as_str());
        if !is_source_artifact(relative) {
            return;
        }
        self.define_pointed_file(EvidenceKind::SchemaFile, pointer, relative);
    }

    /// Defines what a document declares by sitting where it does, for a document this root holds no
    /// text for.
    ///
    /// A file past its ceiling, one that is not valid UTF-8, one the server could not open, and the
    /// first file of a directory that overflows are all documents the project has and the editor
    /// could not read. Each one is already reported once, on itself, with the reason and the fix.
    /// Leaving its name undefined would report it a second time on every document that spells it,
    /// which are documents with nothing wrong: an access policy admitting a question would be told
    /// the question does not exist. So the name is taken from the path, which the authoring form
    /// makes the name anyway, and the definition is anchored at the start of the file the author has
    /// to open. Nothing here reads the file: a document with no text has no `id` to check, no
    /// references to record, and no shape to judge, and its own sentence stands.
    fn define_by_its_place(&mut self, path: &Path) {
        let Some(relative) = path.strip_prefix(self.root).ok() else {
            return;
        };
        let Some(kind) = document_role(relative).and_then(named_by_its_file) else {
            return;
        };
        let Some(name) = document_name(relative) else {
            return;
        };
        self.define(SymbolKey::global(kind, name), None, path, DOCUMENT_START);
    }

    /// Defines the file a pointer names, once a file the server may open really sits there.
    ///
    /// The pointer is the name: the project spells these targets as paths, so `Find references` on
    /// a schema collects every document that wrote that path, and two documents pointing at one
    /// file define it once rather than reporting each other as duplicates. A path no file sits at
    /// defines nothing and leaves the reference unresolved, which is the sentence the author needs
    /// and the outcome the compiler reaches by trying to read the file.
    fn define_pointed_file(&mut self, kind: EvidenceKind, pointer: &YamlScalar, relative: &Path) {
        let target = self.root.join(relative);
        if !crate::safety::is_safe_authored_file(self.root, &target) {
            return;
        }

        let key = SymbolKey::global(kind, pointer.value.as_str());
        if self.referenced_files.insert(key.clone()) {
            self.define(key, None, &target, DOCUMENT_START);
        }
    }

    fn define(
        &mut self,
        key: SymbolKey,
        container_name: Option<String>,
        path: &Path,
        range: Range,
    ) {
        self.symbols.push(IndexedSymbol {
            name: key.name.clone(),
            kind: key.kind,
            container_name,
            location: IndexedLocation {
                path: path.to_path_buf(),
                range,
            },
            key,
            resolvable: true,
        });
    }

    fn refer(&mut self, target: SymbolQuery, path: &Path, range: Range) {
        self.add_reference(target, path, range, true);
    }

    fn refer_quietly(&mut self, target: SymbolQuery, path: &Path, range: Range) {
        self.add_reference(target, path, range, false);
    }

    fn add_reference(
        &mut self,
        target: SymbolQuery,
        path: &Path,
        range: Range,
        reports_unresolved: bool,
    ) {
        self.references.push(IndexedReference {
            target,
            location: IndexedLocation {
                path: path.to_path_buf(),
                range,
            },
            reports_unresolved,
        });
    }

    fn report(&mut self, path: &Path, range: Range, code: &str, message: String) {
        self.diagnostics.push(IndexedDiagnostic {
            path: path.to_path_buf(),
            range,
            severity: DiagnosticSeverity::ERROR,
            code: Some(code.to_owned()),
            message,
        });
    }
}

/// What a document of this role declares just by sitting where it does, for the roles the authoring
/// form names by their file.
///
/// A schema, a fixture, and a derivation are missing because the document that points at one defines
/// it, under the path that pointer spells, and that happens whether or not this root reads the file.
/// The marker declares the root rather than a name, and the OpenAPI description belongs to the phase
/// that reads published operations.
fn named_by_its_file(role: DocumentRole) -> Option<EvidenceKind> {
    match role {
        DocumentRole::Question => Some(EvidenceKind::Question),
        DocumentRole::Source => Some(EvidenceKind::Source),
        DocumentRole::Selector => Some(EvidenceKind::SelectorProfile),
        DocumentRole::AccessPolicy => Some(EvidenceKind::AccessPolicy),
        DocumentRole::Schema
        | DocumentRole::Fixture
        | DocumentRole::Derivation
        | DocumentRole::Marker
        | DocumentRole::OpenApi => None,
    }
}

/// The name a project calls one of its documents: the file name without its extensions.
///
/// A schema is written `schemas/person.schema.yaml` and read as `person.schema`, which is the name
/// the authoring form gives it, so only the last extension comes off.
fn document_name(relative: &Path) -> Option<&str> {
    relative.file_stem()?.to_str()
}

/// The sources some question reads, by the name the project spells them under.
///
/// The compile walks the questions and pulls each one's source out of the set of documents it
/// loaded, so this is the set of sources anything checks. A source outside it is loaded, read far
/// enough to see that it is an object under a usable name, and never opened again.
fn sources_questions_read(
    root: &Path,
    parsed: &BTreeMap<PathBuf, ParsedDocument>,
) -> BTreeSet<String> {
    parsed
        .iter()
        .filter(|(path, _)| {
            path.strip_prefix(root).ok().and_then(document_role) == Some(DocumentRole::Question)
        })
        .filter_map(|(_, document)| {
            document
                .value
                .get("source")
                .and_then(|source| source.get_scalar("ref"))
        })
        .map(|source| source.value.clone())
        .collect()
}

/// Whether a path is one the compiler reads a source's own artifact from: two ordinary components
/// whose first is [`ADAPTERS_DIRECTORY`] or [`SCHEMAS_DIRECTORY`], and any extension at all.
fn is_source_artifact(relative: &Path) -> bool {
    let components = relative.components().collect::<Vec<_>>();
    let [Component::Normal(directory), Component::Normal(_)] = components.as_slice() else {
        return false;
    };
    *directory == OsStr::new(ADAPTERS_DIRECTORY) || *directory == OsStr::new(SCHEMAS_DIRECTORY)
}

/// The role of the document a reference of this kind points at, for the kinds a document names by
/// writing a path. Everything else is named by an identifier and found by its own declaration.
fn referenced_file_role(kind: EvidenceKind) -> Option<DocumentRole> {
    match kind {
        EvidenceKind::DerivationFile => Some(DocumentRole::Derivation),
        EvidenceKind::SchemaFile => Some(DocumentRole::Schema),
        EvidenceKind::FixtureFile => Some(DocumentRole::Fixture),
        EvidenceKind::Question
        | EvidenceKind::Concept
        | EvidenceKind::Source
        | EvidenceKind::SelectorProfile
        | EvidenceKind::AccessPolicy
        | EvidenceKind::Operation
        | EvidenceKind::Collection => None,
    }
}

/// The subjects a question asks about, in either form the authoring form allows.
fn subjects(value: &YamlValue) -> Vec<&YamlValue> {
    let mut subjects = Vec::new();
    if let Some(subject) = value.get("subject") {
        subjects.push(subject);
    }
    subjects.extend(sequence(value.get("subjects")));
    subjects
}

fn sequence(value: Option<&YamlValue>) -> &[YamlValue] {
    value.and_then(YamlValue::as_sequence).unwrap_or(&[])
}

fn scalars(value: Option<&YamlValue>) -> impl Iterator<Item = &YamlScalar> {
    sequence(value).iter().filter_map(YamlValue::as_scalar)
}
