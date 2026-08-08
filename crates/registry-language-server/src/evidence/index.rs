// SPDX-License-Identifier: Apache-2.0
//! Walks the parsed documents of one Evidence authoring project into symbols and references.
//!
//! Every edge walked here is an edge `registry-evidencectl` already refuses a project for: a
//! question that names a source with no document, a derivation file that is not there, an access
//! policy that admits a question the project does not hold. The editor draws them earlier, on text
//! that has not been saved yet, and says the same thing about them. It never draws one the compiler
//! would accept, because a diagnostic an author cannot act on teaches them to ignore the channel.
//!
//! Two families of edge are deliberately absent, and belong to the phase that reads the project's
//! OpenAPI description: `source.operation` with `source.facts[].path`, and `subject.selector` with
//! `source.collectionBounds`. Their targets are leaves of a published operation rather than names
//! another authored document declares, so nothing here could resolve them honestly.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use tower_lsp_server::ls_types::{DiagnosticSeverity, Range};

use crate::{
    evidence::{
        diagnostics::question_shape_diagnostics,
        layout::{document_role, DocumentRole},
    },
    refs::{
        bounded_value, EvidenceKind, IndexedDiagnostic, IndexedLocation, IndexedReference,
        IndexedSymbol, SymbolKey, SymbolQuery, DOCUMENT_START,
    },
    yaml::{ParsedDocument, YamlScalar, YamlValue},
};

pub(crate) fn build_index(
    root: &Path,
    documents: &BTreeMap<PathBuf, String>,
    parsed: &BTreeMap<PathBuf, ParsedDocument>,
) -> (
    Vec<IndexedSymbol>,
    Vec<IndexedReference>,
    Vec<IndexedDiagnostic>,
) {
    let mut builder = IndexBuilder {
        root,
        symbols: Vec::new(),
        references: Vec::new(),
        diagnostics: Vec::new(),
        referenced_files: BTreeSet::new(),
    };

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
                    builder
                        .diagnostics
                        .extend(question_shape_diagnostics(path, source, document));
                }
            }
            DocumentRole::Source => builder.walk_source(path, name, &document.value),
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

    (builder.symbols, builder.references, builder.diagnostics)
}

struct IndexBuilder<'a> {
    root: &'a Path,
    symbols: Vec<IndexedSymbol>,
    references: Vec<IndexedReference>,
    diagnostics: Vec<IndexedDiagnostic>,
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
            self.refer_to_file(path, fixtures, EvidenceKind::FixtureFile);
        }
    }

    /// A source defines itself and names the selector profiles its callers may pick a subject with
    /// and the schemas its own traffic is checked against.
    ///
    /// Nothing inside a source document names it: the project reads a source by its file, which is
    /// also how a question spells it, so the symbol is anchored at the start of the file.
    fn walk_source(&mut self, path: &Path, name: &str, value: &YamlValue) {
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
                    self.refer(
                        SymbolQuery::global(EvidenceKind::SelectorProfile, profile.value.as_str()),
                        path,
                        profile.range,
                    );
                }
            }
        }

        if let Some(schema) =
            request.and_then(|request| request.get_scalar("adapterParametersSchema"))
        {
            self.refer_to_file(path, schema, EvidenceKind::SchemaFile);
        }
        for pointer in ["responseSchema", "factSchema"] {
            if let Some(schema) = value.get_scalar(pointer) {
                self.refer_to_file(path, schema, EvidenceKind::SchemaFile);
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

    /// Records a pointer at another file, and defines what it points at when a file of that role is
    /// really there.
    ///
    /// The pointer is the name: the project spells these targets as paths, so `Find references` on a
    /// schema collects every document that wrote that path. A target the layout does not recognise,
    /// or that no file sits at, defines nothing and leaves the reference unresolved, which is the
    /// sentence the author needs and the outcome the compiler reaches by trying to read the file.
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

/// The name a project calls one of its documents: the file name without its extensions.
///
/// A schema is written `schemas/person.schema.yaml` and read as `person.schema`, which is the name
/// the authoring form gives it, so only the last extension comes off.
fn document_name(relative: &Path) -> Option<&str> {
    relative.file_stem()?.to_str()
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
        | EvidenceKind::AccessPolicy => None,
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
