// SPDX-License-Identifier: Apache-2.0
//! Symbols and references over the normalized EvidenceProject and its named assets.
use crate::{
    evidence::{
        diagnostics::reader_diagnostics,
        layout::{document_role, DocumentRole},
    },
    refs::{
        bounded_message, EvidenceKind, IndexedDiagnostic, IndexedLocation, IndexedProject,
        IndexedReference, IndexedSymbol, SymbolKey, SymbolQuery, DOCUMENT_START,
    },
    yaml::{ParsedDocument, ScalarStyle, SourceMap, YamlScalar, YamlValue},
};
use registry_evidence_authoring::{project, target};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tower_lsp_server::ls_types::{DiagnosticSeverity, Range};

pub(crate) fn build_index(
    root: &Path,
    documents: &BTreeMap<PathBuf, String>,
    parsed: &BTreeMap<PathBuf, ParsedDocument>,
    _dropped: &BTreeSet<PathBuf>,
) -> IndexedProject {
    let path = root.join(project::PROJECT_FILE);
    let (Some(source), Some(document)) = (documents.get(&path), parsed.get(&path)) else {
        return IndexedProject::default();
    };
    let read = project::read_project(&path.to_string_lossy(), source.as_bytes());
    let mut builder = Builder {
        root,
        index: IndexedProject::default(),
        files: BTreeSet::new(),
        function_interfaces: BTreeMap::new(),
    };
    match &read {
        Ok(decoded) => builder.index.diagnostics.extend(reader_diagnostics(
            &path,
            source,
            document,
            decoded.document.warnings().diagnostics(),
        )),
        Err(report) => builder.index.diagnostics.extend(reader_diagnostics(
            &path,
            source,
            document,
            report.diagnostics(),
        )),
    }
    // A retired envelope never contributes a parallel navigation model. Incomplete current
    // projects still yield recoverable names while the shared reader reports their mistakes.
    if document
        .value
        .get_scalar("kind")
        .is_none_or(|kind| kind.value != project::PROJECT_KIND)
    {
        return builder.index;
    }
    let value = &document.value;
    if let Some(id) = value.get_scalar("id") {
        builder.define(
            SymbolKey::global(EvidenceKind::Project, &id.value),
            &path,
            id,
        );
    }
    for profile in mapping(value.get("selectorProfiles")) {
        builder.define(
            SymbolKey::global(EvidenceKind::SelectorProfile, &profile.key.value),
            &path,
            &profile.key,
        );
    }
    for function in sequence(value.get("functions")) {
        let Some(id) = function.get_scalar("id") else {
            continue;
        };
        builder.define(
            SymbolKey::global(EvidenceKind::Function, &id.value),
            &path,
            id,
        );
        if let Some(interface) = function.get_scalar("interface") {
            builder
                .function_interfaces
                .insert(id.value.clone(), interface.value.clone());
        }
        if let Some(asset) = function.get_scalar("source") {
            builder.file(&path, asset, EvidenceKind::FunctionFile, "rhai");
        }
    }
    for source in mapping(value.get("sources")) {
        builder.define(
            SymbolKey::global(EvidenceKind::Source, &source.key.value),
            &path,
            &source.key,
        );
        for (call, interface) in [
            ("prepare", "source-prepare/v1"),
            ("extract", "source-extract/v1"),
        ] {
            builder.function_call(&path, source.value.get(call), interface);
        }
        for selector in sequence(source.value.get("selectors")) {
            builder.profiles(&path, selector.get("profiles"));
        }
        builder.selector_fields(&path, &source.value);
    }
    let mut derive_uses: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for definition in mapping(value.get("assertionDefinitions")) {
        let id = &definition.key.value;
        builder.define(
            SymbolKey::global(EvidenceKind::AssertionDefinition, id),
            &path,
            &definition.key,
        );
        if let Some(requirement) = definition
            .value
            .get("semantics")
            .and_then(|x| x.get_scalar("requirement"))
        {
            builder.define(
                SymbolKey::global(EvidenceKind::Requirement, &requirement.value),
                &path,
                requirement,
            );
        }
        for subject in sequence(definition.value.get("subjects")) {
            builder.profiles(&path, subject.get("selectors"));
        }
        if let Some(acquisition) = definition.value.get("acquisition") {
            for field in ["source", "search", "fetch"] {
                if let Some(at) = acquisition.get_scalar(field) {
                    builder.reference(
                        SymbolQuery::global(EvidenceKind::Source, &at.value),
                        &path,
                        at,
                        None,
                    );
                }
            }
            for fetch in sequence(acquisition.get("fetch")) {
                if let Some(at) = fetch.get_scalar("source") {
                    builder.reference(
                        SymbolQuery::global(EvidenceKind::Source, &at.value),
                        &path,
                        at,
                        None,
                    );
                }
            }
        }
        builder.function_call(&path, definition.value.get("derive"), "assertion-derive/v1");
        if let Some(function) = definition
            .value
            .get("derive")
            .and_then(|x| x.get_scalar("function"))
        {
            derive_uses
                .entry(function.value.clone())
                .or_default()
                .push(id.clone());
        }
        for output in mapping(definition.value.get("outputs")) {
            builder.define(
                SymbolKey::scoped(EvidenceKind::Output, id, &output.key.value),
                &path,
                &output.key,
            );
            if let Some(schema) = output.value.get_scalar("schema") {
                builder.file(&path, schema, EvidenceKind::SchemaFile, "json");
            }
        }
        if let Some(fixture) = definition.value.get_scalar("fixtures") {
            builder.file(&path, fixture, EvidenceKind::FixtureFile, "yaml");
        }
    }
    for (authority_path, authority_document) in parsed {
        let Some(role @ (DocumentRole::Target | DocumentRole::Authority)) = authority_path
            .strip_prefix(root)
            .ok()
            .and_then(document_role)
        else {
            continue;
        };
        let Some(authority_source) = documents.get(authority_path) else {
            continue;
        };
        if role == DocumentRole::Target {
            match target::read_target(
                &authority_path.to_string_lossy(),
                authority_source.as_bytes(),
            ) {
                Ok(decoded) => builder.index.diagnostics.extend(reader_diagnostics(
                    authority_path,
                    authority_source,
                    authority_document,
                    decoded.document.warnings().diagnostics(),
                )),
                Err(report) => builder.index.diagnostics.extend(reader_diagnostics(
                    authority_path,
                    authority_source,
                    authority_document,
                    report.diagnostics(),
                )),
            }
            if authority_document
                .value
                .get_scalar("kind")
                .is_some_and(|kind| kind.value == target::TARGET_KIND)
            {
                if let Some(id) = authority_document.value.get_scalar("id") {
                    builder.define(
                        SymbolKey::global(EvidenceKind::Target, &id.value),
                        authority_path,
                        id,
                    );
                }
                if let Some(at) = authority_document.value.get_scalar("authority") {
                    builder.authority_file(authority_path, at);
                }
                if let Some(at) = authority_document.value.get_scalar("project") {
                    builder.reference(
                        SymbolQuery::global(EvidenceKind::Project, &at.value),
                        authority_path,
                        at,
                        None,
                    );
                }
            }
            continue;
        }
        if let Ok(project) = &read {
            match target::read_authority(
                &authority_path.to_string_lossy(),
                authority_source.as_bytes(),
                &project.value,
            ) {
                Ok(decoded) => builder.index.diagnostics.extend(reader_diagnostics(
                    authority_path,
                    authority_source,
                    authority_document,
                    decoded.document.warnings().diagnostics(),
                )),
                Err(report) => builder.index.diagnostics.extend(reader_diagnostics(
                    authority_path,
                    authority_source,
                    authority_document,
                    report.diagnostics(),
                )),
            }
        }
        if authority_document
            .value
            .get_scalar("kind")
            .is_none_or(|kind| kind.value != target::AUTHORITY_KIND)
        {
            continue;
        }
        for (field, kind) in [
            ("target", EvidenceKind::Target),
            ("project", EvidenceKind::Project),
        ] {
            if let Some(at) = authority_document.value.get_scalar(field) {
                builder.reference(
                    SymbolQuery::global(kind, &at.value),
                    authority_path,
                    at,
                    None,
                );
            }
        }
        for profile in mapping(authority_document.value.get("accessProfiles")) {
            for grant in sequence(profile.value.get("grants")) {
                if let Some(at) = grant.get_scalar("definition") {
                    builder.reference(
                        SymbolQuery::global(EvidenceKind::AssertionDefinition, &at.value),
                        authority_path,
                        at,
                        None,
                    );
                }
                for subject in sequence(grant.get("subjects")) {
                    if let Some(at) = subject.get_scalar("selectorProfile") {
                        builder.reference(
                            SymbolQuery::global(EvidenceKind::SelectorProfile, &at.value),
                            authority_path,
                            at,
                            None,
                        );
                    }
                }
            }
        }
    }
    for function in sequence(value.get("functions")) {
        let (Some(id), Some(asset)) = (function.get_scalar("id"), function.get_scalar("source"))
        else {
            continue;
        };
        let Some(script) = documents.get(&root.join(&asset.value)) else {
            continue;
        };
        if let Some(interface) = read
            .as_ref()
            .ok()
            .and_then(|p| p.value.functions.iter().find(|f| f.id.as_str() == id.value))
            .map(|f| f.interface)
        {
            for finding in
                registry_evidence_authoring::derivation::validate_function(script, interface)
            {
                builder.index.diagnostics.push(IndexedDiagnostic {
                    path: root.join(&asset.value),
                    range: DOCUMENT_START,
                    severity: DiagnosticSeverity::ERROR,
                    code: Some(format!("evidence.function.{}", finding.code)),
                    message: bounded_message(&finding.message),
                });
            }
        }
        if let Some(definitions) = derive_uses.get(&id.value) {
            // A reusable derivation may release only names every calling definition declares.
            let mut offers: Option<BTreeSet<String>> = None;
            for definition in definitions {
                let names = builder
                    .index
                    .symbols
                    .iter()
                    .filter(|symbol| {
                        symbol.kind == EvidenceKind::Output.into()
                            && symbol.key.scope.as_ref() == Some(definition)
                    })
                    .map(|symbol| symbol.name.clone())
                    .collect::<BTreeSet<_>>();
                offers = Some(offers.map_or_else(
                    || names.clone(),
                    |current| current.intersection(&names).cloned().collect(),
                ));
            }
            let offers = Arc::new(offers.unwrap_or_default());
            for token in string_tokens(script) {
                // Only a named output property is a release reference. Other strings in a
                // reviewed function may carry unrelated domain data.
                let before = &script[..token.0.saturating_sub(1)];
                if !before.trim_end().ends_with("output:") {
                    continue;
                }
                let at = token_scalar(script, token);
                for definition in definitions {
                    builder.reference(
                        SymbolQuery::scoped(EvidenceKind::Output, definition, &at.value),
                        &root.join(&asset.value),
                        &at,
                        Some(Arc::clone(&offers)),
                    );
                }
            }
        }
    }
    for (generated_path, code) in documents {
        if !generated_path
            .extension()
            .is_some_and(|x| x == "ts" || x == "py")
            || !code
                .lines()
                .next()
                .is_some_and(|line| line.contains("Generated from the normalized EvidenceProject."))
        {
            continue;
        }
        let mut scope = None;
        let mut catalog_kind = None;
        for (line_index, line) in code.split_inclusive('\n').enumerate() {
            if let Some((_, id)) = line.split_once("evidence-definition: ") {
                scope = Some(id.trim().to_owned());
                catalog_kind = None;
                continue;
            }
            if line.contains("evidence-source: ") || line.contains("evidence-function: ") {
                scope = None;
                catalog_kind = Some(if line.contains("evidence-source: ") {
                    EvidenceKind::Source
                } else {
                    EvidenceKind::Function
                });
                continue;
            }
            if line.contains("assertionDefinitions =") || line.starts_with("ASSERTION_DEFINITIONS:")
            {
                scope = None;
                catalog_kind = None;
            }
            for token in string_tokens(line) {
                let token_end = token.1;
                let mut at = token_scalar(line, token);
                at.range.start.line = line_index as u32;
                at.range.end.line = line_index as u32;
                let is_key = line[token_end + 1..].trim_start().starts_with(':');
                if !is_key {
                    continue;
                }
                if let Some(kind) = catalog_kind {
                    if builder
                        .index
                        .symbols
                        .iter()
                        .any(|symbol| symbol.key.kind == kind.into() && symbol.name == at.value)
                    {
                        builder.reference(
                            SymbolQuery::global(kind, &at.value),
                            generated_path,
                            &at,
                            None,
                        );
                        continue;
                    }
                }
                let is_definition = scope.is_none() || line.trim_end().ends_with('{');
                if is_definition
                    && builder.index.symbols.iter().any(|s| {
                        s.key.kind == EvidenceKind::AssertionDefinition.into() && s.name == at.value
                    })
                {
                    builder.reference(
                        SymbolQuery::global(EvidenceKind::AssertionDefinition, &at.value),
                        generated_path,
                        &at,
                        None,
                    );
                } else if let Some(scope) = &scope {
                    if builder.index.symbols.iter().any(|s| {
                        s.key.kind == EvidenceKind::Output.into()
                            && s.key.scope.as_ref() == Some(scope)
                            && s.name == at.value
                    }) {
                        builder.reference(
                            SymbolQuery::scoped(EvidenceKind::Output, scope, &at.value),
                            generated_path,
                            &at,
                            None,
                        );
                    }
                }
            }
        }
    }
    builder.index
}
struct Builder<'a> {
    root: &'a Path,
    index: IndexedProject,
    files: BTreeSet<SymbolKey>,
    function_interfaces: BTreeMap<String, String>,
}
impl Builder<'_> {
    fn define(&mut self, key: SymbolKey, path: &Path, at: &YamlScalar) {
        self.index.symbols.push(IndexedSymbol {
            name: key.name.clone(),
            kind: key.kind,
            container_name: key.scope.clone(),
            location: IndexedLocation {
                path: path.to_path_buf(),
                range: at.range,
            },
            key,
            resolvable: true,
        });
    }
    fn reference(
        &mut self,
        target: SymbolQuery,
        path: &Path,
        at: &YamlScalar,
        offers: Option<Arc<BTreeSet<String>>>,
    ) {
        self.index.references.push(IndexedReference {
            target,
            location: IndexedLocation {
                path: path.to_path_buf(),
                range: at.range,
            },
            reports_unresolved: false,
            style: at.style,
            offers,
        });
    }
    fn profiles(&mut self, path: &Path, value: Option<&YamlValue>) {
        for at in sequence(value).iter().filter_map(YamlValue::as_scalar) {
            self.reference(
                SymbolQuery::global(EvidenceKind::SelectorProfile, &at.value),
                path,
                at,
                None,
            );
        }
    }
    fn function_call(&mut self, path: &Path, value: Option<&YamlValue>, interface: &str) {
        if let Some(at) = value.and_then(|value| value.get_scalar("function")) {
            let offers = Arc::new(
                self.function_interfaces
                    .iter()
                    .filter(|(_, kind)| kind.as_str() == interface)
                    .map(|(id, _)| id.clone())
                    .collect(),
            );
            self.reference(
                SymbolQuery::global(EvidenceKind::Function, &at.value),
                path,
                at,
                Some(offers),
            );
        }
        if let Some(value) = value {
            self.selector_fields(path, value);
        }
    }
    fn selector_fields(&mut self, path: &Path, value: &YamlValue) {
        match value {
            YamlValue::Mapping(entries) => {
                for entry in entries {
                    if entry.key.value == "selector" {
                        if let Some(at) = entry.value.get_scalar("profile") {
                            self.reference(
                                SymbolQuery::global(EvidenceKind::SelectorProfile, &at.value),
                                path,
                                at,
                                None,
                            );
                        }
                    }
                    self.selector_fields(path, &entry.value);
                }
            }
            YamlValue::Sequence(items) => {
                for item in items {
                    self.selector_fields(path, item);
                }
            }
            _ => {}
        }
    }
    fn authority_file(&mut self, path: &Path, at: &YamlScalar) {
        if !project::valid_asset(&at.value, "yaml") {
            return;
        }
        let Some(parent) = path.parent() else {
            return;
        };
        let target = parent.join(&at.value);
        let Ok(relative) = target.strip_prefix(self.root) else {
            return;
        };
        let name = relative.to_string_lossy().into_owned();
        let key = SymbolKey::global(EvidenceKind::AuthorityFile, &name);
        if crate::safety::is_safe_authored_file(self.root, &target) {
            if self.files.insert(key.clone()) {
                self.define(
                    key,
                    &target,
                    &YamlScalar {
                        value: name.clone(),
                        range: DOCUMENT_START,
                        style: ScalarStyle::Plain,
                    },
                );
            }
        } else {
            self.index.diagnostics.push(IndexedDiagnostic {
                path: path.to_path_buf(),
                range: at.range,
                severity: DiagnosticSeverity::ERROR,
                code: Some("evidence.project.missing-authority-file".to_owned()),
                message: "The named target authority must be a readable regular project file"
                    .to_owned(),
            });
        }
        self.reference(
            SymbolQuery::global(EvidenceKind::AuthorityFile, name),
            path,
            at,
            None,
        );
    }
    fn file(&mut self, path: &Path, at: &YamlScalar, kind: EvidenceKind, extension: &str) {
        let valid_asset = project::valid_asset(&at.value, extension)
            || (matches!(kind, EvidenceKind::SchemaFile | EvidenceKind::FixtureFile)
                && ["yaml", "yml", "json"]
                    .iter()
                    .any(|extension| project::valid_asset(&at.value, extension)));
        if !valid_asset {
            return;
        }
        let target = self.root.join(&at.value);
        let key = SymbolKey::global(kind, &at.value);
        let exists = crate::safety::is_safe_authored_file(self.root, &target);
        if exists && self.files.insert(key.clone()) {
            let start = YamlScalar {
                value: at.value.clone(),
                range: DOCUMENT_START,
                style: ScalarStyle::Plain,
            };
            self.define(key, &target, &start);
        }
        if !exists {
            self.index.diagnostics.push(IndexedDiagnostic {
                path: path.to_path_buf(),
                range: at.range,
                severity: DiagnosticSeverity::ERROR,
                code: Some(format!("evidence.project.missing-{}", kind.slug())),
                message: format!(
                    "The named {} must be a readable regular project file",
                    kind.label()
                ),
            });
        }
        let mut offers = BTreeSet::new();
        if let Some(directory) = target.parent().filter(|directory| {
            crate::safety::secure_directory(self.root, directory).unwrap_or(false)
        }) {
            if let Ok(entries) = std::fs::read_dir(directory) {
                let entries = entries
                    .take(crate::workspace::MAX_INDEXED_PROJECT_DOCUMENTS + 1)
                    .collect::<Vec<_>>();
                if entries.len() <= crate::workspace::MAX_INDEXED_PROJECT_DOCUMENTS {
                    for entry in entries.into_iter().flatten() {
                        let candidate = entry.path();
                        if candidate.extension() == target.extension()
                            && crate::safety::is_safe_authored_file(self.root, &candidate)
                        {
                            if let Ok(relative) = candidate.strip_prefix(self.root) {
                                offers.insert(relative.to_string_lossy().into_owned());
                            }
                        }
                    }
                }
            }
        }
        self.reference(
            SymbolQuery::global(kind, &at.value),
            path,
            at,
            Some(Arc::new(offers)),
        );
    }
}
fn mapping(value: Option<&YamlValue>) -> &[crate::yaml::YamlPair] {
    value.and_then(YamlValue::as_mapping).unwrap_or_default()
}
fn sequence(value: Option<&YamlValue>) -> &[YamlValue] {
    value.and_then(YamlValue::as_sequence).unwrap_or_default()
}
/// Bounded string tokens for generated code and Rhai release-output references. Escaped strings
/// are ignored: generated local identifiers need no escapes, and no code is evaluated.
fn string_tokens(source: &str) -> Vec<(usize, usize, String)> {
    let mut tokens = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' && bytes[i] != b'\'' {
            i += 1;
            continue;
        }
        let quote = bytes[i];
        let start = i + 1;
        i += 1;
        while i < bytes.len() && bytes[i] != quote && bytes[i] != b'\n' && bytes[i] != b'\\' {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == quote {
            tokens.push((start, i, source[start..i].to_owned()));
        }
        i += 1;
    }
    tokens
}
fn token_scalar(source: &str, token: (usize, usize, String)) -> YamlScalar {
    let map = SourceMap::new(source);
    YamlScalar {
        value: token.2,
        range: Range::new(map.position(token.0), map.position(token.1)),
        style: ScalarStyle::DoubleQuoted,
    }
}
