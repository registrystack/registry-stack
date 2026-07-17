// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use tower_lsp_server::ls_types::{DiagnosticSeverity, Position, Range, SymbolKind};
use tree_sitter::{Node, Parser};

const PROJECT_FILE: &str = "registry-stack.yaml";
const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistrySymbolKind {
    Registry,
    Integration,
    Entity,
    Service,
    Consultation,
    Claim,
    CredentialProfile,
    Fixture,
    Environment,
}

impl RegistrySymbolKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Integration => "integration",
            Self::Entity => "entity",
            Self::Service => "service",
            Self::Consultation => "consultation",
            Self::Claim => "claim",
            Self::CredentialProfile => "credential profile",
            Self::Fixture => "fixture",
            Self::Environment => "environment",
        }
    }

    pub fn lsp_kind(self) -> SymbolKind {
        match self {
            Self::Registry => SymbolKind::NAMESPACE,
            Self::Integration | Self::Entity => SymbolKind::MODULE,
            Self::Service => SymbolKind::INTERFACE,
            Self::Consultation => SymbolKind::FUNCTION,
            Self::Claim => SymbolKind::PROPERTY,
            Self::CredentialProfile => SymbolKind::OBJECT,
            Self::Fixture => SymbolKind::EVENT,
            Self::Environment => SymbolKind::PACKAGE,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SymbolKey {
    kind: RegistrySymbolKind,
    scope: Option<String>,
    name: String,
}

impl SymbolKey {
    fn global(kind: RegistrySymbolKind, name: impl Into<String>) -> Self {
        Self {
            kind,
            scope: None,
            name: name.into(),
        }
    }

    fn scoped(kind: RegistrySymbolKind, scope: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            kind,
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
    pub kind: RegistrySymbolKind,
    pub container_name: Option<String>,
    pub location: IndexedLocation,
    key: SymbolKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedDiagnostic {
    pub path: PathBuf,
    pub range: Range,
    pub severity: DiagnosticSeverity,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SymbolQuery {
    kind: RegistrySymbolKind,
    scope: Option<String>,
    name: String,
}

impl SymbolQuery {
    fn global(kind: RegistrySymbolKind, name: impl Into<String>) -> Self {
        Self {
            kind,
            scope: None,
            name: name.into(),
        }
    }

    fn scoped(kind: RegistrySymbolKind, scope: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            kind,
            scope: Some(scope.into()),
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IndexedReference {
    target: SymbolQuery,
    location: IndexedLocation,
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
    pub fn load(root: &Path) -> Result<Self> {
        let root = root
            .canonicalize()
            .with_context(|| format!("failed to resolve project root {}", root.display()))?;
        let documents = load_project_documents(&root)?;
        Ok(Self::from_documents(&root, &documents))
    }

    pub fn from_documents(root: &Path, documents: &BTreeMap<PathBuf, String>) -> Self {
        let root = root.to_path_buf();
        let parsed = documents
            .iter()
            .filter_map(|(path, source)| parse_yaml(source).ok().map(|value| (path.clone(), value)))
            .collect::<BTreeMap<_, _>>();

        let (symbols, references) = {
            let mut builder = IndexBuilder {
                root: &root,
                parsed: &parsed,
                symbols: Vec::new(),
                references: Vec::new(),
            };
            builder.build();
            (builder.symbols, builder.references)
        };

        let mut index = Self {
            root,
            symbols,
            references,
            diagnostics: Vec::new(),
            document_paths: documents.keys().cloned().collect(),
        };
        index.diagnostics = index.build_diagnostics();
        index
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn symbols(&self) -> &[IndexedSymbol] {
        &self.symbols
    }

    pub fn document_symbols(&self, path: &Path) -> Vec<&IndexedSymbol> {
        let path = normalize_lookup_path(path);
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

    pub fn definitions_at(&self, path: &Path, position: Position) -> Vec<IndexedLocation> {
        let path = normalize_lookup_path(path);
        if let Some(reference) = self.reference_at(&path, position) {
            return self
                .definitions_for(&reference.target)
                .into_iter()
                .map(|symbol| symbol.location.clone())
                .collect();
        }

        self.symbol_at(&path, position)
            .map(|symbol| vec![symbol.location.clone()])
            .unwrap_or_default()
    }

    pub fn references_at(
        &self,
        path: &Path,
        position: Position,
        include_declaration: bool,
    ) -> Vec<IndexedLocation> {
        let path = normalize_lookup_path(path);
        let keys = if let Some(symbol) = self.symbol_at(&path, position) {
            vec![symbol.key.clone()]
        } else if let Some(reference) = self.reference_at(&path, position) {
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
            .filter(|symbol| self.query_can_resolve_to(query, &symbol.key))
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
        for symbol in &self.symbols {
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
                        key.name,
                        key.scope
                            .as_ref()
                            .map(|scope| format!(" in service '{scope}'"))
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
                    reference.target.name,
                    reference
                        .target
                        .scope
                        .as_ref()
                        .map(|scope| format!(" in service '{scope}'"))
                        .unwrap_or_default()
                )),
                1 => None,
                count => Some(format!(
                    "Ambiguous {} reference '{}': found {count} definitions",
                    reference.target.kind.label(),
                    reference.target.name
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

        diagnostics.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| range_cmp(left.range, right.range))
                .then_with(|| left.message.cmp(&right.message))
        });
        diagnostics
    }
}

pub fn is_valid_yaml(source: &str) -> bool {
    parse_yaml(source).is_ok()
}

pub fn is_project_document(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let components = relative.components().collect::<Vec<_>>();
    let normal = |component: &Component<'_>| matches!(component, Component::Normal(_));
    let extension_is_yaml = || {
        relative
            .extension()
            .is_some_and(|extension| extension == "yaml")
    };

    match components.as_slice() {
        [Component::Normal(file)] => file == &PROJECT_FILE,
        [first, second] if normal(first) && normal(second) => {
            matches!(first, Component::Normal(name) if *name == "entities" || *name == "environments")
                && extension_is_yaml()
        }
        [Component::Normal(integrations), integration, Component::Normal(file)] => {
            *integrations == "integrations" && normal(integration) && *file == "integration.yaml"
        }
        [Component::Normal(integrations), integration, Component::Normal(fixtures), fixture] => {
            *integrations == "integrations"
                && normal(integration)
                && *fixtures == "fixtures"
                && normal(fixture)
                && extension_is_yaml()
        }
        _ => false,
    }
}

pub fn load_project_documents(root: &Path) -> Result<BTreeMap<PathBuf, String>> {
    let mut candidates = vec![root.join(PROJECT_FILE)];
    add_yaml_files(&root.join("entities"), &mut candidates)?;
    add_yaml_files(&root.join("environments"), &mut candidates)?;

    let integrations = root.join("integrations");
    if let Ok(entries) = fs::read_dir(&integrations) {
        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "failed to inspect integrations under {}",
                    integrations.display()
                )
            })?;
            if entry.file_type()?.is_dir() {
                let directory = entry.path();
                candidates.push(directory.join("integration.yaml"));
                add_yaml_files(&directory.join("fixtures"), &mut candidates)?;
            }
        }
    }

    candidates.sort();
    candidates.dedup();
    let mut documents = BTreeMap::new();
    for path in candidates {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
            }
        };
        if !metadata.file_type().is_file() || metadata.len() > MAX_DOCUMENT_BYTES {
            continue;
        }
        let source = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        documents.insert(path, source);
    }
    Ok(documents)
}

fn add_yaml_files(directory: &Path, candidates: &mut Vec<PathBuf>) -> Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", directory.display()));
        }
    };
    for entry in entries {
        let entry = entry
            .with_context(|| format!("failed to inspect an entry in {}", directory.display()))?;
        if entry.file_type()?.is_file() && entry.path().extension().is_some_and(|ext| ext == "yaml")
        {
            candidates.push(entry.path());
        }
    }
    Ok(())
}

struct IndexBuilder<'a> {
    root: &'a Path,
    parsed: &'a BTreeMap<PathBuf, YamlValue>,
    symbols: Vec<IndexedSymbol>,
    references: Vec<IndexedReference>,
}

impl IndexBuilder<'_> {
    fn build(&mut self) {
        let manifest_path = self.root.join(PROJECT_FILE);
        let mut claimed_definition_files = BTreeSet::new();
        if let Some(manifest) = self.parsed.get(&manifest_path) {
            self.extract_manifest(&manifest_path, manifest, &mut claimed_definition_files);
        }

        for (path, document) in self.parsed {
            if path == &manifest_path {
                continue;
            }
            let Ok(relative) = path.strip_prefix(self.root) else {
                continue;
            };
            if is_fixture_path(relative) {
                self.extract_fixture(path, document);
            } else if is_environment_path(relative) {
                self.extract_environment(path, relative, document);
            } else if !claimed_definition_files.contains(path) {
                if is_integration_path(relative) {
                    self.extract_orphan_definition(path, document, RegistrySymbolKind::Integration);
                } else if is_entity_path(relative) {
                    self.extract_orphan_definition(path, document, RegistrySymbolKind::Entity);
                }
            }
        }
    }

    fn extract_manifest(
        &mut self,
        path: &Path,
        manifest: &YamlValue,
        claimed_definition_files: &mut BTreeSet<PathBuf>,
    ) {
        if let Some(registry_id) = manifest
            .get("registry")
            .and_then(|registry| registry.get_scalar("id"))
        {
            self.add_symbol(
                SymbolKey::global(RegistrySymbolKind::Registry, &registry_id.value),
                None,
                path,
                registry_id.range,
            );
        }

        self.extract_aliases(
            path,
            manifest,
            "integrations",
            RegistrySymbolKind::Integration,
            claimed_definition_files,
        );
        self.extract_aliases(
            path,
            manifest,
            "entities",
            RegistrySymbolKind::Entity,
            claimed_definition_files,
        );

        let Some(services) = manifest.get("services").and_then(YamlValue::as_mapping) else {
            return;
        };
        for service in services {
            let service_name = service.key.value.clone();
            self.add_symbol(
                SymbolKey::global(RegistrySymbolKind::Service, &service_name),
                None,
                path,
                service.key.range,
            );

            if let Some(entity) = service.value.get_scalar("entity") {
                self.add_reference(
                    SymbolQuery::global(RegistrySymbolKind::Entity, &entity.value),
                    path,
                    entity.range,
                );
            }

            if let Some(consultations) = service
                .value
                .get("consultations")
                .and_then(YamlValue::as_mapping)
            {
                for consultation in consultations {
                    self.add_symbol(
                        SymbolKey::scoped(
                            RegistrySymbolKind::Consultation,
                            &service_name,
                            &consultation.key.value,
                        ),
                        Some(service_name.clone()),
                        path,
                        consultation.key.range,
                    );
                    if let Some(integration) = consultation.value.get_scalar("integration") {
                        self.add_reference(
                            SymbolQuery::global(
                                RegistrySymbolKind::Integration,
                                &integration.value,
                            ),
                            path,
                            integration.range,
                        );
                    }
                }
            }

            if let Some(claims) = service.value.get("claims").and_then(YamlValue::as_mapping) {
                for claim in claims {
                    self.add_symbol(
                        SymbolKey::scoped(
                            RegistrySymbolKind::Claim,
                            &service_name,
                            &claim.key.value,
                        ),
                        Some(service_name.clone()),
                        path,
                        claim.key.range,
                    );
                    if let Some(output) = claim.value.get_scalar("output") {
                        if let Some((consultation, _)) = output.value.split_once('.') {
                            self.add_reference(
                                SymbolQuery::scoped(
                                    RegistrySymbolKind::Consultation,
                                    &service_name,
                                    consultation,
                                ),
                                path,
                                scalar_prefix_range(output, consultation),
                            );
                        }
                    }
                }
            }

            if let Some(profiles) = service
                .value
                .get("credential_profiles")
                .and_then(YamlValue::as_mapping)
            {
                for profile in profiles {
                    self.add_symbol(
                        SymbolKey::scoped(
                            RegistrySymbolKind::CredentialProfile,
                            &service_name,
                            &profile.key.value,
                        ),
                        Some(service_name.clone()),
                        path,
                        profile.key.range,
                    );
                    if let Some(claims) =
                        profile.value.get("claims").and_then(YamlValue::as_sequence)
                    {
                        for claim in claims.iter().filter_map(YamlValue::as_scalar) {
                            self.add_reference(
                                SymbolQuery::scoped(
                                    RegistrySymbolKind::Claim,
                                    &service_name,
                                    &claim.value,
                                ),
                                path,
                                claim.range,
                            );
                        }
                    }
                }
            }
        }
    }

    fn extract_aliases(
        &mut self,
        manifest_path: &Path,
        manifest: &YamlValue,
        field: &str,
        kind: RegistrySymbolKind,
        claimed_definition_files: &mut BTreeSet<PathBuf>,
    ) {
        let Some(aliases) = manifest.get(field).and_then(YamlValue::as_mapping) else {
            return;
        };
        for alias in aliases {
            let key = SymbolKey::global(kind, &alias.key.value);
            let definition_path = alias
                .value
                .get_scalar("file")
                .and_then(|file| safe_join(self.root, &file.value));
            let external_id = definition_path
                .as_ref()
                .and_then(|path| self.parsed.get(path).map(|document| (path, document)))
                .and_then(|(path, document)| document.get_scalar("id").map(|id| (path, id)));

            if let Some((path, id)) = external_id {
                claimed_definition_files.insert(path.clone());
                self.add_symbol(key, None, path, id.range);
                self.add_reference(
                    SymbolQuery::global(kind, &alias.key.value),
                    manifest_path,
                    alias.key.range,
                );
            } else {
                self.add_symbol(key, None, manifest_path, alias.key.range);
            }
        }
    }

    fn extract_orphan_definition(
        &mut self,
        path: &Path,
        document: &YamlValue,
        kind: RegistrySymbolKind,
    ) {
        if let Some(id) = document.get_scalar("id") {
            self.add_symbol(SymbolKey::global(kind, &id.value), None, path, id.range);
        }
    }

    fn extract_fixture(&mut self, path: &Path, document: &YamlValue) {
        if let Some(name) = document.get_scalar("name") {
            self.add_symbol(
                SymbolKey::global(RegistrySymbolKind::Fixture, &name.value),
                None,
                path,
                name.range,
            );
        }
        if let Some(claims) = document
            .get("expect")
            .and_then(|expect| expect.get("claims"))
            .and_then(YamlValue::as_mapping)
        {
            for claim in claims {
                self.add_reference(
                    SymbolQuery::global(RegistrySymbolKind::Claim, &claim.key.value),
                    path,
                    claim.key.range,
                );
            }
        }
    }

    fn extract_environment(&mut self, path: &Path, relative: &Path, document: &YamlValue) {
        if let Some(name) = relative.file_stem().and_then(|name| name.to_str()) {
            let range = Range::new(Position::new(0, 0), Position::new(0, 0));
            self.add_symbol(
                SymbolKey::global(RegistrySymbolKind::Environment, name),
                None,
                path,
                range,
            );
        }
        for (field, kind) in [
            ("integrations", RegistrySymbolKind::Integration),
            ("entities", RegistrySymbolKind::Entity),
        ] {
            if let Some(entries) = document.get(field).and_then(YamlValue::as_mapping) {
                for entry in entries {
                    self.add_reference(
                        SymbolQuery::global(kind, &entry.key.value),
                        path,
                        entry.key.range,
                    );
                }
            }
        }
    }

    fn add_symbol(
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
        });
    }

    fn add_reference(&mut self, target: SymbolQuery, path: &Path, range: Range) {
        self.references.push(IndexedReference {
            target,
            location: IndexedLocation {
                path: path.to_path_buf(),
                range,
            },
        });
    }
}

#[derive(Clone, Debug)]
struct YamlScalar {
    value: String,
    range: Range,
}

#[derive(Clone, Debug)]
struct YamlPair {
    key: YamlScalar,
    value: YamlValue,
}

#[derive(Clone, Debug)]
enum YamlValue {
    Scalar(YamlScalar),
    Mapping(Vec<YamlPair>),
    Sequence(Vec<YamlValue>),
    Other,
}

impl YamlValue {
    fn as_mapping(&self) -> Option<&[YamlPair]> {
        match self {
            Self::Mapping(entries) => Some(entries),
            _ => None,
        }
    }

    fn as_sequence(&self) -> Option<&[YamlValue]> {
        match self {
            Self::Sequence(entries) => Some(entries),
            _ => None,
        }
    }

    fn as_scalar(&self) -> Option<&YamlScalar> {
        match self {
            Self::Scalar(scalar) => Some(scalar),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> Option<&YamlValue> {
        self.as_mapping()?
            .iter()
            .find(|entry| entry.key.value == key)
            .map(|entry| &entry.value)
    }

    fn get_scalar(&self, key: &str) -> Option<&YamlScalar> {
        self.get(key)?.as_scalar()
    }
}

fn parse_yaml(source: &str) -> Result<YamlValue> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_yaml::LANGUAGE.into())
        .context("failed to load the YAML parser")?;
    let tree = parser
        .parse(source, None)
        .context("the YAML parser did not produce a syntax tree")?;
    if tree.root_node().has_error() {
        anyhow::bail!("invalid YAML syntax");
    }
    let source_map = SourceMap::new(source);
    Ok(value_from_node(tree.root_node(), source, &source_map))
}

fn value_from_node(node: Node<'_>, source: &str, source_map: &SourceMap<'_>) -> YamlValue {
    match node.kind() {
        "stream"
        | "document"
        | "block_node"
        | "flow_node"
        | "plain_scalar"
        | "block_sequence_item" => meaningful_named_children(node)
            .last()
            .copied()
            .map(|child| value_from_node(child, source, source_map))
            .unwrap_or(YamlValue::Other),
        "block_mapping" | "flow_mapping" => {
            let mut entries = Vec::new();
            let mut cursor = node.walk();
            for pair in node
                .named_children(&mut cursor)
                .filter(|child| matches!(child.kind(), "block_mapping_pair" | "flow_pair"))
            {
                let Some(key_node) = pair.child_by_field_name("key") else {
                    continue;
                };
                let Some(key) = scalar_from_node(key_node, source, source_map) else {
                    continue;
                };
                let value = pair
                    .child_by_field_name("value")
                    .map(|value| value_from_node(value, source, source_map))
                    .unwrap_or(YamlValue::Other);
                entries.push(YamlPair { key, value });
            }
            YamlValue::Mapping(entries)
        }
        "block_sequence" | "flow_sequence" => {
            let values = meaningful_named_children(node)
                .into_iter()
                .map(|child| value_from_node(child, source, source_map))
                .collect();
            YamlValue::Sequence(values)
        }
        kind if kind.ends_with("_scalar") => scalar_from_node(node, source, source_map)
            .map(YamlValue::Scalar)
            .unwrap_or(YamlValue::Other),
        _ => YamlValue::Other,
    }
}

fn scalar_from_node(
    node: Node<'_>,
    source: &str,
    source_map: &SourceMap<'_>,
) -> Option<YamlScalar> {
    if matches!(
        node.kind(),
        "stream" | "document" | "block_node" | "flow_node" | "plain_scalar" | "block_sequence_item"
    ) {
        return meaningful_named_children(node)
            .last()
            .copied()
            .and_then(|child| scalar_from_node(child, source, source_map));
    }
    if !node.kind().ends_with("_scalar") {
        return None;
    }

    let raw = source.get(node.byte_range())?;
    let (value, start_byte, end_byte) = match node.kind() {
        "double_quote_scalar" => {
            let value = serde_json::from_str::<String>(raw)
                .unwrap_or_else(|_| raw.trim_matches('"').to_owned());
            (
                value,
                node.start_byte() + 1,
                node.end_byte().saturating_sub(1),
            )
        }
        "single_quote_scalar" => (
            raw.trim_matches('\'').replace("''", "'"),
            node.start_byte() + 1,
            node.end_byte().saturating_sub(1),
        ),
        _ => (raw.to_owned(), node.start_byte(), node.end_byte()),
    };
    Some(YamlScalar {
        value,
        range: source_map.range(start_byte, end_byte),
    })
}

fn scalar_prefix_range(scalar: &YamlScalar, prefix: &str) -> Range {
    let mut end = scalar.range.start;
    end.character += prefix.encode_utf16().count() as u32;
    Range::new(scalar.range.start, end)
}

fn meaningful_named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !matches!(child.kind(), "comment" | "anchor" | "tag"))
        .collect()
}

struct SourceMap<'a> {
    source: &'a str,
    line_starts: Vec<usize>,
}

impl<'a> SourceMap<'a> {
    fn new(source: &'a str) -> Self {
        let mut line_starts = vec![0];
        for (index, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(index + 1);
            }
        }
        Self {
            source,
            line_starts,
        }
    }

    fn range(&self, start: usize, end: usize) -> Range {
        Range::new(self.position(start), self.position(end))
    }

    fn position(&self, byte: usize) -> Position {
        let byte = byte.min(self.source.len());
        let line = self
            .line_starts
            .partition_point(|line_start| *line_start <= byte)
            .saturating_sub(1);
        let line_start = self.line_starts[line];
        let character = self.source[line_start..byte].encode_utf16().count();
        Position::new(line as u32, character as u32)
    }
}

fn safe_join(root: &Path, relative: &str) -> Option<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(root.join(path))
}

fn normalize_lookup_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn is_integration_path(relative: &Path) -> bool {
    let components = relative.components().collect::<Vec<_>>();
    matches!(
        components.as_slice(),
        [Component::Normal(integrations), Component::Normal(_), Component::Normal(file)]
            if *integrations == "integrations" && *file == "integration.yaml"
    )
}

fn is_entity_path(relative: &Path) -> bool {
    let components = relative.components().collect::<Vec<_>>();
    matches!(
        components.as_slice(),
        [Component::Normal(entities), Component::Normal(file)]
            if *entities == "entities" && Path::new(file).extension().is_some_and(|ext| ext == "yaml")
    )
}

fn is_environment_path(relative: &Path) -> bool {
    let components = relative.components().collect::<Vec<_>>();
    matches!(
        components.as_slice(),
        [Component::Normal(environments), Component::Normal(file)]
            if *environments == "environments" && Path::new(file).extension().is_some_and(|ext| ext == "yaml")
    )
}

fn is_fixture_path(relative: &Path) -> bool {
    let components = relative.components().collect::<Vec<_>>();
    matches!(
        components.as_slice(),
        [Component::Normal(integrations), Component::Normal(_), Component::Normal(fixtures), Component::Normal(file)]
            if *integrations == "integrations" && *fixtures == "fixtures" && Path::new(file).extension().is_some_and(|ext| ext == "yaml")
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
    use std::fs;

    use super::*;
    use tempfile::TempDir;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("fixture path has parent")).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn fixture_project() -> TempDir {
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            PROJECT_FILE,
            r#"version: 1
registry: { id: "fictional-😀-registry" }
integrations:
  people: { file: integrations/people/integration.yaml }
entities:
  residents: { file: entities/residents.yaml }
services:
  person-check:
    kind: evidence
    consultations:
      person_record: { integration: people }
    claims:
      active: { output: person_record.active, disclosure: predicate }
    credential_profiles:
      person-status: { claims: [active] }
  records:
    kind: records_api
    entity: residents
"#,
        );
        write(
            temp.path(),
            "integrations/people/integration.yaml",
            "version: 1\nid: people-source\n",
        );
        write(
            temp.path(),
            "entities/residents.yaml",
            "version: 1\nid: resident-entity\n",
        );
        write(
            temp.path(),
            "environments/local.yaml",
            "version: 1\nintegrations: { people: { source: {} } }\nentities:\n  residents: { provider: {} }\n",
        );
        write(
            temp.path(),
            "integrations/people/fixtures/active.yaml",
            "name: active-person\nexpect: { claims: { active: true } }\n",
        );
        temp
    }

    #[test]
    fn indexes_block_and_flow_yaml_and_resolves_cross_file_definitions() {
        let temp = fixture_project();
        let index = ProjectIndex::load(temp.path()).unwrap();

        assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
        assert!(index.symbols().iter().any(|symbol| {
            symbol.kind == RegistrySymbolKind::Integration
                && symbol.name == "people"
                && symbol.location.path.ends_with("integration.yaml")
        }));
        assert!(index.symbols().iter().any(|symbol| {
            symbol.kind == RegistrySymbolKind::Entity
                && symbol.name == "residents"
                && symbol.location.path.ends_with("residents.yaml")
        }));

        let manifest = temp.path().join(PROJECT_FILE);
        let locations = index.definitions_at(&manifest, Position::new(10, 38));
        assert_eq!(locations.len(), 1);
        assert!(locations[0].path.ends_with("integration.yaml"));

        let fixture = temp.path().join("integrations/people/fixtures/active.yaml");
        let claim_locations = index.definitions_at(&fixture, Position::new(1, 21));
        assert_eq!(claim_locations.len(), 1);
        assert_eq!(claim_locations[0].path, normalize_lookup_path(&manifest));

        let consultation_locations = index.definitions_at(&manifest, Position::new(12, 28));
        assert_eq!(consultation_locations.len(), 1);
        assert_eq!(
            consultation_locations[0].path,
            normalize_lookup_path(&manifest)
        );
        assert_eq!(consultation_locations[0].range.start, Position::new(10, 6));
    }

    #[test]
    fn reports_missing_duplicate_and_ambiguous_references() {
        let temp = fixture_project();
        write(
            temp.path(),
            PROJECT_FILE,
            r#"version: 1
registry: { id: demo }
integrations:
  people: { file: integrations/people/integration.yaml }
services:
  first:
    consultations:
      lookup: { integration: missing }
    claims:
      shared: { cel: true }
      shared: { cel: false }
      broken: { output: absent.value }
  second:
    claims:
      shared: { cel: true }
"#,
        );
        write(
            temp.path(),
            "integrations/people/fixtures/active.yaml",
            "name: active-person\nexpect: { claims: { shared: true } }\n",
        );
        let index = ProjectIndex::load(temp.path()).unwrap();
        let messages = index
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect::<Vec<_>>();

        assert!(messages
            .iter()
            .any(|message| message.contains("Unknown integration")));
        assert!(messages
            .iter()
            .any(|message| message.contains("Duplicate claim")));
        assert!(messages
            .iter()
            .any(|message| message.contains("Ambiguous claim")));
        assert!(messages
            .iter()
            .any(|message| message.contains("Unknown consultation")));
    }

    #[test]
    fn converts_byte_offsets_to_utf16_positions() {
        let value = parse_yaml("registry: { id: \"😀demo\" }\n").unwrap();
        let id = value
            .get("registry")
            .and_then(|registry| registry.get_scalar("id"))
            .unwrap();
        assert_eq!(id.range.start, Position::new(0, 17));
        assert_eq!(id.range.end, Position::new(0, 23));
    }

    #[test]
    fn rejects_unrelated_and_nested_project_documents() {
        let root = Path::new("/project");
        assert!(is_project_document(
            root,
            Path::new("/project/registry-stack.yaml")
        ));
        assert!(is_project_document(
            root,
            Path::new("/project/integrations/people/integration.yaml")
        ));
        assert!(!is_project_document(
            root,
            Path::new("/project/integrations/people/fixtures/bodies/response.yaml")
        ));
        assert!(!is_project_document(root, Path::new("/project/other.yaml")));
    }

    #[test]
    fn indexes_the_bundled_http_starter_without_reference_errors() {
        let starter = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../registryctl/assets/project-starters/bounded-http");
        let index = ProjectIndex::load(&starter).unwrap();

        assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
        for (kind, name) in [
            (RegistrySymbolKind::Registry, "fictional-citizen-registry"),
            (RegistrySymbolKind::Integration, "person-record"),
            (RegistrySymbolKind::Service, "person-verification"),
            (RegistrySymbolKind::Claim, "person-active"),
            (RegistrySymbolKind::Fixture, "active-person"),
            (RegistrySymbolKind::Environment, "local"),
        ] {
            assert!(
                index
                    .symbols()
                    .iter()
                    .any(|symbol| symbol.kind == kind && symbol.name == name),
                "missing {kind:?} {name}"
            );
        }
    }
}
