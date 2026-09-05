// SPDX-License-Identifier: Apache-2.0
//! Bounded Relay V2 project loading, compiler diagnostics, and semantic edges.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use registry_relay_v2::{
    authoring::check_project_documents,
    compiler::{referenced_governed_files, GovernedFileSet},
    contract::{ClassificationReviewDocument, RegistryContract},
    model::DiagnosticSeverity as RelayDiagnosticSeverity,
};
use tower_lsp_server::ls_types::{DiagnosticSeverity, Position, Range};

use crate::{
    refs::{
        document_diagnostic, document_rule_diagnostic, IndexedDiagnostic, IndexedLocation,
        IndexedProject, IndexedReference, IndexedSymbol, RelayV2Kind, SymbolKey, SymbolQuery,
        PROJECT_CEILING_RULE,
    },
    safety::{plain_file, secure_regular_file, SecureFileRead},
    workspace::{
        LoadedProjectDocuments, ProjectFamily, MAX_INDEXED_PROJECT_BYTES,
        MAX_INDEXED_PROJECT_DOCUMENTS, PROJECT_CEILING_MESSAGE,
    },
    yaml::{ParsedDocument, YamlScalar, YamlValue},
};

use super::PROJECT_FILE;

pub(crate) const RUNTIME_FILE: &str = "runtime.yaml";
const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;

pub(crate) fn declares_root(directory: &Path) -> bool {
    plain_file(&directory.join(PROJECT_FILE))
}

/// Whether `path` is one of the documents the current Relay V2 project resolves.
///
/// The recursive watcher has to observe every safe relative path because a governed reference may
/// name any of them. Observation is not ownership: only the two entry documents and the governed
/// closure resolved from the current in-memory documents belong to the project.
pub(crate) fn is_project_document(
    root: &Path,
    path: &Path,
    documents: &BTreeMap<PathBuf, String>,
) -> bool {
    project_document_paths(root, documents).contains(path)
}

pub(crate) fn retain_project_documents(
    root: &Path,
    documents: &mut BTreeMap<PathBuf, String>,
    diagnostics: &mut Vec<IndexedDiagnostic>,
) {
    let retained = project_document_paths(root, documents);
    documents.retain(|path, _| retained.contains(path));
    diagnostics.retain(|diagnostic| retained.contains(&diagnostic.path));
}

pub(crate) fn load_project_documents(root: &Path) -> Result<LoadedProjectDocuments> {
    load_project_documents_with_overrides(root, &BTreeMap::new())
}

pub(crate) fn load_project_documents_with_overrides(
    root: &Path,
    overrides: &BTreeMap<PathBuf, String>,
) -> Result<LoadedProjectDocuments> {
    let mut candidates = entry_document_paths(root);

    let mut documents = BTreeMap::new();
    let mut diagnostics = Vec::new();
    let mut indexed_bytes = 0usize;
    if let Some(path) = load_candidates(
        root,
        &candidates,
        &mut documents,
        &mut diagnostics,
        &mut indexed_bytes,
        overrides,
    )? {
        return Ok(blocked_project(&path));
    }
    let project_path = root.join(PROJECT_FILE);
    let Some(registry_yaml) = documents.get(&project_path) else {
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.path == project_path)
        {
            return Ok(LoadedProjectDocuments {
                documents,
                diagnostics,
                indexing_ceiling_path: None,
            });
        }
        anyhow::bail!("registry.yaml is missing, unsafe, oversized, or not valid UTF-8");
    };

    if RegistryContract::parse_yaml(registry_yaml).is_ok() {
        extend_registry_references(root, &documents, &mut candidates);
        if let Some(path) = load_candidates(
            root,
            &candidates,
            &mut documents,
            &mut diagnostics,
            &mut indexed_bytes,
            overrides,
        )? {
            return Ok(blocked_project(&path));
        }

        if extend_review_references(root, &documents, &mut candidates) {
            if let Some(path) = load_candidates(
                root,
                &candidates,
                &mut documents,
                &mut diagnostics,
                &mut indexed_bytes,
                overrides,
            )? {
                return Ok(blocked_project(&path));
            }
        }
    }

    Ok(LoadedProjectDocuments {
        documents,
        diagnostics,
        indexing_ceiling_path: None,
    })
}

fn entry_document_paths(root: &Path) -> BTreeSet<PathBuf> {
    BTreeSet::from([root.join(PROJECT_FILE), root.join(RUNTIME_FILE)])
}

fn project_document_paths(root: &Path, documents: &BTreeMap<PathBuf, String>) -> BTreeSet<PathBuf> {
    let mut candidates = entry_document_paths(root);
    extend_registry_references(root, documents, &mut candidates);
    extend_review_references(root, documents, &mut candidates);
    candidates
}

fn extend_registry_references(
    root: &Path,
    documents: &BTreeMap<PathBuf, String>,
    candidates: &mut BTreeSet<PathBuf>,
) {
    let Some(contract) = documents
        .get(&root.join(PROJECT_FILE))
        .and_then(|source| RegistryContract::parse_yaml(source).ok())
    else {
        return;
    };
    candidates.extend(
        referenced_governed_files(&contract)
            .into_iter()
            .filter_map(|reference| supported_reference(root, reference)),
    );
}

fn extend_review_references(
    root: &Path,
    documents: &BTreeMap<PathBuf, String>,
    candidates: &mut BTreeSet<PathBuf>,
) -> bool {
    let Some(contract) = documents
        .get(&root.join(PROJECT_FILE))
        .and_then(|source| RegistryContract::parse_yaml(source).ok())
    else {
        return false;
    };
    let Some(review_path) = supported_reference(root, &contract.classifications.provenance_ref)
    else {
        return false;
    };
    let Some(review) = documents
        .get(&review_path)
        .and_then(|source| serde_norway::from_str::<ClassificationReviewDocument>(source).ok())
    else {
        return false;
    };
    for reference in [
        Some(review.rationale_ref.as_str()),
        review
            .generated_identification
            .as_ref()
            .map(|binding| binding.report_ref.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(path) = supported_reference(root, reference) {
            candidates.insert(path);
        }
    }
    true
}

fn load_candidates(
    root: &Path,
    candidates: &BTreeSet<PathBuf>,
    documents: &mut BTreeMap<PathBuf, String>,
    diagnostics: &mut Vec<IndexedDiagnostic>,
    indexed_bytes: &mut usize,
    overrides: &BTreeMap<PathBuf, String>,
) -> Result<Option<PathBuf>> {
    let project_path = root.join(PROJECT_FILE);
    for path in candidates {
        if documents.contains_key(path) {
            continue;
        }
        if documents.len() >= MAX_INDEXED_PROJECT_DOCUMENTS {
            return Ok(Some(path.clone()));
        }
        if let Some(source) = overrides.get(path) {
            if source.len() as u64 > MAX_DOCUMENT_BYTES {
                diagnostics.push(document_diagnostic(
                    path,
                    "Project document exceeds the 1 MiB indexing limit",
                ));
                continue;
            }
            *indexed_bytes = indexed_bytes.saturating_add(source.len());
            if *indexed_bytes > MAX_INDEXED_PROJECT_BYTES {
                return Ok(Some(path.clone()));
            }
            documents.insert(path.clone(), source.clone());
            continue;
        }
        let file = match secure_regular_file(root, path) {
            Ok(Some(file)) => file,
            Ok(None) => continue,
            Err(error) if path == &project_path => {
                return Err(error).context("failed to read registry.yaml");
            }
            Err(_) => {
                diagnostics.push(document_diagnostic(
                    path,
                    "Project document could not be read; check its permissions",
                ));
                continue;
            }
        };
        match file.read_bounded(MAX_DOCUMENT_BYTES) {
            Ok(SecureFileRead::TooLarge) => diagnostics.push(document_diagnostic(
                path,
                "Project document exceeds the 1 MiB indexing limit",
            )),
            Ok(SecureFileRead::Bytes(bytes)) => match String::from_utf8(bytes) {
                Ok(source) => {
                    *indexed_bytes = indexed_bytes.saturating_add(source.len());
                    if *indexed_bytes > MAX_INDEXED_PROJECT_BYTES {
                        return Ok(Some(path.clone()));
                    }
                    documents.insert(path.clone(), source);
                }
                Err(_) => diagnostics.push(document_diagnostic(
                    path,
                    "Project document is not valid UTF-8 and cannot be indexed",
                )),
            },
            Err(error) if path == &project_path => {
                return Err(error).context("failed to read registry.yaml");
            }
            Err(_) => diagnostics.push(document_diagnostic(
                path,
                "Project document could not be read; check its permissions",
            )),
        }
    }
    Ok(None)
}

fn supported_reference(root: &Path, reference: &str) -> Option<PathBuf> {
    let path = root.join(reference);
    let relative = path.strip_prefix(root).ok()?;
    (!relative.as_os_str().is_empty()
        && relative
            .components()
            .all(|component| matches!(component, Component::Normal(_))))
    .then_some(path)
}

fn blocked_project(path: &Path) -> LoadedProjectDocuments {
    LoadedProjectDocuments {
        documents: BTreeMap::new(),
        diagnostics: vec![document_rule_diagnostic(
            path,
            ProjectFamily::RelayV2.diagnostic_code(PROJECT_CEILING_RULE),
            PROJECT_CEILING_MESSAGE,
        )],
        indexing_ceiling_path: Some(path.to_path_buf()),
    }
}

pub(crate) fn build_index(
    root: &Path,
    documents: &BTreeMap<PathBuf, String>,
    parsed: &BTreeMap<PathBuf, ParsedDocument>,
) -> IndexedProject {
    let mut builder = IndexBuilder {
        root,
        documents,
        parsed,
        symbols: Vec::new(),
        references: Vec::new(),
        diagnostics: Vec::new(),
    };
    builder.build();
    IndexedProject {
        symbols: builder.symbols,
        references: builder.references,
        diagnostics: builder.diagnostics,
        choices: Vec::new(),
    }
}

struct IndexBuilder<'a> {
    root: &'a Path,
    documents: &'a BTreeMap<PathBuf, String>,
    parsed: &'a BTreeMap<PathBuf, ParsedDocument>,
    symbols: Vec<IndexedSymbol>,
    references: Vec<IndexedReference>,
    diagnostics: Vec<IndexedDiagnostic>,
}

impl IndexBuilder<'_> {
    fn build(&mut self) {
        let registry_path = self.root.join(PROJECT_FILE);
        if let Some(registry) = self.parsed.get(&registry_path) {
            self.extract_registry(&registry_path, &registry.value);
        }
        let runtime_path = self.root.join(RUNTIME_FILE);
        if let Some(runtime) = self.parsed.get(&runtime_path) {
            self.extract_runtime(&runtime_path, &runtime.value);
        }
        self.extract_governed_files();
        self.extract_compiler_diagnostics();
    }

    fn extract_registry(&mut self, path: &Path, document: &YamlValue) {
        if let Some(identifier) = document
            .get("registry")
            .and_then(|registry| registry.get_scalar("registryIdentifier"))
        {
            self.add_symbol(
                SymbolKey::global(RelayV2Kind::Registry, &identifier.value),
                None,
                path,
                identifier.range,
            );
        }

        if let Some(sources) = document.get("sources").and_then(YamlValue::as_mapping) {
            for source in sources {
                self.add_symbol(
                    SymbolKey::global(RelayV2Kind::Source, &source.key.value),
                    None,
                    path,
                    source.key.range,
                );
            }
        }

        self.file_reference_at(
            path,
            document
                .get("registry")
                .and_then(|registry| registry.get_scalar("identifierLifecyclePolicyRef")),
        );
        self.file_reference_at(
            path,
            document
                .get("classifications")
                .and_then(|catalog| catalog.get_scalar("provenanceRef")),
        );
        if let Some(alignments) = document
            .get("semantics")
            .and_then(|semantics| semantics.get("alignments"))
            .and_then(YamlValue::as_sequence)
        {
            for alignment in alignments {
                self.file_reference_at(path, alignment.get_scalar("profileRef"));
            }
        }

        if let Some(resources) = document.get("resources").and_then(YamlValue::as_sequence) {
            for resource in resources {
                self.extract_resource(path, resource);
            }
        }
        if let Some(datasets) = document
            .get("statisticalDatasets")
            .and_then(YamlValue::as_sequence)
        {
            for dataset in datasets {
                self.extract_statistical_dataset(path, dataset);
            }
        }
    }

    fn extract_resource(&mut self, path: &Path, resource: &YamlValue) {
        let Some(id) = resource.get_scalar("id") else {
            return;
        };
        let resource_id = id.value.clone();
        self.add_symbol(
            SymbolKey::global(RelayV2Kind::Resource, &resource_id),
            None,
            path,
            id.range,
        );
        if let Some(source) = resource
            .get("source")
            .and_then(|source| source.get_scalar("source"))
        {
            self.add_reference(
                SymbolQuery::global(RelayV2Kind::Source, &source.value),
                path,
                source,
            );
        }
        if let Some(codelist) = resource
            .get("recordContext")
            .and_then(|context| context.get("lifecycleState"))
            .and_then(|state| state.get_scalar("codelist"))
        {
            self.file_reference(path, codelist);
        }

        if let Some(properties) = resource.get("properties").and_then(YamlValue::as_mapping) {
            for property in properties {
                self.add_symbol(
                    SymbolKey::scoped(RelayV2Kind::Property, &resource_id, &property.key.value),
                    Some(resource_id.clone()),
                    path,
                    property.key.range,
                );
                self.file_reference_at(path, property.value.get_scalar("codelist"));
            }
        }
        if let Some(primary_geometry) = resource.get_scalar("primaryGeometry") {
            self.add_reference(
                SymbolQuery::scoped(RelayV2Kind::Property, &resource_id, &primary_geometry.value),
                path,
                primary_geometry,
            );
        }

        if let Some(profiles) = resource
            .get("disclosureProfiles")
            .and_then(YamlValue::as_mapping)
        {
            for profile in profiles {
                self.add_symbol(
                    SymbolKey::scoped(
                        RelayV2Kind::DisclosureProfile,
                        &resource_id,
                        &profile.key.value,
                    ),
                    Some(resource_id.clone()),
                    path,
                    profile.key.range,
                );
                if let Some(properties) = profile
                    .value
                    .get("properties")
                    .and_then(YamlValue::as_sequence)
                {
                    for property in properties.iter().filter_map(YamlValue::as_scalar) {
                        self.add_reference(
                            SymbolQuery::scoped(
                                RelayV2Kind::Property,
                                &resource_id,
                                &property.value,
                            ),
                            path,
                            property,
                        );
                    }
                }
            }
        }

        if let Some(operations) = resource.get("operations") {
            if let Some(entries) = operations.as_mapping() {
                for operation in entries
                    .iter()
                    .filter(|operation| matches!(operation.key.value.as_str(), "list" | "read"))
                {
                    self.extract_operation(
                        path,
                        &resource_id,
                        &operation.key.value,
                        &operation.value,
                        operation.key.range,
                    );
                }
            }
            if let Some(lookups) = operations.get("lookups").and_then(YamlValue::as_sequence) {
                for lookup in lookups {
                    if let Some(operation_id) = lookup.get_scalar("id") {
                        self.extract_operation(
                            path,
                            &resource_id,
                            &operation_id.value,
                            lookup,
                            operation_id.range,
                        );
                        if let Some(selectors) = lookup
                            .get("requestBody")
                            .and_then(|body| body.get("selectors"))
                            .and_then(YamlValue::as_mapping)
                        {
                            for selector in selectors {
                                self.file_reference_at(path, selector.value.get_scalar("codelist"));
                            }
                        }
                    }
                }
            }
            if let Some(searches) = operations.get("searches").and_then(YamlValue::as_sequence) {
                for search in searches {
                    if let Some(operation_id) = search.get_scalar("id") {
                        self.extract_operation(
                            path,
                            &resource_id,
                            &operation_id.value,
                            search,
                            operation_id.range,
                        );
                    }
                }
            }
        }

        if let Some(processing) = resource
            .get("processingDescriptions")
            .and_then(YamlValue::as_sequence)
        {
            for description in processing {
                if let Some(operation_refs) = description
                    .get("operationRefs")
                    .and_then(YamlValue::as_sequence)
                {
                    for operation in operation_refs.iter().filter_map(YamlValue::as_scalar) {
                        self.add_reference(
                            SymbolQuery::scoped(
                                RelayV2Kind::Operation,
                                &resource_id,
                                &operation.value,
                            ),
                            path,
                            operation,
                        );
                    }
                }
                self.file_reference_at(path, description.get_scalar("legalBasisRef"));
                self.file_reference_at(path, description.get_scalar("dpvProfileRef"));
            }
        }
    }

    fn extract_statistical_dataset(&mut self, path: &Path, dataset: &YamlValue) {
        let Some(id) = dataset.get_scalar("id") else {
            return;
        };
        let dataset_id = id.value.clone();
        self.add_symbol(
            SymbolKey::global(RelayV2Kind::StatisticalDataset, &dataset_id),
            None,
            path,
            id.range,
        );
        if let Some(source) = dataset
            .get("source")
            .and_then(|source| source.get_scalar("source"))
        {
            self.add_reference(
                SymbolQuery::global(RelayV2Kind::Source, &source.value),
                path,
                source,
            );
        }

        for collection in ["dimensions", "attributes"] {
            if let Some(components) = dataset.get(collection).and_then(YamlValue::as_mapping) {
                for component in components {
                    self.add_statistical_component(
                        path,
                        &dataset_id,
                        &component.key,
                        &component.value,
                    );
                }
            }
        }
        if let Some(entries) = dataset.as_mapping() {
            if let Some(time) = entries.iter().find(|entry| entry.key.value == "time") {
                self.add_statistical_component(path, &dataset_id, &time.key, &time.value);
            }
        }
        if let Some(measure) = dataset.get("measure") {
            if let Some(identifier) = measure.get_scalar("id") {
                self.add_statistical_component(path, &dataset_id, identifier, measure);
            }
        }

        let operation_id = "statistics:read";
        self.add_symbol(
            SymbolKey::scoped(RelayV2Kind::Operation, &dataset_id, operation_id),
            Some(dataset_id.clone()),
            path,
            id.range,
        );
        if let Some(processing) = dataset
            .get("processingDescriptions")
            .and_then(YamlValue::as_sequence)
        {
            for description in processing {
                if let Some(operation_refs) = description
                    .get("operationRefs")
                    .and_then(YamlValue::as_sequence)
                {
                    for operation in operation_refs.iter().filter_map(YamlValue::as_scalar) {
                        self.add_reference(
                            SymbolQuery::scoped(
                                RelayV2Kind::Operation,
                                &dataset_id,
                                &operation.value,
                            ),
                            path,
                            operation,
                        );
                    }
                }
                self.file_reference_at(path, description.get_scalar("legalBasisRef"));
                self.file_reference_at(path, description.get_scalar("dpvProfileRef"));
            }
        }
    }

    fn add_statistical_component(
        &mut self,
        path: &Path,
        dataset_id: &str,
        identifier: &YamlScalar,
        component: &YamlValue,
    ) {
        self.add_symbol(
            SymbolKey::scoped(
                RelayV2Kind::StatisticalComponent,
                dataset_id,
                &identifier.value,
            ),
            Some(dataset_id.to_owned()),
            path,
            identifier.range,
        );
        self.file_reference_at(path, component.get_scalar("vocabulary"));
    }

    fn extract_operation(
        &mut self,
        path: &Path,
        resource_id: &str,
        operation_id: &str,
        operation: &YamlValue,
        operation_range: Range,
    ) {
        self.add_symbol(
            SymbolKey::scoped(RelayV2Kind::Operation, resource_id, operation_id),
            Some(resource_id.to_owned()),
            path,
            operation_range,
        );
        let access_profile_scope = format!("{resource_id}/{operation_id}");
        if let Some(access_profiles) = operation
            .get("accessProfiles")
            .and_then(YamlValue::as_mapping)
        {
            for access_profile in access_profiles {
                self.add_symbol(
                    SymbolKey::scoped(
                        RelayV2Kind::AccessProfile,
                        &access_profile_scope,
                        &access_profile.key.value,
                    ),
                    Some(access_profile_scope.clone()),
                    path,
                    access_profile.key.range,
                );
                if let Some(profile) = access_profile.value.get_scalar("disclosureProfile") {
                    self.add_reference(
                        SymbolQuery::scoped(
                            RelayV2Kind::DisclosureProfile,
                            resource_id,
                            &profile.value,
                        ),
                        path,
                        profile,
                    );
                }
            }
        }
        if let Some(default) = operation.get_scalar("defaultAccessProfile") {
            self.add_reference(
                SymbolQuery::scoped(
                    RelayV2Kind::AccessProfile,
                    &access_profile_scope,
                    &default.value,
                ),
                path,
                default,
            );
        }
        if let Some(filters) = operation.get("filters").and_then(YamlValue::as_sequence) {
            for filter in filters {
                if let Some(property) = filter.get_scalar("property") {
                    self.add_reference(
                        SymbolQuery::scoped(RelayV2Kind::Property, resource_id, &property.value),
                        path,
                        property,
                    );
                }
            }
        }
        if let Some(order) = operation.get("orderBy").and_then(YamlValue::as_sequence) {
            for property in order.iter().filter_map(YamlValue::as_scalar) {
                self.add_reference(
                    SymbolQuery::scoped(RelayV2Kind::Property, resource_id, &property.value),
                    path,
                    property,
                );
            }
        }
    }

    fn extract_runtime(&mut self, path: &Path, runtime: &YamlValue) {
        if let Some(sources) = runtime.get("sources").and_then(YamlValue::as_mapping) {
            for source in sources {
                self.add_reference(
                    SymbolQuery::global(RelayV2Kind::Source, &source.key.value),
                    path,
                    &source.key,
                );
            }
        }
    }

    fn extract_governed_files(&mut self) {
        let project_path = self.root.join(PROJECT_FILE);
        let runtime_path = self.root.join(RUNTIME_FILE);
        for path in self.documents.keys() {
            if path == &project_path || path == &runtime_path {
                continue;
            }
            let Ok(relative) = path.strip_prefix(self.root) else {
                continue;
            };
            let Some(name) = relative.to_str() else {
                continue;
            };
            self.add_symbol(
                SymbolKey::global(RelayV2Kind::GovernedFile, name),
                None,
                path,
                zero_range(),
            );
            if let Some(review) = self.parsed.get(path) {
                self.file_reference_at(path, review.value.get_scalar("rationaleRef"));
                self.file_reference_at(
                    path,
                    review
                        .value
                        .get("generatedIdentification")
                        .and_then(|binding| binding.get_scalar("reportRef")),
                );
            }
        }
    }

    fn extract_compiler_diagnostics(&mut self) {
        let registry_path = self.root.join(PROJECT_FILE);
        let Some(registry_yaml) = self.documents.get(&registry_path) else {
            return;
        };
        let runtime_path = self.root.join(RUNTIME_FILE);
        let runtime_yaml = self.documents.get(&runtime_path).map(String::as_str);
        let governed = self.governed_file_set(registry_yaml);
        for diagnostic in
            check_project_documents(registry_yaml, runtime_yaml, &governed).diagnostics
        {
            let (path, range) = self.compiler_location(&diagnostic.location);
            self.diagnostics.push(IndexedDiagnostic {
                path,
                range,
                severity: match diagnostic.severity {
                    RelayDiagnosticSeverity::Error => DiagnosticSeverity::ERROR,
                    RelayDiagnosticSeverity::Warning => DiagnosticSeverity::WARNING,
                },
                code: Some(format!("relay-v2/{}", diagnostic.code)),
                message: diagnostic.message,
            });
        }
    }

    fn governed_file_set(&self, registry_yaml: &str) -> GovernedFileSet {
        let Ok(contract) = RegistryContract::parse_yaml(registry_yaml) else {
            return GovernedFileSet::new();
        };
        let mut references = referenced_governed_files(&contract)
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let review_path = self.root.join(&contract.classifications.provenance_ref);
        if let Some(review) = self
            .documents
            .get(&review_path)
            .and_then(|source| serde_norway::from_str::<ClassificationReviewDocument>(source).ok())
        {
            references.insert(review.rationale_ref);
            if let Some(binding) = review.generated_identification {
                references.insert(binding.report_ref);
            }
        }
        references
            .into_iter()
            .filter_map(|reference| {
                self.documents
                    .get(&self.root.join(&reference))
                    .map(|source| (reference, source.as_bytes().to_vec()))
            })
            .collect()
    }

    fn compiler_location(&self, location: &str) -> (PathBuf, Range) {
        if location == RUNTIME_FILE || location.starts_with("runtime.yaml.") {
            let path = self.root.join(RUNTIME_FILE);
            let field = location.strip_prefix("runtime.yaml.").unwrap_or("");
            return (path.clone(), self.range_at(&path, field));
        }
        if location == PROJECT_FILE {
            return (self.root.join(PROJECT_FILE), zero_range());
        }
        let governed_path = location.split_once(':').map_or(location, |(path, _)| path);
        let candidate = self.root.join(governed_path);
        if self.documents.contains_key(&candidate) {
            let field = location
                .strip_prefix(governed_path)
                .and_then(|suffix| suffix.strip_prefix(':'))
                .unwrap_or("");
            return (candidate.clone(), self.range_at(&candidate, field));
        }
        if location.contains('/') {
            if let Some((path, range)) = self.find_written_value(location) {
                return (path, range);
            }
        }
        let path = self.root.join(PROJECT_FILE);
        (path.clone(), self.range_at(&path, location))
    }

    fn range_at(&self, path: &Path, location: &str) -> Range {
        if location.is_empty() {
            return zero_range();
        }
        self.parsed
            .get(path)
            .and_then(|document| range_for_location(&document.value, location))
            .unwrap_or_else(zero_range)
    }

    fn find_written_value(&self, value: &str) -> Option<(PathBuf, Range)> {
        self.parsed.iter().find_map(|(path, document)| {
            find_scalar(&document.value, value).map(|scalar| (path.clone(), scalar.range))
        })
    }

    fn file_reference_at(&mut self, path: &Path, scalar: Option<&YamlScalar>) {
        if let Some(scalar) = scalar {
            self.file_reference(path, scalar);
        }
    }

    fn file_reference(&mut self, path: &Path, scalar: &YamlScalar) {
        self.add_reference(
            SymbolQuery::global(RelayV2Kind::GovernedFile, &scalar.value),
            path,
            scalar,
        );
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
            resolvable: true,
        });
    }

    fn add_reference(&mut self, target: SymbolQuery, path: &Path, at: &YamlScalar) {
        self.references.push(IndexedReference {
            target,
            location: IndexedLocation {
                path: path.to_path_buf(),
                range: at.range,
            },
            // The shared compiler owns every semantic refusal. The reference
            // remains navigable and completable without restating its rules.
            reports_unresolved: false,
            style: at.style,
            offers: None,
        });
    }
}

fn range_for_location(root: &YamlValue, location: &str) -> Option<Range> {
    let mut current = root;
    let mut range = None;
    for raw_segment in location.split('.') {
        let (name, index) = segment(raw_segment);
        if !name.is_empty() {
            match current {
                YamlValue::Mapping(entries) => {
                    // A segment that doesn't resolve degrades to the last
                    // ancestor range that did, rather than discarding the
                    // whole walk and falling back to the document origin.
                    let Some(entry) = entries.iter().find(|entry| entry.key.value == name) else {
                        return range;
                    };
                    range = Some(entry.key.range);
                    current = &entry.value;
                }
                YamlValue::Sequence(values) => {
                    let Some(value) = values.iter().find(|value| {
                        value
                            .get_scalar("id")
                            .is_some_and(|identifier| identifier.value == name)
                    }) else {
                        return range;
                    };
                    range = value.get_scalar("id").map(|identifier| identifier.range);
                    current = value;
                }
                YamlValue::Scalar(_) | YamlValue::Other => return range,
            }
        }
        if let Some(index) = index {
            let Some(values) = current.as_sequence() else {
                return range;
            };
            let Some(next) = values.get(index) else {
                return range;
            };
            current = next;
            range = first_scalar(current).map(|scalar| scalar.range).or(range);
        }
    }
    current.as_scalar().map(|scalar| scalar.range).or(range)
}

fn segment(value: &str) -> (&str, Option<usize>) {
    let Some((name, suffix)) = value.split_once('[') else {
        return (value, None);
    };
    let index = suffix
        .strip_suffix(']')
        .and_then(|index| index.parse::<usize>().ok());
    (name, index)
}

fn first_scalar(value: &YamlValue) -> Option<&YamlScalar> {
    match value {
        YamlValue::Scalar(scalar) => Some(scalar),
        YamlValue::Mapping(entries) => entries
            .iter()
            .find_map(|entry| first_scalar(&entry.value).or(Some(&entry.key))),
        YamlValue::Sequence(values) => values.iter().find_map(first_scalar),
        YamlValue::Other => None,
    }
}

fn find_scalar<'a>(value: &'a YamlValue, expected: &str) -> Option<&'a YamlScalar> {
    match value {
        YamlValue::Scalar(scalar) => (scalar.value == expected).then_some(scalar),
        YamlValue::Mapping(entries) => entries.iter().find_map(|entry| {
            (entry.key.value == expected)
                .then_some(&entry.key)
                .or_else(|| find_scalar(&entry.value, expected))
        }),
        YamlValue::Sequence(values) => values.iter().find_map(|value| find_scalar(value, expected)),
        YamlValue::Other => None,
    }
}

fn zero_range() -> Range {
    Range::new(Position::new(0, 0), Position::new(0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refs::SymbolKind;

    #[test]
    fn an_oversized_marker_returns_its_document_diagnostic() {
        let project = tempfile::tempdir().unwrap();
        let marker = project.path().join(PROJECT_FILE);
        std::fs::write(&marker, vec![b'x'; MAX_DOCUMENT_BYTES as usize + 1]).unwrap();

        let loaded = load_project_documents(project.path()).unwrap();

        assert!(loaded.documents.is_empty());
        assert!(loaded.diagnostics.iter().any(|diagnostic| {
            diagnostic.path == marker && diagnostic.message.contains("1 MiB indexing limit")
        }));
    }

    #[test]
    fn all_acceptance_projects_are_compiler_clean_and_index_their_core_edges() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/relay-v2/acceptance");
        for project in [
            "social-assistance",
            "business-registry",
            "civil-event",
            "labour-statistics",
        ] {
            let index = crate::refs::ProjectIndex::load_relay_v2(&root.join(project)).unwrap();
            assert!(
                index.diagnostics().is_empty(),
                "{project}: {:?}",
                index.diagnostics()
            );
            assert!(index
                .symbols()
                .iter()
                .any(|symbol| { symbol.kind == SymbolKind::RelayV2(RelayV2Kind::Source) }));
            assert!(index.symbols().iter().any(|symbol| {
                matches!(
                    symbol.kind,
                    SymbolKind::RelayV2(RelayV2Kind::Resource | RelayV2Kind::StatisticalDataset)
                )
            }));
            assert!(index
                .symbols()
                .iter()
                .any(|symbol| { symbol.kind == SymbolKind::RelayV2(RelayV2Kind::GovernedFile) }));
            assert!(index.symbols().iter().all(|symbol| {
                symbol.kind != SymbolKind::RelayV2(RelayV2Kind::Operation)
                    || symbol.location.range != zero_range()
            }));
            if project == "business-registry" {
                assert!(index.symbols().iter().any(|symbol| {
                    symbol.kind == SymbolKind::RelayV2(RelayV2Kind::AccessProfile)
                }));
            }
            if project == "labour-statistics" {
                for kind in [
                    RelayV2Kind::StatisticalDataset,
                    RelayV2Kind::StatisticalComponent,
                    RelayV2Kind::Operation,
                ] {
                    assert!(index
                        .symbols()
                        .iter()
                        .any(|symbol| symbol.kind == SymbolKind::RelayV2(kind)));
                }
            }
        }
    }

    #[test]
    fn location_parser_reaches_sequence_and_mapping_members() {
        let parsed = crate::yaml::parse_yaml(
            "resources:\n  - id: people\n    properties:\n      name: {type: string}\n",
        )
        .unwrap();
        assert_eq!(
            range_for_location(&parsed.value, "resources[0].properties.name")
                .unwrap()
                .start,
            Position::new(3, 6)
        );
    }

    #[test]
    fn location_parser_falls_back_to_the_deepest_resolved_ancestor() {
        let parsed = crate::yaml::parse_yaml(
            "resources:\n  - id: people\n    properties:\n      name: {type: string}\n",
        )
        .unwrap();
        // "missing" does not exist under properties, but "resources[0].properties"
        // does; the range of that resolved ancestor must survive rather than
        // the whole walk collapsing to None (and the caller's zero_range()).
        assert_eq!(
            range_for_location(&parsed.value, "resources[0].properties.missing")
                .unwrap()
                .start,
            Position::new(2, 4)
        );
    }

    #[test]
    fn location_parser_falls_back_when_a_sequence_index_is_out_of_range() {
        let parsed = crate::yaml::parse_yaml(
            "resources:\n  - id: people\n    properties:\n      name: {type: string}\n",
        )
        .unwrap();
        assert_eq!(
            range_for_location(&parsed.value, "resources[9].name")
                .unwrap()
                .start,
            Position::new(0, 0)
        );
    }

    #[test]
    fn location_parser_returns_none_when_the_first_segment_does_not_resolve() {
        let parsed = crate::yaml::parse_yaml("resources:\n  - id: people\n").unwrap();
        assert!(range_for_location(&parsed.value, "missing.field").is_none());
    }

    #[test]
    fn project_documents_are_entry_documents_and_the_exact_governed_closure() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/relay-v2/acceptance/business-registry");
        let loaded = load_project_documents(&root).unwrap();

        assert!(is_project_document(
            &root,
            &root.join("registry.yaml"),
            &loaded.documents,
        ));
        assert!(is_project_document(
            &root,
            &root.join("runtime.yaml"),
            &loaded.documents,
        ));
        assert!(is_project_document(
            &root,
            &root.join("governance/classification-review-rationale.md"),
            &loaded.documents,
        ));
        assert!(!is_project_document(
            &root,
            &root.join("expected-http.yaml"),
            &loaded.documents,
        ));
        assert!(!is_project_document(
            &root,
            &root.join("../outside/rationale.md"),
            &loaded.documents,
        ));
    }
}
