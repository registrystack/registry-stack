// SPDX-License-Identifier: Apache-2.0
//! Closed compilation from authored contract plus observed schema to one model.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Component, Path};

use chrono::DateTime;
use registry_discovery_profile::{is_valid_endpoint_url, is_valid_public_text};
use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::contract::{
    AccessProfileDefinition, AccessRule, AuthorityRowBinding, ClassificationPartial, DataType,
    DateInputType, DatePrecision, Handling, IdentificationMethod, PropertyBindingDefinition,
    RegistryContract, ReviewStatus, SearchQueryDefinition, SourceProfile, StatisticalValueType,
    TransformDefinition, MAXIMUM_ACCESS_PROFILE_IDENTIFIER_BYTES,
    MAXIMUM_PUBLICATION_JURISDICTIONS,
};
use crate::cursor::MAXIMUM_CURSOR_ORDER_VALUES;
use crate::model::{
    CapabilityFamily, ColumnAccount, ColumnUse, CompileProfile, CompileReport, CompiledAccess,
    CompiledAccessProfile, CompiledClassificationReview, CompiledCodelist,
    CompiledDisclosureProfile, CompiledFilter, CompiledGeneratedIdentificationBinding,
    CompiledGovernedFile, CompiledMetadataVisibility, CompiledOperation, CompiledPagination,
    CompiledPointPropertyBinding, CompiledProperty, CompiledPropertyBinding, CompiledPurpose,
    CompiledRecordContext, CompiledRegistry, CompiledResource, CompiledRowBinding,
    CompiledScalarPropertyBinding, CompiledSdmxBindingProfile, CompiledSelector, CompiledSource,
    CompiledSpatialBboxQuery, CompiledStatisticalAttribute, CompiledStatisticalDataset,
    CompiledStatisticalDimension, CompiledStatisticalMeasure, CompiledStatisticalTimeDimension,
    CompiledTransform, ConsultationPattern, Diagnostic, DiagnosticSeverity,
    EffectiveClassification, ObservedSourceSchema, OperationKind, QueryPlan, RowAuthoritySource,
    StarterColumn, StarterContract,
};

const API_VERSION: &str = "relay.registrystack.org/v2alpha1";
const CRS84: &str = "http://www.opengis.net/def/crs/OGC/0/CRS84";
const RESERVED_PARAMETERS: [&str; 6] = [
    "pageSize",
    "cursor",
    "fields",
    "accessProfile",
    "bbox",
    "formatProfile",
];
const MAXIMUM_RESOURCES: usize = 128;
const MAXIMUM_PROPERTIES_PER_RESOURCE: usize = 128;
const MAXIMUM_DISCLOSURE_PROFILES_PER_RESOURCE: usize = 64;
const MAXIMUM_ACCESS_PROFILES_PER_OPERATION: usize = 16;
const MAXIMUM_ACCESS_PROFILE_EXECUTORS_PER_REGISTRY: usize = 128;
const MAXIMUM_LIST_FILTERS: usize = 32;
const MAXIMUM_LIST_ORDER_KEYS: usize = MAXIMUM_CURSOR_ORDER_VALUES;
const MAXIMUM_LIST_PAGE_SIZE: u32 = 1_000;
const MAXIMUM_LOOKUP_REQUEST_BODY_BYTES: u32 = 1024 * 1024;
const MAXIMUM_LOOKUP_SELECTORS: usize = 32;
const MAXIMUM_SEARCHES_PER_RESOURCE: usize = 16;
const MAXIMUM_STATISTICAL_DATASETS: usize = 32;
const MAXIMUM_SDMX_DIMENSIONS: usize = 16;
const MAXIMUM_SDMX_ATTRIBUTES: usize = 32;
const MAXIMUM_SDMX_OBSERVATIONS: u32 = 10_000;
const MAXIMUM_SDMX_OFFSET: u32 = 1_000_000;
const MAXIMUM_SDMX_COMPONENT_VALUE_BYTES: usize = 1024;
const MAXIMUM_ROUTE_IDENTIFIER_BYTES: usize = 128;
const SDMX_REST_VERSION: &str = "2.2.2";
const SDMX_DATA_JSON_VERSION: &str = "2.1.0";
const SDMX_DATA_CSV_VERSION: &str = "2.1.0";
const SDMX_STRUCTURE_JSON_VERSION: &str = "2.1.0";
const MAXIMUM_SELECTOR_BYTES: u32 = 4 * 1024;
const MAXIMUM_PARTIAL_STRING_CHARACTERS: u16 = 64;
// Keep governed purpose values inside the exact direct-string claim ceiling
// enforced by `auth::direct_string_value` at request time.
const MAXIMUM_DIRECT_CLAIM_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceRuntimeType {
    Text,
    Boolean,
    Integer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SqliteTypeAffinity {
    Integer,
    Text,
    Blob,
    Real,
    Numeric,
}

pub type GovernedFileSet = BTreeMap<String, Vec<u8>>;

/// Every governed file directly named by a Registry contract.
///
/// A classification review may name its rationale and accepted identification
/// report in turn. Callers add those after reading the directly referenced
/// review document.
pub fn referenced_governed_files(contract: &RegistryContract) -> BTreeSet<&str> {
    let mut references = BTreeSet::new();
    references.insert(contract.registry.identifier_lifecycle_policy_ref.as_str());
    references.insert(contract.classifications.provenance_ref.as_str());
    for alignment in &contract.semantics.alignments {
        references.insert(alignment.profile_ref.as_str());
    }
    for resource in &contract.resources {
        references.insert(resource.record_context.lifecycle_state.codelist.as_str());
        for (_, property) in resource.properties.iter() {
            if let Some(codelist) = property
                .scalar_binding()
                .and_then(|binding| binding.codelist.as_deref())
            {
                references.insert(codelist);
            }
        }
        for lookup in &resource.operations.lookups {
            for (_, selector) in lookup.request_body.selectors.iter() {
                if let Some(codelist) = selector.codelist.as_deref() {
                    references.insert(codelist);
                }
            }
        }
        for processing in &resource.processing_descriptions {
            references.insert(processing.legal_basis_ref.as_str());
            references.insert(processing.dpv_profile_ref.as_str());
        }
    }
    for dataset in &contract.statistical_datasets {
        for (_, dimension) in dataset.dimensions.iter() {
            if let Some(vocabulary) = dimension.vocabulary.as_deref() {
                references.insert(vocabulary);
            }
        }
        for (_, attribute) in dataset.attributes.iter() {
            if let Some(vocabulary) = attribute.vocabulary.as_deref() {
                references.insert(vocabulary);
            }
        }
        for processing in &dataset.processing_descriptions {
            references.insert(processing.legal_basis_ref.as_str());
            references.insert(processing.dpv_profile_ref.as_str());
        }
    }
    references
}

pub fn compile_yaml(
    yaml: &str,
    observed: &[ObservedSourceSchema],
    profile: CompileProfile,
) -> Result<CompiledRegistry, CompileReport> {
    let contract = RegistryContract::parse_yaml(yaml).map_err(|_| CompileReport {
        diagnostics: vec![Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "contract.yaml_invalid".into(),
            location: "registry.yaml".into(),
            message: "the governed contract is not valid strict YAML".into(),
        }],
    })?;
    compile_contract(&contract, observed, profile)
}

pub fn compile_contract(
    contract: &RegistryContract,
    observed: &[ObservedSourceSchema],
    profile: CompileProfile,
) -> Result<CompiledRegistry, CompileReport> {
    let mut compiler = Compiler::new(contract, observed, profile);
    compiler.validate_top_level();
    let resources = compiler.compile_resources();
    let statistical_datasets = compiler.compile_statistical_datasets();
    let access_profile_executors = resources
        .iter()
        .flat_map(|resource| &resource.operations)
        .map(|operation| operation.access_profiles.len())
        .sum::<usize>();
    if access_profile_executors > MAXIMUM_ACCESS_PROFILE_EXECUTORS_PER_REGISTRY {
        compiler.error(
            "access_profile.registry_bound_exceeded",
            "resources",
            "the compiled access profile count exceeds the Registry runtime ceiling",
        );
    }
    compiler.validate_observed_source_closure();

    if compiler.report.has_errors() {
        return Err(compiler.report);
    }

    let contract_revision = revision(contract).map_err(|()| CompileReport {
        diagnostics: vec![Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "contract.canonicalization_failed".into(),
            location: "registry.yaml".into(),
            message: "the governed contract could not be canonicalized".into(),
        }],
    })?;

    let registry = CompiledRegistry {
        contract_revision,
        contract_id: contract.metadata.id.clone(),
        contract_version: contract.metadata.version.clone(),
        registry_identifier: contract.registry.registry_identifier.clone(),
        registry_name: contract.registry.name.clone(),
        authority_identifier: contract.registry.authority.identifier.clone(),
        authority_name: contract.registry.authority.name.clone(),
        operator_identifier: contract
            .registry
            .operator
            .as_ref()
            .map(|operator| operator.identifier.clone()),
        operator_name: contract
            .registry
            .operator
            .as_ref()
            .map(|operator| operator.name.clone()),
        authoritative_scope: contract.registry.authoritative_scope.clone(),
        base_uri: contract.registry.base_uri.clone(),
        identifier_lifecycle_policy_ref: contract.registry.identifier_lifecycle_policy_ref.clone(),
        alignment_targets: contract.registry.alignment_targets.clone(),
        controller_identifier: contract.governance.controller.clone(),
        publisher_identifier: contract.governance.publisher.clone(),
        audit_owner_identifier: contract.governance.audit_owner.clone(),
        publication: contract.publication.as_ref().map(|publication| {
            crate::model::CompiledPublication {
                jurisdictions: publication.jurisdictions.clone(),
            }
        }),
        local_vocabulary: contract.semantics.local_vocabulary.clone(),
        semantic_alignments: contract.semantics.alignments.clone(),
        governed_files: Vec::new(),
        classification_review: None,
        codelists: Vec::new(),
        sources: contract
            .sources
            .iter()
            .map(|(id, source)| CompiledSource {
                id: id.to_owned(),
                profile: source.profile,
                expected_schema_fingerprint: source.expected_schema_fingerprint.clone(),
                observed_schema: observed.iter().find(|schema| schema.source == id).cloned(),
            })
            .collect(),
        resources,
        statistical_datasets,
        metadata_visibility: CompiledMetadataVisibility {
            service: contract.metadata_visibility.service,
            resources: contract.metadata_visibility.resources,
            statistical_datasets: contract.metadata_visibility.statistical_datasets,
            semantics: contract.metadata_visibility.semantics,
            classifications: contract.metadata_visibility.classifications,
            processing: contract.metadata_visibility.processing,
        },
    };
    if let Some(publication) = &registry.publication {
        if crate::artifacts::discovery_description(&registry, &publication.jurisdictions).is_err() {
            return Err(CompileReport {
                diagnostics: vec![Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "publication.description_bound_exceeded".into(),
                    location: "publication".into(),
                    message: "the complete public Discovery description exceeds the shared profile bounds"
                        .into(),
                }],
            });
        }
    }
    Ok(registry)
}

/// Compile the complete governed file closure. Production packaging and
/// startup use this entry point so a sidecar or codelist change necessarily
/// changes the active contract revision.
pub fn compile_contract_with_governed_files(
    contract: &RegistryContract,
    observed: &[ObservedSourceSchema],
    profile: CompileProfile,
    files: &GovernedFileSet,
) -> Result<CompiledRegistry, CompileReport> {
    let mut registry = compile_contract(contract, observed, profile)?;
    let (codelists, file_digests, classification_review, mut report) =
        validate_governed_files(contract, files, profile, &registry);
    validate_governed_lookup_body_bounds(contract, &codelists, &mut report);
    if report.has_errors() {
        return Err(report);
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct RevisionInput<'a> {
        contract: &'a RegistryContract,
        governed_files: &'a BTreeMap<String, String>,
    }
    registry.contract_revision = revision(&RevisionInput {
        contract,
        governed_files: &file_digests,
    })
    .map_err(|()| CompileReport {
        diagnostics: vec![Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "contract.canonicalization_failed".into(),
            location: "registry.yaml".into(),
            message: "the governed closure could not be canonicalized".into(),
        }],
    })?;
    registry.codelists = codelists;
    registry.classification_review = classification_review;
    registry.governed_files = file_digests
        .into_iter()
        .map(|(path, sha256)| CompiledGovernedFile {
            roles: governed_file_roles(contract, registry.classification_review.as_ref(), &path),
            path,
            sha256,
        })
        .collect();
    Ok(registry)
}

fn governed_file_roles(
    contract: &RegistryContract,
    review: Option<&CompiledClassificationReview>,
    path: &str,
) -> Vec<String> {
    let mut roles = Vec::new();
    if contract.registry.identifier_lifecycle_policy_ref == path {
        roles.push("identifier-lifecycle-policy".into());
    }
    if contract.classifications.provenance_ref == path {
        roles.push("classification-provenance".into());
    }
    if review.is_some_and(|review| review.rationale_ref == path) {
        roles.push("classification-review-rationale".into());
    }
    if review
        .and_then(|review| review.generated_identification.as_ref())
        .is_some_and(|binding| binding.report_ref == path)
    {
        roles.push("identification-report".into());
    }
    for alignment in &contract.semantics.alignments {
        if alignment.profile_ref == path {
            roles.push(format!("semantic-alignment:{}", alignment.id));
        }
    }
    for resource in &contract.resources {
        if resource.record_context.lifecycle_state.codelist == path {
            roles.push(format!("codelist:{}:lifecycle-state", resource.id));
        }
        for (property, definition) in resource.properties.iter() {
            if definition
                .scalar_binding()
                .and_then(|binding| binding.codelist.as_deref())
                == Some(path)
            {
                roles.push(format!("codelist:{}:{property}", resource.id));
            }
        }
        for lookup in &resource.operations.lookups {
            for (selector, definition) in lookup.request_body.selectors.iter() {
                if definition.codelist.as_deref() == Some(path) {
                    roles.push(format!(
                        "codelist:{}:lookup:{}:{selector}",
                        resource.id, lookup.id
                    ));
                }
            }
        }
        for processing in &resource.processing_descriptions {
            if processing.legal_basis_ref == path {
                roles.push(format!(
                    "processing:{}:{}:legal-basis",
                    resource.id, processing.id
                ));
            }
            if processing.dpv_profile_ref == path {
                roles.push(format!(
                    "processing:{}:{}:dpv-profile",
                    resource.id, processing.id
                ));
            }
        }
    }
    for dataset in &contract.statistical_datasets {
        for (dimension_id, dimension) in dataset.dimensions.iter() {
            if dimension.vocabulary.as_deref() == Some(path) {
                roles.push(format!(
                    "statistical-vocabulary:{}:{dimension_id}",
                    dataset.id
                ));
            }
        }
        for (attribute_id, attribute) in dataset.attributes.iter() {
            if attribute.vocabulary.as_deref() == Some(path) {
                roles.push(format!(
                    "statistical-vocabulary:{}:{attribute_id}",
                    dataset.id
                ));
            }
        }
        for processing in &dataset.processing_descriptions {
            if processing.legal_basis_ref == path {
                roles.push(format!(
                    "processing:{}:{}:legal-basis",
                    dataset.id, processing.id
                ));
            }
            if processing.dpv_profile_ref == path {
                roles.push(format!(
                    "processing:{}:{}:dpv-profile",
                    dataset.id, processing.id
                ));
            }
        }
    }
    roles.sort();
    roles.dedup();
    roles
}

/// Compatibility entry point for binaries that already hold the strict typed
/// contract. All semantics remain in [`compile_contract`].
pub fn compile(
    contract: &RegistryContract,
    observed: &[ObservedSourceSchema],
    profile: CompileProfile,
) -> Result<CompiledRegistry, CompileError> {
    compile_contract(contract, observed, profile)
}

pub type CompileError = CompileReport;

/// Derive an explicitly unreviewed starter from a schema-only observation.
/// This output is an authoring aid and is intentionally not a valid production
/// contract until a publisher reviews semantics, bindings, and classification.
pub fn derive_starter(schema: &ObservedSourceSchema, view: &str) -> Option<StarterContract> {
    let observed_view = schema
        .views
        .iter()
        .find(|candidate| candidate.name == view)?;
    Some(StarterContract {
        source: schema.source.clone(),
        view: view.to_owned(),
        expected_schema_fingerprint: schema.fingerprint.clone(),
        columns: observed_view
            .columns
            .iter()
            .map(|column| StarterColumn {
                source_column: column.name.clone(),
                suggested_property: to_camel_case(&column.name),
                suggested_type: suggested_data_type(&column.declared_type),
                classification_status: ReviewStatus::Suggested,
            })
            .collect(),
    })
}

struct Compiler<'a> {
    contract: &'a RegistryContract,
    observed: HashMap<&'a str, &'a ObservedSourceSchema>,
    profile: CompileProfile,
    report: CompileReport,
    scopes: HashSet<String>,
    publication_ids: HashSet<String>,
    statistical_endpoint_ids: HashSet<(String, String, String)>,
    statistical_structure_ids: HashSet<(String, String, String)>,
    used_observed_sources: HashSet<&'a str>,
}

impl<'a> Compiler<'a> {
    fn new(
        contract: &'a RegistryContract,
        observed: &'a [ObservedSourceSchema],
        profile: CompileProfile,
    ) -> Self {
        let mut by_name = HashMap::new();
        let mut report = CompileReport {
            diagnostics: Vec::new(),
        };
        for item in observed {
            if by_name.insert(item.source.as_str(), item).is_some() {
                report.diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "source.observation_duplicate".into(),
                    location: "observed-schema".into(),
                    message: "a source has more than one observed schema".into(),
                });
            }
        }
        Self {
            contract,
            observed: by_name,
            profile,
            report,
            scopes: HashSet::new(),
            publication_ids: HashSet::new(),
            statistical_endpoint_ids: HashSet::new(),
            statistical_structure_ids: HashSet::new(),
            used_observed_sources: HashSet::new(),
        }
    }

    fn validate_top_level(&mut self) {
        if self.contract.api_version != API_VERSION {
            self.error(
                "contract.api_version_unsupported",
                "apiVersion",
                "the contract API version is unsupported",
            );
        }
        if self.contract.kind != "RegistryContract" {
            self.error(
                "contract.kind_invalid",
                "kind",
                "the governed document kind must be RegistryContract",
            );
        }
        require_nonempty(
            &mut self.report,
            &self.contract.metadata.id,
            "contract.id_empty",
            "metadata.id",
        );
        if !valid_kebab_identifier(&self.contract.metadata.id) {
            self.error(
                "contract.id_invalid",
                "metadata.id",
                "the contract identifier must be URL-safe kebab case",
            );
        }
        for (value, code, location) in [
            (
                self.contract.metadata.version.as_str(),
                "contract.version_empty",
                "metadata.version",
            ),
            (
                self.contract.metadata.title.as_str(),
                "contract.title_empty",
                "metadata.title",
            ),
            (
                self.contract.registry.name.as_str(),
                "registry.name_empty",
                "registry.name",
            ),
            (
                self.contract.registry.authoritative_scope.as_str(),
                "registry.scope_empty",
                "registry.authoritativeScope",
            ),
            (
                self.contract.registry.authority.identifier.as_str(),
                "registry.authority_identifier_empty",
                "registry.authority.identifier",
            ),
            (
                self.contract.registry.authority.name.as_str(),
                "registry.authority_name_empty",
                "registry.authority.name",
            ),
        ] {
            require_nonempty(&mut self.report, value, code, location);
        }
        if let Some(operator) = &self.contract.registry.operator {
            require_nonempty(
                &mut self.report,
                &operator.identifier,
                "registry.operator_identifier_empty",
                "registry.operator.identifier",
            );
            require_nonempty(
                &mut self.report,
                &operator.name,
                "registry.operator_name_empty",
                "registry.operator.name",
            );
        }
        require_nonempty(
            &mut self.report,
            &self.contract.registry.registry_identifier,
            "registry.identifier_empty",
            "registry.registryIdentifier",
        );
        if !valid_global_identifier(&self.contract.registry.registry_identifier) {
            self.error(
                "registry.identifier_invalid",
                "registry.registryIdentifier",
                "the Registry identifier must be a globally scoped URI",
            );
        }
        if !valid_artifact_base_url(&self.contract.registry.base_uri) {
            self.error(
                "registry.base_uri_invalid",
                "registry.baseUri",
                "the Registry base URI must be an absolute HTTP or HTTPS URL without credentials, a query, or a fragment",
            );
        }
        if !valid_turtle_iri(&self.contract.semantics.local_vocabulary) {
            self.error(
                "semantics.local_vocabulary_invalid",
                "semantics.localVocabulary",
                "the local vocabulary must be an absolute HTTP or HTTPS IRI safe for Turtle serialization",
            );
        }
        if !valid_relative_reference(&self.contract.registry.identifier_lifecycle_policy_ref) {
            self.error(
                "registry.identifier_lifecycle_ref_invalid",
                "registry.identifierLifecyclePolicyRef",
                "the identifier lifecycle policy must be a contained relative file reference",
            );
        }
        if self.contract.registry.alignment_targets.is_empty() {
            self.error(
                "registry.alignment_targets_empty",
                "registry.alignmentTargets",
                "at least one directional alignment target is required",
            );
        }
        let mut target_names = HashSet::new();
        for (index, target) in self.contract.registry.alignment_targets.iter().enumerate() {
            let location = format!("registry.alignmentTargets[{index}]");
            if !target_names.insert(target.name.as_str()) {
                self.error(
                    "registry.alignment_target_duplicate",
                    &location,
                    "alignment target names must be unique",
                );
            }
            if target.name.trim().is_empty()
                || target.version.trim().is_empty()
                || target.status != "directional"
            {
                self.error(
                    "registry.alignment_target_invalid",
                    &location,
                    "alignment targets require a name, version, and directional status",
                );
            }
        }
        for (value, location) in [
            (
                &self.contract.governance.controller,
                "governance.controller",
            ),
            (&self.contract.governance.publisher, "governance.publisher"),
            (
                &self.contract.governance.audit_owner,
                "governance.auditOwner",
            ),
        ] {
            if value.trim().is_empty() {
                self.error(
                    "governance.identifier_empty",
                    location,
                    "governance role identifiers must be non-empty",
                );
            }
        }
        if let Some(publication) = &self.contract.publication {
            if publication.jurisdictions.is_empty()
                || publication.jurisdictions.len() > MAXIMUM_PUBLICATION_JURISDICTIONS
                || publication
                    .jurisdictions
                    .iter()
                    .any(|value| !is_valid_public_text(value) || !valid_global_identifier(value))
                || publication
                    .jurisdictions
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                self.error(
                    "publication.jurisdictions_invalid",
                    "publication.jurisdictions",
                    "published jurisdictions must contain between 1 and 128 sorted, duplicate-free globally scoped URIs",
                );
            }
            for (value, code, location, message) in [
                (
                    self.contract.registry.registry_identifier.as_str(),
                    "publication.service_identifier_invalid",
                    "registry.registryIdentifier",
                    "the published service identifier must satisfy the shared Registry Discovery profile",
                ),
                (
                    self.contract.registry.name.as_str(),
                    "publication.title_invalid",
                    "registry.name",
                    "the published title must satisfy the shared Registry Discovery profile",
                ),
                (
                    self.contract.registry.authoritative_scope.as_str(),
                    "publication.description_invalid",
                    "registry.authoritativeScope",
                    "the published description must satisfy the shared Registry Discovery profile",
                ),
            ] {
                if !is_valid_public_text(value) {
                    self.error(code, location, message);
                }
            }
            if !is_valid_endpoint_url(&self.contract.registry.base_uri, true) {
                self.error(
                    "publication.endpoint_invalid",
                    "registry.baseUri",
                    "the published endpoint must satisfy the shared Registry Discovery profile",
                );
            }
            for (value, location) in [
                (
                    self.contract.registry.authority.identifier.as_str(),
                    "registry.authority.identifier",
                ),
                (
                    self.contract.governance.publisher.as_str(),
                    "governance.publisher",
                ),
            ] {
                if !is_valid_public_text(value) || !valid_global_identifier(value) {
                    self.error(
                        "publication.role_identifier_invalid",
                        location,
                        "a role published for discovery must be a globally scoped URI",
                    );
                }
            }
            if let Some(operator) = &self.contract.registry.operator {
                if !is_valid_public_text(&operator.identifier)
                    || !valid_global_identifier(&operator.identifier)
                {
                    self.error(
                        "publication.role_identifier_invalid",
                        "registry.operator.identifier",
                        "a role published for discovery must be a globally scoped URI",
                    );
                }
            }
        }
        if !valid_relative_reference(&self.contract.classifications.provenance_ref) {
            self.error(
                "classification.provenance_ref_invalid",
                "classifications.provenanceRef",
                "classification provenance must be a contained relative file reference",
            );
        }
        for (scheme, location) in [
            (
                &self.contract.classifications.privacy,
                "classifications.privacy",
            ),
            (
                &self.contract.classifications.institutional,
                "classifications.institutional",
            ),
            (
                &self.contract.classifications.handling,
                "classifications.handling",
            ),
        ] {
            if scheme.scheme.trim().is_empty() || scheme.version.trim().is_empty() {
                self.error(
                    "classification.scheme_invalid",
                    location,
                    "classification schemes require a non-empty identifier and version",
                );
            }
        }
        let mut alignment_ids = HashSet::new();
        for (index, alignment) in self.contract.semantics.alignments.iter().enumerate() {
            let location = format!("semantics.alignments[{index}]");
            if !alignment_ids.insert(alignment.id.as_str()) {
                self.error(
                    "semantics.alignment_duplicate",
                    &location,
                    "semantic alignment identifiers must be unique",
                );
            }
            if alignment.id.trim().is_empty()
                || alignment.version.trim().is_empty()
                || !valid_relative_reference(&alignment.profile_ref)
                || !valid_sha256(&alignment.digest)
                || !alignment.relation_required
            {
                self.error(
                    "semantics.alignment_invalid",
                    &location,
                    "semantic alignments must be versioned, digest-pinned contained files with explicit relations",
                );
            }
        }
        if self.contract.sources.is_empty() {
            self.error(
                "source.none",
                "sources",
                "at least one reviewed SQLite source is required",
            );
        }
        if self.contract.resources.is_empty() && self.contract.statistical_datasets.is_empty() {
            self.error(
                "publication.none",
                "resources",
                "at least one resource or statistical dataset is required",
            );
        }
        if self.contract.resources.len() > MAXIMUM_RESOURCES {
            self.error(
                "resource.bound_exceeded",
                "resources",
                "the governed resource count exceeds the product ceiling",
            );
        }
        if self.contract.statistical_datasets.len() > MAXIMUM_STATISTICAL_DATASETS {
            self.error(
                "statistics.dataset_bound_exceeded",
                "statisticalDatasets",
                "the governed statistical-dataset count exceeds the product ceiling",
            );
        }
        for (source_id, source) in self.contract.sources.iter() {
            let location = format!("sources.{source_id}");
            if !valid_kebab_identifier(source_id) {
                self.error(
                    "source.id_invalid",
                    &location,
                    "source identifiers must be URL-safe kebab case",
                );
            }
            if source.kind != "sqlite" {
                self.error(
                    "source.kind_unsupported",
                    &format!("{location}.kind"),
                    "Version one supports only SQLite sources",
                );
            }
            if !valid_sha256(&source.expected_schema_fingerprint) {
                self.error(
                    "source.schema_fingerprint_invalid",
                    &format!("{location}.expectedSchemaFingerprint"),
                    "the expected schema fingerprint must be a SHA-256 digest",
                );
            }
            match self.observed.get(source_id) {
                Some(schema) => {
                    self.used_observed_sources.insert(source_id);
                    validate_observed_schema(&mut self.report, schema, &location);
                    if schema.fingerprint != source.expected_schema_fingerprint {
                        self.error(
                            "source.schema_fingerprint_mismatch",
                            &location,
                            "the observed schema does not match the governed fingerprint",
                        );
                    }
                }
                None if self.profile == CompileProfile::Production => self.error(
                    "source.schema_observation_missing",
                    &location,
                    "production compilation requires the observed source schema",
                ),
                None => self.warning(
                    "source.schema_observation_missing",
                    &location,
                    "source bindings cannot be fully checked without an observed schema",
                ),
            }
        }
        if self.contract.metadata_visibility.service != crate::contract::Visibility::Public {
            self.error(
                "metadata.service_not_public",
                "metadataVisibility.service",
                "Registry service identity is always public",
            );
        }
        if !self.contract.statistical_datasets.is_empty() {
            match self.contract.metadata_visibility.statistical_datasets {
                None => self.error(
                    "metadata.statistical_datasets_missing",
                    "metadataVisibility.statisticalDatasets",
                    "statistical dataset visibility must be explicit when statistical datasets exist",
                ),
                Some(crate::contract::Visibility::OperatorOnly) => self.error(
                    "metadata.statistical_datasets_unresolvable",
                    "metadataVisibility.statisticalDatasets",
                    "successful statistical data responses require resolvable statistical structure metadata",
                ),
                Some(
                    crate::contract::Visibility::Public
                    | crate::contract::Visibility::OperationBound,
                ) => {}
            }
        }
    }

    fn compile_resources(&mut self) -> Vec<CompiledResource> {
        let mut compiled = Vec::with_capacity(self.contract.resources.len());
        for (index, resource) in self.contract.resources.iter().enumerate() {
            let root = format!("resources[{index}]");
            if resource.properties.len() > MAXIMUM_PROPERTIES_PER_RESOURCE {
                self.error(
                    "property.bound_exceeded",
                    &format!("{root}.properties"),
                    "the governed property count exceeds the per-resource product ceiling",
                );
            }
            if resource.disclosure_profiles.len() > MAXIMUM_DISCLOSURE_PROFILES_PER_RESOURCE {
                self.error(
                    "disclosure.bound_exceeded",
                    &format!("{root}.disclosureProfiles"),
                    "the governed disclosure-profile count exceeds the per-resource product ceiling",
                );
            }
            if !self.publication_ids.insert(resource.id.clone()) {
                self.error(
                    "resource.id_duplicate",
                    &format!("{root}.id"),
                    "resource identifiers must be unique",
                );
            }
            if !valid_route_identifier(&resource.id) {
                self.error(
                    "resource.id_invalid",
                    &format!("{root}.id"),
                    "a resource identifier must be URL-safe kebab case within the runtime route ceiling",
                );
            }
            if resource.title.trim().is_empty() || resource.description.trim().is_empty() {
                self.error(
                    "resource.documentation_empty",
                    &root,
                    "resources require a non-empty title and description",
                );
            }
            if !valid_sql_identifier(&resource.source.view) {
                self.error(
                    "resource.view_invalid",
                    &format!("{root}.source.view"),
                    "reviewed SQLite view names must be simple identifiers",
                );
            }
            let Some(source) = self.contract.sources.get(&resource.source.source) else {
                self.error(
                    "resource.source_unknown",
                    &format!("{root}.source.source"),
                    "the resource names no governed source",
                );
                continue;
            };
            let observed_view =
                self.observed
                    .get(resource.source.source.as_str())
                    .and_then(|schema| {
                        schema
                            .views
                            .iter()
                            .find(|view| view.name == resource.source.view)
                    });
            let observed_columns = observed_view.map(|view| {
                view.columns
                    .iter()
                    .map(|column| column.name.as_str())
                    .collect::<BTreeSet<_>>()
            });
            if self.observed.contains_key(resource.source.source.as_str())
                && observed_columns.is_none()
            {
                self.error(
                    "resource.view_unknown",
                    &format!("{root}.source.view"),
                    "the reviewed view is absent from the observed source schema",
                );
            }

            let defaults =
                effective_classification(self.contract, &resource.classification_defaults, None);
            if defaults.is_none() {
                self.error(
                    "classification.defaults_incomplete",
                    &format!("{root}.classificationDefaults"),
                    "resource classification defaults must resolve every dimension",
                );
            }

            let mut property_names = HashSet::new();
            let mut property_columns: HashMap<&str, Vec<(&str, EffectiveClassification, bool)>> =
                HashMap::new();
            let mut point_property_names = Vec::new();
            let mut properties = Vec::with_capacity(resource.properties.len());
            for (name, property) in resource.properties.iter() {
                let location = format!("{root}.properties.{name}");
                if !valid_camel_identifier(name) {
                    self.error(
                        "property.name_invalid",
                        &location,
                        "property keys must be URL-safe camelCase",
                    );
                }
                if property.label.trim().is_empty() || property.description.trim().is_empty() {
                    self.error(
                        "property.documentation_empty",
                        &location,
                        "published properties require a non-empty label and description",
                    );
                }
                if !property_names.insert(name) {
                    self.error(
                        "property.name_duplicate",
                        &location,
                        "property keys must be unique",
                    );
                }
                let classification = effective_classification(
                    self.contract,
                    &resource.classification_defaults,
                    Some(&property.classification),
                );
                let Some(classification) = classification else {
                    self.error(
                        "classification.property_incomplete",
                        &format!("{location}.classification"),
                        "the property classification is incomplete after defaults",
                    );
                    continue;
                };
                if classification.privacy.trim().is_empty()
                    || classification.institutional.trim().is_empty()
                {
                    self.error(
                        "classification.property_empty",
                        &format!("{location}.classification"),
                        "effective privacy and institutional classifications must be non-empty",
                    );
                }
                self.validate_review_status(
                    &classification,
                    &format!("{location}.classification"),
                    None,
                );
                let semantic_iri = match expand_local_term(
                    &self.contract.semantics.local_vocabulary,
                    &property.semantic_term,
                ) {
                    Some(term) => term,
                    None => {
                        self.error(
                            "semantics.term_invalid",
                            &format!("{location}.semanticTerm"),
                            "a semantic term must be local:Name or an absolute HTTP or HTTPS IRI",
                        );
                        property.semantic_term.clone()
                    }
                };
                let binding = match &property.binding {
                    PropertyBindingDefinition::Scalar(binding) => {
                        if !valid_sql_identifier(&binding.source_column) {
                            self.error(
                                "property.column_invalid",
                                &format!("{location}.sourceColumn"),
                                "property columns must be simple SQLite identifiers",
                            );
                        }
                        if !column_exists(observed_columns.as_ref(), &binding.source_column) {
                            self.error(
                                "property.column_unknown",
                                &format!("{location}.sourceColumn"),
                                "the property source column is absent from the reviewed view",
                            );
                        }
                        validate_codelist(
                            &mut self.report,
                            binding.data_type,
                            binding.codelist.as_deref(),
                            &location,
                        );
                        if let Some(codelist) = binding.codelist.as_deref() {
                            if !valid_relative_reference(codelist) {
                                self.error(
                                    "datatype.codelist_ref_invalid",
                                    &format!("{location}.codelist"),
                                    "codelists must be contained relative file references",
                                );
                            }
                        }
                        let transform = self.compile_transform(
                            binding.transform.as_ref(),
                            binding.data_type,
                            &location,
                        );
                        if let Some(observed) =
                            observed_column(observed_view, &binding.source_column)
                        {
                            let source_type =
                                transform_source_type(transform.as_ref(), binding.data_type);
                            if !compatible_declared_type(source_type, &observed.declared_type) {
                                self.error(
                                    "property.declared_type_incompatible",
                                    &format!("{location}.type"),
                                    "the published datatype is incompatible with the reviewed SQLite declaration",
                                );
                            }
                        }
                        property_columns
                            .entry(binding.source_column.as_str())
                            .or_default()
                            .push((name, classification.clone(), transform.is_some()));
                        CompiledPropertyBinding::Scalar(CompiledScalarPropertyBinding {
                            source_column: binding.source_column.clone(),
                            transform,
                            data_type: binding.data_type,
                            codelist: binding.codelist.clone(),
                        })
                    }
                    PropertyBindingDefinition::Point(binding) => {
                        point_property_names.push(name);
                        if binding.crs != CRS84 {
                            self.error(
                                "geometry.crs_unsupported",
                                &format!("{location}.crs"),
                                "Point properties require the exact OGC CRS84 identifier",
                            );
                        }
                        let longitude = &binding.source.longitude_column;
                        let latitude = &binding.source.latitude_column;
                        for (column, field) in
                            [(longitude, "longitudeColumn"), (latitude, "latitudeColumn")]
                        {
                            let column_location = format!("{location}.source.{field}");
                            if !valid_sql_identifier(column) {
                                self.error(
                                    "geometry.carrier_column_invalid",
                                    &column_location,
                                    "Point carrier columns must be simple SQLite identifiers",
                                );
                            }
                            if !column_exists(observed_columns.as_ref(), column) {
                                self.error(
                                    "geometry.carrier_column_unknown",
                                    &column_location,
                                    "the Point carrier column is absent from the reviewed view",
                                );
                            }
                            if observed_column(observed_view, column).is_some_and(|observed| {
                                !has_sqlite_numeric_affinity(&observed.declared_type)
                            }) {
                                self.error(
                                    "geometry.carrier_declared_type_incompatible",
                                    &column_location,
                                    "Point carriers require reviewed SQLite declarations with INTEGER, REAL, or NUMERIC affinity",
                                );
                            }
                        }
                        if longitude == latitude {
                            self.error(
                                "geometry.carrier_columns_duplicate",
                                &format!("{location}.source.latitudeColumn"),
                                "Point longitude and latitude require distinct carrier columns",
                            );
                        }
                        for column in [longitude, latitude] {
                            property_columns.entry(column.as_str()).or_default().push((
                                name,
                                classification.clone(),
                                false,
                            ));
                        }
                        CompiledPropertyBinding::Point(CompiledPointPropertyBinding {
                            crs: binding.crs.clone(),
                            longitude_column: longitude.clone(),
                            latitude_column: latitude.clone(),
                        })
                    }
                };
                properties.push(CompiledProperty {
                    name: name.to_owned(),
                    label: property.label.clone(),
                    description: property.description.clone(),
                    source_required: property.source_required,
                    semantic_iri,
                    classification,
                    binding,
                });
            }

            match point_property_names.as_slice() {
                [] => {
                    if resource.primary_geometry.is_some() {
                        self.error(
                            "geometry.primary_without_point",
                            &format!("{root}.primaryGeometry"),
                            "primaryGeometry requires exactly one Point property",
                        );
                    }
                }
                [point_name] => match resource.primary_geometry.as_deref() {
                    None => self.error(
                        "geometry.primary_required",
                        &format!("{root}.primaryGeometry"),
                        "a resource with a Point property must name it as primaryGeometry",
                    ),
                    Some(primary) if primary != *point_name => self.error(
                        "geometry.primary_invalid",
                        &format!("{root}.primaryGeometry"),
                        "primaryGeometry must name the resource's one Point property",
                    ),
                    Some(_) => {}
                },
                _ => self.error(
                    "geometry.point_count_exceeded",
                    &format!("{root}.properties"),
                    "a resource may define exactly one Point property",
                ),
            }

            let mut disclosures = Vec::with_capacity(resource.disclosure_profiles.len());
            let mut disclosure_names = HashSet::new();
            for (name, disclosure) in resource.disclosure_profiles.iter() {
                let location = format!("{root}.disclosureProfiles.{name}");
                if !valid_kebab_identifier(name) {
                    self.error(
                        "disclosure.id_invalid",
                        &location,
                        "disclosure profile identifiers must be URL-safe kebab case",
                    );
                }
                if !disclosure_names.insert(name) {
                    self.error(
                        "disclosure.id_duplicate",
                        &location,
                        "disclosure profile identifiers must be unique",
                    );
                }
                let mut selected = HashSet::new();
                let mut maximum_handling = Handling::Public;
                if disclosure.properties.is_empty() {
                    self.error(
                        "disclosure.properties_empty",
                        &location,
                        "a disclosure profile must contain at least one property",
                    );
                }
                for property_name in &disclosure.properties {
                    if !selected.insert(property_name.as_str()) {
                        self.error(
                            "disclosure.property_duplicate",
                            &location,
                            "a disclosure profile cannot repeat a property",
                        );
                    }
                    match properties.iter().find(|item| item.name == *property_name) {
                        Some(property) => {
                            maximum_handling =
                                maximum_handling.max(property.classification.handling);
                        }
                        None => self.error(
                            "disclosure.property_unknown",
                            &location,
                            "a disclosure profile names no published property",
                        ),
                    }
                }
                disclosures.push(CompiledDisclosureProfile {
                    id: name.to_owned(),
                    properties: disclosure.properties.clone(),
                    maximum_handling,
                });
            }

            let core = [
                (
                    resource
                        .record_context
                        .record_identifier
                        .source_column
                        .as_str(),
                    ColumnUse::RecordIdentifier,
                ),
                (
                    resource
                        .record_context
                        .revision_identifier
                        .source_column
                        .as_str(),
                    ColumnUse::RevisionIdentifier,
                ),
                (
                    resource
                        .record_context
                        .lifecycle_state
                        .source_column
                        .as_str(),
                    ColumnUse::LifecycleState,
                ),
                (
                    resource.record_context.recorded_at.source_column.as_str(),
                    ColumnUse::RecordedAt,
                ),
            ];
            if !valid_relative_reference(&resource.record_context.lifecycle_state.codelist) {
                self.error(
                    "record.lifecycle_codelist_ref_invalid",
                    &format!("{root}.recordContext.lifecycleState.codelist"),
                    "the lifecycle codelist must be a contained relative file reference",
                );
            }
            let mut core_names = HashSet::new();
            for (column, _) in &core {
                if !valid_sql_identifier(column) {
                    self.error(
                        "record.column_invalid",
                        &format!("{root}.recordContext"),
                        "Registry Core columns must be simple SQLite identifiers",
                    );
                }
                if !core_names.insert(*column) {
                    self.error(
                        "record.column_duplicate",
                        &format!("{root}.recordContext"),
                        "Registry Core fields must bind distinct source columns",
                    );
                }
                if !column_exists(observed_columns.as_ref(), column) {
                    self.error(
                        "record.column_unknown",
                        &format!("{root}.recordContext"),
                        "a Registry Core source column is absent from the reviewed view",
                    );
                }
            }
            for (column, field) in [
                (
                    resource
                        .record_context
                        .record_identifier
                        .source_column
                        .as_str(),
                    "recordIdentifier",
                ),
                (
                    resource
                        .record_context
                        .revision_identifier
                        .source_column
                        .as_str(),
                    "revisionIdentifier",
                ),
                (
                    resource
                        .record_context
                        .lifecycle_state
                        .source_column
                        .as_str(),
                    "lifecycleState",
                ),
                (
                    resource.record_context.recorded_at.source_column.as_str(),
                    "recordedAt",
                ),
            ] {
                if observed_column(observed_view, column)
                    .is_some_and(|observed| !has_sqlite_text_affinity(&observed.declared_type))
                {
                    self.error(
                        "record.declared_type_incompatible",
                        &format!("{root}.recordContext.{field}.sourceColumn"),
                        "Registry Core columns require a reviewed SQLite declaration with TEXT affinity",
                    );
                }
            }

            let mut operations = Vec::new();
            if let Some(list) = &resource.operations.list {
                if source.profile == SourceProfile::LiveReadOnly {
                    self.error(
                        "operation.list_live_forbidden",
                        &format!("{root}.operations.list"),
                        "Version one live sources cannot compile a list operation",
                    );
                }
                let operation = self.compile_list(
                    resource,
                    &properties,
                    &disclosures,
                    observed_view,
                    observed_columns.as_ref(),
                    &root,
                    list,
                );
                if let Some(operation) = operation {
                    operations.push(operation);
                }
            }
            if let Some(read) = &resource.operations.read {
                if let Some(operation) = self.compile_simple_operation(
                    resource,
                    &properties,
                    &disclosures,
                    observed_view,
                    observed_columns.as_ref(),
                    &root,
                    "read",
                    OperationKind::Read,
                    &read.default_access_profile,
                    &read.access_profiles,
                ) {
                    operations.push(operation);
                }
            }
            let mut lookup_ids = HashSet::new();
            for (lookup_index, lookup) in resource.operations.lookups.iter().enumerate() {
                let location = format!("{root}.operations.lookups[{lookup_index}]");
                if !lookup_ids.insert(lookup.id.as_str()) {
                    self.error(
                        "operation.lookup_id_duplicate",
                        &format!("{location}.id"),
                        "lookup identifiers must be unique within a resource",
                    );
                }
                if !valid_route_identifier(&lookup.id) {
                    self.error(
                        "operation.lookup_id_invalid",
                        &format!("{location}.id"),
                        "lookup identifiers must be URL-safe kebab case within the runtime route ceiling",
                    );
                }
                if lookup.request_body.maximum_bytes == 0
                    || lookup.request_body.maximum_bytes > MAXIMUM_LOOKUP_REQUEST_BODY_BYTES
                {
                    self.error(
                        "lookup.body_bound_invalid",
                        &format!("{location}.requestBody.maximumBytes"),
                        "lookup request bodies require a positive byte bound within the product ceiling",
                    );
                }
                if lookup.request_body.selectors.is_empty()
                    || lookup.request_body.selectors.len() > MAXIMUM_LOOKUP_SELECTORS
                {
                    self.error(
                        "lookup.selectors_empty",
                        &format!("{location}.requestBody.selectors"),
                        "an exact lookup requires a bounded non-empty selector set",
                    );
                }
                let mut selectors = Vec::with_capacity(lookup.request_body.selectors.len());
                for (selector_name, selector) in lookup.request_body.selectors.iter() {
                    let selector_location =
                        format!("{location}.requestBody.selectors.{selector_name}");
                    if !valid_camel_identifier(selector_name) {
                        self.error(
                            "lookup.selector_name_invalid",
                            &selector_location,
                            "selector keys must be URL-safe camelCase",
                        );
                    }
                    if !column_exists(observed_columns.as_ref(), &selector.source_column) {
                        self.error(
                            "lookup.selector_column_unknown",
                            &format!("{selector_location}.sourceColumn"),
                            "a selector source column is absent from the reviewed view",
                        );
                    }
                    if !valid_sql_identifier(&selector.source_column) {
                        self.error(
                            "lookup.selector_column_invalid",
                            &format!("{selector_location}.sourceColumn"),
                            "selector columns must be simple SQLite identifiers",
                        );
                    }
                    validate_codelist(
                        &mut self.report,
                        selector.data_type,
                        selector.codelist.as_deref(),
                        &selector_location,
                    );
                    if observed_column(observed_view, &selector.source_column).is_some_and(
                        |observed| {
                            !compatible_declared_type(selector.data_type, &observed.declared_type)
                        },
                    ) {
                        self.error(
                            "lookup.selector_declared_type_incompatible",
                            &format!("{selector_location}.type"),
                            "the selector datatype is incompatible with the reviewed SQLite declaration",
                        );
                    }
                    let bounds_invalid = match selector.data_type {
                        DataType::String => {
                            selector.maximum_bytes.is_none()
                                || selector.maximum_bytes == Some(0)
                                || selector
                                    .maximum_bytes
                                    .is_some_and(|maximum| maximum > MAXIMUM_SELECTOR_BYTES)
                                || selector.minimum_bytes == Some(0)
                                || selector
                                    .minimum_bytes
                                    .zip(selector.maximum_bytes)
                                    .is_some_and(|(minimum, maximum)| minimum > maximum)
                        }
                        _ => selector.minimum_bytes.is_some() || selector.maximum_bytes.is_some(),
                    };
                    if bounds_invalid {
                        self.error(
                            "lookup.selector_bounds_invalid",
                            &selector_location,
                            "string selectors require a positive maximum and ordered byte bounds; other types forbid byte bounds",
                        );
                    }
                    selectors.push(CompiledSelector {
                        name: selector_name.to_owned(),
                        source_column: selector.source_column.clone(),
                        data_type: selector.data_type,
                        minimum_bytes: selector.minimum_bytes,
                        maximum_bytes: selector.maximum_bytes,
                        codelist: selector.codelist.clone(),
                    });
                }
                let minimum_body_bytes =
                    minimum_lookup_body_bytes(lookup.request_body.selectors.iter());
                if u64::from(lookup.request_body.maximum_bytes) < minimum_body_bytes {
                    self.error(
                        "lookup.body_bound_too_small",
                        &format!("{location}.requestBody.maximumBytes"),
                        "the lookup request-body bound cannot contain the smallest valid JSON body for all required selectors",
                    );
                }
                if let Some(mut operation) = self.compile_simple_operation(
                    resource,
                    &properties,
                    &disclosures,
                    observed_view,
                    observed_columns.as_ref(),
                    &location,
                    "lookup",
                    OperationKind::Lookup {
                        name: lookup.id.clone(),
                    },
                    &lookup.default_access_profile,
                    &lookup.access_profiles,
                ) {
                    operation.identifier = format!("{}.lookup.{}", resource.id, lookup.id);
                    operation.query.selectors = selectors;
                    operation.query.maximum_request_body_bytes =
                        Some(lookup.request_body.maximum_bytes);
                    operations.push(operation);
                }
            }
            if resource.operations.searches.len() > MAXIMUM_SEARCHES_PER_RESOURCE {
                self.error(
                    "operation.search_bound_exceeded",
                    &format!("{root}.operations.searches"),
                    "the named search count exceeds the per-resource product ceiling",
                );
            }
            let mut search_ids = HashSet::new();
            for (search_index, search) in resource.operations.searches.iter().enumerate() {
                let location = format!("{root}.operations.searches[{search_index}]");
                if !search_ids.insert(search.id.as_str()) {
                    self.error(
                        "operation.search_id_duplicate",
                        &format!("{location}.id"),
                        "search identifiers must be unique within a resource",
                    );
                }
                if !valid_route_identifier(&search.id) {
                    self.error(
                        "operation.search_id_invalid",
                        &format!("{location}.id"),
                        "search identifiers must be URL-safe kebab case within the runtime route ceiling",
                    );
                }
                if source.profile == SourceProfile::LiveReadOnly {
                    self.error(
                        "operation.search_live_forbidden",
                        &location,
                        "Version one live sources cannot compile a collection search",
                    );
                }
                if let Some(operation) = self.compile_search(
                    resource,
                    &properties,
                    &disclosures,
                    observed_view,
                    observed_columns.as_ref(),
                    &location,
                    search,
                ) {
                    operations.push(operation);
                }
            }
            if operations.is_empty() {
                self.error(
                    "operation.none",
                    &format!("{root}.operations"),
                    "a resource must compile at least one operation",
                );
            }

            self.validate_source_type_interpretations(resource, &properties, &operations, &root);

            self.validate_processing(resource, &operations, &root);
            let column_accounting = self.compile_column_accounting(
                resource,
                &properties,
                &operations,
                &property_columns,
                &core,
                observed_columns.as_ref(),
                &root,
            );
            self.apply_operation_handling(&mut operations, &column_accounting, &root);
            self.validate_metadata_closure(resource, &operations, &properties, &root);
            let semantic_class = match expand_local_term(
                &self.contract.semantics.local_vocabulary,
                &resource.semantic_class,
            ) {
                Some(value) => value,
                None => {
                    self.error(
                        "semantics.class_invalid",
                        &format!("{root}.semanticClass"),
                        "a semantic class must be local:Name or an absolute HTTP or HTTPS IRI",
                    );
                    resource.semantic_class.clone()
                }
            };
            compiled.push(CompiledResource {
                id: resource.id.clone(),
                title: resource.title.clone(),
                description: resource.description.clone(),
                semantic_class,
                source: resource.source.source.clone(),
                view: resource.source.view.clone(),
                record_context: CompiledRecordContext {
                    record_identifier_column: resource
                        .record_context
                        .record_identifier
                        .source_column
                        .clone(),
                    revision_identifier_column: resource
                        .record_context
                        .revision_identifier
                        .source_column
                        .clone(),
                    lifecycle_state_column: resource
                        .record_context
                        .lifecycle_state
                        .source_column
                        .clone(),
                    lifecycle_state_codelist: resource
                        .record_context
                        .lifecycle_state
                        .codelist
                        .clone(),
                    recorded_at_column: resource.record_context.recorded_at.source_column.clone(),
                    schema_reference: artifact_url(
                        &self.contract.registry.base_uri,
                        &format!("{}-full-schema", resource.id),
                    ),
                    semantic_model_reference: artifact_url(
                        &self.contract.registry.base_uri,
                        &format!("{}-full-vocabulary", resource.id),
                    ),
                },
                properties,
                primary_geometry: resource.primary_geometry.clone(),
                disclosure_profiles: disclosures,
                operations,
                column_accounting,
                processing_descriptions: resource.processing_descriptions.clone(),
            });
        }
        compiled
    }

    fn compile_statistical_datasets(&mut self) -> Vec<CompiledStatisticalDataset> {
        let mut compiled = Vec::with_capacity(self.contract.statistical_datasets.len());
        for (index, dataset) in self.contract.statistical_datasets.iter().enumerate() {
            let root = format!("statisticalDatasets[{index}]");
            if !self.publication_ids.insert(dataset.id.clone()) {
                self.error(
                    "statistics.dataset_id_duplicate",
                    &format!("{root}.id"),
                    "resource and statistical dataset identifiers must be globally unique",
                );
            }
            if !valid_route_identifier(&dataset.id) {
                self.error(
                    "statistics.dataset_id_invalid",
                    &format!("{root}.id"),
                    "a statistical dataset identifier must be URL-safe kebab case within the runtime route ceiling",
                );
            }
            if dataset.title.trim().is_empty() || dataset.description.trim().is_empty() {
                self.error(
                    "statistics.documentation_empty",
                    &root,
                    "statistical datasets require a non-empty title and description",
                );
            }
            if DateTime::parse_from_rfc3339(&dataset.publication.release_at).is_err() {
                self.error(
                    "statistics.release_at_invalid",
                    &format!("{root}.publication.releaseAt"),
                    "a statistical publication release time must be an RFC 3339 timestamp",
                );
            }
            if dataset.dimensions.len().saturating_add(1) > MAXIMUM_SDMX_DIMENSIONS {
                self.error(
                    "statistics.dimension_bound_invalid",
                    &format!("{root}.dimensions"),
                    "ordinary dimensions plus the time dimension exceed the product ceiling",
                );
            }
            if dataset.attributes.len() > MAXIMUM_SDMX_ATTRIBUTES {
                self.error(
                    "statistics.attribute_bound_exceeded",
                    &format!("{root}.attributes"),
                    "the statistical attribute count exceeds the product ceiling",
                );
            }
            if dataset.query.maximum_observations == 0
                || dataset.query.maximum_observations > MAXIMUM_SDMX_OBSERVATIONS
                || dataset.query.maximum_offset > MAXIMUM_SDMX_OFFSET
            {
                self.error(
                    "statistics.query_bound_invalid",
                    &format!("{root}.query"),
                    "statistical observation and offset bounds must stay within the product ceilings",
                );
            }

            let sdmx = &dataset.bindings.sdmx;
            let generated_id = to_sdmx_id(&dataset.id);
            let agency_id = sdmx
                .agency_id
                .clone()
                .unwrap_or_else(|| to_sdmx_id(&self.contract.metadata.id));
            let dataflow_id = sdmx
                .dataflow_id
                .clone()
                .unwrap_or_else(|| generated_id.clone());
            let version = sdmx.version.clone().unwrap_or_else(|| "1.0.0".into());
            let data_structure_id = sdmx
                .data_structure_id
                .clone()
                .unwrap_or_else(|| format!("{generated_id}_DSD"));
            let concept_scheme_id = sdmx
                .concept_scheme_id
                .clone()
                .unwrap_or_else(|| format!("{generated_id}_CONCEPTS"));
            if !valid_sdmx_agency_id(&agency_id) {
                self.error(
                    "sdmx.identifier_invalid",
                    &format!("{root}.bindings.sdmx.agencyId"),
                    "an SDMX agency identifier must use dot-separated NCName-compatible segments",
                );
            }
            for (value, location) in [
                (&dataflow_id, format!("{root}.bindings.sdmx.dataflowId")),
                (
                    &data_structure_id,
                    format!("{root}.bindings.sdmx.dataStructureId"),
                ),
                (
                    &concept_scheme_id,
                    format!("{root}.bindings.sdmx.conceptSchemeId"),
                ),
            ] {
                if !valid_sdmx_maintainable_id(value) {
                    self.error(
                        "sdmx.identifier_invalid",
                        &location,
                        "an SDMX artefact identifier must use the single-level NCName-compatible profile",
                    );
                }
            }
            if !valid_sdmx_version(&version) {
                self.error(
                    "sdmx.version_invalid",
                    &format!("{root}.bindings.sdmx.version"),
                    "the SDMX binding requires one three-part numeric semantic version without leading zeroes",
                );
            }
            if !self.statistical_endpoint_ids.insert((
                agency_id.clone(),
                dataflow_id.clone(),
                version.clone(),
            )) {
                self.error(
                    "sdmx.endpoint_duplicate",
                    &format!("{root}.bindings.sdmx"),
                    "SDMX agency, dataflow, and version tuples must be unique",
                );
            }
            if !self.statistical_structure_ids.insert((
                agency_id.clone(),
                data_structure_id.clone(),
                version.clone(),
            )) {
                self.error(
                    "sdmx.structure_endpoint_duplicate",
                    &format!("{root}.bindings.sdmx"),
                    "SDMX agency, data structure, and version tuples must be unique",
                );
            }

            if !valid_sql_identifier(&dataset.source.view) {
                self.error(
                    "statistics.view_invalid",
                    &format!("{root}.source.view"),
                    "reviewed SQLite view names must be simple identifiers",
                );
            }
            let Some(source) = self.contract.sources.get(&dataset.source.source) else {
                self.error(
                    "statistics.source_unknown",
                    &format!("{root}.source.source"),
                    "the statistical dataset names no governed source",
                );
                continue;
            };
            if source.profile != SourceProfile::Snapshot {
                self.error(
                    "statistics.live_source_forbidden",
                    &format!("{root}.source.source"),
                    "statistical datasets require a versioned snapshot source",
                );
            }
            let observed_view =
                self.observed
                    .get(dataset.source.source.as_str())
                    .and_then(|schema| {
                        schema
                            .views
                            .iter()
                            .find(|view| view.name == dataset.source.view)
                    });
            if self.observed.contains_key(dataset.source.source.as_str()) && observed_view.is_none()
            {
                self.error(
                    "statistics.view_unknown",
                    &format!("{root}.source.view"),
                    "the reviewed statistical view is absent from the observed source schema",
                );
            }
            let observed_columns = observed_view.map(|view| {
                view.columns
                    .iter()
                    .map(|column| column.name.as_str())
                    .collect::<BTreeSet<_>>()
            });
            if effective_classification(self.contract, &dataset.classification_defaults, None)
                .is_none()
            {
                self.error(
                    "classification.defaults_incomplete",
                    &format!("{root}.classificationDefaults"),
                    "statistical-dataset classification defaults must resolve every dimension",
                );
            }

            let mut component_ids = HashSet::new();
            let mut component_columns = HashSet::new();
            let mut classifications = BTreeMap::<String, EffectiveClassification>::new();
            let mut dimensions = Vec::with_capacity(dataset.dimensions.len());
            for (local_id, dimension) in dataset.dimensions.iter() {
                let location = format!("{root}.dimensions.{local_id}");
                if !valid_camel_identifier(local_id) {
                    self.error(
                        "statistics.component_id_invalid",
                        &location,
                        "statistical component identifiers must be camelCase",
                    );
                }
                let component_id = to_sdmx_id(local_id);
                self.validate_statistical_component_identity(
                    &component_id,
                    &dimension.label,
                    &dimension.description,
                    &dimension.column,
                    &location,
                    &mut component_ids,
                    &mut component_columns,
                    observed_columns.as_ref(),
                );
                if !matches!(
                    dimension.data_type,
                    StatisticalValueType::Code | StatisticalValueType::String
                ) {
                    self.error(
                        "statistics.dimension_type_invalid",
                        &format!("{location}.type"),
                        "ordinary dimensions use only code or string values",
                    );
                }
                if !compatible_sdmx_declared_type(
                    dimension.data_type,
                    observed_column(observed_view, &dimension.column)
                        .map(|column| column.declared_type.as_str()),
                ) {
                    self.error(
                        "statistics.component_type_incompatible",
                        &format!("{location}.type"),
                        "the statistical value type is incompatible with the reviewed SQLite declaration",
                    );
                }
                let vocabulary_valid = match dimension.data_type {
                    StatisticalValueType::Code => dimension
                        .vocabulary
                        .as_deref()
                        .is_some_and(valid_relative_reference),
                    StatisticalValueType::String => dimension.vocabulary.is_none(),
                    _ => false,
                };
                if !vocabulary_valid {
                    self.error(
                        "statistics.dimension_vocabulary_invalid",
                        &location,
                        "code dimensions require one contained vocabulary and string dimensions cannot declare one",
                    );
                }
                let Some(classification) = effective_classification(
                    self.contract,
                    &dataset.classification_defaults,
                    Some(&dimension.classification),
                ) else {
                    self.error(
                        "classification.property_incomplete",
                        &format!("{location}.classification"),
                        "the dimension classification is incomplete",
                    );
                    continue;
                };
                self.validate_statistical_output_classification(&classification, &location);
                let semantic_iri = self.statistical_semantic_iri(&dimension.concept, &location);
                classifications.insert(dimension.column.clone(), classification.clone());
                dimensions.push(CompiledStatisticalDimension {
                    id: component_id,
                    label: dimension.label.clone(),
                    description: dimension.description.clone(),
                    source_column: dimension.column.clone(),
                    data_type: dimension.data_type,
                    codelist: dimension.vocabulary.clone(),
                    semantic_iri,
                    classification,
                });
            }

            let time_definition = &dataset.time;
            let time_location = format!("{root}.time");
            self.validate_statistical_component_identity(
                "TIME_PERIOD",
                &time_definition.label,
                &time_definition.description,
                &time_definition.column,
                &time_location,
                &mut component_ids,
                &mut component_columns,
                observed_columns.as_ref(),
            );
            if !compatible_sdmx_time_declared_type(
                observed_column(observed_view, &time_definition.column)
                    .map(|column| column.declared_type.as_str()),
            ) {
                self.error(
                    "statistics.component_type_incompatible",
                    &format!("{time_location}.column"),
                    "the time dimension requires a reviewed textual SQLite declaration",
                );
            }
            let Some(time_classification) = effective_classification(
                self.contract,
                &dataset.classification_defaults,
                Some(&time_definition.classification),
            ) else {
                self.error(
                    "classification.property_incomplete",
                    &format!("{time_location}.classification"),
                    "the time-dimension classification is incomplete",
                );
                continue;
            };
            self.validate_statistical_output_classification(&time_classification, &time_location);
            let time = CompiledStatisticalTimeDimension {
                id: "TIME_PERIOD".into(),
                label: time_definition.label.clone(),
                description: time_definition.description.clone(),
                source_column: time_definition.column.clone(),
                granularity: time_definition.granularity,
                semantic_iri: self
                    .statistical_semantic_iri(&time_definition.concept, &time_location),
                classification: time_classification.clone(),
            };
            classifications.insert(time_definition.column.clone(), time_classification);

            let measure_definition = &dataset.measure;
            let measure_location = format!("{root}.measure");
            if !valid_camel_identifier(&measure_definition.id) {
                self.error(
                    "statistics.component_id_invalid",
                    &format!("{measure_location}.id"),
                    "statistical component identifiers must be camelCase",
                );
            }
            let measure_id = to_sdmx_id(&measure_definition.id);
            self.validate_statistical_component_identity(
                &measure_id,
                &measure_definition.label,
                &measure_definition.description,
                &measure_definition.column,
                &measure_location,
                &mut component_ids,
                &mut component_columns,
                observed_columns.as_ref(),
            );
            if !matches!(
                measure_definition.data_type,
                StatisticalValueType::Integer | StatisticalValueType::Decimal
            ) {
                self.error(
                    "statistics.measure_invalid",
                    &measure_location,
                    "the statistical profile requires one integer or decimal measure",
                );
            }
            if !compatible_sdmx_declared_type(
                measure_definition.data_type,
                observed_column(observed_view, &measure_definition.column)
                    .map(|column| column.declared_type.as_str()),
            ) {
                self.error(
                    "statistics.component_type_incompatible",
                    &format!("{measure_location}.type"),
                    "the statistical measure type is incompatible with the reviewed SQLite declaration",
                );
            }
            let Some(measure_classification) = effective_classification(
                self.contract,
                &dataset.classification_defaults,
                Some(&measure_definition.classification),
            ) else {
                self.error(
                    "classification.property_incomplete",
                    &format!("{measure_location}.classification"),
                    "the measure classification is incomplete",
                );
                continue;
            };
            self.validate_statistical_output_classification(
                &measure_classification,
                &measure_location,
            );
            let measure = CompiledStatisticalMeasure {
                id: measure_id,
                label: measure_definition.label.clone(),
                description: measure_definition.description.clone(),
                source_column: measure_definition.column.clone(),
                data_type: measure_definition.data_type,
                semantic_iri: self
                    .statistical_semantic_iri(&measure_definition.concept, &measure_location),
                classification: measure_classification.clone(),
            };
            classifications.insert(measure_definition.column.clone(), measure_classification);

            let mut attributes = Vec::with_capacity(dataset.attributes.len());
            for (local_id, attribute) in dataset.attributes.iter() {
                let location = format!("{root}.attributes.{local_id}");
                if !valid_camel_identifier(local_id) {
                    self.error(
                        "statistics.component_id_invalid",
                        &location,
                        "statistical component identifiers must be camelCase",
                    );
                }
                let component_id = to_sdmx_id(local_id);
                self.validate_statistical_component_identity(
                    &component_id,
                    &attribute.label,
                    &attribute.description,
                    &attribute.column,
                    &location,
                    &mut component_ids,
                    &mut component_columns,
                    observed_columns.as_ref(),
                );
                let vocabulary_valid = match attribute.data_type {
                    StatisticalValueType::Code => attribute
                        .vocabulary
                        .as_deref()
                        .is_some_and(valid_relative_reference),
                    StatisticalValueType::String
                    | StatisticalValueType::Integer
                    | StatisticalValueType::Decimal
                    | StatisticalValueType::Boolean => attribute.vocabulary.is_none(),
                };
                if !vocabulary_valid {
                    self.error(
                        "statistics.attribute_invalid",
                        &location,
                        "code attributes require one contained vocabulary and other attributes cannot declare one",
                    );
                }
                if !compatible_sdmx_declared_type(
                    attribute.data_type,
                    observed_column(observed_view, &attribute.column)
                        .map(|column| column.declared_type.as_str()),
                ) {
                    self.error(
                        "statistics.component_type_incompatible",
                        &format!("{location}.type"),
                        "the statistical attribute type is incompatible with the reviewed SQLite declaration",
                    );
                }
                let Some(classification) = effective_classification(
                    self.contract,
                    &dataset.classification_defaults,
                    Some(&attribute.classification),
                ) else {
                    self.error(
                        "classification.property_incomplete",
                        &format!("{location}.classification"),
                        "the attribute classification is incomplete",
                    );
                    continue;
                };
                self.validate_statistical_output_classification(&classification, &location);
                let semantic_iri = self.statistical_semantic_iri(&attribute.concept, &location);
                classifications.insert(attribute.column.clone(), classification.clone());
                attributes.push(CompiledStatisticalAttribute {
                    id: component_id,
                    label: attribute.label.clone(),
                    description: attribute.description.clone(),
                    source_column: attribute.column.clone(),
                    data_type: attribute.data_type,
                    codelist: attribute.vocabulary.clone(),
                    source_required: attribute.required,
                    semantic_iri,
                    classification,
                });
            }

            let Some(access) = self.compile_access(
                &dataset.access,
                observed_view,
                observed_columns.as_ref(),
                &root,
            ) else {
                continue;
            };
            let column_accounting = self.compile_statistical_column_accounting(
                dataset,
                &dimensions,
                &time,
                &measure,
                &attributes,
                &access,
                &classifications,
                observed_columns.as_ref(),
                &root,
            );
            let processing_handling = column_accounting
                .iter()
                .map(|column| column.classification.handling)
                .max()
                .unwrap_or(Handling::Public);
            let disclosure_handling = dimensions
                .iter()
                .map(|component| component.classification.handling)
                .chain(std::iter::once(time.classification.handling))
                .chain(std::iter::once(measure.classification.handling))
                .chain(
                    attributes
                        .iter()
                        .map(|component| component.classification.handling),
                )
                .max()
                .unwrap_or(Handling::Public);
            if processing_handling > Handling::Public && matches!(access, CompiledAccess::Public) {
                self.error(
                    "statistics.public_nonpublic_forbidden",
                    &format!("{root}.access"),
                    "anonymous statistical publication may process only public-handling columns",
                );
            }
            self.validate_statistical_processing(dataset, &root);
            self.validate_statistical_metadata_closure(processing_handling, &root);
            compiled.push(CompiledStatisticalDataset {
                id: dataset.id.clone(),
                title: dataset.title.clone(),
                description: dataset.description.clone(),
                sdmx: CompiledSdmxBindingProfile {
                    agency_id,
                    dataflow_id,
                    version,
                    data_structure_id,
                    concept_scheme_id,
                    rest_version: SDMX_REST_VERSION.into(),
                    data_json_version: SDMX_DATA_JSON_VERSION.into(),
                    data_csv_version: SDMX_DATA_CSV_VERSION.into(),
                    structure_json_version: SDMX_STRUCTURE_JSON_VERSION.into(),
                },
                release_at: dataset.publication.release_at.clone(),
                source: dataset.source.source.clone(),
                view: dataset.source.view.clone(),
                dimensions,
                time,
                measure,
                attributes,
                access,
                allow_unfiltered: dataset.query.allow_unfiltered,
                maximum_observations: dataset.query.maximum_observations,
                maximum_offset: dataset.query.maximum_offset,
                processing_handling,
                disclosure_handling,
                column_accounting,
                processing_descriptions: dataset.processing_descriptions.clone(),
            });
        }
        compiled
    }

    fn statistical_semantic_iri(&mut self, concept: &str, location: &str) -> String {
        match expand_local_term(&self.contract.semantics.local_vocabulary, concept) {
            Some(value) => value,
            None => {
                self.error(
                    "statistics.concept_invalid",
                    &format!("{location}.concept"),
                    "a statistical concept must be a local term or absolute HTTP IRI",
                );
                concept.to_owned()
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_statistical_component_identity(
        &mut self,
        id: &str,
        label: &str,
        description: &str,
        source_column: &str,
        location: &str,
        component_ids: &mut HashSet<String>,
        component_columns: &mut HashSet<String>,
        observed_columns: Option<&BTreeSet<&str>>,
    ) {
        if !valid_sdmx_component_id(id) || !component_ids.insert(id.to_owned()) {
            self.error(
                "statistics.binding_component_id_invalid",
                location,
                "generated SDMX component identifiers must be unique uppercase identifiers",
            );
        }
        if label.trim().is_empty() || description.trim().is_empty() {
            self.error(
                "statistics.component_documentation_empty",
                location,
                "statistical components require a label and description",
            );
        }
        if !valid_sql_identifier(source_column) || !column_exists(observed_columns, source_column) {
            self.error(
                "statistics.component_column_invalid",
                &format!("{location}.column"),
                "a statistical component must bind one reviewed source column",
            );
        }
        if !component_columns.insert(source_column.to_owned()) {
            self.error(
                "statistics.component_column_reused",
                &format!("{location}.column"),
                "one reviewed column cannot back more than one statistical component",
            );
        }
    }

    fn validate_statistical_output_classification(
        &mut self,
        classification: &EffectiveClassification,
        location: &str,
    ) {
        self.validate_review_status(classification, &format!("{location}.classification"), None);
        if classification.privacy != "non-personal" {
            self.error(
                "statistics.personal_output_forbidden",
                &format!("{location}.classification.privacy"),
                "statistical output components must be reviewed as non-personal",
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_statistical_column_accounting(
        &mut self,
        dataset: &crate::contract::StatisticalDatasetDefinition,
        dimensions: &[CompiledStatisticalDimension],
        time: &CompiledStatisticalTimeDimension,
        measure: &CompiledStatisticalMeasure,
        attributes: &[CompiledStatisticalAttribute],
        access: &CompiledAccess,
        classifications: &BTreeMap<String, EffectiveClassification>,
        observed_columns: Option<&BTreeSet<&str>>,
        root: &str,
    ) -> Vec<ColumnAccount> {
        let mut uses = BTreeMap::<String, BTreeSet<ColumnUse>>::new();
        for dimension in dimensions {
            uses.entry(dimension.source_column.clone())
                .or_default()
                .insert(ColumnUse::StatisticalDimension(dimension.id.clone()));
        }
        uses.entry(time.source_column.clone())
            .or_default()
            .insert(ColumnUse::StatisticalDimension(time.id.clone()));
        uses.entry(measure.source_column.clone())
            .or_default()
            .insert(ColumnUse::StatisticalMeasure(measure.id.clone()));
        for attribute in attributes {
            uses.entry(attribute.source_column.clone())
                .or_default()
                .insert(ColumnUse::StatisticalAttribute(attribute.id.clone()));
        }
        if let CompiledAccess::Protected {
            row_binding: Some(binding),
            ..
        } = access
        {
            uses.entry(binding.source_column.clone())
                .or_default()
                .insert(ColumnUse::RowBinding(format!(
                    "{}.statistics.read",
                    dataset.id
                )));
        }
        if let Some(columns) = observed_columns {
            for column in columns {
                if !uses.contains_key(*column) {
                    self.error(
                        "source.column_unaccounted",
                        &format!("{root}.source"),
                        "the reviewed statistical view contains an unaccounted column",
                    );
                }
            }
        }
        for (column, _) in dataset.source_column_classifications.iter() {
            if !uses.contains_key(column) {
                self.error(
                    "classification.column_override_unknown",
                    &format!("{root}.sourceColumnClassifications.{column}"),
                    "a source-column classification override must name an accounted reviewed column",
                );
            }
        }
        let mut accounts = Vec::with_capacity(uses.len());
        for (column, column_uses) in uses {
            let source_override = dataset.source_column_classifications.get(&column);
            if column_uses.len() > 1
                && !source_override.is_some_and(explicit_reviewed_classification)
            {
                let location = column_accounting_location(root, &column, source_override, None);
                let message = format!(
                    "a multiply-bound statistical source column requires its own complete reviewed classification for source column '{column}'"
                );
                match self.profile {
                    CompileProfile::Authoring => self.warning(
                        "classification.column_explicit_review_required",
                        &location,
                        &message,
                    ),
                    CompileProfile::Production => self.error(
                        "classification.column_explicit_review_required",
                        &location,
                        &message,
                    ),
                }
            }
            let base = classifications.get(&column).map_or_else(
                || dataset.classification_defaults.clone(),
                classification_to_partial,
            );
            let Some(classification) =
                effective_classification(self.contract, &base, source_override)
            else {
                self.error(
                    "classification.column_incomplete",
                    &column_accounting_location(root, &column, source_override, None),
                    &format!(
                        "an accounted statistical source column has no complete classification for source column '{column}'"
                    ),
                );
                continue;
            };
            if let Some(component) = classifications.get(&column) {
                if classification.privacy != component.privacy {
                    self.error(
                        "classification.column_privacy_mismatch",
                        &column_accounting_location(root, &column, source_override, Some("privacy")),
                        &format!(
                            "a statistical component and its source column require exact privacy agreement for source column '{column}'"
                        ),
                    );
                }
                if classification.handling < component.handling {
                    self.error(
                        "classification.column_weaker_than_property",
                        &column_accounting_location(root, &column, source_override, Some("handling")),
                        &format!(
                            "a source-column classification cannot weaken component handling for source column '{column}'"
                        ),
                    );
                }
            }
            self.validate_review_status(
                &classification,
                &column_accounting_location(root, &column, source_override, None),
                Some(&column),
            );
            accounts.push(ColumnAccount {
                column,
                uses: column_uses.into_iter().collect(),
                classification,
            });
        }
        accounts
    }

    fn validate_statistical_processing(
        &mut self,
        dataset: &crate::contract::StatisticalDatasetDefinition,
        root: &str,
    ) {
        if dataset.processing_descriptions.is_empty() {
            self.error(
                "processing.description_missing",
                &format!("{root}.processingDescriptions"),
                "a statistical publication requires a reviewed processing description",
            );
        }
        let mut ids = HashSet::new();
        for (index, processing) in dataset.processing_descriptions.iter().enumerate() {
            let location = format!("{root}.processingDescriptions[{index}]");
            if !ids.insert(processing.id.as_str())
                || !valid_kebab_identifier(&processing.id)
                || processing.purpose.trim().is_empty()
                || processing.recipient_class.trim().is_empty()
                || processing.safeguards.is_empty()
                || has_duplicates(&processing.safeguards)
                || !valid_relative_reference(&processing.legal_basis_ref)
                || !valid_relative_reference(&processing.dpv_profile_ref)
            {
                self.error(
                    "processing.description_invalid",
                    &location,
                    "processing descriptions require stable identifiers, contained governance references, and reviewed safeguards",
                );
            }
            if processing.operation_refs != ["statistics:read"] {
                self.error(
                    "processing.operations_invalid",
                    &format!("{location}.operationRefs"),
                    "a statistical processing description must name statistics:read",
                );
            }
        }
    }

    fn validate_statistical_metadata_closure(&mut self, maximum_handling: Handling, root: &str) {
        if maximum_handling >= Handling::Confidential
            && self.contract.metadata_visibility.classifications
                == crate::contract::Visibility::Public
        {
            self.error(
                "metadata.classification_visibility_invalid",
                root,
                "confidential or restricted statistical components forbid public classification metadata",
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_simple_operation(
        &mut self,
        resource: &crate::contract::ResourceDefinition,
        properties: &[CompiledProperty],
        disclosures: &[CompiledDisclosureProfile],
        observed_view: Option<&crate::model::ObservedView>,
        observed_columns: Option<&BTreeSet<&str>>,
        root: &str,
        operation_location: &str,
        kind: OperationKind,
        default_access_profile: &str,
        access_profile_definitions: &crate::contract::OrderedMap<AccessProfileDefinition>,
    ) -> Option<CompiledOperation> {
        let location = if operation_location == "lookup" {
            root.to_owned()
        } else {
            format!("{root}.operations.{operation_location}")
        };
        if access_profile_definitions.is_empty() {
            self.error(
                "access_profile.none",
                &format!("{location}.accessProfiles"),
                "an operation must declare at least one finite access profile",
            );
            return None;
        }
        if access_profile_definitions.len() > MAXIMUM_ACCESS_PROFILES_PER_OPERATION {
            self.error(
                "access_profile.bound_exceeded",
                &format!("{location}.accessProfiles"),
                "the access profile count exceeds the per-operation product ceiling",
            );
        }
        if !valid_access_profile_identifier(default_access_profile)
            || access_profile_definitions
                .get(default_access_profile)
                .is_none()
        {
            self.error(
                "access_profile.default_invalid",
                &format!("{location}.defaultAccessProfile"),
                "the explicit default must name exactly one declared access profile",
            );
        }
        let identifier = match &kind {
            OperationKind::Read => format!("{}.read", resource.id),
            OperationKind::List => format!("{}.list", resource.id),
            OperationKind::Lookup { name } => format!("{}.lookup.{name}", resource.id),
            OperationKind::Search { name } => format!("{}.search.{name}", resource.id),
        };
        let pattern = match &kind {
            OperationKind::List => ConsultationPattern::List,
            OperationKind::Read => ConsultationPattern::Retrieve,
            OperationKind::Lookup { .. } => ConsultationPattern::Search,
            OperationKind::Search { .. } => ConsultationPattern::Search,
        };
        let artifact_stem = operation_artifact_stem(&resource.id, &kind);
        let mut access_profiles = Vec::with_capacity(access_profile_definitions.len());
        for (access_profile_id, definition) in access_profile_definitions.iter() {
            let access_profile_location = format!("{location}.accessProfiles.{access_profile_id}");
            if !valid_access_profile_identifier(access_profile_id) {
                self.error(
                    "access_profile.id_invalid",
                    &access_profile_location,
                    "access profile identifiers must be URL-safe kebab case within the runtime byte ceiling",
                );
            }
            let Some(disclosure) = disclosures
                .iter()
                .find(|item| item.id == definition.disclosure_profile)
            else {
                self.error(
                    "access_profile.disclosure_unknown",
                    &format!("{access_profile_location}.disclosureProfile"),
                    "the access profile names no disclosure profile",
                );
                continue;
            };
            let Some(access) = self.compile_access(
                &definition.access,
                observed_view,
                observed_columns,
                &access_profile_location,
            ) else {
                continue;
            };
            validate_disclosure_access(
                &mut self.report,
                disclosure,
                &access,
                matches!(&kind, OperationKind::List | OperationKind::Search { .. }),
                &access_profile_location,
            );
            let access_profile_artifact_stem =
                format!("{artifact_stem}--access-profile-{access_profile_id}");
            access_profiles.push(CompiledAccessProfile {
                id: access_profile_id.to_owned(),
                access,
                disclosure_profile: disclosure.id.clone(),
                selectable_properties: disclosure.properties.clone(),
                projected_columns: projected_columns(resource, properties, &disclosure.properties),
                processing_handling: Handling::Public,
                disclosure_handling: disclosure.maximum_handling,
                transform_inventory: disclosure
                    .properties
                    .iter()
                    .filter_map(|name| {
                        properties
                            .iter()
                            .find(|property| property.name == *name)
                            .and_then(|property| {
                                property
                                    .scalar_binding()
                                    .and_then(|binding| binding.transform.as_ref())
                                    .map(|transform| {
                                        format!("{}={}", property.name, transform.identifier())
                                    })
                            })
                    })
                    .collect(),
                schema_reference: artifact_url(
                    &self.contract.registry.base_uri,
                    &format!("{access_profile_artifact_stem}-schema"),
                ),
                semantic_model_reference: artifact_url(
                    &self.contract.registry.base_uri,
                    &format!("{access_profile_artifact_stem}-vocabulary"),
                ),
                context_reference: artifact_url(
                    &self.contract.registry.base_uri,
                    &format!("{access_profile_artifact_stem}-context"),
                ),
            });
        }
        if access_profiles
            .iter()
            .any(|access_profile| matches!(access_profile.access, CompiledAccess::Public))
            && access_profiles
                .iter()
                .find(|access_profile| access_profile.id == default_access_profile)
                .is_some_and(|access_profile| {
                    !matches!(access_profile.access, CompiledAccess::Public)
                })
        {
            self.error(
                "access_profile.public_default_required",
                &format!("{location}.defaultAccessProfile"),
                "an operation with a public access profile must use a public default",
            );
        }
        Some(CompiledOperation {
            identifier,
            family: CapabilityFamily::Consultation,
            pattern,
            kind,
            default_access_profile: default_access_profile.to_owned(),
            access_profiles,
            query: QueryPlan {
                source: resource.source.source.clone(),
                view: resource.source.view.clone(),
                filters: Vec::new(),
                spatial_bbox: None,
                selectors: Vec::new(),
                order_by: Vec::new(),
                allow_unfiltered: false,
                pagination: None,
                maximum_request_body_bytes: None,
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_list(
        &mut self,
        resource: &crate::contract::ResourceDefinition,
        properties: &[CompiledProperty],
        disclosures: &[CompiledDisclosureProfile],
        observed_view: Option<&crate::model::ObservedView>,
        observed_columns: Option<&BTreeSet<&str>>,
        root: &str,
        list: &crate::contract::ListOperation,
    ) -> Option<CompiledOperation> {
        let mut operation = self.compile_simple_operation(
            resource,
            properties,
            disclosures,
            observed_view,
            observed_columns,
            root,
            "list",
            OperationKind::List,
            &list.default_access_profile,
            &list.access_profiles,
        )?;
        let location = format!("{root}.operations.list");
        if list.filters.len() > MAXIMUM_LIST_FILTERS {
            self.error(
                "list.filter_bound_exceeded",
                &format!("{location}.filters"),
                "the governed filter count exceeds the product ceiling",
            );
        }
        if list.order_by.len() > MAXIMUM_LIST_ORDER_KEYS {
            self.error(
                "list.order_bound_exceeded",
                &format!("{location}.orderBy"),
                "the governed order-key count exceeds the product ceiling",
            );
        }
        if list.filters.is_empty() && !list.allow_unfiltered {
            self.error(
                "list.no_reachable_query",
                &location,
                "a list without filters must allow the empty filter set",
            );
        }
        if list.pagination.default_page_size == 0
            || list.pagination.maximum_page_size == 0
            || list.pagination.maximum_page_size > MAXIMUM_LIST_PAGE_SIZE
            || list.pagination.default_page_size > list.pagination.maximum_page_size
        {
            self.error(
                "list.pagination_invalid",
                &format!("{location}.pagination"),
                "page bounds must be positive and the default cannot exceed the maximum",
            );
        }
        let mut filter_names = HashSet::new();
        for (index, filter) in list.filters.iter().enumerate() {
            let filter_location = format!("{location}.filters[{index}]");
            if !valid_camel_identifier(&filter.name)
                || RESERVED_PARAMETERS.contains(&filter.name.as_str())
            {
                self.error(
                    "list.filter_name_invalid",
                    &format!("{filter_location}.name"),
                    "filter names must be non-reserved camelCase parameters",
                );
            }
            if !filter_names.insert(filter.name.as_str()) {
                self.error(
                    "list.filter_name_duplicate",
                    &format!("{filter_location}.name"),
                    "list filter names must be unique",
                );
            }
            match properties
                .iter()
                .find(|property| property.name == filter.property)
            {
                Some(property) => {
                    let Some(binding) = property.scalar_binding() else {
                        self.error(
                            "list.filter_property_point",
                            &filter_location,
                            "Point properties cannot be used as scalar list filters",
                        );
                        continue;
                    };
                    if binding.transform.is_some() {
                        self.error(
                            "list.filter_property_transformed",
                            &filter_location,
                            "transformed properties cannot be used as list filters",
                        );
                        continue;
                    }
                    if binding.data_type != filter.data_type {
                        self.error(
                            "list.filter_type_mismatch",
                            &filter_location,
                            "a filter type must match its published property",
                        );
                    }
                    if property.classification.privacy != "non-personal" {
                        self.error(
                            "list.filter_personal_forbidden",
                            &filter_location,
                            "Version one collection filters must be classified non-personal",
                        );
                    }
                    operation.query.filters.push(CompiledFilter {
                        parameter: filter.name.clone(),
                        property: filter.property.clone(),
                        source_column: binding.source_column.clone(),
                        data_type: filter.data_type,
                    });
                }
                None => self.error(
                    "list.filter_property_unknown",
                    &filter_location,
                    "a list filter must name a published property",
                ),
            }
        }
        let mut order = HashSet::new();
        let mut order_columns = HashSet::new();
        for (index, property_name) in list.order_by.iter().enumerate() {
            if !order.insert(property_name.as_str()) {
                self.error(
                    "list.order_duplicate",
                    &format!("{location}.orderBy[{index}]"),
                    "fixed order keys must be unique",
                );
            }
            match properties
                .iter()
                .find(|property| property.name == *property_name)
            {
                Some(property) => {
                    let Some(binding) = property.scalar_binding() else {
                        self.error(
                            "list.order_property_point",
                            &format!("{location}.orderBy[{index}]"),
                            "Point properties cannot be used as scalar fixed order keys",
                        );
                        continue;
                    };
                    if binding.transform.is_some() {
                        self.error(
                            "list.order_property_transformed",
                            &format!("{location}.orderBy[{index}]"),
                            "transformed properties cannot be used as fixed order keys",
                        );
                        continue;
                    }
                    if !property.source_required {
                        self.error(
                            "list.order_property_optional",
                            &format!("{location}.orderBy[{index}]"),
                            "fixed order properties must be required in the governed source contract",
                        );
                    }
                    if !cursor_order_type_supported(binding.data_type) {
                        self.error(
                            "list.order_property_type_unsupported",
                            &format!("{location}.orderBy[{index}]"),
                            "fixed order properties must use a cursor-supported string, integer, or boolean value shape",
                        );
                    }
                    if !order_columns.insert(binding.source_column.as_str()) {
                        self.error(
                            "list.order_column_duplicate",
                            &format!("{location}.orderBy[{index}]"),
                            "fixed order properties must resolve to distinct source columns",
                        );
                    }
                    self.validate_cursor_order_column(
                        observed_view,
                        &binding.source_column,
                        binding.data_type,
                        &format!("{location}.orderBy[{index}]"),
                    );
                    operation.query.order_by.push(binding.source_column.clone());
                }
                None => self.error(
                    "list.order_property_unknown",
                    &format!("{location}.orderBy[{index}]"),
                    "a fixed order key must name a published property",
                ),
            }
        }
        let record_identifier = &resource.record_context.record_identifier.source_column;
        // The globally unique Registry Record identifier is always the final
        // keyset component. Moving an explicitly authored occurrence to the
        // end makes the order deterministic and guarantees a unique final
        // tie-breaker rather than merely checking that it occurs somewhere.
        operation
            .query
            .order_by
            .retain(|column| column != record_identifier);
        operation.query.order_by.push(record_identifier.clone());
        self.validate_cursor_order_column(
            observed_view,
            record_identifier,
            DataType::String,
            &format!("{location}.orderBy"),
        );
        if operation.query.order_by.len() > MAXIMUM_LIST_ORDER_KEYS {
            self.error(
                "list.order_bound_exceeded",
                &format!("{location}.orderBy"),
                "fixed order keys plus the required record-identifier tie-breaker exceed the product ceiling",
            );
        }
        operation.query.allow_unfiltered = list.allow_unfiltered;
        operation.query.pagination = Some(CompiledPagination {
            default_page_size: list.pagination.default_page_size,
            maximum_page_size: list.pagination.maximum_page_size,
        });
        Some(operation)
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_search(
        &mut self,
        resource: &crate::contract::ResourceDefinition,
        properties: &[CompiledProperty],
        disclosures: &[CompiledDisclosureProfile],
        observed_view: Option<&crate::model::ObservedView>,
        observed_columns: Option<&BTreeSet<&str>>,
        location: &str,
        search: &crate::contract::SearchOperation,
    ) -> Option<CompiledOperation> {
        let mut operation = self.compile_simple_operation(
            resource,
            properties,
            disclosures,
            observed_view,
            observed_columns,
            location,
            "search",
            OperationKind::Search {
                name: search.id.clone(),
            },
            &search.default_access_profile,
            &search.access_profiles,
        )?;
        let Some(primary_name) = resource.primary_geometry.as_deref() else {
            self.error(
                "search.point_bbox_without_geometry",
                &format!("{location}.query"),
                "a point-bbox search requires one compiled primary Point property",
            );
            return Some(operation);
        };
        let Some(primary_property) = properties
            .iter()
            .find(|property| property.name == primary_name)
        else {
            return Some(operation);
        };
        let Some(point) = primary_property.point_binding() else {
            return Some(operation);
        };
        if primary_property.classification.privacy != "non-personal" {
            self.error(
                "search.point_bbox_personal_forbidden",
                &format!("{location}.query"),
                "the point-bbox search profile permits only non-personal geometry",
            );
        }
        let SearchQueryDefinition::PointBbox {
            maximum_longitude_span_degrees,
            maximum_latitude_span_degrees,
        } = &search.query;
        if *maximum_longitude_span_degrees == 0
            || *maximum_longitude_span_degrees > 360
            || *maximum_latitude_span_degrees == 0
            || *maximum_latitude_span_degrees > 180
        {
            self.error(
                "search.point_bbox_bound_invalid",
                &format!("{location}.query"),
                "point-bbox spans must be positive and no larger than the CRS84 world extent",
            );
        }
        operation.query.spatial_bbox = Some(CompiledSpatialBboxQuery {
            longitude_column: point.longitude_column.clone(),
            latitude_column: point.latitude_column.clone(),
            maximum_longitude_span_degrees: *maximum_longitude_span_degrees,
            maximum_latitude_span_degrees: *maximum_latitude_span_degrees,
        });

        if search.order_by.len() > MAXIMUM_LIST_ORDER_KEYS {
            self.error(
                "search.order_bound_exceeded",
                &format!("{location}.orderBy"),
                "the governed order-key count exceeds the product ceiling",
            );
        }
        let mut order = HashSet::new();
        let mut order_columns = HashSet::new();
        for (index, property_name) in search.order_by.iter().enumerate() {
            if !order.insert(property_name.as_str()) {
                self.error(
                    "search.order_duplicate",
                    &format!("{location}.orderBy[{index}]"),
                    "fixed search order keys must be unique",
                );
            }
            match properties
                .iter()
                .find(|property| property.name == *property_name)
            {
                Some(property) => {
                    let Some(binding) = property.scalar_binding() else {
                        self.error(
                            "search.order_property_point",
                            &format!("{location}.orderBy[{index}]"),
                            "Point properties cannot be fixed search order keys",
                        );
                        continue;
                    };
                    if binding.transform.is_some() {
                        self.error(
                            "search.order_property_transformed",
                            &format!("{location}.orderBy[{index}]"),
                            "transformed properties cannot be fixed search order keys",
                        );
                        continue;
                    }
                    if !property.source_required {
                        self.error(
                            "search.order_property_optional",
                            &format!("{location}.orderBy[{index}]"),
                            "fixed search order properties must be required",
                        );
                    }
                    if !cursor_order_type_supported(binding.data_type) {
                        self.error(
                            "search.order_property_type_unsupported",
                            &format!("{location}.orderBy[{index}]"),
                            "fixed search order properties must use a cursor-supported scalar shape",
                        );
                    }
                    if !order_columns.insert(binding.source_column.as_str()) {
                        self.error(
                            "search.order_column_duplicate",
                            &format!("{location}.orderBy[{index}]"),
                            "fixed search order properties must resolve to distinct source columns",
                        );
                    }
                    self.validate_cursor_order_column(
                        observed_view,
                        &binding.source_column,
                        binding.data_type,
                        &format!("{location}.orderBy[{index}]"),
                    );
                    operation.query.order_by.push(binding.source_column.clone());
                }
                None => self.error(
                    "search.order_property_unknown",
                    &format!("{location}.orderBy[{index}]"),
                    "a fixed search order key must name a published property",
                ),
            }
        }
        let record_identifier = &resource.record_context.record_identifier.source_column;
        operation
            .query
            .order_by
            .retain(|column| column != record_identifier);
        operation.query.order_by.push(record_identifier.clone());
        self.validate_cursor_order_column(
            observed_view,
            record_identifier,
            DataType::String,
            &format!("{location}.orderBy"),
        );
        if operation.query.order_by.len() > MAXIMUM_LIST_ORDER_KEYS {
            self.error(
                "search.order_bound_exceeded",
                &format!("{location}.orderBy"),
                "fixed search order keys plus the record-identifier tie-breaker exceed the product ceiling",
            );
        }
        if search.pagination.default_page_size == 0
            || search.pagination.maximum_page_size == 0
            || search.pagination.maximum_page_size > MAXIMUM_LIST_PAGE_SIZE
            || search.pagination.default_page_size > search.pagination.maximum_page_size
        {
            self.error(
                "search.pagination_invalid",
                &format!("{location}.pagination"),
                "page bounds must be positive and the default cannot exceed the maximum",
            );
        }
        operation.query.pagination = Some(CompiledPagination {
            default_page_size: search.pagination.default_page_size,
            maximum_page_size: search.pagination.maximum_page_size,
        });
        Some(operation)
    }

    fn validate_cursor_order_column(
        &mut self,
        observed_view: Option<&crate::model::ObservedView>,
        source_column: &str,
        data_type: DataType,
        location: &str,
    ) {
        let Some(observed) = observed_view.and_then(|view| {
            view.columns
                .iter()
                .find(|column| column.name == source_column)
        }) else {
            return;
        };
        // SQLite does not preserve NOT NULL metadata through views. Even a
        // direct projection of a NOT NULL base-table column is reported as
        // nullable by PRAGMA table_xinfo(view). The authored sourceRequired
        // contract and runtime source-row validation own null rejection;
        // observed metadata still closes the declared scalar type here.
        if !compatible_declared_type(data_type, &observed.declared_type) {
            self.error(
                "list.order_column_type_unsupported",
                location,
                "keyset order columns must have a reviewed SQLite declaration supported by the cursor scalar profile",
            );
        }
    }

    fn compile_transform(
        &mut self,
        definition: Option<&TransformDefinition>,
        output_type: DataType,
        location: &str,
    ) -> Option<CompiledTransform> {
        match definition? {
            TransformDefinition::PartialString { reveal, characters } => {
                if output_type != DataType::String {
                    self.error(
                        "transform.output_type_invalid",
                        &format!("{location}.type"),
                        "partial-string transforms must publish a string property",
                    );
                }
                if !(1..=MAXIMUM_PARTIAL_STRING_CHARACTERS).contains(characters) {
                    self.error(
                        "transform.partial_string_characters_invalid",
                        &format!("{location}.transform.characters"),
                        "partial-string reveal length must be within the fixed product bound",
                    );
                }
                let reveal_label = match reveal {
                    crate::contract::PartialStringReveal::Prefix => "prefix",
                    crate::contract::PartialStringReveal::Suffix => "suffix",
                };
                Some(CompiledTransform::PartialString {
                    identifier: format!("partial-string:{reveal_label}:{characters}"),
                    reveal: *reveal,
                    characters: *characters,
                })
            }
            TransformDefinition::DatePrecision {
                source_type,
                precision,
            } => {
                let expected_output = match precision {
                    DatePrecision::Year => DataType::Year,
                    DatePrecision::YearMonth => DataType::YearMonth,
                };
                if output_type != expected_output {
                    self.error(
                        "transform.output_type_invalid",
                        &format!("{location}.type"),
                        "date-precision output datatype must match the selected precision",
                    );
                }
                let source_label = match source_type {
                    DateInputType::Date => "date",
                    DateInputType::DateTime => "date-time",
                };
                let precision_label = match precision {
                    DatePrecision::Year => "year",
                    DatePrecision::YearMonth => "year-month",
                };
                Some(CompiledTransform::DatePrecision {
                    identifier: format!("date-precision:{source_label}:{precision_label}"),
                    source_type: *source_type,
                    precision: *precision,
                })
            }
        }
    }

    fn compile_access(
        &mut self,
        access: &AccessRule,
        observed_view: Option<&crate::model::ObservedView>,
        observed_columns: Option<&BTreeSet<&str>>,
        location: &str,
    ) -> Option<CompiledAccess> {
        match access {
            AccessRule::Public(value) => {
                if value != "public" {
                    self.error(
                        "access.public_invalid",
                        &format!("{location}.access"),
                        "anonymous access must be the exact public literal",
                    );
                }
                Some(CompiledAccess::Public)
            }
            AccessRule::Protected(protected) => {
                if protected.scope.trim().is_empty() {
                    self.error(
                        "access.scope_empty",
                        &format!("{location}.access.scope"),
                        "protected operations require one non-empty scope",
                    );
                } else if !valid_scope_token(&protected.scope) {
                    self.error(
                        "access.scope_invalid",
                        &format!("{location}.access.scope"),
                        "protected operations require exactly one RFC 6749 scope-token",
                    );
                } else if !self.scopes.insert(protected.scope.clone()) {
                    self.error(
                        "access.scope_duplicate",
                        &format!("{location}.access.scope"),
                        "operation scopes must be globally unique in one Registry",
                    );
                }
                let purpose = protected.purpose.as_ref().map(|purpose| {
                    if purpose.claim.trim().is_empty() || purpose.allowed.is_empty() {
                        self.error(
                            "access.purpose_invalid",
                            &format!("{location}.access.purpose"),
                            "a purpose constraint requires one claim and allowed values",
                        );
                    }
                    if has_duplicates(&purpose.allowed) {
                        self.error(
                            "access.purpose_duplicate",
                            &format!("{location}.access.purpose.allowed"),
                            "allowed purpose values must be unique",
                        );
                    }
                    if purpose.allowed.iter().any(|value| {
                        value.is_empty() || value.len() > MAXIMUM_DIRECT_CLAIM_BYTES
                    }) {
                        self.error(
                            "access.purpose_value_invalid",
                            &format!("{location}.access.purpose.allowed"),
                            "every allowed purpose must be a non-empty direct-string claim value within the runtime byte ceiling",
                        );
                    }
                    CompiledPurpose {
                        claim: purpose.claim.clone(),
                        allowed: purpose.allowed.clone(),
                    }
                });
                let row_binding = protected.authority_row_binding.as_ref().map(|binding| {
                    let (source, column, valid) = match binding {
                        AuthorityRowBinding::Claim(binding) => (
                            RowAuthoritySource::Claim(binding.claim.clone()),
                            binding.source_column.clone(),
                            !binding.claim.trim().is_empty(),
                        ),
                        AuthorityRowBinding::Principal(binding) => (
                            RowAuthoritySource::Principal,
                            binding.source_column.clone(),
                            binding.principal,
                        ),
                    };
                    if !valid {
                        self.error(
                            "access.row_binding_source_invalid",
                            &format!("{location}.access.authorityRowBinding"),
                            "a row binding must select one direct claim or the resolved principal",
                        );
                    }
                    if !column_exists(observed_columns, &column) {
                        self.error(
                            "access.row_binding_column_unknown",
                            &format!("{location}.access.authorityRowBinding.sourceColumn"),
                            "the row-binding column is absent from the reviewed view",
                        );
                    } else if observed_column(observed_view, &column)
                        .is_some_and(|observed| !has_sqlite_text_affinity(&observed.declared_type))
                    {
                        self.error(
                            "access.row_binding_declared_type_incompatible",
                            &format!("{location}.access.authorityRowBinding.sourceColumn"),
                            "row-authority binding columns require a reviewed SQLite declaration with TEXT affinity",
                        );
                    }
                    CompiledRowBinding {
                        source,
                        source_column: column,
                    }
                });
                Some(CompiledAccess::Protected {
                    scope: protected.scope.clone(),
                    purpose,
                    row_binding,
                })
            }
        }
    }

    fn validate_source_type_interpretations(
        &mut self,
        resource: &crate::contract::ResourceDefinition,
        properties: &[CompiledProperty],
        operations: &[CompiledOperation],
        root: &str,
    ) {
        let mut interpretations = BTreeMap::<String, (SourceRuntimeType, String)>::new();
        let core = [
            (
                resource
                    .record_context
                    .record_identifier
                    .source_column
                    .as_str(),
                DataType::String,
                format!("{root}.recordContext.recordIdentifier"),
            ),
            (
                resource
                    .record_context
                    .revision_identifier
                    .source_column
                    .as_str(),
                DataType::String,
                format!("{root}.recordContext.revisionIdentifier"),
            ),
            (
                resource
                    .record_context
                    .lifecycle_state
                    .source_column
                    .as_str(),
                DataType::ControlledCode,
                format!("{root}.recordContext.lifecycleState"),
            ),
            (
                resource.record_context.recorded_at.source_column.as_str(),
                DataType::DateTime,
                format!("{root}.recordContext.recordedAt"),
            ),
        ];
        for (column, data_type, location) in core {
            self.record_source_type(&mut interpretations, column, data_type, &location);
        }
        for property in properties {
            if let Some(binding) = property.scalar_binding() {
                self.record_source_type(
                    &mut interpretations,
                    &binding.source_column,
                    transform_source_type(binding.transform.as_ref(), binding.data_type),
                    &format!("{root}.properties.{}", property.name),
                );
            }
        }
        for operation in operations {
            for selector in &operation.query.selectors {
                self.record_source_type(
                    &mut interpretations,
                    &selector.source_column,
                    selector.data_type,
                    &format!(
                        "{root}.operations.{}.selectors.{}",
                        operation.identifier, selector.name
                    ),
                );
            }
        }
    }

    fn record_source_type(
        &mut self,
        interpretations: &mut BTreeMap<String, (SourceRuntimeType, String)>,
        column: &str,
        data_type: DataType,
        location: &str,
    ) {
        let data_type = source_runtime_type(data_type);
        if let Some((existing, existing_location)) = interpretations.get(column) {
            if *existing != data_type {
                self.error(
                    "source.column_type_interpretation_conflict",
                    location,
                    &format!(
                        "one raw source column cannot have incompatible datatype interpretations; it is already bound at {existing_location}"
                    ),
                );
            }
        } else {
            interpretations.insert(column.to_owned(), (data_type, location.to_owned()));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_column_accounting(
        &mut self,
        resource: &crate::contract::ResourceDefinition,
        properties: &[CompiledProperty],
        operations: &[CompiledOperation],
        property_columns: &HashMap<&str, Vec<(&str, EffectiveClassification, bool)>>,
        core: &[(&str, ColumnUse); 4],
        observed_columns: Option<&BTreeSet<&str>>,
        root: &str,
    ) -> Vec<ColumnAccount> {
        let mut uses: BTreeMap<&str, BTreeSet<ColumnUse>> = BTreeMap::new();
        for (column, usage) in core {
            uses.entry(column).or_default().insert(usage.clone());
        }
        for property in properties {
            match &property.binding {
                CompiledPropertyBinding::Scalar(binding) => {
                    uses.entry(&binding.source_column)
                        .or_default()
                        .insert(ColumnUse::Property(property.name.clone()));
                }
                CompiledPropertyBinding::Point(binding) => {
                    uses.entry(&binding.longitude_column)
                        .or_default()
                        .insert(ColumnUse::PointLongitude(property.name.clone()));
                    uses.entry(&binding.latitude_column)
                        .or_default()
                        .insert(ColumnUse::PointLatitude(property.name.clone()));
                }
            }
        }
        for operation in operations {
            for filter in &operation.query.filters {
                uses.entry(&filter.source_column)
                    .or_default()
                    .insert(ColumnUse::Filter(filter.parameter.clone()));
            }
            for column in &operation.query.order_by {
                uses.entry(column).or_default().insert(ColumnUse::Order);
            }
            for selector in &operation.query.selectors {
                uses.entry(&selector.source_column)
                    .or_default()
                    .insert(ColumnUse::Selector(selector.name.clone()));
            }
            for access_profile in &operation.access_profiles {
                if let CompiledAccess::Protected {
                    row_binding: Some(row_binding),
                    ..
                } = &access_profile.access
                {
                    uses.entry(&row_binding.source_column).or_default().insert(
                        ColumnUse::RowBinding(format!(
                            "{}:{}",
                            operation.identifier, access_profile.id
                        )),
                    );
                }
            }
        }
        if let Some(columns) = observed_columns {
            for column in columns {
                if !uses.contains_key(column) {
                    self.error(
                        "source.column_unaccounted",
                        &format!("{root}.source"),
                        "the reviewed view contains an unaccounted column",
                    );
                }
            }
        }
        for (column, _) in resource.source_column_classifications.iter() {
            if !uses.contains_key(column) {
                self.error(
                    "classification.column_override_unknown",
                    &format!("{root}.sourceColumnClassifications.{column}"),
                    "a source-column classification override must name an accounted reviewed column",
                );
            }
        }

        let mut accounts = Vec::with_capacity(uses.len());
        for (column, column_uses) in uses {
            let source_override = resource.source_column_classifications.get(column);
            let property_bindings = property_columns.get(column);
            let point_use = column_uses.iter().find_map(|usage| match usage {
                ColumnUse::PointLongitude(property) => Some((property.as_str(), "longitudeColumn")),
                ColumnUse::PointLatitude(property) => Some((property.as_str(), "latitudeColumn")),
                _ => None,
            });
            if let Some((property, field)) = point_use {
                if column_uses.len() != 1 {
                    self.error(
                        "geometry.carrier_column_collision",
                        &format!("{root}.properties.{property}.source.{field}"),
                        "Point carriers cannot also serve Registry Core, scalar properties, filters, selectors, ordering, or row bindings",
                    );
                }
            }
            let requires_explicit_review = property_bindings.is_some_and(|bindings| {
                bindings.len() > 1 || bindings.iter().any(|(_, _, transformed)| *transformed)
            });
            if requires_explicit_review
                && !source_override.is_some_and(explicit_reviewed_classification)
            {
                let location = column_accounting_location(root, column, source_override, None);
                if self.profile == CompileProfile::Production {
                    self.error(
                        "classification.column_explicit_review_required",
                        &location,
                        &format!(
                            "a transformed or multiply-bound source column requires its own complete reviewed classification for source column '{column}'"
                        ),
                    );
                } else {
                    self.warning(
                        "classification.column_explicit_review_required",
                        &location,
                        &format!(
                            "a transformed or multiply-bound source column still requires its own complete reviewed classification for source column '{column}'"
                        ),
                    );
                }
            }
            let property_classification = property_bindings
                .and_then(|bindings| bindings.first())
                .map(|(_, item, _)| item);
            let classification = match property_classification {
                Some(property) if !requires_explicit_review => effective_classification(
                    self.contract,
                    &classification_to_partial(property),
                    source_override,
                ),
                None => effective_classification(
                    self.contract,
                    &resource.classification_defaults,
                    source_override,
                ),
                Some(_) => effective_classification(
                    self.contract,
                    &resource.classification_defaults,
                    source_override,
                ),
            };
            let Some(classification) = classification else {
                self.error(
                    "classification.column_incomplete",
                    &column_accounting_location(root, column, source_override, None),
                    &format!(
                        "an accounted source column has no complete classification for source column '{column}'"
                    ),
                );
                continue;
            };
            if let Some((property_name, _)) = point_use {
                if properties
                    .iter()
                    .find(|property| property.name == property_name)
                    .is_some_and(|property| {
                        property.classification.privacy != classification.privacy
                    })
                {
                    self.error(
                        "classification.geometry_carrier_privacy_mismatch",
                        &column_accounting_location(root, column, source_override, Some("privacy")),
                        &format!(
                            "a Point property and each carrier require exact reviewed privacy agreement for source column '{column}'"
                        ),
                    );
                }
            }
            if let Some(bindings) = property_bindings {
                let strongest_direct = bindings
                    .iter()
                    .filter(|(_, _, transformed)| !*transformed)
                    .map(|(_, item, _)| item.handling)
                    .max();
                if strongest_direct.is_some_and(|handling| classification.handling < handling) {
                    self.error(
                        "classification.column_weaker_than_property",
                        &column_accounting_location(root, column, source_override, Some("handling")),
                        &format!(
                            "a source-column classification cannot weaken a direct property handling floor for source column '{column}'"
                        ),
                    );
                }
            }
            self.validate_review_status(
                &classification,
                &column_accounting_location(root, column, source_override, None),
                Some(column),
            );
            accounts.push(ColumnAccount {
                column: column.to_owned(),
                uses: column_uses.into_iter().collect(),
                classification,
            });
        }
        accounts
    }

    fn apply_operation_handling(
        &mut self,
        operations: &mut [CompiledOperation],
        columns: &[ColumnAccount],
        root: &str,
    ) {
        for operation in operations {
            let location = match &operation.kind {
                OperationKind::List => format!("{root}.operations.list"),
                OperationKind::Read => format!("{root}.operations.read"),
                OperationKind::Lookup { name } => {
                    format!("{root}.operations.lookups.{name}")
                }
                OperationKind::Search { name } => {
                    format!("{root}.operations.searches.{name}")
                }
            };
            for access_profile in &mut operation.access_profiles {
                let mut referenced = BTreeSet::new();
                referenced.extend(access_profile.projected_columns.iter().map(String::as_str));
                referenced.extend(
                    operation
                        .query
                        .filters
                        .iter()
                        .map(|filter| filter.source_column.as_str()),
                );
                referenced.extend(operation.query.order_by.iter().map(String::as_str));
                if let Some(spatial) = &operation.query.spatial_bbox {
                    referenced.insert(&spatial.longitude_column);
                    referenced.insert(&spatial.latitude_column);
                }
                referenced.extend(
                    operation
                        .query
                        .selectors
                        .iter()
                        .map(|selector| selector.source_column.as_str()),
                );
                if let CompiledAccess::Protected {
                    row_binding: Some(binding),
                    ..
                } = &access_profile.access
                {
                    referenced.insert(&binding.source_column);
                }
                access_profile.processing_handling = columns
                    .iter()
                    .filter(|column| referenced.contains(column.column.as_str()))
                    .fold(Handling::Public, |maximum, column| {
                        maximum.max(column.classification.handling)
                    });
                let access_profile_location =
                    format!("{location}.accessProfiles.{}", access_profile.id);
                if access_profile.processing_handling > Handling::Public
                    && matches!(access_profile.access, CompiledAccess::Public)
                {
                    self.error(
                        "access.public_nonpublic_forbidden",
                        &access_profile_location,
                        "anonymous access profiles may process only public-handling reviewed columns",
                    );
                }
                if access_profile.processing_handling == Handling::Restricted
                    && matches!(
                        &operation.kind,
                        OperationKind::List | OperationKind::Search { .. }
                    )
                {
                    self.error(
                        "operation.restricted_list_forbidden",
                        &access_profile_location,
                        "restricted reviewed data cannot be processed by a collection list",
                    );
                }
            }
        }
    }

    fn validate_metadata_closure(
        &mut self,
        _resource: &crate::contract::ResourceDefinition,
        operations: &[CompiledOperation],
        _properties: &[CompiledProperty],
        _root: &str,
    ) {
        use crate::contract::Visibility;

        let has_public = operations.iter().any(|operation| {
            operation
                .access_profiles
                .iter()
                .any(|access_profile| matches!(access_profile.access, CompiledAccess::Public))
        });
        for (name, visibility) in [
            ("resources", self.contract.metadata_visibility.resources),
            ("semantics", self.contract.metadata_visibility.semantics),
        ] {
            if visibility == Visibility::OperatorOnly
                || (has_public && visibility != Visibility::Public)
            {
                self.error(
                    "metadata.reference_visibility_invalid",
                    &format!("metadataVisibility.{name}"),
                    "every Record audience must be able to resolve its resource and semantic references",
                );
            }
        }
        // Classification and processing artifacts are projected per finite
        // access profile. A protected access profile is operation-bound even
        // when a public sibling permits public metadata for its own profile.
    }

    fn validate_processing(
        &mut self,
        resource: &crate::contract::ResourceDefinition,
        operations: &[CompiledOperation],
        root: &str,
    ) {
        let mut ids = HashSet::new();
        for (index, processing) in resource.processing_descriptions.iter().enumerate() {
            let location = format!("{root}.processingDescriptions[{index}]");
            if !ids.insert(processing.id.as_str()) {
                self.error(
                    "processing.id_duplicate",
                    &location,
                    "processing description identifiers must be unique",
                );
            }
            if !valid_kebab_identifier(&processing.id)
                || processing.purpose.trim().is_empty()
                || processing.recipient_class.trim().is_empty()
                || processing.safeguards.is_empty()
                || has_duplicates(&processing.safeguards)
                || !valid_relative_reference(&processing.legal_basis_ref)
                || !valid_relative_reference(&processing.dpv_profile_ref)
            {
                self.error(
                    "processing.description_invalid",
                    &location,
                    "processing descriptions require stable identifiers, contained governance references, and reviewed safeguards",
                );
            }
            if processing.operation_refs.is_empty() || has_duplicates(&processing.operation_refs) {
                self.error(
                    "processing.operations_invalid",
                    &format!("{location}.operationRefs"),
                    "processing descriptions require a duplicate-free operation set",
                );
            }
            for reference in &processing.operation_refs {
                let present = operations.iter().any(|operation| match &operation.kind {
                    OperationKind::List => reference == "list",
                    OperationKind::Read => reference == "read",
                    OperationKind::Lookup { name } => reference == &format!("lookup:{name}"),
                    OperationKind::Search { name } => reference == &format!("search:{name}"),
                });
                if !present {
                    self.error(
                        "processing.operation_unknown",
                        &format!("{location}.operationRefs"),
                        "a processing sidecar names no compiled operation",
                    );
                }
            }
        }
    }

    fn validate_review_status(
        &mut self,
        classification: &EffectiveClassification,
        location: &str,
        column: Option<&str>,
    ) {
        if classification.status != ReviewStatus::Reviewed {
            let detail = column
                .map(|column| format!(" for source column '{column}'"))
                .unwrap_or_default();
            match self.profile {
                CompileProfile::Authoring => self.warning(
                    "classification.unreviewed",
                    location,
                    &format!("classification suggestions require institutional review{detail}"),
                ),
                CompileProfile::Production => self.error(
                    "classification.unreviewed",
                    location,
                    &format!("production compilation requires reviewed classification{detail}"),
                ),
            }
        }
    }

    fn validate_observed_source_closure(&mut self) {
        for source in self.observed.keys().copied().collect::<Vec<_>>() {
            if self.contract.sources.get(source).is_none() {
                self.error(
                    "source.observation_unknown",
                    "observed-schema",
                    "an observed schema does not belong to a governed source",
                );
            }
        }
    }

    fn error(&mut self, code: &str, location: &str, message: &str) {
        self.report.diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: code.into(),
            location: location.into(),
            message: message.into(),
        });
    }

    fn warning(&mut self, code: &str, location: &str, message: &str) {
        self.report.diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Warning,
            code: code.into(),
            location: location.into(),
            message: message.into(),
        });
    }
}

fn revision<T: Serialize>(value: &T) -> Result<String, ()> {
    let json = serde_json::to_value(value).map_err(|_| ())?;
    let canonical = canonicalize_json(&json).map_err(|_| ())?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(canonical))))
}

/// Digest the non-circular inventory an institutional classification review
/// accepts. Contract revisions, governed file bytes, and review metadata are
/// deliberately absent; processed source columns, governed properties, query
/// uses, and finite access profile disclosures are present.
pub fn classification_inventory_digest(
    registry: &CompiledRegistry,
) -> Result<String, CompileReport> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Inventory<'a> {
        registry_identifier: &'a str,
        sources: Vec<SourceInventory<'a>>,
        resources: Vec<ResourceInventory<'a>>,
        statistical_datasets: Vec<StatisticalDatasetInventory<'a>>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SourceInventory<'a> {
        id: &'a str,
        profile: SourceProfile,
        expected_schema_fingerprint: &'a str,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ResourceInventory<'a> {
        id: &'a str,
        source: &'a str,
        view: &'a str,
        record_context: RecordContextInventory<'a>,
        properties: Vec<PropertyInventory<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        primary_geometry: Option<&'a str>,
        column_accounting: Vec<ColumnInventory<'a>>,
        disclosure_profiles: Vec<DisclosureInventory<'a>>,
        operations: Vec<OperationInventory<'a>>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct RecordContextInventory<'a> {
        record_identifier_column: &'a str,
        revision_identifier_column: &'a str,
        lifecycle_state_column: &'a str,
        lifecycle_state_codelist: &'a str,
        recorded_at_column: &'a str,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PropertyInventory<'a> {
        name: &'a str,
        #[serde(flatten)]
        binding: PropertyBindingInventory<'a>,
        source_required: bool,
        semantic_iri: &'a str,
        classification: &'a EffectiveClassification,
    }

    #[derive(Serialize)]
    #[serde(untagged)]
    enum PropertyBindingInventory<'a> {
        Scalar {
            #[serde(rename = "sourceColumn")]
            source_column: &'a str,
            transform: Option<&'a CompiledTransform>,
            #[serde(rename = "dataType")]
            data_type: DataType,
            codelist: Option<&'a str>,
        },
        Point {
            kind: &'static str,
            crs: &'a str,
            #[serde(rename = "longitudeColumn")]
            longitude_column: &'a str,
            #[serde(rename = "latitudeColumn")]
            latitude_column: &'a str,
        },
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ColumnInventory<'a> {
        column: &'a str,
        uses: &'a [ColumnUse],
        classification: &'a EffectiveClassification,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DisclosureInventory<'a> {
        id: &'a str,
        properties: &'a [String],
        maximum_handling: Handling,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OperationInventory<'a> {
        kind: &'a OperationKind,
        default_access_profile: &'a str,
        access_profiles: Vec<AccessProfileInventory<'a>>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AccessProfileInventory<'a> {
        id: &'a str,
        access: &'a CompiledAccess,
        disclosure_profile: &'a str,
        selectable_properties: &'a [String],
        projected_columns: &'a [String],
        processing_handling: Handling,
        disclosure_handling: Handling,
        transform_inventory: &'a [String],
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct StatisticalDatasetInventory<'a> {
        id: &'a str,
        source: &'a str,
        view: &'a str,
        dimensions: Vec<StatisticalComponentInventory<'a>>,
        time: StatisticalTimeInventory<'a>,
        measure: StatisticalComponentInventory<'a>,
        attributes: Vec<StatisticalAttributeInventory<'a>>,
        access: &'a CompiledAccess,
        processing_handling: Handling,
        disclosure_handling: Handling,
        column_accounting: Vec<ColumnInventory<'a>>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct StatisticalComponentInventory<'a> {
        id: &'a str,
        source_column: &'a str,
        data_type: StatisticalValueType,
        codelist: Option<&'a str>,
        semantic_iri: &'a str,
        classification: &'a EffectiveClassification,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct StatisticalTimeInventory<'a> {
        id: &'a str,
        source_column: &'a str,
        granularity: crate::contract::StatisticalTimeGranularity,
        semantic_iri: &'a str,
        classification: &'a EffectiveClassification,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct StatisticalAttributeInventory<'a> {
        #[serde(flatten)]
        component: StatisticalComponentInventory<'a>,
        source_required: bool,
    }

    let inventory = Inventory {
        registry_identifier: &registry.registry_identifier,
        sources: registry
            .sources
            .iter()
            .map(|source| SourceInventory {
                id: &source.id,
                profile: source.profile,
                expected_schema_fingerprint: &source.expected_schema_fingerprint,
            })
            .collect(),
        resources: registry
            .resources
            .iter()
            .map(|resource| ResourceInventory {
                id: &resource.id,
                source: &resource.source,
                view: &resource.view,
                record_context: RecordContextInventory {
                    record_identifier_column: &resource.record_context.record_identifier_column,
                    revision_identifier_column: &resource.record_context.revision_identifier_column,
                    lifecycle_state_column: &resource.record_context.lifecycle_state_column,
                    lifecycle_state_codelist: &resource.record_context.lifecycle_state_codelist,
                    recorded_at_column: &resource.record_context.recorded_at_column,
                },
                properties: resource
                    .properties
                    .iter()
                    .map(|property| {
                        let binding = match &property.binding {
                            CompiledPropertyBinding::Scalar(binding) => {
                                PropertyBindingInventory::Scalar {
                                    source_column: &binding.source_column,
                                    transform: binding.transform.as_ref(),
                                    data_type: binding.data_type,
                                    codelist: binding.codelist.as_deref(),
                                }
                            }
                            CompiledPropertyBinding::Point(binding) => {
                                PropertyBindingInventory::Point {
                                    kind: "point",
                                    crs: &binding.crs,
                                    longitude_column: &binding.longitude_column,
                                    latitude_column: &binding.latitude_column,
                                }
                            }
                        };
                        PropertyInventory {
                            name: &property.name,
                            binding,
                            source_required: property.source_required,
                            semantic_iri: &property.semantic_iri,
                            classification: &property.classification,
                        }
                    })
                    .collect(),
                primary_geometry: resource.primary_geometry.as_deref(),
                column_accounting: resource
                    .column_accounting
                    .iter()
                    .map(|column| ColumnInventory {
                        column: &column.column,
                        uses: &column.uses,
                        classification: &column.classification,
                    })
                    .collect(),
                disclosure_profiles: resource
                    .disclosure_profiles
                    .iter()
                    .map(|disclosure| DisclosureInventory {
                        id: &disclosure.id,
                        properties: &disclosure.properties,
                        maximum_handling: disclosure.maximum_handling,
                    })
                    .collect(),
                operations: resource
                    .operations
                    .iter()
                    .map(|operation| OperationInventory {
                        kind: &operation.kind,
                        default_access_profile: &operation.default_access_profile,
                        access_profiles: operation
                            .access_profiles
                            .iter()
                            .map(|access_profile| AccessProfileInventory {
                                id: &access_profile.id,
                                access: &access_profile.access,
                                disclosure_profile: &access_profile.disclosure_profile,
                                selectable_properties: &access_profile.selectable_properties,
                                projected_columns: &access_profile.projected_columns,
                                processing_handling: access_profile.processing_handling,
                                disclosure_handling: access_profile.disclosure_handling,
                                transform_inventory: &access_profile.transform_inventory,
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
        statistical_datasets: registry
            .statistical_datasets
            .iter()
            .map(|dataset| StatisticalDatasetInventory {
                id: &dataset.id,
                source: &dataset.source,
                view: &dataset.view,
                dimensions: dataset
                    .dimensions
                    .iter()
                    .map(|component| StatisticalComponentInventory {
                        id: &component.id,
                        source_column: &component.source_column,
                        data_type: component.data_type,
                        codelist: component.codelist.as_deref(),
                        semantic_iri: &component.semantic_iri,
                        classification: &component.classification,
                    })
                    .collect(),
                time: StatisticalTimeInventory {
                    id: &dataset.time.id,
                    source_column: &dataset.time.source_column,
                    granularity: dataset.time.granularity,
                    semantic_iri: &dataset.time.semantic_iri,
                    classification: &dataset.time.classification,
                },
                measure: StatisticalComponentInventory {
                    id: &dataset.measure.id,
                    source_column: &dataset.measure.source_column,
                    data_type: dataset.measure.data_type,
                    codelist: None,
                    semantic_iri: &dataset.measure.semantic_iri,
                    classification: &dataset.measure.classification,
                },
                attributes: dataset
                    .attributes
                    .iter()
                    .map(|component| StatisticalAttributeInventory {
                        component: StatisticalComponentInventory {
                            id: &component.id,
                            source_column: &component.source_column,
                            data_type: component.data_type,
                            codelist: component.codelist.as_deref(),
                            semantic_iri: &component.semantic_iri,
                            classification: &component.classification,
                        },
                        source_required: component.source_required,
                    })
                    .collect(),
                access: &dataset.access,
                processing_handling: dataset.processing_handling,
                disclosure_handling: dataset.disclosure_handling,
                column_accounting: dataset
                    .column_accounting
                    .iter()
                    .map(|column| ColumnInventory {
                        column: &column.column,
                        uses: &column.uses,
                        classification: &column.classification,
                    })
                    .collect(),
            })
            .collect(),
    };
    revision(&inventory).map_err(|()| CompileReport {
        diagnostics: vec![Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "classification.inventory_canonicalization_failed".into(),
            location: "classifications.provenanceRef".into(),
            message: "the classification inventory could not be canonicalized".into(),
        }],
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CodelistDocument {
    id: String,
    version: serde_json::Value,
    values: Vec<String>,
    #[serde(default)]
    status: Option<ReviewStatus>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SemanticAlignmentDocument {
    schema_version: String,
    profile: String,
    profile_version: String,
    #[serde(default)]
    profile_digest: Option<String>,
    status: String,
    mappings: Vec<SemanticMapping>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticMapping {
    local: String,
    external: String,
    relation: String,
}

fn parse_classification_review(
    contract: &RegistryContract,
    files: &GovernedFileSet,
    profile: CompileProfile,
    registry: &CompiledRegistry,
    report: &mut CompileReport,
) -> Option<CompiledClassificationReview> {
    let path = &contract.classifications.provenance_ref;
    let content = files.get(path)?;
    let document = match crate::identification::parse_classification_review_yaml(content) {
        Ok(document) => document,
        Err(_) => {
            review_diagnostic(
                report,
                profile,
                "classification.review_invalid",
                path,
                "the classification review is not valid strict governed YAML",
            );
            return None;
        }
    };
    let inventory_digest = match classification_inventory_digest(registry) {
        Ok(digest) => digest,
        Err(failure) => {
            report.diagnostics.extend(failure.diagnostics);
            return None;
        }
    };
    let mut expected_bytes = None;
    let expected_generated = if document.method == IdentificationMethod::Generated {
        crate::identification::identify_contract(contract, &observed_schemas(registry))
            .ok()
            .and_then(|expected_report| {
                let bytes =
                    crate::identification::render_identification_report(&expected_report).ok()?;
                let report_digest =
                    crate::identification::identification_report_digest(&expected_report).ok()?;
                let rule_pack = crate::identification::core_pack_reference().ok()?;
                expected_bytes = Some(bytes);
                Some(crate::contract::GeneratedIdentificationBinding {
                    report_ref: crate::identification::REVIEWED_IDENTIFICATION_REPORT_PATH.into(),
                    report_digest,
                    rule_pack,
                })
            })
    } else {
        None
    };
    let expectation = crate::identification::ClassificationReviewExpectation {
        registry_identifier: contract.registry.registry_identifier.clone(),
        classification_inventory_digest: inventory_digest,
        generated_identification: expected_generated,
    };
    let validation = crate::identification::validate_classification_review(&document, &expectation);
    let mut accepted = validation.is_valid();
    for diagnostic in validation.diagnostics {
        review_diagnostic(
            report,
            profile,
            &diagnostic.code,
            &format!("{path}:{}", diagnostic.location),
            &diagnostic.message,
        );
    }
    if document.status == ReviewStatus::Reviewed
        && document.method == IdentificationMethod::Generated
    {
        let actual = document
            .generated_identification
            .as_ref()
            .and_then(|binding| files.get(&binding.report_ref));
        if actual
            .zip(expected_bytes.as_ref())
            .is_none_or(|(actual, expected)| actual != expected)
        {
            accepted = false;
            review_diagnostic(
                report,
                profile,
                "classification.review_identification_report_mismatch",
                path,
                "the governed identification report bytes do not match independent recomputation",
            );
        }
    }
    let generated_identification = document.generated_identification.as_ref().map(|binding| {
        CompiledGeneratedIdentificationBinding {
            report_ref: binding.report_ref.clone(),
            report_digest: binding.report_digest.clone(),
            rule_pack_id: binding.rule_pack.id.clone(),
            rule_pack_version: binding.rule_pack.version.clone(),
            rule_pack_digest: binding.rule_pack.digest.clone(),
        }
    });
    accepted.then_some(CompiledClassificationReview {
        registry_identifier: document.registry_identifier,
        classification_inventory_digest: document.classification_inventory_digest,
        method: document.method,
        reviewer: document.reviewer,
        review_date: document.review_date,
        status: document.status,
        rationale_ref: document.rationale_ref,
        generated_identification,
    })
}

fn review_diagnostic(
    report: &mut CompileReport,
    profile: CompileProfile,
    code: &str,
    location: &str,
    message: &str,
) {
    report.diagnostics.push(Diagnostic {
        severity: if profile == CompileProfile::Production {
            DiagnosticSeverity::Error
        } else {
            DiagnosticSeverity::Warning
        },
        code: code.into(),
        location: location.into(),
        message: message.into(),
    });
}

fn observed_schemas(registry: &CompiledRegistry) -> Vec<ObservedSourceSchema> {
    registry
        .sources
        .iter()
        .filter_map(|source| source.observed_schema.clone())
        .collect()
}

fn validate_governed_files(
    contract: &RegistryContract,
    files: &GovernedFileSet,
    profile: CompileProfile,
    registry: &CompiledRegistry,
) -> (
    Vec<CompiledCodelist>,
    BTreeMap<String, String>,
    Option<CompiledClassificationReview>,
    CompileReport,
) {
    let mut report = CompileReport {
        diagnostics: Vec::new(),
    };
    let total_bytes = files
        .values()
        .try_fold(0_usize, |total, content| total.checked_add(content.len()));
    if files.len() > 256 || total_bytes.is_none_or(|total| total > 16 * 1024 * 1024) {
        report.diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "contract.governed_closure_bound".into(),
            location: "governed".into(),
            message: "the governed file closure exceeds its file or byte bound".into(),
        });
        return (Vec::new(), BTreeMap::new(), None, report);
    }
    let mut codelist_paths = BTreeSet::new();
    let mut statistical_codelist_paths = BTreeSet::new();
    let mut sidecar_paths = BTreeSet::new();
    sidecar_paths.insert(contract.registry.identifier_lifecycle_policy_ref.as_str());
    sidecar_paths.insert(contract.classifications.provenance_ref.as_str());
    for alignment in &contract.semantics.alignments {
        sidecar_paths.insert(alignment.profile_ref.as_str());
    }
    for resource in &contract.resources {
        codelist_paths.insert(resource.record_context.lifecycle_state.codelist.as_str());
        for (_, property) in resource.properties.iter() {
            if let Some(codelist) = property
                .scalar_binding()
                .and_then(|binding| binding.codelist.as_deref())
            {
                codelist_paths.insert(codelist);
            }
        }
        for lookup in &resource.operations.lookups {
            for (_, selector) in lookup.request_body.selectors.iter() {
                if let Some(codelist) = selector.codelist.as_deref() {
                    codelist_paths.insert(codelist);
                }
            }
        }
        for processing in &resource.processing_descriptions {
            sidecar_paths.insert(processing.legal_basis_ref.as_str());
            sidecar_paths.insert(processing.dpv_profile_ref.as_str());
        }
    }
    for dataset in &contract.statistical_datasets {
        for (_, dimension) in dataset.dimensions.iter() {
            if let Some(codelist) = dimension.vocabulary.as_deref() {
                codelist_paths.insert(codelist);
                statistical_codelist_paths.insert(codelist);
            }
        }
        for (_, attribute) in dataset.attributes.iter() {
            if let Some(codelist) = attribute.vocabulary.as_deref() {
                codelist_paths.insert(codelist);
                statistical_codelist_paths.insert(codelist);
            }
        }
        for processing in &dataset.processing_descriptions {
            sidecar_paths.insert(processing.legal_basis_ref.as_str());
            sidecar_paths.insert(processing.dpv_profile_ref.as_str());
        }
    }
    if codelist_paths.contains(contract.registry.identifier_lifecycle_policy_ref.as_str()) {
        report.diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "contract.governed_file_role_collision".into(),
            location: contract.registry.identifier_lifecycle_policy_ref.clone(),
            message:
                "one governed file cannot be both the identifier-lifecycle policy and a codelist"
                    .into(),
        });
    }
    let classification_review =
        parse_classification_review(contract, files, profile, registry, &mut report);
    if let Some(review) = &classification_review {
        sidecar_paths.insert(review.rationale_ref.as_str());
        if let Some(generated) = &review.generated_identification {
            sidecar_paths.insert(generated.report_ref.as_str());
        }
    }
    let expected = sidecar_paths
        .iter()
        .chain(codelist_paths.iter())
        .copied()
        .collect::<BTreeSet<_>>();
    for path in files.keys() {
        if !expected.contains(path.as_str()) {
            report.diagnostics.push(Diagnostic {
                severity: if profile == CompileProfile::Authoring {
                    DiagnosticSeverity::Warning
                } else {
                    DiagnosticSeverity::Error
                },
                code: "contract.governed_file_unknown".into(),
                location: path.clone(),
                message: "the governed closure contains an unreferenced file".into(),
            });
        }
    }
    let mut file_digests = BTreeMap::new();
    for path in &expected {
        let Some(content) = files.get(*path) else {
            report.diagnostics.push(Diagnostic {
                severity: if profile == CompileProfile::Authoring
                    && *path == contract.classifications.provenance_ref
                {
                    DiagnosticSeverity::Warning
                } else {
                    DiagnosticSeverity::Error
                },
                code: "contract.governed_file_missing".into(),
                location: (*path).into(),
                message: "a referenced governed file is absent from the captured closure".into(),
            });
            continue;
        };
        file_digests.insert((*path).into(), digest(content));
        if *path != contract.classifications.provenance_ref
            && !codelist_paths.contains(path)
            && !contract
                .semantics
                .alignments
                .iter()
                .any(|alignment| alignment.profile_ref == **path)
            && serde_norway::from_slice::<serde_norway::Value>(content).is_err()
        {
            report.diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "contract.governance_yaml_invalid".into(),
                location: (*path).into(),
                message: "a governance sidecar is not valid YAML".into(),
            });
        }
    }
    let mut codelists = Vec::new();
    for path in codelist_paths {
        let Some(content) = files.get(path) else {
            continue;
        };
        let document = match serde_norway::from_slice::<CodelistDocument>(content) {
            Ok(document) => document,
            Err(_) => {
                report.diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "codelist.yaml_invalid".into(),
                    location: path.into(),
                    message: "a codelist is not valid strict YAML".into(),
                });
                continue;
            }
        };
        let version = scalar_text(&document.version);
        let mut values = HashSet::new();
        if document.id.trim().is_empty()
            || version.is_none()
            || document.values.is_empty()
            || document
                .values
                .iter()
                .any(|value| value.trim().is_empty() || !values.insert(value.as_str()))
        {
            report.diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "codelist.content_invalid".into(),
                location: path.into(),
                message:
                    "codelists require an identifier, scalar version, and unique non-empty values"
                        .into(),
            });
            continue;
        }
        if statistical_codelist_paths.contains(path)
            && document
                .values
                .iter()
                .any(|value| !valid_sdmx_code_value(value))
        {
            report.diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "sdmx.codelist_value_invalid".into(),
                location: path.into(),
                message: "statistical codelist values must use the bounded SDMX code profile"
                    .into(),
            });
            continue;
        }
        if profile == CompileProfile::Production && document.status != Some(ReviewStatus::Reviewed)
        {
            report.diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "codelist.unreviewed".into(),
                location: path.into(),
                message: "production codelists must be institutionally reviewed".into(),
            });
            continue;
        }
        codelists.push(CompiledCodelist {
            path: path.into(),
            id: document.id,
            version: version.expect("validated scalar version"),
            values: document.values,
        });
    }
    for alignment in &contract.semantics.alignments {
        let Some(content) = files.get(&alignment.profile_ref) else {
            continue;
        };
        if digest(content) != alignment.digest {
            report.diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "semantics.alignment_digest_mismatch".into(),
                location: alignment.profile_ref.clone(),
                message: "the semantic alignment file does not match its governed digest".into(),
            });
            continue;
        }
        let document = match serde_norway::from_slice::<SemanticAlignmentDocument>(content) {
            Ok(document) => document,
            Err(_) => {
                report.diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "semantics.alignment_yaml_invalid".into(),
                    location: alignment.profile_ref.clone(),
                    message: "the semantic alignment is not valid strict YAML".into(),
                });
                continue;
            }
        };
        let valid_document = document
            .schema_version
            .starts_with("relay.registrystack.org/semantic-alignment/")
            && valid_absolute_url(&document.profile)
            && !document.profile_version.trim().is_empty()
            && document.profile_digest.as_deref().is_none_or(valid_sha256)
            && !document.status.trim().is_empty()
            && !document.mappings.is_empty()
            && document.mappings.iter().all(|mapping| {
                expand_local_term(&contract.semantics.local_vocabulary, &mapping.local).is_some()
                    && valid_absolute_url(&mapping.external)
                    && matches!(
                        mapping.relation.as_str(),
                        "exact" | "close" | "broad" | "narrow" | "related"
                    )
            });
        if !valid_document {
            report.diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "semantics.alignment_content_invalid".into(),
                location: alignment.profile_ref.clone(),
                message: "the semantic alignment is incomplete or contains an unsupported relation"
                    .into(),
            });
        }
    }
    codelists.sort_by(|left, right| left.path.cmp(&right.path));
    (codelists, file_digests, classification_review, report)
}

fn digest(content: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(content)))
}

fn scalar_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn effective_classification(
    contract: &RegistryContract,
    defaults: &ClassificationPartial,
    explicit: Option<&ClassificationPartial>,
) -> Option<EffectiveClassification> {
    let explicit = explicit.cloned().unwrap_or_default();
    Some(EffectiveClassification {
        privacy: explicit.privacy.or_else(|| defaults.privacy.clone())?,
        privacy_scheme: contract.classifications.privacy.scheme.clone(),
        privacy_version: contract.classifications.privacy.version.clone(),
        institutional: explicit
            .institutional
            .or_else(|| defaults.institutional.clone())?,
        institutional_scheme: contract.classifications.institutional.scheme.clone(),
        institutional_version: contract.classifications.institutional.version.clone(),
        handling: explicit.handling.or(defaults.handling)?,
        handling_scheme: contract.classifications.handling.scheme.clone(),
        handling_version: contract.classifications.handling.version.clone(),
        status: explicit.status.or(defaults.status)?,
        provenance_ref: contract.classifications.provenance_ref.clone(),
    })
}

fn classification_to_partial(value: &EffectiveClassification) -> ClassificationPartial {
    ClassificationPartial {
        privacy: Some(value.privacy.clone()),
        institutional: Some(value.institutional.clone()),
        handling: Some(value.handling),
        status: Some(value.status),
    }
}

fn explicit_reviewed_classification(value: &ClassificationPartial) -> bool {
    value
        .privacy
        .as_deref()
        .is_some_and(|item| !item.trim().is_empty())
        && value
            .institutional
            .as_deref()
            .is_some_and(|item| !item.trim().is_empty())
        && value.handling.is_some()
        && value.status == Some(ReviewStatus::Reviewed)
}

/// Locates a column-accounting diagnostic about one accounted column. When the
/// resource or dataset authored a source-column classification entry for the
/// column, the location targets that entry, or one of its fields; otherwise
/// the column's classification came entirely from `classificationDefaults`,
/// so the location targets that always-authored field instead, since no
/// `sourceColumnClassifications` entry names the column in the authored
/// document.
fn column_accounting_location(
    root: &str,
    column: &str,
    source_override: Option<&ClassificationPartial>,
    field: Option<&str>,
) -> String {
    match source_override {
        Some(_) => match field {
            Some(field) => format!("{root}.sourceColumnClassifications.{column}.{field}"),
            None => format!("{root}.sourceColumnClassifications.{column}"),
        },
        None => format!("{root}.classificationDefaults"),
    }
}

fn validate_disclosure_access(
    report: &mut CompileReport,
    disclosure: &CompiledDisclosureProfile,
    access: &CompiledAccess,
    is_list: bool,
    location: &str,
) {
    if disclosure.maximum_handling > Handling::Public && matches!(access, CompiledAccess::Public) {
        report.diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "disclosure.public_nonpublic_forbidden".into(),
            location: location.into(),
            message: "public operations may disclose only public handling data".into(),
        });
    }
    if disclosure.maximum_handling == Handling::Restricted && is_list {
        report.diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "disclosure.restricted_list_forbidden".into(),
            location: location.into(),
            message: "restricted properties cannot be disclosed by a list operation".into(),
        });
    }
}

fn projected_columns(
    resource: &crate::contract::ResourceDefinition,
    properties: &[CompiledProperty],
    disclosure: &[String],
) -> Vec<String> {
    let mut columns = Vec::new();
    for column in [
        &resource.record_context.record_identifier.source_column,
        &resource.record_context.revision_identifier.source_column,
        &resource.record_context.lifecycle_state.source_column,
        &resource.record_context.recorded_at.source_column,
    ] {
        push_unique(&mut columns, column);
    }
    // Only the selected finite access profile may widen the Registry Core
    // projection. This is what lets a public access profile prove that it
    // never processes a hidden non-public source column.
    for name in disclosure {
        if let Some(property) = properties.iter().find(|property| property.name == *name) {
            for source_column in property.source_columns() {
                push_unique(&mut columns, source_column);
            }
        }
    }
    columns
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|candidate| candidate == value) {
        values.push(value.to_owned());
    }
}

fn validate_codelist(
    report: &mut CompileReport,
    data_type: DataType,
    codelist: Option<&str>,
    location: &str,
) {
    let valid = match data_type {
        DataType::ControlledCode => codelist.is_some_and(|value| !value.trim().is_empty()),
        _ => codelist.is_none(),
    };
    if !valid {
        report.diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "datatype.codelist_invalid".into(),
            location: location.into(),
            message: "controlled-code requires one codelist and other types forbid it".into(),
        });
    }
}

fn require_nonempty(report: &mut CompileReport, value: &str, code: &str, location: &str) {
    if value.trim().is_empty() {
        report.diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: code.into(),
            location: location.into(),
            message: "a required governed identifier is empty".into(),
        });
    }
}

fn column_exists(columns: Option<&BTreeSet<&str>>, column: &str) -> bool {
    columns.is_none_or(|columns| columns.contains(column))
}

fn observed_column<'a>(
    view: Option<&'a crate::model::ObservedView>,
    column: &str,
) -> Option<&'a crate::model::ObservedColumn> {
    view?.columns.iter().find(|item| item.name == column)
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn valid_absolute_url(value: &str) -> bool {
    Url::parse(value)
        .ok()
        .is_some_and(|url| matches!(url.scheme(), "http" | "https") && url.has_host())
}

fn valid_artifact_base_url(value: &str) -> bool {
    Url::parse(value).ok().is_some_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn valid_turtle_iri(value: &str) -> bool {
    valid_absolute_url(value)
        && !value.chars().any(|character| {
            character <= '\u{20}'
                || matches!(
                    character,
                    '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`' | '\\'
                )
        })
}

fn valid_global_identifier(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix("urn:") {
        return !rest.is_empty() && !rest.chars().any(char::is_whitespace);
    }
    valid_absolute_url(value)
}

fn valid_relative_reference(value: &str) -> bool {
    let path = Path::new(value);
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn valid_sql_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_sdmx_ncname_segment(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_sdmx_agency_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.split('.').all(valid_sdmx_ncname_segment)
}

fn valid_sdmx_maintainable_id(value: &str) -> bool {
    value.len() <= 128 && valid_sdmx_ncname_segment(value)
}

fn valid_sdmx_component_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_uppercase())
        && value.len() <= 128
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_sdmx_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    value.len() <= MAXIMUM_ROUTE_IDENTIFIER_BYTES
        && parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == &"0" || !part.starts_with('0'))
        })
}

fn valid_sdmx_code_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_SDMX_COMPONENT_VALUE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'@' | b'$' | b'-'))
}

fn to_sdmx_id(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase() && !output.is_empty() && !output.ends_with('_') {
                output.push('_');
            }
            output.push(character.to_ascii_uppercase());
        } else if !output.is_empty() && !output.ends_with('_') {
            output.push('_');
        }
    }
    output.trim_end_matches('_').to_owned()
}

fn compatible_sdmx_declared_type(
    data_type: StatisticalValueType,
    declared_type: Option<&str>,
) -> bool {
    let Some(declared_type) = declared_type else {
        return true;
    };
    match data_type {
        StatisticalValueType::Boolean | StatisticalValueType::Integer => {
            sqlite_declared_type_affinity(declared_type) == SqliteTypeAffinity::Integer
                || declared_type.trim().eq_ignore_ascii_case("BOOLEAN")
        }
        StatisticalValueType::Decimal => has_sqlite_numeric_affinity(declared_type),
        StatisticalValueType::Code | StatisticalValueType::String => {
            has_sqlite_text_affinity(declared_type)
        }
    }
}

fn compatible_sdmx_time_declared_type(declared_type: Option<&str>) -> bool {
    declared_type.is_none_or(has_sqlite_text_affinity)
}

fn compatible_declared_type(data_type: DataType, declared_type: &str) -> bool {
    let affinity = sqlite_declared_type_affinity(declared_type);
    match data_type {
        // Relay's boolean and integer runtime shapes are both backed by exact
        // SQLite INTEGER values. The canonical BOOLEAN declaration is retained
        // as the one intentional NUMERIC-affinity exception for existing
        // governed schemas; arbitrary NUMERIC declarations remain incompatible.
        DataType::Boolean | DataType::Integer => {
            affinity == SqliteTypeAffinity::Integer
                || declared_type.trim().eq_ignore_ascii_case("BOOLEAN")
        }
        DataType::String
        | DataType::Date
        | DataType::DateTime
        | DataType::Year
        | DataType::YearMonth
        | DataType::ControlledCode => affinity == SqliteTypeAffinity::Text,
    }
}

fn has_sqlite_text_affinity(declared_type: &str) -> bool {
    sqlite_declared_type_affinity(declared_type) == SqliteTypeAffinity::Text
}

fn has_sqlite_numeric_affinity(declared_type: &str) -> bool {
    matches!(
        sqlite_declared_type_affinity(declared_type),
        SqliteTypeAffinity::Integer | SqliteTypeAffinity::Real | SqliteTypeAffinity::Numeric
    )
}

fn sqlite_declared_type_affinity(declared_type: &str) -> SqliteTypeAffinity {
    let declared = declared_type.trim().to_ascii_uppercase();
    // This order is SQLite's declared-type affinity algorithm. Precedence is
    // significant: for example, INTTEXT and CHARINT both have INTEGER affinity.
    if declared.contains("INT") {
        SqliteTypeAffinity::Integer
    } else if declared.contains("CHAR") || declared.contains("CLOB") || declared.contains("TEXT") {
        SqliteTypeAffinity::Text
    } else if declared.is_empty() || declared.contains("BLOB") {
        SqliteTypeAffinity::Blob
    } else if declared.contains("REAL") || declared.contains("FLOA") || declared.contains("DOUB") {
        SqliteTypeAffinity::Real
    } else {
        SqliteTypeAffinity::Numeric
    }
}

fn valid_scope_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

fn minimum_lookup_body_bytes<'a>(
    selectors: impl Iterator<Item = (&'a str, &'a crate::contract::SelectorDefinition)>,
) -> u64 {
    // `{"selectors":{` plus the two closing braces.
    let mut bytes = 16_u64;
    for (index, (name, selector)) in selectors.enumerate() {
        if index != 0 {
            bytes += 1; // comma
        }
        bytes += name.len() as u64 + 3; // quoted key and colon
        bytes += minimum_selector_json_bytes(selector);
    }
    bytes
}

fn minimum_selector_json_bytes(selector: &crate::contract::SelectorDefinition) -> u64 {
    match selector.data_type {
        DataType::String => u64::from(selector.minimum_bytes.unwrap_or(1)) + 2,
        DataType::ControlledCode => 3, // shortest possible non-empty string
        DataType::Boolean => 4,        // true
        DataType::Integer => 1,        // 0
        DataType::Date => 12,          // "1970-01-01"
        DataType::DateTime => 22,      // "1970-01-01T00:00:00Z"
        DataType::Year => 6,           // "1970"
        DataType::YearMonth => 9,      // "1970-01"
    }
}

fn validate_governed_lookup_body_bounds(
    contract: &RegistryContract,
    codelists: &[CompiledCodelist],
    report: &mut CompileReport,
) {
    let codelists = codelists
        .iter()
        .map(|codelist| (codelist.path.as_str(), codelist))
        .collect::<BTreeMap<_, _>>();
    for (resource_index, resource) in contract.resources.iter().enumerate() {
        for (lookup_index, lookup) in resource.operations.lookups.iter().enumerate() {
            if !lookup
                .request_body
                .selectors
                .iter()
                .any(|(_, selector)| selector.data_type == DataType::ControlledCode)
            {
                continue;
            }
            let location =
                format!("resources[{resource_index}].operations.lookups[{lookup_index}]");
            let mut minimum_body_bytes = 16_u64;
            let mut complete = true;
            for (selector_index, (name, selector)) in
                lookup.request_body.selectors.iter().enumerate()
            {
                if selector_index != 0 {
                    minimum_body_bytes += 1;
                }
                minimum_body_bytes += name.len() as u64 + 3;
                if selector.data_type != DataType::ControlledCode {
                    minimum_body_bytes += minimum_selector_json_bytes(selector);
                    continue;
                }
                let Some(path) = selector.codelist.as_deref() else {
                    complete = false;
                    continue;
                };
                let Some(codelist) = codelists.get(path) else {
                    complete = false;
                    continue;
                };
                let Some(minimum_value_bytes) = codelist
                    .values
                    .iter()
                    .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
                    .map(|value| {
                        serde_json::to_vec(value).expect("a string always serializes as JSON")
                    })
                    .map(|value| value.len() as u64)
                    .min()
                else {
                    report.diagnostics.push(Diagnostic {
                        severity: DiagnosticSeverity::Error,
                        code: "lookup.selector_codelist_unusable".into(),
                        location: format!(
                            "{location}.requestBody.selectors.{name}.codelist"
                        ),
                        message: "the selector codelist contains no runtime-acceptable controlled-code value".into(),
                    });
                    complete = false;
                    continue;
                };
                minimum_body_bytes += minimum_value_bytes;
            }
            if complete && u64::from(lookup.request_body.maximum_bytes) < minimum_body_bytes {
                report.diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "lookup.body_bound_too_small".into(),
                    location: format!("{location}.requestBody.maximumBytes"),
                    message: "the lookup request-body bound cannot contain the smallest runtime-acceptable JSON body for all required selectors".into(),
                });
            }
        }
    }
}

fn transform_source_type(transform: Option<&CompiledTransform>, output_type: DataType) -> DataType {
    match transform {
        Some(CompiledTransform::PartialString { .. }) => DataType::String,
        Some(CompiledTransform::DatePrecision {
            source_type: DateInputType::Date,
            ..
        }) => DataType::Date,
        Some(CompiledTransform::DatePrecision {
            source_type: DateInputType::DateTime,
            ..
        }) => DataType::DateTime,
        None => output_type,
    }
}

fn source_runtime_type(data_type: DataType) -> SourceRuntimeType {
    match data_type {
        DataType::Boolean => SourceRuntimeType::Boolean,
        DataType::Integer => SourceRuntimeType::Integer,
        DataType::String
        | DataType::Date
        | DataType::DateTime
        | DataType::Year
        | DataType::YearMonth
        | DataType::ControlledCode => SourceRuntimeType::Text,
    }
}

fn cursor_order_type_supported(data_type: DataType) -> bool {
    matches!(
        data_type,
        DataType::String
            | DataType::ControlledCode
            | DataType::Date
            | DataType::DateTime
            | DataType::Integer
            | DataType::Boolean
    )
}

fn validate_observed_schema(
    report: &mut CompileReport,
    schema: &ObservedSourceSchema,
    location: &str,
) {
    if !valid_sha256(&schema.fingerprint) {
        report.diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "source.observed_fingerprint_invalid".into(),
            location: location.into(),
            message: "the observed schema fingerprint is not a SHA-256 digest".into(),
        });
    }
    let mut views = HashSet::new();
    for view in &schema.views {
        if !views.insert(view.name.as_str()) || !valid_sql_identifier(&view.name) {
            report.diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "source.observed_view_invalid".into(),
                location: location.into(),
                message: "observed view identifiers must be unique simple SQLite identifiers"
                    .into(),
            });
        }
        let mut columns = HashSet::new();
        for column in &view.columns {
            if !columns.insert(column.name.as_str()) || !valid_sql_identifier(&column.name) {
                report.diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "source.observed_column_invalid".into(),
                    location: location.into(),
                    message: "observed column identifiers must be unique simple SQLite identifiers"
                        .into(),
                });
            }
        }
    }
}

fn expand_local_term(base: &str, term: &str) -> Option<String> {
    if let Some(local) = term.strip_prefix("local:") {
        if local.is_empty() || local.contains(|character: char| character.is_whitespace()) {
            return None;
        }
        let expanded = format!("{base}{local}");
        return valid_turtle_iri(&expanded).then_some(expanded);
    }
    valid_turtle_iri(term).then(|| term.to_owned())
}

fn artifact_url(base: &str, artifact_id: &str) -> String {
    Url::parse(base).map_or_else(
        |_| format!("{base}v2/artifacts/{artifact_id}"),
        |mut url| {
            if let Ok(mut segments) = url.path_segments_mut() {
                segments.pop_if_empty();
                segments.push("v2");
                segments.push("artifacts");
                segments.push(artifact_id);
            }
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        },
    )
}

fn operation_artifact_stem(resource: &str, kind: &OperationKind) -> String {
    match kind {
        OperationKind::List => format!("{resource}--list"),
        OperationKind::Read => format!("{resource}--read"),
        OperationKind::Lookup { name } => format!("{resource}--lookup-{name}"),
        OperationKind::Search { name } => format!("{resource}--search-{name}"),
    }
}

fn valid_camel_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_alphanumeric())
}

fn valid_kebab_identifier(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.contains("--")
}

fn valid_access_profile_identifier(value: &str) -> bool {
    value.len() <= MAXIMUM_ACCESS_PROFILE_IDENTIFIER_BYTES && valid_kebab_identifier(value)
}

fn valid_route_identifier(value: &str) -> bool {
    value.len() <= MAXIMUM_ROUTE_IDENTIFIER_BYTES && valid_kebab_identifier(value)
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = HashSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn suggested_data_type(declared_type: &str) -> DataType {
    let normalized = declared_type.to_ascii_uppercase();
    if normalized.contains("BOOL") {
        DataType::Boolean
    } else if normalized.contains("INT") {
        DataType::Integer
    } else {
        DataType::String
    }
}

fn to_camel_case(value: &str) -> String {
    let mut output = String::new();
    let mut upper = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            if output.is_empty() {
                output.push(character.to_ascii_lowercase());
            } else if upper {
                output.push(character.to_ascii_uppercase());
                upper = false;
            } else {
                output.push(character);
            }
        } else {
            upper = !output.is_empty();
        }
    }
    if output.is_empty() {
        "column".into()
    } else {
        output
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn publication_jurisdictions_are_bounded_before_artifact_generation() {
        let jurisdictions = |count| {
            (0..count)
                .map(|index| format!("https://example.invalid/jurisdictions/{index:03}"))
                .collect()
        };
        let mut contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        contract.publication = Some(crate::contract::Publication {
            jurisdictions: jurisdictions(MAXIMUM_PUBLICATION_JURISDICTIONS),
        });
        compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect("the shared profile boundary compiles");

        contract.publication = Some(crate::contract::Publication {
            jurisdictions: jurisdictions(MAXIMUM_PUBLICATION_JURISDICTIONS + 1),
        });
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("an over-bound publication must fail during compilation");
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "publication.jurisdictions_invalid"
                && diagnostic.location == "publication.jurisdictions"
        }));
    }

    #[test]
    fn publication_projection_fields_fail_during_compilation() {
        let invalid_fields = [
            (
                "publication.endpoint_invalid",
                "registry.baseUri",
                "public-http-endpoint",
            ),
            ("publication.title_invalid", "registry.name", "padded-title"),
            (
                "publication.description_invalid",
                "registry.authoritativeScope",
                "controlled-description",
            ),
        ];

        for (expected_code, expected_location, case) in invalid_fields {
            let mut contract =
                RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
            contract.publication = Some(crate::contract::Publication {
                jurisdictions: vec!["urn:example:jurisdiction".into()],
            });
            match case {
                "public-http-endpoint" => {
                    contract.registry.base_uri = "http://relay.example/registry/".into();
                }
                "padded-title" => contract.registry.name = " padded ".into(),
                "controlled-description" => {
                    contract.registry.authoritative_scope = "line\nbreak".into();
                }
                _ => unreachable!("closed test cases"),
            }

            let report =
                compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                    .expect_err("invalid Discovery publication fields fail compilation");
            assert!(report.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == expected_code && diagnostic.location == expected_location
            }));
        }
    }

    #[test]
    fn complete_publication_projection_bound_fails_during_compilation() {
        let mut contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        contract.publication = Some(crate::contract::Publication {
            jurisdictions: vec!["urn:example:jurisdiction".into()],
        });
        contract.registry.name = "n".repeat(registry_discovery_profile::MAX_STRING_CHARACTERS);
        contract.registry.authoritative_scope =
            "s".repeat(registry_discovery_profile::MAX_STRING_CHARACTERS);
        let template = contract.resources[0].clone();
        contract.resources = (0..MAXIMUM_RESOURCES)
            .map(|index| {
                let mut resource = template.clone();
                resource.id = format!("resource-{index:03}");
                resource.semantic_class =
                    format!("https://example.invalid/semantic-class/{index:03}");
                resource
            })
            .collect();

        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("an over-bound complete publication must fail during compilation");
        assert!(
            report.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == "publication.description_bound_exceeded"
                    && diagnostic.location == "publication"
            }),
            "unexpected diagnostics: {:?}",
            report.diagnostics
        );
    }

    #[test]
    fn starter_never_marks_classification_reviewed() {
        let schema = ObservedSourceSchema {
            source: "source".into(),
            fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            views: vec![crate::model::ObservedView {
                name: "registry_records".into(),
                columns: vec![crate::model::ObservedColumn {
                    name: "record_id".into(),
                    declared_type: "TEXT".into(),
                    nullable: false,
                    primary_key: false,
                }],
            }],
        };
        let starter = derive_starter(&schema, "registry_records").expect("view exists");
        assert_eq!(starter.columns[0].suggested_property, "recordId");
        assert_eq!(
            starter.columns[0].classification_status,
            ReviewStatus::Suggested
        );
    }

    #[test]
    fn field_and_resource_names_have_closed_syntax() {
        assert!(valid_camel_identifier("registrationStatus"));
        assert!(!valid_camel_identifier("registration_status"));
        assert!(!valid_camel_identifier("source.column"));
        assert!(valid_kebab_identifier("registered-business"));
        assert!(!valid_kebab_identifier("RegisteredBusiness"));
    }

    #[test]
    fn route_identifiers_cannot_compile_unreachable_paths() {
        let base = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        let boundary = "a".repeat(MAXIMUM_ROUTE_IDENTIFIER_BYTES);
        let oversized = "a".repeat(MAXIMUM_ROUTE_IDENTIFIER_BYTES + 1);
        assert!(valid_route_identifier(&boundary));
        assert!(!valid_route_identifier(&oversized));
        let version_boundary = format!("1.1.{}", "1".repeat(MAXIMUM_ROUTE_IDENTIFIER_BYTES - 4));
        let oversized_version = format!("1.1.{}", "1".repeat(MAXIMUM_ROUTE_IDENTIFIER_BYTES - 3));
        assert_eq!(version_boundary.len(), MAXIMUM_ROUTE_IDENTIFIER_BYTES);
        assert!(valid_sdmx_version(&version_boundary));
        assert!(!valid_sdmx_version(&oversized_version));

        let compile_value = |value| {
            let contract = serde_json::from_value::<RegistryContract>(value)
                .expect("strict generated contract");
            compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
        };
        let reports_code = |report: CompileReport, code: &str| {
            assert!(
                report
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == code),
                "missing diagnostic {code}: {:?}",
                report.diagnostics
            );
        };

        let mut boundary_resource = serde_json::to_value(&base).expect("contract serializes");
        *boundary_resource
            .pointer_mut("/resources/0/id")
            .expect("resource identifier") = serde_json::json!(boundary);
        compile_value(boundary_resource).expect("the route identifier ceiling compiles");

        let mut oversized_resource = serde_json::to_value(&base).expect("contract serializes");
        *oversized_resource
            .pointer_mut("/resources/0/id")
            .expect("resource identifier") = serde_json::json!(oversized.clone());
        reports_code(
            compile_value(oversized_resource).expect_err("oversized resource route is refused"),
            "resource.id_invalid",
        );

        let mut oversized_lookup = serde_json::to_value(&base).expect("contract serializes");
        oversized_lookup
            .pointer_mut("/resources/0/operations")
            .and_then(serde_json::Value::as_object_mut)
            .expect("operations object")
            .insert(
                "lookups".into(),
                serde_json::json!([{
                    "id": oversized.clone(),
                    "requestBody": {
                        "maximumBytes": 128,
                        "selectors": {
                            "name": {"sourceColumn": "name", "type": "string", "maximumBytes": 32}
                        }
                    },
                    "defaultAccessProfile": "public",
                    "accessProfiles": {
                        "public": {"access": "public", "disclosureProfile": "public"}
                    }
                }]),
            );
        reports_code(
            compile_value(oversized_lookup).expect_err("oversized lookup route is refused"),
            "operation.lookup_id_invalid",
        );

        let mut oversized_search = serde_json::to_value(&base).expect("contract serializes");
        oversized_search
            .pointer_mut("/resources/0/operations")
            .and_then(serde_json::Value::as_object_mut)
            .expect("operations object")
            .insert(
                "searches".into(),
                serde_json::json!([{
                    "id": oversized,
                    "query": {
                        "kind": "point-bbox",
                        "maximumLongitudeSpanDegrees": 2,
                        "maximumLatitudeSpanDegrees": 2
                    },
                    "defaultAccessProfile": "public",
                    "accessProfiles": {
                        "public": {"access": "public", "disclosureProfile": "public"}
                    },
                    "orderBy": ["name"],
                    "pagination": {"defaultPageSize": 10, "maximumPageSize": 100}
                }]),
            );
        reports_code(
            compile_value(oversized_search).expect_err("oversized search route is refused"),
            "operation.search_id_invalid",
        );
    }

    #[test]
    fn statistical_dataset_compiles_as_a_separate_fixed_profile() {
        let contract = RegistryContract::parse_yaml(statistical_contract())
            .expect("strict statistical contract");
        let roundtrip =
            serde_norway::to_string(&contract).expect("statistical contract serializes");
        assert_eq!(
            RegistryContract::parse_yaml(&roundtrip).expect("serialized contract parses"),
            contract
        );
        let authored_targets = contract.registry.alignment_targets.clone();
        let compiled = compile_contract(
            &contract,
            &[statistical_observed_schema()],
            CompileProfile::Production,
        )
        .expect("statistical contract compiles");

        assert!(compiled.resources.is_empty());
        assert_eq!(compiled.alignment_targets, authored_targets);
        let dataset = &compiled.statistical_datasets[0];
        assert_eq!(
            dataset.operation_identifier(),
            "labour-rates.statistics.read"
        );
        assert_eq!(dataset.source, "db");
        assert_eq!(dataset.view, "statistical_observations");
        assert_eq!(
            dataset
                .dimensions
                .iter()
                .map(|component| component.id.as_str())
                .collect::<Vec<_>>(),
            ["REF_AREA", "SEX"]
        );
        assert_eq!(dataset.time.id, "TIME_PERIOD");
        assert_eq!(
            dataset.time.granularity,
            crate::contract::StatisticalTimeGranularity::Annual
        );
        assert_eq!(dataset.measure.id, "OBS_VALUE");
        assert_eq!(dataset.attributes[0].id, "UNIT_MEASURE");
        assert_eq!(dataset.sdmx.rest_version, "2.2.2");
        assert_eq!(dataset.sdmx.data_json_version, "2.1.0");
        assert_eq!(dataset.sdmx.data_csv_version, "2.1.0");
        assert_eq!(dataset.sdmx.structure_json_version, "2.1.0");
        assert!(matches!(dataset.access, CompiledAccess::Public));
    }

    #[test]
    fn statistical_source_visibility_and_type_boundaries_fail_closed() {
        let compile = |yaml: &str| {
            let contract = RegistryContract::parse_yaml(yaml).expect("strict contract shape");
            compile_contract(
                &contract,
                &[statistical_observed_schema()],
                CompileProfile::Production,
            )
            .expect_err("unsupported statistical contract is refused")
        };
        for (yaml, code, location) in [
            (
                statistical_contract().replace("profile: snapshot", "profile: live-read-only"),
                "statistics.live_source_forbidden",
                "statisticalDatasets[0].source.source",
            ),
            (
                statistical_contract().replace(", statisticalDatasets: public", ""),
                "metadata.statistical_datasets_missing",
                "metadataVisibility.statisticalDatasets",
            ),
            (
                statistical_contract().replace(
                    "statisticalDatasets: public",
                    "statisticalDatasets: operator-only",
                ),
                "metadata.statistical_datasets_unresolvable",
                "metadataVisibility.statisticalDatasets",
            ),
            (
                statistical_contract()
                    .replace("releaseAt: 2026-08-10T00:00:00Z", "releaseAt: pending"),
                "statistics.release_at_invalid",
                "statisticalDatasets[0].publication.releaseAt",
            ),
            (
                statistical_contract()
                    .replace("maximumObservations: 100", "maximumObservations: 0"),
                "statistics.query_bound_invalid",
                "statisticalDatasets[0].query",
            ),
            (
                statistical_contract().replacen("type: code", "type: integer", 1),
                "statistics.dimension_type_invalid",
                "statisticalDatasets[0].dimensions.refArea.type",
            ),
            (
                statistical_contract().replace("type: decimal", "type: string"),
                "statistics.measure_invalid",
                "statisticalDatasets[0].measure",
            ),
        ] {
            let report = compile(&yaml);
            assert!(
                report.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == code && diagnostic.location == location
                }),
                "missing {code} at {location}: {report:?}"
            );
        }
    }

    #[test]
    fn resource_and_statistical_dataset_identifiers_share_one_namespace() {
        let mut contract =
            RegistryContract::parse_yaml(valid_contract()).expect("resource contract");
        let statistical =
            RegistryContract::parse_yaml(statistical_contract()).expect("statistical contract");
        contract.statistical_datasets = statistical.statistical_datasets;
        contract.statistical_datasets[0].id = contract.resources[0].id.clone();
        contract.metadata_visibility.statistical_datasets =
            Some(crate::contract::Visibility::Public);
        let mut observed = observed_schema();
        observed
            .views
            .push(statistical_observed_schema().views[0].clone());
        let report = compile_contract(&contract, &[observed], CompileProfile::Production)
            .expect_err("cross-surface identity collision is refused");
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "statistics.dataset_id_duplicate"
                && diagnostic.location == "statisticalDatasets[0].id"
        }));
    }

    #[test]
    fn statistical_codelists_use_the_runtime_sdmx_code_profile() {
        let contract = RegistryContract::parse_yaml(statistical_contract())
            .expect("strict statistical contract");
        compile_contract_with_governed_files(
            &contract,
            &[statistical_observed_schema()],
            CompileProfile::Production,
            &governed_files_for(&contract),
        )
        .expect("valid statistical codelists compile");

        let mut governed = governed_files_for(&contract);
        governed.insert(
            "codelists/areas.yaml".into(),
            b"id: areas\nversion: 1\nvalues: ['not valid']\nstatus: reviewed\n".to_vec(),
        );
        let report = compile_contract_with_governed_files(
            &contract,
            &[statistical_observed_schema()],
            CompileProfile::Production,
            &governed,
        )
        .expect_err("a code rejected by the runtime SDMX profile fails compilation");
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "sdmx.codelist_value_invalid"
                && diagnostic.location == "codelists/areas.yaml"
        }));
    }

    #[test]
    fn statistical_processing_handling_includes_hidden_columns_but_disclosure_does_not() {
        let yaml = statistical_contract()
            .replace(
                "    sourceColumnClassifications: {}",
                "    sourceColumnClassifications:\n      tenant: {privacy: non-personal, institutional: internal, handling: confidential, status: reviewed}",
            )
            .replace(
                "    access: public",
                "    access:\n      scope: statistics:read\n      authorityRowBinding: {principal: true, sourceColumn: tenant}",
            )
            .replace(
                "statisticalDatasets: public, semantics: public, classifications: public, processing: public",
                "statisticalDatasets: public, semantics: public, classifications: operation-bound, processing: operation-bound",
            );
        let contract = RegistryContract::parse_yaml(&yaml).expect("protected statistical contract");
        let mut observed = statistical_observed_schema();
        observed.views[0]
            .columns
            .push(crate::model::ObservedColumn {
                name: "tenant".into(),
                declared_type: "TEXT".into(),
                nullable: false,
                primary_key: false,
            });
        let compiled = compile_contract(&contract, &[observed], CompileProfile::Production)
            .expect("protected statistical contract compiles");
        let dataset = &compiled.statistical_datasets[0];
        assert_eq!(dataset.processing_handling, Handling::Confidential);
        assert_eq!(dataset.disclosure_handling, Handling::Public);
        assert!(dataset.column_accounting.iter().any(|column| {
            column.column == "tenant"
                && column.classification.handling == Handling::Confidential
                && column.uses == [ColumnUse::RowBinding(dataset.operation_identifier())]
        }));
        assert!(dataset
            .dimensions
            .iter()
            .all(|component| component.source_column != "tenant"));
        assert_ne!(dataset.time.source_column, "tenant");
        assert_ne!(dataset.measure.source_column, "tenant");
        assert!(dataset
            .attributes
            .iter()
            .all(|component| component.source_column != "tenant"));
    }

    #[test]
    fn unreviewed_statistical_source_columns_without_override_point_at_classification_defaults() {
        let suggested = statistical_contract().replace(
            "classificationDefaults: {privacy: non-personal, institutional: public, handling: public, status: reviewed}",
            "classificationDefaults: {privacy: non-personal, institutional: public, handling: public, status: suggested}",
        );
        let contract =
            RegistryContract::parse_yaml(&suggested).expect("strict statistical contract");
        let report = compile_contract(
            &contract,
            &[statistical_observed_schema()],
            CompileProfile::Production,
        )
        .expect_err("unreviewed statistical source columns refuse production compilation");
        let unreviewed = report
            .diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == "classification.unreviewed"
                    && diagnostic.location == "statisticalDatasets[0].classificationDefaults"
            })
            .collect::<Vec<_>>();
        for column in [
            "ref_area",
            "sex",
            "time_period",
            "obs_value",
            "unit_measure",
        ] {
            assert!(
                unreviewed
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains(&format!("'{column}'"))),
                "expected a classification.unreviewed diagnostic naming source column '{column}': {unreviewed:?}"
            );
        }
    }

    #[test]
    fn unreviewed_statistical_source_column_with_override_points_at_its_own_entry() {
        let yaml = statistical_contract().replace(
            "    sourceColumnClassifications: {}",
            "    sourceColumnClassifications:\n      ref_area: {privacy: non-personal, institutional: public, handling: public, status: suggested}",
        );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict statistical contract");
        let report = compile_contract(
            &contract,
            &[statistical_observed_schema()],
            CompileProfile::Production,
        )
        .expect_err(
            "an unreviewed statistical source-column override refuses production compilation",
        );
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.code == "classification.unreviewed"
                    && diagnostic.location
                        == "statisticalDatasets[0].sourceColumnClassifications.ref_area"
            })
            .expect("an authored override still resolves to its own entry");
        assert!(diagnostic.message.contains("'ref_area'"));
    }

    #[test]
    fn complete_governed_closure_compiles_reproducibly() {
        let contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        let first = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed_files(),
        )
        .expect("production compilation");
        let second = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed_files(),
        )
        .expect("repeat production compilation");

        assert_eq!(first, second);
        assert_eq!(first.codelists[0].values, ["ACTIVE", "RETIRED"]);
        assert!(first.contract_revision.starts_with("sha256:"));
        assert!(first.sources[0].observed_schema.is_some());
        let first_artifacts = crate::artifacts::generate_artifacts(&first).expect("artifacts");
        let second_artifacts = crate::artifacts::generate_artifacts(&second).expect("artifacts");
        assert_eq!(first_artifacts, second_artifacts);
        let operation = &first.resources[0].operations[0];
        let access_profile = &operation.access_profiles[0];
        let schema = first_artifacts
            .artifacts
            .iter()
            .find(|artifact| access_profile.schema_reference.ends_with(&artifact.id))
            .expect("operation schema is mounted by its exact artifact identifier");
        assert_eq!(schema.visibility, crate::contract::Visibility::Public);
    }

    #[test]
    fn authority_and_operator_display_names_are_carried_into_the_compiled_registry() {
        let yaml = valid_contract().replace(
            "  authority: {identifier: urn:example:authority, name: Registry Authority}",
            "  authority: {identifier: urn:example:authority, name: Registry Authority}\n  operator: {identifier: urn:example:operator, name: Registry Operator}",
        );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
        let compiled =
            compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                .expect("contract compiles");

        assert_eq!(compiled.authority_name, "Registry Authority");
        assert_eq!(compiled.operator_name.as_deref(), Some("Registry Operator"));
    }

    #[test]
    fn identifier_lifecycle_policy_cannot_alias_a_referenced_codelist() {
        let yaml = valid_contract().replace(
            "lifecycleState: {sourceColumn: lifecycle, codelist: codelists/record-lifecycle.yaml}",
            "lifecycleState: {sourceColumn: lifecycle, codelist: governance/identifier-lifecycle.yaml}",
        );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
        let report = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed_files_for(&contract),
        )
        .expect_err("one file cannot carry incompatible governed roles");
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "contract.governed_file_role_collision"
                && diagnostic.location == "governance/identifier-lifecycle.yaml"
        }));
    }

    #[test]
    fn every_referenced_property_codelist_must_be_in_the_governed_closure() {
        let yaml = valid_contract().replace(
            "type: string\n        sourceRequired: true",
            "type: controlled-code\n        codelist: codelists/names.yaml\n        sourceRequired: true",
        );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
        let report = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed_files_for(&contract),
        )
        .expect_err("a referenced codelist cannot be absent");
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "contract.governed_file_missing"
                && diagnostic.location == "codelists/names.yaml"
        }));
    }

    #[test]
    fn every_referenced_selector_codelist_must_be_in_the_governed_closure() {
        let yaml = valid_contract()
            .replace(
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "lookups:\n        - id: by-name\n          requestBody:\n            maximumBytes: 1024\n            selectors:\n              name: {sourceColumn: name, type: controlled-code, codelist: codelists/selector-names.yaml}\n          defaultAccessProfile: public\n          accessProfiles:\n            public: {access: public, disclosureProfile: public}",
            )
            .replace("operationRefs: [read]", "operationRefs: [lookup:by-name]");
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict lookup contract");
        let report = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed_files_for(&contract),
        )
        .expect_err("a selector codelist cannot be absent");
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "contract.governed_file_missing"
                && diagnostic.location == "codelists/selector-names.yaml"
        }));
    }

    #[test]
    fn list_order_ends_in_one_non_null_string_record_identifier() {
        let yaml = valid_contract()
            .replace(
                "        semanticTerm: local:name\n    disclosureProfiles",
                "        semanticTerm: local:name\n      recordId:\n        label: Record identifier\n        description: Stable record identifier\n        sourceColumn: id\n        type: string\n        sourceRequired: true\n        semanticTerm: local:recordId\n    disclosureProfiles",
            )
            .replace(
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [recordId, name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            )
            .replace("operationRefs: [read]", "operationRefs: [list]");
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict list contract");
        let compiled =
            compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                .expect("cursor-safe list order");
        assert_eq!(
            compiled.resources[0].operations[0].query.order_by,
            ["name", "id"]
        );
    }

    #[test]
    fn optional_and_unsupported_cursor_order_columns_are_refused() {
        let yaml = valid_contract()
            .replace(
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            )
            .replace("operationRefs: [read]", "operationRefs: [list]");
        let optional = yaml.replace(
            "sourceColumn: name\n        type: string\n        sourceRequired: true",
            "sourceColumn: name\n        type: string\n        sourceRequired: false",
        );
        let optional = RegistryContract::parse_yaml(&optional).expect("strict list contract");
        let report = compile_contract(&optional, &[observed_schema()], CompileProfile::Production)
            .expect_err("optional cursor order refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "list.order_property_optional"));

        let contract = RegistryContract::parse_yaml(&yaml).expect("strict list contract");
        let mut unsupported = observed_schema();
        unsupported.views[0]
            .columns
            .iter_mut()
            .find(|column| column.name == "name")
            .expect("name column")
            .declared_type = "REAL".into();
        let report = compile_contract(&contract, &[unsupported], CompileProfile::Production)
            .expect_err("unsupported cursor scalar refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "list.order_column_type_unsupported" }));
    }

    #[test]
    fn transformed_properties_cannot_be_list_filters_or_order_keys() {
        let transformed = valid_contract()
            .replace(
                "    sourceColumnClassifications: {}",
                "    sourceColumnClassifications:\n      name: {privacy: non-personal, institutional: public, handling: public, status: reviewed}",
            )
            .replace(
                "        semanticTerm: local:name\n    disclosureProfiles",
                "        semanticTerm: local:name\n        transform: {kind: partial-string, reveal: suffix, characters: 4}\n    disclosureProfiles",
            );

        let filtered = transformed
            .replace(
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters:\n          - {name: byName, property: name, type: string}\n        allowUnfiltered: false\n        orderBy: []\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            )
            .replace("operationRefs: [read]", "operationRefs: [list]");
        let contract = RegistryContract::parse_yaml(&filtered).expect("strict filter contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("a transformed filter cannot compare its raw source input");
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "list.filter_property_transformed")
            .expect("stable transformed-filter diagnostic");
        assert_eq!(
            diagnostic.location,
            "resources[0].operations.list.filters[0]"
        );
        assert_eq!(
            diagnostic.message,
            "transformed properties cannot be used as list filters"
        );

        let ordered = transformed
            .replace(
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            )
            .replace("operationRefs: [read]", "operationRefs: [list]");
        let contract = RegistryContract::parse_yaml(&ordered).expect("strict order contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("a transformed order key cannot compare its raw source input");
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "list.order_property_transformed")
            .expect("stable transformed-order diagnostic");
        assert_eq!(
            diagnostic.location,
            "resources[0].operations.list.orderBy[0]"
        );
        assert_eq!(
            diagnostic.message,
            "transformed properties cannot be used as fixed order keys"
        );
    }

    #[test]
    fn fixed_list_order_diagnostics_name_each_order_position() {
        let yaml = valid_contract()
            .replace(
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name, name, absent]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            )
            .replace("operationRefs: [read]", "operationRefs: [list]");
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict list contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("repeated and unknown fixed order keys are refused");
        let located = |code: &str| {
            report
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == code)
                .map(|diagnostic| diagnostic.location.clone())
                .unwrap_or_else(|| panic!("stable {code} diagnostic"))
        };
        assert_eq!(
            located("list.order_duplicate"),
            "resources[0].operations.list.orderBy[1]"
        );
        assert_eq!(
            located("list.order_column_duplicate"),
            "resources[0].operations.list.orderBy[1]"
        );
        assert_eq!(
            located("list.order_property_unknown"),
            "resources[0].operations.list.orderBy[2]"
        );
    }

    #[test]
    fn fixed_search_order_diagnostics_name_each_order_position() {
        let yaml = point_contract()
            .replace(
                "disclosureProfiles: {public: {properties: [name]}}",
                "disclosureProfiles: {public: {properties: [name, location]}}",
            )
            .replace(
                "      read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "      searches:\n        - id: within-bbox\n          query: {kind: point-bbox, maximumLongitudeSpanDegrees: 2, maximumLatitudeSpanDegrees: 2}\n          defaultAccessProfile: public\n          accessProfiles:\n            public: {access: public, disclosureProfile: public}\n          orderBy: [name, name, absent]\n          pagination: {defaultPageSize: 10, maximumPageSize: 100}",
            )
            .replace(
                "operationRefs: [read]",
                "operationRefs: [search:within-bbox]",
            );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict spatial contract");
        let report = compile_contract(
            &contract,
            &[point_observed_schema("INTEGER", "REAL")],
            CompileProfile::Production,
        )
        .expect_err("repeated and unknown fixed search order keys are refused");
        let located = |code: &str| {
            report
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == code)
                .map(|diagnostic| diagnostic.location.clone())
                .unwrap_or_else(|| panic!("stable {code} diagnostic"))
        };
        assert_eq!(
            located("search.order_duplicate"),
            "resources[0].operations.searches[0].orderBy[1]"
        );
        assert_eq!(
            located("search.order_column_duplicate"),
            "resources[0].operations.searches[0].orderBy[1]"
        );
        assert_eq!(
            located("search.order_property_unknown"),
            "resources[0].operations.searches[0].orderBy[2]"
        );
    }

    #[test]
    fn sqlite_view_nullable_metadata_does_not_override_required_order_contract() {
        let yaml = valid_contract()
            .replace(
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            )
            .replace("operationRefs: [read]", "operationRefs: [list]");
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict list contract");
        let mut observed = observed_schema();
        for column in &mut observed.views[0].columns {
            column.nullable = true;
        }
        let compiled = compile_contract(&contract, &[observed], CompileProfile::Production)
            .expect("SQLite view nullability cannot disprove the required source contract");
        assert_eq!(
            compiled.resources[0].operations[0].query.order_by,
            ["name", "id"]
        );
    }

    #[test]
    fn required_record_identifier_tie_breaker_is_included_in_order_cap() {
        let yaml = valid_contract()
            .replace(
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: []\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            )
            .replace("operationRefs: [read]", "operationRefs: [list]");
        let base = RegistryContract::parse_yaml(&yaml).expect("strict list contract");

        let compile_with_authored_order = |count: usize| {
            let mut value = serde_json::to_value(&base).expect("contract serializes");
            let properties = value
                .pointer_mut("/resources/0/properties")
                .and_then(serde_json::Value::as_object_mut)
                .expect("properties object");
            let template = properties.get("name").expect("name property").clone();
            let mut schema = observed_schema();
            for index in 0..count {
                let property_name = format!("sort{index}");
                let column_name = format!("sort_{index}");
                let mut property = template.clone();
                property
                    .as_object_mut()
                    .expect("property object")
                    .insert("sourceColumn".into(), serde_json::json!(column_name));
                properties.insert(property_name, property);
                schema.views[0].columns.push(crate::model::ObservedColumn {
                    name: column_name,
                    declared_type: "TEXT".into(),
                    nullable: false,
                    primary_key: false,
                });
            }
            *value
                .pointer_mut("/resources/0/operations/list/orderBy")
                .expect("order array") = serde_json::Value::Array(
                (0..count)
                    .map(|index| serde_json::json!(format!("sort{index}")))
                    .collect(),
            );
            let contract = serde_json::from_value::<RegistryContract>(value)
                .expect("strict generated contract");
            compile_contract(&contract, &[schema], CompileProfile::Production)
        };

        let at_cap = compile_with_authored_order(MAXIMUM_LIST_ORDER_KEYS - 1)
            .expect("authored order plus tie-breaker fits the cap");
        assert_eq!(
            at_cap.resources[0].operations[0].query.order_by.len(),
            MAXIMUM_LIST_ORDER_KEYS
        );
        let report = compile_with_authored_order(MAXIMUM_LIST_ORDER_KEYS)
            .expect_err("the implicit tie-breaker cannot create cap plus one");
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "list.order_bound_exceeded"));
    }

    #[test]
    fn classification_inventory_excludes_presentation_and_runtime_tuning() {
        let yaml = valid_contract()
            .replace(
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            )
            .replace("operationRefs: [read]", "operationRefs: [list]");
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict list contract");
        let compiled =
            compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                .expect("classification inventory compiles");
        let baseline = classification_inventory_digest(&compiled).expect("baseline digest");

        let mut presentation_only = compiled.clone();
        presentation_only.registry_name = "Renamed registry".into();
        presentation_only.resources[0].title = "Renamed resource".into();
        presentation_only.resources[0].description = "Reworded description".into();
        presentation_only.resources[0].properties[0].label = "Renamed property".into();
        presentation_only.resources[0].properties[0].description = "Reworded property".into();
        let operation = &mut presentation_only.resources[0].operations[0];
        operation
            .query
            .pagination
            .as_mut()
            .expect("list pagination")
            .maximum_page_size = 99;
        operation.access_profiles[0].schema_reference = "https://elsewhere.invalid/schema".into();
        operation.access_profiles[0].semantic_model_reference =
            "https://elsewhere.invalid/vocabulary".into();
        operation.access_profiles[0].context_reference = "https://elsewhere.invalid/context".into();
        assert_eq!(
            classification_inventory_digest(&presentation_only).expect("narrow digest"),
            baseline
        );

        let mut source_changed = compiled.clone();
        source_changed.sources[0].expected_schema_fingerprint =
            format!("sha256:{}", "b".repeat(64));
        assert_ne!(
            classification_inventory_digest(&source_changed).expect("source digest"),
            baseline
        );

        let mut classification_changed = compiled.clone();
        classification_changed.resources[0].properties[0]
            .classification
            .privacy = "identifying".into();
        assert_ne!(
            classification_inventory_digest(&classification_changed)
                .expect("classification digest"),
            baseline
        );

        let mut semantic_changed = compiled.clone();
        semantic_changed.resources[0].properties[0].semantic_iri =
            "https://example.invalid/changed-term".into();
        assert_ne!(
            classification_inventory_digest(&semantic_changed).expect("semantic digest"),
            baseline
        );

        let mut transform_changed = compiled.clone();
        let CompiledPropertyBinding::Scalar(binding) =
            &mut transform_changed.resources[0].properties[0].binding
        else {
            panic!("fixture property is scalar");
        };
        binding.transform = Some(CompiledTransform::PartialString {
            identifier: "partial-string:suffix:2".into(),
            reveal: crate::contract::PartialStringReveal::Suffix,
            characters: 2,
        });
        assert_ne!(
            classification_inventory_digest(&transform_changed).expect("transform digest"),
            baseline
        );

        let mut transform_inventory_changed = compiled.clone();
        transform_inventory_changed.resources[0].operations[0].access_profiles[0]
            .transform_inventory
            .push("partial-string:suffix:2".into());
        assert_ne!(
            classification_inventory_digest(&transform_inventory_changed)
                .expect("transform inventory digest"),
            baseline
        );

        let mut access_changed = compiled.clone();
        access_changed.resources[0].operations[0].access_profiles[0].access =
            CompiledAccess::Protected {
                scope: "registry:changed:read".into(),
                purpose: None,
                row_binding: None,
            };
        assert_ne!(
            classification_inventory_digest(&access_changed).expect("access digest"),
            baseline
        );

        let mut disclosure_changed = compiled;
        disclosure_changed.resources[0].operations[0].access_profiles[0].disclosure_handling =
            Handling::Internal;
        assert_ne!(
            classification_inventory_digest(&disclosure_changed).expect("disclosure digest"),
            baseline
        );
    }

    #[test]
    fn stale_review_fails_production_but_remains_an_authoring_finding() {
        let contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        let mut governed = governed_files();
        let review = String::from_utf8(
            governed
                .get("governance/classification-review.yaml")
                .expect("review")
                .clone(),
        )
        .expect("review text");
        let review = review
            .lines()
            .map(|line| {
                if line.starts_with("classificationInventoryDigest:") {
                    "classificationInventoryDigest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        governed.insert(
            "governance/classification-review.yaml".into(),
            review.into_bytes(),
        );
        let production = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed,
        )
        .expect_err("stale production review refused");
        assert!(production
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "classification.review_inventory_stale"));

        let authoring = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Authoring,
            &governed,
        )
        .expect("authoring remains usable");
        assert!(authoring.classification_review.is_none());
    }

    #[test]
    fn production_requires_an_explicitly_reviewed_codelist() {
        let contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        let mut governed = governed_files();
        governed.insert(
            "codelists/record-lifecycle.yaml".into(),
            b"id: record-lifecycle\nversion: 1\nvalues: [ACTIVE, RETIRED]\n".to_vec(),
        );
        let report = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed,
        )
        .expect_err("a codelist without review status is refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "codelist.unreviewed"));
    }

    #[test]
    fn classification_rationale_is_part_of_the_governed_artifact_closure() {
        let contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        let mut governed = governed_files();
        governed.remove("governance/review-rationale");
        let report = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed,
        )
        .expect_err("missing review rationale refused");
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "contract.governed_file_missing"
                && diagnostic.location == "governance/review-rationale"
        }));
    }

    #[test]
    fn governed_query_bounds_cannot_exceed_product_ceilings() {
        let oversized_list = valid_contract().replace(
            "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
            &format!(
                "list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {{access: public, disclosureProfile: public}}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {{defaultPageSize: 1, maximumPageSize: {}}}",
                MAXIMUM_LIST_PAGE_SIZE + 1
            ),
        );
        let contract = RegistryContract::parse_yaml(&oversized_list).expect("strict list contract");
        let report = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed_files(),
        )
        .expect_err("oversized governed list is refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "list.pagination_invalid"));

        let oversized_lookup = valid_contract().replace(
            "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
            &format!(
                "lookups:\n        - id: by-name\n          requestBody:\n            maximumBytes: {}\n            selectors:\n              name: {{sourceColumn: name, type: string, maximumBytes: 32}}\n          defaultAccessProfile: public\n          accessProfiles:\n            public: {{access: {{scope: registry:records:lookup}}, disclosureProfile: public}}",
                MAXIMUM_LOOKUP_REQUEST_BODY_BYTES + 1
            ),
        );
        let contract =
            RegistryContract::parse_yaml(&oversized_lookup).expect("strict lookup contract");
        let report = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed_files(),
        )
        .expect_err("oversized governed lookup is refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "lookup.body_bound_invalid"));
    }

    #[test]
    fn artifact_base_is_closed_and_preserves_its_path_prefix() {
        for base in [
            "https://user@example.invalid/registry/",
            "https://example.invalid/registry/?tenant=one",
            "https://example.invalid/registry/#tenant",
        ] {
            let yaml = valid_contract().replace(
                "baseUri: https://registry.example.invalid/registry/",
                &format!("baseUri: \"{base}\""),
            );
            let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
            let report =
                compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                    .expect_err("ambiguous artifact base refused");
            assert!(report
                .diagnostics
                .iter()
                .any(|item| item.code == "registry.base_uri_invalid"));
        }

        let contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        let compiled =
            compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                .expect("contract compiles");
        assert!(compiled.resources[0]
            .record_context
            .schema_reference
            .starts_with("https://registry.example.invalid/registry/v2/artifacts/"));
    }

    #[test]
    fn semantic_iris_unsafe_for_turtle_are_refused_before_artifact_generation() {
        let invalid_vocabulary = valid_contract().replace(
            "localVocabulary: https://registry.example.invalid/vocabulary/",
            "localVocabulary: \"https://registry.example.invalid/vocabulary/>\"",
        );
        let invalid_term =
            valid_contract().replace("semanticTerm: local:name", "semanticTerm: \"local:bad>\"");
        for (yaml, code) in [
            (invalid_vocabulary, "semantics.local_vocabulary_invalid"),
            (invalid_term, "semantics.term_invalid"),
        ] {
            let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
            let report =
                compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                    .expect_err("Turtle-unsafe IRI refused");
            assert!(report.diagnostics.iter().any(|item| item.code == code));
        }
    }

    #[test]
    fn every_registry_core_column_requires_sqlite_text_affinity() {
        for (column, declared_type) in [
            ("id", "DATE"),
            ("revision", "DATETIME"),
            ("lifecycle", "STRING"),
            ("recorded_at", "INTTEXT"),
        ] {
            let contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
            let mut observed = observed_schema();
            observed.views[0]
                .columns
                .iter_mut()
                .find(|item| item.name == column)
                .expect("core column")
                .declared_type = declared_type.into();
            let report = compile_contract(&contract, &[observed], CompileProfile::Production)
                .expect_err("non-TEXT-affinity Registry Core declaration refused");
            assert!(report
                .diagnostics
                .iter()
                .any(|item| item.code == "record.declared_type_incompatible"));
        }
    }

    #[test]
    fn sqlite_declared_type_affinity_follows_sqlite_precedence() {
        for (declared_type, expected) in [
            ("INTTEXT", SqliteTypeAffinity::Integer),
            ("CHARINT", SqliteTypeAffinity::Integer),
            ("VARCHAR(255)", SqliteTypeAffinity::Text),
            ("CLOB", SqliteTypeAffinity::Text),
            ("TEXT", SqliteTypeAffinity::Text),
            ("", SqliteTypeAffinity::Blob),
            ("BLOB", SqliteTypeAffinity::Blob),
            ("REAL", SqliteTypeAffinity::Real),
            ("FLOAT", SqliteTypeAffinity::Real),
            ("DOUBLE PRECISION", SqliteTypeAffinity::Real),
            ("DATE", SqliteTypeAffinity::Numeric),
            ("DATETIME", SqliteTypeAffinity::Numeric),
            ("NUMERIC", SqliteTypeAffinity::Numeric),
            ("STRING", SqliteTypeAffinity::Numeric),
        ] {
            assert_eq!(
                sqlite_declared_type_affinity(declared_type),
                expected,
                "unexpected affinity for {declared_type:?}"
            );
        }
    }

    #[test]
    fn every_text_runtime_datatype_requires_sqlite_text_affinity() {
        let text_runtime_types = [
            DataType::String,
            DataType::Date,
            DataType::DateTime,
            DataType::Year,
            DataType::YearMonth,
            DataType::ControlledCode,
        ];
        // These are SQLite's documented TEXT-affinity declaration families.
        let text_declarations = [
            "CHARACTER(20)",
            "VARCHAR(255)",
            "VARYING CHARACTER(255)",
            "NCHAR(55)",
            "NATIVE CHARACTER(70)",
            "NVARCHAR(100)",
            "TEXT",
            "CLOB",
        ];
        let incompatible_declarations = [
            "INTTEXT", "DATE", "DATETIME", "STRING", "", "BLOB", "REAL", "NUMERIC",
        ];

        for data_type in text_runtime_types {
            for declared_type in text_declarations {
                assert!(
                    compatible_declared_type(data_type, declared_type),
                    "{data_type:?} should accept {declared_type:?}"
                );
            }
            for declared_type in incompatible_declarations {
                assert!(
                    !compatible_declared_type(data_type, declared_type),
                    "{data_type:?} should refuse {declared_type:?}"
                );
            }
        }
    }

    #[test]
    fn integer_backed_datatypes_accept_only_integer_affinity_or_boolean() {
        // Every INT-containing declaration has INTEGER affinity. BOOLEAN is
        // the intentional compatibility exception retained from version one.
        let compatible_declarations = [
            "INT",
            "INTEGER",
            "TINYINT",
            "SMALLINT",
            "MEDIUMINT",
            "BIGINT",
            "UNSIGNED BIG INT",
            "INT2",
            "INT8",
            "INTTEXT",
            "BOOLEAN",
        ];
        let incompatible_declarations = ["NUMERIC", "DATE", "REAL", "TEXT", "BLOB", ""];

        for data_type in [DataType::Boolean, DataType::Integer] {
            for declared_type in compatible_declarations {
                assert!(
                    compatible_declared_type(data_type, declared_type),
                    "{data_type:?} should accept {declared_type:?}"
                );
            }
            for declared_type in incompatible_declarations {
                assert!(
                    !compatible_declared_type(data_type, declared_type),
                    "{data_type:?} should refuse {declared_type:?}"
                );
            }
        }
    }

    #[test]
    fn lookup_selector_type_and_smallest_json_body_are_closed() {
        let lookup = |maximum: u32, data_type: &str| {
            valid_contract()
                .replace(
                    "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                    &format!(
                        "lookups:\n        - id: by-name\n          requestBody:\n            maximumBytes: {maximum}\n            selectors:\n              name: {{sourceColumn: name, type: {data_type}, minimumBytes: 1, maximumBytes: 32}}\n          defaultAccessProfile: public\n          accessProfiles:\n            public: {{access: public, disclosureProfile: public}}"
                    ),
                )
                .replace("operationRefs: [read]", "operationRefs: [lookup:by-name]")
        };

        let too_small = RegistryContract::parse_yaml(&lookup(25, "string")).expect("contract");
        let report = compile_contract(&too_small, &[observed_schema()], CompileProfile::Production)
            .expect_err("body unable to contain its required selector refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "lookup.body_bound_too_small"));

        let exact = RegistryContract::parse_yaml(&lookup(26, "string")).expect("contract");
        compile_contract(&exact, &[observed_schema()], CompileProfile::Production)
            .expect("exact minimum JSON body bound compiles");

        let incompatible = RegistryContract::parse_yaml(&lookup(64, "integer")).expect("contract");
        let report = compile_contract(
            &incompatible,
            &[observed_schema()],
            CompileProfile::Production,
        )
        .expect_err("selector/SQLite type mismatch refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| { item.code == "lookup.selector_declared_type_incompatible" }));

        let adversarial = RegistryContract::parse_yaml(&lookup(64, "string")).expect("contract");
        let mut observed = observed_schema();
        observed.views[0]
            .columns
            .iter_mut()
            .find(|column| column.name == "name")
            .expect("selector column")
            .declared_type = "INTTEXT".into();
        let report = compile_contract(&adversarial, &[observed], CompileProfile::Production)
            .expect_err("INTEGER-affinity string selector refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "lookup.selector_declared_type_incompatible"));
    }

    #[test]
    fn list_filter_source_columns_inherit_property_affinity_validation() {
        let yaml = valid_contract()
            .replace(
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters:\n          - {name: byName, property: name, type: string}\n        allowUnfiltered: false\n        orderBy: []\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            )
            .replace("operationRefs: [read]", "operationRefs: [list]");
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict filter contract");
        let mut observed = observed_schema();
        observed.views[0]
            .columns
            .iter_mut()
            .find(|column| column.name == "name")
            .expect("filter property column")
            .declared_type = "INTTEXT".into();

        let report = compile_contract(&contract, &[observed], CompileProfile::Production)
            .expect_err("INTEGER-affinity string filter source refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "property.declared_type_incompatible"));
    }

    #[test]
    fn governed_controlled_codes_set_the_exact_production_lookup_body_boundary() {
        let lookup = |maximum: u32| {
            valid_contract()
                .replace(
                    "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                    &format!(
                        "lookups:\n        - id: verify-registration\n          requestBody:\n            maximumBytes: {maximum}\n            selectors:\n              registrationNumber: {{sourceColumn: name, type: string, minimumBytes: 12, maximumBytes: 96}}\n              eventType: {{sourceColumn: name, type: controlled-code, codelist: codelists/selector-types.yaml}}\n          defaultAccessProfile: public\n          accessProfiles:\n            public: {{access: public, disclosureProfile: public}}"
                    ),
                )
                .replace(
                    "operationRefs: [read]",
                    "operationRefs: [lookup:verify-registration]",
                )
        };
        let governed_selector_codes =
            b"id: selector-types\nversion: 1\nstatus: reviewed\nvalues: ['\"', \xc3\xa9]\n";
        let compile_with_codes = |maximum| {
            let contract = RegistryContract::parse_yaml(&lookup(maximum)).expect("strict contract");
            let mut files = governed_files_for(&contract);
            files.insert(
                "codelists/selector-types.yaml".into(),
                governed_selector_codes.to_vec(),
            );
            compile_contract_with_governed_files(
                &contract,
                &[observed_schema()],
                CompileProfile::Production,
                &files,
            )
        };

        let provisional = RegistryContract::parse_yaml(&lookup(67)).expect("strict contract");
        compile_contract(
            &provisional,
            &[observed_schema()],
            CompileProfile::Production,
        )
        .expect("the pre-codelist lower bound remains provisional");
        let report = compile_with_codes(67)
            .expect_err("a bound below the actual governed JSON minimum is refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "lookup.body_bound_too_small"));

        compile_with_codes(68)
            .expect("the exact UTF-8 and JSON-escaping-aware production boundary compiles");
    }

    #[test]
    fn protected_scope_and_purpose_values_match_runtime_token_bounds() {
        let with_scope = |scope: &str| {
            let contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
            let mut value = serde_json::to_value(contract).expect("contract serializes");
            *value
                .pointer_mut("/resources/0/operations/read/accessProfiles/public/access")
                .expect("access profile access") = serde_json::json!({"scope": scope});
            serde_json::from_value(value).expect("strict contract")
        };
        compile_contract(
            &with_scope("!#$%&'()*+,-./012:;<=>?@AZ[]^_`az{|}~"),
            &[observed_schema()],
            CompileProfile::Production,
        )
        .expect("every permitted RFC 6749 scope-token byte compiles");
        for (kind, scope) in [
            ("quote", "registry:records:\"read"),
            ("backslash", "registry:records:\\read"),
            ("control", "registry:records:\u{1f}read"),
            ("delete control", "registry:records:\u{7f}read"),
            ("non-ASCII", "registry:records:r\u{e9}ad"),
            ("whitespace", "registry:records read"),
        ] {
            let report = compile_contract(
                &with_scope(scope),
                &[observed_schema()],
                CompileProfile::Production,
            )
            .expect_err(kind);
            assert!(
                report
                    .diagnostics
                    .iter()
                    .any(|item| item.code == "access.scope_invalid"),
                "missing scope diagnostic for {kind}"
            );
        }

        let with_access =
            |access: &str| valid_contract().replace("access: public", &format!("access: {access}"));
        let maximum = "x".repeat(MAXIMUM_DIRECT_CLAIM_BYTES);
        let valid = with_access(&format!(
            "{{scope: registry:records:read, purpose: {{claim: purpose, allowed: [\"{maximum}\"]}}}}"
        ));
        let contract = RegistryContract::parse_yaml(&valid).expect("strict contract");
        compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect("runtime maximum direct purpose value compiles");

        let oversized = format!("{maximum}x");
        let invalid = with_access(&format!(
            "{{scope: registry:records:read, purpose: {{claim: purpose, allowed: [\"{oversized}\"]}}}}"
        ));
        let contract = RegistryContract::parse_yaml(&invalid).expect("strict contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("oversized direct purpose value refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "access.purpose_value_invalid"));
    }

    #[test]
    fn multiply_bound_columns_require_one_runtime_scalar_interpretation() {
        let contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        let mut value = serde_json::to_value(contract).expect("contract serializes");
        let properties = value
            .pointer_mut("/resources/0/properties")
            .and_then(serde_json::Value::as_object_mut)
            .expect("properties");
        let name = properties
            .get_mut("name")
            .and_then(serde_json::Value::as_object_mut)
            .expect("name property");
        name.insert("type".into(), serde_json::json!("boolean"));
        let mut count = serde_json::Value::Object(name.clone());
        let count = count.as_object_mut().expect("count property");
        count.insert("label".into(), serde_json::json!("Count"));
        count.insert("description".into(), serde_json::json!("Count"));
        count.insert("type".into(), serde_json::json!("integer"));
        count.insert("semanticTerm".into(), serde_json::json!("local:count"));
        properties.insert("count".into(), serde_json::Value::Object(count.clone()));
        let contract: RegistryContract = serde_json::from_value(value).expect("strict contract");
        let mut observed = observed_schema();
        observed.views[0]
            .columns
            .iter_mut()
            .find(|item| item.name == "name")
            .expect("name column")
            .declared_type = "BOOLEAN".into();

        let report = compile_contract(&contract, &[observed], CompileProfile::Production)
            .expect_err("incompatible raw scalar interpretations refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| { item.code == "source.column_type_interpretation_conflict" }));
    }

    #[test]
    fn governed_structure_counts_cannot_exceed_product_ceilings() {
        let parse_value = |value: serde_json::Value| {
            serde_json::from_value::<RegistryContract>(value).expect("strict contract value")
        };
        let assert_refused = |contract: &RegistryContract, code: &str| {
            let report =
                compile_contract(contract, &[observed_schema()], CompileProfile::Production)
                    .expect_err("oversized governed structure is refused");
            assert!(
                report.diagnostics.iter().any(|item| item.code == code),
                "missing {code} diagnostic in {:?}",
                report.diagnostics
            );
        };

        let base = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        let mut resources_value = serde_json::to_value(&base).expect("contract serializes");
        let resources = resources_value
            .get_mut("resources")
            .and_then(serde_json::Value::as_array_mut)
            .expect("resources array");
        let resource = resources[0].clone();
        for index in 1..=MAXIMUM_RESOURCES {
            let mut item = resource.clone();
            item.as_object_mut()
                .expect("resource object")
                .insert("id".into(), serde_json::json!(format!("record-{index}")));
            resources.push(item);
        }
        assert_refused(&parse_value(resources_value), "resource.bound_exceeded");

        let mut properties_value = serde_json::to_value(&base).expect("contract serializes");
        let properties = properties_value
            .pointer_mut("/resources/0/properties")
            .and_then(serde_json::Value::as_object_mut)
            .expect("properties object");
        let property = properties.get("name").expect("name property").clone();
        for index in 1..=MAXIMUM_PROPERTIES_PER_RESOURCE {
            properties.insert(format!("name{index}"), property.clone());
        }
        assert_refused(&parse_value(properties_value), "property.bound_exceeded");

        let mut disclosures_value = serde_json::to_value(&base).expect("contract serializes");
        let disclosures = disclosures_value
            .pointer_mut("/resources/0/disclosureProfiles")
            .and_then(serde_json::Value::as_object_mut)
            .expect("disclosures object");
        let disclosure = disclosures
            .get("public")
            .expect("public disclosure")
            .clone();
        for index in 1..=MAXIMUM_DISCLOSURE_PROFILES_PER_RESOURCE {
            disclosures.insert(format!("profile-{index}"), disclosure.clone());
        }
        assert_refused(&parse_value(disclosures_value), "disclosure.bound_exceeded");

        let mut access_profiles_value = serde_json::to_value(&base).expect("contract serializes");
        let access_profiles = access_profiles_value
            .pointer_mut("/resources/0/operations/read/accessProfiles")
            .and_then(serde_json::Value::as_object_mut)
            .expect("access profiles object");
        let access_profile = access_profiles
            .get("public")
            .expect("public access profile")
            .clone();
        for index in 1..=MAXIMUM_ACCESS_PROFILES_PER_OPERATION {
            access_profiles.insert(format!("profile-{index}"), access_profile.clone());
        }
        assert_refused(
            &parse_value(access_profiles_value),
            "access_profile.bound_exceeded",
        );

        let mut registry_access_profiles_value =
            serde_json::to_value(&base).expect("contract serializes");
        let registry_access_profiles = registry_access_profiles_value
            .pointer_mut("/resources/0/operations/read/accessProfiles")
            .and_then(serde_json::Value::as_object_mut)
            .expect("access profiles object");
        let access_profile = registry_access_profiles
            .get("public")
            .expect("public access profile")
            .clone();
        for index in 1..=MAXIMUM_ACCESS_PROFILE_EXECUTORS_PER_REGISTRY {
            registry_access_profiles.insert(format!("profile-{index}"), access_profile.clone());
        }
        assert_refused(
            &parse_value(registry_access_profiles_value),
            "access_profile.registry_bound_exceeded",
        );

        let list_yaml = valid_contract().replace(
            "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
            "list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 1}",
        );
        let list_contract = RegistryContract::parse_yaml(&list_yaml).expect("strict list contract");
        let mut filters_value = serde_json::to_value(&list_contract).expect("contract serializes");
        let filters = filters_value
            .pointer_mut("/resources/0/operations/list/filters")
            .and_then(serde_json::Value::as_array_mut)
            .expect("filters array");
        for index in 0..=MAXIMUM_LIST_FILTERS {
            filters.push(serde_json::json!({
                "name": format!("filter{index}"),
                "property": "name",
                "type": "string",
            }));
        }
        assert_refused(&parse_value(filters_value), "list.filter_bound_exceeded");

        let mut order_value = serde_json::to_value(&list_contract).expect("contract serializes");
        let order = order_value
            .pointer_mut("/resources/0/operations/list/orderBy")
            .and_then(serde_json::Value::as_array_mut)
            .expect("order array");
        *order = (0..=MAXIMUM_LIST_ORDER_KEYS)
            .map(|_| serde_json::json!("name"))
            .collect();
        assert_refused(&parse_value(order_value), "list.order_bound_exceeded");
    }

    #[test]
    fn access_profile_identifiers_match_the_runtime_byte_ceiling() {
        let base = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        let profile_at = |value: &mut serde_json::Value, identifier: &str, replace: bool| {
            let profiles = value
                .pointer_mut("/resources/0/operations/read/accessProfiles")
                .and_then(serde_json::Value::as_object_mut)
                .expect("access profiles object");
            let profile = profiles
                .get("public")
                .expect("public access profile")
                .clone();
            if replace {
                profiles.remove("public");
            }
            profiles.insert(identifier.into(), profile);
            if replace {
                *value
                    .pointer_mut("/resources/0/operations/read/defaultAccessProfile")
                    .expect("default access profile") = serde_json::json!(identifier);
            }
        };
        let compile_value = |value| {
            let contract =
                serde_json::from_value::<RegistryContract>(value).expect("strict contract value");
            compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
        };

        let boundary = "a".repeat(MAXIMUM_ACCESS_PROFILE_IDENTIFIER_BYTES);
        let mut boundary_value = serde_json::to_value(&base).expect("contract serializes");
        profile_at(&mut boundary_value, &boundary, true);
        compile_value(boundary_value).expect("runtime boundary compiles");

        let oversized = "a".repeat(MAXIMUM_ACCESS_PROFILE_IDENTIFIER_BYTES + 1);
        let mut oversized_default = serde_json::to_value(&base).expect("contract serializes");
        profile_at(&mut oversized_default, &oversized, true);
        let report = compile_value(oversized_default).expect_err("oversized default is refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "access_profile.default_invalid"));
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "access_profile.id_invalid"));

        let mut oversized_non_default = serde_json::to_value(&base).expect("contract serializes");
        profile_at(&mut oversized_non_default, &oversized, false);
        let report =
            compile_value(oversized_non_default).expect_err("oversized non-default is refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "access_profile.id_invalid"));
    }

    #[test]
    fn an_operation_with_a_public_access_profile_requires_a_public_default() {
        let contract = RegistryContract::parse_yaml(&valid_contract().replace(
            "defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
            "defaultAccessProfile: protected\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n          protected: {access: {scope: registry:record:protected}, disclosureProfile: public}",
        ))
        .expect("strict contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("a hidden protected default is refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "access_profile.public_default_required"));
    }

    #[test]
    fn one_operation_compiles_finite_access_profiles_with_distinct_handling() {
        let contract = RegistryContract::parse_yaml(&governed_access_profiles_contract())
            .expect("strict access profile contract");
        let compiled =
            compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                .expect("access profiles compile");
        let resource = &compiled.resources[0];
        assert_eq!(resource.operations.len(), 1);
        let operation = &resource.operations[0];
        assert_eq!(operation.identifier, "record.read");
        assert_eq!(operation.default_access_profile, "limited");
        assert_eq!(operation.access_profiles.len(), 2);
        let limited = &operation.access_profiles[0];
        let full = &operation.access_profiles[1];
        assert_eq!(limited.id, "limited");
        assert_eq!(limited.disclosure_handling, Handling::Confidential);
        assert_eq!(limited.processing_handling, Handling::Restricted);
        assert_eq!(full.processing_handling, Handling::Restricted);
        assert_eq!(
            limited.transform_inventory,
            ["maskedName=partial-string:suffix:4"]
        );
        assert_ne!(limited.schema_reference, full.schema_reference);
        assert_eq!(
            limited.projected_columns,
            ["id", "revision", "lifecycle", "recorded_at", "name"]
        );
        assert!(resource
            .properties
            .iter()
            .all(|property| property.source_required));
        let account = resource
            .column_accounting
            .iter()
            .find(|account| account.column == "name")
            .expect("source account");
        assert_eq!(account.classification.handling, Handling::Restricted);
        assert!(account.uses.contains(&ColumnUse::Property("name".into())));
        assert!(account
            .uses
            .contains(&ColumnUse::Property("maskedName".into())));
    }

    #[test]
    fn transformed_and_multiply_bound_columns_require_explicit_review() {
        let yaml = governed_access_profiles_contract().replace(
            "    sourceColumnClassifications:\n      name: {privacy: identifying, institutional: restricted, handling: restricted, status: reviewed}\n",
            "    sourceColumnClassifications: {}\n",
        );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("implicit source classification is refused");
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "classification.column_explicit_review_required"
        }));
    }

    #[test]
    fn unreviewed_source_columns_without_override_name_each_column_in_the_message() {
        let suggested = valid_contract().replace(
            "classificationDefaults: {privacy: non-personal, institutional: public, handling: public, status: reviewed}",
            "classificationDefaults: {privacy: non-personal, institutional: public, handling: public, status: suggested}",
        );
        let contract = RegistryContract::parse_yaml(&suggested).expect("strict contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("unreviewed source columns refuse production compilation");
        let unreviewed = report
            .diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == "classification.unreviewed"
                    && diagnostic.location == "resources[0].classificationDefaults"
            })
            .collect::<Vec<_>>();
        for column in ["id", "lifecycle", "name", "recorded_at", "revision"] {
            assert!(
                unreviewed
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains(&format!("'{column}'"))),
                "expected a classification.unreviewed diagnostic naming source column '{column}': {unreviewed:?}"
            );
        }
    }

    #[test]
    fn unreviewed_source_column_with_override_points_at_its_own_entry() {
        let yaml = valid_contract().replace(
            "    sourceColumnClassifications: {}",
            "    sourceColumnClassifications:\n      name: {privacy: non-personal, institutional: public, handling: public, status: suggested}",
        );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("an unreviewed source-column override refuses production compilation");
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.code == "classification.unreviewed"
                    && diagnostic.location == "resources[0].sourceColumnClassifications.name"
            })
            .expect("an authored override still resolves to its own entry");
        assert!(diagnostic.message.contains("'name'"));
    }

    #[test]
    fn incomplete_source_column_classifications_name_each_column_in_the_message() {
        let incomplete = valid_contract().replace(
            "classificationDefaults: {privacy: non-personal, institutional: public, handling: public, status: reviewed}",
            "classificationDefaults: {privacy: non-personal, institutional: public, status: reviewed}",
        );
        let contract = RegistryContract::parse_yaml(&incomplete).expect("strict contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("incomplete source columns refuse production compilation");
        let incomplete_diagnostics = report
            .diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == "classification.column_incomplete"
                    && diagnostic.location == "resources[0].classificationDefaults"
            })
            .collect::<Vec<_>>();
        // A published property with an incomplete classification is refused
        // before column accounting, so the accounted columns left to report
        // are the four Registry Core carriers.
        for column in ["id", "lifecycle", "recorded_at", "revision"] {
            assert!(
                incomplete_diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains(&format!("'{column}'"))),
                "expected a classification.column_incomplete diagnostic naming source column '{column}': {incomplete_diagnostics:?}"
            );
        }
    }

    #[test]
    fn access_profile_default_and_transform_parameters_fail_closed() {
        let invalid_default = governed_access_profiles_contract().replace(
            "defaultAccessProfile: limited",
            "defaultAccessProfile: absent",
        );
        let contract = RegistryContract::parse_yaml(&invalid_default).expect("strict contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("unknown default refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "access_profile.default_invalid"));

        for characters in [0, MAXIMUM_PARTIAL_STRING_CHARACTERS + 1] {
            let yaml = governed_access_profiles_contract()
                .replace("characters: 4", &format!("characters: {characters}"));
            let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
            let report =
                compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                    .expect_err("out-of-profile transform refused");
            assert!(report.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == "transform.partial_string_characters_invalid"
            }));
        }
    }

    #[test]
    fn public_masked_access_profile_cannot_process_restricted_source() {
        let yaml = governed_access_profiles_contract()
            .replace(
                "classification: {privacy: partially-revealed-identifying, institutional: confidential, handling: confidential, status: reviewed}",
                "classification: {privacy: partially-revealed-identifying, institutional: public, handling: public, status: reviewed}",
            )
            .replace(
                "limited:\n            access: {scope: registry:records:limited}",
                "limited:\n            access: public",
            );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("public processing of restricted raw source refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "access.public_nonpublic_forbidden"));
    }

    #[test]
    fn date_precision_is_typed_and_closed() {
        let yaml = governed_access_profiles_contract()
            .replace("type: string\n        sourceRequired: true\n        semanticTerm: local:maskedName\n        classification: {privacy: partially-revealed-identifying, institutional: confidential, handling: confidential, status: reviewed}\n        transform: {kind: partial-string, reveal: suffix, characters: 4}", "type: year-month\n        sourceRequired: true\n        semanticTerm: local:maskedName\n        classification: {privacy: partially-revealed-identifying, institutional: confidential, handling: confidential, status: reviewed}\n        transform: {kind: date-precision, sourceType: date-time, precision: year-month}");
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict date transform");
        let compiled =
            compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                .expect("typed date precision compiles");
        assert_eq!(
            compiled.resources[0].properties[1]
                .scalar_binding()
                .map(|binding| binding.data_type),
            Some(DataType::YearMonth)
        );

        let invalid = yaml.replace("type: year-month", "type: year");
        let contract = RegistryContract::parse_yaml(&invalid).expect("strict contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("precision/output mismatch refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "transform.output_type_invalid"));
    }

    #[test]
    fn public_operation_cannot_process_nonpublic_columns() {
        let yaml = valid_contract().replace(
            "handling: public, status: reviewed",
            "handling: internal, status: reviewed",
        );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
        let report = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed_files(),
        )
        .expect_err("anonymous non-public processing is refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "access.public_nonpublic_forbidden"));
    }

    #[test]
    fn row_authority_is_a_compiler_injected_lane_not_a_filter() {
        let yaml = valid_contract().replace(
            "access: public",
            "access: {scope: registry:records:read, authorityRowBinding: {claim: region, sourceColumn: id}}",
        );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
        let compiled = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed_files_for(&contract),
        )
        .expect("protected row-bound compilation");
        let operation = &compiled.resources[0].operations[0];
        assert!(operation.query.filters.is_empty());
        let CompiledAccess::Protected {
            row_binding: Some(binding),
            ..
        } = &operation.access_profiles[0].access
        else {
            panic!("row-bound protected access expected");
        };
        assert_eq!(binding.source_column, "id");
        assert_eq!(binding.source, RowAuthoritySource::Claim("region".into()));
        let artifacts = crate::artifacts::generate_artifacts(&compiled).expect("artifacts");
        let public_openapi = artifacts
            .get("openapi.public.json")
            .expect("public OpenAPI");
        let openapi: serde_json::Value =
            serde_json::from_slice(&public_openapi.content).expect("generated JSON");
        assert!(openapi["paths"]
            .get("/v2/resources/record/records/{recordIdentifier}")
            .is_none());
    }

    #[test]
    fn row_authority_binding_requires_sqlite_text_affinity() {
        let yaml = valid_contract().replace(
            "access: public",
            "access: {scope: registry:records:read, authorityRowBinding: {claim: region, sourceColumn: name}}",
        );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
        let mut observed = observed_schema();
        observed.views[0]
            .columns
            .iter_mut()
            .find(|column| column.name == "name")
            .expect("row-binding column")
            .declared_type = "DATE".into();

        let report = compile_contract(&contract, &[observed], CompileProfile::Production)
            .expect_err("NUMERIC-affinity row binding refused");
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "access.row_binding_declared_type_incompatible")
            .expect("stable row-binding declaration diagnostic");
        assert_eq!(
            diagnostic.location,
            "resources[0].operations.read.accessProfiles.public.access.authorityRowBinding.sourceColumn"
        );
        assert_eq!(
            diagnostic.message,
            "row-authority binding columns require a reviewed SQLite declaration with TEXT affinity"
        );
    }

    #[test]
    fn public_record_cannot_reference_operator_only_semantics() {
        let yaml = valid_contract().replace(
            "resources: public, semantics: public",
            "resources: public, semantics: operator-only",
        );
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict contract");
        let report = compile_contract_with_governed_files(
            &contract,
            &[observed_schema()],
            CompileProfile::Production,
            &governed_files(),
        )
        .expect_err("unresolvable semantic reference is refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "metadata.reference_visibility_invalid"));
    }

    #[test]
    fn scalar_property_authoring_shape_remains_flat() {
        let contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        let property = contract.resources[0]
            .properties
            .get("name")
            .expect("name property");
        let value = serde_json::to_value(property).expect("property serializes");
        assert_eq!(value["sourceColumn"], "name");
        assert_eq!(value["type"], "string");
        for forbidden in ["binding", "kind", "source", "crs"] {
            assert!(value.get(forbidden).is_none());
        }
    }

    #[test]
    fn point_property_shape_is_strict_and_rejects_the_inline_primary_branch() {
        let contract = RegistryContract::parse_yaml(&point_contract()).expect("strict Point");
        let point = contract.resources[0]
            .properties
            .get("location")
            .and_then(crate::contract::PropertyDefinition::point_binding)
            .expect("Point binding");
        assert_eq!(point.crs, CRS84);
        assert_eq!(point.source.longitude_column, "longitude");
        let authored = contract.resources[0]
            .properties
            .get("location")
            .expect("authored Point");
        let encoded = serde_norway::to_string(authored).expect("Point serializes");
        let decoded: crate::contract::PropertyDefinition =
            serde_norway::from_str(&encoded).expect("Point deserializes");
        assert_eq!(&decoded, authored);

        for invalid in [
            point_contract().replace(
                "        type: point",
                "        sourceColumn: longitude\n        type: point",
            ),
            point_contract().replace(
                "        type: point",
                "        type: point\n        unknownPointField: value",
            ),
            point_contract().replace(
                "source: {longitudeColumn: longitude, latitudeColumn: latitude}",
                "source: {longitudeColumn: longitude, latitudeColumn: latitude, altitudeColumn: altitude}",
            ),
            point_contract().replace(
                "        label: Location",
                "        label: Location\n        label: Duplicate location",
            ),
            point_contract().replace(
                "source: {longitudeColumn: longitude, latitudeColumn: latitude}",
                "source: {longitudeColumn: longitude, longitudeColumn: duplicate, latitudeColumn: latitude}",
            ),
            point_contract().replace(
                "    primaryGeometry: location",
                "    primaryGeometry: {name: location, crs: http://www.opengis.net/def/crs/OGC/0/CRS84}",
            ),
            valid_contract().replace(
                "        sourceColumn: name",
                "        sourceColumn: name\n        source: {longitudeColumn: longitude, latitudeColumn: latitude}",
            ),
        ] {
            assert!(RegistryContract::parse_yaml(&invalid).is_err());
        }
    }

    #[test]
    fn point_property_compiles_as_one_resolved_primary_binding() {
        let contract = RegistryContract::parse_yaml(&point_contract()).expect("strict Point");
        let compiled = compile_contract(
            &contract,
            &[point_observed_schema("INTEGER", "REAL")],
            CompileProfile::Production,
        )
        .expect("governed Point compiles");
        let resource = &compiled.resources[0];
        assert_eq!(resource.primary_geometry.as_deref(), Some("location"));
        let property = resource
            .properties
            .iter()
            .find(|property| property.name == "location")
            .expect("compiled Point property");
        let encoded = serde_json::to_vec(property).expect("compiled Point serializes");
        let decoded: CompiledProperty =
            serde_json::from_slice(&encoded).expect("compiled Point deserializes");
        assert_eq!(&decoded, property);
        let value = serde_json::to_value(property).expect("compiled Point JSON");
        assert_eq!(value["binding"]["kind"], "point");
        assert_eq!(value["binding"]["longitudeColumn"], "longitude");
        assert_eq!(value["binding"]["latitudeColumn"], "latitude");
        let point = property.point_binding().expect("Point binding");
        assert_eq!(point.crs, CRS84);
        assert_eq!(point.longitude_column, "longitude");
        assert_eq!(point.latitude_column, "latitude");
        for (column_name, usage) in [
            ("longitude", ColumnUse::PointLongitude("location".into())),
            ("latitude", ColumnUse::PointLatitude("location".into())),
        ] {
            let column = resource
                .column_accounting
                .iter()
                .find(|column| column.column == column_name)
                .expect("Point carrier is accounted");
            assert_eq!(column.uses, [usage]);
            assert_eq!(column.classification, property.classification);
        }
    }

    #[test]
    fn point_count_and_primary_reference_are_closed() {
        let no_point_primary = valid_contract().replace(
            "    disclosureProfiles:",
            "    primaryGeometry: location\n    disclosureProfiles:",
        );
        assert_point_code(
            &no_point_primary,
            observed_schema(),
            "geometry.primary_without_point",
            "resources[0].primaryGeometry",
        );

        let missing_primary = point_contract().replace("    primaryGeometry: location\n", "");
        assert_point_code(
            &missing_primary,
            point_observed_schema("REAL", "REAL"),
            "geometry.primary_required",
            "resources[0].primaryGeometry",
        );

        let wrong_primary =
            point_contract().replace("    primaryGeometry: location", "    primaryGeometry: name");
        assert_point_code(
            &wrong_primary,
            point_observed_schema("REAL", "REAL"),
            "geometry.primary_invalid",
            "resources[0].primaryGeometry",
        );

        let two_points = point_contract().replace(
            "    primaryGeometry: location",
            "      secondLocation:\n        label: Second location\n        description: A second reviewed Point\n        type: point\n        crs: http://www.opengis.net/def/crs/OGC/0/CRS84\n        source: {longitudeColumn: second_longitude, latitudeColumn: second_latitude}\n        sourceRequired: true\n        semanticTerm: local:secondLocation\n    primaryGeometry: location",
        );
        let mut observed = point_observed_schema("REAL", "REAL");
        for name in ["second_longitude", "second_latitude"] {
            observed.views[0]
                .columns
                .push(crate::model::ObservedColumn {
                    name: name.into(),
                    declared_type: "REAL".into(),
                    nullable: false,
                    primary_key: false,
                });
        }
        assert_point_code(
            &two_points,
            observed,
            "geometry.point_count_exceeded",
            "resources[0].properties",
        );
    }

    #[test]
    fn point_carriers_require_distinct_known_simple_numeric_columns() {
        let wrong_crs = point_contract().replace(
            "http://www.opengis.net/def/crs/OGC/0/CRS84",
            "https://www.opengis.net/def/crs/OGC/0/CRS84",
        );
        assert_point_code(
            &wrong_crs,
            point_observed_schema("REAL", "REAL"),
            "geometry.crs_unsupported",
            "resources[0].properties.location.crs",
        );

        let invalid = point_contract().replace(
            "longitudeColumn: longitude",
            "longitudeColumn: longitude.value",
        );
        assert_point_code(
            &invalid,
            point_observed_schema("REAL", "REAL"),
            "geometry.carrier_column_invalid",
            "resources[0].properties.location.source.longitudeColumn",
        );

        let unknown = point_contract().replace(
            "longitudeColumn: longitude",
            "longitudeColumn: missing_longitude",
        );
        assert_point_code(
            &unknown,
            point_observed_schema("REAL", "REAL"),
            "geometry.carrier_column_unknown",
            "resources[0].properties.location.source.longitudeColumn",
        );

        let duplicate =
            point_contract().replace("latitudeColumn: latitude", "latitudeColumn: longitude");
        assert_point_code(
            &duplicate,
            point_observed_schema("REAL", "REAL"),
            "geometry.carrier_columns_duplicate",
            "resources[0].properties.location.source.latitudeColumn",
        );

        assert_point_code(
            &point_contract(),
            point_observed_schema("TEXT", "REAL"),
            "geometry.carrier_declared_type_incompatible",
            "resources[0].properties.location.source.longitudeColumn",
        );
    }

    #[test]
    fn point_carrier_classification_inherits_and_obeys_monotonic_overrides() {
        let stricter = point_contract().replace(
            "    sourceColumnClassifications: {}",
            "    sourceColumnClassifications: {longitude: {handling: internal}}",
        );
        let contract = RegistryContract::parse_yaml(&stricter).expect("strict Point");
        let compiled = compile_contract(
            &contract,
            &[point_observed_schema("REAL", "NUMERIC")],
            CompileProfile::Production,
        )
        .expect("a stricter carrier handling override compiles");
        let longitude = compiled.resources[0]
            .column_accounting
            .iter()
            .find(|column| column.column == "longitude")
            .expect("longitude account");
        assert_eq!(longitude.classification.handling, Handling::Internal);

        let weaker = point_contract()
            .replace(
                "        semanticTerm: local:location",
                "        semanticTerm: local:location\n        classification: {handling: internal}",
            )
            .replace(
                "    sourceColumnClassifications: {}",
                "    sourceColumnClassifications: {longitude: {handling: public}}",
            );
        assert_point_code(
            &weaker,
            point_observed_schema("REAL", "NUMERIC"),
            "classification.column_weaker_than_property",
            "resources[0].sourceColumnClassifications.longitude.handling",
        );

        let privacy_mismatch = point_contract().replace(
            "    sourceColumnClassifications: {}",
            "    sourceColumnClassifications: {latitude: {privacy: identifying}}",
        );
        assert_point_code(
            &privacy_mismatch,
            point_observed_schema("REAL", "NUMERIC"),
            "classification.geometry_carrier_privacy_mismatch",
            "resources[0].sourceColumnClassifications.latitude.privacy",
        );
    }

    #[test]
    fn geometry_disclosure_is_access_profile_scoped() {
        let disclosed = point_contract().replace(
            "disclosureProfiles: {public: {properties: [name]}}",
            "disclosureProfiles: {public: {properties: [name, location]}}",
        );
        let contract = RegistryContract::parse_yaml(&disclosed).expect("strict Point contract");
        let compiled = compile_contract(
            &contract,
            &[point_observed_schema("REAL", "REAL")],
            CompileProfile::Production,
        )
        .expect("Point disclosure compiles");
        assert_eq!(
            compiled.resources[0].operations[0].access_profiles[0].projected_columns,
            [
                "id",
                "revision",
                "lifecycle",
                "recorded_at",
                "name",
                "longitude",
                "latitude"
            ]
        );
        let mut hidden = compiled.resources[0].operations[0].access_profiles[0].clone();
        hidden
            .selectable_properties
            .retain(|property| property != "location");
        hidden
            .projected_columns
            .retain(|column| column != "longitude" && column != "latitude");
        assert!(!hidden.selectable_properties.contains(&"location".into()));
        assert!(!hidden
            .projected_columns
            .iter()
            .any(|column| column == "longitude" || column == "latitude"));
    }

    #[test]
    fn point_carriers_cannot_collide_with_existing_column_uses() {
        let core = point_contract().replace("longitudeColumn: longitude", "longitudeColumn: id");
        let scalar =
            point_contract().replace("longitudeColumn: longitude", "longitudeColumn: name");
        let selector = point_contract().replace(
            "      read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
            "      lookups:\n        - id: by-coordinate\n          requestBody:\n            maximumBytes: 64\n            selectors:\n              coordinate: {sourceColumn: longitude, type: integer}\n          defaultAccessProfile: public\n          accessProfiles:\n            public: {access: public, disclosureProfile: public}",
        );
        let row_binding = point_contract().replace(
            "access: public",
            "access: {scope: registry:records:read, authorityRowBinding: {claim: region, sourceColumn: longitude}}",
        );
        let filter = point_contract()
            .replace(
                "sourceColumn: name\n        type: string",
                "sourceColumn: longitude\n        type: integer",
            )
            .replace(
                "      read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "      list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters:\n          - {name: byName, property: name, type: integer}\n        allowUnfiltered: false\n        orderBy: []\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            );
        let order = point_contract()
            .replace(
                "sourceColumn: name\n        type: string",
                "sourceColumn: longitude\n        type: integer",
            )
            .replace(
                "      read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "      list:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            );

        for yaml in [core, scalar, selector, row_binding, filter, order] {
            assert_point_code(
                &yaml,
                point_observed_schema("INTEGER", "REAL"),
                "geometry.carrier_column_collision",
                "resources[0].properties.location.source.longitudeColumn",
            );
        }
    }

    fn assert_point_code(yaml: &str, observed: ObservedSourceSchema, code: &str, location: &str) {
        let contract = RegistryContract::parse_yaml(yaml).expect("strict Point contract");
        let report = compile_contract(&contract, &[observed], CompileProfile::Production)
            .expect_err("invalid Point contract is refused");
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("missing {code}: {:?}", report.diagnostics));
        assert_eq!(diagnostic.location, location);
    }

    fn point_contract() -> String {
        valid_contract()
            .replace(
                "        semanticTerm: local:name\n    disclosureProfiles:",
                "        semanticTerm: local:name\n      location:\n        label: Location\n        description: Reviewed Point location\n        type: point\n        crs: http://www.opengis.net/def/crs/OGC/0/CRS84\n        source: {longitudeColumn: longitude, latitudeColumn: latitude}\n        sourceRequired: true\n        semanticTerm: local:location\n    primaryGeometry: location\n    disclosureProfiles:",
            )
    }

    #[test]
    fn named_point_bbox_search_compiles_against_the_primary_point_property() {
        let contract = spatial_contract();
        let compiled = compile_contract(
            &contract,
            &[point_observed_schema("INTEGER", "REAL")],
            CompileProfile::Production,
        )
        .expect("named Point bbox search compiles");
        let operation = &compiled.resources[0].operations[0];
        assert_eq!(operation.identifier, "record.search.within-bbox");
        assert_eq!(
            operation.query.spatial_bbox.as_ref(),
            Some(&CompiledSpatialBboxQuery {
                longitude_column: "longitude".into(),
                latitude_column: "latitude".into(),
                maximum_longitude_span_degrees: 2,
                maximum_latitude_span_degrees: 2,
            })
        );
        assert_eq!(operation.query.order_by, ["name", "id"]);
    }

    pub(crate) fn spatial_contract() -> RegistryContract {
        let yaml = point_contract()
            .replace(
                "disclosureProfiles: {public: {properties: [name]}}",
                "disclosureProfiles: {public: {properties: [name, location]}}",
            )
            .replace(
                "      read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "      searches:\n        - id: within-bbox\n          query: {kind: point-bbox, maximumLongitudeSpanDegrees: 2, maximumLatitudeSpanDegrees: 2}\n          defaultAccessProfile: public\n          accessProfiles:\n            public: {access: public, disclosureProfile: public}\n          orderBy: [name]\n          pagination: {defaultPageSize: 10, maximumPageSize: 100}",
            )
            .replace(
                "operationRefs: [read]",
                "operationRefs: [search:within-bbox]",
            );
        RegistryContract::parse_yaml(&yaml).expect("strict spatial contract")
    }

    pub(crate) fn point_observed_schema(
        longitude_type: &str,
        latitude_type: &str,
    ) -> ObservedSourceSchema {
        let mut observed = observed_schema();
        for (name, declared_type) in [("longitude", longitude_type), ("latitude", latitude_type)] {
            observed.views[0]
                .columns
                .push(crate::model::ObservedColumn {
                    name: name.into(),
                    declared_type: declared_type.into(),
                    nullable: false,
                    primary_key: false,
                });
        }
        observed
    }

    pub(crate) fn observed_schema() -> ObservedSourceSchema {
        ObservedSourceSchema {
            source: "db".into(),
            fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            views: vec![crate::model::ObservedView {
                name: "registry_records".into(),
                columns: ["id", "revision", "lifecycle", "recorded_at", "name"]
                    .into_iter()
                    .map(|name| crate::model::ObservedColumn {
                        name: name.into(),
                        declared_type: "TEXT".into(),
                        nullable: false,
                        primary_key: false,
                    })
                    .collect(),
            }],
        }
    }

    pub(crate) fn governed_files() -> GovernedFileSet {
        let contract = RegistryContract::parse_yaml(valid_contract()).expect("strict contract");
        governed_files_for(&contract)
    }

    pub(crate) fn statistical_observed_schema() -> ObservedSourceSchema {
        ObservedSourceSchema {
            source: "db".into(),
            fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            views: vec![crate::model::ObservedView {
                name: "statistical_observations".into(),
                columns: [
                    ("ref_area", "TEXT"),
                    ("sex", "TEXT"),
                    ("time_period", "TEXT"),
                    ("obs_value", "REAL"),
                    ("unit_measure", "TEXT"),
                ]
                .into_iter()
                .map(|(name, declared_type)| crate::model::ObservedColumn {
                    name: name.into(),
                    declared_type: declared_type.into(),
                    nullable: false,
                    primary_key: false,
                })
                .collect(),
            }],
        }
    }

    pub(crate) fn statistical_contract() -> &'static str {
        r#"apiVersion: relay.registrystack.org/v2alpha1
kind: RegistryContract
metadata: {id: statistics, version: "1", title: Statistics}
registry:
  registryIdentifier: urn:example:registry:statistics
  name: Statistics
  authority: {identifier: urn:example:authority, name: Registry Authority}
  authoritativeScope: Reviewed aggregate observations
  baseUri: https://statistics.example.invalid/registry/
  identifierLifecyclePolicyRef: governance/identifier-lifecycle.yaml
  alignmentTargets:
    - {name: govstack-digital-registries, version: 3.0.0-alpha.2, status: directional}
governance: {controller: urn:example:authority, publisher: urn:example:authority, auditOwner: urn:example:audit}
semantics: {localVocabulary: https://statistics.example.invalid/vocabulary/}
classifications:
  privacy: {scheme: https://w3id.org/dpv, version: "2.3"}
  institutional: {scheme: urn:example:classification, version: "1"}
  handling: {scheme: https://id.registrystack.org/vocab/handling, version: "1"}
  provenanceRef: governance/classification-review.yaml
sources:
  db: {kind: sqlite, profile: snapshot, expectedSchemaFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
statisticalDatasets:
  - id: labour-rates
    title: Labour rates
    description: Reviewed aggregate labour rates
    publication: {releaseAt: 2026-08-10T00:00:00Z}
    source: {source: db, view: statistical_observations}
    classificationDefaults: {privacy: non-personal, institutional: public, handling: public, status: reviewed}
    sourceColumnClassifications: {}
    dimensions:
      refArea: {label: Reference area, description: Observation area, column: ref_area, type: code, vocabulary: codelists/areas.yaml, concept: local:refArea}
      sex: {label: Sex, description: Observation sex, column: sex, type: code, vocabulary: codelists/sex.yaml, concept: local:sex}
    time: {label: Time period, description: Annual observation period, column: time_period, granularity: annual, concept: local:timePeriod}
    measure: {id: obsValue, label: Observation value, description: Labour rate, column: obs_value, type: decimal, concept: local:obsValue}
    attributes:
      unitMeasure: {label: Unit, description: Observation unit, column: unit_measure, type: code, vocabulary: codelists/units.yaml, required: true, concept: local:unitMeasure}
    access: public
    query: {allowUnfiltered: true, maximumObservations: 100, maximumOffset: 1000}
    bindings: {sdmx: {}}
    processingDescriptions:
      - id: statistical-publication
        operationRefs: [statistics:read]
        purpose: statistical-publication
        recipientClass: public
        legalBasisRef: governance/legal-basis.yaml
        dpvProfileRef: governance/processing.dpv.yaml
        safeguards: [pre-aggregated-publication]
metadataVisibility: {service: public, resources: operator-only, statisticalDatasets: public, semantics: public, classifications: public, processing: public}
"#
    }

    pub(crate) fn governed_files_for(contract: &RegistryContract) -> GovernedFileSet {
        let observed = if !contract.statistical_datasets.is_empty() {
            statistical_observed_schema()
        } else if contract
            .resources
            .iter()
            .any(|resource| resource.primary_geometry.is_some())
        {
            point_observed_schema("INTEGER", "REAL")
        } else {
            observed_schema()
        };
        let compiled = compile_contract(contract, &[observed], CompileProfile::Production)
            .expect("inventory compiles");
        let inventory_digest =
            classification_inventory_digest(&compiled).expect("inventory digest");
        let registry_identifier = &contract.registry.registry_identifier;
        let review = format!(
            "apiVersion: relay.registrystack.org/classification-review/v1\nkind: ClassificationReview\nregistryIdentifier: {registry_identifier}\nclassificationInventoryDigest: {inventory_digest}\nmethod: manual\nreviewer: urn:example:authority\nreviewDate: 2026-08-10\nstatus: reviewed\nrationaleRef: governance/review-rationale\n"
        );
        let mut files = [
            (
                "governance/identifier-lifecycle.yaml",
                "status: reviewed\npolicy: identifiers are not reassigned\n",
            ),
            (
                "governance/legal-basis.yaml",
                "status: reviewed\nbasis: statutory-publication\n",
            ),
            (
                "governance/review-rationale",
                "reviewed classification and access profile design\n",
            ),
            (
                "governance/processing.dpv.yaml",
                "status: reviewed\nprofile: https://w3id.org/dpv/2.3\n",
            ),
            (
                "codelists/record-lifecycle.yaml",
                "id: record-lifecycle\nversion: 1\nvalues: [ACTIVE, RETIRED]\nstatus: reviewed\n",
            ),
        ]
        .into_iter()
        .map(|(path, content)| (path.into(), content.as_bytes().to_vec()))
        .collect::<GovernedFileSet>();
        files.insert(
            "governance/classification-review.yaml".into(),
            review.into_bytes(),
        );
        if !contract.statistical_datasets.is_empty() {
            files.remove("codelists/record-lifecycle.yaml");
            for (path, id, values) in [
                ("codelists/areas.yaml", "areas", "[AREA_A, AREA_B]"),
                ("codelists/sex.yaml", "sex", "[F, M, TOTAL]"),
                ("codelists/units.yaml", "units", "[PERCENT]"),
            ] {
                files.insert(
                    path.into(),
                    format!("id: {id}\nversion: 1\nvalues: {values}\nstatus: reviewed\n")
                        .into_bytes(),
                );
            }
        }
        files
    }

    fn governed_access_profiles_contract() -> String {
        valid_contract()
            .replace(
                "    sourceColumnClassifications: {}",
                "    sourceColumnClassifications:\n      name: {privacy: identifying, institutional: restricted, handling: restricted, status: reviewed}",
            )
            .replace(
                "        semanticTerm: local:name\n    disclosureProfiles: {public: {properties: [name]}}",
                "        semanticTerm: local:name\n        classification: {privacy: identifying, institutional: restricted, handling: restricted, status: reviewed}\n      maskedName:\n        label: Masked name\n        description: Partially revealed Record name\n        sourceColumn: name\n        type: string\n        sourceRequired: true\n        semanticTerm: local:maskedName\n        classification: {privacy: partially-revealed-identifying, institutional: confidential, handling: confidential, status: reviewed}\n        transform: {kind: partial-string, reveal: suffix, characters: 4}\n    disclosureProfiles:\n      limited: {properties: [maskedName]}\n      full: {properties: [name]}",
            )
            .replace(
                "      read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "      read:\n        defaultAccessProfile: limited\n        accessProfiles:\n          limited:\n            access: {scope: registry:records:limited}\n            disclosureProfile: limited\n          full:\n            access: {scope: registry:records:full}\n            disclosureProfile: full",
            )
            .replace(
                "metadataVisibility: {service: public, resources: public, semantics: public, classifications: public, processing: public}",
                "metadataVisibility: {service: public, resources: operation-bound, semantics: operation-bound, classifications: operation-bound, processing: operation-bound}",
            )
    }

    pub(crate) fn valid_contract() -> &'static str {
        r#"apiVersion: relay.registrystack.org/v2alpha1
kind: RegistryContract
metadata: {id: records, version: "1", title: Records}
registry:
  registryIdentifier: urn:example:registry:records
  name: Records
  authority: {identifier: urn:example:authority, name: Registry Authority}
  authoritativeScope: Synthetic records
  baseUri: https://registry.example.invalid/registry/
  identifierLifecyclePolicyRef: governance/identifier-lifecycle.yaml
  alignmentTargets:
    - {name: govstack-digital-registries, version: 3.0.0-alpha.2, status: directional}
governance: {controller: urn:example:authority, publisher: urn:example:authority, auditOwner: urn:example:audit}
semantics: {localVocabulary: https://registry.example.invalid/vocabulary/}
classifications:
  privacy: {scheme: https://w3id.org/dpv, version: "2.3"}
  institutional: {scheme: urn:example:classification, version: "1"}
  handling: {scheme: https://id.registrystack.org/vocab/handling, version: "1"}
  provenanceRef: governance/classification-review.yaml
sources:
  db: {kind: sqlite, profile: snapshot, expectedSchemaFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
resources:
  - id: record
    title: Record
    description: One governed Record
    semanticClass: local:Record
    source: {source: db, view: registry_records}
    classificationDefaults: {privacy: non-personal, institutional: public, handling: public, status: reviewed}
    recordContext:
      recordIdentifier: {sourceColumn: id}
      revisionIdentifier: {sourceColumn: revision}
      lifecycleState: {sourceColumn: lifecycle, codelist: codelists/record-lifecycle.yaml}
      recordedAt: {sourceColumn: recorded_at}
    sourceColumnClassifications: {}
    properties:
      name:
        label: Name
        description: Public Record name
        sourceColumn: name
        type: string
        sourceRequired: true
        semanticTerm: local:name
    disclosureProfiles: {public: {properties: [name]}}
    operations:
      read:
        defaultAccessProfile: public
        accessProfiles:
          public: {access: public, disclosureProfile: public}
    processingDescriptions:
      - id: statutory-publication
        operationRefs: [read]
        purpose: statutory-publication
        recipientClass: public
        legalBasisRef: governance/legal-basis.yaml
        dpvProfileRef: governance/processing.dpv.yaml
        safeguards: [property-minimization]
metadataVisibility: {service: public, resources: public, semantics: public, classifications: public, processing: public}
"#
    }
}
