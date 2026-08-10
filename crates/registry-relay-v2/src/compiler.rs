// SPDX-License-Identifier: Apache-2.0
//! Closed compilation from authored contract plus observed schema to one model.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Component, Path};

use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::contract::{
    AccessRule, AuthorityRowBinding, ClassificationPartial, DataType, DateInputType, DatePrecision,
    Handling, IdentificationMethod, RegistryContract, RepresentationDefinition, ReviewStatus,
    SourceProfile, TransformDefinition,
};
use crate::model::{
    CapabilityFamily, ColumnAccount, ColumnUse, CompileProfile, CompileReport, CompiledAccess,
    CompiledClassificationReview, CompiledCodelist, CompiledDisclosureProfile, CompiledFilter,
    CompiledGeneratedIdentificationBinding, CompiledGovernedFile, CompiledMetadataVisibility,
    CompiledOperation, CompiledPagination, CompiledProperty, CompiledPurpose,
    CompiledRecordContext, CompiledRegistry, CompiledRepresentation, CompiledResource,
    CompiledRowBinding, CompiledSelector, CompiledSource, CompiledTransform, ConsultationPattern,
    Diagnostic, DiagnosticSeverity, EffectiveClassification, ObservedSourceSchema, OperationKind,
    QueryPlan, RowAuthoritySource, StarterColumn, StarterContract,
};

const API_VERSION: &str = "relay.registrystack.org/v2alpha1";
const RESERVED_PARAMETERS: [&str; 4] = ["pageSize", "cursor", "fields", "representation"];
const MAXIMUM_RESOURCES: usize = 128;
const MAXIMUM_PROPERTIES_PER_RESOURCE: usize = 128;
const MAXIMUM_DISCLOSURE_PROFILES_PER_RESOURCE: usize = 64;
const MAXIMUM_REPRESENTATIONS_PER_OPERATION: usize = 16;
const MAXIMUM_REPRESENTATION_EXECUTORS_PER_REGISTRY: usize = 128;
const MAXIMUM_LIST_FILTERS: usize = 32;
const MAXIMUM_LIST_ORDER_KEYS: usize = 32;
const MAXIMUM_LIST_PAGE_SIZE: u32 = 1_000;
const MAXIMUM_LOOKUP_REQUEST_BODY_BYTES: u32 = 1024 * 1024;
const MAXIMUM_LOOKUP_SELECTORS: usize = 32;
const MAXIMUM_SELECTOR_BYTES: u32 = 4 * 1024;
const MAXIMUM_PARTIAL_STRING_CHARACTERS: u16 = 64;

pub type GovernedFileSet = BTreeMap<String, Vec<u8>>;

pub(crate) fn referenced_governed_files(contract: &RegistryContract) -> BTreeSet<&str> {
    let mut references = BTreeSet::new();
    references.insert(contract.registry.identifier_lifecycle_policy_ref.as_str());
    references.insert(contract.classifications.provenance_ref.as_str());
    for alignment in &contract.semantics.alignments {
        references.insert(alignment.profile_ref.as_str());
    }
    for resource in &contract.resources {
        references.insert(resource.record_context.lifecycle_state.codelist.as_str());
        for (_, property) in resource.properties.iter() {
            if let Some(codelist) = property.codelist.as_deref() {
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
    let representation_executors = resources
        .iter()
        .flat_map(|resource| &resource.operations)
        .map(|operation| operation.representations.len())
        .sum::<usize>();
    if representation_executors > MAXIMUM_REPRESENTATION_EXECUTORS_PER_REGISTRY {
        compiler.error(
            "representation.registry_bound_exceeded",
            "resources",
            "the compiled representation count exceeds the Registry runtime ceiling",
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

    Ok(CompiledRegistry {
        contract_revision,
        contract_id: contract.metadata.id.clone(),
        contract_version: contract.metadata.version.clone(),
        registry_identifier: contract.registry.registry_identifier.clone(),
        registry_name: contract.registry.name.clone(),
        authority_identifier: contract.registry.authority.identifier.clone(),
        operator_identifier: contract
            .registry
            .operator
            .as_ref()
            .map(|operator| operator.identifier.clone()),
        authoritative_scope: contract.registry.authoritative_scope.clone(),
        base_uri: contract.registry.base_uri.clone(),
        identifier_lifecycle_policy_ref: contract.registry.identifier_lifecycle_policy_ref.clone(),
        alignment_targets: contract.registry.alignment_targets.clone(),
        controller_identifier: contract.governance.controller.clone(),
        publisher_identifier: contract.governance.publisher.clone(),
        audit_owner_identifier: contract.governance.audit_owner.clone(),
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
        metadata_visibility: CompiledMetadataVisibility {
            service: contract.metadata_visibility.service,
            resources: contract.metadata_visibility.resources,
            semantics: contract.metadata_visibility.semantics,
            classifications: contract.metadata_visibility.classifications,
            processing: contract.metadata_visibility.processing,
        },
    })
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
    let (codelists, file_digests, classification_review, report) =
        validate_governed_files(contract, files, profile, &registry);
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
            if definition.codelist.as_deref() == Some(path) {
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
    resource_ids: HashSet<String>,
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
            resource_ids: HashSet::new(),
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
        if !valid_absolute_url(&self.contract.registry.base_uri) {
            self.error(
                "registry.base_uri_invalid",
                "registry.baseUri",
                "the Registry base URI must be an absolute HTTP or HTTPS URL",
            );
        }
        if !valid_absolute_url(&self.contract.semantics.local_vocabulary) {
            self.error(
                "semantics.local_vocabulary_invalid",
                "semantics.localVocabulary",
                "the local vocabulary must be an absolute HTTP or HTTPS URL",
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
        if self.contract.resources.is_empty() {
            self.error(
                "resource.none",
                "resources",
                "at least one resource is required",
            );
        }
        if self.contract.resources.len() > MAXIMUM_RESOURCES {
            self.error(
                "resource.bound_exceeded",
                "resources",
                "the governed resource count exceeds the product ceiling",
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
            if !self.resource_ids.insert(resource.id.clone()) {
                self.error(
                    "resource.id_duplicate",
                    &format!("{root}.id"),
                    "resource identifiers must be unique",
                );
            }
            if !valid_kebab_identifier(&resource.id) {
                self.error(
                    "resource.id_invalid",
                    &format!("{root}.id"),
                    "a resource identifier must be URL-safe kebab case",
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
                if !valid_sql_identifier(&property.source_column) {
                    self.error(
                        "property.column_invalid",
                        &format!("{location}.sourceColumn"),
                        "property columns must be simple SQLite identifiers",
                    );
                }
                if !property_names.insert(name) {
                    self.error(
                        "property.name_duplicate",
                        &location,
                        "property keys must be unique",
                    );
                }
                if !column_exists(observed_columns.as_ref(), &property.source_column) {
                    self.error(
                        "property.column_unknown",
                        &format!("{location}.sourceColumn"),
                        "the property source column is absent from the reviewed view",
                    );
                }
                validate_codelist(
                    &mut self.report,
                    property.data_type,
                    property.codelist.as_deref(),
                    &location,
                );
                if let Some(codelist) = property.codelist.as_deref() {
                    if !valid_relative_reference(codelist) {
                        self.error(
                            "datatype.codelist_ref_invalid",
                            &format!("{location}.codelist"),
                            "codelists must be contained relative file references",
                        );
                    }
                }
                let transform = self.compile_transform(
                    property.transform.as_ref(),
                    property.data_type,
                    &location,
                );
                if let Some(observed) = observed_view.and_then(|view| {
                    view.columns
                        .iter()
                        .find(|column| column.name == property.source_column)
                }) {
                    let source_type = transform_source_type(transform.as_ref(), property.data_type);
                    if !compatible_declared_type(source_type, &observed.declared_type) {
                        self.error(
                            "property.declared_type_incompatible",
                            &format!("{location}.type"),
                            "the published datatype is incompatible with the reviewed SQLite declaration",
                        );
                    }
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
                self.validate_review_status(&classification, &format!("{location}.classification"));
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
                property_columns
                    .entry(property.source_column.as_str())
                    .or_default()
                    .push((name, classification.clone(), transform.is_some()));
                properties.push(CompiledProperty {
                    name: name.to_owned(),
                    label: property.label.clone(),
                    description: property.description.clone(),
                    source_column: property.source_column.clone(),
                    transform,
                    data_type: property.data_type,
                    codelist: property.codelist.clone(),
                    source_required: property.source_required,
                    semantic_iri,
                    classification,
                });
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
                    observed_columns.as_ref(),
                    &root,
                    "read",
                    OperationKind::Read,
                    &read.default_representation,
                    &read.representations,
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
                if !valid_kebab_identifier(&lookup.id) {
                    self.error(
                        "operation.lookup_id_invalid",
                        &format!("{location}.id"),
                        "lookup identifiers must be URL-safe kebab case",
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
                if let Some(mut operation) = self.compile_simple_operation(
                    resource,
                    &properties,
                    &disclosures,
                    observed_columns.as_ref(),
                    &location,
                    "lookup",
                    OperationKind::Lookup {
                        name: lookup.id.clone(),
                    },
                    &lookup.default_representation,
                    &lookup.representations,
                ) {
                    operation.identifier = format!("{}.lookup.{}", resource.id, lookup.id);
                    operation.query.selectors = selectors;
                    operation.query.maximum_request_body_bytes =
                        Some(lookup.request_body.maximum_bytes);
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
                disclosure_profiles: disclosures,
                operations,
                column_accounting,
                processing_descriptions: resource.processing_descriptions.clone(),
            });
        }
        compiled
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_simple_operation(
        &mut self,
        resource: &crate::contract::ResourceDefinition,
        properties: &[CompiledProperty],
        disclosures: &[CompiledDisclosureProfile],
        observed_columns: Option<&BTreeSet<&str>>,
        root: &str,
        operation_location: &str,
        kind: OperationKind,
        default_representation: &str,
        representation_definitions: &crate::contract::OrderedMap<RepresentationDefinition>,
    ) -> Option<CompiledOperation> {
        let location = if operation_location == "lookup" {
            root.to_owned()
        } else {
            format!("{root}.operations.{operation_location}")
        };
        if representation_definitions.is_empty() {
            self.error(
                "representation.none",
                &format!("{location}.representations"),
                "an operation must declare at least one finite representation",
            );
            return None;
        }
        if representation_definitions.len() > MAXIMUM_REPRESENTATIONS_PER_OPERATION {
            self.error(
                "representation.bound_exceeded",
                &format!("{location}.representations"),
                "the representation count exceeds the per-operation product ceiling",
            );
        }
        if !valid_kebab_identifier(default_representation)
            || representation_definitions
                .get(default_representation)
                .is_none()
        {
            self.error(
                "representation.default_invalid",
                &format!("{location}.defaultRepresentation"),
                "the explicit default must name exactly one declared representation",
            );
        }
        let identifier = match &kind {
            OperationKind::Read => format!("{}.read", resource.id),
            OperationKind::List => format!("{}.list", resource.id),
            OperationKind::Lookup { name } => format!("{}.lookup.{name}", resource.id),
        };
        let pattern = match &kind {
            OperationKind::List => ConsultationPattern::List,
            OperationKind::Read => ConsultationPattern::Retrieve,
            OperationKind::Lookup { .. } => ConsultationPattern::Search,
        };
        let artifact_stem = operation_artifact_stem(&resource.id, &kind);
        let mut representations = Vec::with_capacity(representation_definitions.len());
        for (representation_id, definition) in representation_definitions.iter() {
            let representation_location = format!("{location}.representations.{representation_id}");
            if !valid_kebab_identifier(representation_id) {
                self.error(
                    "representation.id_invalid",
                    &representation_location,
                    "representation identifiers must be URL-safe kebab case",
                );
            }
            let Some(disclosure) = disclosures
                .iter()
                .find(|item| item.id == definition.disclosure_profile)
            else {
                self.error(
                    "representation.disclosure_unknown",
                    &format!("{representation_location}.disclosureProfile"),
                    "the representation names no disclosure profile",
                );
                continue;
            };
            let Some(access) = self.compile_access(
                &definition.access,
                observed_columns,
                &representation_location,
            ) else {
                continue;
            };
            validate_disclosure_access(
                &mut self.report,
                disclosure,
                &access,
                matches!(&kind, OperationKind::List),
                &representation_location,
            );
            let representation_artifact_stem =
                format!("{artifact_stem}--representation-{representation_id}");
            representations.push(CompiledRepresentation {
                id: representation_id.to_owned(),
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
                                property.transform.as_ref().map(|transform| {
                                    format!("{}={}", property.name, transform.identifier())
                                })
                            })
                    })
                    .collect(),
                schema_reference: artifact_url(
                    &self.contract.registry.base_uri,
                    &format!("{representation_artifact_stem}-schema"),
                ),
                semantic_model_reference: artifact_url(
                    &self.contract.registry.base_uri,
                    &format!("{representation_artifact_stem}-vocabulary"),
                ),
                context_reference: artifact_url(
                    &self.contract.registry.base_uri,
                    &format!("{representation_artifact_stem}-context"),
                ),
            });
        }
        if representations
            .iter()
            .any(|representation| matches!(representation.access, CompiledAccess::Public))
            && representations
                .iter()
                .find(|representation| representation.id == default_representation)
                .is_some_and(|representation| {
                    !matches!(representation.access, CompiledAccess::Public)
                })
        {
            self.error(
                "representation.public_default_required",
                &format!("{location}.defaultRepresentation"),
                "an operation with a public representation must use a public default",
            );
        }
        Some(CompiledOperation {
            identifier,
            family: CapabilityFamily::Consultation,
            pattern,
            kind,
            default_representation: default_representation.to_owned(),
            representations,
            query: QueryPlan {
                source: resource.source.source.clone(),
                view: resource.source.view.clone(),
                filters: Vec::new(),
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
            observed_columns,
            root,
            "list",
            OperationKind::List,
            &list.default_representation,
            &list.representations,
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
                    if property.data_type != filter.data_type {
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
                        source_column: property.source_column.clone(),
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
        for property_name in &list.order_by {
            if !order.insert(property_name.as_str()) {
                self.error(
                    "list.order_duplicate",
                    &format!("{location}.orderBy"),
                    "fixed order keys must be unique",
                );
            }
            match properties
                .iter()
                .find(|property| property.name == *property_name)
            {
                Some(property) => {
                    if !property.source_required {
                        self.error(
                            "list.order_property_optional",
                            &format!("{location}.orderBy"),
                            "fixed order properties must be required in the governed source contract",
                        );
                    }
                    if !cursor_order_type_supported(property.data_type) {
                        self.error(
                            "list.order_property_type_unsupported",
                            &format!("{location}.orderBy"),
                            "fixed order properties must use a cursor-supported string, integer, or boolean value shape",
                        );
                    }
                    if !order_columns.insert(property.source_column.as_str()) {
                        self.error(
                            "list.order_column_duplicate",
                            &format!("{location}.orderBy"),
                            "fixed order properties must resolve to distinct source columns",
                        );
                    }
                    self.validate_cursor_order_column(
                        observed_view,
                        &property.source_column,
                        property.data_type,
                        &format!("{location}.orderBy"),
                    );
                    operation
                        .query
                        .order_by
                        .push(property.source_column.clone());
                }
                None => self.error(
                    "list.order_property_unknown",
                    &format!("{location}.orderBy"),
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

    fn compile_access(
        &mut self,
        access: &AccessRule,
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
            uses.entry(&property.source_column)
                .or_default()
                .insert(ColumnUse::Property(property.name.clone()));
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
            for representation in &operation.representations {
                if let CompiledAccess::Protected {
                    row_binding: Some(row_binding),
                    ..
                } = &representation.access
                {
                    uses.entry(&row_binding.source_column).or_default().insert(
                        ColumnUse::RowBinding(format!(
                            "{}:{}",
                            operation.identifier, representation.id
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
            let requires_explicit_review = property_bindings.is_some_and(|bindings| {
                bindings.len() > 1 || bindings.iter().any(|(_, _, transformed)| *transformed)
            });
            if requires_explicit_review
                && !source_override.is_some_and(explicit_reviewed_classification)
            {
                if self.profile == CompileProfile::Production {
                    self.error(
                        "classification.column_explicit_review_required",
                        &format!("{root}.sourceColumnClassifications.{column}"),
                        "a transformed or multiply-bound source column requires its own complete reviewed classification",
                    );
                } else {
                    self.warning(
                        "classification.column_explicit_review_required",
                        &format!("{root}.sourceColumnClassifications.{column}"),
                        "a transformed or multiply-bound source column still requires its own complete reviewed classification",
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
                    &format!("{root}.sourceColumnClassifications"),
                    "an accounted source column has no complete classification",
                );
                continue;
            };
            if let Some(bindings) = property_bindings {
                let strongest_direct = bindings
                    .iter()
                    .filter(|(_, _, transformed)| !*transformed)
                    .map(|(_, item, _)| item.handling)
                    .max();
                if source_override.is_some_and(explicit_reviewed_classification)
                    && strongest_direct.is_some_and(|handling| classification.handling < handling)
                {
                    self.error(
                        "classification.column_weaker_than_property",
                        &format!("{root}.sourceColumnClassifications"),
                        "a source-column classification cannot weaken a direct property handling floor",
                    );
                }
            }
            self.validate_review_status(
                &classification,
                &format!("{root}.sourceColumnClassifications"),
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
            };
            for representation in &mut operation.representations {
                let mut referenced = BTreeSet::new();
                referenced.extend(representation.projected_columns.iter().map(String::as_str));
                referenced.extend(
                    operation
                        .query
                        .filters
                        .iter()
                        .map(|filter| filter.source_column.as_str()),
                );
                referenced.extend(operation.query.order_by.iter().map(String::as_str));
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
                } = &representation.access
                {
                    referenced.insert(&binding.source_column);
                }
                representation.processing_handling = columns
                    .iter()
                    .filter(|column| referenced.contains(column.column.as_str()))
                    .fold(Handling::Public, |maximum, column| {
                        maximum.max(column.classification.handling)
                    });
                let representation_location =
                    format!("{location}.representations.{}", representation.id);
                if representation.processing_handling > Handling::Public
                    && matches!(representation.access, CompiledAccess::Public)
                {
                    self.error(
                        "access.public_nonpublic_forbidden",
                        &representation_location,
                        "anonymous representations may process only public-handling reviewed columns",
                    );
                }
                if representation.processing_handling == Handling::Restricted
                    && matches!(&operation.kind, OperationKind::List)
                {
                    self.error(
                        "operation.restricted_list_forbidden",
                        &representation_location,
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
                .representations
                .iter()
                .any(|representation| matches!(representation.access, CompiledAccess::Public))
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
        // representation. A protected representation is operation-bound even
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

    fn validate_review_status(&mut self, classification: &EffectiveClassification, location: &str) {
        if classification.status != ReviewStatus::Reviewed {
            match self.profile {
                CompileProfile::Authoring => self.warning(
                    "classification.unreviewed",
                    location,
                    "classification suggestions require institutional review",
                ),
                CompileProfile::Production => self.error(
                    "classification.unreviewed",
                    location,
                    "production compilation requires reviewed classification",
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
/// uses, and finite representation disclosures are present.
pub fn classification_inventory_digest(
    registry: &CompiledRegistry,
) -> Result<String, CompileReport> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Inventory<'a> {
        registry_identifier: &'a str,
        sources: Vec<SourceInventory<'a>>,
        resources: Vec<ResourceInventory<'a>>,
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
        source_column: &'a str,
        transform: &'a Option<CompiledTransform>,
        data_type: DataType,
        codelist: &'a Option<String>,
        source_required: bool,
        semantic_iri: &'a str,
        classification: &'a EffectiveClassification,
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
        default_representation: &'a str,
        representations: Vec<RepresentationInventory<'a>>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct RepresentationInventory<'a> {
        id: &'a str,
        access: &'a CompiledAccess,
        disclosure_profile: &'a str,
        selectable_properties: &'a [String],
        projected_columns: &'a [String],
        processing_handling: Handling,
        disclosure_handling: Handling,
        transform_inventory: &'a [String],
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
                    .map(|property| PropertyInventory {
                        name: &property.name,
                        source_column: &property.source_column,
                        transform: &property.transform,
                        data_type: property.data_type,
                        codelist: &property.codelist,
                        source_required: property.source_required,
                        semantic_iri: &property.semantic_iri,
                        classification: &property.classification,
                    })
                    .collect(),
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
                        default_representation: &operation.default_representation,
                        representations: operation
                            .representations
                            .iter()
                            .map(|representation| RepresentationInventory {
                                id: &representation.id,
                                access: &representation.access,
                                disclosure_profile: &representation.disclosure_profile,
                                selectable_properties: &representation.selectable_properties,
                                projected_columns: &representation.projected_columns,
                                processing_handling: representation.processing_handling,
                                disclosure_handling: representation.disclosure_handling,
                                transform_inventory: &representation.transform_inventory,
                            })
                            .collect(),
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
    let mut sidecar_paths = BTreeSet::new();
    sidecar_paths.insert(contract.registry.identifier_lifecycle_policy_ref.as_str());
    sidecar_paths.insert(contract.classifications.provenance_ref.as_str());
    for alignment in &contract.semantics.alignments {
        sidecar_paths.insert(alignment.profile_ref.as_str());
    }
    for resource in &contract.resources {
        codelist_paths.insert(resource.record_context.lifecycle_state.codelist.as_str());
        for (_, property) in resource.properties.iter() {
            if let Some(codelist) = property.codelist.as_deref() {
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
    // Only the selected finite representation may widen the Registry Core
    // projection. This is what lets a public representation prove that it
    // never processes a hidden non-public source column.
    for name in disclosure {
        if let Some(property) = properties.iter().find(|property| property.name == *name) {
            push_unique(&mut columns, &property.source_column);
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

fn compatible_declared_type(data_type: DataType, declared_type: &str) -> bool {
    let declared = declared_type.trim().to_ascii_uppercase();
    match data_type {
        DataType::Boolean | DataType::Integer => declared.contains("INT") || declared == "BOOLEAN",
        DataType::String
        | DataType::Date
        | DataType::DateTime
        | DataType::Year
        | DataType::YearMonth
        | DataType::ControlledCode => {
            declared.contains("CHAR")
                || declared.contains("CLOB")
                || declared.contains("TEXT")
                || declared == "DATE"
                || declared == "DATETIME"
        }
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
        return Some(format!("{base}{local}"));
    }
    valid_absolute_url(term).then(|| term.to_owned())
}

fn artifact_url(base: &str, artifact_id: &str) -> String {
    Url::parse(base).map_or_else(
        |_| format!("{base}v2/artifacts/{artifact_id}"),
        |mut url| {
            url.set_path(&format!("/v2/artifacts/{artifact_id}"));
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
        let representation = &operation.representations[0];
        let schema = first_artifacts
            .artifacts
            .iter()
            .find(|artifact| representation.schema_reference.ends_with(&artifact.id))
            .expect("operation schema is mounted by its exact artifact identifier");
        assert_eq!(schema.visibility, crate::contract::Visibility::Public);
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
    fn list_order_ends_in_one_non_null_string_record_identifier() {
        let yaml = valid_contract()
            .replace(
                "        semanticTerm: local:name\n    disclosureProfiles",
                "        semanticTerm: local:name\n      recordId:\n        label: Record identifier\n        description: Stable record identifier\n        sourceColumn: id\n        type: string\n        sourceRequired: true\n        semanticTerm: local:recordId\n    disclosureProfiles",
            )
            .replace(
                "read:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [recordId, name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
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
                "read:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
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
    fn sqlite_view_nullable_metadata_does_not_override_required_order_contract() {
        let yaml = valid_contract()
            .replace(
                "read:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
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
                "read:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: []\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
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
                "read:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}",
                "list:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
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
        operation.representations[0].schema_reference = "https://elsewhere.invalid/schema".into();
        operation.representations[0].semantic_model_reference =
            "https://elsewhere.invalid/vocabulary".into();
        operation.representations[0].context_reference = "https://elsewhere.invalid/context".into();
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
        transform_changed.resources[0].properties[0].transform =
            Some(CompiledTransform::PartialString {
                identifier: "partial-string:suffix:2".into(),
                reveal: crate::contract::PartialStringReveal::Suffix,
                characters: 2,
            });
        assert_ne!(
            classification_inventory_digest(&transform_changed).expect("transform digest"),
            baseline
        );

        let mut transform_inventory_changed = compiled.clone();
        transform_inventory_changed.resources[0].operations[0].representations[0]
            .transform_inventory
            .push("partial-string:suffix:2".into());
        assert_ne!(
            classification_inventory_digest(&transform_inventory_changed)
                .expect("transform inventory digest"),
            baseline
        );

        let mut access_changed = compiled.clone();
        access_changed.resources[0].operations[0].representations[0].access =
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
        disclosure_changed.resources[0].operations[0].representations[0].disclosure_handling =
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
            "read:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}",
            &format!(
                "list:\n        defaultRepresentation: public\n        representations:\n          public: {{access: public, disclosureProfile: public}}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {{defaultPageSize: 1, maximumPageSize: {}}}",
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
            "read:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}",
            &format!(
                "lookups:\n        - id: by-name\n          requestBody:\n            maximumBytes: {}\n            selectors:\n              name: {{sourceColumn: name, type: string, maximumBytes: 32}}\n          defaultRepresentation: public\n          representations:\n            public: {{access: {{scope: registry:records:lookup}}, disclosureProfile: public}}",
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

        let mut representations_value = serde_json::to_value(&base).expect("contract serializes");
        let representations = representations_value
            .pointer_mut("/resources/0/operations/read/representations")
            .and_then(serde_json::Value::as_object_mut)
            .expect("representations object");
        let representation = representations
            .get("public")
            .expect("public representation")
            .clone();
        for index in 1..=MAXIMUM_REPRESENTATIONS_PER_OPERATION {
            representations.insert(format!("profile-{index}"), representation.clone());
        }
        assert_refused(
            &parse_value(representations_value),
            "representation.bound_exceeded",
        );

        let mut registry_representations_value =
            serde_json::to_value(&base).expect("contract serializes");
        let registry_representations = registry_representations_value
            .pointer_mut("/resources/0/operations/read/representations")
            .and_then(serde_json::Value::as_object_mut)
            .expect("representations object");
        let representation = registry_representations
            .get("public")
            .expect("public representation")
            .clone();
        for index in 1..=MAXIMUM_REPRESENTATION_EXECUTORS_PER_REGISTRY {
            registry_representations.insert(format!("profile-{index}"), representation.clone());
        }
        assert_refused(
            &parse_value(registry_representations_value),
            "representation.registry_bound_exceeded",
        );

        let list_yaml = valid_contract().replace(
            "read:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}",
            "list:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 1}",
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
    fn an_operation_with_a_public_representation_requires_a_public_default() {
        let contract = RegistryContract::parse_yaml(&valid_contract().replace(
            "defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}",
            "defaultRepresentation: protected\n        representations:\n          public: {access: public, disclosureProfile: public}\n          protected: {access: {scope: registry:record:protected}, disclosureProfile: public}",
        ))
        .expect("strict contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("a hidden protected default is refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "representation.public_default_required"));
    }

    #[test]
    fn one_operation_compiles_finite_representations_with_distinct_handling() {
        let contract = RegistryContract::parse_yaml(&governed_representations_contract())
            .expect("strict representation contract");
        let compiled =
            compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                .expect("representations compile");
        let resource = &compiled.resources[0];
        assert_eq!(resource.operations.len(), 1);
        let operation = &resource.operations[0];
        assert_eq!(operation.identifier, "record.read");
        assert_eq!(operation.default_representation, "limited");
        assert_eq!(operation.representations.len(), 2);
        let limited = &operation.representations[0];
        let full = &operation.representations[1];
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
        let yaml = governed_representations_contract().replace(
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
    fn representation_default_and_transform_parameters_fail_closed() {
        let invalid_default = governed_representations_contract().replace(
            "defaultRepresentation: limited",
            "defaultRepresentation: absent",
        );
        let contract = RegistryContract::parse_yaml(&invalid_default).expect("strict contract");
        let report = compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
            .expect_err("unknown default refused");
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "representation.default_invalid"));

        for characters in [0, MAXIMUM_PARTIAL_STRING_CHARACTERS + 1] {
            let yaml = governed_representations_contract()
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
    fn public_masked_representation_cannot_process_restricted_source() {
        let yaml = governed_representations_contract()
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
        let yaml = governed_representations_contract()
            .replace("type: string\n        sourceRequired: true\n        semanticTerm: local:maskedName\n        classification: {privacy: partially-revealed-identifying, institutional: confidential, handling: confidential, status: reviewed}\n        transform: {kind: partial-string, reveal: suffix, characters: 4}", "type: year-month\n        sourceRequired: true\n        semanticTerm: local:maskedName\n        classification: {privacy: partially-revealed-identifying, institutional: confidential, handling: confidential, status: reviewed}\n        transform: {kind: date-precision, sourceType: date-time, precision: year-month}");
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict date transform");
        let compiled =
            compile_contract(&contract, &[observed_schema()], CompileProfile::Production)
                .expect("typed date precision compiles");
        assert_eq!(
            compiled.resources[0].properties[1].data_type,
            DataType::YearMonth
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
        } = &operation.representations[0].access
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

    fn governed_files_for(contract: &RegistryContract) -> GovernedFileSet {
        let compiled = compile_contract(contract, &[observed_schema()], CompileProfile::Production)
            .expect("inventory compiles");
        let inventory_digest =
            classification_inventory_digest(&compiled).expect("inventory digest");
        let review = format!(
            "apiVersion: relay.registrystack.org/classification-review/v1\nkind: ClassificationReview\nregistryIdentifier: urn:example:registry:records\nclassificationInventoryDigest: {inventory_digest}\nmethod: manual\nreviewer: urn:example:authority\nreviewDate: 2026-08-10\nstatus: reviewed\nrationaleRef: governance/review-rationale\n"
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
                "reviewed classification and representation design\n",
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
        files
    }

    fn governed_representations_contract() -> String {
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
                "      read:\n        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}",
                "      read:\n        defaultRepresentation: limited\n        representations:\n          limited:\n            access: {scope: registry:records:limited}\n            disclosureProfile: limited\n          full:\n            access: {scope: registry:records:full}\n            disclosureProfile: full",
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
        defaultRepresentation: public
        representations:
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
