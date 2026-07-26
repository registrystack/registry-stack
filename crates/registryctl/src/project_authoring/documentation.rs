// SPDX-License-Identifier: Apache-2.0
//! Deterministic documentation data for project-authoring and product runtime contracts.
//!
//! The generator has three declared inputs: committed JSON Schemas, the field-knowledge catalog,
//! and reviewed human intent. It has no project-directory argument and cannot open a country
//! workspace. Schema validation remains authoritative; this projection exists only for reference
//! documentation and coverage enforcement.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::knowledge::{
    index_published_field_knowledge, reachable_published_field_paths, Availability, Consumer,
    FieldKnowledgeCatalog, FieldPath, FieldPathKind, GeneratedArtifact, HumanOwner, Migration,
    Product, PublishedSchema, ReviewClass, SchemaKind, SemanticOwner, SemanticRule, Sensitivity,
    Stability,
};

pub const CONFIGURATION_REFERENCE_FORMAT_VERSION: &str = "1.0";
pub const CONFIGURATION_REFERENCE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/registryctl/project-documentation/registry.project.configuration_reference.v1.schema.json";
pub const CONFIGURATION_REFERENCE_COVERAGE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/registryctl/project-documentation/registry.project.configuration_reference_coverage.v1.schema.json";

const INTENT_ASSET: &str =
    include_str!("../../schemas/project-authoring/documentation-intent.json");
const PROJECT_SCHEMA: &str = include_str!("../../schemas/project-authoring/project.schema.json");
const ENVIRONMENT_SCHEMA: &str =
    include_str!("../../schemas/project-authoring/environment.schema.json");
const INTEGRATION_SCHEMA: &str =
    include_str!("../../schemas/project-authoring/integration.schema.json");
const FIXTURE_SCHEMA: &str = include_str!("../../schemas/project-authoring/fixture.schema.json");
const ENTITY_SCHEMA: &str = include_str!("../../schemas/project-authoring/entity.schema.json");
const KNOWLEDGE_ASSET: &str = include_str!("../../schemas/project-authoring/parity-coverage.json");
const RELAY_RUNTIME_INTENT_ASSET: &str =
    include_str!("../../../registry-relay/config/documentation-intent.json");
const NOTARY_RUNTIME_INTENT_ASSET: &str =
    include_str!("../../../registry-notary-core/config/documentation-intent.json");
const RELAY_RUNTIME_INTENT_SOURCE: &str = "crates/registry-relay/config/documentation-intent.json";
const NOTARY_RUNTIME_INTENT_SOURCE: &str =
    "crates/registry-notary-core/config/documentation-intent.json";

const CONSTRAINT_KEYWORDS: [&str; 21] = [
    "const",
    "dependentRequired",
    "enum",
    "exclusiveMaximum",
    "exclusiveMinimum",
    "format",
    "maxItems",
    "maxLength",
    "maxProperties",
    "maximum",
    "minItems",
    "minLength",
    "minProperties",
    "minimum",
    "multipleOf",
    "pattern",
    "patternProperties",
    "required",
    "type",
    "uniqueItems",
    "unevaluatedProperties",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationIntentCatalog {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub format_version: String,
    pub policy: DocumentationIntentPolicy,
    pub structural_intents: BTreeMap<FieldPathKind, StructuralIntent>,
    pub structural_reviews: Vec<StructuralIntentReview>,
    pub domains: Vec<DocumentationDomainIntent>,
    pub overrides: Vec<FieldIntentOverride>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationIntentPolicy {
    pub human_sources: Vec<HumanIntentSource>,
    pub prohibited_sources: Vec<ProhibitedIntentSource>,
    pub prose_required_for: Vec<FieldPathKind>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanIntentSource {
    SchemaDescription,
    ReviewedOverride,
    StructuralTaxonomy,
    ReviewedProfile,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum ProhibitedIntentSource {
    CountryWorkspace,
    CountryValue,
    RuntimeConfiguration,
    DerivedFieldLabel,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralIntent {
    pub purpose: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralIntentReview {
    pub schema: SchemaKind,
    pub pointer: String,
    pub path_kind: FieldPathKind,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIntentCatalog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub format_version: String,
    pub runtime_schema: ConfigurationSchemaKind,
    pub schema_id: String,
    pub schema_source: String,
    pub profiles: Vec<RuntimeIntentProfile>,
    pub assignments: Vec<RuntimeIntentAssignment>,
    pub overrides: Vec<RuntimeIntentOverride>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIntentProfile {
    pub id: String,
    pub purpose: String,
    pub semantic_owner: SemanticOwner,
    pub human_owner: HumanOwner,
    pub scope: String,
    pub environment_behavior: EnvironmentBehavior,
    pub sensitivity: Sensitivity,
    pub state: ConfigurationState,
    pub products: Vec<Product>,
    pub availability: Availability,
    pub stability: Stability,
    pub validation_stages: Vec<ValidationStage>,
    pub diagnostic: String,
    pub introduced_in: String,
    pub migration: Migration,
    pub migration_note: String,
    pub example_guidance: String,
    pub consumers: Vec<Consumer>,
    pub generated_artifacts: Vec<GeneratedArtifact>,
    pub review_classes: Vec<ReviewClass>,
    pub semantic_rules: Vec<SemanticRule>,
    #[serde(default)]
    pub open_map_semantics: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePurposeSource {
    SchemaDescription,
    Profile,
    Override,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDefaultSource {
    SchemaDefault,
    NoSchemaDefault,
    ReviewedRuntimeDefault,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIntentAssignment {
    pub schema: ConfigurationSchemaKind,
    pub pointer: String,
    pub key_path: String,
    pub path_kind: FieldPathKind,
    pub profile: String,
    pub purpose_source: RuntimePurposeSource,
    pub default_source: RuntimeDefaultSource,
    pub schema_facts_reviewed: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIntentOverride {
    pub schema: ConfigurationSchemaKind,
    pub pointer: String,
    pub key_path: String,
    pub path_kind: FieldPathKind,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub runtime_default_note: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationDomainIntent {
    pub schema: SchemaKind,
    pub scope: String,
    pub state: ConfigurationState,
    pub environment_behavior: EnvironmentBehavior,
    pub validation_stages: Vec<ValidationStage>,
    pub diagnostic: String,
    pub migration_note: String,
    pub example_guidance: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldIntentOverride {
    pub schema: SchemaKind,
    pub pointer: String,
    pub purpose: String,
    #[serde(default)]
    pub environment_behavior: Option<EnvironmentBehavior>,
    #[serde(default)]
    pub diagnostic: Option<String>,
    #[serde(default)]
    pub migration_note: Option<String>,
    #[serde(default)]
    pub example_guidance: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationState {
    Authored,
    EnvironmentBound,
    Runtime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentBehavior {
    EnvironmentIndependent,
    BoundByEnvironment,
    NarrowsReviewedAuthority,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStage {
    JsonSchema,
    RustDeserialization,
    CrossFileSemantic,
    FixtureExecution,
    ProductBuild,
    OperatorPreflight,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationSchemaKind {
    Project,
    Environment,
    Integration,
    Fixture,
    Entity,
    Relay,
    Notary,
}

impl fmt::Display for ConfigurationSchemaKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Project => "project",
            Self::Environment => "environment",
            Self::Integration => "integration",
            Self::Fixture => "fixture",
            Self::Entity => "entity",
            Self::Relay => "relay",
            Self::Notary => "notary",
        })
    }
}

impl From<SchemaKind> for ConfigurationSchemaKind {
    fn from(kind: SchemaKind) -> Self {
        match kind {
            SchemaKind::Project => Self::Project,
            SchemaKind::Environment => Self::Environment,
            SchemaKind::Integration => Self::Integration,
            SchemaKind::Fixture => Self::Fixture,
            SchemaKind::Entity => Self::Entity,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationReferenceV1 {
    pub schema_id: &'static str,
    pub format_version: &'static str,
    pub reference_baseline: ReferenceBaseline,
    pub source_contract: ReferenceSourceContract,
    pub coverage: ReferenceCoverageSummary,
    pub fields: Vec<ConfigurationFieldReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceBaseline {
    pub generator_lifecycle: GeneratorLifecycle,
    pub published_release: Option<String>,
    pub field_history_status: FieldHistoryStatus,
    pub history_verification_method: Option<HistoryVerificationMethod>,
    pub compared_releases: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorLifecycle {
    Unreleased,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldHistoryStatus {
    NotVerified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryVerificationMethod {
    ReleaseSchemaDiff,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceSourceContract {
    pub schemas: Vec<ConfigurationSchemaKind>,
    pub schema_sources: Vec<String>,
    pub field_knowledge: &'static str,
    pub human_intent: &'static str,
    pub runtime_intent: Vec<&'static str>,
    pub reads_country_workspaces: bool,
    pub reads_runtime_configuration: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceCoverageSummary {
    pub schema_count: usize,
    pub path_count: usize,
    pub reference_count: usize,
    pub by_schema: BTreeMap<ConfigurationSchemaKind, usize>,
    pub by_path_kind: BTreeMap<FieldPathKind, usize>,
    pub by_sensitivity: BTreeMap<Sensitivity, usize>,
    pub by_intent_source: BTreeMap<HumanIntentSource, usize>,
    pub by_intent_profile: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationFieldReference {
    pub address: DocumentationFieldAddress,
    pub purpose: String,
    pub purpose_source: HumanIntentSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_profile: Option<String>,
    pub semantic_owner: SemanticOwner,
    pub human_owner: HumanOwner,
    pub scope: String,
    pub field_type: FieldTypeDocumentation,
    pub requiredness: Requiredness,
    pub null_behavior: NullBehavior,
    pub empty_behavior: EmptyBehavior,
    pub default: DefaultDocumentation,
    pub environment_behavior: EnvironmentBehavior,
    pub sensitivity: Sensitivity,
    pub state: ConfigurationState,
    pub products: Vec<Product>,
    pub availability: Availability,
    pub stability: Stability,
    pub validation_stages: Vec<ValidationStage>,
    pub diagnostic: String,
    pub history_status: FieldHistoryStatus,
    pub introduced_in: Option<String>,
    pub version_history: Vec<VersionHistoryEntry>,
    pub example: ExampleDocumentation,
    pub migration: Migration,
    pub migration_note: String,
    pub consumers: Vec<Consumer>,
    pub generated_artifacts: Vec<GeneratedArtifact>,
    pub review_classes: Vec<ReviewClass>,
    pub semantic_rules: Vec<SemanticRule>,
    pub constraints: Vec<SchemaConstraint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_reference: Option<DocumentationSchemaAddress>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationFieldAddress {
    pub schema: ConfigurationSchemaKind,
    pub pointer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    pub path_kind: FieldPathKind,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationSchemaAddress {
    pub schema: ConfigurationSchemaKind,
    pub pointer: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FieldTypeDocumentation {
    pub schema_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_reference: Option<String>,
    pub composed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Requiredness {
    Required,
    Optional,
    Conditional,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullBehavior {
    Allowed,
    Rejected,
    Conditional,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmptyBehavior {
    Allowed,
    Rejected,
    Conditional,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultDocumentation {
    pub behavior: DefaultBehavior,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_behavior: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultBehavior {
    NoSchemaDefault,
    SchemaDefault,
    ReviewedRuntimeDefault,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VersionHistoryEntry {
    pub version: String,
    pub change: VersionChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionChange {
    Introduced,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExampleDocumentation {
    pub guidance: String,
    pub schema_examples_available: bool,
    pub contains_country_values: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaConstraint {
    pub keyword: String,
    pub value: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationReferenceCoverageV1 {
    pub schema_id: &'static str,
    pub format_version: &'static str,
    pub status: CoverageStatus,
    pub reference_baseline: ReferenceBaseline,
    pub source_contract: ReferenceSourceContract,
    pub coverage: ReferenceCoverageSummary,
    pub reviewed_intent_assignment_required_count: usize,
    pub reviewed_intent_assignment_covered_count: usize,
    pub distinct_reviewed_intent_count: usize,
    pub distinct_reviewed_intents_reused_count: usize,
    pub reviewed_intent_assignments_using_reused_intent_count: usize,
    pub missing_intent: Vec<DocumentationFieldAddress>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentationError(String);

impl fmt::Display for DocumentationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for DocumentationError {}

fn documentation_error(message: impl Into<String>) -> DocumentationError {
    DocumentationError(message.into())
}

#[derive(Debug)]
pub struct DocumentationSchema<'a> {
    pub published: PublishedSchema<'a>,
    pub source_name: &'a str,
}

#[derive(Debug)]
struct PreparedDocumentation<'a> {
    schemas: &'a [DocumentationSchema<'a>],
    index: super::knowledge::FieldKnowledgeIndex,
    domains: BTreeMap<SchemaKind, &'a DocumentationDomainIntent>,
    overrides: BTreeMap<FieldPath, &'a FieldIntentOverride>,
    structural_reviews: BTreeSet<(FieldPath, FieldPathKind)>,
    purpose_sources: BTreeMap<HumanIntentSource, usize>,
    purpose_counts: BTreeMap<String, usize>,
    missing: Vec<DocumentationFieldAddress>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RuntimePathIdentity {
    schema: ConfigurationSchemaKind,
    pointer: String,
    key_path: String,
    path_kind: FieldPathKind,
}

#[derive(Clone, Debug)]
struct RuntimeSchemaPath {
    identity: RuntimePathIdentity,
    nodes: Vec<Value>,
    required: BTreeSet<bool>,
}

#[derive(Debug)]
struct PreparedRuntimeIntent<'a> {
    paths: BTreeMap<String, RuntimeSchemaPath>,
    profiles: BTreeMap<&'a str, &'a RuntimeIntentProfile>,
    assignments: BTreeMap<String, &'a RuntimeIntentAssignment>,
    overrides: BTreeMap<String, &'a RuntimeIntentOverride>,
    missing: Vec<DocumentationFieldAddress>,
}

/// Audits all documentation inputs and returns a deterministic, value-free coverage report.
pub fn configuration_reference_coverage(
    catalog: &FieldKnowledgeCatalog,
    schemas: &[DocumentationSchema<'_>],
    intent: &DocumentationIntentCatalog,
) -> Result<ConfigurationReferenceCoverageV1, DocumentationError> {
    let prepared = prepare(catalog, schemas, intent)?;
    let source_contract = source_contract(schemas);
    let coverage = coverage_summary(&prepared);
    let reviewed_intent_assignment_required_count = prepared
        .index
        .by_path()
        .values()
        .filter(|knowledge| {
            intent
                .policy
                .prose_required_for
                .contains(&knowledge.path_kind)
        })
        .count();
    let reviewed_intent_assignment_covered_count =
        reviewed_intent_assignment_required_count - prepared.missing.len();
    let intent_counts = reviewed_intent_counts(&prepared.purpose_counts);
    Ok(ConfigurationReferenceCoverageV1 {
        schema_id: CONFIGURATION_REFERENCE_COVERAGE_SCHEMA_ID,
        format_version: CONFIGURATION_REFERENCE_FORMAT_VERSION,
        status: if prepared.missing.is_empty() {
            CoverageStatus::Complete
        } else {
            CoverageStatus::Incomplete
        },
        reference_baseline: reference_baseline(),
        source_contract,
        coverage,
        reviewed_intent_assignment_required_count,
        reviewed_intent_assignment_covered_count,
        distinct_reviewed_intent_count: intent_counts.distinct,
        distinct_reviewed_intents_reused_count: intent_counts.distinct_reused,
        reviewed_intent_assignments_using_reused_intent_count: intent_counts
            .assignments_using_reused,
        missing_intent: prepared.missing,
    })
}

/// Generates the canonical reference only after every prose-required field has reviewed intent.
pub fn generate_configuration_reference(
    catalog: &FieldKnowledgeCatalog,
    schemas: &[DocumentationSchema<'_>],
    intent: &DocumentationIntentCatalog,
) -> Result<ConfigurationReferenceV1, DocumentationError> {
    let prepared = prepare(catalog, schemas, intent)?;
    if !prepared.missing.is_empty() {
        let paths = prepared
            .missing
            .iter()
            .map(|address| format!("{}#{}", address.schema, address.pointer))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(documentation_error(format!(
            "configuration reference has {} fields without reviewed human intent: {paths}",
            prepared.missing.len()
        )));
    }

    let fields = prepared
        .index
        .by_path()
        .iter()
        .map(|(path, knowledge)| {
            let schema = prepared
                .schemas
                .iter()
                .find(|schema| schema.published.kind == path.schema)
                .ok_or_else(|| documentation_error(format!("missing schema for {path}")))?;
            let node = schema
                .published
                .document
                .pointer(&path.pointer)
                .ok_or_else(|| {
                    documentation_error(format!("published documentation path disappeared: {path}"))
                })?;
            let contract_node = resolve_local_reference(schema.published.document, node)?;
            let domain = prepared.domains[&path.schema];
            let override_intent = prepared.overrides.get(path).copied();
            let (purpose, purpose_source) = reviewed_purpose(
                node,
                contract_node,
                knowledge.path_kind,
                override_intent,
                intent,
                path,
                &prepared.structural_reviews,
            )?;
            let environment_behavior = override_intent
                .and_then(|entry| entry.environment_behavior)
                .unwrap_or(domain.environment_behavior);
            let diagnostic = override_intent
                .and_then(|entry| entry.diagnostic.as_ref())
                .unwrap_or(&domain.diagnostic)
                .clone();
            let migration_note = override_intent
                .and_then(|entry| entry.migration_note.as_ref())
                .unwrap_or(&domain.migration_note)
                .clone();
            let example_guidance = override_intent
                .and_then(|entry| entry.example_guidance.as_ref())
                .unwrap_or(&domain.example_guidance)
                .clone();
            let reference = prepared.index.references().get(path);

            Ok(ConfigurationFieldReference {
                address: field_address(path, knowledge.path_kind),
                purpose,
                purpose_source,
                intent_profile: None,
                semantic_owner: knowledge.semantic_owner,
                human_owner: knowledge.human_owner,
                scope: domain.scope.clone(),
                field_type: field_type(node, contract_node),
                requiredness: requiredness(
                    schema.published.document,
                    path,
                    node,
                    knowledge.path_kind,
                ),
                null_behavior: null_behavior(contract_node, knowledge.path_kind),
                empty_behavior: empty_behavior(contract_node, knowledge.path_kind),
                default: default_documentation(contract_node, knowledge.path_kind),
                environment_behavior,
                sensitivity: knowledge.sensitivity,
                state: domain.state,
                products: knowledge.products.clone(),
                availability: knowledge.availability,
                stability: knowledge.stability,
                validation_stages: domain.validation_stages.clone(),
                diagnostic,
                history_status: FieldHistoryStatus::NotVerified,
                introduced_in: None,
                version_history: Vec::new(),
                example: ExampleDocumentation {
                    guidance: example_guidance,
                    schema_examples_available: contract_node
                        .get("examples")
                        .and_then(Value::as_array)
                        .is_some_and(|examples| !examples.is_empty()),
                    contains_country_values: false,
                },
                migration: knowledge.migration,
                migration_note,
                consumers: knowledge.consumers.clone(),
                generated_artifacts: knowledge.generated_artifacts.clone(),
                review_classes: knowledge.review_classes.clone(),
                semantic_rules: knowledge.semantic_rules.clone(),
                constraints: schema_constraints(node, contract_node),
                local_reference: reference.map(|target| DocumentationSchemaAddress {
                    schema: target.schema.into(),
                    pointer: target.pointer.clone(),
                }),
            })
        })
        .collect::<Result<Vec<_>, DocumentationError>>()?;

    Ok(ConfigurationReferenceV1 {
        schema_id: CONFIGURATION_REFERENCE_SCHEMA_ID,
        format_version: CONFIGURATION_REFERENCE_FORMAT_VERSION,
        reference_baseline: reference_baseline(),
        source_contract: source_contract(schemas),
        coverage: coverage_summary(&prepared),
        fields,
    })
}

fn runtime_schema_paths(
    schema: ConfigurationSchemaKind,
    document: &Value,
) -> Result<BTreeMap<String, RuntimeSchemaPath>, DocumentationError> {
    let mut paths = BTreeMap::new();
    let mut visited_references = BTreeSet::new();
    record_runtime_path(
        &mut paths,
        RuntimePathIdentity {
            schema,
            pointer: String::new(),
            key_path: String::new(),
            path_kind: FieldPathKind::Root,
        },
        document,
        None,
    )?;
    walk_runtime_schema(
        schema,
        document,
        document,
        "",
        "",
        &mut visited_references,
        &mut paths,
    )?;
    Ok(paths)
}

fn walk_runtime_schema(
    schema: ConfigurationSchemaKind,
    document: &Value,
    node: &Value,
    pointer: &str,
    key_path: &str,
    visited_references: &mut BTreeSet<(String, String)>,
    paths: &mut BTreeMap<String, RuntimeSchemaPath>,
) -> Result<(), DocumentationError> {
    let Some(object) = node.as_object() else {
        return Ok(());
    };
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let target_pointer = reference.strip_prefix('#').ok_or_else(|| {
            documentation_error(format!(
                "{schema} runtime schema uses external reference {reference:?}"
            ))
        })?;
        let visit = (target_pointer.to_owned(), key_path.to_owned());
        if visited_references.insert(visit) {
            let target = document.pointer(target_pointer).ok_or_else(|| {
                documentation_error(format!(
                    "{schema} runtime schema has unresolved reference {reference:?}"
                ))
            })?;
            walk_runtime_schema(
                schema,
                document,
                target,
                target_pointer,
                key_path,
                visited_references,
                paths,
            )?;
        }
    }

    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = object.get(keyword).and_then(Value::as_array) {
            for (index, branch) in branches.iter().enumerate() {
                walk_runtime_schema(
                    schema,
                    document,
                    branch,
                    &format!("{pointer}/{keyword}/{index}"),
                    key_path,
                    visited_references,
                    paths,
                )?;
            }
        }
    }

    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        let required = object
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        for (name, property) in properties {
            let child_pointer = format!("{pointer}/properties/{}", escape_pointer_segment(name));
            let child_key_path = if key_path.is_empty() {
                name.clone()
            } else {
                format!("{key_path}.{name}")
            };
            record_runtime_path(
                paths,
                RuntimePathIdentity {
                    schema,
                    pointer: child_pointer.clone(),
                    key_path: child_key_path.clone(),
                    path_kind: FieldPathKind::Property,
                },
                property,
                Some(required.contains(name.as_str())),
            )?;
            walk_runtime_schema(
                schema,
                document,
                property,
                &child_pointer,
                &child_key_path,
                visited_references,
                paths,
            )?;
        }
    }

    if let Some(items) = object.get("items").filter(|value| value.is_object()) {
        let child_pointer = format!("{pointer}/items");
        let child_key_path = format!("{key_path}[]");
        record_runtime_path(
            paths,
            RuntimePathIdentity {
                schema,
                pointer: child_pointer.clone(),
                key_path: child_key_path.clone(),
                path_kind: FieldPathKind::ArrayItem,
            },
            items,
            None,
        )?;
        walk_runtime_schema(
            schema,
            document,
            items,
            &child_pointer,
            &child_key_path,
            visited_references,
            paths,
        )?;
    }

    if let Some(values) = object
        .get("additionalProperties")
        .filter(|value| value.is_object())
    {
        let child_pointer = format!("{pointer}/additionalProperties");
        let child_key_path = format!("{key_path}.*");
        record_runtime_path(
            paths,
            RuntimePathIdentity {
                schema,
                pointer: child_pointer.clone(),
                key_path: child_key_path.clone(),
                path_kind: FieldPathKind::MapValue,
            },
            values,
            None,
        )?;
        walk_runtime_schema(
            schema,
            document,
            values,
            &child_pointer,
            &child_key_path,
            visited_references,
            paths,
        )?;
    }
    Ok(())
}

fn record_runtime_path(
    paths: &mut BTreeMap<String, RuntimeSchemaPath>,
    identity: RuntimePathIdentity,
    node: &Value,
    required: Option<bool>,
) -> Result<(), DocumentationError> {
    if let Some(existing) = paths.get_mut(&identity.key_path) {
        if existing.identity.schema != identity.schema
            || existing.identity.path_kind != identity.path_kind
        {
            return Err(documentation_error(format!(
                "runtime key path {:?} resolves to conflicting schema path kinds",
                identity.key_path
            )));
        }
        if identity.pointer < existing.identity.pointer {
            existing.identity.pointer = identity.pointer;
        }
        existing.nodes.push(node.clone());
        if let Some(required) = required {
            existing.required.insert(required);
        }
        return Ok(());
    }
    let mut requiredness = BTreeSet::new();
    if let Some(required) = required {
        requiredness.insert(required);
    }
    paths.insert(
        identity.key_path.clone(),
        RuntimeSchemaPath {
            identity,
            nodes: vec![node.clone()],
            required: requiredness,
        },
    );
    Ok(())
}

fn escape_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn prepare_runtime_intent<'a>(
    document: &Value,
    intent: &'a RuntimeIntentCatalog,
) -> Result<PreparedRuntimeIntent<'a>, DocumentationError> {
    if intent.schema
        != "https://id.registrystack.org/schemas/registryctl/project-documentation/registry.runtime.configuration_intent.v1.schema.json"
        || intent.format_version != CONFIGURATION_REFERENCE_FORMAT_VERSION
    {
        return Err(documentation_error(
            "runtime intent must identify the strict v1 intent contract",
        ));
    }
    if !matches!(
        intent.runtime_schema,
        ConfigurationSchemaKind::Relay | ConfigurationSchemaKind::Notary
    ) {
        return Err(documentation_error(
            "runtime intent schema must be relay or notary",
        ));
    }
    if document.get("$id").and_then(Value::as_str) != Some(intent.schema_id.as_str()) {
        return Err(documentation_error(format!(
            "{} runtime intent schema id does not match its product schema",
            intent.runtime_schema
        )));
    }
    if !intent.schema_source.ends_with(".schema.json") {
        return Err(documentation_error(
            "runtime intent schema source must name a JSON Schema artifact",
        ));
    }
    let paths = runtime_schema_paths(intent.runtime_schema, document)?;

    let mut profiles = BTreeMap::new();
    for profile in &intent.profiles {
        if profile.id.is_empty()
            || !profile.id.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            })
        {
            return Err(documentation_error(format!(
                "runtime intent profile id {:?} is invalid",
                profile.id
            )));
        }
        for (name, prose) in [
            ("purpose", &profile.purpose),
            ("scope", &profile.scope),
            ("migration_note", &profile.migration_note),
            ("example_guidance", &profile.example_guidance),
        ] {
            validate_prose(
                prose,
                &format!("{} profile {} {name}", intent.runtime_schema, profile.id),
            )?;
        }
        if let Some(semantics) = &profile.open_map_semantics {
            validate_prose(
                semantics,
                &format!(
                    "{} profile {} open_map_semantics",
                    intent.runtime_schema, profile.id
                ),
            )?;
        }
        validate_introduced_version(&profile.introduced_in)?;
        if profile.products.is_empty()
            || profile.validation_stages.is_empty()
            || profile.consumers.is_empty()
            || profile.generated_artifacts.is_empty()
            || profile.review_classes.is_empty()
            || profile.semantic_rules.is_empty()
        {
            return Err(documentation_error(format!(
                "{} profile {} has an empty required semantic dimension",
                intent.runtime_schema, profile.id
            )));
        }
        validate_runtime_profile(intent.runtime_schema, profile)?;
        if profiles.insert(profile.id.as_str(), profile).is_some() {
            return Err(documentation_error(format!(
                "duplicate runtime intent profile {}",
                profile.id
            )));
        }
    }

    let mut assignments = BTreeMap::new();
    let mut used_profiles = BTreeSet::new();
    for assignment in &intent.assignments {
        if assignment.schema != intent.runtime_schema {
            return Err(documentation_error(format!(
                "runtime assignment {:?} declares the wrong product schema",
                assignment.key_path
            )));
        }
        let path = paths.get(&assignment.key_path).ok_or_else(|| {
            documentation_error(format!(
                "{} runtime assignment targets stale key path {:?}",
                intent.runtime_schema, assignment.key_path
            ))
        })?;
        if assignment.pointer != path.identity.pointer
            || assignment.path_kind != path.identity.path_kind
        {
            return Err(documentation_error(format!(
                "{} runtime assignment {:?} has stale pointer or wrong path kind",
                intent.runtime_schema, assignment.key_path
            )));
        }
        if !assignment.schema_facts_reviewed {
            return Err(documentation_error(format!(
                "{} runtime assignment {:?} has not reviewed its schema facts",
                intent.runtime_schema, assignment.key_path
            )));
        }
        let profile = profiles.get(assignment.profile.as_str()).ok_or_else(|| {
            documentation_error(format!(
                "{} runtime assignment {:?} uses unknown profile {:?}",
                intent.runtime_schema, assignment.key_path, assignment.profile
            ))
        })?;
        if assignment.path_kind == FieldPathKind::MapValue && profile.open_map_semantics.is_none() {
            return Err(documentation_error(format!(
                "{} open map {:?} lacks exact extension semantics",
                intent.runtime_schema, assignment.key_path
            )));
        }
        if assignment.path_kind != FieldPathKind::MapValue && profile.open_map_semantics.is_some() {
            return Err(documentation_error(format!(
                "{} non-map path {:?} uses an open-map profile",
                intent.runtime_schema, assignment.key_path
            )));
        }
        let required_path_rule = match assignment.path_kind {
            FieldPathKind::MapKey | FieldPathKind::MapValue => {
                Some(SemanticRule::ArbitraryMapKeysNotFixedProperties)
            }
            FieldPathKind::ArrayItem => Some(SemanticRule::ArrayItemsShareElementContract),
            FieldPathKind::Branch => Some(SemanticRule::BranchHasNoAuthoredValue),
            FieldPathKind::Root | FieldPathKind::Property => None,
        };
        if required_path_rule.is_some_and(|rule| !profile.semantic_rules.contains(&rule)) {
            return Err(documentation_error(format!(
                "{} runtime assignment {:?} profile lacks its path-kind semantic rule",
                intent.runtime_schema, assignment.key_path
            )));
        }
        used_profiles.insert(assignment.profile.as_str());
        if assignments
            .insert(assignment.key_path.clone(), assignment)
            .is_some()
        {
            return Err(documentation_error(format!(
                "duplicate {} runtime assignment for {:?}",
                intent.runtime_schema, assignment.key_path
            )));
        }
    }
    let unused_profiles = profiles
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        .difference(&used_profiles)
        .copied()
        .collect::<Vec<_>>();
    if !unused_profiles.is_empty() {
        return Err(documentation_error(format!(
            "{} runtime intent has unused profiles: {}",
            intent.runtime_schema,
            unused_profiles.join(", ")
        )));
    }

    let mut overrides = BTreeMap::new();
    for entry in &intent.overrides {
        if entry.schema != intent.runtime_schema {
            return Err(documentation_error(
                "runtime override declares wrong schema",
            ));
        }
        let assignment = assignments.get(&entry.key_path).ok_or_else(|| {
            documentation_error(format!(
                "{} runtime override targets unassigned key path {:?}",
                intent.runtime_schema, entry.key_path
            ))
        })?;
        if entry.pointer != assignment.pointer || entry.path_kind != assignment.path_kind {
            return Err(documentation_error(format!(
                "{} runtime override {:?} has stale pointer or wrong path kind",
                intent.runtime_schema, entry.key_path
            )));
        }
        if entry.purpose.is_some() != (assignment.purpose_source == RuntimePurposeSource::Override)
            || entry.runtime_default_note.is_some()
                != (assignment.default_source == RuntimeDefaultSource::ReviewedRuntimeDefault)
        {
            return Err(documentation_error(format!(
                "{} runtime override {:?} conflicts with assignment source flags",
                intent.runtime_schema, entry.key_path
            )));
        }
        if let Some(prose) = &entry.purpose {
            validate_prose(
                prose,
                &format!("{}#{} purpose", entry.schema, entry.key_path),
            )?;
        }
        if let Some(prose) = &entry.runtime_default_note {
            validate_prose(
                prose,
                &format!("{}#{} runtime default", entry.schema, entry.key_path),
            )?;
        }
        if entry.purpose.is_none() && entry.runtime_default_note.is_none() {
            return Err(documentation_error(format!(
                "{} runtime override {:?} is unused",
                intent.runtime_schema, entry.key_path
            )));
        }
        if overrides.insert(entry.key_path.clone(), entry).is_some() {
            return Err(documentation_error(format!(
                "duplicate {} runtime override for {:?}",
                intent.runtime_schema, entry.key_path
            )));
        }
    }

    let mut missing = paths
        .values()
        .filter(|path| !assignments.contains_key(&path.identity.key_path))
        .map(|path| DocumentationFieldAddress {
            schema: path.identity.schema,
            pointer: path.identity.pointer.clone(),
            key_path: Some(path.identity.key_path.clone()),
            path_kind: path.identity.path_kind,
        })
        .collect::<Vec<_>>();
    missing.sort();
    Ok(PreparedRuntimeIntent {
        paths,
        profiles,
        assignments,
        overrides,
        missing,
    })
}

fn validate_runtime_profile(
    schema: ConfigurationSchemaKind,
    profile: &RuntimeIntentProfile,
) -> Result<(), DocumentationError> {
    let (id_prefix, semantic_owner, human_owner, product, consumer, artifact, review_class) =
        match schema {
            ConfigurationSchemaKind::Relay => (
                "relay_",
                SemanticOwner::RelayRuntime,
                HumanOwner::RelayMaintainers,
                Product::Relay,
                Consumer::RegistryRelay,
                GeneratedArtifact::RelayConfig,
                ReviewClass::Relay,
            ),
            ConfigurationSchemaKind::Notary => (
                "notary_",
                SemanticOwner::NotaryRuntime,
                HumanOwner::NotaryMaintainers,
                Product::Notary,
                Consumer::RegistryNotary,
                GeneratedArtifact::NotaryConfig,
                ReviewClass::Notary,
            ),
            _ => {
                return Err(documentation_error(
                    "runtime profile validation requires a product runtime schema",
                ));
            }
        };
    if !profile.id.starts_with(id_prefix)
        || profile.semantic_owner != semantic_owner
        || profile.human_owner != human_owner
        || profile.state != ConfigurationState::Runtime
        || profile.diagnostic.trim().is_empty()
    {
        return Err(documentation_error(format!(
            "{schema} profile {} crosses its product ownership boundary",
            profile.id
        )));
    }
    if profile.diagnostic.contains(' ') {
        validate_prose(
            &profile.diagnostic,
            &format!("{schema} profile {} diagnostic limitation", profile.id),
        )?;
    } else {
        let product_prefix = match schema {
            ConfigurationSchemaKind::Relay => "registry.relay.config.",
            ConfigurationSchemaKind::Notary => "registry.notary.config.",
            _ => unreachable!("runtime profile schema was restricted above"),
        };
        let suffix = profile
            .diagnostic
            .strip_prefix("config.")
            .or_else(|| profile.diagnostic.strip_prefix(product_prefix));
        if suffix.is_none_or(|suffix| {
            suffix.is_empty()
                || !suffix.chars().all(|character| {
                    character.is_ascii_lowercase()
                        || character.is_ascii_digit()
                        || matches!(character, '_' | '.')
                })
        }) {
            return Err(documentation_error(format!(
                "{schema} profile {} has an invalid or cross-product diagnostic code",
                profile.id
            )));
        }
    }
    let products = profile.products.iter().copied().collect::<BTreeSet<_>>();
    let consumers = profile.consumers.iter().copied().collect::<BTreeSet<_>>();
    let artifacts = profile
        .generated_artifacts
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let reviews = profile
        .review_classes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let rules = profile
        .semantic_rules
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if products != [product, Product::Docs].into_iter().collect()
        || consumers != [consumer, Consumer::DocsGenerator].into_iter().collect()
        || artifacts
            != [artifact, GeneratedArtifact::FieldReference]
                .into_iter()
                .collect()
        || ![
            ReviewClass::Contract,
            review_class,
            ReviewClass::Documentation,
        ]
        .into_iter()
        .all(|required| reviews.contains(&required))
        || ![
            SemanticRule::KnowledgeOnly,
            SemanticRule::GeneratedDocsNeverLoadCountryValues,
        ]
        .into_iter()
        .all(|required| rules.contains(&required))
    {
        return Err(documentation_error(format!(
            "{schema} profile {} has incomplete or cross-product ownership metadata",
            profile.id
        )));
    }
    let sensitivity_rule = match profile.sensitivity {
        Sensitivity::Sensitive => Some(SemanticRule::SensitiveOperationalMetadata),
        Sensitivity::SecretReference | Sensitivity::SecretValue => {
            Some(SemanticRule::SecretNeverReportable)
        }
        Sensitivity::RedactedFixture => Some(SemanticRule::SyntheticFixtureValueRedacted),
        Sensitivity::Public | Sensitivity::Internal | Sensitivity::Structural => None,
    };
    if sensitivity_rule.is_some_and(|rule| !rules.contains(&rule)) {
        return Err(documentation_error(format!(
            "{schema} profile {} lacks its sensitivity semantic rule",
            profile.id
        )));
    }
    Ok(())
}

fn validate_introduced_version(version: &str) -> Result<(), DocumentationError> {
    let parts = version.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty() || !part.chars().all(|character| character.is_ascii_digit())
        })
    {
        return Err(documentation_error(format!(
            "runtime intent introduced version {version:?} must be semver-like"
        )));
    }
    Ok(())
}

fn runtime_configuration_fields(
    document: &Value,
    intent: &RuntimeIntentCatalog,
) -> Result<
    (
        Vec<ConfigurationFieldReference>,
        Vec<DocumentationFieldAddress>,
    ),
    DocumentationError,
> {
    let prepared = prepare_runtime_intent(document, intent)?;
    let fields = prepared
        .paths
        .iter()
        .filter(|(key_path, _)| prepared.assignments.contains_key(*key_path))
        .map(|(key_path, path)| {
            let assignment = prepared.assignments[key_path];
            let profile = prepared.profiles[assignment.profile.as_str()];
            let override_intent = prepared.overrides.get(key_path).copied();
            let descriptions = runtime_schema_values(document, &path.nodes, "description")?
                .into_iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect::<BTreeSet<_>>();
            let (purpose, purpose_source) = match assignment.purpose_source {
                RuntimePurposeSource::SchemaDescription => {
                    if descriptions.len() != 1 {
                        return Err(documentation_error(format!(
                            "{} runtime path {key_path:?} reviewed schema-description source but resolves to {} descriptions",
                            intent.runtime_schema,
                            descriptions.len()
                        )));
                    }
                    let purpose = descriptions
                        .iter()
                        .next()
                        .expect("one description is present")
                        .clone();
                    validate_prose(
                        &purpose,
                        &format!("{}#{key_path} schema description", intent.runtime_schema),
                    )?;
                    (purpose, HumanIntentSource::SchemaDescription)
                }
                RuntimePurposeSource::Profile => {
                    if override_intent.and_then(|entry| entry.purpose.as_ref()).is_some() {
                        return Err(documentation_error(format!(
                            "{} runtime path {key_path:?} has a conflicting purpose override",
                            intent.runtime_schema
                        )));
                    }
                    (profile.purpose.clone(), HumanIntentSource::ReviewedProfile)
                }
                RuntimePurposeSource::Override => {
                    let purpose = override_intent
                        .and_then(|entry| entry.purpose.as_ref())
                        .ok_or_else(|| {
                            documentation_error(format!(
                                "{} runtime path {key_path:?} lacks its reviewed purpose override",
                                intent.runtime_schema
                            ))
                        })?
                        .clone();
                    (purpose, HumanIntentSource::ReviewedOverride)
                }
            };
            let defaults = runtime_schema_values(document, &path.nodes, "default")?;
            let default = match assignment.default_source {
                RuntimeDefaultSource::SchemaDefault => {
                    if defaults.len() != 1 {
                        return Err(documentation_error(format!(
                            "{} runtime path {key_path:?} reviewed schema-default source but resolves to {} defaults",
                            intent.runtime_schema,
                            defaults.len()
                        )));
                    }
                    DefaultDocumentation {
                        behavior: DefaultBehavior::SchemaDefault,
                        // Runtime schema defaults may contain deployment-local names or paths.
                        // The reviewed reference reports behavior without copying the value.
                        schema_value: None,
                        source_version: None,
                        reviewed_behavior: Some(
                            "The product-owned JSON Schema publishes the default; its value is intentionally omitted from this value-free reference."
                                .to_owned(),
                        ),
                    }
                }
                RuntimeDefaultSource::NoSchemaDefault => {
                    if !defaults.is_empty() {
                        return Err(documentation_error(format!(
                            "{} runtime path {key_path:?} declares no schema default but one is present",
                            intent.runtime_schema
                        )));
                    }
                    DefaultDocumentation {
                        behavior: DefaultBehavior::NoSchemaDefault,
                        schema_value: None,
                        source_version: None,
                        reviewed_behavior: None,
                    }
                }
                RuntimeDefaultSource::ReviewedRuntimeDefault => {
                    if !defaults.is_empty() {
                        return Err(documentation_error(format!(
                            "{} runtime path {key_path:?} declares an out-of-schema default but the schema publishes one",
                            intent.runtime_schema
                        )));
                    }
                    DefaultDocumentation {
                        behavior: DefaultBehavior::ReviewedRuntimeDefault,
                        schema_value: None,
                        source_version: None,
                        reviewed_behavior: Some(
                            override_intent
                                .and_then(|entry| entry.runtime_default_note.as_ref())
                                .ok_or_else(|| {
                                    documentation_error(format!(
                                        "{} runtime path {key_path:?} lacks its reviewed default override",
                                        intent.runtime_schema
                                    ))
                                })?
                                .clone(),
                        ),
                    }
                }
                RuntimeDefaultSource::NotApplicable => {
                    if !defaults.is_empty() {
                        return Err(documentation_error(format!(
                            "{} runtime path {key_path:?} marks default not applicable but the schema publishes one",
                            intent.runtime_schema
                        )));
                    }
                    DefaultDocumentation {
                        behavior: DefaultBehavior::NotApplicable,
                        schema_value: None,
                        source_version: None,
                        reviewed_behavior: None,
                    }
                }
            };
            let schema_types = runtime_schema_types(document, &path.nodes)?;
            let requiredness = runtime_requiredness(path);
            let null_behavior = runtime_null_behavior(path.identity.path_kind, &schema_types);
            let empty_behavior =
                runtime_empty_behavior(document, path.identity.path_kind, &path.nodes, &schema_types)?;
            let constraints = runtime_schema_constraints(document, &path.nodes)?;
            let local_reference = path
                .nodes
                .iter()
                .find_map(|node| node.get("$ref").and_then(Value::as_str))
                .map(|pointer| DocumentationSchemaAddress {
                    schema: intent.runtime_schema,
                    pointer: pointer.strip_prefix('#').unwrap_or(pointer).to_owned(),
                });
            Ok(ConfigurationFieldReference {
                address: DocumentationFieldAddress {
                    schema: intent.runtime_schema,
                    pointer: path.identity.pointer.clone(),
                    key_path: Some(key_path.clone()),
                    path_kind: path.identity.path_kind,
                },
                purpose,
                purpose_source,
                intent_profile: Some(profile.id.clone()),
                semantic_owner: profile.semantic_owner,
                human_owner: profile.human_owner,
                scope: profile.scope.clone(),
                field_type: FieldTypeDocumentation {
                    schema_types,
                    local_reference: path
                        .nodes
                        .iter()
                        .find_map(|node| node.get("$ref").and_then(Value::as_str))
                        .map(str::to_owned),
                    composed: path.nodes.iter().any(|node| {
                        ["allOf", "anyOf", "oneOf"]
                            .iter()
                            .any(|keyword| node.get(keyword).is_some())
                    }),
                },
                requiredness,
                null_behavior,
                empty_behavior,
                default,
                environment_behavior: profile.environment_behavior,
                sensitivity: profile.sensitivity,
                state: profile.state,
                products: profile.products.clone(),
                availability: profile.availability,
                stability: profile.stability,
                validation_stages: profile.validation_stages.clone(),
                diagnostic: profile.diagnostic.clone(),
                history_status: FieldHistoryStatus::NotVerified,
                introduced_in: None,
                version_history: Vec::new(),
                example: ExampleDocumentation {
                    guidance: profile.example_guidance.clone(),
                    schema_examples_available: !runtime_schema_values(
                        document,
                        &path.nodes,
                        "examples",
                    )?
                    .is_empty(),
                    contains_country_values: false,
                },
                migration: profile.migration,
                migration_note: profile.migration_note.clone(),
                consumers: profile.consumers.clone(),
                generated_artifacts: profile.generated_artifacts.clone(),
                review_classes: profile.review_classes.clone(),
                semantic_rules: profile.semantic_rules.clone(),
                constraints,
                local_reference,
            })
        })
        .collect::<Result<Vec<_>, DocumentationError>>()?;
    Ok((fields, prepared.missing))
}

pub fn runtime_configuration_intent_gaps(
    document: &Value,
    intent: &RuntimeIntentCatalog,
) -> Result<Vec<DocumentationFieldAddress>, DocumentationError> {
    Ok(prepare_runtime_intent(document, intent)?.missing)
}

pub fn generate_runtime_configuration_fields(
    document: &Value,
    intent: &RuntimeIntentCatalog,
) -> Result<Vec<ConfigurationFieldReference>, DocumentationError> {
    let (fields, missing) = runtime_configuration_fields(document, intent)?;
    if !missing.is_empty() {
        return Err(documentation_error(format!(
            "{} runtime configuration has {} paths without exact reviewed intent",
            intent.runtime_schema,
            missing.len()
        )));
    }
    Ok(fields)
}

fn runtime_schema_values(
    document: &Value,
    nodes: &[Value],
    keyword: &str,
) -> Result<Vec<Value>, DocumentationError> {
    let mut values = BTreeMap::new();
    for node in nodes {
        collect_runtime_schema_values(document, node, keyword, &mut BTreeSet::new(), &mut values)?;
    }
    Ok(values.into_values().collect())
}

fn collect_runtime_schema_values(
    document: &Value,
    node: &Value,
    keyword: &str,
    visited: &mut BTreeSet<String>,
    values: &mut BTreeMap<String, Value>,
) -> Result<(), DocumentationError> {
    let Some(object) = node.as_object() else {
        return Ok(());
    };
    if let Some(value) = object.get(keyword) {
        values.insert(
            serde_json::to_string(value).expect("schema keyword value serializes"),
            value.clone(),
        );
    }
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let pointer = reference.strip_prefix('#').ok_or_else(|| {
            documentation_error(format!(
                "runtime schema uses external reference {reference:?}"
            ))
        })?;
        if visited.insert(pointer.to_owned()) {
            let target = document.pointer(pointer).ok_or_else(|| {
                documentation_error(format!(
                    "runtime schema has unresolved reference {reference:?}"
                ))
            })?;
            collect_runtime_schema_values(document, target, keyword, visited, values)?;
        }
    }
    for composer in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = object.get(composer).and_then(Value::as_array) {
            for branch in branches {
                collect_runtime_schema_values(document, branch, keyword, visited, values)?;
            }
        }
    }
    Ok(())
}

fn runtime_schema_types(
    document: &Value,
    nodes: &[Value],
) -> Result<Vec<String>, DocumentationError> {
    let values = runtime_schema_values(document, nodes, "type")?;
    let mut types = BTreeSet::new();
    for value in values {
        match value {
            Value::String(kind) => {
                types.insert(kind);
            }
            Value::Array(kinds) => {
                types.extend(
                    kinds
                        .into_iter()
                        .filter_map(|kind| kind.as_str().map(str::to_owned)),
                );
            }
            _ => {
                return Err(documentation_error(
                    "runtime schema type keyword must be a string or string array",
                ));
            }
        }
    }
    if runtime_schema_values(document, nodes, "const")?
        .iter()
        .any(Value::is_null)
    {
        types.insert("null".to_owned());
    }
    Ok(types.into_iter().collect())
}

fn runtime_requiredness(path: &RuntimeSchemaPath) -> Requiredness {
    match path.identity.path_kind {
        FieldPathKind::Root | FieldPathKind::ArrayItem | FieldPathKind::MapValue => {
            Requiredness::NotApplicable
        }
        FieldPathKind::Property if path.required == [true].into_iter().collect() => {
            Requiredness::Required
        }
        FieldPathKind::Property if path.required == [false].into_iter().collect() => {
            Requiredness::Optional
        }
        FieldPathKind::Property => Requiredness::Conditional,
        FieldPathKind::MapKey | FieldPathKind::Branch => Requiredness::NotApplicable,
    }
}

fn runtime_null_behavior(kind: FieldPathKind, schema_types: &[String]) -> NullBehavior {
    if kind == FieldPathKind::Root {
        return NullBehavior::NotApplicable;
    }
    if schema_types.iter().any(|kind| kind == "null") {
        if schema_types.len() == 1 {
            NullBehavior::Allowed
        } else {
            NullBehavior::Conditional
        }
    } else {
        NullBehavior::Rejected
    }
}

fn runtime_empty_behavior(
    document: &Value,
    kind: FieldPathKind,
    nodes: &[Value],
    schema_types: &[String],
) -> Result<EmptyBehavior, DocumentationError> {
    if kind == FieldPathKind::Root || !schema_types.iter().any(|kind| kind == "string") {
        return Ok(EmptyBehavior::NotApplicable);
    }
    let minimums = runtime_schema_values(document, nodes, "minLength")?
        .into_iter()
        .filter_map(|value| value.as_u64())
        .collect::<Vec<_>>();
    Ok(if minimums.is_empty() {
        EmptyBehavior::Allowed
    } else if minimums.iter().all(|minimum| *minimum >= 1) {
        EmptyBehavior::Rejected
    } else {
        EmptyBehavior::Conditional
    })
}

fn runtime_schema_constraints(
    document: &Value,
    nodes: &[Value],
) -> Result<Vec<SchemaConstraint>, DocumentationError> {
    let mut constraints = BTreeMap::new();
    for keyword in CONSTRAINT_KEYWORDS {
        let values = runtime_schema_values(document, nodes, keyword)?;
        if values.len() == 1 {
            constraints.insert(
                keyword.to_owned(),
                values
                    .into_iter()
                    .next()
                    .expect("one constraint is present"),
            );
        } else if !values.is_empty() {
            constraints.insert(
                keyword.to_owned(),
                Value::Array(values.into_iter().collect()),
            );
        }
    }
    Ok(constraints
        .into_iter()
        .map(|(keyword, value)| SchemaConstraint { keyword, value })
        .collect())
}

/// Returns the embedded coverage audit. This function parses committed release assets only.
pub fn embedded_configuration_reference_coverage(
) -> Result<ConfigurationReferenceCoverageV1, DocumentationError> {
    let authored_coverage = with_embedded_inputs(configuration_reference_coverage)?;
    let (fields, missing) = embedded_seven_domain_fields()?;
    let coverage = combined_coverage_summary(&fields, &missing);
    let authored_path_count = [
        ConfigurationSchemaKind::Project,
        ConfigurationSchemaKind::Environment,
        ConfigurationSchemaKind::Integration,
        ConfigurationSchemaKind::Fixture,
        ConfigurationSchemaKind::Entity,
    ]
    .into_iter()
    .map(|schema| coverage.by_schema.get(&schema).copied().unwrap_or_default())
    .sum::<usize>();
    if authored_coverage.status != CoverageStatus::Complete
        || authored_coverage.coverage.path_count != authored_path_count
    {
        return Err(documentation_error(
            "combined reference does not preserve the complete authored coverage audit",
        ));
    }
    let reviewed_intent_assignment_required_count = coverage.path_count;
    let purpose_counts = fields.iter().fold(BTreeMap::new(), |mut counts, field| {
        *counts.entry(field.purpose.clone()).or_default() += 1;
        counts
    });
    let intent_counts = reviewed_intent_counts(&purpose_counts);
    Ok(ConfigurationReferenceCoverageV1 {
        schema_id: CONFIGURATION_REFERENCE_COVERAGE_SCHEMA_ID,
        format_version: CONFIGURATION_REFERENCE_FORMAT_VERSION,
        status: if missing.is_empty() {
            CoverageStatus::Complete
        } else {
            CoverageStatus::Incomplete
        },
        reference_baseline: reference_baseline(),
        source_contract: combined_source_contract(),
        coverage,
        reviewed_intent_assignment_required_count,
        reviewed_intent_assignment_covered_count: fields.len(),
        distinct_reviewed_intent_count: intent_counts.distinct,
        distinct_reviewed_intents_reused_count: intent_counts.distinct_reused,
        reviewed_intent_assignments_using_reused_intent_count: intent_counts
            .assignments_using_reused,
        missing_intent: missing,
    })
}

/// Returns the embedded canonical reference, failing until human-intent coverage is complete.
pub fn embedded_configuration_reference() -> Result<ConfigurationReferenceV1, DocumentationError> {
    let (fields, missing) = embedded_seven_domain_fields()?;
    if !missing.is_empty() {
        return Err(documentation_error(format!(
            "configuration reference has {} runtime paths without reviewed product intent",
            missing.len()
        )));
    }
    Ok(ConfigurationReferenceV1 {
        schema_id: CONFIGURATION_REFERENCE_SCHEMA_ID,
        format_version: CONFIGURATION_REFERENCE_FORMAT_VERSION,
        reference_baseline: reference_baseline(),
        source_contract: combined_source_contract(),
        coverage: combined_coverage_summary(&fields, &[]),
        fields,
    })
}

fn embedded_seven_domain_fields() -> Result<
    (
        Vec<ConfigurationFieldReference>,
        Vec<DocumentationFieldAddress>,
    ),
    DocumentationError,
> {
    let authored = with_embedded_inputs(generate_configuration_reference)?;
    let relay_document = registry_relay::config::schema::document();
    let notary_document = registry_notary_core::config::schema::document();
    let relay_intent: RuntimeIntentCatalog = serde_json::from_str(RELAY_RUNTIME_INTENT_ASSET)
        .map_err(|error| documentation_error(format!("embedded Relay runtime intent: {error}")))?;
    let notary_intent: RuntimeIntentCatalog = serde_json::from_str(NOTARY_RUNTIME_INTENT_ASSET)
        .map_err(|error| documentation_error(format!("embedded Notary runtime intent: {error}")))?;
    validate_embedded_runtime_identity(
        &relay_intent,
        ConfigurationSchemaKind::Relay,
        "registry-relay.config.schema.json",
    )?;
    validate_embedded_runtime_identity(
        &notary_intent,
        ConfigurationSchemaKind::Notary,
        "registry-notary.config.schema.json",
    )?;
    let relay_required =
        runtime_schema_paths(ConfigurationSchemaKind::Relay, &relay_document)?.len();
    let notary_required =
        runtime_schema_paths(ConfigurationSchemaKind::Notary, &notary_document)?.len();
    let mut missing = runtime_configuration_intent_gaps(&relay_document, &relay_intent)?;
    let notary_missing = runtime_configuration_intent_gaps(&notary_document, &notary_intent)?;
    let relay_fields = if missing.is_empty() {
        generate_runtime_configuration_fields(&relay_document, &relay_intent)?
    } else {
        runtime_configuration_fields(&relay_document, &relay_intent)?.0
    };
    let notary_fields = if notary_missing.is_empty() {
        generate_runtime_configuration_fields(&notary_document, &notary_intent)?
    } else {
        runtime_configuration_fields(&notary_document, &notary_intent)?.0
    };
    if relay_fields.len() + missing.len() != relay_required {
        return Err(documentation_error(
            "Relay runtime reference coverage does not match its authoritative schema paths",
        ));
    }
    if notary_fields.len() + notary_missing.len() != notary_required {
        return Err(documentation_error(
            "Notary runtime reference coverage does not match its authoritative schema paths",
        ));
    }
    missing.extend(notary_missing);
    missing.sort();
    let mut fields = authored.fields;
    fields.extend(relay_fields);
    fields.extend(notary_fields);
    fields.sort_by(|left, right| left.address.cmp(&right.address));
    if fields
        .windows(2)
        .any(|pair| pair[0].address == pair[1].address)
    {
        return Err(documentation_error(
            "combined configuration reference contains a duplicate field address",
        ));
    }
    Ok((fields, missing))
}

fn validate_embedded_runtime_identity(
    intent: &RuntimeIntentCatalog,
    schema: ConfigurationSchemaKind,
    schema_source: &str,
) -> Result<(), DocumentationError> {
    if intent.runtime_schema != schema || intent.schema_source != schema_source {
        return Err(documentation_error(format!(
            "{schema} runtime intent does not identify its exact product schema source"
        )));
    }
    Ok(())
}

fn combined_source_contract() -> ReferenceSourceContract {
    ReferenceSourceContract {
        schemas: vec![
            ConfigurationSchemaKind::Project,
            ConfigurationSchemaKind::Environment,
            ConfigurationSchemaKind::Integration,
            ConfigurationSchemaKind::Fixture,
            ConfigurationSchemaKind::Entity,
            ConfigurationSchemaKind::Relay,
            ConfigurationSchemaKind::Notary,
        ],
        schema_sources: vec![
            "project.schema.json".to_owned(),
            "environment.schema.json".to_owned(),
            "integration.schema.json".to_owned(),
            "fixture.schema.json".to_owned(),
            "entity.schema.json".to_owned(),
            "registry-relay.config.schema.json".to_owned(),
            "registry-notary.config.schema.json".to_owned(),
        ],
        field_knowledge: "schemas/project-authoring/parity-coverage.json#field_knowledge",
        human_intent: "schemas/project-authoring/documentation-intent.json",
        runtime_intent: vec![RELAY_RUNTIME_INTENT_SOURCE, NOTARY_RUNTIME_INTENT_SOURCE],
        reads_country_workspaces: false,
        reads_runtime_configuration: false,
    }
}

fn combined_coverage_summary(
    fields: &[ConfigurationFieldReference],
    missing: &[DocumentationFieldAddress],
) -> ReferenceCoverageSummary {
    let mut by_schema = BTreeMap::new();
    let mut by_path_kind = BTreeMap::new();
    let mut by_sensitivity = BTreeMap::new();
    let mut by_intent_source = BTreeMap::new();
    let mut by_intent_profile = BTreeMap::new();
    let mut reference_count = 0;
    for field in fields {
        *by_schema.entry(field.address.schema).or_default() += 1;
        *by_path_kind.entry(field.address.path_kind).or_default() += 1;
        *by_sensitivity.entry(field.sensitivity).or_default() += 1;
        *by_intent_source.entry(field.purpose_source).or_default() += 1;
        if let Some(profile) = &field.intent_profile {
            *by_intent_profile.entry(profile.clone()).or_default() += 1;
        }
        if field.local_reference.is_some() {
            reference_count += 1;
        }
    }
    for address in missing {
        *by_schema.entry(address.schema).or_default() += 1;
        *by_path_kind.entry(address.path_kind).or_default() += 1;
    }
    ReferenceCoverageSummary {
        schema_count: by_schema.len(),
        path_count: fields.len() + missing.len(),
        reference_count,
        by_schema,
        by_path_kind,
        by_sensitivity,
        by_intent_source,
        by_intent_profile,
    }
}

struct EmbeddedInputs {
    catalog: FieldKnowledgeCatalog,
    documents: Vec<(SchemaKind, Value, &'static str)>,
    intent: DocumentationIntentCatalog,
}

fn embedded_inputs() -> Result<EmbeddedInputs, DocumentationError> {
    #[derive(Deserialize)]
    struct CoverageAsset {
        field_knowledge: FieldKnowledgeCatalog,
    }

    let coverage: CoverageAsset = serde_json::from_str(KNOWLEDGE_ASSET)
        .map_err(|error| documentation_error(format!("embedded field knowledge: {error}")))?;
    let intent: DocumentationIntentCatalog = serde_json::from_str(INTENT_ASSET)
        .map_err(|error| documentation_error(format!("embedded documentation intent: {error}")))?;
    let documents = [
        (SchemaKind::Project, PROJECT_SCHEMA, "project.schema.json"),
        (
            SchemaKind::Environment,
            ENVIRONMENT_SCHEMA,
            "environment.schema.json",
        ),
        (
            SchemaKind::Integration,
            INTEGRATION_SCHEMA,
            "integration.schema.json",
        ),
        (SchemaKind::Fixture, FIXTURE_SCHEMA, "fixture.schema.json"),
        (SchemaKind::Entity, ENTITY_SCHEMA, "entity.schema.json"),
    ]
    .into_iter()
    .map(|(kind, text, source)| {
        serde_json::from_str(text)
            .map(|document| (kind, document, source))
            .map_err(|error| {
                documentation_error(format!("embedded {kind} authoring schema: {error}"))
            })
    })
    .collect::<Result<Vec<_>, _>>()?;

    Ok(EmbeddedInputs {
        catalog: coverage.field_knowledge,
        documents,
        intent,
    })
}

fn with_embedded_inputs<T>(
    operation: impl FnOnce(
        &FieldKnowledgeCatalog,
        &[DocumentationSchema<'_>],
        &DocumentationIntentCatalog,
    ) -> Result<T, DocumentationError>,
) -> Result<T, DocumentationError> {
    let embedded = embedded_inputs()?;
    let schemas = embedded
        .documents
        .iter()
        .map(|(kind, document, source_name)| DocumentationSchema {
            published: PublishedSchema {
                kind: *kind,
                document,
            },
            source_name,
        })
        .collect::<Vec<_>>();
    operation(&embedded.catalog, &schemas, &embedded.intent)
}

fn prepare<'a>(
    catalog: &FieldKnowledgeCatalog,
    schemas: &'a [DocumentationSchema<'a>],
    intent: &'a DocumentationIntentCatalog,
) -> Result<PreparedDocumentation<'a>, DocumentationError> {
    validate_intent_policy(intent)?;
    let published = schemas
        .iter()
        .map(|schema| PublishedSchema {
            kind: schema.published.kind,
            document: schema.published.document,
        })
        .collect::<Vec<_>>();
    let index = index_published_field_knowledge(catalog, &published)
        .map_err(|error| documentation_error(format!("field knowledge: {error}")))?;
    let reachable = published
        .iter()
        .map(reachable_published_field_paths)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| documentation_error(format!("reachable schema fields: {error}")))?
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>();
    if reachable != index.by_path().keys().cloned().collect::<BTreeSet<_>>() {
        return Err(documentation_error(
            "documentation fields and reachable authored schema paths differ",
        ));
    }
    let domains = unique_domains(intent, schemas)?;
    let overrides = unique_overrides(intent, &index)?;
    let structural_reviews = unique_structural_reviews(intent, &index)?;
    let mut missing = Vec::new();
    let mut purpose_sources = BTreeMap::new();
    let mut purpose_counts = BTreeMap::new();
    for (path, knowledge) in index.by_path() {
        if !intent
            .policy
            .prose_required_for
            .contains(&knowledge.path_kind)
        {
            continue;
        }
        let schema = schemas
            .iter()
            .find(|schema| schema.published.kind == path.schema)
            .ok_or_else(|| documentation_error(format!("missing schema for {path}")))?;
        let node = schema
            .published
            .document
            .pointer(&path.pointer)
            .ok_or_else(|| {
                documentation_error(format!("published documentation path disappeared: {path}"))
            })?;
        let contract_node = resolve_local_reference(schema.published.document, node)?;
        match reviewed_purpose(
            node,
            contract_node,
            knowledge.path_kind,
            overrides.get(path).copied(),
            intent,
            path,
            &structural_reviews,
        ) {
            Ok((purpose, source)) => {
                *purpose_sources.entry(source).or_default() += 1;
                *purpose_counts.entry(purpose).or_default() += 1;
            }
            Err(_) => missing.push(field_address(path, knowledge.path_kind)),
        }
    }
    missing.sort();

    Ok(PreparedDocumentation {
        schemas,
        index,
        domains,
        overrides,
        structural_reviews,
        purpose_sources,
        purpose_counts,
        missing,
    })
}

fn validate_intent_policy(intent: &DocumentationIntentCatalog) -> Result<(), DocumentationError> {
    if intent.schema.as_deref()
        != Some(
            "https://id.registrystack.org/schemas/registryctl/project-authoring/documentation-intent.v1.schema.json",
        )
    {
        return Err(documentation_error(
            "documentation intent must identify its strict v1 schema",
        ));
    }
    if intent.format_version != CONFIGURATION_REFERENCE_FORMAT_VERSION {
        return Err(documentation_error(format!(
            "unsupported documentation-intent format version {:?}",
            intent.format_version
        )));
    }
    let human_sources = intent
        .policy
        .human_sources
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let required_sources = [
        HumanIntentSource::SchemaDescription,
        HumanIntentSource::ReviewedOverride,
        HumanIntentSource::StructuralTaxonomy,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if human_sources != required_sources {
        return Err(documentation_error(
            "documentation intent must declare the exact reviewed human sources",
        ));
    }
    let prohibited = intent
        .policy
        .prohibited_sources
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let required_prohibited = [
        ProhibitedIntentSource::CountryWorkspace,
        ProhibitedIntentSource::CountryValue,
        ProhibitedIntentSource::RuntimeConfiguration,
        ProhibitedIntentSource::DerivedFieldLabel,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if prohibited != required_prohibited {
        return Err(documentation_error(
            "documentation intent must prohibit country, runtime, and derived-label sources",
        ));
    }
    let prose_kinds = intent
        .policy
        .prose_required_for
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if prose_kinds
        != [
            FieldPathKind::Root,
            FieldPathKind::Property,
            FieldPathKind::MapKey,
            FieldPathKind::MapValue,
            FieldPathKind::ArrayItem,
            FieldPathKind::Branch,
        ]
        .into_iter()
        .collect()
    {
        return Err(documentation_error(
            "documentation prose coverage must include every published path kind",
        ));
    }
    let structural = intent
        .structural_intents
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    let required_structural = [
        FieldPathKind::MapKey,
        FieldPathKind::MapValue,
        FieldPathKind::ArrayItem,
        FieldPathKind::Branch,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if structural != required_structural {
        return Err(documentation_error(
            "structural intent taxonomy must cover map keys, map values, array items, and branches exactly",
        ));
    }
    for (kind, entry) in &intent.structural_intents {
        validate_prose(
            &entry.purpose,
            &format!("structural intent {kind:?} purpose"),
        )?;
    }
    Ok(())
}

fn unique_domains<'a>(
    intent: &'a DocumentationIntentCatalog,
    schemas: &[DocumentationSchema<'_>],
) -> Result<BTreeMap<SchemaKind, &'a DocumentationDomainIntent>, DocumentationError> {
    let mut domains = BTreeMap::new();
    for domain in &intent.domains {
        validate_prose(&domain.scope, &format!("{} scope", domain.schema))?;
        validate_prose(
            &domain.migration_note,
            &format!("{} migration note", domain.schema),
        )?;
        validate_prose(
            &domain.example_guidance,
            &format!("{} example guidance", domain.schema),
        )?;
        if !domain.diagnostic.starts_with("registryctl.authoring.") {
            return Err(documentation_error(format!(
                "{} diagnostic must be in registryctl.authoring.*",
                domain.schema
            )));
        }
        if domain.validation_stages.is_empty() {
            return Err(documentation_error(format!(
                "{} validation stages cannot be empty",
                domain.schema
            )));
        }
        if domains.insert(domain.schema, domain).is_some() {
            return Err(documentation_error(format!(
                "duplicate documentation domain for {}",
                domain.schema
            )));
        }
    }
    let schema_kinds = schemas
        .iter()
        .map(|schema| schema.published.kind)
        .collect::<BTreeSet<_>>();
    if domains.keys().copied().collect::<BTreeSet<_>>() != schema_kinds {
        return Err(documentation_error(
            "documentation domains must exactly match the supplied authored schemas",
        ));
    }
    Ok(domains)
}

fn unique_overrides<'a>(
    intent: &'a DocumentationIntentCatalog,
    index: &super::knowledge::FieldKnowledgeIndex,
) -> Result<BTreeMap<FieldPath, &'a FieldIntentOverride>, DocumentationError> {
    let mut overrides = BTreeMap::new();
    for entry in &intent.overrides {
        validate_prose(
            &entry.purpose,
            &format!("{}#{} purpose", entry.schema, entry.pointer),
        )?;
        for (name, prose) in [
            ("migration_note", entry.migration_note.as_ref()),
            ("example_guidance", entry.example_guidance.as_ref()),
        ] {
            if let Some(prose) = prose {
                validate_prose(prose, &format!("{}#{} {name}", entry.schema, entry.pointer))?;
            }
        }
        if entry
            .diagnostic
            .as_ref()
            .is_some_and(|code| !code.starts_with("registryctl.authoring."))
        {
            return Err(documentation_error(format!(
                "{}#{} override diagnostic must be in registryctl.authoring.*",
                entry.schema, entry.pointer
            )));
        }
        let path = FieldPath {
            schema: entry.schema,
            pointer: entry.pointer.clone(),
        };
        if !index.by_path().contains_key(&path) {
            return Err(documentation_error(format!(
                "documentation intent override targets unknown path {path}"
            )));
        }
        if overrides.insert(path.clone(), entry).is_some() {
            return Err(documentation_error(format!(
                "duplicate documentation intent override for {path}"
            )));
        }
    }
    Ok(overrides)
}

fn unique_structural_reviews(
    intent: &DocumentationIntentCatalog,
    index: &super::knowledge::FieldKnowledgeIndex,
) -> Result<BTreeSet<(FieldPath, FieldPathKind)>, DocumentationError> {
    let mut reviews = BTreeSet::new();
    for entry in &intent.structural_reviews {
        if !matches!(
            entry.path_kind,
            FieldPathKind::MapKey
                | FieldPathKind::MapValue
                | FieldPathKind::ArrayItem
                | FieldPathKind::Branch
        ) {
            return Err(documentation_error(format!(
                "{}#{} structural review must use a structural path kind",
                entry.schema, entry.pointer
            )));
        }
        let path = FieldPath {
            schema: entry.schema,
            pointer: entry.pointer.clone(),
        };
        let knowledge = index.by_path().get(&path).ok_or_else(|| {
            documentation_error(format!("structural review targets unknown path {path}"))
        })?;
        if knowledge.path_kind != entry.path_kind {
            return Err(documentation_error(format!(
                "structural review for {path} declares {:?} but schema path is {:?}",
                entry.path_kind, knowledge.path_kind
            )));
        }
        if !reviews.insert((path.clone(), entry.path_kind)) {
            return Err(documentation_error(format!(
                "duplicate structural review for {path}"
            )));
        }
    }
    Ok(reviews)
}

fn validate_prose(prose: &str, context: &str) -> Result<(), DocumentationError> {
    let trimmed = prose.trim();
    if trimmed.len() < 24 || trimmed != prose || prose.contains("TODO") || prose.contains("TBD") {
        return Err(documentation_error(format!(
            "{context} must be reviewed, non-placeholder prose of at least 24 characters"
        )));
    }
    Ok(())
}

fn reviewed_purpose(
    node: &Value,
    contract_node: &Value,
    kind: FieldPathKind,
    override_intent: Option<&FieldIntentOverride>,
    intent: &DocumentationIntentCatalog,
    path: &FieldPath,
    structural_reviews: &BTreeSet<(FieldPath, FieldPathKind)>,
) -> Result<(String, HumanIntentSource), DocumentationError> {
    let structural_kind = matches!(
        kind,
        FieldPathKind::MapKey
            | FieldPathKind::MapValue
            | FieldPathKind::ArrayItem
            | FieldPathKind::Branch
    );
    if structural_kind && !structural_reviews.contains(&(path.clone(), kind)) {
        return Err(documentation_error(
            "structural path has no exact reviewed schema, pointer, and path-kind entry",
        ));
    }
    if let Some(entry) = override_intent {
        return Ok((entry.purpose.clone(), HumanIntentSource::ReviewedOverride));
    }
    if let Some(description) = node.get("description").and_then(Value::as_str) {
        validate_prose(description, "schema description")?;
        return Ok((description.to_owned(), HumanIntentSource::SchemaDescription));
    }
    if !std::ptr::eq(node, contract_node) {
        if let Some(description) = contract_node.get("description").and_then(Value::as_str) {
            validate_prose(description, "referenced schema description")?;
            return Ok((description.to_owned(), HumanIntentSource::SchemaDescription));
        }
    }
    if structural_reviews.contains(&(path.clone(), kind)) {
        let structural = intent.structural_intents.get(&kind).ok_or_else(|| {
            documentation_error(format!(
                "reviewed structural path {path} has no structural taxonomy entry"
            ))
        })?;
        return Ok((
            structural.purpose.clone(),
            HumanIntentSource::StructuralTaxonomy,
        ));
    }
    Err(documentation_error("field has no reviewed human intent"))
}

fn reference_baseline() -> ReferenceBaseline {
    ReferenceBaseline {
        generator_lifecycle: GeneratorLifecycle::Unreleased,
        published_release: None,
        field_history_status: FieldHistoryStatus::NotVerified,
        history_verification_method: None,
        compared_releases: Vec::new(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedIntentCounts {
    distinct: usize,
    distinct_reused: usize,
    assignments_using_reused: usize,
}

fn reviewed_intent_counts(purpose_counts: &BTreeMap<String, usize>) -> ReviewedIntentCounts {
    ReviewedIntentCounts {
        distinct: purpose_counts.len(),
        distinct_reused: purpose_counts.values().filter(|count| **count > 1).count(),
        assignments_using_reused: purpose_counts.values().filter(|count| **count > 1).sum(),
    }
}

fn source_contract(schemas: &[DocumentationSchema<'_>]) -> ReferenceSourceContract {
    ReferenceSourceContract {
        schemas: schemas
            .iter()
            .map(|schema| schema.published.kind.into())
            .collect(),
        schema_sources: schemas
            .iter()
            .map(|schema| schema.source_name.to_owned())
            .collect(),
        field_knowledge: "schemas/project-authoring/parity-coverage.json#field_knowledge",
        human_intent: "schemas/project-authoring/documentation-intent.json",
        runtime_intent: Vec::new(),
        reads_country_workspaces: false,
        reads_runtime_configuration: false,
    }
}

fn coverage_summary(prepared: &PreparedDocumentation<'_>) -> ReferenceCoverageSummary {
    ReferenceCoverageSummary {
        schema_count: prepared.schemas.len(),
        path_count: prepared.index.by_path().len(),
        reference_count: prepared.index.references().len(),
        by_schema: prepared
            .index
            .coverage_by_schema()
            .into_iter()
            .map(|(kind, count)| (kind.into(), count))
            .collect(),
        by_path_kind: prepared.index.coverage_by_path_kind(),
        by_sensitivity: prepared.index.coverage_by_sensitivity(),
        by_intent_source: prepared.purpose_sources.clone(),
        by_intent_profile: BTreeMap::new(),
    }
}

fn field_address(path: &FieldPath, path_kind: FieldPathKind) -> DocumentationFieldAddress {
    DocumentationFieldAddress {
        schema: path.schema.into(),
        pointer: path.pointer.clone(),
        key_path: None,
        path_kind,
    }
}

fn field_type(node: &Value, contract_node: &Value) -> FieldTypeDocumentation {
    let mut schema_types = BTreeSet::new();
    collect_schema_types(contract_node, &mut schema_types);
    FieldTypeDocumentation {
        schema_types: schema_types.into_iter().collect(),
        local_reference: node.get("$ref").and_then(Value::as_str).map(str::to_owned),
        composed: ["allOf", "anyOf", "oneOf"]
            .iter()
            .any(|keyword| node.get(keyword).is_some()),
    }
}

fn collect_schema_types(node: &Value, types: &mut BTreeSet<String>) {
    match node.get("type") {
        Some(Value::String(kind)) => {
            types.insert(kind.clone());
        }
        Some(Value::Array(kinds)) => {
            types.extend(kinds.iter().filter_map(Value::as_str).map(str::to_owned));
        }
        _ => {}
    }
    if node.get("const").is_some_and(Value::is_null) {
        types.insert("null".to_owned());
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = node.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                collect_schema_types(branch, types);
            }
        }
    }
}

fn requiredness(
    document: &Value,
    path: &FieldPath,
    node: &Value,
    kind: FieldPathKind,
) -> Requiredness {
    if kind != FieldPathKind::Property {
        return if kind == FieldPathKind::Branch {
            Requiredness::Conditional
        } else {
            Requiredness::NotApplicable
        };
    }
    let Some((parent_pointer, name)) = property_parent(&path.pointer) else {
        return Requiredness::NotApplicable;
    };
    let Some(parent) = document.pointer(&parent_pointer) else {
        return Requiredness::Optional;
    };
    if parent
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| required.iter().any(|entry| entry.as_str() == Some(&name)))
    {
        Requiredness::Required
    } else if node.get("readOnly") == Some(&Value::Bool(true)) {
        Requiredness::NotApplicable
    } else {
        Requiredness::Optional
    }
}

fn property_parent(pointer: &str) -> Option<(String, String)> {
    let (parent, name) = pointer.rsplit_once("/properties/")?;
    if name.contains('/') {
        return None;
    }
    Some((parent.to_owned(), unescape_pointer_segment(name)))
}

fn null_behavior(node: &Value, kind: FieldPathKind) -> NullBehavior {
    if matches!(kind, FieldPathKind::Root | FieldPathKind::Branch) {
        return NullBehavior::NotApplicable;
    }
    let mut types = BTreeSet::new();
    collect_schema_types(node, &mut types);
    if types.contains("null") {
        if types.len() == 1 {
            NullBehavior::Allowed
        } else {
            NullBehavior::Conditional
        }
    } else {
        NullBehavior::Rejected
    }
}

fn empty_behavior(node: &Value, kind: FieldPathKind) -> EmptyBehavior {
    if matches!(kind, FieldPathKind::Root | FieldPathKind::Branch) {
        return EmptyBehavior::NotApplicable;
    }
    let mut types = BTreeSet::new();
    collect_schema_types(node, &mut types);
    if !types.contains("string") {
        return EmptyBehavior::NotApplicable;
    }
    let minimums = collect_numeric_keyword(node, "minLength");
    if minimums.is_empty() {
        EmptyBehavior::Allowed
    } else if minimums.iter().all(|minimum| *minimum >= 1) {
        EmptyBehavior::Rejected
    } else {
        EmptyBehavior::Conditional
    }
}

fn collect_numeric_keyword(node: &Value, keyword: &str) -> Vec<i64> {
    let mut values = node
        .get(keyword)
        .and_then(Value::as_i64)
        .into_iter()
        .collect::<Vec<_>>();
    for composer in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = node.get(composer).and_then(Value::as_array) {
            for branch in branches {
                values.extend(collect_numeric_keyword(branch, keyword));
            }
        }
    }
    values
}

fn default_documentation(node: &Value, kind: FieldPathKind) -> DefaultDocumentation {
    if matches!(kind, FieldPathKind::Root | FieldPathKind::Branch) {
        return DefaultDocumentation {
            behavior: DefaultBehavior::NotApplicable,
            schema_value: None,
            source_version: None,
            reviewed_behavior: None,
        };
    }
    if let Some(value) = node.get("default") {
        DefaultDocumentation {
            behavior: DefaultBehavior::SchemaDefault,
            schema_value: Some(value.clone()),
            source_version: None,
            reviewed_behavior: None,
        }
    } else {
        DefaultDocumentation {
            behavior: DefaultBehavior::NoSchemaDefault,
            schema_value: None,
            source_version: None,
            reviewed_behavior: None,
        }
    }
}

fn schema_constraints(node: &Value, contract_node: &Value) -> Vec<SchemaConstraint> {
    let mut constraints = BTreeMap::new();
    for source in [contract_node, node] {
        for keyword in CONSTRAINT_KEYWORDS {
            if let Some(value) = source.get(keyword) {
                constraints.insert(keyword.to_owned(), value.clone());
            }
        }
    }
    constraints
        .into_iter()
        .map(|(keyword, value)| SchemaConstraint { keyword, value })
        .collect()
}

fn resolve_local_reference<'a>(
    document: &'a Value,
    node: &'a Value,
) -> Result<&'a Value, DocumentationError> {
    let mut current = node;
    let mut visited = BTreeSet::new();
    loop {
        let Some(reference) = current.get("$ref").and_then(Value::as_str) else {
            return Ok(current);
        };
        let pointer = reference.strip_prefix('#').ok_or_else(|| {
            documentation_error(format!(
                "documentation schema uses external reference {reference:?}"
            ))
        })?;
        if !visited.insert(pointer.to_owned()) {
            return Err(documentation_error(format!(
                "documentation schema has cyclic reference {reference:?}"
            )));
        }
        current = document.pointer(pointer).ok_or_else(|| {
            documentation_error(format!(
                "documentation schema has unresolved reference {reference:?}"
            ))
        })?;
    }
}

fn unescape_pointer_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_entry_points_have_no_workspace_or_runtime_input() {
        let coverage = with_embedded_inputs(configuration_reference_coverage)
            .expect("embedded reference coverage is readable");
        assert!(!coverage.source_contract.reads_country_workspaces);
        assert!(!coverage.source_contract.reads_runtime_configuration);
        assert_eq!(coverage.coverage.path_count, 623);
    }

    #[test]
    fn removed_project_paths_cannot_remain_as_reviewed_intent() {
        const REMOVED_PATHS: [&str; 3] = [
            "/$defs/recordAttributeReleaseProfile/properties/subject/properties/input",
            "/$defs/recordAttributeReleaseProfile/properties/response",
            "/$defs/recordAttributeReleaseProfile/properties/response/properties/max_age_seconds",
        ];

        let embedded = embedded_inputs().expect("embedded documentation inputs parse");
        let schemas = embedded
            .documents
            .iter()
            .map(|(kind, document, source_name)| DocumentationSchema {
                published: PublishedSchema {
                    kind: *kind,
                    document,
                },
                source_name,
            })
            .collect::<Vec<_>>();

        for pointer in REMOVED_PATHS {
            let mut intent: DocumentationIntentCatalog =
                serde_json::from_str(INTENT_ASSET).expect("embedded intent parses");
            assert!(
                intent
                    .overrides
                    .iter()
                    .all(|entry| entry.pointer != pointer),
                "removed path {pointer} must not remain in committed intent"
            );
            intent.overrides.push(FieldIntentOverride {
                schema: SchemaKind::Project,
                pointer: pointer.to_owned(),
                purpose:
                    "This deliberately stale reviewed purpose must fail the exact coverage gate."
                        .to_owned(),
                environment_behavior: None,
                diagnostic: None,
                migration_note: None,
                example_guidance: None,
            });
            let error = configuration_reference_coverage(&embedded.catalog, &schemas, &intent)
                .expect_err("removed path intent must fail closed");
            assert!(
                error.to_string().contains("targets unknown path"),
                "removed path {pointer} produced unexpected error: {error}"
            );
        }
    }
}
