// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use jsonschema::{Draft, JSONSchema};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde::{
    de::DeserializeOwned, de::Error as _, de::IntoDeserializer, Deserialize, Deserializer,
    Serialize,
};
use serde_json::Value;

use crate::diagnostics::{CompileFailure, Diagnostic};

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryProject {
    pub api_version: String,
    pub kind: String,
    pub registry: RegistryIdentitySource,
    #[serde(default)]
    pub package: Option<PackageIdentitySource>,
    #[serde(default)]
    pub manifest_projection: Option<ManifestProjectionSource>,
    #[serde(default)]
    pub modules: Vec<ModuleLockSource>,
    #[serde(default)]
    pub entities: Vec<EntitySource>,
    #[serde(default)]
    pub access_profiles: Vec<ProjectAccessProfileSource>,
    #[serde(default)]
    pub vocabularies: Vec<VocabularySource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryIdentitySource {
    pub id: String,
    pub version: String,
    pub default_language: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageIdentitySource {
    pub environment: String,
    pub instance_id: String,
    pub sequence: u64,
    pub source_revision: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionSource {
    pub access_profile: String,
    pub classification_ceiling: Classification,
    pub catalog: ManifestProjectionCatalogSource,
    pub dataset: ManifestProjectionDatasetSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_service: Option<ManifestProjectionDataServiceSource>,
    #[serde(default)]
    pub entities: Vec<ManifestProjectionEntitySource>,
    #[serde(default)]
    pub vocabularies: Vec<ManifestProjectionVocabularySource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ManifestProjectionTextSource {
    Plain(String),
    Localized(BTreeMap<String, String>),
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionCatalogSource {
    pub base_url: String,
    pub title: ManifestProjectionTextSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<ManifestProjectionTextSource>,
    pub publisher: ManifestProjectionPublisherSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participant_id: Option<String>,
    #[serde(default)]
    pub conforms_to: Vec<String>,
    #[serde(default)]
    pub standards: ManifestProjectionStandardsSource,
    #[serde(default)]
    pub application_profiles: Vec<ManifestProjectionApplicationProfileSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionStandardsSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dcat: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shacl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionApplicationProfileSource {
    pub id: String,
    pub version: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionPublisherSource {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_type: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionDatasetSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub title: ManifestProjectionTextSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<ManifestProjectionTextSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ManifestProjectionDatasetStatus>,
    #[serde(default)]
    pub conforms_to: Vec<String>,
    #[serde(default)]
    pub applicable_legislation: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spatial_coverage: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionDataServiceSource {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iri: Option<String>,
    pub title: ManifestProjectionTextSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<ManifestProjectionTextSource>,
    pub endpoint_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conforms_to: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionEntitySource {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<ManifestProjectionTextSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<ManifestProjectionTextSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concept_uri: Option<String>,
    #[serde(default)]
    pub identifiers: Vec<ManifestProjectionIdentifierSource>,
    #[serde(default)]
    pub fields: Vec<ManifestProjectionFieldSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionIdentifierSource {
    pub field: String,
    pub kind: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionFieldSource {
    pub id: String,
    #[serde(default)]
    pub concepts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_concept_uri: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionVocabularySource {
    pub id: String,
    pub scheme_iri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    #[serde(default)]
    pub concepts: Vec<ManifestProjectionVocabularyConceptSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionVocabularyConceptSource {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<ManifestProjectionTextSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestProjectionDatasetStatus {
    UnderDevelopment,
    Active,
    Completed,
    Deprecated,
    Withdrawn,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModuleLockSource {
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub digest: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryModule {
    /// Stable module identifier, referenced by the project's module lock.
    pub id: String,
    /// Module version recorded alongside its content digest in the project.
    pub version: String,
    /// Identifiers of modules that must be applied before this module.
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// Entities introduced by this module.
    #[serde(default)]
    pub entities: Vec<EntitySource>,
    /// Additive contributions to entities already declared by the project or another module.
    #[serde(default)]
    pub extend_entities: Vec<EntityExtensionSource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleAssetSource {
    pub module: Option<String>,
    pub path: String,
    pub bytes: Vec<u8>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EntitySource {
    pub id: String,
    pub route: String,
    pub mutation_mode: MutationMode,
    #[serde(default)]
    pub tombstone: bool,
    #[serde(default)]
    pub batch: Option<BatchSource>,
    #[serde(default = "default_classification")]
    pub classification: Classification,
    #[serde(default)]
    pub fields: Vec<FieldSource>,
    /// Mandatory request-access requirements checked against every profile, including module contributions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_requirements: Option<AccessRequirementsSource>,
    #[serde(default)]
    pub constraints: Vec<ConstraintSource>,
    #[serde(default)]
    pub indexes: Vec<IndexSource>,
    /// Internal/module profile contributions. Public project authoring should use
    /// top-level `accessProfiles`.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub access_profiles: Vec<AccessProfileSource>,
    #[serde(default)]
    pub events: Vec<EventSource>,
    #[serde(default)]
    pub temporal: Option<TemporalSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived: Vec<DerivedSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selector_profiles: Vec<SelectorProfileSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_paths: Vec<ReadPathSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_control: Option<ChangeControlSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_request: Option<ChangeRequestSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BatchSource {
    pub maximum_items: u16,
    pub maximum_bytes: u32,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EntityExtensionSource {
    pub entity: String,
    /// Add mandatory requirements only when the entity has none; replacing them is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_requirements: Option<AccessRequirementsSource>,
    #[serde(default)]
    pub fields: Vec<FieldSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived: Vec<DerivedSource>,
    #[serde(default)]
    pub constraints: Vec<ConstraintSource>,
    #[serde(default)]
    pub indexes: Vec<IndexSource>,
    /// Internal/module profile contributions. Public project authoring should use
    /// top-level `accessProfiles`.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub access_profiles: Vec<AccessProfileSource>,
    #[serde(default)]
    pub events: Vec<EventSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selector_profiles: Vec<SelectorProfileSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_paths: Vec<ReadPathSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_control: Option<ChangeControlSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_request: Option<ChangeRequestSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationMode {
    Mutable,
    CreateOnly,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeControlSource {
    #[serde(default)]
    pub required_for: BTreeSet<Operation>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestSource {
    #[serde(default)]
    pub effects: Vec<ChangeRequestEffectSource>,
    pub review: ChangeRequestReviewSource,
    #[serde(default)]
    pub retention: ChangeRequestRetentionSource,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ChangeRequestRetentionModeSource {
    #[default]
    Retain,
    OperatorErase,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestRetentionSource {
    #[serde(default)]
    pub mode: ChangeRequestRetentionModeSource,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestEffectSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub target: ChangeRequestTargetSource,
    pub operation: Operation,
    #[serde(default)]
    pub set: BTreeMap<String, ChangeRequestValueSource>,
    #[serde(default)]
    pub clear: BTreeSet<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestTargetSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_field: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestValueSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_effect: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestReviewSource {
    #[serde(default)]
    pub stages: Vec<ChangeRequestReviewStageSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestReviewStageSource {
    pub id: String,
    pub approvals: u16,
    #[serde(default)]
    pub exclude_submitter: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Public,
    Internal,
    Restricted,
}

fn default_classification() -> Classification {
    Classification::Internal
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FieldSource {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_name: Option<String>,
    #[serde(flatten)]
    pub field_type: FieldTypeSource,
    #[serde(default)]
    pub required: bool,
    pub classification: Classification,
    #[serde(default)]
    pub valid_time_role: Option<ValidTimeRole>,
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for FieldSource {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("FieldSource")
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(concat!(module_path!(), "::FieldSource"))
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        FieldSourceSchema::json_schema(generator)
    }
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(untagged)]
enum FieldSourceSchema {
    Boolean(BooleanFieldSourceSchema),
    String(StringFieldSourceSchema),
    Text(TextFieldSourceSchema),
    Int64(Int64FieldSourceSchema),
    Decimal(DecimalFieldSourceSchema),
    Date(DateFieldSourceSchema),
    Timestamp(TimestampFieldSourceSchema),
    Uuid(UuidFieldSourceSchema),
    VocabularyCode(VocabularyCodeFieldSourceSchema),
    Reference(ReferenceFieldSourceSchema),
    Crs84Point(Crs84PointFieldSourceSchema),
    Structured(StructuredFieldSourceSchema),
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BooleanFieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: BooleanFieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StringFieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: StringFieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
    #[serde(default)]
    min_length: u32,
    max_length: u32,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TextFieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: TextFieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
    max_length: u32,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Int64FieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: Int64FieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DecimalFieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: DecimalFieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
    precision: u8,
    scale: u8,
    #[serde(default)]
    minimum: Option<String>,
    #[serde(default)]
    maximum: Option<String>,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DateFieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: DateFieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TimestampFieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: TimestampFieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UuidFieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: UuidFieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VocabularyCodeFieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: VocabularyCodeFieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
    vocabulary: String,
    #[serde(default)]
    values: Vec<String>,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReferenceFieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: ReferenceFieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
    target: String,
    #[serde(default)]
    on_delete: ReferenceDelete,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Crs84PointFieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: Crs84PointFieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
    precision: u8,
    #[serde(default)]
    bbox: Option<Crs84BboxSource>,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StructuredFieldSourceSchema {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    field_type: StructuredFieldKindSchema,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
    max_bytes: u32,
    schema: Value,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum BooleanFieldKindSchema {
    Boolean,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum StringFieldKindSchema {
    String,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum TextFieldKindSchema {
    Text,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Int64FieldKindSchema {
    Int64,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum DecimalFieldKindSchema {
    Decimal,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum DateFieldKindSchema {
    Date,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum TimestampFieldKindSchema {
    Timestamp,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum UuidFieldKindSchema {
    Uuid,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
enum VocabularyCodeFieldKindSchema {
    #[serde(rename = "vocabulary-code")]
    VocabularyCode,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum ReferenceFieldKindSchema {
    Reference,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
enum Crs84PointFieldKindSchema {
    #[serde(rename = "crs84-point")]
    Crs84Point,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum StructuredFieldKindSchema {
    Structured,
}

impl<'de> Deserialize<'de> for FieldSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawFieldSource::deserialize(deserializer)?;
        let field_type = parse_field_type::<D::Error>(&raw)?;
        Ok(Self {
            id: raw.id,
            api_name: raw.api_name,
            field_type,
            required: raw.required,
            classification: raw.classification,
            valid_time_role: raw.valid_time_role,
        })
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DerivedFieldSource {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_name: Option<String>,
    #[serde(flatten)]
    pub field_type: FieldTypeSource,
    pub classification: Classification,
}

impl<'de> Deserialize<'de> for DerivedFieldSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawFieldSource::deserialize(deserializer)?;
        if raw.required || raw.valid_time_role.is_some() {
            return Err(D::Error::custom(
                "derived fields cannot declare required or validTimeRole",
            ));
        }
        let field_type = parse_field_type::<D::Error>(&raw)?;
        Ok(Self {
            id: raw.id,
            api_name: raw.api_name,
            field_type,
            classification: raw.classification,
        })
    }
}

fn parse_field_type<E: serde::de::Error>(raw: &RawFieldSource) -> Result<FieldTypeSource, E> {
    let field_type = match raw.kind {
        RawFieldKind::Boolean => {
            reject_type_options::<E>(raw, TypeOptionAllowances::NONE)?;
            FieldTypeSource::Boolean
        }
        RawFieldKind::String => {
            reject_type_options::<E>(raw, TypeOptionAllowances::STRING)?;
            FieldTypeSource::String {
                min_length: raw.min_length.unwrap_or_default(),
                max_length: raw
                    .max_length
                    .ok_or_else(|| E::custom("string maxLength is required"))?,
            }
        }
        RawFieldKind::Text => {
            reject_type_options::<E>(raw, TypeOptionAllowances::TEXT)?;
            FieldTypeSource::Text {
                max_length: raw
                    .max_length
                    .ok_or_else(|| E::custom("text maxLength is required"))?,
            }
        }
        RawFieldKind::Int64 => {
            reject_type_options::<E>(raw, TypeOptionAllowances::NONE)?;
            FieldTypeSource::Int64
        }
        RawFieldKind::Decimal => {
            reject_type_options::<E>(raw, TypeOptionAllowances::DECIMAL)?;
            FieldTypeSource::Decimal {
                precision: raw
                    .precision
                    .ok_or_else(|| E::custom("decimal precision is required"))?,
                scale: raw
                    .scale
                    .ok_or_else(|| E::custom("decimal scale is required"))?,
                minimum: raw.minimum.clone(),
                maximum: raw.maximum.clone(),
            }
        }
        RawFieldKind::Date => {
            reject_type_options::<E>(raw, TypeOptionAllowances::NONE)?;
            FieldTypeSource::Date
        }
        RawFieldKind::Timestamp => {
            reject_type_options::<E>(raw, TypeOptionAllowances::NONE)?;
            FieldTypeSource::Timestamp
        }
        RawFieldKind::Uuid => {
            reject_type_options::<E>(raw, TypeOptionAllowances::NONE)?;
            FieldTypeSource::Uuid
        }
        RawFieldKind::VocabularyCode => {
            reject_type_options::<E>(raw, TypeOptionAllowances::VOCABULARY)?;
            FieldTypeSource::VocabularyCode {
                vocabulary: raw
                    .vocabulary
                    .clone()
                    .ok_or_else(|| E::custom("vocabulary is required"))?,
                values: raw.values.clone(),
            }
        }
        RawFieldKind::Reference => {
            reject_type_options::<E>(raw, TypeOptionAllowances::REFERENCE)?;
            FieldTypeSource::Reference {
                target: raw
                    .target
                    .clone()
                    .ok_or_else(|| E::custom("reference target is required"))?,
                on_delete: raw.on_delete.clone().unwrap_or_default(),
            }
        }
        RawFieldKind::Crs84Point => {
            reject_type_options::<E>(raw, TypeOptionAllowances::CRS84_POINT)?;
            FieldTypeSource::Crs84Point {
                precision: raw
                    .precision
                    .ok_or_else(|| E::custom("point precision is required"))?,
                bbox: raw.bbox.clone(),
            }
        }
        RawFieldKind::Structured => {
            reject_type_options::<E>(raw, TypeOptionAllowances::STRUCTURED)?;
            FieldTypeSource::Structured {
                max_bytes: raw
                    .max_bytes
                    .ok_or_else(|| E::custom("structured maxBytes is required"))?,
                schema: raw
                    .schema
                    .clone()
                    .ok_or_else(|| E::custom("structured schema is required"))?,
            }
        }
    };
    Ok(field_type)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawFieldSource {
    id: String,
    #[serde(default)]
    api_name: Option<String>,
    #[serde(rename = "type")]
    kind: RawFieldKind,
    #[serde(default)]
    required: bool,
    classification: Classification,
    #[serde(default)]
    valid_time_role: Option<ValidTimeRole>,
    #[serde(default)]
    min_length: Option<u32>,
    #[serde(default)]
    max_length: Option<u32>,
    #[serde(default)]
    precision: Option<u8>,
    #[serde(default)]
    scale: Option<u8>,
    #[serde(default)]
    minimum: Option<String>,
    #[serde(default)]
    maximum: Option<String>,
    #[serde(default)]
    bbox: Option<Crs84BboxSource>,
    #[serde(default)]
    max_bytes: Option<u32>,
    #[serde(default)]
    schema: Option<Value>,
    #[serde(default)]
    vocabulary: Option<String>,
    #[serde(default)]
    values: Vec<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    on_delete: Option<ReferenceDelete>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DerivedSource {
    pub id: String,
    pub sql: String,
    pub key: String,
    #[serde(default)]
    pub execution: DerivedExecutionSource,
    #[serde(default)]
    pub fields: Vec<DerivedFieldSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedExecutionSource {
    #[default]
    Live,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectorProfileSource {
    pub id: String,
    pub fields: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReadPathSource {
    pub id: String,
    pub through: String,
    pub to: String,
    pub route: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawFieldKind {
    Boolean,
    String,
    Text,
    Int64,
    Decimal,
    Date,
    Timestamp,
    Uuid,
    #[serde(rename = "vocabulary-code")]
    VocabularyCode,
    Reference,
    #[serde(rename = "crs84-point")]
    Crs84Point,
    Structured,
}

#[derive(Clone, Copy)]
struct TypeOptionAllowances {
    min_length: bool,
    max_length: bool,
    precision: bool,
    scale: bool,
    decimal_bounds: bool,
    structured: bool,
    vocabulary: bool,
    target: bool,
    bbox: bool,
    delete: bool,
}

impl TypeOptionAllowances {
    const NONE: Self = Self {
        min_length: false,
        max_length: false,
        precision: false,
        scale: false,
        decimal_bounds: false,
        structured: false,
        vocabulary: false,
        target: false,
        bbox: false,
        delete: false,
    };
    const STRING: Self = Self {
        min_length: true,
        max_length: true,
        ..Self::NONE
    };
    const TEXT: Self = Self {
        max_length: true,
        ..Self::NONE
    };
    const DECIMAL: Self = Self {
        precision: true,
        scale: true,
        decimal_bounds: true,
        ..Self::NONE
    };
    const VOCABULARY: Self = Self {
        vocabulary: true,
        ..Self::NONE
    };
    const REFERENCE: Self = Self {
        target: true,
        delete: true,
        ..Self::NONE
    };
    const CRS84_POINT: Self = Self {
        precision: true,
        bbox: true,
        ..Self::NONE
    };
    const STRUCTURED: Self = Self {
        structured: true,
        ..Self::NONE
    };
}

fn reject_type_options<E: serde::de::Error>(
    raw: &RawFieldSource,
    allowed: TypeOptionAllowances,
) -> Result<(), E> {
    if (!allowed.min_length && raw.min_length.is_some())
        || (!allowed.max_length && raw.max_length.is_some())
        || (!allowed.precision && raw.precision.is_some())
        || (!allowed.scale && raw.scale.is_some())
        || (!allowed.decimal_bounds && (raw.minimum.is_some() || raw.maximum.is_some()))
        || (!allowed.structured && (raw.max_bytes.is_some() || raw.schema.is_some()))
        || (!allowed.bbox && raw.bbox.is_some())
        || (!allowed.vocabulary && (raw.vocabulary.is_some() || !raw.values.is_empty()))
        || (!allowed.target && raw.target.is_some())
        || (!allowed.delete && raw.on_delete.is_some())
    {
        return Err(E::custom("the field type contains an incompatible option"));
    }
    Ok(())
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum FieldTypeSource {
    Boolean,
    String {
        #[serde(default)]
        min_length: u32,
        max_length: u32,
    },
    Text {
        max_length: u32,
    },
    Int64,
    Decimal {
        precision: u8,
        scale: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        minimum: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        maximum: Option<String>,
    },
    Date,
    Timestamp,
    Uuid,
    #[serde(rename = "vocabulary-code")]
    VocabularyCode {
        vocabulary: String,
        #[serde(default)]
        values: Vec<String>,
    },
    Reference {
        target: String,
        #[serde(default)]
        on_delete: ReferenceDelete,
    },
    #[serde(rename = "crs84-point")]
    Crs84Point {
        precision: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        bbox: Option<Crs84BboxSource>,
    },
    Structured {
        max_bytes: u32,
        schema: Value,
    },
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Crs84BboxSource {
    pub west: String,
    pub south: String,
    pub east: String,
    pub north: String,
}

pub(crate) const MAX_STRUCTURED_SCHEMA_BYTES: usize = 64 * 1024;
pub(crate) const MAX_STRUCTURED_VALUE_BYTES: u32 = 1024 * 1024;

pub(crate) fn decimal_scaled_value(value: &str, precision: u8, scale: u8) -> Option<i128> {
    if !(1..=38).contains(&precision) || scale > precision {
        return None;
    }
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    if unsigned.is_empty() || unsigned.contains('+') {
        return None;
    }
    let max_integer_digits = usize::from(precision - scale);
    let (integer, fraction) = if scale == 0 {
        if unsigned.contains('.') {
            return None;
        }
        (unsigned, "")
    } else {
        let (integer, fraction) = unsigned.split_once('.')?;
        if fraction.len() != usize::from(scale) {
            return None;
        }
        (integer, fraction)
    };
    if integer.is_empty()
        || integer.bytes().any(|byte| !byte.is_ascii_digit())
        || fraction.bytes().any(|byte| !byte.is_ascii_digit())
        || integer.len() > 1 && integer.starts_with('0')
        || integer != "0" && integer.len() > max_integer_digits
        || integer == "0" && scale == 0 && precision == 0
    {
        return None;
    }
    let digits = format!("{integer}{fraction}");
    let scaled = digits.parse::<i128>().ok()?;
    if value.starts_with('-') {
        if scaled == 0 {
            None
        } else {
            Some(-scaled)
        }
    } else {
        Some(scaled)
    }
}

pub(crate) fn valid_decimal_bounds(
    precision: u8,
    scale: u8,
    minimum: Option<&str>,
    maximum: Option<&str>,
) -> bool {
    if !(1..=38).contains(&precision) || scale > precision {
        return false;
    }
    let minimum = match minimum {
        Some(value) => match decimal_scaled_value(value, precision, scale) {
            Some(parsed) => Some(parsed),
            None => return false,
        },
        None => None,
    };
    let maximum = match maximum {
        Some(value) => match decimal_scaled_value(value, precision, scale) {
            Some(parsed) => Some(parsed),
            None => return false,
        },
        None => None,
    };
    minimum
        .zip(maximum)
        .is_none_or(|(minimum, maximum)| minimum <= maximum)
}

#[cfg_attr(not(feature = "runtime"), allow(dead_code))]
pub(crate) fn valid_decimal_value(
    value: &str,
    precision: u8,
    scale: u8,
    minimum: Option<&str>,
    maximum: Option<&str>,
) -> bool {
    let Some(parsed) = decimal_scaled_value(value, precision, scale) else {
        return false;
    };
    if let Some(minimum) = minimum {
        let Some(minimum) = decimal_scaled_value(minimum, precision, scale) else {
            return false;
        };
        if parsed < minimum {
            return false;
        }
    }
    if let Some(maximum) = maximum {
        let Some(maximum) = decimal_scaled_value(maximum, precision, scale) else {
            return false;
        };
        if parsed > maximum {
            return false;
        }
    }
    true
}

#[cfg_attr(not(feature = "runtime"), allow(dead_code))]
pub(crate) fn parsed_bbox(bbox: &Crs84BboxSource, precision: u8) -> Option<(f64, f64, f64, f64)> {
    if precision > 9 {
        return None;
    }
    let west = parse_coordinate(&bbox.west, precision, -180.0, 180.0)?;
    let south = parse_coordinate(&bbox.south, precision, -90.0, 90.0)?;
    let east = parse_coordinate(&bbox.east, precision, -180.0, 180.0)?;
    let north = parse_coordinate(&bbox.north, precision, -90.0, 90.0)?;
    (west <= east && south <= north).then_some((west, south, east, north))
}

#[cfg_attr(not(feature = "runtime"), allow(dead_code))]
pub(crate) fn valid_crs84_point(
    value: &Value,
    precision: u8,
    bbox: Option<&Crs84BboxSource>,
) -> bool {
    if precision > 9 {
        return false;
    }
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 2 || object.get("type").and_then(Value::as_str) != Some("Point") {
        return false;
    }
    let Some(coordinates) = object.get("coordinates").and_then(Value::as_array) else {
        return false;
    };
    if coordinates.len() != 2 {
        return false;
    }
    let Some(lon) = coordinate_number(&coordinates[0], precision, -180.0, 180.0) else {
        return false;
    };
    let Some(lat) = coordinate_number(&coordinates[1], precision, -90.0, 90.0) else {
        return false;
    };
    bbox.and_then(|bbox| parsed_bbox(bbox, precision))
        .is_none_or(|(west, south, east, north)| {
            lon >= west && lon <= east && lat >= south && lat <= north
        })
}

pub(crate) fn valid_structured_schema(schema: &Value) -> bool {
    schema.as_object().is_some_and(|object| {
        schema_declares_object(object)
            && object.get("additionalProperties") == Some(&Value::Bool(false))
    }) && canonicalize_json(schema).is_ok_and(|bytes| bytes.len() <= MAX_STRUCTURED_SCHEMA_BYTES)
        && schema_refs_are_local(schema)
        && object_schemas_are_closed(schema)
        && JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(schema)
            .is_ok()
}

fn schema_declares_object(object: &serde_json::Map<String, Value>) -> bool {
    object.get("type").is_some_and(|kind| {
        kind == "object"
            || kind
                .as_array()
                .is_some_and(|types| types.iter().any(|kind| kind == "object"))
    })
}

#[cfg_attr(not(feature = "runtime"), allow(dead_code))]
pub(crate) fn valid_structured_value(value: &Value, max_bytes: u32, schema: &Value) -> bool {
    if max_bytes == 0 || max_bytes > MAX_STRUCTURED_VALUE_BYTES || !valid_structured_schema(schema)
    {
        return false;
    }
    let Ok(bytes) = canonicalize_json(value) else {
        return false;
    };
    if bytes.len() > max_bytes as usize {
        return false;
    }
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .is_ok_and(|compiled| compiled.is_valid(value))
}

#[cfg_attr(not(feature = "runtime"), allow(dead_code))]
fn parse_coordinate(value: &str, precision: u8, minimum: f64, maximum: f64) -> Option<f64> {
    if value.is_empty() || value.starts_with('+') || value.contains('e') || value.contains('E') {
        return None;
    }
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    let (integer, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if integer.is_empty()
        || integer.bytes().any(|byte| !byte.is_ascii_digit())
        || fraction.bytes().any(|byte| !byte.is_ascii_digit())
        || integer.len() > 1 && integer.starts_with('0')
        || fraction.len() > usize::from(precision)
    {
        return None;
    }
    let parsed = value.parse::<f64>().ok()?;
    (parsed >= minimum && parsed <= maximum).then_some(parsed)
}

#[cfg_attr(not(feature = "runtime"), allow(dead_code))]
fn coordinate_number(value: &Value, precision: u8, minimum: f64, maximum: f64) -> Option<f64> {
    value
        .is_number()
        .then(|| parse_coordinate(&value.to_string(), precision, minimum, maximum))
        .flatten()
}

fn schema_refs_are_local(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().all(|(key, value)| {
            if key == "$ref" {
                value
                    .as_str()
                    .is_some_and(|reference| reference == "#" || reference.starts_with("#/"))
            } else {
                schema_refs_are_local(value)
            }
        }),
        Value::Array(values) => values.iter().all(schema_refs_are_local),
        _ => true,
    }
}

fn object_schemas_are_closed(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            let describes_object = object.get("properties").is_some()
                || object.get("patternProperties").is_some()
                || schema_declares_object(object);
            (!describes_object || object.get("additionalProperties") == Some(&Value::Bool(false)))
                && object.values().all(object_schemas_are_closed)
        }
        Value::Array(values) => values.iter().all(object_schemas_are_closed),
        _ => true,
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceDelete {
    #[default]
    Restrict,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidTimeRole {
    ValidFrom,
    ValidTo,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ConstraintSource {
    Unique {
        #[serde(default)]
        id: Option<String>,
        fields: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        when: Option<Vec<UniqueWhenPredicate>>,
    },
    Compare {
        #[serde(default)]
        id: Option<String>,
        left: String,
        operator: ComparisonOperator,
        right: String,
    },
    IntRange {
        #[serde(default)]
        id: Option<String>,
        field: String,
        #[serde(default)]
        minimum: Option<i64>,
        #[serde(default)]
        maximum: Option<i64>,
    },
    Vocabulary {
        #[serde(default)]
        id: Option<String>,
        field: String,
        values: Vec<String>,
    },
    #[serde(rename = "temporal-non-overlap")]
    TemporalNonOverlap {
        #[serde(default)]
        id: Option<String>,
        scope_fields: Vec<String>,
        #[serde(default)]
        start_field: Option<String>,
        #[serde(default)]
        end_field: Option<String>,
    },
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum UniqueWhenPredicate {
    FieldEquals { field: String, value: Value },
    FieldIsNull { field: String },
    FieldIsNotNull { field: String },
    ActiveLifecycle {},
}

impl ConstraintSource {
    pub fn explicit_id(&self) -> Option<&str> {
        match self {
            Self::Unique { id, .. }
            | Self::Compare { id, .. }
            | Self::IntRange { id, .. }
            | Self::Vocabulary { id, .. }
            | Self::TemporalNonOverlap { id, .. } => id.as_deref(),
        }
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TemporalSource {
    pub start_field: String,
    pub end_field: String,
    /// Deprecated bounded predecessor bridge. New authoring should declare
    /// exclusivity only through `constraints[].scopeFields`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_fields: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonOperator {
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IndexSource {
    pub id: String,
    pub fields: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessProfileSource {
    pub id: String,
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub anonymous: bool,
    #[serde(default)]
    pub principal_claim: Option<String>,
    #[serde(default)]
    /// All listed scopes must be present in the verified token.
    pub required_scopes: BTreeSet<String>,
    #[serde(default)]
    /// The verified token's purpose must match one listed value. Empty means no purpose restriction.
    pub required_purposes: BTreeSet<String>,
    pub operations: BTreeSet<Operation>,
    #[serde(default)]
    pub readable_fields: BTreeSet<String>,
    #[serde(default)]
    pub writable_fields: BTreeSet<String>,
    #[serde(default)]
    pub filterable_fields: BTreeSet<String>,
    #[serde(default)]
    pub sortable_fields: BTreeSet<String>,
    #[serde(default)]
    pub row_boundaries: Vec<RowBoundarySource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lookups: Vec<LookupGrantSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_paths: Vec<ReadPathGrantSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_stages: Vec<ReviewStageGrantSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apply_targets: Vec<ApplyTargetGrantSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_presence: Vec<RequestPresenceGrantSource>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_count: bool,
    #[serde(default)]
    pub revision_access: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_fields: Vec<ProvenanceFieldSource>,
    #[serde(default)]
    pub allow_data_export: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Create,
    Get,
    Lookup,
    List,
    Patch,
    Tombstone,
    Batch,
    Revisions,
    Snapshot,
    SubmitRequest,
    ApproveRequest,
    RejectRequest,
    RequestRevision,
    ReviseRequest,
    CancelRequest,
    ApplyRequest,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProvenanceFieldSource {
    Kind,
    ReasonCode,
    ReasonText,
    SourceReferences,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RowBoundarySource {
    pub field: String,
    pub claim: String,
    pub operator: BoundaryOperator,
}

/// Compile-time requirements, not grants. Profiles must explicitly satisfy them.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessRequirementsSource {
    /// Every profile must require all these scopes. Requirements never grant access.
    #[serde(default)]
    pub required_scopes: BTreeSet<String>,
    /// When nonempty, every profile must restrict purpose to a nonempty subset of these values. Empty imposes no purpose requirement.
    #[serde(default)]
    pub allowed_purposes: BTreeSet<String>,
    /// Every profile must include these exact field, verified-claim, and operator bindings.
    #[serde(default)]
    pub row_boundaries: Vec<RowBoundarySource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryOperator {
    Equals,
    In,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EventSource {
    /// Stable event contract identifier, sent as `ce-type`. Use a new identifier for a breaking payload change.
    pub id: String,
    /// Committed record change that can produce this event.
    pub trigger: EventTrigger,
    /// Declared field identifiers to include in `values`. System event metadata is included separately.
    pub projection: BTreeSet<String>,
    /// Optional field tests, combined with AND. Omit to emit on every matching trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<EventConditionSource>,
    /// Logical delivery destination. Production compilation requires a webhook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook: Option<WebhookSource>,
}

/// Closed Version 1 event selection language.
///
/// A tagged shape leaves room for a later, separately governed rule ABI
/// without turning fields into an ad hoc expression language.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum EventConditionSource {
    Fields {
        /// Fields whose values must change. Only valid with the patched trigger.
        #[serde(default)]
        changed: BTreeSet<String>,
        /// Required values before the change. Valid with patched and tombstoned triggers.
        #[serde(default)]
        before_equals: BTreeMap<String, EventScalarValue>,
        /// Required values after the change. Valid with created and patched triggers.
        #[serde(default)]
        after_equals: BTreeMap<String, EventScalarValue>,
    },
    RequestLifecycle {
        #[serde(default)]
        transitions: BTreeSet<String>,
        #[serde(default)]
        to_states: BTreeSet<String>,
        #[serde(default)]
        stages: BTreeSet<String>,
    },
}

/// A comparison literal in the closed field-condition language.
///
/// Objects and arrays are refused during source parsing. The compiler then
/// validates each scalar against the declared Registry field type.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventScalarValue {
    Null,
    Boolean(bool),
    Number(serde_json::Number),
    String(String),
}

/// Governed, destination-neutral webhook subscription.
///
/// Deployment configuration may bind `destination_id` to transport details
/// and tighten these bounds, but cannot supply or widen this authority.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WebhookSource {
    /// Key in runtime `eventDestinations`; the project carries no URL or secret.
    pub destination_id: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookAuthenticationProfile {
    HmacSha256V1,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookDeadLetterMode {
    Required,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProjectAccessProfileSource {
    pub id: String,
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub anonymous: bool,
    #[serde(default)]
    pub principal_claim: Option<String>,
    #[serde(default)]
    /// All listed scopes must be present in the verified token.
    pub required_scopes: BTreeSet<String>,
    #[serde(default)]
    /// The verified token's purpose must match one listed value. Empty means no purpose restriction.
    pub required_purposes: BTreeSet<String>,
    #[serde(default)]
    pub grants: Vec<AccessGrantSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessGrantSource {
    pub entity: String,
    pub operations: BTreeSet<Operation>,
    #[serde(default)]
    pub readable_fields: BTreeSet<String>,
    #[serde(default)]
    pub writable_fields: BTreeSet<String>,
    #[serde(default)]
    pub filterable_fields: BTreeSet<String>,
    #[serde(default)]
    pub sortable_fields: BTreeSet<String>,
    #[serde(default)]
    pub row_boundaries: Vec<RowBoundarySource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lookups: Vec<LookupGrantSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_paths: Vec<ReadPathGrantSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_stages: Vec<ReviewStageGrantSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apply_targets: Vec<ApplyTargetGrantSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_presence: Vec<RequestPresenceGrantSource>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_count: bool,
    #[serde(default)]
    pub revision_access: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_fields: Vec<ProvenanceFieldSource>,
    #[serde(default)]
    pub allow_data_export: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LookupGrantSource {
    pub selector: String,
    pub value_origin: LookupValueOrigin,
    #[serde(default)]
    pub claim_mapping: BTreeMap<String, String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupValueOrigin {
    Request,
    VerifiedClaim,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReadPathGrantSource {
    pub path: String,
    #[serde(default)]
    pub readable_fields: BTreeSet<String>,
    #[serde(default)]
    pub filterable_fields: BTreeSet<String>,
    #[serde(default)]
    pub sortable_fields: BTreeSet<String>,
    #[serde(default)]
    pub allow_count: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewStageGrantSource {
    pub stage: String,
    #[serde(default)]
    pub targets: Vec<ReviewStageTargetGrantSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewStageTargetGrantSource {
    pub entity: String,
    #[serde(default)]
    pub readable_fields: BTreeSet<String>,
    #[serde(default)]
    pub row_boundaries: Vec<RowBoundarySource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApplyTargetGrantSource {
    pub entity: String,
    #[serde(default)]
    pub row_boundaries: Vec<RowBoundarySource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RequestPresenceGrantSource {
    pub request_type: String,
    #[serde(default)]
    pub row_boundaries: Vec<RowBoundarySource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VocabularySource {
    pub id: String,
    pub values: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventTrigger {
    Created,
    Patched,
    Tombstoned,
    RequestLifecycle,
}

pub fn parse_project_json(bytes: &[u8]) -> Result<RegistryProject, CompileFailure> {
    parse_json(bytes, "project")
}

pub fn parse_module_json(bytes: &[u8]) -> Result<RegistryModule, CompileFailure> {
    parse_json(bytes, "module")
}

pub fn parse_project_yaml(bytes: &[u8]) -> Result<RegistryProject, CompileFailure> {
    parse_yaml(bytes, "project")
}

pub fn parse_module_yaml(bytes: &[u8]) -> Result<RegistryModule, CompileFailure> {
    parse_yaml(bytes, "module")
}

fn parse_json<T: DeserializeOwned>(bytes: &[u8], root: &str) -> Result<T, CompileFailure> {
    let value = parse_json_strict(bytes).map_err(|_| {
        CompileFailure::from_one(Diagnostic::error(
            "source.json.invalid",
            root,
            "the JSON source is structurally invalid",
        ))
    })?;
    deserialize_value(value, root)
}

fn parse_yaml<T: DeserializeOwned>(bytes: &[u8], root: &str) -> Result<T, CompileFailure> {
    let deserializer = serde_norway::Deserializer::from_slice(bytes);
    serde_path_to_error::deserialize(deserializer).map_err(|error| {
        let suffix = error.path().to_string();
        let path = if suffix.is_empty() {
            root.to_owned()
        } else {
            format!("{root}.{suffix}")
        };
        CompileFailure::from_one(Diagnostic::error(
            "source.yaml.invalid",
            path,
            "the YAML source is structurally invalid",
        ))
    })
}

fn deserialize_value<T: DeserializeOwned>(
    value: serde_json::Value,
    root: &str,
) -> Result<T, CompileFailure> {
    let deserializer = value.into_deserializer();
    serde_path_to_error::deserialize(deserializer).map_err(|error| {
        let suffix = error.path().to_string();
        let path = if suffix.is_empty() {
            root.to_owned()
        } else {
            format!("{root}.{suffix}")
        };
        CompileFailure::from_one(Diagnostic::error(
            "source.shape.invalid",
            path,
            "the source field is unknown, duplicated, missing, or has the wrong type",
        ))
    })
}
