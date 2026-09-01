// SPDX-License-Identifier: Apache-2.0
//! Immutable compiled model and rendering-neutral reports.

use serde::{Deserialize, Serialize};

use crate::contract::{
    AlignmentTarget, DataType, DateInputType, DatePrecision, Handling, IdentificationMethod,
    PartialStringReveal, ProcessingDescription, SemanticAlignment, SourceProfile,
    StatisticalTimeGranularity, StatisticalValueType, Visibility,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub location: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompileReport {
    pub diagnostics: Vec<Diagnostic>,
}

impl CompileReport {
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|item| item.severity == DiagnosticSeverity::Error)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CompileProfile {
    Authoring,
    Production,
}

/// Product-neutral result of inspecting every reviewed source view. The
/// SQLite platform crate owns extraction and fingerprint calculation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ObservedSourceSchema {
    pub source: String,
    pub fingerprint: String,
    pub views: Vec<ObservedView>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ObservedView {
    pub name: String,
    pub columns: Vec<ObservedColumn>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ObservedColumn {
    pub name: String,
    pub declared_type: String,
    pub nullable: bool,
    pub primary_key: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledRegistry {
    pub contract_revision: String,
    pub contract_id: String,
    pub contract_version: String,
    pub registry_identifier: String,
    pub registry_name: String,
    pub authority_identifier: String,
    pub authority_name: String,
    pub operator_identifier: Option<String>,
    pub operator_name: Option<String>,
    pub authoritative_scope: String,
    pub base_uri: String,
    pub identifier_lifecycle_policy_ref: String,
    pub alignment_targets: Vec<AlignmentTarget>,
    pub controller_identifier: String,
    pub publisher_identifier: String,
    pub audit_owner_identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication: Option<CompiledPublication>,
    pub local_vocabulary: String,
    pub semantic_alignments: Vec<SemanticAlignment>,
    pub governed_files: Vec<CompiledGovernedFile>,
    pub classification_review: Option<CompiledClassificationReview>,
    pub codelists: Vec<CompiledCodelist>,
    pub sources: Vec<CompiledSource>,
    pub resources: Vec<CompiledResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statistical_datasets: Vec<CompiledStatisticalDataset>,
    pub metadata_visibility: CompiledMetadataVisibility,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledPublication {
    pub jurisdictions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledGovernedFile {
    pub path: String,
    pub sha256: String,
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledCodelist {
    pub path: String,
    pub id: String,
    pub version: String,
    pub values: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledSource {
    pub id: String,
    pub profile: SourceProfile,
    pub expected_schema_fingerprint: String,
    pub observed_schema: Option<ObservedSourceSchema>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledResource {
    pub id: String,
    pub dataset_identifier: String,
    pub entity_type_identifier: String,
    pub title: String,
    pub description: String,
    pub semantic_class: String,
    pub source: String,
    pub view: String,
    pub record_context: CompiledRecordContext,
    pub properties: Vec<CompiledProperty>,
    pub primary_geometry: Option<String>,
    pub disclosure_profiles: Vec<CompiledDisclosureProfile>,
    pub operations: Vec<CompiledOperation>,
    pub column_accounting: Vec<ColumnAccount>,
    pub processing_descriptions: Vec<ProcessingDescription>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledStatisticalDataset {
    pub id: String,
    pub title: String,
    pub description: String,
    pub sdmx: CompiledSdmxBindingProfile,
    pub release_at: String,
    pub source: String,
    pub view: String,
    pub dimensions: Vec<CompiledStatisticalDimension>,
    pub time: CompiledStatisticalTimeDimension,
    pub measure: CompiledStatisticalMeasure,
    pub attributes: Vec<CompiledStatisticalAttribute>,
    pub access: CompiledAccess,
    pub allow_unfiltered: bool,
    pub maximum_observations: u32,
    pub maximum_offset: u32,
    pub processing_handling: Handling,
    pub disclosure_handling: Handling,
    pub column_accounting: Vec<ColumnAccount>,
    pub processing_descriptions: Vec<ProcessingDescription>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledSdmxBindingProfile {
    pub agency_id: String,
    pub dataflow_id: String,
    pub version: String,
    pub data_structure_id: String,
    pub concept_scheme_id: String,
    pub rest_version: String,
    pub data_json_version: String,
    pub data_csv_version: String,
    pub structure_json_version: String,
}

impl CompiledStatisticalDataset {
    #[must_use]
    pub fn operation_identifier(&self) -> String {
        format!("{}.statistics.read", self.id)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledStatisticalDimension {
    pub id: String,
    pub label: String,
    pub description: String,
    pub source_column: String,
    pub data_type: StatisticalValueType,
    pub codelist: Option<String>,
    pub semantic_iri: String,
    pub classification: EffectiveClassification,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledStatisticalTimeDimension {
    pub id: String,
    pub label: String,
    pub description: String,
    pub source_column: String,
    pub granularity: StatisticalTimeGranularity,
    pub semantic_iri: String,
    pub classification: EffectiveClassification,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledStatisticalMeasure {
    pub id: String,
    pub label: String,
    pub description: String,
    pub source_column: String,
    pub data_type: StatisticalValueType,
    pub semantic_iri: String,
    pub classification: EffectiveClassification,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledStatisticalAttribute {
    pub id: String,
    pub label: String,
    pub description: String,
    pub source_column: String,
    pub data_type: StatisticalValueType,
    pub codelist: Option<String>,
    pub source_required: bool,
    pub semantic_iri: String,
    pub classification: EffectiveClassification,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledRecordContext {
    pub record_identifier_column: String,
    pub revision_identifier_column: String,
    pub lifecycle_state_column: String,
    pub lifecycle_state_codelist: String,
    pub recorded_at_column: String,
    pub schema_reference: String,
    pub semantic_model_reference: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledProperty {
    pub name: String,
    pub label: String,
    pub description: String,
    pub source_required: bool,
    pub semantic_iri: String,
    pub classification: EffectiveClassification,
    pub binding: CompiledPropertyBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum CompiledPropertyBinding {
    Scalar(CompiledScalarPropertyBinding),
    Point(CompiledPointPropertyBinding),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledScalarPropertyBinding {
    pub source_column: String,
    pub transform: Option<CompiledTransform>,
    pub data_type: DataType,
    pub codelist: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledPointPropertyBinding {
    pub crs: String,
    pub longitude_column: String,
    pub latitude_column: String,
}

impl CompiledProperty {
    #[must_use]
    pub fn scalar_binding(&self) -> Option<&CompiledScalarPropertyBinding> {
        match &self.binding {
            CompiledPropertyBinding::Scalar(binding) => Some(binding),
            CompiledPropertyBinding::Point(_) => None,
        }
    }

    #[must_use]
    pub fn point_binding(&self) -> Option<&CompiledPointPropertyBinding> {
        match &self.binding {
            CompiledPropertyBinding::Point(binding) => Some(binding),
            CompiledPropertyBinding::Scalar(_) => None,
        }
    }

    pub fn source_columns(&self) -> impl Iterator<Item = &str> {
        match &self.binding {
            CompiledPropertyBinding::Scalar(binding) => {
                [Some(binding.source_column.as_str()), None]
                    .into_iter()
                    .flatten()
            }
            CompiledPropertyBinding::Point(binding) => [
                Some(binding.longitude_column.as_str()),
                Some(binding.latitude_column.as_str()),
            ]
            .into_iter()
            .flatten(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CompiledTransform {
    PartialString {
        identifier: String,
        reveal: PartialStringReveal,
        characters: u16,
    },
    DatePrecision {
        identifier: String,
        source_type: DateInputType,
        precision: DatePrecision,
    },
}

impl CompiledTransform {
    #[must_use]
    pub fn identifier(&self) -> &str {
        match self {
            Self::PartialString { identifier, .. } | Self::DatePrecision { identifier, .. } => {
                identifier
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveClassification {
    pub privacy: String,
    pub privacy_scheme: String,
    pub privacy_version: String,
    pub institutional: String,
    pub institutional_scheme: String,
    pub institutional_version: String,
    pub handling: Handling,
    pub handling_scheme: String,
    pub handling_version: String,
    pub status: crate::contract::ReviewStatus,
    pub provenance_ref: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledDisclosureProfile {
    pub id: String,
    /// Maximum and default set in authored order.
    pub properties: Vec<String>,
    pub maximum_handling: Handling,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledClassificationReview {
    pub registry_identifier: String,
    pub classification_inventory_digest: String,
    pub method: IdentificationMethod,
    pub reviewer: String,
    pub review_date: String,
    pub status: crate::contract::ReviewStatus,
    pub rationale_ref: String,
    pub generated_identification: Option<CompiledGeneratedIdentificationBinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledGeneratedIdentificationBinding {
    pub report_ref: String,
    pub report_digest: String,
    pub rule_pack_id: String,
    pub rule_pack_version: String,
    pub rule_pack_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledOperation {
    pub identifier: String,
    pub family: CapabilityFamily,
    pub pattern: ConsultationPattern,
    pub kind: OperationKind,
    pub default_access_profile: String,
    pub access_profiles: Vec<CompiledAccessProfile>,
    pub query: QueryPlan,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledAccessProfile {
    pub id: String,
    pub access: CompiledAccess,
    pub disclosure_profile: String,
    pub selectable_properties: Vec<String>,
    pub projected_columns: Vec<String>,
    pub processing_handling: Handling,
    pub disclosure_handling: Handling,
    pub transform_inventory: Vec<String>,
    pub schema_reference: String,
    pub semantic_model_reference: String,
    pub context_reference: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityFamily {
    Consultation,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConsultationPattern {
    List,
    Retrieve,
    Search,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum FormatProfile {
    Rfc7946,
    JsonFg,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OperationKind {
    List,
    Read,
    Lookup { name: String },
    Search { name: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CompiledAccess {
    Public,
    Protected {
        scope: String,
        purpose: Option<CompiledPurpose>,
        row_binding: Option<CompiledRowBinding>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledPurpose {
    pub claim: String,
    pub allowed: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledRowBinding {
    pub source: RowAuthoritySource,
    pub source_column: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "claim", rename_all = "kebab-case")]
pub enum RowAuthoritySource {
    Principal,
    Claim(String),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QueryPlan {
    pub source: String,
    pub view: String,
    pub filters: Vec<CompiledFilter>,
    pub spatial_bbox: Option<CompiledSpatialBboxQuery>,
    pub selectors: Vec<CompiledSelector>,
    pub order_by: Vec<String>,
    pub allow_unfiltered: bool,
    pub pagination: Option<CompiledPagination>,
    pub maximum_request_body_bytes: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledSpatialBboxQuery {
    pub longitude_column: String,
    pub latitude_column: String,
    pub maximum_longitude_span_degrees: u16,
    pub maximum_latitude_span_degrees: u16,
}

pub const POINT_BBOX_PREDICATE: &str = "inclusive-point-within-bbox";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledFilter {
    pub parameter: String,
    pub property: String,
    pub source_column: String,
    pub data_type: DataType,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledSelector {
    pub name: String,
    pub source_column: String,
    pub data_type: DataType,
    pub minimum_bytes: Option<u32>,
    pub maximum_bytes: Option<u32>,
    pub codelist: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledPagination {
    pub default_page_size: u32,
    pub maximum_page_size: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ColumnAccount {
    pub column: String,
    pub uses: Vec<ColumnUse>,
    pub classification: EffectiveClassification,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ColumnUse {
    RecordIdentifier,
    RevisionIdentifier,
    LifecycleState,
    RecordedAt,
    Property(String),
    PointLongitude(String),
    PointLatitude(String),
    Filter(String),
    Order,
    Selector(String),
    RowBinding(String),
    StatisticalDimension(String),
    StatisticalMeasure(String),
    StatisticalAttribute(String),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledMetadataVisibility {
    pub service: Visibility,
    pub resources: Visibility,
    pub statistical_datasets: Option<Visibility>,
    pub semantics: Visibility,
    pub classifications: Visibility,
    pub processing: Visibility,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StarterContract {
    pub source: String,
    pub view: String,
    pub expected_schema_fingerprint: String,
    pub columns: Vec<StarterColumn>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StarterColumn {
    pub source_column: String,
    pub suggested_property: String,
    pub suggested_type: DataType,
    pub classification_status: crate::contract::ReviewStatus,
}
