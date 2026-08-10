// SPDX-License-Identifier: Apache-2.0
//! Deterministic, schema-only Relay identification and classification-review binding.
//!
//! This module accepts only the governed contract and [`ObservedSourceSchema`]
//! metadata. It has no database, filesystem, network, or source-row interface.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use chrono::NaiveDate;
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::contract::{
    AccessRule, AuthorityRowBinding, ClassificationReviewDocument, GeneratedIdentificationBinding,
    Handling, IdentificationMethod, RegistryContract, ReviewStatus, RulePackBinding, SourceProfile,
};
use crate::format_capabilities::{
    response_format_capabilities, FormatProfileIdentifier, WireFormatCapability,
    WireFormatIdentifier, CRS84_URI,
};
use crate::model::{
    CapabilityFamily, ColumnUse, CompiledAccess, CompiledAccessProfile, CompiledOperation,
    CompiledRegistry, CompiledResource, CompiledTransform, ConsultationPattern,
    EffectiveClassification, ObservedColumn, ObservedSourceSchema, OperationKind,
    RowAuthoritySource, POINT_BBOX_PREDICATE,
};

pub const IDENTIFICATION_REPORT_PATH: &str = "reports/identification-report.json";
pub const CLASSIFICATION_INVENTORY_REPORT_PATH: &str = "reports/classification-inventory.json";
pub const OPERATION_EXPLANATION_PATH: &str = "reports/operation-explanation.json";
pub const CONTEXTUAL_REVIEW_FINDINGS_PATH: &str = "reports/contextual-review-findings.json";
pub const CLASSIFICATION_REVIEW_STARTER_PATH: &str =
    "governance/classification-review-starter.yaml";
pub const REVIEWED_IDENTIFICATION_REPORT_PATH: &str = "reports/identification-report.json";

const REPORT_API_VERSION: &str = "relay.registrystack.org/identification-report/v1";
const REPORT_KIND: &str = "IdentificationReport";
const REVIEW_API_VERSION: &str = "relay.registrystack.org/classification-review/v1";
const REVIEW_KIND: &str = "ClassificationReview";
const CORE_PACK_DIGEST: &str =
    "sha256:5ad3abd1615c409741c190ff17c4ad8cf31db88dfe49c9bbddf47a2e12896fa2";
const CORE_PACK_BYTES: &[u8] = include_bytes!("../assets/identification/core-pack-v1.json");
const MAXIMUM_PACK_BYTES: usize = 64 * 1024;
const MAXIMUM_RULES: usize = 128;
const MAXIMUM_CONDITIONS_PER_RULE: usize = 8;
const MAXIMUM_SOURCES: usize = 256;
const MAXIMUM_VIEWS: usize = 10_000;
const MAXIMUM_COLUMNS: usize = 100_000;
const MAXIMUM_REVIEW_TEXT_BYTES: usize = 512;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum IdentificationError {
    #[error("the embedded identification pack digest does not match its pin")]
    PackDigestMismatch,
    #[error("the embedded identification pack is invalid")]
    PackInvalid,
    #[error("the observed schema exceeds the identification bounds")]
    InputTooLarge,
    #[error("the identification artifact could not be canonicalized")]
    Canonicalization,
    #[error("the classification review could not be rendered")]
    ReviewRender,
    #[error("the classification review is not valid strict YAML")]
    ReviewParse,
    #[error("the classification inventory digest is invalid")]
    InventoryDigestInvalid,
}

impl IdentificationError {
    /// A categorical failure that cannot expose schema names or source values.
    pub fn safe_message(&self) -> &'static str {
        match self {
            Self::PackDigestMismatch => {
                "the embedded identification pack digest does not match its pin"
            }
            Self::PackInvalid => "the embedded identification pack is invalid",
            Self::InputTooLarge => "the observed schema exceeds the identification bounds",
            Self::Canonicalization => "the identification artifact could not be canonicalized",
            Self::ReviewRender => "the classification review could not be rendered",
            Self::ReviewParse => "the classification review is not valid strict YAML",
            Self::InventoryDigestInvalid => "the classification inventory digest is invalid",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IdentificationReport {
    pub api_version: String,
    pub kind: String,
    pub registry_identifier: String,
    pub observed_schema_digest: String,
    pub rule_pack: RulePackBinding,
    pub privacy_candidate_vocabulary: CandidateVocabulary,
    pub candidates: Vec<IdentificationCandidate>,
    pub diagnostics: Vec<IdentificationDiagnostic>,
}

/// The local vocabulary used by an identification pack for review candidates.
///
/// Candidate terms are never asserted to belong to the registry's configured
/// privacy scheme. An institutional reviewer must map or replace them before
/// accepting the governed classification inventory.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CandidateVocabulary {
    pub scheme: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CandidateTerm {
    pub scheme: String,
    pub version: String,
    pub term: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IdentificationCandidate {
    pub source: String,
    pub view: String,
    pub source_column: String,
    pub suggested_property: Option<String>,
    pub suggested_semantic_term: Option<String>,
    pub suggested_role: Option<TechnicalRole>,
    pub suggested_privacy: Vec<CandidateTerm>,
    pub matched_rules: Vec<MatchedRule>,
    pub rule_pack: RulePackBinding,
    pub confidence: CategoricalConfidence,
    pub status: IdentificationStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MatchedRule {
    pub id: String,
    pub version: String,
    pub family: RuleFamily,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum RuleFamily {
    AdministrativeCodes,
    Codelists,
    Columns,
    Contact,
    GeographicCodes,
    Identifiers,
    Lifecycle,
    PersonReferences,
    Revisions,
    Times,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum TechnicalRole {
    AdministrativeCode,
    Codelist,
    EmailAddress,
    GeographicCode,
    Identifier,
    LifecycleState,
    PersonReference,
    Property,
    RecordedTime,
    RecordIdentifier,
    RevisionIdentifier,
    TelephoneNumber,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CategoricalConfidence {
    Exact,
    Strong,
    Weak,
    Conflict,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IdentificationStatus {
    Suggested,
    Uncertain,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IdentificationDiagnostic {
    pub severity: IdentificationDiagnosticSeverity,
    pub code: String,
    pub source: String,
    pub view: String,
    pub source_column: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IdentificationDiagnosticSeverity {
    Warning,
}

/// Identify every observed column using the single embedded technical pack.
///
/// Input order is deliberately erased before digesting and matching. Authored
/// property names, semantic terms, codelists, Registry Core roles, filters,
/// selectors, ordering, and row bindings are the only contextual hints.
pub fn identify_contract(
    contract: &RegistryContract,
    observed: &[ObservedSourceSchema],
) -> Result<IdentificationReport, IdentificationError> {
    ensure_observation_bounds(observed)?;
    let pack = load_core_pack(CORE_PACK_BYTES, CORE_PACK_DIGEST)?;
    let rule_pack = pack.reference(CORE_PACK_DIGEST);
    let privacy_candidate_vocabulary = pack.privacy_candidate_vocabulary.clone();
    let normalized_observation = normalized_observation(observed);
    let observed_schema_digest = digest_serializable(&normalized_observation)?;
    let hints = authored_hints(contract);
    let mut candidates = Vec::new();
    let mut diagnostics = Vec::new();

    for schema in &normalized_observation {
        for view in &schema.views {
            for column in &view.columns {
                let hint = hints.get(&(
                    schema.source.clone(),
                    view.name.clone(),
                    column.name.clone(),
                ));
                let candidate =
                    identify_column(&pack, &rule_pack, &schema.source, &view.name, column, hint);
                if candidate.status == IdentificationStatus::Uncertain {
                    diagnostics.push(IdentificationDiagnostic {
                        severity: IdentificationDiagnosticSeverity::Warning,
                        code: "identification.candidate_conflict".into(),
                        source: schema.source.clone(),
                        view: view.name.clone(),
                        source_column: column.name.clone(),
                        message:
                            "credible schema-only rules conflict; institutional review is required"
                                .into(),
                    });
                }
                candidates.push(candidate);
            }
        }
    }

    Ok(IdentificationReport {
        api_version: REPORT_API_VERSION.into(),
        kind: REPORT_KIND.into(),
        registry_identifier: contract.registry.registry_identifier.clone(),
        observed_schema_digest,
        rule_pack,
        privacy_candidate_vocabulary,
        candidates,
        diagnostics,
    })
}

/// Render the exact deterministic bytes used for the generated report digest.
pub fn render_identification_report(
    report: &IdentificationReport,
) -> Result<Vec<u8>, IdentificationError> {
    let value = serde_json::to_value(report).map_err(|_| IdentificationError::Canonicalization)?;
    canonicalize_json(&value).map_err(|_| IdentificationError::Canonicalization)
}

pub fn identification_report_digest(
    report: &IdentificationReport,
) -> Result<String, IdentificationError> {
    Ok(sha256(&render_identification_report(report)?))
}

/// Verify and return the identity of the one embedded identification pack.
pub fn core_pack_reference() -> Result<RulePackBinding, IdentificationError> {
    Ok(load_core_pack(CORE_PACK_BYTES, CORE_PACK_DIGEST)?.reference(CORE_PACK_DIGEST))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClassificationInventoryReport {
    pub api_version: String,
    pub kind: String,
    pub registry_identifier: String,
    pub classification_inventory_digest: String,
    pub resources: Vec<ResourceClassificationInventory>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceClassificationInventory {
    pub resource: String,
    pub source: String,
    pub view: String,
    pub source_columns: Vec<SourceColumnClassificationInventory>,
    pub properties: Vec<PropertyClassificationInventory>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceColumnClassificationInventory {
    pub source_column: String,
    pub uses: Vec<ColumnUse>,
    pub classification: EffectiveClassification,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PropertyClassificationInventory {
    pub property: String,
    pub source_column: String,
    pub semantic_term: String,
    pub transform: Option<String>,
    pub classification: EffectiveClassification,
}

pub fn classification_inventory_report(
    registry: &CompiledRegistry,
    classification_inventory_digest: &str,
) -> Result<ClassificationInventoryReport, IdentificationError> {
    require_inventory_digest(registry, classification_inventory_digest)?;
    let mut resources = registry
        .resources
        .iter()
        .map(|resource| {
            let mut source_columns = resource
                .column_accounting
                .iter()
                .map(|column| SourceColumnClassificationInventory {
                    source_column: column.column.clone(),
                    uses: column.uses.clone(),
                    classification: column.classification.clone(),
                })
                .collect::<Vec<_>>();
            source_columns.sort_by(|left, right| left.source_column.cmp(&right.source_column));
            let mut properties = resource
                .properties
                .iter()
                .map(|property| PropertyClassificationInventory {
                    property: property.name.clone(),
                    source_column: property.source_column.clone(),
                    semantic_term: property.semantic_iri.clone(),
                    transform: property
                        .transform
                        .as_ref()
                        .map(|transform| transform.identifier().to_owned()),
                    classification: property.classification.clone(),
                })
                .collect::<Vec<_>>();
            properties.sort_by(|left, right| left.property.cmp(&right.property));
            ResourceClassificationInventory {
                resource: resource.id.clone(),
                source: resource.source.clone(),
                view: resource.view.clone(),
                source_columns,
                properties,
            }
        })
        .collect::<Vec<_>>();
    resources.sort_by(|left, right| left.resource.cmp(&right.resource));
    Ok(ClassificationInventoryReport {
        api_version: "relay.registrystack.org/classification-inventory/v1".into(),
        kind: "ClassificationInventory".into(),
        registry_identifier: registry.registry_identifier.clone(),
        classification_inventory_digest: classification_inventory_digest.into(),
        resources,
    })
}

pub fn render_classification_inventory_report(
    report: &ClassificationInventoryReport,
) -> Result<Vec<u8>, IdentificationError> {
    render_canonical(report)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OperationExplanation {
    pub api_version: String,
    pub kind: String,
    pub registry_identifier: String,
    pub contract_revision: String,
    pub classification_inventory_digest: String,
    pub operations: Vec<OperationExplanationEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OperationExplanationEntry {
    pub resource_identifier: String,
    pub operation_identifier: String,
    pub family: CapabilityFamily,
    pub pattern: ConsultationPattern,
    pub operation_kind: String,
    pub http: HttpOperationBinding,
    pub query: QueryExplanation,
    pub selection: SelectionExplanation,
    pub access_profiles: Vec<AccessProfileExplanation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HttpOperationBinding {
    pub method: HttpMethod,
    pub path: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QueryExplanation {
    pub capabilities: Vec<QueryCapabilityExplanation>,
    pub fixed_order_by: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QueryCapabilityExplanation {
    pub id: QueryCapabilityIdentifier,
    pub availability: CapabilityAvailability,
    pub reason: CapabilityReason,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_request_body_bytes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_page_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_page_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spatial: Option<SpatialQueryExplanation>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum QueryCapabilityIdentifier {
    ExactFilters,
    Unfiltered,
    Pagination,
    ExactLookup,
    PointBbox,
    CallerSorting,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityAvailability {
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityReason {
    DeclaredExactFilters,
    NoDeclaredExactFilters,
    OperationAllowsUnfiltered,
    OperationRequiresDeclaredFilter,
    PaginationConfigured,
    PaginationNotApplicable,
    ExactLookupOperation,
    NotExactLookupOperation,
    PointBboxSearchOperation,
    NotPointBboxSearchOperation,
    FixedOrderOnly,
    NotApplicableToOperation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpatialQueryExplanation {
    pub parameter: String,
    pub crs: String,
    pub predicate: String,
    pub maximum_longitude_span_degrees: u16,
    pub maximum_latitude_span_degrees: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectionExplanation {
    pub access_profile_parameter: String,
    pub fields_parameter: String,
    pub format_profile_parameter: String,
    pub default_access_profile: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessProfileExplanation {
    pub access_profile_identifier: String,
    pub is_default: bool,
    pub access: AccessPolicyExplanation,
    pub processing: ProcessingExplanation,
    pub disclosure: DisclosureExplanation,
    pub transforms: Vec<TransformExplanation>,
    pub wire_formats: Vec<WireFormatCapability>,
    pub cache: CacheExplanation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AccessPolicyExplanation {
    Public,
    Protected {
        scope: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        purpose: Option<PurposeExplanation>,
        #[serde(skip_serializing_if = "Option::is_none")]
        row_binding: Option<RowBindingExplanation>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PurposeExplanation {
    pub claim: String,
    pub allowed_value_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RowBindingExplanation {
    pub authority_source: RowAuthorityExplanation,
    pub source_column: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RowAuthorityExplanation {
    Principal,
    Claim { claim: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProcessingExplanation {
    pub source_columns: Vec<String>,
    pub handling: Handling,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DisclosureExplanation {
    pub profile_identifier: String,
    pub properties: Vec<String>,
    pub handling: Handling,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TransformExplanation {
    PartialString {
        property: String,
        identifier: String,
        reveal: crate::contract::PartialStringReveal,
        characters: u16,
    },
    DatePrecision {
        property: String,
        identifier: String,
        source_type: crate::contract::DateInputType,
        precision: crate::contract::DatePrecision,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CacheExplanation {
    pub kind: CachePosture,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CachePosture {
    PublicRevalidate,
    NoStore,
}

pub fn operation_explanation(
    registry: &CompiledRegistry,
    classification_inventory_digest: &str,
) -> Result<OperationExplanation, IdentificationError> {
    require_inventory_digest(registry, classification_inventory_digest)?;
    let mut operations = registry
        .resources
        .iter()
        .flat_map(|resource| {
            resource
                .operations
                .iter()
                .map(|operation| {
                    let mut access_profiles = operation
                        .access_profiles
                        .iter()
                        .map(|access_profile| AccessProfileExplanation {
                            access_profile_identifier: access_profile.id.clone(),
                            is_default: access_profile.id == operation.default_access_profile,
                            access: access_policy_explanation(&access_profile.access),
                            processing: ProcessingExplanation {
                                source_columns: processed_columns(operation, access_profile),
                                handling: access_profile.processing_handling,
                            },
                            disclosure: DisclosureExplanation {
                                profile_identifier: access_profile.disclosure_profile.clone(),
                                properties: sorted_unique(
                                    access_profile.selectable_properties.iter().cloned(),
                                ),
                                handling: access_profile.disclosure_handling,
                            },
                            transforms: transform_explanations(resource, access_profile),
                            wire_formats: response_format_capabilities(resource, access_profile),
                            cache: CacheExplanation {
                                kind: cache_posture(registry, resource, access_profile),
                            },
                        })
                        .collect::<Vec<_>>();
                    access_profiles.sort_by(|left, right| {
                        left.access_profile_identifier
                            .cmp(&right.access_profile_identifier)
                    });
                    let (method, path) = operation_http_binding(resource, operation);
                    OperationExplanationEntry {
                        resource_identifier: resource.id.clone(),
                        operation_identifier: operation.identifier.clone(),
                        family: operation.family,
                        pattern: operation.pattern,
                        operation_kind: operation_kind(&operation.kind),
                        http: HttpOperationBinding { method, path },
                        query: query_explanation(operation),
                        selection: SelectionExplanation {
                            access_profile_parameter: "accessProfile".into(),
                            fields_parameter: "fields".into(),
                            format_profile_parameter: "formatProfile".into(),
                            default_access_profile: operation.default_access_profile.clone(),
                        },
                        access_profiles,
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    operations.sort_by(|left, right| {
        left.resource_identifier
            .cmp(&right.resource_identifier)
            .then(left.operation_identifier.cmp(&right.operation_identifier))
    });
    Ok(OperationExplanation {
        api_version: "relay.registrystack.org/operation-explanation/v1".into(),
        kind: "OperationExplanation".into(),
        registry_identifier: registry.registry_identifier.clone(),
        contract_revision: registry.contract_revision.clone(),
        classification_inventory_digest: classification_inventory_digest.into(),
        operations,
    })
}

fn cache_posture(
    registry: &CompiledRegistry,
    resource: &CompiledResource,
    access_profile: &CompiledAccessProfile,
) -> CachePosture {
    let snapshot_source = registry
        .sources
        .iter()
        .any(|source| source.id == resource.source && source.profile == SourceProfile::Snapshot);
    if matches!(access_profile.access, CompiledAccess::Public)
        && access_profile.processing_handling == Handling::Public
        && snapshot_source
    {
        CachePosture::PublicRevalidate
    } else {
        CachePosture::NoStore
    }
}

pub fn render_operation_explanation(
    report: &OperationExplanation,
) -> Result<Vec<u8>, IdentificationError> {
    render_canonical(report)
}

/// Render a compact, deterministic operator view without re-deriving any
/// contract semantics in the command-line adapter.
#[must_use]
pub fn render_operation_explanation_text(report: &OperationExplanation) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    let _ = writeln!(output, "Registry: {}", report.registry_identifier);
    let _ = writeln!(output, "Contract revision: {}", report.contract_revision);
    let mut current_resource = None;
    for operation in &report.operations {
        if current_resource != Some(operation.resource_identifier.as_str()) {
            current_resource = Some(operation.resource_identifier.as_str());
            let _ = writeln!(output, "\nResource: {}", operation.resource_identifier);
        }
        let _ = writeln!(
            output,
            "\n  Operation: {}  {} {}  consultation/{}",
            operation.operation_identifier,
            http_method(operation.http.method),
            operation.http.path,
            consultation_pattern_name(operation.pattern),
        );
        let _ = writeln!(
            output,
            "    selection: access-profile={}; fields={}; format-profile={}",
            operation.selection.access_profile_parameter,
            operation.selection.fields_parameter,
            operation.selection.format_profile_parameter,
        );
        let _ = writeln!(
            output,
            "    default access profile: {}",
            operation.selection.default_access_profile
        );
        let _ = writeln!(
            output,
            "    fixed order: {}",
            comma_list(&operation.query.fixed_order_by)
        );
        let _ = writeln!(output, "    query capabilities:");
        for capability in &operation.query.capabilities {
            let _ = writeln!(
                output,
                "      {}: {} ({}){}",
                query_capability_name(capability.id),
                availability_name(capability.availability),
                capability_reason_name(capability.reason),
                if capability.required {
                    "; required"
                } else {
                    ""
                },
            );
            if !capability.parameters.is_empty() {
                let _ = writeln!(
                    output,
                    "        parameters: {}",
                    comma_list(&capability.parameters)
                );
            }
            if let Some(maximum) = capability.maximum_request_body_bytes {
                let _ = writeln!(output, "        maximum request bytes: {maximum}");
            }
            if let (Some(default), Some(maximum)) =
                (capability.default_page_size, capability.maximum_page_size)
            {
                let _ = writeln!(
                    output,
                    "        page size: default={default}; maximum={maximum}"
                );
            }
            if let Some(spatial) = &capability.spatial {
                let _ = writeln!(
                    output,
                    "        spatial: parameter={}; crs={}; predicate={}; max-longitude-span={}; max-latitude-span={}",
                    spatial.parameter,
                    spatial.crs,
                    spatial.predicate,
                    spatial.maximum_longitude_span_degrees,
                    spatial.maximum_latitude_span_degrees,
                );
            }
        }
        for access_profile in &operation.access_profiles {
            let _ = writeln!(
                output,
                "    access profile: {}{}",
                access_profile.access_profile_identifier,
                if access_profile.is_default {
                    " (default)"
                } else {
                    ""
                }
            );
            match &access_profile.access {
                AccessPolicyExplanation::Public => {
                    let _ = writeln!(output, "      access: public");
                }
                AccessPolicyExplanation::Protected {
                    scope,
                    purpose,
                    row_binding,
                } => {
                    let _ = writeln!(output, "      access: protected; scope={scope}");
                    if let Some(purpose) = purpose {
                        let _ = writeln!(
                            output,
                            "      purpose: claim={}; allowed-value-count={}",
                            purpose.claim, purpose.allowed_value_count
                        );
                    }
                    if let Some(row_binding) = row_binding {
                        let authority = match &row_binding.authority_source {
                            RowAuthorityExplanation::Principal => "principal".to_owned(),
                            RowAuthorityExplanation::Claim { claim } => {
                                format!("claim:{claim}")
                            }
                        };
                        let _ = writeln!(
                            output,
                            "      row binding: authority={authority}; source-column={}",
                            row_binding.source_column
                        );
                    }
                }
            }
            let _ = writeln!(
                output,
                "      processing: {}; columns={}",
                handling_name(access_profile.processing.handling),
                comma_list(&access_profile.processing.source_columns),
            );
            let _ = writeln!(
                output,
                "      disclosure: {}; profile={}; properties={}",
                handling_name(access_profile.disclosure.handling),
                access_profile.disclosure.profile_identifier,
                comma_list(&access_profile.disclosure.properties),
            );
            if access_profile.transforms.is_empty() {
                let _ = writeln!(output, "      transforms: none");
            } else {
                let _ = writeln!(output, "      transforms:");
                for transform in &access_profile.transforms {
                    match transform {
                        TransformExplanation::PartialString {
                            property,
                            identifier,
                            reveal,
                            characters,
                        } => {
                            let reveal = match reveal {
                                crate::contract::PartialStringReveal::Prefix => "prefix",
                                crate::contract::PartialStringReveal::Suffix => "suffix",
                            };
                            let _ = writeln!(
                                output,
                                "        {property}: partial-string; id={identifier}; reveal={reveal}; characters={characters}"
                            );
                        }
                        TransformExplanation::DatePrecision {
                            property,
                            identifier,
                            source_type,
                            precision,
                        } => {
                            let source_type = match source_type {
                                crate::contract::DateInputType::Date => "date",
                                crate::contract::DateInputType::DateTime => "date-time",
                            };
                            let precision = match precision {
                                crate::contract::DatePrecision::Year => "year",
                                crate::contract::DatePrecision::YearMonth => "year-month",
                            };
                            let _ = writeln!(
                                output,
                                "        {property}: date-precision; id={identifier}; source-type={source_type}; precision={precision}"
                            );
                        }
                    }
                }
            }
            let _ = writeln!(output, "      wire formats:");
            for format in &access_profile.wire_formats {
                let profiles = format
                    .format_profiles
                    .iter()
                    .map(|profile| format_profile_name(profile.id))
                    .collect::<Vec<_>>();
                let profile_suffix = if profiles.is_empty() {
                    String::new()
                } else {
                    format!("; format-profiles={}", profiles.join(", "))
                };
                let _ = writeln!(
                    output,
                    "        {}: {}{}",
                    wire_format_name(format.id),
                    format.media_type,
                    profile_suffix
                );
            }
            let _ = writeln!(
                output,
                "      cache: {}",
                match access_profile.cache.kind {
                    CachePosture::PublicRevalidate => "public-revalidate",
                    CachePosture::NoStore => "no-store",
                }
            );
        }
    }
    output
}

fn operation_http_binding(
    resource: &CompiledResource,
    operation: &CompiledOperation,
) -> (HttpMethod, String) {
    match &operation.kind {
        OperationKind::List => (
            HttpMethod::Get,
            format!("/v2/resources/{}/records", resource.id),
        ),
        OperationKind::Read => (
            HttpMethod::Get,
            format!("/v2/resources/{}/records/{{recordIdentifier}}", resource.id),
        ),
        OperationKind::Lookup { name } => (
            HttpMethod::Post,
            format!("/v2/resources/{}/lookups/{name}", resource.id),
        ),
        OperationKind::Search { name } => (
            HttpMethod::Get,
            format!("/v2/resources/{}/searches/{name}", resource.id),
        ),
    }
}

fn query_explanation(operation: &CompiledOperation) -> QueryExplanation {
    let mut filters = operation
        .query
        .filters
        .iter()
        .map(|filter| filter.parameter.clone())
        .collect::<Vec<_>>();
    filters.sort();
    let exact_filters_available = !filters.is_empty();
    let unfiltered_applicable = matches!(operation.kind, OperationKind::List);
    let pagination = operation.query.pagination.as_ref();
    let lookup = matches!(operation.kind, OperationKind::Lookup { .. });
    let mut selectors = operation
        .query
        .selectors
        .iter()
        .map(|selector| selector.name.clone())
        .collect::<Vec<_>>();
    selectors.sort();
    let spatial = operation
        .query
        .spatial_bbox
        .as_ref()
        .map(|bbox| SpatialQueryExplanation {
            parameter: "bbox".into(),
            crs: CRS84_URI.into(),
            predicate: POINT_BBOX_PREDICATE.into(),
            maximum_longitude_span_degrees: bbox.maximum_longitude_span_degrees,
            maximum_latitude_span_degrees: bbox.maximum_latitude_span_degrees,
        });
    let capabilities = vec![
        QueryCapabilityExplanation {
            id: QueryCapabilityIdentifier::ExactFilters,
            availability: available(exact_filters_available),
            reason: if exact_filters_available {
                CapabilityReason::DeclaredExactFilters
            } else {
                CapabilityReason::NoDeclaredExactFilters
            },
            required: exact_filters_available && !operation.query.allow_unfiltered,
            parameters: filters,
            maximum_request_body_bytes: None,
            default_page_size: None,
            maximum_page_size: None,
            spatial: None,
        },
        QueryCapabilityExplanation {
            id: QueryCapabilityIdentifier::Unfiltered,
            availability: available(unfiltered_applicable && operation.query.allow_unfiltered),
            reason: if !unfiltered_applicable {
                CapabilityReason::NotApplicableToOperation
            } else if operation.query.allow_unfiltered {
                CapabilityReason::OperationAllowsUnfiltered
            } else {
                CapabilityReason::OperationRequiresDeclaredFilter
            },
            required: false,
            parameters: Vec::new(),
            maximum_request_body_bytes: None,
            default_page_size: None,
            maximum_page_size: None,
            spatial: None,
        },
        QueryCapabilityExplanation {
            id: QueryCapabilityIdentifier::Pagination,
            availability: available(pagination.is_some()),
            reason: if pagination.is_some() {
                CapabilityReason::PaginationConfigured
            } else {
                CapabilityReason::PaginationNotApplicable
            },
            required: false,
            parameters: pagination
                .map(|_| vec!["pageSize".into(), "cursor".into()])
                .unwrap_or_default(),
            maximum_request_body_bytes: None,
            default_page_size: pagination.map(|value| value.default_page_size),
            maximum_page_size: pagination.map(|value| value.maximum_page_size),
            spatial: None,
        },
        QueryCapabilityExplanation {
            id: QueryCapabilityIdentifier::ExactLookup,
            availability: available(lookup),
            reason: if lookup {
                CapabilityReason::ExactLookupOperation
            } else {
                CapabilityReason::NotExactLookupOperation
            },
            required: lookup,
            parameters: selectors,
            maximum_request_body_bytes: operation.query.maximum_request_body_bytes,
            default_page_size: None,
            maximum_page_size: None,
            spatial: None,
        },
        QueryCapabilityExplanation {
            id: QueryCapabilityIdentifier::PointBbox,
            availability: available(spatial.is_some()),
            reason: if spatial.is_some() {
                CapabilityReason::PointBboxSearchOperation
            } else {
                CapabilityReason::NotPointBboxSearchOperation
            },
            required: spatial.is_some(),
            parameters: spatial
                .as_ref()
                .map(|_| vec!["bbox".into()])
                .unwrap_or_default(),
            maximum_request_body_bytes: None,
            default_page_size: None,
            maximum_page_size: None,
            spatial,
        },
        QueryCapabilityExplanation {
            id: QueryCapabilityIdentifier::CallerSorting,
            availability: CapabilityAvailability::Unavailable,
            reason: CapabilityReason::FixedOrderOnly,
            required: false,
            parameters: Vec::new(),
            maximum_request_body_bytes: None,
            default_page_size: None,
            maximum_page_size: None,
            spatial: None,
        },
    ];
    QueryExplanation {
        capabilities,
        fixed_order_by: operation.query.order_by.clone(),
    }
}

fn available(value: bool) -> CapabilityAvailability {
    if value {
        CapabilityAvailability::Available
    } else {
        CapabilityAvailability::Unavailable
    }
}

fn access_policy_explanation(access: &CompiledAccess) -> AccessPolicyExplanation {
    match access {
        CompiledAccess::Public => AccessPolicyExplanation::Public,
        CompiledAccess::Protected {
            scope,
            purpose,
            row_binding,
        } => AccessPolicyExplanation::Protected {
            scope: scope.clone(),
            purpose: purpose.as_ref().map(|purpose| PurposeExplanation {
                claim: purpose.claim.clone(),
                allowed_value_count: purpose.allowed.len(),
            }),
            row_binding: row_binding.as_ref().map(|binding| RowBindingExplanation {
                authority_source: match &binding.source {
                    RowAuthoritySource::Principal => RowAuthorityExplanation::Principal,
                    RowAuthoritySource::Claim(claim) => RowAuthorityExplanation::Claim {
                        claim: claim.clone(),
                    },
                },
                source_column: binding.source_column.clone(),
            }),
        },
    }
}

fn transform_explanations(
    resource: &CompiledResource,
    access_profile: &CompiledAccessProfile,
) -> Vec<TransformExplanation> {
    let selectable = access_profile
        .selectable_properties
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut transforms = resource
        .properties
        .iter()
        .filter(|property| selectable.contains(property.name.as_str()))
        .filter_map(|property| {
            property
                .transform
                .as_ref()
                .map(|transform| match transform {
                    CompiledTransform::PartialString {
                        identifier,
                        reveal,
                        characters,
                    } => TransformExplanation::PartialString {
                        property: property.name.clone(),
                        identifier: identifier.clone(),
                        reveal: *reveal,
                        characters: *characters,
                    },
                    CompiledTransform::DatePrecision {
                        identifier,
                        source_type,
                        precision,
                    } => TransformExplanation::DatePrecision {
                        property: property.name.clone(),
                        identifier: identifier.clone(),
                        source_type: *source_type,
                        precision: *precision,
                    },
                })
        })
        .collect::<Vec<_>>();
    transforms.sort_by(|left, right| transform_property(left).cmp(transform_property(right)));
    transforms
}

fn transform_property(transform: &TransformExplanation) -> &str {
    match transform {
        TransformExplanation::PartialString { property, .. }
        | TransformExplanation::DatePrecision { property, .. } => property,
    }
}

fn http_method(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
    }
}

fn consultation_pattern_name(pattern: ConsultationPattern) -> &'static str {
    match pattern {
        ConsultationPattern::List => "list",
        ConsultationPattern::Retrieve => "retrieve",
        ConsultationPattern::Search => "search",
    }
}

fn query_capability_name(capability: QueryCapabilityIdentifier) -> &'static str {
    match capability {
        QueryCapabilityIdentifier::ExactFilters => "exact-filters",
        QueryCapabilityIdentifier::Unfiltered => "unfiltered",
        QueryCapabilityIdentifier::Pagination => "pagination",
        QueryCapabilityIdentifier::ExactLookup => "exact-lookup",
        QueryCapabilityIdentifier::PointBbox => "point-bbox",
        QueryCapabilityIdentifier::CallerSorting => "caller-sorting",
    }
}

fn availability_name(availability: CapabilityAvailability) -> &'static str {
    match availability {
        CapabilityAvailability::Available => "available",
        CapabilityAvailability::Unavailable => "unavailable",
    }
}

fn capability_reason_name(reason: CapabilityReason) -> &'static str {
    match reason {
        CapabilityReason::DeclaredExactFilters => "declared-exact-filters",
        CapabilityReason::NoDeclaredExactFilters => "no-declared-exact-filters",
        CapabilityReason::OperationAllowsUnfiltered => "operation-allows-unfiltered",
        CapabilityReason::OperationRequiresDeclaredFilter => "operation-requires-declared-filter",
        CapabilityReason::PaginationConfigured => "pagination-configured",
        CapabilityReason::PaginationNotApplicable => "pagination-not-applicable",
        CapabilityReason::ExactLookupOperation => "exact-lookup-operation",
        CapabilityReason::NotExactLookupOperation => "not-exact-lookup-operation",
        CapabilityReason::PointBboxSearchOperation => "point-bbox-search-operation",
        CapabilityReason::NotPointBboxSearchOperation => "not-point-bbox-search-operation",
        CapabilityReason::FixedOrderOnly => "fixed-order-only",
        CapabilityReason::NotApplicableToOperation => "not-applicable-to-operation",
    }
}

fn handling_name(handling: Handling) -> &'static str {
    match handling {
        Handling::Public => "public",
        Handling::Internal => "internal",
        Handling::Confidential => "confidential",
        Handling::Restricted => "restricted",
    }
}

fn comma_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values.join(", ")
    }
}

fn wire_format_name(format: WireFormatIdentifier) -> &'static str {
    match format {
        WireFormatIdentifier::Json => "json",
        WireFormatIdentifier::JsonLd => "json-ld",
        WireFormatIdentifier::Geojson => "geojson",
    }
}

fn format_profile_name(profile: FormatProfileIdentifier) -> &'static str {
    match profile {
        FormatProfileIdentifier::Rfc7946 => "rfc7946",
        FormatProfileIdentifier::Jsonfg => "jsonfg",
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContextualReviewFindings {
    pub api_version: String,
    pub kind: String,
    pub registry_identifier: String,
    pub classification_inventory_digest: String,
    pub findings: Vec<ContextualReviewFinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContextualReviewFinding {
    pub code: String,
    pub status: ContextualFindingStatus,
    pub resource: String,
    pub operation: Option<String>,
    pub access_profile: Option<String>,
    pub properties: Vec<String>,
    pub source_columns: Vec<String>,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ContextualFindingStatus {
    ReviewRequired,
}

/// Generate fixed contextual prompts. Findings never grant access, select a
/// access profile, or alter a compiled handling floor.
pub fn contextual_review_findings(
    registry: &CompiledRegistry,
    classification_inventory_digest: &str,
) -> Result<ContextualReviewFindings, IdentificationError> {
    require_inventory_digest(registry, classification_inventory_digest)?;
    let mut findings = Vec::new();
    for resource in &registry.resources {
        let identifying = resource
            .properties
            .iter()
            .filter(|property| is_identifying(&property.classification.privacy))
            .collect::<Vec<_>>();
        let sensitive = resource
            .properties
            .iter()
            .filter(|property| {
                is_sensitive(&property.classification.privacy)
                    || property.classification.handling >= Handling::Confidential
            })
            .collect::<Vec<_>>();
        if identifying
            .iter()
            .any(|left| sensitive.iter().any(|right| left.name != right.name))
        {
            push_finding(
                &mut findings,
                "classification.context.identifying_and_sensitive",
                resource,
                None,
                None,
                identifying
                    .iter()
                    .chain(sensitive.iter())
                    .map(|property| property.name.clone()),
                std::iter::empty(),
                "identifying and sensitive properties coexist in one resource",
            );
        }

        let linkable = resource
            .properties
            .iter()
            .filter(|property| is_potentially_linkable(&property.classification.privacy))
            .collect::<Vec<_>>();
        if linkable.len() > 1 {
            push_finding(
                &mut findings,
                "classification.context.potentially_linkable_combination",
                resource,
                None,
                None,
                linkable.iter().map(|property| property.name.clone()),
                linkable
                    .iter()
                    .map(|property| property.source_column.clone()),
                "multiple properties may become linkable in combination",
            );
        }

        let personal_public = resource
            .properties
            .iter()
            .filter(|property| {
                is_personal(&property.classification.privacy)
                    && is_public_label(&property.classification.institutional)
            })
            .collect::<Vec<_>>();
        if !personal_public.is_empty() {
            push_finding(
                &mut findings,
                "classification.context.personal_institutionally_public",
                resource,
                None,
                None,
                personal_public
                    .iter()
                    .map(|property| property.name.clone()),
                personal_public
                    .iter()
                    .map(|property| property.source_column.clone()),
                "personal properties have public institutional classification and require an explicit publication basis review",
            );
        }

        for property in resource
            .properties
            .iter()
            .filter(|property| property.transform.is_some())
        {
            let source = resource
                .column_accounting
                .iter()
                .find(|column| column.column == property.source_column);
            if source.is_some_and(|column| {
                column.classification.handling > property.classification.handling
            }) {
                push_finding(
                    &mut findings,
                    "classification.context.transform_weaker_than_source",
                    resource,
                    None,
                    None,
                    [property.name.clone()],
                    [property.source_column.clone()],
                    "a transformed property has weaker handling than its source column",
                );
            }
        }

        let mut properties_by_column: BTreeMap<&str, Vec<_>> = BTreeMap::new();
        for property in &resource.properties {
            properties_by_column
                .entry(&property.source_column)
                .or_default()
                .push(property);
        }
        for (column, properties) in properties_by_column {
            let incompatible = properties.iter().enumerate().any(|(index, left)| {
                properties.iter().skip(index + 1).any(|right| {
                    left.classification.privacy != right.classification.privacy
                        || left.classification.institutional != right.classification.institutional
                        || left.classification.handling != right.classification.handling
                })
            });
            if incompatible {
                push_finding(
                    &mut findings,
                    "classification.context.source_column_incompatible_properties",
                    resource,
                    None,
                    None,
                    properties.iter().map(|property| property.name.clone()),
                    [column.to_owned()],
                    "one source column backs properties with incompatible classifications",
                );
            }
        }

        for operation in &resource.operations {
            for access_profile in &operation.access_profiles {
                let restrictive_selectors = operation
                    .query
                    .selectors
                    .iter()
                    .filter(|selector| {
                        column_handling(resource, &selector.source_column)
                            .is_some_and(|handling| handling > access_profile.disclosure_handling)
                    })
                    .collect::<Vec<_>>();
                if !restrictive_selectors.is_empty() {
                    push_finding(
                        &mut findings,
                        "classification.context.selector_more_restrictive_than_disclosure",
                        resource,
                        Some(&operation.identifier),
                        Some(&access_profile.id),
                        access_profile.selectable_properties.iter().cloned(),
                        restrictive_selectors
                            .iter()
                            .map(|selector| selector.source_column.clone()),
                        "one or more selectors are more restrictive than disclosed properties",
                    );
                }
                if matches!(operation.kind, OperationKind::List)
                    && access_profile.disclosure_handling >= Handling::Confidential
                {
                    push_finding(
                        &mut findings,
                        "classification.context.nonpublic_list_disclosure",
                        resource,
                        Some(&operation.identifier),
                        Some(&access_profile.id),
                        access_profile.selectable_properties.iter().cloned(),
                        std::iter::empty(),
                        "confidential or restricted data appears in a list access profile",
                    );
                }
                if matches!(access_profile.access, CompiledAccess::Public) {
                    let disclosed_columns = disclosed_source_columns(resource, access_profile);
                    let hidden_nonpublic = processed_columns(operation, access_profile)
                        .into_iter()
                        .filter(|column| !disclosed_columns.contains(column))
                        .filter(|column| {
                            column_handling(resource, column)
                                .is_some_and(|handling| handling > Handling::Public)
                        })
                        .collect::<Vec<_>>();
                    if !hidden_nonpublic.is_empty() {
                        push_finding(
                            &mut findings,
                            "classification.context.public_processes_hidden_nonpublic",
                            resource,
                            Some(&operation.identifier),
                            Some(&access_profile.id),
                            access_profile.selectable_properties.iter().cloned(),
                            hidden_nonpublic,
                            "a public access profile processes hidden non-public source columns",
                        );
                    }
                }
            }
        }
    }
    findings.sort_by(|left, right| {
        left.resource
            .cmp(&right.resource)
            .then(left.operation.cmp(&right.operation))
            .then(left.access_profile.cmp(&right.access_profile))
            .then(left.code.cmp(&right.code))
            .then(left.properties.cmp(&right.properties))
            .then(left.source_columns.cmp(&right.source_columns))
    });
    Ok(ContextualReviewFindings {
        api_version: "relay.registrystack.org/contextual-review-findings/v1".into(),
        kind: "ContextualReviewFindings".into(),
        registry_identifier: registry.registry_identifier.clone(),
        classification_inventory_digest: classification_inventory_digest.into(),
        findings,
    })
}

pub fn render_contextual_review_findings(
    report: &ContextualReviewFindings,
) -> Result<Vec<u8>, IdentificationError> {
    render_canonical(report)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassificationReviewExpectation {
    pub registry_identifier: String,
    pub classification_inventory_digest: String,
    /// Recomputed from the current contract, observation, and embedded pack.
    pub generated_identification: Option<GeneratedIdentificationBinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewValidation {
    pub diagnostics: Vec<ReviewDiagnostic>,
}

impl ReviewValidation {
    pub fn is_valid(&self) -> bool {
        self.diagnostics.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewDiagnostic {
    pub code: String,
    pub location: String,
    pub message: String,
}

/// Build an explicitly unreviewed starter. It is deterministic and cannot pass
/// [`validate_classification_review`] until a reviewer supplies a real date,
/// rationale, and reviewed status.
pub fn classification_review_starter(
    contract: &RegistryContract,
    classification_inventory_digest: &str,
    report: &IdentificationReport,
) -> Result<ClassificationReviewDocument, IdentificationError> {
    Ok(ClassificationReviewDocument {
        api_version: REVIEW_API_VERSION.into(),
        kind: REVIEW_KIND.into(),
        registry_identifier: contract.registry.registry_identifier.clone(),
        classification_inventory_digest: classification_inventory_digest.into(),
        method: IdentificationMethod::Generated,
        reviewer: contract.registry.authority.identifier.clone(),
        review_date: "pending-review".into(),
        status: ReviewStatus::Suggested,
        rationale_ref: "pending-review".into(),
        generated_identification: Some(GeneratedIdentificationBinding {
            report_ref: REVIEWED_IDENTIFICATION_REPORT_PATH.into(),
            report_digest: identification_report_digest(report)?,
            rule_pack: report.rule_pack.clone(),
        }),
    })
}

pub fn render_classification_review_yaml(
    review: &ClassificationReviewDocument,
) -> Result<Vec<u8>, IdentificationError> {
    serde_norway::to_string(review)
        .map(String::into_bytes)
        .map_err(|_| IdentificationError::ReviewRender)
}

pub fn parse_classification_review_yaml(
    bytes: &[u8],
) -> Result<ClassificationReviewDocument, IdentificationError> {
    if bytes.len() > 64 * 1024 {
        return Err(IdentificationError::ReviewParse);
    }
    serde_norway::from_slice(bytes).map_err(|_| IdentificationError::ReviewParse)
}

/// Validate freshness and method-specific review evidence without trusting an
/// authored report digest. The caller supplies the independently recomputed
/// expected inventory and, for generated reviews, report and pack binding.
pub fn validate_classification_review(
    review: &ClassificationReviewDocument,
    expected: &ClassificationReviewExpectation,
) -> ReviewValidation {
    let mut diagnostics = Vec::new();
    if review.api_version != REVIEW_API_VERSION || review.kind != REVIEW_KIND {
        push_review_diagnostic(
            &mut diagnostics,
            "classification.review_identity_invalid",
            "apiVersion",
            "the classification review document identity is unsupported",
        );
    }
    if review.registry_identifier != expected.registry_identifier {
        push_review_diagnostic(
            &mut diagnostics,
            "classification.review_registry_stale",
            "registryIdentifier",
            "the classification review is bound to another Registry",
        );
    }
    if !valid_sha256(&review.classification_inventory_digest)
        || review.classification_inventory_digest != expected.classification_inventory_digest
    {
        push_review_diagnostic(
            &mut diagnostics,
            "classification.review_inventory_stale",
            "classificationInventoryDigest",
            "the classification review does not bind the current inventory",
        );
    }
    if review.status != ReviewStatus::Reviewed {
        push_review_diagnostic(
            &mut diagnostics,
            "classification.review_unreviewed",
            "status",
            "production classification requires reviewed institutional evidence",
        );
    }
    if !valid_review_text(&review.reviewer) {
        push_review_diagnostic(
            &mut diagnostics,
            "classification.review_reviewer_invalid",
            "reviewer",
            "the reviewer or reviewing authority identifier is invalid",
        );
    }
    if !canonical_review_date(&review.review_date) {
        push_review_diagnostic(
            &mut diagnostics,
            "classification.review_date_invalid",
            "reviewDate",
            "the review date must be a canonical calendar date",
        );
    }
    if !valid_relative_reference(&review.rationale_ref) {
        push_review_diagnostic(
            &mut diagnostics,
            "classification.review_rationale_invalid",
            "rationaleRef",
            "the rationale reference must be a bounded contained relative reference",
        );
    }

    match review.method {
        IdentificationMethod::Generated => {
            let Some(actual) = review.generated_identification.as_ref() else {
                push_review_diagnostic(
                    &mut diagnostics,
                    "classification.review_generated_binding_missing",
                    "generatedIdentification",
                    "a generated review must bind the recomputed report and rule pack",
                );
                return ReviewValidation { diagnostics };
            };
            if !valid_relative_reference(&actual.report_ref)
                || !valid_sha256(&actual.report_digest)
                || !valid_sha256(&actual.rule_pack.digest)
            {
                push_review_diagnostic(
                    &mut diagnostics,
                    "classification.review_generated_binding_invalid",
                    "generatedIdentification",
                    "the generated identification binding is invalid",
                );
            }
            match expected.generated_identification.as_ref() {
                Some(current) if actual != current => push_review_diagnostic(
                    &mut diagnostics,
                    "classification.review_identification_stale",
                    "generatedIdentification",
                    "the classification review does not bind the current identification report and rule pack",
                ),
                None => push_review_diagnostic(
                    &mut diagnostics,
                    "classification.review_identification_unverified",
                    "generatedIdentification",
                    "the generated identification binding was not independently recomputed",
                ),
                Some(_) => {}
            }
        }
        IdentificationMethod::Imported | IdentificationMethod::Manual => {
            if review.generated_identification.is_some() {
                push_review_diagnostic(
                    &mut diagnostics,
                    "classification.review_generated_binding_forbidden",
                    "generatedIdentification",
                    "manual and imported reviews do not carry generated-identification evidence",
                );
            }
        }
    }

    ReviewValidation { diagnostics }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RulePack {
    pack_id: String,
    pack_version: String,
    privacy_candidate_vocabulary: CandidateVocabulary,
    rules: Vec<Rule>,
}

impl RulePack {
    fn reference(&self, digest: &str) -> RulePackBinding {
        RulePackBinding {
            id: self.pack_id.clone(),
            version: self.pack_version.clone(),
            digest: digest.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Rule {
    id: String,
    version: String,
    family: RuleFamily,
    confidence: RuleConfidence,
    when: Vec<RuleCondition>,
    suggestion: RuleSuggestion,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
enum RuleConfidence {
    Weak,
    Strong,
    Exact,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum RuleCondition {
    Any,
    AuthoredRole { value: AuthoredRole },
    CodelistPresent,
    DeclaredType { values: Vec<String> },
    NameEquals { values: Vec<String> },
    NameSuffix { values: Vec<String> },
    NameTokenAny { values: Vec<String> },
    PrimaryKey,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RuleSuggestion {
    role: TechnicalRole,
    privacy: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum AuthoredRole {
    Codelist,
    Filter,
    LifecycleState,
    Order,
    Property,
    RecordedAt,
    RecordIdentifier,
    RevisionIdentifier,
    RowBinding,
    Selector,
}

#[derive(Clone, Debug, Default)]
struct ColumnHints {
    roles: BTreeSet<AuthoredRole>,
    properties: BTreeSet<(String, String)>,
    codelist: bool,
}

fn load_core_pack(bytes: &[u8], expected_digest: &str) -> Result<RulePack, IdentificationError> {
    if bytes.len() > MAXIMUM_PACK_BYTES || sha256(bytes) != expected_digest {
        return Err(IdentificationError::PackDigestMismatch);
    }
    let value = parse_json_strict(bytes).map_err(|_| IdentificationError::PackInvalid)?;
    let pack: RulePack =
        serde_json::from_value(value).map_err(|_| IdentificationError::PackInvalid)?;
    validate_pack(&pack)?;
    Ok(pack)
}

fn validate_pack(pack: &RulePack) -> Result<(), IdentificationError> {
    if pack.pack_id != "registrystack.relay.identification.core"
        || pack.pack_version != "1"
        || pack.privacy_candidate_vocabulary.scheme != "urn:registrystack:relay:privacy-candidate"
        || pack.privacy_candidate_vocabulary.version != "1"
        || pack.rules.is_empty()
        || pack.rules.len() > MAXIMUM_RULES
    {
        return Err(IdentificationError::PackInvalid);
    }
    let mut rule_ids = BTreeSet::new();
    let mut fallback_count = 0;
    for rule in &pack.rules {
        if !valid_pack_identifier(&rule.id)
            || !valid_pack_identifier(&rule.version)
            || rule.when.is_empty()
            || rule.when.len() > MAXIMUM_CONDITIONS_PER_RULE
            || !rule_ids.insert(rule.id.as_str())
            || rule.suggestion.privacy.len() > 8
            || rule
                .suggestion
                .privacy
                .iter()
                .any(|value| !valid_pack_identifier(value))
            || rule
                .when
                .iter()
                .any(|condition| !valid_condition(condition))
        {
            return Err(IdentificationError::PackInvalid);
        }
        if rule.id == "core.column.fallback" {
            fallback_count += 1;
            if rule.when != [RuleCondition::Any]
                || rule.suggestion.role != TechnicalRole::Property
                || rule.confidence != RuleConfidence::Weak
            {
                return Err(IdentificationError::PackInvalid);
            }
        } else if rule.when.contains(&RuleCondition::Any) {
            return Err(IdentificationError::PackInvalid);
        }
    }
    if fallback_count != 1 {
        return Err(IdentificationError::PackInvalid);
    }
    Ok(())
}

fn valid_condition(condition: &RuleCondition) -> bool {
    let values = match condition {
        RuleCondition::DeclaredType { values }
        | RuleCondition::NameEquals { values }
        | RuleCondition::NameSuffix { values }
        | RuleCondition::NameTokenAny { values } => Some(values),
        RuleCondition::Any
        | RuleCondition::AuthoredRole { .. }
        | RuleCondition::CodelistPresent
        | RuleCondition::PrimaryKey => None,
    };
    values.is_none_or(|values| {
        !values.is_empty()
            && values.len() <= 32
            && values.iter().all(|value| {
                !value.is_empty()
                    && value.len() <= 64
                    && value.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'-')
                    })
            })
    })
}

fn valid_pack_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

fn ensure_observation_bounds(observed: &[ObservedSourceSchema]) -> Result<(), IdentificationError> {
    let views = observed
        .iter()
        .map(|schema| schema.views.len())
        .sum::<usize>();
    let columns = observed
        .iter()
        .flat_map(|schema| &schema.views)
        .map(|view| view.columns.len())
        .sum::<usize>();
    if observed.len() > MAXIMUM_SOURCES || views > MAXIMUM_VIEWS || columns > MAXIMUM_COLUMNS {
        Err(IdentificationError::InputTooLarge)
    } else {
        Ok(())
    }
}

fn normalized_observation(observed: &[ObservedSourceSchema]) -> Vec<ObservedSourceSchema> {
    let mut normalized = observed.to_vec();
    for schema in &mut normalized {
        for view in &mut schema.views {
            view.columns
                .sort_by(|left, right| left.name.cmp(&right.name));
        }
        schema
            .views
            .sort_by(|left, right| left.name.cmp(&right.name));
    }
    normalized.sort_by(|left, right| left.source.cmp(&right.source));
    normalized
}

fn authored_hints(contract: &RegistryContract) -> BTreeMap<(String, String, String), ColumnHints> {
    let mut hints = BTreeMap::new();
    for resource in &contract.resources {
        let source = resource.source.source.as_str();
        let view = resource.source.view.as_str();
        add_role(
            &mut hints,
            source,
            view,
            &resource.record_context.record_identifier.source_column,
            AuthoredRole::RecordIdentifier,
        );
        add_role(
            &mut hints,
            source,
            view,
            &resource.record_context.revision_identifier.source_column,
            AuthoredRole::RevisionIdentifier,
        );
        add_role(
            &mut hints,
            source,
            view,
            &resource.record_context.lifecycle_state.source_column,
            AuthoredRole::LifecycleState,
        );
        add_codelist(
            &mut hints,
            source,
            view,
            &resource.record_context.lifecycle_state.source_column,
        );
        add_role(
            &mut hints,
            source,
            view,
            &resource.record_context.recorded_at.source_column,
            AuthoredRole::RecordedAt,
        );

        for (property_name, property) in resource.properties.iter() {
            let entry = column_hint(&mut hints, source, view, &property.source_column);
            entry.roles.insert(AuthoredRole::Property);
            entry
                .properties
                .insert((property_name.into(), property.semantic_term.clone()));
            if property.codelist.is_some() {
                entry.roles.insert(AuthoredRole::Codelist);
                entry.codelist = true;
            }
        }

        if let Some(operation) = &resource.operations.list {
            for filter in &operation.filters {
                if let Some(property) = resource.properties.get(&filter.property) {
                    add_role(
                        &mut hints,
                        source,
                        view,
                        &property.source_column,
                        AuthoredRole::Filter,
                    );
                }
            }
            for property_name in &operation.order_by {
                if let Some(property) = resource.properties.get(property_name) {
                    add_role(
                        &mut hints,
                        source,
                        view,
                        &property.source_column,
                        AuthoredRole::Order,
                    );
                }
            }
            for (_, access_profile) in operation.access_profiles.iter() {
                add_access_roles(&mut hints, source, view, &access_profile.access);
            }
        }
        if let Some(operation) = &resource.operations.read {
            for (_, access_profile) in operation.access_profiles.iter() {
                add_access_roles(&mut hints, source, view, &access_profile.access);
            }
        }
        for lookup in &resource.operations.lookups {
            for (_, selector) in lookup.request_body.selectors.iter() {
                add_role(
                    &mut hints,
                    source,
                    view,
                    &selector.source_column,
                    AuthoredRole::Selector,
                );
                if selector.codelist.is_some() {
                    add_codelist(&mut hints, source, view, &selector.source_column);
                }
            }
            for (_, access_profile) in lookup.access_profiles.iter() {
                add_access_roles(&mut hints, source, view, &access_profile.access);
            }
        }
        for search in &resource.operations.searches {
            for property_name in &search.order_by {
                if let Some(property) = resource.properties.get(property_name) {
                    add_role(
                        &mut hints,
                        source,
                        view,
                        &property.source_column,
                        AuthoredRole::Order,
                    );
                }
            }
            for (_, access_profile) in search.access_profiles.iter() {
                add_access_roles(&mut hints, source, view, &access_profile.access);
            }
        }
    }
    hints
}

fn add_access_roles(
    hints: &mut BTreeMap<(String, String, String), ColumnHints>,
    source: &str,
    view: &str,
    access: &AccessRule,
) {
    let AccessRule::Protected(protected) = access else {
        return;
    };
    let source_column = match protected.authority_row_binding.as_ref() {
        Some(AuthorityRowBinding::Claim(binding)) => Some(binding.source_column.as_str()),
        Some(AuthorityRowBinding::Principal(binding)) => Some(binding.source_column.as_str()),
        None => None,
    };
    if let Some(source_column) = source_column {
        add_role(hints, source, view, source_column, AuthoredRole::RowBinding);
    }
}

fn add_role(
    hints: &mut BTreeMap<(String, String, String), ColumnHints>,
    source: &str,
    view: &str,
    column: &str,
    role: AuthoredRole,
) {
    column_hint(hints, source, view, column).roles.insert(role);
}

fn add_codelist(
    hints: &mut BTreeMap<(String, String, String), ColumnHints>,
    source: &str,
    view: &str,
    column: &str,
) {
    let hint = column_hint(hints, source, view, column);
    hint.roles.insert(AuthoredRole::Codelist);
    hint.codelist = true;
}

fn column_hint<'a>(
    hints: &'a mut BTreeMap<(String, String, String), ColumnHints>,
    source: &str,
    view: &str,
    column: &str,
) -> &'a mut ColumnHints {
    hints
        .entry((source.into(), view.into(), column.into()))
        .or_default()
}

fn identify_column(
    pack: &RulePack,
    rule_pack: &RulePackBinding,
    source: &str,
    view: &str,
    column: &ObservedColumn,
    hint: Option<&ColumnHints>,
) -> IdentificationCandidate {
    let normalized_name = normalize_column_name(&column.name);
    let tokens = normalized_name
        .split('_')
        .filter(|token| !token.is_empty())
        .collect::<BTreeSet<_>>();
    let default_hint = ColumnHints::default();
    let hint = hint.unwrap_or(&default_hint);
    let mut matches = pack
        .rules
        .iter()
        .filter(|rule| {
            rule.when.iter().all(|condition| {
                condition_matches(
                    condition,
                    &normalized_name,
                    &tokens,
                    &column.declared_type,
                    column.primary_key,
                    hint,
                )
            })
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| left.id.cmp(&right.id));

    let property_conflict = hint.properties.len() > 1;
    let (suggested_property, suggested_semantic_term) = if property_conflict {
        (None, None)
    } else if let Some((property, semantic_term)) = hint.properties.iter().next() {
        (Some(property.clone()), Some(semantic_term.clone()))
    } else {
        let property = property_name(&normalized_name);
        (Some(property.clone()), Some(format!("local:{property}")))
    };

    // The generic rule is an actual fallback, not corroborating evidence. It
    // must disappear from the candidate as soon as any authored or schema
    // rule matches, including a weak but more specific rule.
    if matches.iter().any(|rule| rule.id != "core.column.fallback") {
        matches.retain(|rule| rule.id != "core.column.fallback");
    }
    let considered = &matches;
    let maximum_confidence = considered
        .iter()
        .map(|rule| rule.confidence)
        .max()
        .unwrap_or(RuleConfidence::Weak);
    let top = considered
        .iter()
        .copied()
        .filter(|rule| rule.confidence == maximum_confidence)
        .collect::<Vec<_>>();
    let has_specific_role = top.iter().any(|rule| {
        !matches!(
            rule.suggestion.role,
            TechnicalRole::Codelist | TechnicalRole::Identifier | TechnicalRole::Property
        )
    });
    let top_roles = top
        .iter()
        .filter_map(|rule| {
            let role = rule.suggestion.role;
            (!has_specific_role
                || !matches!(
                    role,
                    TechnicalRole::Codelist | TechnicalRole::Identifier | TechnicalRole::Property
                ))
            .then_some(role)
        })
        .collect::<BTreeSet<_>>();
    let role_conflict = top_roles.len() > 1;
    let conflict = property_conflict || role_conflict;
    let suggested_role = if conflict {
        None
    } else {
        top_roles
            .iter()
            .next()
            .copied()
            .or(Some(TechnicalRole::Property))
    };
    let suggested_privacy = matches
        .iter()
        .flat_map(|rule| rule.suggestion.privacy.iter())
        .map(|term| CandidateTerm {
            scheme: pack.privacy_candidate_vocabulary.scheme.clone(),
            version: pack.privacy_candidate_vocabulary.version.clone(),
            term: term.clone(),
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let matched_rules = matches
        .iter()
        .map(|rule| MatchedRule {
            id: rule.id.clone(),
            version: rule.version.clone(),
            family: rule.family,
        })
        .collect();
    let confidence = if conflict {
        CategoricalConfidence::Conflict
    } else {
        match maximum_confidence {
            RuleConfidence::Exact => CategoricalConfidence::Exact,
            RuleConfidence::Strong => CategoricalConfidence::Strong,
            RuleConfidence::Weak => CategoricalConfidence::Weak,
        }
    };

    IdentificationCandidate {
        source: source.into(),
        view: view.into(),
        source_column: column.name.clone(),
        suggested_property,
        suggested_semantic_term,
        suggested_role,
        suggested_privacy,
        matched_rules,
        rule_pack: rule_pack.clone(),
        confidence,
        status: if conflict {
            IdentificationStatus::Uncertain
        } else {
            IdentificationStatus::Suggested
        },
    }
}

fn condition_matches(
    condition: &RuleCondition,
    normalized_name: &str,
    tokens: &BTreeSet<&str>,
    declared_type: &str,
    primary_key: bool,
    hint: &ColumnHints,
) -> bool {
    match condition {
        RuleCondition::Any => true,
        RuleCondition::AuthoredRole { value } => hint.roles.contains(value),
        RuleCondition::CodelistPresent => hint.codelist,
        RuleCondition::DeclaredType { values } => {
            let normalized_type = declared_type.trim().to_ascii_lowercase();
            values.iter().any(|value| value == &normalized_type)
        }
        RuleCondition::NameEquals { values } => values.iter().any(|value| value == normalized_name),
        RuleCondition::NameSuffix { values } => {
            values.iter().any(|value| normalized_name.ends_with(value))
        }
        RuleCondition::NameTokenAny { values } => {
            values.iter().any(|value| tokens.contains(value.as_str()))
        }
        RuleCondition::PrimaryKey => primary_key,
    }
}

fn normalize_column_name(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut previous_was_lower_or_digit = false;
    let mut previous_was_separator = true;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase()
                && previous_was_lower_or_digit
                && !previous_was_separator
            {
                normalized.push('_');
            }
            normalized.push(character.to_ascii_lowercase());
            previous_was_lower_or_digit =
                character.is_ascii_lowercase() || character.is_ascii_digit();
            previous_was_separator = false;
        } else if !previous_was_separator && !normalized.is_empty() {
            normalized.push('_');
            previous_was_lower_or_digit = false;
            previous_was_separator = true;
        }
    }
    while normalized.ends_with('_') {
        normalized.pop();
    }
    if normalized.is_empty() {
        "column".into()
    } else {
        normalized
    }
}

fn property_name(normalized: &str) -> String {
    let mut tokens = normalized.split('_').filter(|token| !token.is_empty());
    let mut property = tokens.next().unwrap_or("column").to_owned();
    for token in tokens {
        let mut characters = token.chars();
        if let Some(first) = characters.next() {
            property.push(first.to_ascii_uppercase());
            property.extend(characters);
        }
    }
    property
}

fn render_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, IdentificationError> {
    let value = serde_json::to_value(value).map_err(|_| IdentificationError::Canonicalization)?;
    canonicalize_json(&value).map_err(|_| IdentificationError::Canonicalization)
}

fn require_inventory_digest(
    registry: &CompiledRegistry,
    value: &str,
) -> Result<(), IdentificationError> {
    let current = crate::compiler::classification_inventory_digest(registry)
        .map_err(|_| IdentificationError::Canonicalization)?;
    if valid_sha256(value) && value == current {
        Ok(())
    } else {
        Err(IdentificationError::InventoryDigestInvalid)
    }
}

fn operation_kind(kind: &OperationKind) -> String {
    match kind {
        OperationKind::List => "list".into(),
        OperationKind::Read => "read".into(),
        OperationKind::Lookup { name } => format!("lookup:{name}"),
        OperationKind::Search { name } => format!("search:{name}"),
    }
}

fn processed_columns(
    operation: &CompiledOperation,
    access_profile: &CompiledAccessProfile,
) -> Vec<String> {
    let mut columns = access_profile
        .projected_columns
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    columns.extend(
        operation
            .query
            .filters
            .iter()
            .map(|filter| filter.source_column.clone()),
    );
    if let Some(spatial) = &operation.query.spatial_bbox {
        columns.insert(spatial.longitude_column.clone());
        columns.insert(spatial.latitude_column.clone());
    }
    columns.extend(operation.query.order_by.iter().cloned());
    columns.extend(
        operation
            .query
            .selectors
            .iter()
            .map(|selector| selector.source_column.clone()),
    );
    if let CompiledAccess::Protected {
        row_binding: Some(binding),
        ..
    } = &access_profile.access
    {
        columns.insert(binding.source_column.clone());
    }
    columns.into_iter().collect()
}

fn disclosed_source_columns(
    resource: &CompiledResource,
    access_profile: &CompiledAccessProfile,
) -> BTreeSet<String> {
    let mut columns = [
        &resource.record_context.record_identifier_column,
        &resource.record_context.revision_identifier_column,
        &resource.record_context.lifecycle_state_column,
        &resource.record_context.recorded_at_column,
    ]
    .into_iter()
    .cloned()
    .collect::<BTreeSet<_>>();
    for name in &access_profile.selectable_properties {
        if let Some(property) = resource
            .properties
            .iter()
            .find(|property| property.name == *name && property.transform.is_none())
        {
            columns.insert(property.source_column.clone());
        }
        if let Some(geometry) = resource
            .primary_geometry
            .as_ref()
            .filter(|geometry| geometry.name == *name)
        {
            columns.insert(geometry.longitude_column.clone());
            columns.insert(geometry.latitude_column.clone());
        }
    }
    columns
}

fn column_handling(resource: &CompiledResource, column: &str) -> Option<Handling> {
    resource
        .column_accounting
        .iter()
        .find(|account| account.column == column)
        .map(|account| account.classification.handling)
}

fn sorted_unique(values: impl Iterator<Item = String>) -> Vec<String> {
    values.collect::<BTreeSet<_>>().into_iter().collect()
}

#[allow(clippy::too_many_arguments)]
fn push_finding<I, J>(
    findings: &mut Vec<ContextualReviewFinding>,
    code: &str,
    resource: &CompiledResource,
    operation: Option<&str>,
    access_profile: Option<&str>,
    properties: I,
    source_columns: J,
    message: &str,
) where
    I: IntoIterator<Item = String>,
    J: IntoIterator<Item = String>,
{
    findings.push(ContextualReviewFinding {
        code: code.into(),
        status: ContextualFindingStatus::ReviewRequired,
        resource: resource.id.clone(),
        operation: operation.map(str::to_owned),
        access_profile: access_profile.map(str::to_owned),
        properties: sorted_unique(properties.into_iter()),
        source_columns: sorted_unique(source_columns.into_iter()),
        message: message.into(),
    });
}

fn classification_tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn is_identifying(value: &str) -> bool {
    classification_tokens(value)
        .iter()
        .any(|token| token.starts_with("identif"))
}

fn is_sensitive(value: &str) -> bool {
    classification_tokens(value)
        .iter()
        .any(|token| token.starts_with("sensitive"))
}

fn is_personal(value: &str) -> bool {
    classification_tokens(value).iter().any(|token| {
        token.starts_with("personal") || token.starts_with("identif") || token == "contact"
    })
}

fn is_potentially_linkable(value: &str) -> bool {
    classification_tokens(value).iter().any(|token| {
        token.starts_with("quasi")
            || token.starts_with("link")
            || token.starts_with("indirect")
            || token.starts_with("potential")
    })
}

fn is_public_label(value: &str) -> bool {
    classification_tokens(value).contains("public")
}

fn digest_serializable<T: Serialize>(value: &T) -> Result<String, IdentificationError> {
    let value = serde_json::to_value(value).map_err(|_| IdentificationError::Canonicalization)?;
    let bytes = canonicalize_json(&value).map_err(|_| IdentificationError::Canonicalization)?;
    Ok(sha256(&bytes))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn canonical_review_date(value: &str) -> bool {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .ok()
        .is_some_and(|date| date.format("%Y-%m-%d").to_string() == value)
}

fn valid_review_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAXIMUM_REVIEW_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_relative_reference(value: &str) -> bool {
    valid_review_text(value)
        && !Path::new(value).is_absolute()
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn push_review_diagnostic(
    diagnostics: &mut Vec<ReviewDiagnostic>,
    code: &str,
    location: &str,
    message: &str,
) {
    diagnostics.push(ReviewDiagnostic {
        code: code.into(),
        location: location.into(),
        message: message.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{
        classification_inventory_digest, compile_contract_with_governed_files,
        tests as compiler_tests,
    };
    use crate::model::{CompileProfile, CompiledPurpose, CompiledRowBinding};

    #[test]
    fn pack_tampering_is_refused_before_parsing() {
        let mut tampered = CORE_PACK_BYTES.to_vec();
        tampered[0] ^= 1;
        assert_eq!(
            load_core_pack(&tampered, CORE_PACK_DIGEST),
            Err(IdentificationError::PackDigestMismatch)
        );
    }

    #[test]
    fn a_mismatched_pack_pin_is_refused() {
        assert_eq!(
            load_core_pack(CORE_PACK_BYTES, &format!("sha256:{}", "0".repeat(64))),
            Err(IdentificationError::PackDigestMismatch)
        );
    }

    #[test]
    fn public_snapshot_source_is_explained_as_public_revalidation() {
        let mut registry = public_registry(SourceProfile::Snapshot);
        let source_metadata_canary = "SOURCE_METADATA_CANARY_4ee4ba";
        registry.sources[0].expected_schema_fingerprint = source_metadata_canary.into();
        let digest = classification_inventory_digest(&registry).expect("inventory digest");

        let explanation = operation_explanation(&registry, &digest).expect("explanation");
        let access_profile = &explanation.operations[0].access_profiles[0];
        assert_eq!(access_profile.cache.kind, CachePosture::PublicRevalidate);
        let rendered = render_operation_explanation(&explanation).expect("canonical explanation");
        assert!(!String::from_utf8(rendered)
            .expect("UTF-8 JSON")
            .contains(source_metadata_canary));
    }

    #[test]
    fn public_live_source_is_explained_as_no_store() {
        let registry = public_registry(SourceProfile::LiveReadOnly);
        let digest = classification_inventory_digest(&registry).expect("inventory digest");

        let explanation = operation_explanation(&registry, &digest).expect("explanation");
        let access_profile = &explanation.operations[0].access_profiles[0];
        assert_eq!(access_profile.cache.kind, CachePosture::NoStore);
        assert!(matches!(
            access_profile.access,
            AccessPolicyExplanation::Public
        ));
    }

    #[test]
    fn operation_explanation_is_canonical_value_free_and_complete_for_spatial_search() {
        let contract = compiler_tests::spatial_contract(true);
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::spatial_observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files_for(&contract),
        )
        .expect("spatial contract compiles");
        registry.resources[0].properties[0].transform = Some(CompiledTransform::PartialString {
            identifier: "partial-string:suffix:2".into(),
            reveal: crate::contract::PartialStringReveal::Suffix,
            characters: 2,
        });
        let canary = "PURPOSE_VALUE_CANARY_58a4c9";
        registry.resources[0].operations[0].access_profiles[0].access = CompiledAccess::Protected {
            scope: "registry:records:search".into(),
            purpose: Some(CompiledPurpose {
                claim: "purpose".into(),
                allowed: vec![canary.into()],
            }),
            row_binding: Some(CompiledRowBinding {
                source: RowAuthoritySource::Claim("authority".into()),
                source_column: "name".into(),
            }),
        };
        let mut hidden_geometry = registry.resources[0].operations[0].access_profiles[0].clone();
        hidden_geometry.id = "hidden-geometry".into();
        hidden_geometry
            .selectable_properties
            .retain(|property| property != "location");
        hidden_geometry
            .projected_columns
            .retain(|column| !matches!(column.as_str(), "longitude" | "latitude"));
        registry.resources[0].operations[0]
            .access_profiles
            .push(hidden_geometry);
        let digest = classification_inventory_digest(&registry).expect("inventory digest");
        let explanation = operation_explanation(&registry, &digest).expect("explanation");
        assert_eq!(
            explanation.api_version,
            "relay.registrystack.org/operation-explanation/v1"
        );
        assert_eq!(explanation.kind, "OperationExplanation");
        let operation = &explanation.operations[0];
        assert_eq!(operation.operation_kind, "search:within-bbox");
        assert_eq!(
            operation.http.path,
            "/v2/resources/record/searches/within-bbox"
        );
        let bbox = operation
            .query
            .capabilities
            .iter()
            .find(|capability| capability.id == QueryCapabilityIdentifier::PointBbox)
            .expect("bbox capability");
        assert_eq!(bbox.availability, CapabilityAvailability::Available);
        assert_eq!(bbox.reason, CapabilityReason::PointBboxSearchOperation);
        assert!(bbox.required);
        let caller_sorting = operation
            .query
            .capabilities
            .iter()
            .find(|capability| capability.id == QueryCapabilityIdentifier::CallerSorting)
            .expect("sorting capability");
        assert_eq!(
            caller_sorting.availability,
            CapabilityAvailability::Unavailable
        );
        assert_eq!(caller_sorting.reason, CapabilityReason::FixedOrderOnly);

        let access_profile = operation
            .access_profiles
            .iter()
            .find(|profile| profile.access_profile_identifier == "public")
            .expect("public access profile");
        assert_eq!(access_profile.wire_formats.len(), 3);
        assert!(matches!(
            &access_profile.access,
            AccessPolicyExplanation::Protected {
                purpose: Some(PurposeExplanation {
                    allowed_value_count: 1,
                    ..
                }),
                row_binding: Some(_),
                ..
            }
        ));
        assert!(matches!(
            access_profile.transforms.as_slice(),
            [TransformExplanation::PartialString {
                property,
                characters: 2,
                ..
            }] if property == "name"
        ));
        let hidden_geometry = operation
            .access_profiles
            .iter()
            .find(|profile| profile.access_profile_identifier == "hidden-geometry")
            .expect("hidden-geometry access profile");
        assert!(hidden_geometry
            .processing
            .source_columns
            .contains(&"longitude".into()));
        assert!(hidden_geometry
            .processing
            .source_columns
            .contains(&"latitude".into()));
        assert_eq!(hidden_geometry.wire_formats.len(), 2);
        assert!(hidden_geometry
            .wire_formats
            .iter()
            .all(|format| format.id != WireFormatIdentifier::Geojson));

        let first = render_operation_explanation(&explanation).expect("canonical bytes");
        let second = render_operation_explanation(&explanation).expect("canonical bytes again");
        assert_eq!(first, second);
        let encoded = String::from_utf8(first).expect("UTF-8 JSON");
        assert!(!encoded.contains(canary));
        assert!(encoded.contains("allowedValueCount"));
        let mut unknown = serde_json::to_value(&explanation).expect("explanation serializes");
        unknown["operations"][0]["selection"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<OperationExplanation>(unknown).is_err());
        let text = render_operation_explanation_text(&explanation);
        assert!(text.contains("Resource: record"));
        assert!(text.contains("Operation: record.search.within-bbox"));
        assert!(text.contains("max-longitude-span=10"));
        assert!(text.contains("format-profiles=rfc7946, jsonfg"));
        assert!(!text.contains(canary));
    }

    fn public_registry(profile: SourceProfile) -> CompiledRegistry {
        let contract = compiler_tests::spatial_contract(false);
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::spatial_observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files_for(&contract),
        )
        .expect("public contract compiles");
        registry.sources[0].profile = profile;
        registry
    }
}
