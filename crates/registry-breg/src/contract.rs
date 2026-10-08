// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use jsonschema::{Draft, JSONSchema};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_config::contains_environment_expression;
pub use registry_platform_hooks::{HookHandlerSource, HookPhase};
use registry_platform_yaml::{
    ApiVersion, BoundedU32, BoundedU64, DataLiteral, Digest, EnvelopeRule, Expect, FormatSpec,
    Invalid, Reader, Refusal, ScalarHook, ScalarSite, Severity, Url,
};
pub use registry_platform_yaml::{Decoded, Report};
use serde::{
    de::DeserializeOwned, de::Error as _, de::IntoDeserializer, Deserialize, Deserializer,
    Serialize,
};
use serde_json::Value;

use crate::diagnostics::{CompileFailure, Diagnostic};
pub use crate::unique_set::UniqueSet;

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryProject {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_providers: Vec<crate::action_evidence_contracts::EvidenceProviderSource>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ActionSource>,
    #[serde(default)]
    pub access_profiles: Vec<ProjectAccessProfileSource>,
    #[serde(default)]
    pub vocabularies: Vec<VocabularySource>,
    /// Declared count tables computed from governed Registry records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statistical_datasets: Vec<StatisticalDatasetSource>,
    /// Named organizations and frozen groups that consent may be given to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipients: Option<RecipientsSource>,
    /// Consent scope codes of removed gated profiles, kept so existing consent
    /// rows still validate. A retired scope matches nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired_consent_scopes: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalDatasetSource {
    pub id: String,
    pub unit: String,
    pub population: String,
    pub period: StatisticalPeriodSource,
    pub dimensions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<StatisticalDisclosureSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub live: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releases: Option<StatisticalReleasesSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum StatisticalPeriodSource {
    Flow {
        field: String,
        granularity: StatisticalPeriodGranularitySource,
        first_period: String,
    },
    Stock {
        granularity: StatisticalPeriodGranularitySource,
        first_period: String,
        validity: StatisticalValiditySource,
    },
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatisticalPeriodGranularitySource {
    Day,
    Month,
    Quarter,
    Year,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StatisticalValiditySource {
    Temporal(StatisticalTemporalValiditySource),
    Fields(StatisticalValidityFieldsSource),
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatisticalTemporalValiditySource {
    Temporal,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalValidityFieldsSource {
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalDisclosureSource {
    #[serde(deserialize_with = "bounded_u64::<_, 2, MAX_EXACT_JSON_INTEGER>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<2, MAX_EXACT_JSON_INTEGER>")
    )]
    pub minimum_count: u64,
    #[serde(deserialize_with = "bounded_u64::<_, 2, MAX_EXACT_JSON_INTEGER>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<2, MAX_EXACT_JSON_INTEGER>")
    )]
    pub rounding_base: u64,
}

/// The largest integer a JSON number carries exactly, the bound of a
/// statistical disclosure parameter.
pub const MAX_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalReleasesSource {
    pub publisher: String,
    pub readers: Vec<String>,
}

/// Declared consent recipients. Organization and group ids share one
/// namespace and form the append-only `registry-recipients` vocabulary.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecipientsSource {
    #[serde(default)]
    pub organizations: Vec<RecipientOrganizationSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<RecipientGroupSource>,
}

/// One named organization. Its clients are the verified OAuth clients that act
/// for it; an organization with no clients is retired and keeps its code.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecipientOrganizationSource {
    pub id: String,
    pub name: String,
    pub contact: String,
    pub clients: Vec<String>,
}

/// A frozen, named list of declared organizations. Groups do not nest.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecipientGroupSource {
    pub id: String,
    pub name: String,
    pub members: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryIdentitySource {
    pub id: String,
    pub version: String,
    pub default_language: String,
    // Keep omissions in the compiler's field-specific diagnostic domain while
    // telling schemars not to inherit serde's compatibility default. Published
    // schemas therefore structurally require a non-null string member.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(!default))]
    pub canonical_base_iri: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageIdentitySource {
    pub source_revision: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionSource {
    pub access_profile: String,
    pub classification_ceiling: Classification,
    pub catalog: ManifestProjectionCatalogSource,
    pub public_service: ManifestProjectionPublicServiceSource,
    pub datasets: Vec<ManifestProjectionDatasetSource>,
    pub data_services: Vec<ManifestProjectionDataServiceSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub distributions: Vec<ManifestProjectionDistributionSource>,
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
    #[serde(deserialize_with = "url_text")]
    #[cfg_attr(feature = "schema", schemars(with = "Url"))]
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
    pub id: String,
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
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification_ceiling: Option<Classification>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionPublicServiceSource {
    pub id: String,
    pub title: ManifestProjectionTextSource,
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
    #[serde(deserialize_with = "url_text")]
    #[cfg_attr(feature = "schema", schemars(with = "Url"))]
    pub endpoint_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conforms_to: Option<String>,
    pub serves_datasets: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestProjectionDistributionSource {
    pub id: String,
    pub dataset: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_service: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_url_text"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<Url>"))]
    pub access_url: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_url_text"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<Url>"))]
    pub download_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<ManifestProjectionTextSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<ManifestProjectionTextSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iri: Option<String>,
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
    #[serde(default, deserialize_with = "optional_digest_text")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<Digest>"))]
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
    /// Named immediate actions introduced by this module.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ActionSource>,
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
    // See RegistryIdentitySource::canonical_base_iri. New authoring schemas
    // require this member; serde's empty compatibility value only exists so
    // compilation can report the stable membership diagnostic.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(!default))]
    pub primary_dataset: String,
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
    /// Governed binary slots on change-request entities, projected under their exact IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentSlotSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geojson: Option<GeoJsonSource>,
    /// Mandatory request-access requirements checked against every profile, including module contributions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_requirements: Option<AccessRequirementsSource>,
    /// Subject-facing record access history, separate from the operational audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_log: Option<AccessLogSource>,
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
    pub hooks: Vec<HookSource>,
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
    /// Declares this entity's rows as subject-issued consent decisions that
    /// `requireConsent` permissions check before returning a subject's row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_record: Option<ConsentRecordSource>,
}

/// Maximum retained subject-facing access-log window.
pub const MAX_ACCESS_LOG_RETENTION_DAYS: u16 = 3_650;
/// Maximum length of a plaintext subject identifier stored on a logged entity.
pub const MAX_ACCESS_LOG_SUBJECT_CHARACTERS: u32 = 512;
/// Maximum explicit intermediary clients trusted by one logged entity.
pub const MAX_ACCESS_LOG_TRUSTED_INTERMEDIARIES: usize = 64;
/// Maximum delayed-disclosure policies declared by one logged entity.
pub const MAX_ACCESS_LOG_EXEMPTIONS: usize = 64;
/// Maximum UTF-8 bytes in a delayed-disclosure policy reason.
pub const MAX_ACCESS_LOG_EXEMPTION_REASON_BYTES: usize = 256;

const fn default_access_log_retention_days() -> u16 {
    90
}

/// Governed subject-facing access-log policy for an entity.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessLogSource {
    /// Required plaintext string or text field matched to the subject's verified principal.
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 64), regex(pattern = "^[a-z][a-z0-9_-]*$"))
    )]
    pub subject_field: String,
    /// Days each entry remains available before bounded background erasure.
    #[serde(default = "default_access_log_retention_days")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 3_650)))]
    pub retention_days: u16,
    /// Verified intermediary client IDs allowed to forward original requester attribution.
    #[serde(default, skip_serializing_if = "UniqueSet::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 64)))]
    pub trusted_intermediaries: UniqueSet<String>,
    /// Access profiles whose entries become subject-visible only after a policy delay.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(extend(
            "maxProperties" = MAX_ACCESS_LOG_EXEMPTIONS,
            "propertyNames" = {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[a-z][a-z0-9_-]*$"
            }
        ))
    )]
    pub exemptions: BTreeMap<String, AccessLogExemptionSource>,
}

/// Delayed subject disclosure for reads under one access profile.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessLogExemptionSource {
    /// Entity whose access profile authorizes the read. Omitted for direct reads of the logged entity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 64), regex(pattern = "^[a-z][a-z0-9_-]*$"))
    )]
    pub source_entity: Option<String>,
    /// Bounded policy reason retained and audited with each delayed entry.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
    pub reason: String,
    /// Days after the read when the entry becomes visible to the subject.
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 3_649)))]
    pub delay_days: u16,
}

/// The fields of a consent-record entity the engine reads. Other fields are
/// ignored by consent enforcement.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConsentRecordSource {
    /// A reference field naming the protected subject row.
    pub subject: String,
    /// A vocabulary-code field bound to `registry-recipients`.
    pub recipient: String,
    /// A vocabulary-code field compared with the verified request purpose.
    pub purpose: String,
    /// A vocabulary-code field bound to `registry-consent-scopes`.
    pub scope: String,
    pub decision: ConsentDecisionSource,
    pub validity: ConsentValiditySource,
}

/// Maps the adopter's decision codes onto the engine's decision sets.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConsentDecisionSource {
    pub field: String,
    /// Codes that give consent.
    pub gives: Vec<String>,
    /// Codes that supersede every give on the same key ordered no later.
    pub revokes: Vec<String>,
    /// Revoke codes never shown to recipients.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<String>,
}

/// Validity of a consent decision. Every give expires within `maxDuration`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConsentValiditySource {
    /// A required timestamp field; a give is active only from this time.
    pub from: String,
    /// An optional timestamp field ending the give earlier than `maxDuration`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    /// An ISO 8601 duration such as `P365D`, at most ten years.
    pub max_duration: String,
}

/// A consent check ANDed into one read permission.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConsentRequirementSource {
    /// The consent-record entity checked.
    pub record: String,
    /// The permission entity's field the consent subject references; `id` is
    /// the row's own identity.
    pub on: String,
}

/// Who an action creates consent rows for.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentIssuerSource {
    /// The subject, bound through a principal link entity.
    #[serde(rename = "self")]
    Subject,
    /// A reviewed steward act on the subject's behalf.
    Steward,
}

/// A request may declare at most eight independently governed binary slots.
pub const MAX_ATTACHMENT_SLOTS: usize = 8;
/// Bounds both database content and optional external storage operations.
pub const MAX_ATTACHMENT_BYTES: u32 = 16 * 1024 * 1024;
pub const MAX_ATTACHMENT_CONTENT_TYPES: usize = 16;

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttachmentSlotSource {
    pub id: String,
    pub required: bool,
    #[serde(deserialize_with = "bounded_u32::<_, 1, MAX_ATTACHMENT_BYTES>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU32<1, MAX_ATTACHMENT_BYTES>")
    )]
    pub maximum_bytes: u32,
    pub content_types: Vec<String>,
    pub classification: Classification,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BatchSource {
    #[serde(deserialize_with = "bounded_u16::<_, 1, { crate::compiler::MAX_BATCH_ITEMS as u32 }>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU32<1, { crate::compiler::MAX_BATCH_ITEMS as u32 }>")
    )]
    pub maximum_items: u16,
    #[serde(deserialize_with = "bounded_u32::<_, 1, { crate::compiler::MAX_BATCH_BYTES }>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU32<1, { crate::compiler::MAX_BATCH_BYTES }>")
    )]
    pub maximum_bytes: u32,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EntityExtensionSource {
    pub entity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geojson: Option<GeoJsonSource>,
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
    pub hooks: Vec<HookSource>,
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
pub struct GeoJsonSource {
    pub geometry_field: String,
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
    pub required_for: UniqueSet<Operation>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestSource {
    #[serde(default)]
    pub effects: Vec<ChangeRequestEffectSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planner: Option<ChangeRequestPlannerSource>,
    pub review: ChangeRequestReviewSource,
    #[serde(default)]
    pub on_approved: ChangeRequestOnApprovedSource,
    #[serde(default)]
    pub application: ChangeRequestApplicationSource,
    #[serde(default)]
    pub retention: ChangeRequestRetentionSource,
}

pub const CHANGE_REQUEST_PLAN_ABI_V1: &str = "registry.change-request-plan/v1";

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestPlannerSource {
    pub kind: ChangeRequestPlannerKindSource,
    pub script: String,
    pub abi: String,
    #[serde(default)]
    pub request_fields: Vec<String>,
    #[serde(default)]
    pub writes: Vec<ChangeRequestPlannerWriteSource>,
}

/// The authored action-handler backend. The wasm backend is admitted when
/// this build of the compiler carries the `wasm` cargo feature, which
/// validates a declared WASM handler module against the platform guest
/// ABI at compile time; without that feature a declared WASM handler is
/// refused with the pinned `action.handler.wasm_build_unsupported`
/// diagnostic.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionHandlerKindSource {
    Rhai,
    Wasm,
}

/// The authored change-request planner backend. The wasm backend is
/// expressible so a declared WASM planner is refused by the compiler with a
/// pinned diagnostic; WASM planners stay unsupported. Retained Rust name for
/// the reviewed change-request authoring contract.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRequestPlannerKindSource {
    Rhai,
    Wasm,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestPlannerWriteSource {
    pub target: ChangeRequestPlannerTargetSource,
    pub operation: Operation,
    #[serde(default)]
    pub fields: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestPlannerTargetSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestApplicationSource {
    #[serde(
        default,
        skip_serializing_if = "ChangeRequestPreconditionsSource::is_empty"
    )]
    pub preconditions: ChangeRequestPreconditionsSource,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestPreconditionsSource {
    /// Predicates over the frozen request intake itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request: Vec<ChangeRequestPredicateSource>,
    /// Existing records read and revision-bound at proposal preparation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<ChangeRequestGuardTargetSource>,
    /// Governed Evidence acquisitions required immediately before application.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ChangeRequestEvidenceSource>,
}

impl ChangeRequestPreconditionsSource {
    pub fn is_empty(&self) -> bool {
        self.request.is_empty() && self.targets.is_empty() && self.evidence.is_empty()
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestGuardTargetSource {
    pub id: String,
    pub entity: String,
    pub from_field: String,
    #[serde(default)]
    pub requires: Vec<ChangeRequestPredicateSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestPredicateSource {
    pub field: String,
    #[serde(
        default,
        deserialize_with = "present_data_literal",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "DataLiteral"))]
    pub equals: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals_from_request_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(range(min = i64::MIN, max = i64::MAX)))]
    pub at_least: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(range(min = i64::MIN, max = i64::MAX)))]
    pub at_most: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_date: Option<ChangeRequestCurrentDatePredicateSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRequestCurrentDatePredicateSource {
    OnOrAfter,
    OnOrBefore,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestEvidenceSource {
    pub id: String,
    pub provider: String,
    pub requirement: String,
    pub subjects: BTreeMap<String, ChangeRequestEvidenceSubjectSource>,
    #[serde(default)]
    pub requires: Vec<ChangeRequestEvidenceRequirementSource>,
    #[serde(
        deserialize_with = "bounded_u64::<_, 1, { crate::action_evidence_contracts::MAX_EVIDENCE_OBSERVATION_AGE_SECONDS }>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "BoundedU64<1, { crate::action_evidence_contracts::MAX_EVIDENCE_OBSERVATION_AGE_SECONDS }>"
        )
    )]
    pub maximum_observation_age_seconds: u64,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestEvidenceSubjectSource {
    pub profile: String,
    /// Exact governed selector-profile field map. Every profile field must be
    /// present exactly once and no undeclared field is admitted.
    pub selectors: BTreeMap<String, ChangeRequestSelectorSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "source", rename_all = "snake_case")]
pub enum ChangeRequestSelectorSource {
    RequestField { field: String },
    TargetField { target: String, field: String },
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestEvidenceRequirementSource {
    pub output: String,
    #[serde(
        default,
        deserialize_with = "present_json_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub equals: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals_from_request_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(range(min = i64::MIN, max = i64::MAX)))]
    pub at_least: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(range(min = i64::MIN, max = i64::MAX)))]
    pub at_most: Option<i64>,
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
    pub clear: UniqueSet<String>,
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
pub struct ActionSource {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<crate::action_evidence_contracts::ActionEvidenceSource>,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<ActionHandlerSource>,
    #[serde(default)]
    pub inputs: Vec<ActionInputSource>,
    #[serde(default)]
    pub effects: Vec<ActionEffectSource>,
    /// Acceptance-time checks over exact existing reference inputs, combined with AND.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<ActionRequirementSource>,
    /// Required when the action creates consent-record rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_issuer: Option<ConsentIssuerSource>,
}

pub const ACTION_HANDLER_ABI_V2: &str = "registry.action-handler/v2";

pub const ACTION_HANDLER_ABI_V1: &str = "registry.action-handler/v1";

/// The authored action handler: the shared hook handler declaration, with the
/// authorization members a governed action adds.
///
/// `handler` is [`HookHandlerSource`], the same declaration an entity hook
/// carries, so this product spells a handler one way. It is flattened, so the
/// authored member set stays `kind`, the source reference the kind names,
/// `abi`, `writes`, and `refusals`. `writes` and `refusals` are this
/// product's own: they bound what the handler may write and the refusals it
/// may return, and no hook declares them.
///
/// Two rules narrow the shared declaration to what this path runs. `abi` is
/// optional there and required here, refused at deserialization, because
/// every backend an action may declare speaks one. The `url` kind is refused
/// by the compiler at `actions[].handler.kind`, because an action handler
/// runs inside the triggering transaction and cannot be remote.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
// Flattening drops the closed member set schemars derives, so the authoring
// schema restates it: an unknown member of `handler:` is refused by the
// schema an editor reads as well as by deserialization.
#[cfg_attr(feature = "schema", schemars(extend("additionalProperties" = false)))]
#[serde(rename_all = "camelCase")]
pub struct ActionHandlerSource {
    /// Where the handler runs, with the source reference and ABI it declares.
    #[serde(flatten)]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "action_handler_half_schema")
    )]
    pub handler: HookHandlerSource,
    pub writes: Vec<ActionHandlerWriteSource>,
    #[serde(default)]
    pub refusals: Vec<ActionHandlerRefusalSource>,
}

impl ActionHandlerSource {
    /// The declared backend, or `None` for a handler kind an action cannot
    /// run. Derived from the embedded handler, so the backend is spelled once.
    #[must_use]
    pub const fn kind(&self) -> Option<ActionHandlerKindSource> {
        match self.handler {
            HookHandlerSource::Rhai { .. } => Some(ActionHandlerKindSource::Rhai),
            HookHandlerSource::Wasm { .. } => Some(ActionHandlerKindSource::Wasm),
            HookHandlerSource::Url { .. } => None,
        }
    }

    /// The declared handler ABI, absent only for a kind that carries none.
    #[must_use]
    pub fn abi(&self) -> Option<&str> {
        match &self.handler {
            HookHandlerSource::Rhai { abi, .. } | HookHandlerSource::Wasm { abi, .. } => {
                abi.as_deref()
            }
            HookHandlerSource::Url { .. } => None,
        }
    }

    /// The Rhai handler script path, declared by a rhai handler only.
    #[must_use]
    pub fn script(&self) -> Option<&str> {
        match &self.handler {
            HookHandlerSource::Rhai { script, .. } => Some(script.as_str()),
            HookHandlerSource::Wasm { .. } | HookHandlerSource::Url { .. } => None,
        }
    }

    /// The WASM handler module path, declared by a wasm handler only.
    #[must_use]
    pub fn module(&self) -> Option<&str> {
        match &self.handler {
            HookHandlerSource::Wasm { module, .. } => Some(module.as_str()),
            HookHandlerSource::Rhai { .. } | HookHandlerSource::Url { .. } => None,
        }
    }
}

impl<'de> Deserialize<'de> for ActionHandlerSource {
    /// Deserialization is manual because serde refuses `deny_unknown_fields`
    /// beside `flatten`, and the authored member set must stay closed. The
    /// members the shared declaration owns are handed to it unchanged, so the
    /// kind and its source reference pair by that one rule, and the members
    /// this product owns keep deserializing through the caller's
    /// deserializer, so a refusal inside them still names the member path.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            Kind,
            Script,
            Module,
            Abi,
            DestinationId,
            Writes,
            Refusals,
        }

        struct ActionHandlerVisitor;

        impl<'de> serde::de::Visitor<'de> for ActionHandlerVisitor {
            type Value = ActionHandlerSource;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an action handler declaration")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut handler = serde_json::Map::new();
                let mut declared = BTreeSet::new();
                let mut writes: Option<Vec<ActionHandlerWriteSource>> = None;
                let mut refusals: Option<Vec<ActionHandlerRefusalSource>> = None;
                while let Some(field) = map.next_key::<Field>()? {
                    let member = match field {
                        Field::Kind => "kind",
                        Field::Script => "script",
                        Field::Module => "module",
                        Field::Abi => "abi",
                        Field::DestinationId => "destinationId",
                        Field::Writes => {
                            if writes.replace(map.next_value()?).is_some() {
                                return Err(A::Error::duplicate_field("writes"));
                            }
                            continue;
                        }
                        Field::Refusals => {
                            if refusals.replace(map.next_value()?).is_some() {
                                return Err(A::Error::duplicate_field("refusals"));
                            }
                            continue;
                        }
                    };
                    if !declared.insert(member) {
                        return Err(A::Error::duplicate_field(member));
                    }
                    // An explicit null reads as an undeclared member, the
                    // reading the optional source references already carried.
                    if let Some(value) = map.next_value::<Option<String>>()? {
                        handler.insert(member.to_owned(), Value::String(value));
                    }
                }
                let source = ActionHandlerSource {
                    handler: HookHandlerSource::deserialize(
                        Value::Object(handler).into_deserializer(),
                    )
                    .map_err(A::Error::custom)?,
                    writes: writes.ok_or_else(|| A::Error::missing_field("writes"))?,
                    refusals: refusals.unwrap_or_default(),
                };
                if source.kind().is_some() && source.abi().is_none() {
                    return Err(A::Error::missing_field("abi"));
                }
                Ok(source)
            }
        }

        deserializer.deserialize_map(ActionHandlerVisitor)
    }
}

/// The handler half as this product's authoring schema already described it:
/// the two backends an action may declare, their paired source references,
/// and the closed ABI list. The shared declaration's own rendering carries a
/// third kind an action cannot run and leaves the ABI open, so the schema an
/// author's editor reads is written here rather than derived from it.
#[cfg(feature = "schema")]
fn action_handler_half_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let kind = generator.subschema_for::<ActionHandlerKindSource>();
    schemars::json_schema!({
        "type": "object",
        "properties": {
            "kind": kind,
            "script": {
                "description": "The Rhai handler script path. Declared for rhai handlers only; the\ncompiler enforces the pairing with the declared backend.",
                "type": ["string", "null"],
            },
            "module": {
                "description": "The WASM handler module path, project-local. Declared for wasm\nhandlers only; the compiler enforces the pairing with the declared\nbackend.",
                "type": ["string", "null"],
            },
            "abi": {"type": "string", "enum": [ACTION_HANDLER_ABI_V1, ACTION_HANDLER_ABI_V2]},
        },
        "required": ["kind", "abi"],
    })
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionHandlerWriteSource {
    pub id: String,
    pub target: ActionTargetSource,
    pub operation: Operation,
    pub fields: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionHandlerRefusalSource {
    pub code: String,
    pub label: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionRequirementSource {
    pub input: String,
    pub field: String,
    #[serde(
        default,
        deserialize_with = "present_data_literal",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "DataLiteral"))]
    pub equals: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals_input: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionInputSource {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_name: Option<String>,
    #[serde(flatten)]
    pub field_type: FieldTypeSource,
    #[serde(default)]
    pub required: bool,
    pub classification: Classification,
}

impl<'de> Deserialize<'de> for ActionInputSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawFieldSource::deserialize(deserializer)?;
        if raw.valid_time_role.is_some()
            || raw.pattern.is_some()
            || raw.encrypted.is_some()
            || raw.lookup.is_some()
        {
            return Err(D::Error::custom(Invalid::expected(
                "an action input without validTimeRole, pattern, encrypted, or lookup",
                "Remove validTimeRole, pattern, encrypted, and lookup from the action input.",
            )));
        }
        let field_type = parse_field_type::<D::Error>(&raw)?;
        Ok(Self {
            id: raw.id,
            api_name: raw.api_name,
            field_type,
            required: raw.required,
            classification: raw.classification,
        })
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionEffectSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub target: ActionTargetSource,
    pub operation: Operation,
    #[serde(default)]
    pub set: BTreeMap<String, ActionValueSource>,
    #[serde(default)]
    pub clear: UniqueSet<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionTargetSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_field: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionValueSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_effect: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ChangeRequestReviewSource {
    Required(ChangeRequestReviewRequirementSource),
    None(ChangeRequestNoReviewSource),
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestReviewRequirementSource {
    pub authority: String,
    pub policy_id: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestNoReviewSource {
    pub mode: ChangeRequestNoReviewModeSource,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRequestNoReviewModeSource {
    None,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangeRequestOnApprovedSource {
    #[serde(default)]
    pub mode: ChangeRequestOnApprovedModeSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRequestOnApprovedModeSource {
    #[default]
    Manual,
    Automatic,
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

/// Maximum canonical plaintext bytes one Phase 1 encrypted field may seal.
///
/// This mirrors the runtime cryptographic envelope limit while keeping the
/// configuration compiler usable without the optional runtime feature.
pub const MAX_ENCRYPTED_FIELD_PLAINTEXT_BYTES: u32 = 64 * 1024;
#[cfg(feature = "runtime")]
const _: () = assert!(
    MAX_ENCRYPTED_FIELD_PLAINTEXT_BYTES as usize
        == registry_platform_crypto::field_encryption::MAX_FIELD_PLAINTEXT_BYTES
);
/// Maximum authored characters for encrypted string and text fields. One
/// Unicode scalar value can occupy four UTF-8 bytes.
pub const MAX_ENCRYPTED_FIELD_STRING_CHARACTERS: u32 = MAX_ENCRYPTED_FIELD_PLAINTEXT_BYTES / 4;
/// Maximum encrypted members one entity may retain in a revision snapshot.
/// Together with the 3 MiB internal history ceiling, this bounds the fixed
/// envelope overhead above the 2 MiB canonical plaintext snapshot budget.
pub const MAX_ENCRYPTED_FIELDS_PER_ENTITY: usize = 128;
/// Maximum number of transformations in one blind-index normalization pipeline.
pub const MAX_FIELD_LOOKUP_NORMALIZATION_STEPS: usize = 8;

/// A normalization step applied to the canonical string form of an encrypted
/// value before its blind index is derived. The vocabulary is closed.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NormalizationStep {
    Trim,
    Uppercase,
    Lowercase,
    CollapseWhitespace,
    /// Strips spaces, hyphens, slashes, and dots from the canonical form.
    RemoveSeparators,
}

/// The authored blind-index declaration for an encrypted field. Normalization
/// composes in declared order over the canonical string form of the value;
/// `unique` requests a unique index over the derived blind-index column.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FieldLookupSource {
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(length(max = 8)))]
    pub normalization: Vec<NormalizationStep>,
    #[serde(default)]
    pub unique: bool,
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
    /// Native PostgreSQL ARE expression for a persisted string/text value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    pub classification: Classification,
    #[serde(default)]
    pub valid_time_role: Option<ValidTimeRole>,
    /// Persist the value as an encrypted envelope instead of plaintext.
    #[serde(default, skip_serializing_if = "is_false")]
    pub encrypted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup: Option<FieldLookupSource>,
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
    #[schemars(with = "BoundedU32<0, MAX_STRING_FIELD_LENGTH>")]
    min_length: u32,
    #[schemars(with = "BoundedU32<1, MAX_STRING_FIELD_LENGTH>")]
    max_length: u32,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    lookup: Option<FieldLookupSource>,
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
    #[schemars(with = "BoundedU32<1, MAX_TEXT_FIELD_LENGTH>")]
    max_length: u32,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    lookup: Option<FieldLookupSource>,
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
    #[schemars(with = "BoundedU32<1, MAX_DECIMAL_PRECISION>")]
    precision: u8,
    #[schemars(with = "BoundedU32<0, MAX_DECIMAL_PRECISION>")]
    scale: u8,
    #[serde(default)]
    minimum: Option<String>,
    #[serde(default)]
    maximum: Option<String>,
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    lookup: Option<FieldLookupSource>,
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
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    lookup: Option<FieldLookupSource>,
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
    #[schemars(with = "BoundedU32<0, MAX_CRS84_PRECISION>")]
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
    #[schemars(with = "BoundedU32<1, MAX_STRUCTURED_VALUE_BYTES>")]
    max_bytes: u32,
    #[schemars(extend("x-registry-foreign" = "json-schema-2020-12"))]
    schema: Value,
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    lookup: Option<FieldLookupSource>,
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
        if raw.pattern.is_some()
            && !matches!(
                field_type,
                FieldTypeSource::String { .. } | FieldTypeSource::Text { .. }
            )
        {
            return Err(D::Error::custom(Invalid::expected(
                "pattern only on a persisted string or text field",
                "Remove pattern, or declare the field with type string or text.",
            )));
        }
        let encrypted = raw.encrypted.unwrap_or_default();
        if encrypted
            && (raw.classification != Classification::Restricted
                || !matches!(
                    field_type,
                    FieldTypeSource::String { .. }
                        | FieldTypeSource::Text { .. }
                        | FieldTypeSource::Date
                        | FieldTypeSource::Decimal { .. }
                        | FieldTypeSource::Structured { .. }
                ))
        {
            return Err(D::Error::custom(Invalid::expected(
                "encrypted only on a restricted string, text, date, decimal, or structured field",
                "Remove encrypted, or declare the field restricted with type string, text, date, \
                 decimal, or structured.",
            )));
        }
        if raw.lookup.is_some() && !encrypted {
            return Err(D::Error::custom(Invalid::expected(
                "lookup only on an encrypted field",
                "Declare encrypted: true on the field, or remove lookup.",
            )));
        }
        Ok(Self {
            id: raw.id,
            api_name: raw.api_name,
            field_type,
            required: raw.required,
            pattern: raw.pattern,
            classification: raw.classification,
            valid_time_role: raw.valid_time_role,
            encrypted,
            lookup: raw.lookup,
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
        if raw.required
            || raw.valid_time_role.is_some()
            || raw.pattern.is_some()
            || raw.encrypted.is_some()
            || raw.lookup.is_some()
        {
            return Err(D::Error::custom(Invalid::expected(
                "a derived field without required, validTimeRole, pattern, encrypted, or lookup",
                "Remove required, validTimeRole, pattern, encrypted, and lookup from the derived \
                 field.",
            )));
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
            let max_length = raw.max_length.ok_or_else(|| {
                E::custom(Invalid::expected(
                    "a string field with maxLength",
                    "Declare maxLength on the string field.",
                ))
            })?;
            if max_length > MAX_STRING_FIELD_LENGTH {
                return Err(E::custom(Invalid::expected(
                    "a string field with maxLength from 1 to 1000000",
                    "Lower maxLength to at most 1000000, or declare the field as text.",
                )));
            }
            FieldTypeSource::String {
                min_length: raw.min_length.unwrap_or_default(),
                max_length,
            }
        }
        RawFieldKind::Text => {
            reject_type_options::<E>(raw, TypeOptionAllowances::TEXT)?;
            FieldTypeSource::Text {
                max_length: raw.max_length.ok_or_else(|| {
                    E::custom(Invalid::expected(
                        "a text field with maxLength",
                        "Declare maxLength on the text field.",
                    ))
                })?,
            }
        }
        RawFieldKind::Int64 => {
            reject_type_options::<E>(raw, TypeOptionAllowances::NONE)?;
            FieldTypeSource::Int64
        }
        RawFieldKind::Decimal => {
            reject_type_options::<E>(raw, TypeOptionAllowances::DECIMAL)?;
            let precision = raw.precision.ok_or_else(|| {
                E::custom(Invalid::expected(
                    "a decimal field with precision",
                    "Declare precision on the decimal field.",
                ))
            })?;
            if precision == 0 {
                return Err(E::custom(Invalid::expected(
                    "a decimal field with precision from 1 to 38",
                    "Declare a precision of at least 1 on the decimal field.",
                )));
            }
            FieldTypeSource::Decimal {
                precision,
                scale: raw.scale.ok_or_else(|| {
                    E::custom(Invalid::expected(
                        "a decimal field with scale",
                        "Declare scale on the decimal field.",
                    ))
                })?,
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
                vocabulary: raw.vocabulary.clone().ok_or_else(|| {
                    E::custom(Invalid::expected(
                        "a vocabulary-code field with vocabulary",
                        "Declare vocabulary on the vocabulary-code field.",
                    ))
                })?,
                values: raw.values.clone(),
            }
        }
        RawFieldKind::Reference => {
            reject_type_options::<E>(raw, TypeOptionAllowances::REFERENCE)?;
            FieldTypeSource::Reference {
                target: raw.target.clone().ok_or_else(|| {
                    E::custom(Invalid::expected(
                        "a reference field with target",
                        "Declare target on the reference field.",
                    ))
                })?,
                on_delete: raw.on_delete.clone().unwrap_or_default(),
            }
        }
        RawFieldKind::Crs84Point => {
            reject_type_options::<E>(raw, TypeOptionAllowances::CRS84_POINT)?;
            let precision = raw.precision.ok_or_else(|| {
                E::custom(Invalid::expected(
                    "a crs84-point field with precision",
                    "Declare precision on the crs84-point field.",
                ))
            })?;
            if u32::from(precision) > MAX_CRS84_PRECISION {
                return Err(E::custom(Invalid::expected(
                    "a crs84-point field with precision from 0 to 9",
                    "Lower precision on the crs84-point field to at most 9.",
                )));
            }
            FieldTypeSource::Crs84Point {
                precision,
                bbox: raw.bbox.clone(),
            }
        }
        RawFieldKind::Structured => {
            reject_type_options::<E>(raw, TypeOptionAllowances::STRUCTURED)?;
            FieldTypeSource::Structured {
                max_bytes: raw.max_bytes.ok_or_else(|| {
                    E::custom(Invalid::expected(
                        "a structured field with maxBytes",
                        "Declare maxBytes on the structured field.",
                    ))
                })?,
                schema: raw.schema.clone().ok_or_else(|| {
                    E::custom(Invalid::expected(
                        "a structured field with schema",
                        "Declare schema on the structured field.",
                    ))
                })?,
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
    #[serde(
        default,
        deserialize_with = "optional_bounded_u32::<_, 0, MAX_STRING_FIELD_LENGTH>"
    )]
    min_length: Option<u32>,
    // The widest bound of the two kinds that take it; `parse_field_type`
    // holds a string to its own.
    #[serde(
        default,
        deserialize_with = "optional_bounded_u32::<_, 1, MAX_TEXT_FIELD_LENGTH>"
    )]
    max_length: Option<u32>,
    // The widest bound of the two kinds that take it; `parse_field_type`
    // holds each kind to its own.
    #[serde(
        default,
        deserialize_with = "optional_bounded_u8::<_, 0, MAX_DECIMAL_PRECISION>"
    )]
    precision: Option<u8>,
    #[serde(
        default,
        deserialize_with = "optional_bounded_u8::<_, 0, MAX_DECIMAL_PRECISION>"
    )]
    scale: Option<u8>,
    #[serde(default)]
    minimum: Option<String>,
    #[serde(default)]
    maximum: Option<String>,
    #[serde(default)]
    bbox: Option<Crs84BboxSource>,
    #[serde(
        default,
        deserialize_with = "optional_bounded_u32::<_, 1, MAX_STRUCTURED_VALUE_BYTES>"
    )]
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
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    encrypted: Option<bool>,
    #[serde(default)]
    lookup: Option<FieldLookupSource>,
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
        return Err(E::custom(Invalid::expected(
            "only the options the field's type accepts",
            "Remove the options the type does not take: string takes minLength and maxLength, \
             text maxLength, decimal precision, scale, minimum, and maximum, vocabulary-code \
             vocabulary and values, reference target and onDelete, crs84-point precision and \
             bbox, and structured maxBytes and schema.",
        )));
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
        #[cfg_attr(
            feature = "schema",
            schemars(with = "BoundedU32<0, MAX_STRING_FIELD_LENGTH>")
        )]
        min_length: u32,
        #[cfg_attr(
            feature = "schema",
            schemars(with = "BoundedU32<1, MAX_STRING_FIELD_LENGTH>")
        )]
        max_length: u32,
    },
    Text {
        #[cfg_attr(
            feature = "schema",
            schemars(with = "BoundedU32<1, MAX_TEXT_FIELD_LENGTH>")
        )]
        max_length: u32,
    },
    Int64,
    Decimal {
        #[cfg_attr(
            feature = "schema",
            schemars(with = "BoundedU32<1, MAX_DECIMAL_PRECISION>")
        )]
        precision: u8,
        #[cfg_attr(
            feature = "schema",
            schemars(with = "BoundedU32<0, MAX_DECIMAL_PRECISION>")
        )]
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
        #[cfg_attr(
            feature = "schema",
            schemars(with = "BoundedU32<0, MAX_CRS84_PRECISION>")
        )]
        precision: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        bbox: Option<Crs84BboxSource>,
    },
    Structured {
        #[cfg_attr(
            feature = "schema",
            schemars(with = "BoundedU32<1, MAX_STRUCTURED_VALUE_BYTES>")
        )]
        max_bytes: u32,
        #[cfg_attr(
            feature = "schema",
            schemars(extend("x-registry-foreign" = "json-schema-2020-12"))
        )]
        schema: Value,
    },
}

impl FieldTypeSource {
    /// Whether every value `previous` admitted is still a valid value of this
    /// type with no change to its stored column type: the vocabulary gained
    /// codes, a `text` length limit rose, or a `string` minimum length fell.
    pub fn admits_every_value_of(&self, previous: &FieldTypeSource) -> bool {
        self.keeps_vocabulary_codes_of(previous) || self.widens_length_limits_of(previous)
    }

    /// Whether this type only relaxes a length bound `previous` enforced with
    /// a column check: a `text` `maxLength` rose, or a `string` `minLength`
    /// fell under the same `maxLength`.
    pub fn widens_length_limits_of(&self, previous: &FieldTypeSource) -> bool {
        self.widens_text_length_of(previous) || self.lowers_string_min_length_of(previous)
    }

    /// Whether this is a `string` type with the same `maxLength` as
    /// `previous` and a lower `minLength`. The minimum is a column check, so
    /// the stored `varchar` column type is unchanged.
    pub fn lowers_string_min_length_of(&self, previous: &FieldTypeSource) -> bool {
        matches!(
            (previous, self),
            (
                FieldTypeSource::String {
                    min_length: previous_min,
                    max_length: previous_max,
                },
                FieldTypeSource::String {
                    min_length,
                    max_length,
                },
            ) if max_length == previous_max && min_length < previous_min
        )
    }

    /// Whether this is a `text` type whose `maxLength` is higher than
    /// `previous`'s. A `text` column bounds its length with a check, so the
    /// stored column type stays `text`. A `string` field's `maxLength` is its
    /// `varchar` column type, so raising it is a type change and not covered.
    pub fn widens_text_length_of(&self, previous: &FieldTypeSource) -> bool {
        matches!(
            (previous, self),
            (
                FieldTypeSource::Text {
                    max_length: previous_max,
                },
                FieldTypeSource::Text { max_length },
            ) if max_length > previous_max
        )
    }

    /// Whether this type keeps `previous`'s vocabulary and every code it
    /// declared, possibly adding codes. A stored code of `previous` is then
    /// always a valid code of this type.
    pub fn keeps_vocabulary_codes_of(&self, previous: &FieldTypeSource) -> bool {
        match (previous, self) {
            (
                FieldTypeSource::VocabularyCode {
                    vocabulary: previous_vocabulary,
                    values: previous_values,
                },
                FieldTypeSource::VocabularyCode { vocabulary, values },
            ) => {
                previous_vocabulary == vocabulary
                    && previous_values.iter().all(|value| values.contains(value))
            }
            _ => false,
        }
    }
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
/// The longest `maxLength` a string field or action input declares.
pub const MAX_STRING_FIELD_LENGTH: u32 = 1_000_000;
/// The longest `maxLength` a text field or action input declares.
pub const MAX_TEXT_FIELD_LENGTH: u32 = 10_000_000;
/// The largest decimal `precision` and `scale`.
pub const MAX_DECIMAL_PRECISION: u32 = 38;
/// The largest CRS84 point `precision`, in decimal places.
pub const MAX_CRS84_PRECISION: u32 = 9;

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
        (schema_declares_object(object)
            && object.get("additionalProperties") == Some(&Value::Bool(false)))
            || (object.get("type") == Some(&Value::String("array".to_owned()))
                && object.get("items").is_some_and(Value::is_object))
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
        #[cfg_attr(feature = "schema", schemars(range(min = i64::MIN, max = i64::MAX)))]
        minimum: Option<i64>,
        #[serde(default)]
        #[cfg_attr(feature = "schema", schemars(range(min = i64::MIN, max = i64::MAX)))]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<ActorKindSource>,
    #[serde(default, skip_serializing_if = "UniqueSet::is_empty")]
    pub requester_clients: UniqueSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_grant: Option<CompiledTaskGrantSource>,
    #[serde(default)]
    pub principal_claim: Option<String>,
    #[serde(default)]
    /// All listed scopes must be present in the verified token.
    pub required_scopes: UniqueSet<String>,
    #[serde(default)]
    /// The verified token's purpose must match one listed value. Empty means no purpose restriction.
    pub required_purposes: UniqueSet<String>,
    pub operations: UniqueSet<Operation>,
    #[serde(default)]
    pub readable_fields: UniqueSet<String>,
    /// Readable change-request decision detail. Anonymous profiles never receive reason text.
    #[serde(
        default = "default_readable_request_fields",
        skip_serializing_if = "is_default_readable_request_fields"
    )]
    pub readable_request_fields: UniqueSet<RequestMetadataFieldSource>,
    #[serde(default)]
    pub writable_fields: UniqueSet<String>,
    #[serde(default)]
    pub filterable_fields: UniqueSet<String>,
    #[serde(default)]
    pub sortable_fields: UniqueSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spatial_queries: Option<SpatialQueryPermissionSource>,
    /// Explicit row reach; an empty array intentionally permits all rows.
    pub row_boundaries: Vec<RowBoundarySource>,
    /// Current active membership required for each stored reference key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub membership_boundaries: Vec<MembershipBoundarySource>,
    /// Current subject-issued consent required for each row, ANDed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require_consent: Vec<ConsentRequirementSource>,
    /// Restricts change-request reads to rows owned by the authenticated principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_visibility: Option<RequestVisibilitySource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lookups: Vec<LookupPermissionSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_paths: Vec<ReadPathPermissionSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apply_targets: Vec<ApplyTargetPermissionSource>,
    /// Native-reference targets requiring current same-profile GET authority at intake and preparation.
    #[serde(default, skip_serializing_if = "UniqueSet::is_empty")]
    pub submitter_targets: UniqueSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_presence: Vec<RequestPresencePermissionSource>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_count: bool,
    #[serde(default)]
    pub revision_access: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_fields: Vec<ProvenanceFieldSource>,
    #[serde(default)]
    pub allow_data_export: bool,
}

/// Fields of request decision metadata governed separately from stored record fields.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestMetadataFieldSource {
    ActorReference,
    Reason,
    ReviewState,
}

fn default_readable_request_fields<S: From<[RequestMetadataFieldSource; 1]>>() -> S {
    S::from([RequestMetadataFieldSource::Reason])
}

pub(crate) fn is_default_readable_request_fields(
    fields: &BTreeSet<RequestMetadataFieldSource>,
) -> bool {
    fields == &default_readable_request_fields::<BTreeSet<_>>()
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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
    ReviseRequest,
    CancelRequest,
    ApplyRequest,
    Invoke,
    /// Create records through a durable ingestion run, and nothing else. The
    /// grant is enabled only while an operator-opened import authority is open
    /// for the entity and profile. It declares no item route and no raw batch
    /// route, and change control does not count it as a direct write.
    Import,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKindSource {
    Human,
    Agent,
    Service,
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

/// A one-hop current membership requirement, combined with every other row boundary.
/// The root field and membership key must reference the same entity. The active
/// field is Boolean, and principalField matches the profile's verified principal.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MembershipBoundarySource {
    pub field: String,
    pub membership_entity: String,
    pub membership_key_field: String,
    pub principal_field: String,
    pub active_field: String,
}

/// Compile-time requirements, not grants. Profiles must explicitly satisfy them.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessRequirementsSource {
    /// Every profile must require all these scopes. Requirements never grant access.
    #[serde(default)]
    pub required_scopes: UniqueSet<String>,
    /// When nonempty, every profile must restrict purpose to a nonempty subset of these values. Empty imposes no purpose requirement.
    #[serde(default)]
    pub allowed_purposes: UniqueSet<String>,
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

/// One declared hook on an entity.
///
/// The shape is [`registry_platform_hooks::HookDeclaration`] with `trigger`
/// and `when` closed to the vocabulary this compiler validates, and with
/// `handler` optional. A hook that declares no handler is still recorded in
/// the outbox and delivered nowhere; production compilation refuses that.
///
/// Entity hooks run after the triggering transaction commits, so `phase` is
/// written and the compiler refuses any value it cannot run.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HookSource {
    /// Stable hook contract identifier, sent as `ce-type`. Use a new identifier for a breaking payload change.
    pub id: String,
    /// When the hook runs relative to the triggering transaction.
    pub phase: HookPhase,
    /// Committed record change that can produce this hook.
    pub trigger: EventTrigger,
    /// Optional field tests, combined with AND. Omit to run on every matching trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<EventConditionSource>,
    /// The access profile a proposal from this hook is applied under.
    /// Optional: a hook that declares none is a non-proposing hook, and a
    /// proposal from one is refused and dead-lettered at delivery time.
    /// Declaring none is not an authoring error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Declared field identifiers to include in `values`. System event metadata is included separately.
    pub projection: UniqueSet<String>,
    /// Governed, destination-neutral delivery. `destinationId` is a key in
    /// runtime `eventDestinations`; the project carries no URL or secret, and
    /// deployment configuration may tighten the bounds it binds but cannot
    /// supply or widen this authority. Production compilation requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<HookHandlerSource>,
}

/// Closed Version 1 event selection language.
///
/// A tagged shape leaves room for a later, separately governed rule ABI
/// without turning fields into an ad hoc expression language. The shared
/// reader's union helper decodes it, so an error inside a variant keeps its
/// position and a `null` comparison literal is read as a value (CFG-SCHEMA-8,
/// CFG-EMPTY-1).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(
    remote = "Self",
    deny_unknown_fields,
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "kind"))]
pub enum EventConditionSource {
    Fields {
        /// Fields whose values must change. Only valid with the patched trigger.
        #[serde(default)]
        changed: UniqueSet<String>,
        /// Required values before the change. Valid with patched and tombstoned triggers.
        #[serde(default)]
        before_equals: BTreeMap<String, EventScalarValue>,
        /// Required values after the change. Valid with created and patched triggers.
        #[serde(default)]
        after_equals: BTreeMap<String, EventScalarValue>,
    },
    RequestLifecycle {
        #[serde(default)]
        transitions: UniqueSet<String>,
        #[serde(default)]
        to_states: UniqueSet<String>,
    },
}
registry_platform_yaml::tagged_union!(EventConditionSource, tag = "kind");

/// The serialized form of [`EventConditionSource`], kept byte-identical to
/// the shape module digests are computed over.
#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum EventConditionWire<'a> {
    Fields {
        changed: &'a BTreeSet<String>,
        before_equals: &'a BTreeMap<String, EventScalarValue>,
        after_equals: &'a BTreeMap<String, EventScalarValue>,
    },
    RequestLifecycle {
        transitions: &'a BTreeSet<String>,
        to_states: &'a BTreeSet<String>,
    },
}

impl Serialize for EventConditionSource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Fields {
                changed,
                before_equals,
                after_equals,
            } => EventConditionWire::Fields {
                changed,
                before_equals,
                after_equals,
            },
            Self::RequestLifecycle {
                transitions,
                to_states,
            } => EventConditionWire::RequestLifecycle {
                transitions,
                to_states,
            },
        }
        .serialize(serializer)
    }
}

/// A comparison literal in the closed field-condition language.
///
/// It is read as the shared reader's [`DataLiteral`], the one position where
/// `null` is a value (CFG-EMPTY-1). Objects and arrays are refused during
/// source parsing. The compiler then validates each scalar against the
/// declared Registry field type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventScalarValue {
    Null,
    Boolean(bool),
    Number(serde_json::Number),
    String(String),
}

impl From<DataLiteral> for EventScalarValue {
    fn from(literal: DataLiteral) -> Self {
        match literal {
            DataLiteral::Null => EventScalarValue::Null,
            DataLiteral::Boolean(value) => EventScalarValue::Boolean(value),
            DataLiteral::Number(value) => EventScalarValue::Number(value),
            DataLiteral::String(value) => EventScalarValue::String(value),
        }
    }
}

impl Serialize for EventScalarValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            EventScalarValue::Null => serializer.serialize_unit(),
            EventScalarValue::Boolean(value) => serializer.serialize_bool(*value),
            EventScalarValue::Number(value) => value.serialize(serializer),
            EventScalarValue::String(value) => serializer.serialize_str(value),
        }
    }
}

impl<'de> Deserialize<'de> for EventScalarValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        DataLiteral::deserialize(deserializer).map(EventScalarValue::from)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for EventScalarValue {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        DataLiteral::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        generator.subschema_for::<DataLiteral>()
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<ActorKindSource>,
    #[serde(default, skip_serializing_if = "UniqueSet::is_empty")]
    pub requester_clients: UniqueSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_grant: Option<TaskGrantSource>,
    #[serde(default)]
    pub principal_claim: Option<String>,
    #[serde(default)]
    /// All listed scopes must be present in the verified token.
    pub required_scopes: UniqueSet<String>,
    #[serde(default)]
    /// The verified token's purpose must match one listed value. Empty means no purpose restriction.
    pub required_purposes: UniqueSet<String>,
    #[serde(default)]
    pub permissions: Vec<AccessPermissionSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TaskGrantSource {
    #[serde(deserialize_with = "url_text")]
    #[cfg_attr(feature = "schema", schemars(with = "Url"))]
    pub source_issuer: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledTaskGrantSource {
    pub source_issuer: String,
    pub permissions: Vec<CompiledTaskGrantPermissionSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledTaskGrantPermissionSource {
    pub collection: String,
    pub operations: UniqueSet<Operation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessPermissionSource {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub entity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    pub operations: BTreeSet<Operation>,
    #[serde(default)]
    pub readable_fields: BTreeSet<String>,
    /// Readable change-request decision detail. Anonymous profiles never receive reason text.
    #[serde(
        default = "default_readable_request_fields",
        skip_serializing_if = "is_default_readable_request_fields"
    )]
    pub readable_request_fields: BTreeSet<RequestMetadataFieldSource>,
    #[serde(default)]
    pub writable_fields: BTreeSet<String>,
    #[serde(default)]
    pub filterable_fields: BTreeSet<String>,
    #[serde(default)]
    pub sortable_fields: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spatial_queries: Option<SpatialQueryPermissionSource>,
    #[serde(default)]
    pub row_boundaries: Vec<RowBoundarySource>,
    /// Current active membership required for each stored reference key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub membership_boundaries: Vec<MembershipBoundarySource>,
    /// Current subject-issued consent required for each row, ANDed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require_consent: Vec<ConsentRequirementSource>,
    /// Restricts change-request reads to rows owned by the authenticated principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_visibility: Option<RequestVisibilitySource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lookups: Vec<LookupPermissionSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_paths: Vec<ReadPathPermissionSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apply_targets: Vec<ApplyTargetPermissionSource>,
    /// Native-reference targets requiring current same-profile GET authority at intake and preparation.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub submitter_targets: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_presence: Vec<RequestPresencePermissionSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<ActionTargetPermissionSource>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub results: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_count: bool,
    #[serde(default)]
    pub revision_access: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_fields: Vec<ProvenanceFieldSource>,
    #[serde(default)]
    pub allow_data_export: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawAccessPermissionSource {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    entity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    operations: UniqueSet<Operation>,
    #[serde(default)]
    readable_fields: UniqueSet<String>,
    /// Readable change-request decision detail. Anonymous profiles never receive reason text.
    #[serde(
        default = "default_readable_request_fields",
        skip_serializing_if = "is_default_readable_request_fields"
    )]
    readable_request_fields: UniqueSet<RequestMetadataFieldSource>,
    #[serde(default)]
    writable_fields: UniqueSet<String>,
    #[serde(default)]
    filterable_fields: UniqueSet<String>,
    #[serde(default)]
    sortable_fields: UniqueSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spatial_queries: Option<SpatialQueryPermissionSource>,
    #[serde(default)]
    row_boundaries: Option<Vec<RowBoundarySource>>,
    #[serde(default)]
    membership_boundaries: Vec<MembershipBoundarySource>,
    #[serde(default)]
    require_consent: Vec<ConsentRequirementSource>,
    /// Restricts change-request reads to rows owned by the authenticated principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_visibility: Option<RequestVisibilitySource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    lookups: Vec<LookupPermissionSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    read_paths: Vec<ReadPathPermissionSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    apply_targets: Vec<ApplyTargetPermissionSource>,
    #[serde(default, skip_serializing_if = "UniqueSet::is_empty")]
    submitter_targets: UniqueSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    request_presence: Vec<RequestPresencePermissionSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    targets: Vec<ActionTargetPermissionSource>,
    #[serde(default, skip_serializing_if = "UniqueSet::is_empty")]
    results: UniqueSet<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    allow_count: bool,
    #[serde(default)]
    revision_access: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    provenance_fields: Vec<ProvenanceFieldSource>,
    #[serde(default)]
    allow_data_export: bool,
}

// Entity grants must state their row reach. Action invocation itself has no
// rows; its target permissions carry the independently required declarations.
impl<'de> Deserialize<'de> for AccessPermissionSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawAccessPermissionSource::deserialize(deserializer)?;
        if !raw.entity.is_empty() && raw.row_boundaries.is_none() {
            return Err(D::Error::custom(Invalid::expected(
                "an entity permission with rowBoundaries",
                "Declare rowBoundaries on the permission; an explicit empty list grants every row.",
            )));
        }
        Ok(Self {
            entity: raw.entity,
            action: raw.action,
            operations: raw.operations.into_set(),
            readable_fields: raw.readable_fields.into_set(),
            readable_request_fields: raw.readable_request_fields.into_set(),
            writable_fields: raw.writable_fields.into_set(),
            filterable_fields: raw.filterable_fields.into_set(),
            sortable_fields: raw.sortable_fields.into_set(),
            spatial_queries: raw.spatial_queries,
            row_boundaries: raw.row_boundaries.unwrap_or_default(),
            membership_boundaries: raw.membership_boundaries,
            require_consent: raw.require_consent,
            request_visibility: raw.request_visibility,
            lookups: raw.lookups,
            read_paths: raw.read_paths,
            apply_targets: raw.apply_targets,
            submitter_targets: raw.submitter_targets.into_set(),
            request_presence: raw.request_presence,
            targets: raw.targets,
            results: raw.results.into_set(),
            allow_count: raw.allow_count,
            revision_access: raw.revision_access,
            provenance_fields: raw.provenance_fields,
            allow_data_export: raw.allow_data_export,
        })
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for AccessPermissionSource {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("AccessPermissionSource")
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(concat!(module_path!(), "::AccessPermissionSource"))
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        AccessPermissionSourceSchema::json_schema(generator)
    }
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(untagged)]
enum AccessPermissionSourceSchema {
    Entity(Box<EntityAccessPermissionSourceSchema>),
    Action(ActionAccessPermissionSourceSchema),
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EntityAccessPermissionSourceSchema {
    entity: String,
    operations: UniqueSet<Operation>,
    #[serde(default)]
    readable_fields: UniqueSet<String>,
    /// Readable change-request decision detail. Anonymous profiles never receive reason text.
    #[serde(
        default = "default_readable_request_fields",
        skip_serializing_if = "is_default_readable_request_fields"
    )]
    readable_request_fields: UniqueSet<RequestMetadataFieldSource>,
    #[serde(default)]
    writable_fields: UniqueSet<String>,
    #[serde(default)]
    filterable_fields: UniqueSet<String>,
    #[serde(default)]
    sortable_fields: UniqueSet<String>,
    #[serde(default)]
    spatial_queries: Option<SpatialQueryPermissionSource>,
    row_boundaries: Vec<RowBoundarySource>,
    /// Current active membership required for each stored reference key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    membership_boundaries: Vec<MembershipBoundarySource>,
    /// Current subject-issued consent required for each row, ANDed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    require_consent: Vec<ConsentRequirementSource>,
    #[serde(default)]
    request_visibility: Option<RequestVisibilitySource>,
    #[serde(default)]
    lookups: Vec<LookupPermissionSource>,
    #[serde(default)]
    read_paths: Vec<ReadPathPermissionSource>,
    #[serde(default)]
    apply_targets: Vec<ApplyTargetPermissionSource>,
    #[serde(default, skip_serializing_if = "UniqueSet::is_empty")]
    submitter_targets: UniqueSet<String>,
    #[serde(default)]
    request_presence: Vec<RequestPresencePermissionSource>,
    #[serde(default)]
    allow_count: bool,
    #[serde(default)]
    revision_access: bool,
    #[serde(default)]
    allow_data_export: bool,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ActionAccessPermissionSourceSchema {
    action: String,
    operations: UniqueSet<Operation>,
    #[serde(default)]
    targets: Vec<ActionTargetPermissionSource>,
    #[serde(default)]
    results: UniqueSet<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpatialQueryPermissionSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bbox: Option<SpatialBboxPermissionSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpatialBboxPermissionSource {
    pub maximum_longitude_span_degrees: serde_json::Number,
    pub maximum_latitude_span_degrees: serde_json::Number,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LookupPermissionSource {
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
pub struct ReadPathPermissionSource {
    pub path: String,
    #[serde(default)]
    pub readable_fields: UniqueSet<String>,
    #[serde(default)]
    pub filterable_fields: UniqueSet<String>,
    #[serde(default)]
    pub sortable_fields: UniqueSet<String>,
    #[serde(default)]
    pub allow_count: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApplyTargetPermissionSource {
    pub entity: String,
    /// Explicit row reach; an empty array intentionally permits all rows.
    pub row_boundaries: Vec<RowBoundarySource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RequestPresencePermissionSource {
    pub request_type: String,
    /// Explicit row reach; an empty array intentionally permits all rows.
    pub row_boundaries: Vec<RowBoundarySource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestVisibilitySource {
    /// Expose only requests created by the current authenticated principal.
    Owner,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionTargetPermissionSource {
    pub entity: String,
    /// Explicit row reach; an empty array intentionally permits all rows.
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

/// The file name a project read from bytes alone is reported under.
pub const PROJECT_FILE: &str = "registry.yaml";

/// The file name a module read from bytes alone is reported under.
pub const MODULE_FILE: &str = "module.yaml";

const PROJECT_API_VERSIONS: [ApiVersion<'static>; 1] =
    [ApiVersion::current(crate::compiler::AUTHORING_API_VERSION)];

/// `registry.yaml`, the authored project file.
pub const PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: "RegistryProject",
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &PROJECT_API_VERSIONS,
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// A module's `module.yaml`. A module carries no envelope: its project's
/// module lock names it by identifier, version, and digest.
pub const MODULE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: "RegistryModule",
    envelope: EnvelopeRule::Exempt {
        reason: "a module is named by its project's module lock, which records its \
                 identifier, version, and digest",
    },
    removed_keys: &[],
};

/// Read an authored project through the shared reader. `file` is the name
/// diagnostics carry. Every diagnostic carries its code, path, line and
/// column, and the action that fixes it (CFG-DIAG-1), and none repeats a
/// value from the file.
pub fn read_project_yaml(file: &str, bytes: &[u8]) -> Result<Decoded<RegistryProject>, Report> {
    read_authored(file, bytes, &PROJECT_FORMAT)
}

/// Read an authored module through the shared reader, as
/// [`read_project_yaml`] reads a project.
pub fn read_module_yaml(file: &str, bytes: &[u8]) -> Result<Decoded<RegistryModule>, Report> {
    read_authored(file, bytes, &MODULE_FORMAT)
}

fn read_authored<T: DeserializeOwned>(
    file: &str,
    bytes: &[u8],
    format: &FormatSpec<'_>,
) -> Result<Decoded<T>, Report> {
    let mut hook = AuthoredExpressions;
    Reader::new(file)
        .with_hook(&mut hook)
        .decode::<T>(bytes, &Expect::one(format))
}

pub fn parse_project_yaml(bytes: &[u8]) -> Result<RegistryProject, CompileFailure> {
    read_project_yaml(PROJECT_FILE, bytes)
        .map(|decoded| decoded.value)
        .map_err(|report| compile_failure_from_report("project", &report))
}

pub fn parse_module_yaml(bytes: &[u8]) -> Result<RegistryModule, CompileFailure> {
    read_module_yaml(MODULE_FILE, bytes)
        .map(|decoded| decoded.value)
        .map_err(|report| compile_failure_from_report("module", &report))
}

fn parse_json<T: DeserializeOwned>(bytes: &[u8], root: &str) -> Result<T, CompileFailure> {
    let value = parse_json_strict(bytes).map_err(|error| {
        CompileFailure::from_one(Diagnostic::error(
            "source.json.invalid",
            root,
            &format!(
                "the JSON source is structurally invalid: {}",
                redact_authored_values(&error.to_string())
            ),
        ))
    })?;
    deserialize_value(value, root)
}

fn deserialize_value<T: DeserializeOwned>(
    value: serde_json::Value,
    root: &str,
) -> Result<T, CompileFailure> {
    let deserializer = value.into_deserializer();
    serde_path_to_error::deserialize(deserializer).map_err(|error| {
        CompileFailure::from_one(Diagnostic::error(
            "source.shape.invalid",
            document_path(root, &error),
            &format!(
                "the source field is unknown, duplicated, missing, or has the wrong type: {}",
                redact_authored_values(&error.inner().to_string())
            ),
        ))
    })
}

/// The shared reader's refusal of an authored file as compiler diagnostics:
/// each error keeps the reader's code, its path in the compiler's
/// `root.member[index]` form, and its message followed by the action that
/// fixes it.
pub fn compile_failure_from_report(root: &str, report: &Report) -> CompileFailure {
    CompileFailure::from_errors(
        report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Error)
            .map(|diagnostic| {
                let position = diagnostic
                    .source
                    .as_ref()
                    .and_then(|source| Some((source.line?, source.column?)))
                    .map(|(line, column)| format!(" (line {line}, column {column})"))
                    .unwrap_or_default();
                Diagnostic::error(
                    &diagnostic.code,
                    compiler_path(root, &diagnostic.path),
                    &format!(
                        "{}{position}; next: {}",
                        diagnostic.message.trim_end_matches('.'),
                        diagnostic.suggested_action
                    ),
                )
            })
            .collect(),
    )
}

/// `${...}` substitution belongs to `runtime.yaml`; an authored project or
/// module is reviewed and packaged as written, so an environment expression
/// in a key or a text value of one is refused where it is written.
struct AuthoredExpressions;

impl AuthoredExpressions {
    fn check(text: &str) -> Result<(), Refusal> {
        if contains_environment_expression(text) {
            return Err(Refusal {
                code: "config.substitution-not-allowed".to_owned(),
                message: "a `${...}` expression is written in an authored file; substitution \
                          applies to runtime.yaml only"
                    .to_owned(),
                suggested_action: "Write the value in the authored file directly.".to_owned(),
            });
        }
        Ok(())
    }
}

impl ScalarHook for AuthoredExpressions {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        Self::check(site.text)
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        Self::check(site.text).map(|()| None)
    }
}

/// Render an RFC 6901 pointer in the `root.member[index]` form the
/// compiler's other diagnostics use. A numeric segment is a list index.
pub fn compiler_path(root: &str, pointer: &str) -> String {
    let mut path = root.to_owned();
    let Some(rest) = pointer.strip_prefix('/') else {
        return path;
    };
    for segment in rest.split('/') {
        let segment = segment.replace("~1", "/").replace("~0", "~");
        if !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit()) {
            path.push('[');
            path.push_str(&segment);
            path.push(']');
        } else {
            path.push('.');
            path.push_str(&segment);
        }
    }
    path
}

/// Join the document root with the member path `serde_path_to_error` recorded.
pub(crate) fn document_path<E: std::fmt::Display>(
    root: &str,
    error: &serde_path_to_error::Error<E>,
) -> String {
    let suffix = error.path().to_string();
    if suffix.is_empty() {
        root.to_owned()
    } else {
        format!("{root}.{suffix}")
    }
}

/// Keep the parts of a deserialization message an adopter needs, the member
/// name, the closed list of alternatives, and the source location, while the
/// authored value stays out of the diagnostic.
///
/// serde reports the offending value inside an `invalid type:` or
/// `invalid value:` clause. Only the shape word that opens such a clause
/// survives, so the message still says a string arrived where a sequence was
/// required without repeating the string.
///
/// A refusal a source type writes for the shared reader carries the reader's
/// markers after its sentence; only the sentence is kept.
pub(crate) fn redact_authored_values(message: &str) -> String {
    const CLAUSES: [&str; 2] = ["invalid type: ", "invalid value: "];
    let message = message.split('\u{1f}').next().unwrap_or(message);
    let mut redacted = String::with_capacity(message.len());
    let mut rest = message;
    loop {
        let Some((start, len)) = CLAUSES
            .iter()
            .filter_map(|clause| rest.find(clause).map(|start| (start, clause.len())))
            .min_by_key(|(start, _)| *start)
        else {
            redacted.push_str(rest);
            return redacted;
        };
        let opened = start + len;
        redacted.push_str(&rest[..opened]);
        let (shape, tail) = split_unexpected_value(&rest[opened..]);
        redacted.push_str(shape);
        rest = tail;
    }
}

/// Split one serde `Unexpected` rendering into its shape word and the text that
/// follows the clause, dropping any quoted or backticked authored value.
fn split_unexpected_value(clause: &str) -> (&str, &str) {
    let bytes = clause.as_bytes();
    let mut index = 0;
    let mut shape_end = None;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                shape_end.get_or_insert(index);
                index = skip_quoted(bytes, index, b'"');
            }
            b'`' => {
                shape_end.get_or_insert(index);
                index = skip_quoted(bytes, index, b'`');
            }
            b',' => break,
            _ => index += 1,
        }
    }
    let shape_end = shape_end.unwrap_or(index);
    (clause[..shape_end].trim_end(), &clause[index..])
}

/// Return the offset just past the delimited run that opens at `open`.
///
/// serde renders a string value with `Debug`, so a delimiter inside the value
/// arrives escaped and must not end the run.
fn skip_quoted(bytes: &[u8], open: usize, delimiter: u8) -> usize {
    let mut index = open + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == delimiter => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

// A member the published schema types as `Url` (CFG-VAL-7) or `Digest`
// (CFG-VAL-6) is checked by the shared type and kept as the text written, so
// the serialized source a digest covers is unchanged.
fn url_text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Url::deserialize(deserializer).map(Url::into_string)
}

fn optional_url_text<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    url_text(deserializer).map(Some)
}

fn optional_digest_text<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Digest::deserialize(deserializer).map(|digest| Some(digest.into_string()))
}

// An integer member the published schema bounds (CFG-QTY-4) is read through
// the shared bounded type and kept as the plain integer, so the serialized
// source a digest covers is unchanged.
pub(crate) fn bounded_u32<'de, D: Deserializer<'de>, const MIN: u32, const MAX: u32>(
    deserializer: D,
) -> Result<u32, D::Error> {
    BoundedU32::<MIN, MAX>::deserialize(deserializer).map(BoundedU32::get)
}

pub(crate) fn bounded_u64<'de, D: Deserializer<'de>, const MIN: u64, const MAX: u64>(
    deserializer: D,
) -> Result<u64, D::Error> {
    BoundedU64::<MIN, MAX>::deserialize(deserializer).map(BoundedU64::get)
}

fn bounded_u16<'de, D: Deserializer<'de>, const MIN: u32, const MAX: u32>(
    deserializer: D,
) -> Result<u16, D::Error> {
    const { assert!(MAX <= u16::MAX as u32) };
    bounded_u32::<D, MIN, MAX>(deserializer).map(|value| value as u16)
}

fn optional_bounded_u32<'de, D: Deserializer<'de>, const MIN: u32, const MAX: u32>(
    deserializer: D,
) -> Result<Option<u32>, D::Error> {
    bounded_u32::<D, MIN, MAX>(deserializer).map(Some)
}

fn optional_bounded_u8<'de, D: Deserializer<'de>, const MIN: u32, const MAX: u32>(
    deserializer: D,
) -> Result<Option<u8>, D::Error> {
    const { assert!(MAX <= u8::MAX as u32) };
    bounded_u32::<D, MIN, MAX>(deserializer).map(|value| Some(value as u8))
}

// An omitted predicate differs from an explicit JSON null equality literal.
pub(crate) fn present_json_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

// An omitted equality differs from an explicit `null` one: the literal is read
// as a `DataLiteral`, the one position where `null` is a value (CFG-EMPTY-1),
// and a list or a mapping is refused.
pub(crate) fn present_data_literal<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    DataLiteral::deserialize(deserializer).map(|literal| {
        Some(match literal {
            DataLiteral::Null => Value::Null,
            DataLiteral::Boolean(value) => Value::Bool(value),
            DataLiteral::Number(value) => Value::Number(value),
            DataLiteral::String(value) => Value::String(value),
        })
    })
}
