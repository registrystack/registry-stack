// SPDX-License-Identifier: Apache-2.0
//! Portable metadata model and pure renderers for registry catalogs.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oxiri::Iri;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[allow(dead_code)]
const DATASETS_COLLECTION_ID: &str = "datasets";
const JSON_SCHEMA_DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";
const EU_DATA_THEME_SCHEME: &str = "http://publications.europa.eu/resource/authority/data-theme";
const EUROVOC_THEME_SCHEME: &str = "http://eurovoc.europa.eu/100141";
const EU_LOCATION_IRI: &str = "http://publications.europa.eu/resource/authority/country/EUR";
const REGISTRY_NOTARY_FEDERATION_PROTOCOL: &str = "registry-notary-federation/v0.1";
const CATALOG_SCHEMA_VERSION: &str = "registry-manifest-catalog/v1";
const EVIDENCE_OFFERINGS_SCHEMA_VERSION: &str = "registry-manifest-evidence-offerings/v1";
const EVIDENCE_OFFERING_SCHEMA_VERSION: &str = "registry-manifest-evidence-offering/v1";
const POLICY_COLLECTION_SCHEMA_VERSION: &str = "registry-manifest-policy-collection/v1";
const POLICY_SCHEMA_VERSION: &str = "registry-manifest-policy/v1";
const SHACL_SCHEMA_VERSION: &str = "registry-manifest-shacl/v1";
const CODELIST_SCHEMA_VERSION: &str = "registry-manifest-codelist/v1";
const ENTITY_JSON_SCHEMA_VERSION: &str = "registry-manifest-entity-json-schema/v1";
const FORM_JSON_SCHEMA_VERSION: &str = "registry-manifest-form-json-schema/v1";
const OGC_RECORDS_SCHEMA_VERSION: &str = "registry-manifest-ogc-records/v1";
const MAX_PROFILES: usize = 64;
const MAX_CATALOG_CONFORMS_TO: usize = 64;
const MAX_CATALOG_APPLICATION_PROFILES: usize = 32;
const MAX_TOP_LEVEL_COLLECTION_ITEMS: usize = 256;
const MAX_DATASET_ENTITIES: usize = 256;
const MAX_ENTITY_FIELDS: usize = 512;
const MAX_ENTITY_RELATIONSHIPS: usize = 512;
const MAX_CODELIST_CONCEPTS: usize = 1024;
const MAX_URI_LIST_ITEMS: usize = 128;
const BUILTIN_VOCABULARIES: &[(&str, &str)] = &[
    ("adms", "http://www.w3.org/ns/adms#"),
    ("cccev", "http://data.europa.eu/m8g/"),
    ("cpsv", "http://purl.org/vocab/cpsv#"),
    ("cv", "http://data.europa.eu/m8g/"),
    ("dcat", "http://www.w3.org/ns/dcat#"),
    ("dcatap", "http://data.europa.eu/r5r/"),
    ("dcterms", "http://purl.org/dc/terms/"),
    ("eli", "http://data.europa.eu/eli/ontology#"),
    ("foaf", "http://xmlns.com/foaf/0.1/"),
    ("odrl", "http://www.w3.org/ns/odrl/2/"),
    ("rdfs", "http://www.w3.org/2000/01/rdf-schema#"),
    ("registry_manifest", "https://registry-manifest.dev/ns/v1#"),
    ("registry_relay", "https://registry-relay.dev/"),
    ("sh", "http://www.w3.org/ns/shacl#"),
    ("skos", "http://www.w3.org/2004/02/skos/core#"),
    ("xsd", "http://www.w3.org/2001/XMLSchema#"),
];

pub const RUNTIME_ONLY_KEYS: &[&str] = &[
    "admin_bind",
    "admin_listener",
    "audit",
    "auth",
    "bind",
    "bindings",
    "capabilities",
    "column",
    "config_trust",
    "file_path",
    "listener",
    "listeners",
    "peer_allowlist",
    "peers",
    "private_jwk",
    "private_jwk_env",
    "query",
    "replay",
    "required_filters",
    "rows_scope",
    "scope",
    "secret_provider",
    "secret_providers",
    "signing_keys",
    "source",
    "source_id",
    "table",
    "token_url",
    "url",
    "url_env",
    "visibility",
];

#[must_use]
pub fn is_runtime_only_key(key: &str) -> bool {
    RUNTIME_ONLY_KEYS.contains(&key)
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ManifestDigestError {
    #[error("metadata manifest canonical JSON does not support non-finite numbers")]
    InvalidNumber,
    #[error("metadata manifest serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn canonicalize_json(value: &Value) -> Result<Vec<u8>, ManifestDigestError> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

pub fn source_manifest_digest(manifest: &MetadataManifest) -> Result<String, ManifestDigestError> {
    let value = serde_json::to_value(manifest)?;
    let canonical = canonicalize_json(&value)?;
    Ok(sha256_uri(&canonical))
}

#[must_use]
pub fn sha256_uri(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity("sha256:".len() + 64);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), ManifestDigestError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => {
            if let Some(value) = number.as_f64() {
                if !value.is_finite() {
                    return Err(ManifestDigestError::InvalidNumber);
                }
            }
            out.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(value) => out.extend_from_slice(serde_json::to_string(value)?.as_bytes()),
        Value::Array(values) => {
            out.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => write_canonical_object(map, out)?,
    }
    Ok(())
}

fn write_canonical_object(
    map: &Map<String, Value>,
    out: &mut Vec<u8>,
) -> Result<(), ManifestDigestError> {
    out.push(b'{');
    let mut entries = map.iter().collect::<Vec<_>>();
    entries.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(serde_json::to_string(key)?.as_bytes());
        out.push(b':');
        write_canonical(value, out)?;
    }
    out.push(b'}');
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetadataManifest {
    pub schema_version: String,
    pub catalog: CatalogManifest,
    #[serde(default)]
    pub vocabularies: BTreeMap<String, String>,
    #[serde(default)]
    pub profiles: Vec<ProfileClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<FederationManifest>,
    #[serde(default)]
    pub evaluation_profiles: Vec<EvaluationProfileManifest>,
    #[serde(default)]
    pub requirements: Vec<RequirementManifest>,
    #[serde(default)]
    pub evidence_types: Vec<EvidenceTypeManifest>,
    #[serde(default)]
    pub authorities: Vec<AuthorityManifest>,
    #[serde(default)]
    pub public_services: Vec<ServiceManifest>,
    #[serde(default)]
    pub data_services: Vec<DataServiceManifest>,
    #[serde(default)]
    pub forms: Vec<FormManifest>,
    #[serde(default)]
    pub datasets: Vec<DatasetManifest>,
    #[serde(default)]
    pub codelists: Vec<CodelistManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogManifest {
    pub id: String,
    pub base_url: String,
    pub title: LocalizedText,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    pub publisher: PublisherManifest,
    #[serde(default)]
    pub participant_id: Option<String>,
    #[serde(default)]
    pub conforms_to: Vec<String>,
    #[serde(default)]
    pub standards: StandardsManifest,
    #[serde(default)]
    pub application_profiles: Vec<ApplicationProfile>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StandardsManifest {
    #[serde(default)]
    pub dcat: Option<String>,
    #[serde(default)]
    pub shacl: Option<String>,
    #[serde(default)]
    pub json_schema: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationProfile {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileClaim {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FederationManifest {
    pub node_id: String,
    pub issuer: String,
    pub jwks_uri: String,
    pub federation_api: String,
    #[serde(default)]
    pub supported_protocol_versions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationProfileManifest {
    pub id: String,
    pub ruleset: String,
    pub claim_id: String,
    pub subject_id_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_source_observed_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum LocalizedText {
    Plain(String),
    Localized(BTreeMap<String, String>),
}

impl LocalizedText {
    pub fn text(&self) -> String {
        match self {
            Self::Plain(value) => value.clone(),
            Self::Localized(values) => values
                .get("en")
                .or_else(|| values.values().next())
                .cloned()
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublisherManifest {
    pub name: String,
    #[serde(default)]
    pub iri: Option<String>,
    #[serde(default)]
    pub authority_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityManifest {
    pub id: String,
    #[serde(default)]
    pub iri: Option<String>,
    pub name: String,
    #[serde(default)]
    pub authority_type: Option<String>,
    #[serde(default)]
    pub spatial: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceManifest {
    pub id: String,
    #[serde(default)]
    pub iri: Option<String>,
    pub title: LocalizedText,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(default)]
    pub competent_authority: Option<String>,
    #[serde(default)]
    pub jurisdiction: Option<String>,
    #[serde(default)]
    pub channels: Vec<ChannelManifest>,
    #[serde(default)]
    pub holds_requirements: Vec<String>,
    #[serde(default)]
    pub produces: Vec<String>,
    #[serde(default)]
    pub data_services: Vec<String>,
    #[serde(default)]
    pub forms: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelManifest {
    pub id: String,
    #[serde(default)]
    pub iri: Option<String>,
    #[serde(default)]
    pub title: Option<LocalizedText>,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub access_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DataServiceManifest {
    pub id: String,
    #[serde(default)]
    pub iri: Option<String>,
    pub title: LocalizedText,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(default)]
    pub endpoint_url: Option<String>,
    #[serde(default)]
    pub endpoint_description: Option<String>,
    #[serde(default)]
    pub serves_datasets: Vec<String>,
    #[serde(default)]
    pub conforms_to: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FormManifest {
    pub id: String,
    #[serde(default)]
    pub iri: Option<String>,
    pub title: LocalizedText,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    pub service: String,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub validates_with: Option<FormValidationManifest>,
    #[serde(default)]
    pub sections: Vec<FormSectionManifest>,
    #[serde(default)]
    pub fields: Vec<FormFieldManifest>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FormValidationManifest {
    #[serde(default)]
    pub json_schema: Option<String>,
    #[serde(default)]
    pub shacl: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FormSectionManifest {
    pub id: String,
    #[serde(default)]
    pub title: Option<LocalizedText>,
    #[serde(default)]
    pub repeatable: bool,
    #[serde(default)]
    pub min_occurs: Option<u32>,
    #[serde(default)]
    pub max_occurs: Option<u32>,
    #[serde(default)]
    pub visible_when: Option<FormVisibilityManifest>,
    #[serde(default)]
    pub fields: Vec<FormFieldManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FormFieldManifest {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub label: LocalizedText,
    #[serde(default)]
    pub widget_type: Option<String>,
    #[serde(default)]
    pub data_type: Option<String>,
    #[serde(default)]
    pub concept: Option<String>,
    #[serde(default)]
    pub supports_requirement: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub min_occurs: Option<u32>,
    #[serde(default)]
    pub max_occurs: Option<u32>,
    #[serde(default)]
    pub visible_when: Option<FormVisibilityManifest>,
    #[serde(default)]
    pub fulfillment: Option<FormFulfillmentManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FormVisibilityManifest {
    pub field: String,
    pub equals: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FormFulfillmentManifest {
    #[serde(default)]
    pub modes: Vec<String>,
    #[serde(default)]
    pub preferred_mode: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DatasetManifest {
    pub id: String,
    pub title: LocalizedText,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub sensitivity: Sensitivity,
    #[serde(default)]
    pub access_rights: AccessRights,
    #[serde(default)]
    pub update_frequency: UpdateFrequency,
    #[serde(default)]
    pub conforms_to: Vec<String>,
    /// DCAT-AP `dcatap:applicableLegislation` IRIs. These are standard
    /// evidence links only; downstream systems may use them to infer legal
    /// readiness, but Registry Relay does not publish an authority verdict.
    #[serde(default)]
    pub applicable_legislation: Vec<String>,
    #[serde(default)]
    pub spatial_coverage: Option<String>,
    #[serde(default)]
    pub status: Option<AdmsStatus>,
    /// Related CPSV public services that produce this dataset. Published as
    /// JSON-LD `cpsv:PublicService` nodes with `cpsv:produces`; consumers can
    /// interpret that evidence, but the manifest does not declare
    /// source-of-truth status.
    #[serde(default)]
    pub public_services: Vec<PublicServiceManifest>,
    #[serde(default)]
    pub policy: Option<DatasetPolicyManifest>,
    #[serde(default)]
    pub evidence_offerings: Vec<EvidenceOfferingManifest>,
    #[serde(default)]
    pub entities: Vec<EntityManifest>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DatasetPolicyManifest {
    #[serde(default)]
    pub uid: Option<String>,
    #[serde(default)]
    pub assigner: Option<String>,
    #[serde(default)]
    pub profile: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<PolicyRuleManifest>,
    #[serde(default)]
    pub prohibitions: Vec<PolicyRuleManifest>,
    #[serde(default)]
    pub obligations: Vec<PolicyDutyManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleManifest {
    pub action: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default)]
    pub constraints: Vec<PolicyConstraintManifest>,
    #[serde(default)]
    pub duties: Vec<PolicyDutyManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDutyManifest {
    pub action: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default)]
    pub constraints: Vec<PolicyConstraintManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyConstraintManifest {
    pub left_operand: String,
    pub operator: String,
    pub right_operand: PolicyOperandValue,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub datatype: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyOperandValue {
    #[serde(default)]
    pub iri: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicServiceManifest {
    #[serde(default)]
    pub id: Option<String>,
    pub title: LocalizedText,
    #[serde(default)]
    pub description: Option<LocalizedText>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequirementManifest {
    pub id: String,
    #[serde(default)]
    pub iri: Option<String>,
    pub title: LocalizedText,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(default)]
    pub rdf_type: Option<String>,
    #[serde(default)]
    pub procedure_contexts: Vec<String>,
    #[serde(default)]
    pub reference_frameworks: Vec<ReferenceFrameworkManifest>,
    #[serde(default)]
    pub evidence_type_lists: Vec<EvidenceTypeListManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTypeListManifest {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub title: Option<LocalizedText>,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(default)]
    pub evidence_types: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReferenceFrameworkManifest {
    pub iri: String,
    pub identifier: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTypeManifest {
    pub id: String,
    #[serde(default)]
    pub iri: Option<String>,
    pub title: LocalizedText,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(default)]
    pub proves: Vec<String>,
    #[serde(default)]
    pub information_concepts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceOfferingManifest {
    pub id: String,
    #[serde(default)]
    pub iri: Option<String>,
    pub title: LocalizedText,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    pub evidence_type: String,
    pub issuing_authority: IssuingAuthorityManifest,
    #[serde(default)]
    pub jurisdiction: Option<JurisdictionManifest>,
    #[serde(default)]
    pub level_of_assurance: Option<String>,
    pub entity: String,
    #[serde(default)]
    pub lookup_keys: Vec<String>,
    #[serde(default)]
    pub procedure_contexts: Vec<String>,
    pub access: EvidenceOfferingAccessManifest,
    #[serde(default)]
    pub policy: Option<EvidenceOfferingPolicyManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuingAuthorityManifest {
    pub id: String,
    #[serde(default)]
    pub iri: Option<String>,
    pub name: String,
    #[serde(default)]
    pub country: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JurisdictionManifest {
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceOfferingAccessManifest {
    pub kind: String,
    #[serde(default)]
    pub conforms_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_url: Option<String>,
    pub ruleset: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceOfferingPolicyManifest {
    #[serde(default)]
    pub purpose: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntityManifest {
    pub name: String,
    #[serde(default)]
    pub title: Option<LocalizedText>,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(default)]
    pub concept_uri: Option<String>,
    #[serde(default)]
    pub identifiers: Vec<IdentifierManifest>,
    #[serde(default)]
    pub fields: Vec<FieldManifest>,
    #[serde(default)]
    pub relationships: Vec<RelationshipManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentifierManifest {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FieldManifest {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub constraints: FieldConstraints,
    #[serde(default)]
    pub concepts: Vec<String>,
    #[serde(default)]
    pub codelist: Option<String>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FieldConstraints {
    #[serde(default)]
    pub min_length: Option<u64>,
    #[serde(default)]
    pub max_length: Option<u64>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default, rename = "in")]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelationshipManifest {
    pub name: String,
    #[serde(default)]
    pub target_entity: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub cardinality: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub concept_uri: Option<String>,
}

impl RelationshipManifest {
    fn target_name(&self) -> Option<&str> {
        self.target_entity.as_deref().or(self.target.as_deref())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodelistManifest {
    pub id: String,
    pub scheme_iri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<String>,
    #[serde(default)]
    pub external_ref: Option<String>,
    #[serde(default)]
    pub concepts: Vec<CodelistConcept>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodelistConcept {
    pub code: String,
    #[serde(default)]
    pub iri: Option<String>,
    #[serde(default)]
    pub label: Option<LocalizedText>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    #[default]
    Public,
    Internal,
    Personal,
    Confidential,
    Secret,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessRights {
    Public,
    #[default]
    Restricted,
    NonPublic,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateFrequency {
    Continuous,
    Daily,
    Weekly,
    Termly,
    Monthly,
    Quarterly,
    Annual,
    Irregular,
    AsNeeded,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmsStatus {
    UnderDevelopment,
    Active,
    Completed,
    Deprecated,
    Withdrawn,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    String,
    Number,
    Integer,
    Boolean,
    Date,
    Timestamp,
    Code,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledMetadata {
    inner: Arc<CompiledMetadataInner>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledMetadataInner {
    pub catalog: CompiledCatalog,
    pub authorities: BTreeMap<String, CompiledAuthority>,
    pub public_services: BTreeMap<String, CompiledService>,
    pub data_services: BTreeMap<String, CompiledDataService>,
    pub forms: BTreeMap<String, CompiledForm>,
    pub requirements: BTreeMap<String, CompiledRequirement>,
    pub evidence_types: BTreeMap<String, CompiledEvidenceType>,
    pub datasets: BTreeMap<String, CompiledDataset>,
    pub codelists: BTreeMap<String, CompiledCodelist>,
    pub profiles: Vec<ProfileClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation: Option<FederationManifest>,
    pub evaluation_profiles: Vec<EvaluationProfileManifest>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledCatalog {
    pub id: String,
    pub title: String,
    pub description: String,
    pub publisher: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_iri: Option<String>,
    pub base_url: String,
    pub participant_id: String,
    pub conforms_to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_type: Option<String>,
    pub application_profiles: Vec<ApplicationProfile>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledAuthority {
    pub id: String,
    pub iri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spatial: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledService {
    pub id: String,
    pub iri: String,
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub competent_authority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    pub channels: Vec<CompiledChannel>,
    pub holds_requirements: Vec<String>,
    pub produces: Vec<String>,
    pub data_services: Vec<String>,
    pub forms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledChannel {
    pub id: String,
    pub iri: String,
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledDataService {
    pub id: String,
    pub iri: String,
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_description: Option<String>,
    pub serves_datasets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conforms_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledForm {
    pub id: String,
    pub iri: String,
    pub title: String,
    pub description: String,
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validates_with: Option<CompiledFormValidation>,
    pub sections: Vec<CompiledFormSection>,
    pub fields: Vec<CompiledFormField>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledFormValidation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shacl: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledFormSection {
    pub id: String,
    pub title: String,
    pub repeatable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_occurs: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_occurs: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visible_when: Option<FormVisibilityManifest>,
    pub fields: Vec<CompiledFormField>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledFormField {
    pub id: String,
    pub name: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widget_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concept: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_requirement: Option<String>,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_occurs: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_occurs: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visible_when: Option<FormVisibilityManifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<FormFulfillmentManifest>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledDataset {
    pub dataset_id: String,
    pub title: String,
    pub description: String,
    pub owner: String,
    pub sensitivity: Sensitivity,
    pub access_rights: AccessRights,
    pub update_frequency: UpdateFrequency,
    pub conforms_to: Vec<String>,
    pub applicable_legislation: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spatial_coverage: Option<String>,
    pub adms_status: AdmsStatus,
    pub public_services: Vec<CompiledPublicService>,
    pub policy: CompiledDatasetPolicy,
    pub evidence_offerings: BTreeMap<String, CompiledEvidenceOffering>,
    pub entities: BTreeMap<String, CompiledEntity>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledRequirement {
    pub id: String,
    pub iri: String,
    pub title: String,
    pub description: String,
    pub rdf_type: String,
    pub procedure_contexts: Vec<String>,
    pub reference_frameworks: Vec<CompiledReferenceFramework>,
    pub evidence_type_lists: Vec<CompiledEvidenceTypeList>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledEvidenceTypeList {
    pub id: String,
    pub iri: String,
    pub title: String,
    pub description: String,
    pub evidence_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledReferenceFramework {
    pub iri: String,
    pub identifier: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledEvidenceType {
    pub id: String,
    pub iri: String,
    pub title: String,
    pub description: String,
    pub proves: Vec<String>,
    pub requirement_iris: Vec<String>,
    pub information_concepts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledEvidenceOffering {
    pub id: String,
    pub iri: String,
    pub title: String,
    pub description: String,
    pub dataset_id: String,
    pub verification_request_schema_url: String,
    pub evidence_type: String,
    pub evidence_type_iri: String,
    pub requirement_iris: Vec<String>,
    pub information_concepts: Vec<String>,
    pub issuing_authority: CompiledIssuingAuthority,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<JurisdictionManifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level_of_assurance: Option<String>,
    pub entity: String,
    pub lookup_keys: Vec<String>,
    pub procedure_contexts: Vec<String>,
    pub access: EvidenceOfferingAccessManifest,
    pub policy: CompiledEvidenceOfferingPolicy,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledIssuingAuthority {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iri: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct CompiledEvidenceOfferingPolicy {
    pub purpose: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledDatasetPolicy {
    pub uid: String,
    pub assigner: String,
    pub profile: Vec<String>,
    pub permissions: Vec<CompiledPolicyRule>,
    pub prohibitions: Vec<CompiledPolicyRule>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledPolicyRule {
    pub action: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    pub constraints: Vec<CompiledPolicyConstraint>,
    pub duties: Vec<CompiledPolicyDuty>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledPolicyDuty {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    pub constraints: Vec<CompiledPolicyConstraint>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledPolicyConstraint {
    pub left_operand: String,
    pub operator: String,
    pub right_operand: CompiledPolicyOperandValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datatype: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum CompiledPolicyOperandValue {
    Iri(String),
    Literal(String),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledPublicService {
    pub id: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledEntity {
    pub name: String,
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concept_uri: Option<String>,
    pub primary_key: String,
    pub identifiers: Vec<IdentifierManifest>,
    pub fields: BTreeMap<String, CompiledField>,
    pub relationships: Vec<CompiledRelationship>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledField {
    pub name: String,
    pub field_type: FieldType,
    pub required: bool,
    pub constraints: FieldConstraints,
    pub concepts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codelist: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codelist_scheme_iri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledRelationship {
    pub name: String,
    pub target: String,
    pub cardinality: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concept_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledCodelist {
    pub id: String,
    pub scheme_iri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    pub concepts: Vec<CodelistConcept>,
}

impl CompiledMetadata {
    pub fn catalog(&self) -> &CompiledCatalog {
        &self.inner.catalog
    }

    pub fn datasets(&self) -> impl Iterator<Item = &CompiledDataset> {
        self.inner.datasets.values()
    }

    pub fn authorities(&self) -> impl Iterator<Item = &CompiledAuthority> {
        self.inner.authorities.values()
    }

    pub fn authority(&self, authority_id: &str) -> Option<&CompiledAuthority> {
        self.inner.authorities.get(authority_id)
    }

    pub fn public_services(&self) -> impl Iterator<Item = &CompiledService> {
        self.inner.public_services.values()
    }

    pub fn public_service(&self, service_id: &str) -> Option<&CompiledService> {
        self.inner.public_services.get(service_id)
    }

    pub fn data_services(&self) -> impl Iterator<Item = &CompiledDataService> {
        self.inner.data_services.values()
    }

    pub fn data_service(&self, data_service_id: &str) -> Option<&CompiledDataService> {
        self.inner.data_services.get(data_service_id)
    }

    pub fn forms(&self) -> impl Iterator<Item = &CompiledForm> {
        self.inner.forms.values()
    }

    pub fn form(&self, form_id: &str) -> Option<&CompiledForm> {
        self.inner.forms.get(form_id)
    }

    pub fn requirements(&self) -> impl Iterator<Item = &CompiledRequirement> {
        self.inner.requirements.values()
    }

    pub fn requirement(&self, requirement_id: &str) -> Option<&CompiledRequirement> {
        self.inner.requirements.get(requirement_id)
    }

    pub fn evidence_types(&self) -> impl Iterator<Item = &CompiledEvidenceType> {
        self.inner.evidence_types.values()
    }

    pub fn evidence_type(&self, evidence_type_id: &str) -> Option<&CompiledEvidenceType> {
        self.inner.evidence_types.get(evidence_type_id)
    }

    pub fn evidence_offerings(&self) -> impl Iterator<Item = &CompiledEvidenceOffering> {
        self.inner
            .datasets
            .values()
            .flat_map(|dataset| dataset.evidence_offerings.values())
    }

    pub fn evidence_offering(&self, offering_id: &str) -> Option<&CompiledEvidenceOffering> {
        self.inner
            .datasets
            .values()
            .find_map(|dataset| dataset.evidence_offerings.get(offering_id))
    }

    pub fn dataset(&self, dataset_id: &str) -> Option<&CompiledDataset> {
        self.inner.datasets.get(dataset_id)
    }

    pub fn codelist(&self, codelist_id: &str) -> Option<&CompiledCodelist> {
        self.inner.codelists.get(codelist_id)
    }

    pub fn codelists(&self) -> impl Iterator<Item = &CompiledCodelist> {
        self.inner.codelists.values()
    }

    pub fn profiles(&self) -> &[ProfileClaim] {
        &self.inner.profiles
    }

    pub fn federation(&self) -> Option<&FederationManifest> {
        self.inner.federation.as_ref()
    }

    pub fn evaluation_profiles(&self) -> &[EvaluationProfileManifest] {
        &self.inner.evaluation_profiles
    }

    pub fn filter(
        &self,
        predicate: impl Fn(&CompiledDataset, &CompiledEntity) -> bool,
    ) -> CompiledMetadata {
        let datasets: BTreeMap<String, CompiledDataset> = self
            .inner
            .datasets
            .iter()
            .filter_map(|(dataset_id, dataset)| {
                let entities = dataset
                    .entities
                    .iter()
                    .filter(|(_, entity)| predicate(dataset, entity))
                    .map(|(entity_name, entity)| (entity_name.clone(), entity.clone()))
                    .collect::<BTreeMap<_, _>>();
                let evidence_offerings = dataset
                    .evidence_offerings
                    .iter()
                    .filter(|(_, offering)| entities.contains_key(&offering.entity))
                    .map(|(offering_id, offering)| (offering_id.clone(), offering.clone()))
                    .collect::<BTreeMap<_, _>>();
                (!entities.is_empty()).then(|| {
                    let mut dataset = dataset.clone();
                    dataset.entities = entities;
                    dataset.evidence_offerings = evidence_offerings;
                    (dataset_id.clone(), dataset)
                })
            })
            .collect();
        let visible_evidence_types = datasets
            .values()
            .flat_map(|dataset| {
                dataset
                    .evidence_offerings
                    .values()
                    .map(|offering| offering.evidence_type.as_str())
            })
            .collect::<BTreeSet<_>>();
        let evidence_types = self
            .inner
            .evidence_types
            .iter()
            .filter(|(id, _)| visible_evidence_types.contains(id.as_str()))
            .map(|(id, evidence_type)| (id.clone(), evidence_type.clone()))
            .collect::<BTreeMap<_, _>>();
        let visible_requirements = evidence_types
            .values()
            .flat_map(|evidence_type| evidence_type.proves.iter().map(String::as_str))
            .collect::<BTreeSet<_>>();
        let requirements = self
            .inner
            .requirements
            .iter()
            .filter(|(id, _)| visible_requirements.contains(id.as_str()))
            .map(|(id, requirement)| (id.clone(), requirement.clone()))
            .collect::<BTreeMap<_, _>>();
        let visible_codelists = datasets
            .values()
            .flat_map(|dataset| dataset.entities.values())
            .flat_map(|entity| entity.fields.values())
            .filter_map(|field| field.codelist.as_deref())
            .collect::<BTreeSet<_>>();
        let codelists = self
            .inner
            .codelists
            .iter()
            .filter(|(id, _)| visible_codelists.contains(id.as_str()))
            .map(|(id, codelist)| (id.clone(), codelist.clone()))
            .collect::<BTreeMap<_, _>>();
        CompiledMetadata {
            inner: Arc::new(CompiledMetadataInner {
                catalog: self.inner.catalog.clone(),
                authorities: self.inner.authorities.clone(),
                public_services: self.inner.public_services.clone(),
                data_services: self.inner.data_services.clone(),
                forms: self.inner.forms.clone(),
                requirements,
                evidence_types,
                datasets,
                codelists,
                profiles: self.inner.profiles.clone(),
                federation: self.inner.federation.clone(),
                evaluation_profiles: self.inner.evaluation_profiles.clone(),
            }),
        }
    }
}

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("metadata.manifest.version_unsupported")]
    VersionUnsupported,
    #[error("metadata.manifest.validation_failed")]
    Validation { errors: Vec<ValidationError> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

impl ValidationError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

fn validate_federation(federation: Option<&FederationManifest>, errors: &mut Vec<ValidationError>) {
    let Some(federation) = federation else {
        return;
    };

    validate_non_empty(&federation.node_id, "federation.node_id", errors);
    validate_https_url(&federation.issuer, "federation.issuer", errors);
    validate_https_url(&federation.jwks_uri, "federation.jwks_uri", errors);
    validate_https_url(
        &federation.federation_api,
        "federation.federation_api",
        errors,
    );
    if !federation
        .supported_protocol_versions
        .iter()
        .any(|version| version == REGISTRY_NOTARY_FEDERATION_PROTOCOL)
    {
        errors.push(ValidationError::new(
            "federation.supported_protocol_versions",
            format!(
                "supported protocol versions must include {REGISTRY_NOTARY_FEDERATION_PROTOCOL}"
            ),
        ));
    }
    for (index, version) in federation.supported_protocol_versions.iter().enumerate() {
        validate_non_empty(
            version,
            format!("federation.supported_protocol_versions[{index}]"),
            errors,
        );
    }

    match did_web_host(&federation.node_id) {
        Some(did_web_host) => {
            if url_host(&federation.issuer)
                .is_some_and(|issuer_host| !did_web_host.eq_ignore_ascii_case(issuer_host.as_str()))
            {
                errors.push(ValidationError::new(
                    "federation.node_id",
                    "DID:web node id must bind to federation issuer host",
                ));
            }
        }
        None => errors.push(ValidationError::new(
            "federation.node_id",
            "federation node id must be a did:web identifier",
        )),
    }
}

fn validate_evaluation_profiles<'a>(
    manifest: &'a MetadataManifest,
    errors: &mut Vec<ValidationError>,
) -> BTreeSet<&'a str> {
    let mut ids = BTreeSet::new();
    let mut rulesets = BTreeSet::new();
    for (index, profile) in manifest.evaluation_profiles.iter().enumerate() {
        let path = format!("evaluation_profiles[{index}]");
        validate_id(&profile.id, format!("{path}.id"), errors);
        if !ids.insert(profile.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "evaluation profile id must be unique",
            ));
        }
        validate_non_empty(&profile.ruleset, format!("{path}.ruleset"), errors);
        if !profile.ruleset.trim().is_empty() && !rulesets.insert(profile.ruleset.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.ruleset"),
                "evaluation profile ruleset must be unique",
            ));
        }
        validate_id(&profile.claim_id, format!("{path}.claim_id"), errors);
        validate_id(
            &profile.subject_id_type,
            format!("{path}.subject_id_type"),
            errors,
        );
    }
    rulesets
}

fn validate_collection_limits(manifest: &MetadataManifest, errors: &mut Vec<ValidationError>) {
    validate_count_limit(manifest.profiles.len(), "profiles", MAX_PROFILES, errors);
    validate_count_limit(
        manifest.catalog.conforms_to.len(),
        "catalog.conforms_to",
        MAX_CATALOG_CONFORMS_TO,
        errors,
    );
    validate_count_limit(
        manifest.catalog.application_profiles.len(),
        "catalog.application_profiles",
        MAX_CATALOG_APPLICATION_PROFILES,
        errors,
    );
    validate_count_limit(
        manifest.evaluation_profiles.len(),
        "evaluation_profiles",
        MAX_TOP_LEVEL_COLLECTION_ITEMS,
        errors,
    );
    validate_count_limit(
        manifest.requirements.len(),
        "requirements",
        MAX_TOP_LEVEL_COLLECTION_ITEMS,
        errors,
    );
    validate_count_limit(
        manifest.evidence_types.len(),
        "evidence_types",
        MAX_TOP_LEVEL_COLLECTION_ITEMS,
        errors,
    );
    validate_count_limit(
        manifest.authorities.len(),
        "authorities",
        MAX_TOP_LEVEL_COLLECTION_ITEMS,
        errors,
    );
    validate_count_limit(
        manifest.public_services.len(),
        "public_services",
        MAX_TOP_LEVEL_COLLECTION_ITEMS,
        errors,
    );
    validate_count_limit(
        manifest.data_services.len(),
        "data_services",
        MAX_TOP_LEVEL_COLLECTION_ITEMS,
        errors,
    );
    validate_count_limit(
        manifest.forms.len(),
        "forms",
        MAX_TOP_LEVEL_COLLECTION_ITEMS,
        errors,
    );
    validate_count_limit(
        manifest.datasets.len(),
        "datasets",
        MAX_TOP_LEVEL_COLLECTION_ITEMS,
        errors,
    );
    validate_count_limit(
        manifest.codelists.len(),
        "codelists",
        MAX_TOP_LEVEL_COLLECTION_ITEMS,
        errors,
    );

    for (index, requirement) in manifest.requirements.iter().enumerate() {
        validate_count_limit(
            requirement.procedure_contexts.len(),
            format!("requirements[{index}].procedure_contexts"),
            MAX_URI_LIST_ITEMS,
            errors,
        );
    }
    for (index, evidence_type) in manifest.evidence_types.iter().enumerate() {
        validate_count_limit(
            evidence_type.information_concepts.len(),
            format!("evidence_types[{index}].information_concepts"),
            MAX_URI_LIST_ITEMS,
            errors,
        );
    }
    for (dataset_index, dataset) in manifest.datasets.iter().enumerate() {
        let dataset_path = format!("datasets[{dataset_index}]");
        validate_count_limit(
            dataset.conforms_to.len(),
            format!("{dataset_path}.conforms_to"),
            MAX_URI_LIST_ITEMS,
            errors,
        );
        validate_count_limit(
            dataset.applicable_legislation.len(),
            format!("{dataset_path}.applicable_legislation"),
            MAX_URI_LIST_ITEMS,
            errors,
        );
        validate_count_limit(
            dataset.entities.len(),
            format!("{dataset_path}.entities"),
            MAX_DATASET_ENTITIES,
            errors,
        );
        if let Some(policy) = dataset.policy.as_ref() {
            validate_count_limit(
                policy.profile.len(),
                format!("{dataset_path}.policy.profile"),
                MAX_URI_LIST_ITEMS,
                errors,
            );
        }
        for (offering_index, offering) in dataset.evidence_offerings.iter().enumerate() {
            let offering_path = format!("{dataset_path}.evidence_offerings[{offering_index}]");
            validate_count_limit(
                offering.procedure_contexts.len(),
                format!("{offering_path}.procedure_contexts"),
                MAX_URI_LIST_ITEMS,
                errors,
            );
            if let Some(policy) = offering.policy.as_ref() {
                validate_count_limit(
                    policy.purpose.len(),
                    format!("{offering_path}.policy.purpose"),
                    MAX_URI_LIST_ITEMS,
                    errors,
                );
            }
        }
        for (entity_index, entity) in dataset.entities.iter().enumerate() {
            let entity_path = format!("{dataset_path}.entities[{entity_index}]");
            validate_count_limit(
                entity.fields.len(),
                format!("{entity_path}.fields"),
                MAX_ENTITY_FIELDS,
                errors,
            );
            validate_count_limit(
                entity.relationships.len(),
                format!("{entity_path}.relationships"),
                MAX_ENTITY_RELATIONSHIPS,
                errors,
            );
            for (field_index, field) in entity.fields.iter().enumerate() {
                validate_count_limit(
                    field.concepts.len(),
                    format!("{entity_path}.fields[{field_index}].concepts"),
                    MAX_URI_LIST_ITEMS,
                    errors,
                );
            }
        }
    }
    for (index, codelist) in manifest.codelists.iter().enumerate() {
        validate_count_limit(
            codelist.concepts.len(),
            format!("codelists[{index}].concepts"),
            MAX_CODELIST_CONCEPTS,
            errors,
        );
    }
}

fn validate_count_limit(
    count: usize,
    path: impl Into<String>,
    max: usize,
    errors: &mut Vec<ValidationError>,
) {
    if count > max {
        errors.push(ValidationError::new(
            path,
            format!("collection must contain at most {max} items"),
        ));
    }
}

pub fn validate_manifest(manifest: &MetadataManifest) -> Result<(), MetadataError> {
    let mut errors = Vec::new();
    if manifest.schema_version != "registry-manifest/v1" {
        return Err(MetadataError::VersionUnsupported);
    }
    validate_collection_limits(manifest, &mut errors);
    if !errors.is_empty() {
        return Err(MetadataError::Validation { errors });
    }
    validate_vocabularies(&manifest.vocabularies, &mut errors);
    validate_id(&manifest.catalog.id, "catalog.id", &mut errors);
    validate_http_url(&manifest.catalog.base_url, "catalog.base_url", &mut errors);
    validate_non_empty(&manifest.catalog.title.text(), "catalog.title", &mut errors);
    validate_non_empty(
        &manifest.catalog.publisher.name,
        "catalog.publisher.name",
        &mut errors,
    );
    validate_optional_uri(
        manifest.catalog.publisher.iri.as_deref(),
        "catalog.publisher.iri",
        &manifest.vocabularies,
        &mut errors,
    );
    validate_optional_uri(
        manifest.catalog.publisher.authority_type.as_deref(),
        "catalog.publisher.authority_type",
        &manifest.vocabularies,
        &mut errors,
    );
    validate_uri_list(
        &manifest.catalog.conforms_to,
        "catalog.conforms_to",
        &manifest.vocabularies,
        &mut errors,
    );
    for (index, profile) in manifest.catalog.application_profiles.iter().enumerate() {
        validate_id(
            &profile.id,
            format!("catalog.application_profiles[{index}].id"),
            &mut errors,
        );
        validate_non_empty(
            &profile.version,
            format!("catalog.application_profiles[{index}].version"),
            &mut errors,
        );
        if !is_supported_application_profile(&profile.id) {
            errors.push(ValidationError::new(
                format!("catalog.application_profiles[{index}].id"),
                "application profile is not supported by the current renderer",
            ));
        }
    }

    let mut profile_ids = BTreeSet::new();
    for (index, profile) in manifest.profiles.iter().enumerate() {
        let path = format!("profiles[{index}]");
        validate_id(&profile.id, format!("{path}.id"), &mut errors);
        validate_non_empty(&profile.version, format!("{path}.version"), &mut errors);
        if !profile_ids.insert(profile.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "profile id must be unique",
            ));
        }
    }

    validate_federation(manifest.federation.as_ref(), &mut errors);
    let evaluation_profile_rulesets = validate_evaluation_profiles(manifest, &mut errors);
    let requirement_ids = validate_requirements(manifest, &mut errors);
    let evidence_type_ids = validate_evidence_types(manifest, &requirement_ids, &mut errors);
    validate_requirement_evidence_type_lists(manifest, &evidence_type_ids, &mut errors);
    let service_refs = validate_service_catalog(manifest, &requirement_ids, &mut errors);

    let mut codelist_ids = BTreeSet::new();
    for (index, codelist) in manifest.codelists.iter().enumerate() {
        let path = format!("codelists[{index}]");
        validate_id(&codelist.id, format!("{path}.id"), &mut errors);
        if !codelist_ids.insert(codelist.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "codelist id must be unique",
            ));
        }
        validate_uri(
            &codelist.scheme_iri,
            format!("{path}.scheme_iri"),
            &manifest.vocabularies,
            &mut errors,
        );
        validate_optional_uri(
            codelist.external_ref.as_deref(),
            format!("{path}.external_ref"),
            &manifest.vocabularies,
            &mut errors,
        );
        let mut concept_codes = BTreeSet::new();
        for (concept_index, concept) in codelist.concepts.iter().enumerate() {
            let concept_path = format!("{path}.concepts[{concept_index}]");
            validate_codelist_concept(concept, &concept_path, &mut concept_codes, &mut errors);
            validate_optional_uri(
                concept.iri.as_deref(),
                format!("{concept_path}.iri"),
                &manifest.vocabularies,
                &mut errors,
            );
        }
    }

    if manifest.federation.is_none()
        && manifest.datasets.iter().any(|dataset| {
            dataset
                .evidence_offerings
                .iter()
                .any(|offering| offering.access.kind == "registry-notary")
        })
    {
        errors.push(ValidationError::new(
            "federation",
            "registry-notary access requires a top-level federation block",
        ));
    }

    let mut dataset_ids = BTreeSet::new();
    let mut offering_ids = BTreeSet::new();
    for (dataset_index, dataset) in manifest.datasets.iter().enumerate() {
        let path = format!("datasets[{dataset_index}]");
        validate_id(&dataset.id, format!("{path}.id"), &mut errors);
        if !dataset_ids.insert(dataset.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "dataset id must be unique",
            ));
        }
        validate_non_empty(&dataset.title.text(), format!("{path}.title"), &mut errors);
        validate_uri_list(
            &dataset.conforms_to,
            format!("{path}.conforms_to"),
            &manifest.vocabularies,
            &mut errors,
        );
        validate_uri_list(
            &dataset.applicable_legislation,
            format!("{path}.applicable_legislation"),
            &manifest.vocabularies,
            &mut errors,
        );
        validate_optional_uri(
            dataset.spatial_coverage.as_deref(),
            format!("{path}.spatial_coverage"),
            &manifest.vocabularies,
            &mut errors,
        );
        let mut dataset_public_service_ids = BTreeSet::new();
        for (service_index, service) in dataset.public_services.iter().enumerate() {
            let service_path = format!("{path}.public_services[{service_index}]");
            validate_non_empty(
                &service.title.text(),
                format!("{service_path}.title"),
                &mut errors,
            );
            if let Some(service_id) = service.id.as_deref() {
                validate_dataset_public_service_id(
                    service_id,
                    format!("{service_path}.id"),
                    &mut errors,
                );
                if !dataset_public_service_ids.insert(service_id) {
                    errors.push(ValidationError::new(
                        format!("{service_path}.id"),
                        "dataset public service id must be unique within a dataset",
                    ));
                }
            }
        }
        validate_dataset_policy(
            dataset.policy.as_ref(),
            &path,
            &manifest.vocabularies,
            &mut errors,
        );
        validate_entities(
            dataset,
            &path,
            &codelist_ids,
            &manifest.vocabularies,
            &mut errors,
        );
        validate_evidence_offerings(
            dataset,
            &path,
            &evidence_type_ids,
            &evaluation_profile_rulesets,
            &mut offering_ids,
            &manifest.vocabularies,
            &mut errors,
        );
    }
    validate_service_catalog_dataset_refs(manifest, &service_refs, &dataset_ids, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(MetadataError::Validation { errors })
    }
}

pub fn compile_manifest(manifest: &MetadataManifest) -> Result<CompiledMetadata, MetadataError> {
    validate_manifest(manifest)?;
    let base_url = normalized_base_url(&manifest.catalog.base_url);
    let codelists = manifest
        .codelists
        .iter()
        .map(|codelist| {
            (
                codelist.id.clone(),
                CompiledCodelist {
                    id: codelist.id.clone(),
                    scheme_iri: expand_uri(&codelist.scheme_iri, &manifest.vocabularies)
                        .unwrap_or_else(|| codelist.scheme_iri.clone()),
                    version: codelist.version.clone(),
                    valid_from: codelist.valid_from.clone(),
                    valid_to: codelist.valid_to.clone(),
                    external_ref: codelist
                        .external_ref
                        .as_deref()
                        .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
                    concepts: codelist.concepts.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let requirements = manifest
        .requirements
        .iter()
        .map(|requirement| {
            (
                requirement.id.clone(),
                compile_requirement(manifest, &base_url, requirement),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let evidence_types = manifest
        .evidence_types
        .iter()
        .map(|evidence_type| {
            (
                evidence_type.id.clone(),
                compile_evidence_type(manifest, &base_url, &requirements, evidence_type),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let authorities = manifest
        .authorities
        .iter()
        .map(|authority| {
            (
                authority.id.clone(),
                compile_authority(manifest, &base_url, authority),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let data_services = manifest
        .data_services
        .iter()
        .map(|data_service| {
            (
                data_service.id.clone(),
                compile_data_service(manifest, &base_url, data_service),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let forms = manifest
        .forms
        .iter()
        .map(|form| (form.id.clone(), compile_form(manifest, &base_url, form)))
        .collect::<BTreeMap<_, _>>();
    let public_services = manifest
        .public_services
        .iter()
        .map(|service| {
            (
                service.id.clone(),
                compile_service(manifest, &base_url, service),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let datasets = manifest
        .datasets
        .iter()
        .map(|dataset| {
            (
                dataset.id.clone(),
                compile_dataset(manifest, &base_url, &codelists, &evidence_types, dataset),
            )
        })
        .collect();
    let publisher = &manifest.catalog.publisher;
    Ok(CompiledMetadata {
        inner: Arc::new(CompiledMetadataInner {
            catalog: CompiledCatalog {
                id: manifest.catalog.id.clone(),
                title: manifest.catalog.title.text(),
                description: manifest
                    .catalog
                    .description
                    .as_ref()
                    .map(LocalizedText::text)
                    .unwrap_or_default(),
                publisher: publisher.name.clone(),
                publisher_iri: publisher
                    .iri
                    .as_deref()
                    .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
                base_url: base_url.clone(),
                participant_id: manifest
                    .catalog
                    .participant_id
                    .clone()
                    .unwrap_or_else(|| base_url.clone()),
                conforms_to: manifest
                    .catalog
                    .conforms_to
                    .iter()
                    .filter_map(|iri| expand_uri(iri, &manifest.vocabularies))
                    .collect(),
                authority_type: publisher
                    .authority_type
                    .as_deref()
                    .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
                application_profiles: manifest.catalog.application_profiles.clone(),
            },
            authorities,
            public_services,
            data_services,
            forms,
            requirements,
            evidence_types,
            datasets,
            codelists,
            profiles: manifest.profiles.clone(),
            federation: manifest.federation.clone(),
            evaluation_profiles: manifest.evaluation_profiles.clone(),
        }),
    })
}

pub fn render_catalog(compiled: &CompiledMetadata) -> Value {
    let mut catalog = json!({
        "schema_version": CATALOG_SCHEMA_VERSION,
        "id": compiled.catalog().id,
        "title": compiled.catalog().title,
        "description": compiled.catalog().description,
        "publisher": compiled.catalog().publisher,
        "base_url": compiled.catalog().base_url,
        "participant_id": compiled.catalog().participant_id,
        "conforms_to": compiled.catalog().conforms_to,
        "application_profiles": compiled.catalog().application_profiles,
        "datasets": compiled.datasets().map(catalog_dataset_json).collect::<Vec<_>>(),
        "profiles": compiled.profiles(),
    });
    let requirements = compiled.requirements().collect::<Vec<_>>();
    if !requirements.is_empty() {
        catalog["requirements"] = json!(requirements);
    }
    let evidence_types = compiled.evidence_types().collect::<Vec<_>>();
    if !evidence_types.is_empty() {
        catalog["evidence_types"] = json!(evidence_types);
    }
    let authorities = compiled.authorities().collect::<Vec<_>>();
    if !authorities.is_empty() {
        catalog["authorities"] = json!(authorities);
    }
    let public_services = compiled.public_services().collect::<Vec<_>>();
    if !public_services.is_empty() {
        catalog["public_services"] = json!(public_services);
    }
    let data_services = compiled.data_services().collect::<Vec<_>>();
    if !data_services.is_empty() {
        catalog["data_services"] = json!(data_services);
    }
    let forms = compiled.forms().collect::<Vec<_>>();
    if !forms.is_empty() {
        catalog["forms"] = json!(forms);
    }
    let evidence_offerings = compiled.evidence_offerings().collect::<Vec<_>>();
    if !evidence_offerings.is_empty() {
        catalog["evidence_offerings"] = json!(evidence_offerings);
    }
    if let Some(federation) = compiled.federation() {
        catalog["federation"] = json!(federation);
    }
    if !compiled.evaluation_profiles().is_empty() {
        catalog["evaluation_profiles"] = json!(compiled.evaluation_profiles());
    }
    catalog
}

pub fn render_evidence_offerings(compiled: &CompiledMetadata) -> Value {
    json!({
        "schema_version": EVIDENCE_OFFERINGS_SCHEMA_VERSION,
        "evidence_offerings": compiled.evidence_offerings().collect::<Vec<_>>(),
    })
}

pub fn render_evidence_offering(compiled: &CompiledMetadata, offering_id: &str) -> Option<Value> {
    compiled
        .evidence_offering(offering_id)
        .map(|offering| with_schema_version(json!(offering), EVIDENCE_OFFERING_SCHEMA_VERSION))
}

fn with_schema_version(mut value: Value, schema_version: &str) -> Value {
    value["schema_version"] = json!(schema_version);
    value
}

pub fn render_base_dcat(compiled: &CompiledMetadata) -> Value {
    let mut catalog = json!({
        "@context": standards_jsonld_context(jsonld_context_with_policy_terms()),
        "@id": format!("{}/metadata/dcat.jsonld", compiled.catalog().base_url),
        "@type": "dcat:Catalog",
        "dcterms:identifier": compiled.catalog().id,
        "dcterms:title": compiled.catalog().title,
        "dcterms:description": compiled.catalog().description,
        "dcterms:publisher": publisher_agent(compiled.catalog()),
        "dcat:landingPage": compiled.catalog().base_url,
        "dcat:themeTaxonomy": [EU_DATA_THEME_SCHEME, EUROVOC_THEME_SCHEME],
        "dcterms:conformsTo": compiled.catalog().conforms_to,
        "dcat:dataset": compiled
            .datasets()
            .map(|dataset| base_dcat_dataset(compiled, dataset))
            .collect::<Vec<_>>(),
    });
    let mut included = standard_reference_nodes(compiled);
    included.extend(dcat_range_reference_nodes(&catalog));
    append_included_nodes(&mut catalog, included);
    catalog
}

pub fn render_breg_dcat_ap(compiled: &CompiledMetadata) -> Value {
    let mut catalog = render_base_dcat(compiled);
    catalog["@id"] = json!(format!(
        "{}/metadata/dcat.bregdcat-ap.jsonld",
        compiled.catalog().base_url
    ));
    catalog["dcat:dataset"] = Value::Array(
        compiled
            .datasets()
            .map(|dataset| breg_dcat_dataset(compiled, dataset))
            .collect(),
    );
    let public_services = compiled
        .datasets()
        .flat_map(|dataset| {
            dataset
                .public_services
                .iter()
                .map(move |service| public_service_node(compiled.catalog(), dataset, service))
        })
        .collect::<Vec<_>>();
    let has_public_service_terms = !public_services.is_empty()
        || compiled
            .datasets()
            .any(|dataset| !dataset.applicable_legislation.is_empty());
    let mut included = standard_reference_nodes(compiled);
    included.extend(public_services);
    included.extend(dcat_range_reference_nodes(&catalog));
    if has_public_service_terms || compiled.evidence_offerings().next().is_some() {
        catalog["@context"] = standards_jsonld_context(jsonld_context_with_evidence_terms());
    }
    append_included_nodes(&mut catalog, included);
    append_graph_nodes(&mut catalog, evidence_jsonld_nodes(compiled));
    catalog["sh:shapesGraph"] = Value::Array(
        compiled
            .datasets()
            .flat_map(|dataset| {
                dataset
                    .entities
                    .values()
                    .map(move |entity| entity_shape(compiled, dataset, entity))
            })
            .collect(),
    );
    catalog
}

pub fn render_cpsv_ap(compiled: &CompiledMetadata) -> Value {
    let public_services = compiled
        .public_services()
        .map(|service| iri_object(&service.iri))
        .chain(compiled.datasets().flat_map(|dataset| {
            dataset
                .public_services
                .iter()
                .map(|service| iri_object(&service.id))
        }))
        .collect::<Vec<_>>();
    let data_services = compiled
        .data_services()
        .map(|service| iri_object(&service.iri))
        .collect::<Vec<_>>();
    let mut catalog = json!({
        "@context": standards_jsonld_context(jsonld_context_with_service_catalogue_terms()),
        "@id": format!("{}/metadata/cpsv-ap", compiled.catalog().base_url),
        "@type": "dcat:Catalog",
        "dcterms:identifier": compiled.catalog().id,
        "dcterms:title": compiled.catalog().title,
        "dcterms:description": compiled.catalog().description,
        "dcterms:publisher": publisher_agent(compiled.catalog()),
        "dcterms:conformsTo": "https://semiceu.github.io/CPSV-AP/releases/3.2.0/",
        "dcterms:hasPart": public_services,
        "dcat:service": data_services,
    });
    let mut graph = Vec::new();
    graph.extend(compiled.authorities().map(service_authority_node));
    graph.extend(
        compiled
            .public_services()
            .map(|service| service_catalogue_public_service_node(compiled, service)),
    );
    graph.extend(compiled.datasets().flat_map(|dataset| {
        dataset
            .public_services
            .iter()
            .map(|service| public_service_node(compiled.catalog(), dataset, service))
    }));
    graph.extend(
        compiled
            .public_services()
            .flat_map(|service| service.channels.iter().map(service_channel_node)),
    );
    graph.extend(
        compiled
            .data_services()
            .map(|service| data_service_node(compiled, service)),
    );
    graph.extend(compiled.forms().map(|form| form_node(compiled, form)));
    graph.extend(evidence_jsonld_nodes(compiled));
    let output_dataset_ids = compiled
        .public_services()
        .flat_map(|service| service.produces.iter().cloned())
        .chain(
            compiled
                .datasets()
                .filter(|dataset| !dataset.public_services.is_empty())
                .map(|dataset| dataset.dataset_id.clone()),
        )
        .collect::<BTreeSet<_>>();
    graph.extend(
        compiled
            .datasets()
            .filter(|dataset| output_dataset_ids.contains(&dataset.dataset_id))
            .map(|dataset| cpsv_output_dataset_node(compiled, dataset)),
    );
    let served_dataset_ids = compiled
        .data_services()
        .flat_map(|service| service.serves_datasets.iter().cloned())
        .collect::<BTreeSet<_>>();
    graph.extend(
        compiled
            .datasets()
            .filter(|dataset| {
                served_dataset_ids.contains(&dataset.dataset_id)
                    && !output_dataset_ids.contains(&dataset.dataset_id)
            })
            .map(|dataset| base_dcat_dataset(compiled, dataset)),
    );
    catalog["@graph"] = Value::Array(graph);
    catalog
}

pub fn render_policy_collection(compiled: &CompiledMetadata) -> Value {
    json!({
        "schema_version": POLICY_COLLECTION_SCHEMA_VERSION,
        "@context": jsonld_context_with_policy_terms(),
        "@id": format!("{}/metadata/policies", compiled.catalog().base_url),
        "dcterms:title": "Dataset access policies",
        "dcterms:isPartOf": format!("{}/metadata/dcat.jsonld", compiled.catalog().base_url),
        "@graph": compiled
            .datasets()
            .map(render_dataset_policy)
            .collect::<Vec<_>>(),
    })
}

pub fn render_dataset_policy_document(
    compiled: &CompiledMetadata,
    dataset_id: &str,
) -> Option<Value> {
    let mut policy = render_dataset_policy(compiled.dataset(dataset_id)?);
    policy["@context"] = json!(jsonld_context_with_policy_terms());
    policy["schema_version"] = json!(POLICY_SCHEMA_VERSION);
    Some(policy)
}

fn dcat_range_reference_nodes(document: &Value) -> Vec<Value> {
    let mut typed_iris = BTreeSet::new();
    collect_typed_reference_iris(
        document,
        "dcterms:accessRights",
        "dcterms:RightsStatement",
        &mut typed_iris,
    );
    collect_typed_reference_iris(
        document,
        "dcterms:accrualPeriodicity",
        "dcterms:Frequency",
        &mut typed_iris,
    );
    collect_typed_reference_iris(
        document,
        "dcat:landingPage",
        "foaf:Document",
        &mut typed_iris,
    );
    collect_typed_reference_iris(
        document,
        "dcat:mediaType",
        "dcterms:MediaType",
        &mut typed_iris,
    );
    collect_typed_reference_iris(
        document,
        "dcat:themeTaxonomy",
        "skos:ConceptScheme",
        &mut typed_iris,
    );
    collect_typed_reference_iris(
        document,
        "dcterms:spatial",
        "dcterms:Location",
        &mut typed_iris,
    );
    collect_typed_reference_iris(
        document,
        "dcterms:conformsTo",
        "dcterms:Standard",
        &mut typed_iris,
    );
    let mut controlled_terms = BTreeMap::new();
    collect_controlled_reference_iris(
        document,
        "adms:status",
        "http://purl.org/adms/status/1.0",
        &mut controlled_terms,
    );
    collect_controlled_reference_iris(
        document,
        "dcat:theme",
        EU_DATA_THEME_SCHEME,
        &mut controlled_terms,
    );
    collect_controlled_reference_iris(
        document,
        "dcatap:availability",
        "http://data.europa.eu/r5r/availability/1.0",
        &mut controlled_terms,
    );
    collect_controlled_reference_iris(
        document,
        "dcterms:accessRights",
        "http://publications.europa.eu/resource/authority/access-right",
        &mut controlled_terms,
    );
    collect_controlled_reference_iris(
        document,
        "dcterms:accrualPeriodicity",
        "http://publications.europa.eu/resource/authority/frequency",
        &mut controlled_terms,
    );
    collect_controlled_reference_iris(
        document,
        "dcterms:format",
        "http://publications.europa.eu/resource/authority/file-type",
        &mut controlled_terms,
    );
    collect_controlled_reference_iris(
        document,
        "dcterms:type",
        "http://purl.org/adms/publishertype/1.0",
        &mut controlled_terms,
    );
    let controlled_schemes = controlled_terms.values().cloned().collect::<BTreeSet<_>>();
    typed_iris
        .into_iter()
        .map(|(iri, node_type)| match node_type.as_str() {
            "skos:ConceptScheme" => json!({
                "@id": iri,
                "@type": node_type,
                "dcterms:title": controlled_term_label(&iri),
                "skos:prefLabel": controlled_term_label(&iri),
            }),
            _ => json!({
                "@id": iri,
                "@type": node_type,
            }),
        })
        .chain(controlled_schemes.into_iter().map(|scheme| {
            json!({
                "@id": scheme,
                "@type": "skos:ConceptScheme",
                "dcterms:title": controlled_term_label(&scheme),
                "skos:prefLabel": controlled_term_label(&scheme),
            })
        }))
        .chain(controlled_terms.into_iter().map(|(iri, scheme)| {
            json!({
                "@id": iri,
                "@type": "skos:Concept",
                "skos:inScheme": scheme,
                "skos:prefLabel": controlled_term_label(&iri),
            })
        }))
        .collect()
}

fn collect_typed_reference_iris(
    value: &Value,
    predicate: &str,
    node_type: &str,
    iris: &mut BTreeSet<(String, String)>,
) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get(predicate) {
                let mut values = BTreeSet::new();
                collect_string_values(reference, &mut values);
                iris.extend(
                    values
                        .into_iter()
                        .map(|value| (value, node_type.to_string())),
                );
            }
            for nested in object.values() {
                collect_typed_reference_iris(nested, predicate, node_type, iris);
            }
        }
        Value::Array(values) => {
            for nested in values {
                collect_typed_reference_iris(nested, predicate, node_type, iris);
            }
        }
        _ => {}
    }
}

fn collect_controlled_reference_iris(
    value: &Value,
    predicate: &str,
    scheme: &str,
    iris: &mut BTreeMap<String, String>,
) {
    let mut values = BTreeSet::new();
    collect_reference_values(value, predicate, &mut values);
    for value in values {
        iris.insert(value, scheme.to_string());
    }
}

fn collect_reference_values(value: &Value, predicate: &str, values: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get(predicate) {
                collect_string_values(reference, values);
            }
            for nested in object.values() {
                collect_reference_values(nested, predicate, values);
            }
        }
        Value::Array(items) => {
            for nested in items {
                collect_reference_values(nested, predicate, values);
            }
        }
        _ => {}
    }
}

fn collect_string_values(value: &Value, values: &mut BTreeSet<String>) {
    match value {
        Value::String(value) => {
            values.insert(value.clone());
        }
        Value::Array(items) => {
            for item in items {
                collect_string_values(item, values);
            }
        }
        Value::Object(object) => {
            if let Some(id) = object.get("@id").and_then(Value::as_str) {
                values.insert(id.to_string());
            }
        }
        _ => {}
    }
}

fn controlled_term_label(iri: &str) -> String {
    iri.rsplit(&['/', '#'][..])
        .find(|part| !part.is_empty())
        .unwrap_or(iri)
        .replace(['_', '-'], " ")
}

fn standard_reference_nodes(compiled: &CompiledMetadata) -> Vec<Value> {
    // `dcterms:conformsTo` has a standards/profile meaning in DCAT-AP
    // validation. If a value is not intended to identify a standard or
    // application profile, publishers should not place it in `conforms_to`.
    let mut iris = BTreeSet::new();
    iris.extend(compiled.catalog().conforms_to.iter().cloned());
    for dataset in compiled.datasets() {
        iris.extend(dataset.conforms_to.iter().cloned());
    }
    iris.into_iter()
        .map(|iri| {
            json!({
                "@id": iri,
                "@type": "dcterms:Standard",
            })
        })
        .collect()
}

fn append_included_nodes(document: &mut Value, nodes: Vec<Value>) {
    if nodes.is_empty() {
        return;
    }
    let mut existing = document
        .get_mut("@included")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .unwrap_or_default();
    let mut seen = existing
        .iter()
        .filter_map(included_node_key)
        .collect::<BTreeSet<_>>();
    for node in nodes {
        if included_node_key(&node).is_some_and(|key| seen.insert(key)) {
            existing.push(node);
        }
    }
    document["@included"] = Value::Array(existing);
}

fn append_graph_nodes(document: &mut Value, nodes: Vec<Value>) {
    if nodes.is_empty() {
        return;
    }
    let mut existing = document
        .get_mut("@graph")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .unwrap_or_default();
    let mut seen = existing
        .iter()
        .filter_map(included_node_key)
        .collect::<BTreeSet<_>>();
    for node in nodes {
        if included_node_key(&node).is_some_and(|key| seen.insert(key)) {
            existing.push(node);
        }
    }
    document["@graph"] = Value::Array(existing);
}

fn included_node_key(node: &Value) -> Option<(String, String)> {
    let object = node.as_object()?;
    Some((
        object.get("@id")?.as_str()?.to_string(),
        object.get("@type")?.as_str()?.to_string(),
    ))
}

pub fn render_dcat_profile(compiled: &CompiledMetadata, profile: &str) -> Option<Value> {
    match profile {
        "bregdcat-ap" => Some(render_breg_dcat_ap(compiled)),
        "dcat" | "dcat-ap" => Some(render_base_dcat(compiled)),
        _ => None,
    }
}

pub fn render_shacl(compiled: &CompiledMetadata) -> Value {
    json!({
        "schema_version": SHACL_SCHEMA_VERSION,
        "@context": jsonld_context(),
        "@graph": compiled
            .datasets()
            .flat_map(|dataset| dataset.entities.values().map(move |entity| entity_shape(compiled, dataset, entity)))
            .chain(compiled.codelists().map(manifest_codelist_shape))
            .collect::<Vec<_>>(),
    })
}

/// Consumed by Registry Relay's metadata API (`src/api/metadata.rs`) to render a
/// per-entity SHACL document.
pub fn render_entity_shacl(
    compiled: &CompiledMetadata,
    dataset_id: &str,
    entity_name: &str,
) -> Option<Value> {
    let dataset = compiled.dataset(dataset_id)?;
    let entity = dataset.entities.get(entity_name)?;
    Some(json!({
        "@context": jsonld_context(),
        "shape": entity_shape(compiled, dataset, entity),
    }))
}

pub fn render_entity_schema_draft_2020_12(
    compiled: &CompiledMetadata,
    dataset_id: &str,
    entity_name: &str,
) -> Option<Value> {
    let dataset = compiled.dataset(dataset_id)?;
    let entity = dataset.entities.get(entity_name)?;
    Some(entity_json_schema(compiled, dataset, entity))
}

pub fn render_form_schema_draft_2020_12(
    compiled: &CompiledMetadata,
    form_id: &str,
) -> Option<Value> {
    let form = compiled.form(form_id)?;
    Some(form_json_schema(form))
}

pub fn render_ogc_records_items(compiled: &CompiledMetadata) -> Value {
    let features = compiled
        .datasets()
        .map(record_feature_json)
        .collect::<Vec<_>>();
    json!({
        "schema_version": OGC_RECORDS_SCHEMA_VERSION,
        "type": "FeatureCollection",
        "numberMatched": features.len(),
        "numberReturned": features.len(),
        "features": features,
    })
}

/// Consumed by Registry Relay's metadata + OGC Records API
/// (`src/api/metadata.rs`, `src/api/ogc/records.rs`) to render a single record.
pub fn render_ogc_records_item(compiled: &CompiledMetadata, record_id: &str) -> Option<Value> {
    compiled.dataset(record_id).map(record_feature_json)
}

// OGC API Records collection / conformance scaffolding. Currently unused
// inside the workspace (Registry Relay serves its own collection / conformance
// documents). Kept as `pub(crate)` so the renderer set stays internally
// complete; the `#[allow(dead_code)]` will lift the moment a caller is added.
#[allow(dead_code)]
pub(crate) fn render_ogc_records_collections() -> Value {
    json!({ "collections": [records_collection_json()] })
}

#[allow(dead_code)]
pub(crate) fn render_ogc_records_collection(collection_id: &str) -> Option<Value> {
    (collection_id == DATASETS_COLLECTION_ID).then(records_collection_json)
}

#[allow(dead_code)]
pub(crate) fn render_ogc_records_conformance() -> Value {
    json!({ "conformsTo": ogc_records_conformance() })
}

fn validate_requirements<'a>(
    manifest: &'a MetadataManifest,
    errors: &mut Vec<ValidationError>,
) -> BTreeSet<&'a str> {
    let mut ids = BTreeSet::new();
    for (index, requirement) in manifest.requirements.iter().enumerate() {
        let path = format!("requirements[{index}]");
        validate_id(&requirement.id, format!("{path}.id"), errors);
        if !ids.insert(requirement.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "requirement id must be unique",
            ));
        }
        validate_optional_uri(
            requirement.iri.as_deref(),
            format!("{path}.iri"),
            &manifest.vocabularies,
            errors,
        );
        validate_non_empty(&requirement.title.text(), format!("{path}.title"), errors);
        validate_optional_uri(
            requirement.rdf_type.as_deref(),
            format!("{path}.rdf_type"),
            &manifest.vocabularies,
            errors,
        );
        validate_uri_or_code_list(
            &requirement.procedure_contexts,
            format!("{path}.procedure_contexts"),
            &manifest.vocabularies,
            errors,
        );
        for (framework_index, framework) in requirement.reference_frameworks.iter().enumerate() {
            let framework_path = format!("{path}.reference_frameworks[{framework_index}]");
            validate_uri(
                &framework.iri,
                format!("{framework_path}.iri"),
                &manifest.vocabularies,
                errors,
            );
            validate_non_empty(
                &framework.identifier,
                format!("{framework_path}.identifier"),
                errors,
            );
        }
    }
    ids
}

fn validate_evidence_types<'a>(
    manifest: &'a MetadataManifest,
    requirement_ids: &BTreeSet<&str>,
    errors: &mut Vec<ValidationError>,
) -> BTreeSet<&'a str> {
    let mut ids = BTreeSet::new();
    for (index, evidence_type) in manifest.evidence_types.iter().enumerate() {
        let path = format!("evidence_types[{index}]");
        validate_id(&evidence_type.id, format!("{path}.id"), errors);
        if !ids.insert(evidence_type.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "evidence type id must be unique",
            ));
        }
        validate_optional_uri(
            evidence_type.iri.as_deref(),
            format!("{path}.iri"),
            &manifest.vocabularies,
            errors,
        );
        validate_non_empty(&evidence_type.title.text(), format!("{path}.title"), errors);
        if evidence_type.proves.is_empty() {
            errors.push(ValidationError::new(
                format!("{path}.proves"),
                "evidence type must prove at least one requirement",
            ));
        }
        for (proves_index, requirement_id) in evidence_type.proves.iter().enumerate() {
            validate_id(
                requirement_id,
                format!("{path}.proves[{proves_index}]"),
                errors,
            );
            if !requirement_ids.contains(requirement_id.as_str()) {
                errors.push(ValidationError::new(
                    format!("{path}.proves[{proves_index}]"),
                    "evidence type must prove a known requirement",
                ));
            }
        }
        validate_uri_list(
            &evidence_type.information_concepts,
            format!("{path}.information_concepts"),
            &manifest.vocabularies,
            errors,
        );
    }
    ids
}

fn validate_requirement_evidence_type_lists(
    manifest: &MetadataManifest,
    evidence_type_ids: &BTreeSet<&str>,
    errors: &mut Vec<ValidationError>,
) {
    let evidence_type_proofs = manifest
        .evidence_types
        .iter()
        .map(|evidence_type| {
            (
                evidence_type.id.as_str(),
                evidence_type
                    .proves
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for (requirement_index, requirement) in manifest.requirements.iter().enumerate() {
        let total_lists = requirement.evidence_type_lists.len();
        let mut list_ids = BTreeSet::new();
        for (list_index, list) in requirement.evidence_type_lists.iter().enumerate() {
            let path =
                format!("requirements[{requirement_index}].evidence_type_lists[{list_index}]");
            let list_id = evidence_type_list_manifest_id(list, list_index, total_lists);
            validate_id(&list_id, format!("{path}.id"), errors);
            if !list_ids.insert(list_id) {
                errors.push(ValidationError::new(
                    format!("{path}.id"),
                    "evidence type list id must be unique per requirement",
                ));
            }
            if let Some(title) = list.title.as_ref() {
                validate_non_empty(&title.text(), format!("{path}.title"), errors);
            }
            if list.evidence_types.is_empty() {
                errors.push(ValidationError::new(
                    format!("{path}.evidence_types"),
                    "evidence type list must include at least one evidence type",
                ));
            }

            let mut listed_evidence_types = BTreeSet::new();
            for (evidence_type_index, evidence_type_id) in list.evidence_types.iter().enumerate() {
                let evidence_type_path = format!("{path}.evidence_types[{evidence_type_index}]");
                validate_id(evidence_type_id, &evidence_type_path, errors);
                if !listed_evidence_types.insert(evidence_type_id.as_str()) {
                    errors.push(ValidationError::new(
                        &evidence_type_path,
                        "evidence type id must be unique within an evidence type list",
                    ));
                }
                if !evidence_type_ids.contains(evidence_type_id.as_str()) {
                    errors.push(ValidationError::new(
                        &evidence_type_path,
                        "evidence type list must reference a known evidence type",
                    ));
                    continue;
                }
                if !evidence_type_proofs
                    .get(evidence_type_id.as_str())
                    .is_some_and(|proves| proves.contains(requirement.id.as_str()))
                {
                    errors.push(ValidationError::new(
                        &evidence_type_path,
                        "listed evidence type must prove the owning requirement",
                    ));
                }
            }
        }
    }
}

struct ServiceCatalogRefs<'a> {
    service_ids: BTreeSet<&'a str>,
    data_service_ids: BTreeSet<&'a str>,
    form_ids: BTreeSet<&'a str>,
    channel_ids: BTreeSet<String>,
}

fn validate_service_catalog<'a>(
    manifest: &'a MetadataManifest,
    requirement_ids: &BTreeSet<&str>,
    errors: &mut Vec<ValidationError>,
) -> ServiceCatalogRefs<'a> {
    let mut authority_ids = BTreeSet::new();
    for (index, authority) in manifest.authorities.iter().enumerate() {
        let path = format!("authorities[{index}]");
        validate_id(&authority.id, format!("{path}.id"), errors);
        if !authority_ids.insert(authority.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "authority id must be unique",
            ));
        }
        validate_optional_uri(
            authority.iri.as_deref(),
            format!("{path}.iri"),
            &manifest.vocabularies,
            errors,
        );
        validate_non_empty(&authority.name, format!("{path}.name"), errors);
        validate_optional_uri(
            authority.authority_type.as_deref(),
            format!("{path}.authority_type"),
            &manifest.vocabularies,
            errors,
        );
        validate_optional_uri(
            authority.spatial.as_deref(),
            format!("{path}.spatial"),
            &manifest.vocabularies,
            errors,
        );
    }

    let mut service_ids = BTreeSet::new();
    let mut channel_ids = BTreeSet::new();
    for (index, service) in manifest.public_services.iter().enumerate() {
        let path = format!("public_services[{index}]");
        validate_id(&service.id, format!("{path}.id"), errors);
        if !service_ids.insert(service.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "public service id must be unique",
            ));
        }
        validate_optional_uri(
            service.iri.as_deref(),
            format!("{path}.iri"),
            &manifest.vocabularies,
            errors,
        );
        validate_non_empty(&service.title.text(), format!("{path}.title"), errors);
        match service.description.as_ref() {
            Some(description) => {
                validate_non_empty(&description.text(), format!("{path}.description"), errors);
            }
            None => errors.push(ValidationError::new(
                format!("{path}.description"),
                "public service description is required",
            )),
        }
        if let Some(authority_id) = service.competent_authority.as_deref() {
            validate_id(authority_id, format!("{path}.competent_authority"), errors);
            if !authority_ids.contains(authority_id) {
                errors.push(ValidationError::new(
                    format!("{path}.competent_authority"),
                    "public service competent_authority must reference a known authority",
                ));
            }
        }
        validate_optional_uri(
            service.jurisdiction.as_deref(),
            format!("{path}.jurisdiction"),
            &manifest.vocabularies,
            errors,
        );
        for (requirement_index, requirement_id) in service.holds_requirements.iter().enumerate() {
            validate_id(
                requirement_id,
                format!("{path}.holds_requirements[{requirement_index}]"),
                errors,
            );
            if !requirement_ids.contains(requirement_id.as_str()) {
                errors.push(ValidationError::new(
                    format!("{path}.holds_requirements[{requirement_index}]"),
                    "public service holds_requirements must reference a known requirement",
                ));
            }
        }
        for (channel_index, channel) in service.channels.iter().enumerate() {
            let channel_path = format!("{path}.channels[{channel_index}]");
            validate_id(&channel.id, format!("{channel_path}.id"), errors);
            let channel_key = format!("{}:{}", service.id, channel.id);
            if !channel_ids.insert(channel_key) {
                errors.push(ValidationError::new(
                    format!("{channel_path}.id"),
                    "channel id must be unique within a public service",
                ));
            }
            validate_optional_uri(
                channel.iri.as_deref(),
                format!("{channel_path}.iri"),
                &manifest.vocabularies,
                errors,
            );
            validate_optional_uri(
                channel.kind.as_deref(),
                format!("{channel_path}.kind"),
                &manifest.vocabularies,
                errors,
            );
            if let Some(access_url) = channel.access_url.as_deref() {
                validate_http_url(access_url, format!("{channel_path}.access_url"), errors);
            }
        }
        for (index, data_service_id) in service.data_services.iter().enumerate() {
            validate_id(
                data_service_id,
                format!("{path}.data_services[{index}]"),
                errors,
            );
        }
        for (index, form_id) in service.forms.iter().enumerate() {
            validate_id(form_id, format!("{path}.forms[{index}]"), errors);
        }
    }

    let mut data_service_ids = BTreeSet::new();
    for (index, data_service) in manifest.data_services.iter().enumerate() {
        let path = format!("data_services[{index}]");
        validate_id(&data_service.id, format!("{path}.id"), errors);
        if !data_service_ids.insert(data_service.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "data service id must be unique",
            ));
        }
        validate_optional_uri(
            data_service.iri.as_deref(),
            format!("{path}.iri"),
            &manifest.vocabularies,
            errors,
        );
        validate_non_empty(&data_service.title.text(), format!("{path}.title"), errors);
        if let Some(endpoint_url) = data_service.endpoint_url.as_deref() {
            validate_http_url(endpoint_url, format!("{path}.endpoint_url"), errors);
        }
        if let Some(endpoint_description) = data_service.endpoint_description.as_deref() {
            validate_http_url(
                endpoint_description,
                format!("{path}.endpoint_description"),
                errors,
            );
        }
        validate_optional_uri(
            data_service.conforms_to.as_deref(),
            format!("{path}.conforms_to"),
            &manifest.vocabularies,
            errors,
        );
    }
    for (service_index, service) in manifest.public_services.iter().enumerate() {
        for (index, data_service_id) in service.data_services.iter().enumerate() {
            if !data_service_ids.contains(data_service_id.as_str()) {
                errors.push(ValidationError::new(
                    format!("public_services[{service_index}].data_services[{index}]"),
                    "public service data_services must reference a known data service",
                ));
            }
        }
    }

    let mut form_ids = BTreeSet::new();
    let mut form_service_by_id = BTreeMap::new();
    for (index, form) in manifest.forms.iter().enumerate() {
        let path = format!("forms[{index}]");
        validate_id(&form.id, format!("{path}.id"), errors);
        if !form_ids.insert(form.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "form id must be unique",
            ));
        }
        form_service_by_id.insert(form.id.as_str(), form.service.as_str());
        validate_optional_uri(
            form.iri.as_deref(),
            format!("{path}.iri"),
            &manifest.vocabularies,
            errors,
        );
        validate_non_empty(&form.title.text(), format!("{path}.title"), errors);
        validate_id(&form.service, format!("{path}.service"), errors);
        if !service_ids.contains(form.service.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.service"),
                "form service must reference a known public service",
            ));
        }
        if let Some(validation) = form.validates_with.as_ref() {
            validate_optional_uri(
                validation.json_schema.as_deref(),
                format!("{path}.validates_with.json_schema"),
                &manifest.vocabularies,
                errors,
            );
            validate_optional_uri(
                validation.shacl.as_deref(),
                format!("{path}.validates_with.shacl"),
                &manifest.vocabularies,
                errors,
            );
        }
        if let Some(channel_id) = form.channel.as_deref() {
            validate_id(channel_id, format!("{path}.channel"), errors);
            if !channel_ids.contains(&format!("{}:{channel_id}", form.service)) {
                errors.push(ValidationError::new(
                    format!("{path}.channel"),
                    "form channel must reference a channel on the form service",
                ));
            }
        }
        let mut field_ids = BTreeSet::new();
        for (field_index, field) in form.fields.iter().enumerate() {
            let field_path = format!("{path}.fields[{field_index}]");
            validate_form_field(
                field,
                &field_path,
                &mut field_ids,
                requirement_ids,
                &manifest.vocabularies,
                errors,
            );
        }
        let mut section_ids = BTreeSet::new();
        for (section_index, section) in form.sections.iter().enumerate() {
            let section_path = format!("{path}.sections[{section_index}]");
            validate_id(&section.id, format!("{section_path}.id"), errors);
            if !section_ids.insert(section.id.as_str()) {
                errors.push(ValidationError::new(
                    format!("{section_path}.id"),
                    "form section id must be unique within a form",
                ));
            }
            if let Some(title) = section.title.as_ref() {
                validate_non_empty(&title.text(), format!("{section_path}.title"), errors);
            }
            validate_occurs(
                section.min_occurs,
                section.max_occurs,
                format!("{section_path}.min_occurs"),
                errors,
            );
            if let Some(visible_when) = section.visible_when.as_ref() {
                validate_visibility(visible_when, format!("{section_path}.visible_when"), errors);
            }
            for (field_index, field) in section.fields.iter().enumerate() {
                let field_path = format!("{section_path}.fields[{field_index}]");
                validate_form_field(
                    field,
                    &field_path,
                    &mut field_ids,
                    requirement_ids,
                    &manifest.vocabularies,
                    errors,
                );
            }
        }
    }
    for (service_index, service) in manifest.public_services.iter().enumerate() {
        for (index, form_id) in service.forms.iter().enumerate() {
            if !form_ids.contains(form_id.as_str()) {
                errors.push(ValidationError::new(
                    format!("public_services[{service_index}].forms[{index}]"),
                    "public service forms must reference a known form",
                ));
            } else if form_service_by_id.get(form_id.as_str()) != Some(&service.id.as_str()) {
                errors.push(ValidationError::new(
                    format!("public_services[{service_index}].forms[{index}]"),
                    "public service forms must reference forms owned by the same public service",
                ));
            }
        }
    }

    ServiceCatalogRefs {
        service_ids,
        data_service_ids,
        form_ids,
        channel_ids,
    }
}

fn validate_form_field<'a>(
    field: &'a FormFieldManifest,
    path: &str,
    field_ids: &mut BTreeSet<&'a str>,
    requirement_ids: &BTreeSet<&str>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    validate_id(&field.id, format!("{path}.id"), errors);
    if !field_ids.insert(field.id.as_str()) {
        errors.push(ValidationError::new(
            format!("{path}.id"),
            "form field id must be unique within a form",
        ));
    }
    if let Some(name) = field.name.as_deref() {
        validate_non_empty(name, format!("{path}.name"), errors);
    }
    validate_non_empty(&field.label.text(), format!("{path}.label"), errors);
    validate_optional_uri(
        field.concept.as_deref(),
        format!("{path}.concept"),
        vocabularies,
        errors,
    );
    validate_optional_uri(
        field.data_type.as_deref(),
        format!("{path}.data_type"),
        vocabularies,
        errors,
    );
    if let Some(requirement_id) = field.supports_requirement.as_deref() {
        validate_id(
            requirement_id,
            format!("{path}.supports_requirement"),
            errors,
        );
        if !requirement_ids.contains(requirement_id) {
            errors.push(ValidationError::new(
                format!("{path}.supports_requirement"),
                "form field supports_requirement must reference a known requirement",
            ));
        }
    }
    validate_occurs(
        field.min_occurs,
        field.max_occurs,
        format!("{path}.min_occurs"),
        errors,
    );
    if let Some(visible_when) = field.visible_when.as_ref() {
        validate_visibility(visible_when, format!("{path}.visible_when"), errors);
    }
    if let Some(fulfillment) = field.fulfillment.as_ref() {
        for (index, mode) in fulfillment.modes.iter().enumerate() {
            validate_fulfillment_mode(mode, format!("{path}.fulfillment.modes[{index}]"), errors);
        }
        if let Some(preferred_mode) = fulfillment.preferred_mode.as_deref() {
            validate_fulfillment_mode(
                preferred_mode,
                format!("{path}.fulfillment.preferred_mode"),
                errors,
            );
            if !fulfillment.modes.is_empty()
                && !fulfillment.modes.iter().any(|mode| mode == preferred_mode)
            {
                errors.push(ValidationError::new(
                    format!("{path}.fulfillment.preferred_mode"),
                    "preferred fulfillment mode must be listed in modes",
                ));
            }
        }
    }
}

fn validate_occurs(
    min_occurs: Option<u32>,
    max_occurs: Option<u32>,
    path: impl Into<String>,
    errors: &mut Vec<ValidationError>,
) {
    if let (Some(min), Some(max)) = (min_occurs, max_occurs) {
        if max < min {
            errors.push(ValidationError::new(
                path,
                "max_occurs must be greater than or equal to min_occurs",
            ));
        }
    }
}

fn validate_visibility(
    visible_when: &FormVisibilityManifest,
    path: impl Into<String>,
    errors: &mut Vec<ValidationError>,
) {
    let path = path.into();
    validate_non_empty(&visible_when.field, format!("{path}.field"), errors);
    validate_non_empty(&visible_when.equals, format!("{path}.equals"), errors);
}

fn validate_fulfillment_mode(
    mode: &str,
    path: impl Into<String>,
    errors: &mut Vec<ValidationError>,
) {
    if !matches!(
        mode,
        "manual_input"
            | "file_upload"
            | "registry_lookup"
            | "oots_evidence_exchange"
            | "self_declaration"
            | "known_from_context"
    ) {
        errors.push(ValidationError::new(
            path,
            "fulfillment mode must be manual_input, file_upload, registry_lookup, oots_evidence_exchange, self_declaration, or known_from_context",
        ));
    }
}

fn validate_service_catalog_dataset_refs(
    manifest: &MetadataManifest,
    service_refs: &ServiceCatalogRefs<'_>,
    dataset_ids: &BTreeSet<&str>,
    errors: &mut Vec<ValidationError>,
) {
    for (service_index, service) in manifest.public_services.iter().enumerate() {
        for (index, dataset_id) in service.produces.iter().enumerate() {
            validate_id(
                dataset_id,
                format!("public_services[{service_index}].produces[{index}]"),
                errors,
            );
            if !dataset_ids.contains(dataset_id.as_str()) {
                errors.push(ValidationError::new(
                    format!("public_services[{service_index}].produces[{index}]"),
                    "public service produces must reference a known dataset",
                ));
            }
        }
    }
    for (index, data_service) in manifest.data_services.iter().enumerate() {
        for (dataset_index, dataset_id) in data_service.serves_datasets.iter().enumerate() {
            validate_id(
                dataset_id,
                format!("data_services[{index}].serves_datasets[{dataset_index}]"),
                errors,
            );
            if !dataset_ids.contains(dataset_id.as_str()) {
                errors.push(ValidationError::new(
                    format!("data_services[{index}].serves_datasets[{dataset_index}]"),
                    "data service serves_datasets must reference a known dataset",
                ));
            }
        }
    }
    let _ = (
        &service_refs.service_ids,
        &service_refs.data_service_ids,
        &service_refs.form_ids,
        &service_refs.channel_ids,
    );
}

fn validate_entities(
    dataset: &DatasetManifest,
    path: &str,
    codelist_ids: &BTreeSet<&str>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    let entity_names = dataset
        .entities
        .iter()
        .map(|entity| entity.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen_entity_names = BTreeSet::new();
    for (entity_index, entity) in dataset.entities.iter().enumerate() {
        let entity_path = format!("{path}.entities[{entity_index}]");
        validate_id(&entity.name, format!("{entity_path}.name"), errors);
        if !seen_entity_names.insert(entity.name.as_str()) {
            errors.push(ValidationError::new(
                format!("{entity_path}.name"),
                "entity name must be unique within a dataset",
            ));
        }
        validate_optional_uri(
            entity.concept_uri.as_deref(),
            format!("{entity_path}.concept_uri"),
            vocabularies,
            errors,
        );
        let mut field_names = BTreeSet::new();
        for (field_index, field) in entity.fields.iter().enumerate() {
            let field_path = format!("{entity_path}.fields[{field_index}]");
            validate_id(&field.name, format!("{field_path}.name"), errors);
            if !field_names.insert(field.name.as_str()) {
                errors.push(ValidationError::new(
                    format!("{field_path}.name"),
                    "field name must be unique within an entity",
                ));
            }
            validate_uri_list(
                &field.concepts,
                format!("{field_path}.concepts"),
                vocabularies,
                errors,
            );
            if let Some(codelist) = field.codelist.as_deref() {
                validate_id(codelist, format!("{field_path}.codelist"), errors);
                if !codelist_ids.contains(codelist) {
                    errors.push(ValidationError::new(
                        format!("{field_path}.codelist"),
                        "field codelist must reference a known codelist",
                    ));
                }
            }
        }
        for identifier in &entity.identifiers {
            if !field_names.contains(identifier.name.as_str()) {
                errors.push(ValidationError::new(
                    format!("{entity_path}.identifiers"),
                    "identifier must reference a field on the entity",
                ));
            }
        }
        for (relationship_index, relationship) in entity.relationships.iter().enumerate() {
            let relationship_path = format!("{entity_path}.relationships[{relationship_index}]");
            validate_id(
                &relationship.name,
                format!("{relationship_path}.name"),
                errors,
            );
            let Some(target) = relationship.target_name() else {
                errors.push(ValidationError::new(
                    format!("{relationship_path}.target_entity"),
                    "relationship target_entity is required",
                ));
                continue;
            };
            if !entity_names.contains(target) {
                errors.push(ValidationError::new(
                    format!("{relationship_path}.target_entity"),
                    "relationship target must name an entity in the same dataset",
                ));
            }
            validate_optional_uri(
                relationship.concept_uri.as_deref(),
                format!("{relationship_path}.concept_uri"),
                vocabularies,
                errors,
            );
            if let Some(cardinality) = relationship.cardinality.as_deref() {
                validate_cardinality(
                    cardinality,
                    format!("{relationship_path}.cardinality"),
                    errors,
                );
            }
        }
    }
}

// Validates every evidence offering on a dataset against the manifest's
// cross-cutting context (catalog-wide id table, evidence-type allowlist,
// evaluation-profile rulesets, vocabulary prefixes). Each argument is
// load-bearing for at least one validation rule, so collapsing them into a
// context struct would only rename the dependency, not remove it.
fn validate_evidence_offerings(
    dataset: &DatasetManifest,
    path: &str,
    evidence_type_ids: &BTreeSet<&str>,
    evaluation_profile_rulesets: &BTreeSet<&str>,
    offering_ids: &mut BTreeSet<String>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    let entity_fields = dataset
        .entities
        .iter()
        .map(|entity| {
            (
                entity.name.as_str(),
                entity
                    .fields
                    .iter()
                    .map(|field| field.name.as_str())
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for (index, offering) in dataset.evidence_offerings.iter().enumerate() {
        let offering_path = format!("{path}.evidence_offerings[{index}]");
        validate_id(&offering.id, format!("{offering_path}.id"), errors);
        if !offering_ids.insert(offering.id.clone()) {
            errors.push(ValidationError::new(
                format!("{offering_path}.id"),
                "evidence offering id must be unique globally",
            ));
        }
        validate_optional_uri(
            offering.iri.as_deref(),
            format!("{offering_path}.iri"),
            vocabularies,
            errors,
        );
        validate_non_empty(
            &offering.title.text(),
            format!("{offering_path}.title"),
            errors,
        );
        validate_id(
            &offering.evidence_type,
            format!("{offering_path}.evidence_type"),
            errors,
        );
        if !evidence_type_ids.contains(offering.evidence_type.as_str()) {
            errors.push(ValidationError::new(
                format!("{offering_path}.evidence_type"),
                "evidence offering must reference a known evidence type",
            ));
        }
        validate_id(
            &offering.issuing_authority.id,
            format!("{offering_path}.issuing_authority.id"),
            errors,
        );
        validate_optional_uri(
            offering.issuing_authority.iri.as_deref(),
            format!("{offering_path}.issuing_authority.iri"),
            vocabularies,
            errors,
        );
        validate_non_empty(
            &offering.issuing_authority.name,
            format!("{offering_path}.issuing_authority.name"),
            errors,
        );
        if offering
            .issuing_authority
            .country
            .as_deref()
            .is_some_and(|country| country.trim().is_empty())
        {
            errors.push(ValidationError::new(
                format!("{offering_path}.issuing_authority.country"),
                "issuing authority country must not be empty when present",
            ));
        }
        if offering.jurisdiction.as_ref().is_some_and(|jurisdiction| {
            jurisdiction.country.is_none() && jurisdiction.region.is_none()
        }) {
            errors.push(ValidationError::new(
                format!("{offering_path}.jurisdiction"),
                "jurisdiction must declare country or region",
            ));
        }
        validate_id(&offering.entity, format!("{offering_path}.entity"), errors);
        let Some(fields) = entity_fields.get(offering.entity.as_str()) else {
            errors.push(ValidationError::new(
                format!("{offering_path}.entity"),
                "evidence offering entity must name an entity in the same dataset",
            ));
            continue;
        };
        if offering.lookup_keys.is_empty() {
            errors.push(ValidationError::new(
                format!("{offering_path}.lookup_keys"),
                "evidence offering must declare at least one lookup key",
            ));
        }
        for (key_index, key) in offering.lookup_keys.iter().enumerate() {
            validate_id(
                key,
                format!("{offering_path}.lookup_keys[{key_index}]"),
                errors,
            );
            if !fields.contains(key.as_str()) {
                errors.push(ValidationError::new(
                    format!("{offering_path}.lookup_keys[{key_index}]"),
                    "lookup key must reference a field on the offering entity",
                ));
            }
        }
        validate_uri_or_code_list(
            &offering.procedure_contexts,
            format!("{offering_path}.procedure_contexts"),
            vocabularies,
            errors,
        );
        if offering.access.kind.trim().is_empty() {
            errors.push(ValidationError::new(
                format!("{offering_path}.access.kind"),
                "access kind must not be empty",
            ));
        }
        if offering.access.conforms_to.as_deref() != Some(REGISTRY_NOTARY_FEDERATION_PROTOCOL) {
            validate_optional_uri(
                offering.access.conforms_to.as_deref(),
                format!("{offering_path}.access.conforms_to"),
                vocabularies,
                errors,
            );
        }
        if offering.access.kind == "registry-notary" {
            validate_registry_notary_access(
                offering,
                &offering_path,
                evaluation_profile_rulesets,
                errors,
            );
        } else {
            if let Some(endpoint_url) = offering.access.endpoint_url.as_deref() {
                validate_http_url(
                    endpoint_url,
                    format!("{offering_path}.access.endpoint_url"),
                    errors,
                );
            }
            if let Some(discovery_url) = offering.access.discovery_url.as_deref() {
                validate_http_url(
                    discovery_url,
                    format!("{offering_path}.access.discovery_url"),
                    errors,
                );
            }
        }
        validate_non_empty(
            &offering.access.ruleset,
            format!("{offering_path}.access.ruleset"),
            errors,
        );
        if let Some(policy) = offering.policy.as_ref() {
            validate_uri_list(
                &policy.purpose,
                format!("{offering_path}.policy.purpose"),
                vocabularies,
                errors,
            );
        }
    }
}

fn validate_registry_notary_access(
    offering: &EvidenceOfferingManifest,
    offering_path: &str,
    evaluation_profile_rulesets: &BTreeSet<&str>,
    errors: &mut Vec<ValidationError>,
) {
    if offering.access.conforms_to.as_deref() != Some(REGISTRY_NOTARY_FEDERATION_PROTOCOL) {
        errors.push(ValidationError::new(
            format!("{offering_path}.access.conforms_to"),
            format!("registry-notary access must conform to {REGISTRY_NOTARY_FEDERATION_PROTOCOL}"),
        ));
    }
    match offering.access.endpoint_url.as_deref() {
        Some(endpoint_url) => validate_https_url(
            endpoint_url,
            format!("{offering_path}.access.endpoint_url"),
            errors,
        ),
        None => errors.push(ValidationError::new(
            format!("{offering_path}.access.endpoint_url"),
            "registry-notary access must declare an HTTPS endpoint URL",
        )),
    }
    match offering.access.discovery_url.as_deref() {
        Some(discovery_url) => validate_https_url(
            discovery_url,
            format!("{offering_path}.access.discovery_url"),
            errors,
        ),
        None => errors.push(ValidationError::new(
            format!("{offering_path}.access.discovery_url"),
            "registry-notary access must declare an HTTPS discovery URL",
        )),
    }
    if !offering.access.ruleset.trim().is_empty()
        && !evaluation_profile_rulesets.contains(offering.access.ruleset.as_str())
    {
        errors.push(ValidationError::new(
            format!("{offering_path}.access.ruleset"),
            "registry-notary access.ruleset must reference a known evaluation profile ruleset",
        ));
    }
}

fn validate_dataset_policy(
    policy: Option<&DatasetPolicyManifest>,
    dataset_path: &str,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    let Some(policy) = policy else {
        return;
    };
    let policy_path = format!("{dataset_path}.policy");
    validate_optional_policy_iri(
        policy.uid.as_deref(),
        format!("{policy_path}.uid"),
        vocabularies,
        errors,
    );
    validate_optional_policy_iri(
        policy.assigner.as_deref(),
        format!("{policy_path}.assigner"),
        vocabularies,
        errors,
    );
    validate_policy_iri_list(
        &policy.profile,
        format!("{policy_path}.profile"),
        vocabularies,
        errors,
    );
    if policy.permissions.is_empty() && policy.prohibitions.is_empty() {
        errors.push(ValidationError::new(
            policy_path.clone(),
            "policy must declare at least one permission or prohibition",
        ));
    }
    if !policy.obligations.is_empty() {
        errors.push(ValidationError::new(
            format!("{policy_path}.obligations"),
            "top-level ODRL obligations are not supported in v0.1",
        ));
    }
    for (index, rule) in policy.permissions.iter().enumerate() {
        validate_policy_rule(
            rule,
            &format!("{policy_path}.permissions[{index}]"),
            vocabularies,
            errors,
        );
    }
    for (index, rule) in policy.prohibitions.iter().enumerate() {
        validate_policy_rule(
            rule,
            &format!("{policy_path}.prohibitions[{index}]"),
            vocabularies,
            errors,
        );
        if !rule.duties.is_empty() {
            errors.push(ValidationError::new(
                format!("{policy_path}.prohibitions[{index}].duties"),
                "prohibition duties are not supported in v0.1",
            ));
        }
    }
}

fn validate_policy_rule(
    rule: &PolicyRuleManifest,
    path: &str,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    validate_policy_iri(&rule.action, format!("{path}.action"), vocabularies, errors);
    validate_optional_policy_iri(
        rule.target.as_deref(),
        format!("{path}.target"),
        vocabularies,
        errors,
    );
    validate_optional_policy_iri(
        rule.assignee.as_deref(),
        format!("{path}.assignee"),
        vocabularies,
        errors,
    );
    for (index, constraint) in rule.constraints.iter().enumerate() {
        validate_policy_constraint(
            constraint,
            &format!("{path}.constraints[{index}]"),
            vocabularies,
            errors,
        );
    }
    for (index, duty) in rule.duties.iter().enumerate() {
        validate_policy_duty(
            duty,
            &format!("{path}.duties[{index}]"),
            vocabularies,
            errors,
        );
    }
}

fn validate_policy_duty(
    duty: &PolicyDutyManifest,
    path: &str,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    validate_policy_iri(&duty.action, format!("{path}.action"), vocabularies, errors);
    validate_optional_policy_iri(
        duty.target.as_deref(),
        format!("{path}.target"),
        vocabularies,
        errors,
    );
    validate_optional_policy_iri(
        duty.assignee.as_deref(),
        format!("{path}.assignee"),
        vocabularies,
        errors,
    );
    for (index, constraint) in duty.constraints.iter().enumerate() {
        validate_policy_constraint(
            constraint,
            &format!("{path}.constraints[{index}]"),
            vocabularies,
            errors,
        );
    }
}

fn validate_policy_constraint(
    constraint: &PolicyConstraintManifest,
    path: &str,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    let left_operand = expand_policy_uri(&constraint.left_operand, vocabularies);
    validate_policy_iri(
        &constraint.left_operand,
        format!("{path}.left_operand"),
        vocabularies,
        errors,
    );
    validate_policy_iri(
        &constraint.operator,
        format!("{path}.operator"),
        vocabularies,
        errors,
    );
    let has_iri = constraint.right_operand.iri.is_some();
    let has_value = constraint.right_operand.value.is_some();
    match (has_iri, has_value) {
        (true, false) => {
            if let Some(iri) = constraint.right_operand.iri.as_deref() {
                validate_policy_iri(iri, format!("{path}.right_operand"), vocabularies, errors);
            }
        }
        (false, true) => {
            if left_operand
                .as_deref()
                .is_some_and(policy_left_operand_requires_iri)
            {
                errors.push(ValidationError::new(
                    format!("{path}.right_operand"),
                    "right operand must be an IRI for this left operand",
                ));
            }
        }
        _ => errors.push(ValidationError::new(
            format!("{path}.right_operand"),
            "right operand must contain exactly one of iri or value",
        )),
    }
    validate_optional_policy_iri(
        constraint.unit.as_deref(),
        format!("{path}.unit"),
        vocabularies,
        errors,
    );
    validate_optional_policy_iri(
        constraint.datatype.as_deref(),
        format!("{path}.datatype"),
        vocabularies,
        errors,
    );
}

fn validate_policy_iri(
    value: &str,
    path: impl Into<String>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    if expand_policy_uri(value, vocabularies).is_none() {
        errors.push(ValidationError::new(
            path,
            "policy IRI must be absolute or use a configured or built-in vocabulary prefix",
        ));
    }
}

fn validate_optional_policy_iri(
    value: Option<&str>,
    path: impl Into<String>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    if let Some(value) = value {
        validate_policy_iri(value, path, vocabularies, errors);
    }
}

fn validate_policy_iri_list(
    values: &[String],
    path: impl Into<String>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    let path = path.into();
    for (index, value) in values.iter().enumerate() {
        validate_policy_iri(value, format!("{path}[{index}]"), vocabularies, errors);
    }
}

fn policy_left_operand_requires_iri(left_operand: &str) -> bool {
    matches!(
        left_operand,
        "http://www.w3.org/ns/odrl/2/purpose"
            | "http://www.w3.org/ns/odrl/2/recipient"
            | "http://www.w3.org/ns/odrl/2/spatial"
            | "http://www.w3.org/ns/odrl/2/industry"
            | "http://www.w3.org/ns/odrl/2/systemDevice"
    )
}

fn compile_authority(
    manifest: &MetadataManifest,
    base_url: &str,
    authority: &AuthorityManifest,
) -> CompiledAuthority {
    CompiledAuthority {
        id: authority.id.clone(),
        iri: authority
            .iri
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies))
            .unwrap_or_else(|| format!("{base_url}/metadata/authorities/{}", authority.id)),
        name: authority.name.clone(),
        authority_type: authority
            .authority_type
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
        spatial: authority
            .spatial
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
    }
}

fn compile_service(
    manifest: &MetadataManifest,
    base_url: &str,
    service: &ServiceManifest,
) -> CompiledService {
    CompiledService {
        id: service.id.clone(),
        iri: service
            .iri
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies))
            .unwrap_or_else(|| format!("{base_url}/metadata/public-services/{}", service.id)),
        title: service.title.text(),
        description: service
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        competent_authority: service.competent_authority.clone(),
        jurisdiction: service
            .jurisdiction
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
        channels: service
            .channels
            .iter()
            .map(|channel| compile_channel(manifest, base_url, &service.id, channel))
            .collect(),
        holds_requirements: service.holds_requirements.clone(),
        produces: service.produces.clone(),
        data_services: service.data_services.clone(),
        forms: service.forms.clone(),
    }
}

fn compile_channel(
    manifest: &MetadataManifest,
    base_url: &str,
    service_id: &str,
    channel: &ChannelManifest,
) -> CompiledChannel {
    CompiledChannel {
        id: channel.id.clone(),
        iri: channel
            .iri
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies))
            .unwrap_or_else(|| {
                format!(
                    "{base_url}/metadata/public-services/{service_id}/channels/{}",
                    channel.id
                )
            }),
        title: channel
            .title
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_else(|| channel.id.clone()),
        description: channel
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        kind: channel
            .kind
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
        access_url: channel.access_url.clone(),
    }
}

fn compile_data_service(
    manifest: &MetadataManifest,
    base_url: &str,
    data_service: &DataServiceManifest,
) -> CompiledDataService {
    CompiledDataService {
        id: data_service.id.clone(),
        iri: data_service
            .iri
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies))
            .unwrap_or_else(|| format!("{base_url}/metadata/data-services/{}", data_service.id)),
        title: data_service.title.text(),
        description: data_service
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        endpoint_url: data_service.endpoint_url.clone(),
        endpoint_description: data_service.endpoint_description.clone(),
        serves_datasets: data_service.serves_datasets.clone(),
        conforms_to: data_service
            .conforms_to
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
    }
}

fn compile_form(manifest: &MetadataManifest, base_url: &str, form: &FormManifest) -> CompiledForm {
    CompiledForm {
        id: form.id.clone(),
        iri: form
            .iri
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies))
            .unwrap_or_else(|| format!("{base_url}/metadata/forms/{}", form.id)),
        title: form.title.text(),
        description: form
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        service: form.service.clone(),
        channel: form.channel.clone(),
        validates_with: form
            .validates_with
            .as_ref()
            .map(|validation| CompiledFormValidation {
                json_schema: validation
                    .json_schema
                    .as_deref()
                    .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
                shacl: validation
                    .shacl
                    .as_deref()
                    .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
            }),
        sections: form
            .sections
            .iter()
            .map(|section| CompiledFormSection {
                id: section.id.clone(),
                title: section
                    .title
                    .as_ref()
                    .map(LocalizedText::text)
                    .unwrap_or_else(|| section.id.clone()),
                repeatable: section.repeatable,
                min_occurs: section.min_occurs,
                max_occurs: section.max_occurs,
                visible_when: section.visible_when.clone(),
                fields: section
                    .fields
                    .iter()
                    .map(|field| compile_form_field(manifest, field))
                    .collect(),
            })
            .collect(),
        fields: form
            .fields
            .iter()
            .map(|field| compile_form_field(manifest, field))
            .collect(),
    }
}

fn compile_form_field(manifest: &MetadataManifest, field: &FormFieldManifest) -> CompiledFormField {
    CompiledFormField {
        id: field.id.clone(),
        name: field.name.clone().unwrap_or_else(|| field.id.clone()),
        label: field.label.text(),
        widget_type: field.widget_type.clone(),
        data_type: field
            .data_type
            .as_deref()
            .and_then(|iri| expand_form_data_type(iri, &manifest.vocabularies)),
        concept: field
            .concept
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
        supports_requirement: field.supports_requirement.clone(),
        required: field.required,
        min_occurs: field.min_occurs,
        max_occurs: field.max_occurs,
        visible_when: field.visible_when.clone(),
        fulfillment: field.fulfillment.clone(),
    }
}

fn expand_form_data_type(uri: &str, vocabularies: &BTreeMap<String, String>) -> Option<String> {
    if let Some(suffix) = uri.strip_prefix("xsd:") {
        return Some(format!("http://www.w3.org/2001/XMLSchema#{suffix}"));
    }
    expand_uri(uri, vocabularies)
}

fn compile_dataset(
    manifest: &MetadataManifest,
    base_url: &str,
    codelists: &BTreeMap<String, CompiledCodelist>,
    evidence_types: &BTreeMap<String, CompiledEvidenceType>,
    dataset: &DatasetManifest,
) -> CompiledDataset {
    let entities = dataset
        .entities
        .iter()
        .map(|entity| {
            (
                entity.name.clone(),
                compile_entity(manifest, base_url, codelists, &dataset.id, entity),
            )
        })
        .collect();
    CompiledDataset {
        dataset_id: dataset.id.clone(),
        title: dataset.title.text(),
        description: dataset
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        owner: dataset
            .owner
            .clone()
            .unwrap_or_else(|| manifest.catalog.publisher.name.clone()),
        sensitivity: dataset.sensitivity,
        access_rights: dataset.access_rights,
        update_frequency: dataset.update_frequency,
        conforms_to: dataset
            .conforms_to
            .iter()
            .filter_map(|iri| expand_uri(iri, &manifest.vocabularies))
            .collect(),
        applicable_legislation: dataset
            .applicable_legislation
            .iter()
            .filter_map(|iri| expand_uri(iri, &manifest.vocabularies))
            .collect(),
        spatial_coverage: dataset
            .spatial_coverage
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
        adms_status: dataset.status.unwrap_or(AdmsStatus::UnderDevelopment),
        public_services: dataset
            .public_services
            .iter()
            .enumerate()
            .map(|(index, service)| CompiledPublicService {
                id: service
                    .id
                    .clone()
                    .unwrap_or_else(|| format!("#service-{}-{}", dataset.id, index + 1)),
                title: service.title.text(),
                description: service
                    .description
                    .as_ref()
                    .map(LocalizedText::text)
                    .unwrap_or_default(),
            })
            .collect(),
        policy: compile_dataset_policy(manifest, base_url, dataset),
        evidence_offerings: dataset
            .evidence_offerings
            .iter()
            .map(|offering| {
                (
                    offering.id.clone(),
                    compile_evidence_offering(
                        manifest,
                        base_url,
                        evidence_types,
                        &dataset.id,
                        offering,
                    ),
                )
            })
            .collect(),
        entities,
    }
}

fn compile_requirement(
    manifest: &MetadataManifest,
    base_url: &str,
    requirement: &RequirementManifest,
) -> CompiledRequirement {
    let iri = requirement
        .iri
        .as_deref()
        .and_then(|iri| expand_uri(iri, &manifest.vocabularies))
        .unwrap_or_else(|| format!("{base_url}/metadata/requirements/{}", requirement.id));
    CompiledRequirement {
        id: requirement.id.clone(),
        iri: iri.clone(),
        title: requirement.title.text(),
        description: requirement
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        rdf_type: requirement
            .rdf_type
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies))
            .unwrap_or_else(|| "http://data.europa.eu/m8g/Requirement".to_string()),
        procedure_contexts: requirement.procedure_contexts.clone(),
        reference_frameworks: requirement
            .reference_frameworks
            .iter()
            .filter_map(|framework| {
                Some(CompiledReferenceFramework {
                    iri: expand_uri(&framework.iri, &manifest.vocabularies)?,
                    identifier: framework.identifier.clone(),
                })
            })
            .collect(),
        evidence_type_lists: requirement
            .evidence_type_lists
            .iter()
            .enumerate()
            .map(|(index, list)| compile_evidence_type_list(requirement, &iri, list, index))
            .collect(),
    }
}

fn compile_evidence_type_list(
    requirement: &RequirementManifest,
    requirement_iri: &str,
    list: &EvidenceTypeListManifest,
    index: usize,
) -> CompiledEvidenceTypeList {
    let list_id =
        evidence_type_list_manifest_id(list, index, requirement.evidence_type_lists.len());
    CompiledEvidenceTypeList {
        iri: evidence_type_list_iri_from_id(requirement_iri, &list_id),
        title: list
            .title
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_else(|| {
                format!(
                    "Evidence type list {list_id} for {}",
                    requirement.title.text()
                )
            }),
        description: list
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        id: list_id,
        evidence_types: list.evidence_types.clone(),
    }
}

fn compile_evidence_type(
    manifest: &MetadataManifest,
    base_url: &str,
    requirements: &BTreeMap<String, CompiledRequirement>,
    evidence_type: &EvidenceTypeManifest,
) -> CompiledEvidenceType {
    CompiledEvidenceType {
        id: evidence_type.id.clone(),
        iri: evidence_type
            .iri
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies))
            .unwrap_or_else(|| format!("{base_url}/metadata/evidence-types/{}", evidence_type.id)),
        title: evidence_type.title.text(),
        description: evidence_type
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        proves: evidence_type.proves.clone(),
        requirement_iris: evidence_type
            .proves
            .iter()
            .filter_map(|requirement_id| requirements.get(requirement_id))
            .map(|requirement| requirement.iri.clone())
            .collect(),
        information_concepts: evidence_type
            .information_concepts
            .iter()
            .filter_map(|iri| expand_uri(iri, &manifest.vocabularies))
            .collect(),
    }
}

fn compile_evidence_offering(
    manifest: &MetadataManifest,
    base_url: &str,
    evidence_types: &BTreeMap<String, CompiledEvidenceType>,
    dataset_id: &str,
    offering: &EvidenceOfferingManifest,
) -> CompiledEvidenceOffering {
    let evidence_type = evidence_types.get(&offering.evidence_type);
    CompiledEvidenceOffering {
        id: offering.id.clone(),
        iri: offering
            .iri
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies))
            .unwrap_or_else(|| format!("{base_url}/metadata/evidence-offerings/{}", offering.id)),
        title: offering.title.text(),
        description: offering
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        dataset_id: dataset_id.to_string(),
        verification_request_schema_url: format!(
            "{base_url}/metadata/schema/{dataset_id}/{}/schema.json",
            offering.entity
        ),
        evidence_type: offering.evidence_type.clone(),
        evidence_type_iri: evidence_type
            .map(|evidence_type| evidence_type.iri.clone())
            .unwrap_or_else(|| {
                format!(
                    "{base_url}/metadata/evidence-types/{}",
                    offering.evidence_type
                )
            }),
        requirement_iris: evidence_type
            .map(|evidence_type| evidence_type.requirement_iris.clone())
            .unwrap_or_default(),
        information_concepts: evidence_type
            .map(|evidence_type| evidence_type.information_concepts.clone())
            .unwrap_or_default(),
        issuing_authority: CompiledIssuingAuthority {
            id: offering.issuing_authority.id.clone(),
            iri: offering
                .issuing_authority
                .iri
                .as_deref()
                .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
            name: offering.issuing_authority.name.clone(),
            country: offering.issuing_authority.country.clone(),
        },
        jurisdiction: offering.jurisdiction.clone(),
        level_of_assurance: offering.level_of_assurance.clone(),
        entity: offering.entity.clone(),
        lookup_keys: offering.lookup_keys.clone(),
        procedure_contexts: offering.procedure_contexts.clone(),
        access: offering.access.clone(),
        policy: CompiledEvidenceOfferingPolicy {
            purpose: offering
                .policy
                .as_ref()
                .map(|policy| {
                    policy
                        .purpose
                        .iter()
                        .filter_map(|iri| expand_uri(iri, &manifest.vocabularies))
                        .collect()
                })
                .unwrap_or_default(),
        },
    }
}

fn compile_dataset_policy(
    manifest: &MetadataManifest,
    base_url: &str,
    dataset: &DatasetManifest,
) -> CompiledDatasetPolicy {
    let dataset_target = dataset_url_from_id(&dataset.id);
    let default_uid = format!("#policy-{}-offer", dataset.id);
    let default_assigner = manifest
        .catalog
        .participant_id
        .as_deref()
        .or(manifest.catalog.publisher.iri.as_deref())
        .and_then(|iri| expand_policy_uri(iri, &manifest.vocabularies))
        .unwrap_or_else(|| base_url.to_string());
    let Some(policy) = dataset.policy.as_ref() else {
        return CompiledDatasetPolicy {
            uid: default_uid,
            assigner: default_assigner.clone(),
            profile: Vec::new(),
            permissions: vec![CompiledPolicyRule {
                action: "odrl:use".to_string(),
                target: dataset_target,
                assignee: None,
                constraints: Vec::new(),
                duties: Vec::new(),
            }],
            prohibitions: Vec::new(),
        };
    };
    let assigner = policy
        .assigner
        .as_deref()
        .and_then(|iri| expand_policy_uri(iri, &manifest.vocabularies))
        .unwrap_or(default_assigner);
    let uid = policy
        .uid
        .as_deref()
        .and_then(|iri| expand_policy_uri(iri, &manifest.vocabularies))
        .unwrap_or(default_uid);
    CompiledDatasetPolicy {
        uid,
        assigner: assigner.clone(),
        profile: policy
            .profile
            .iter()
            .filter_map(|iri| expand_policy_uri(iri, &manifest.vocabularies))
            .collect(),
        permissions: policy
            .permissions
            .iter()
            .map(|rule| compile_policy_rule(rule, &dataset_target, &manifest.vocabularies))
            .collect(),
        prohibitions: policy
            .prohibitions
            .iter()
            .map(|rule| compile_policy_rule(rule, &dataset_target, &manifest.vocabularies))
            .collect(),
    }
}

fn compile_policy_rule(
    rule: &PolicyRuleManifest,
    default_target: &str,
    vocabularies: &BTreeMap<String, String>,
) -> CompiledPolicyRule {
    CompiledPolicyRule {
        action: expand_policy_uri(&rule.action, vocabularies)
            .unwrap_or_else(|| rule.action.clone()),
        target: rule
            .target
            .as_deref()
            .and_then(|iri| expand_policy_uri(iri, vocabularies))
            .unwrap_or_else(|| default_target.to_string()),
        assignee: rule
            .assignee
            .as_deref()
            .and_then(|iri| expand_policy_uri(iri, vocabularies)),
        constraints: rule
            .constraints
            .iter()
            .map(|constraint| compile_policy_constraint(constraint, vocabularies))
            .collect(),
        duties: rule
            .duties
            .iter()
            .map(|duty| compile_policy_duty(duty, vocabularies))
            .collect(),
    }
}

fn compile_policy_duty(
    duty: &PolicyDutyManifest,
    vocabularies: &BTreeMap<String, String>,
) -> CompiledPolicyDuty {
    CompiledPolicyDuty {
        action: expand_policy_uri(&duty.action, vocabularies)
            .unwrap_or_else(|| duty.action.clone()),
        target: duty
            .target
            .as_deref()
            .and_then(|iri| expand_policy_uri(iri, vocabularies)),
        assignee: duty
            .assignee
            .as_deref()
            .and_then(|iri| expand_policy_uri(iri, vocabularies)),
        constraints: duty
            .constraints
            .iter()
            .map(|constraint| compile_policy_constraint(constraint, vocabularies))
            .collect(),
    }
}

fn compile_policy_constraint(
    constraint: &PolicyConstraintManifest,
    vocabularies: &BTreeMap<String, String>,
) -> CompiledPolicyConstraint {
    let right_operand = if let Some(iri) = constraint.right_operand.iri.as_deref() {
        CompiledPolicyOperandValue::Iri(
            expand_policy_uri(iri, vocabularies).unwrap_or_else(|| iri.to_string()),
        )
    } else {
        CompiledPolicyOperandValue::Literal(
            constraint.right_operand.value.clone().unwrap_or_default(),
        )
    };
    CompiledPolicyConstraint {
        left_operand: expand_policy_uri(&constraint.left_operand, vocabularies)
            .unwrap_or_else(|| constraint.left_operand.clone()),
        operator: expand_policy_uri(&constraint.operator, vocabularies)
            .unwrap_or_else(|| constraint.operator.clone()),
        right_operand,
        unit: constraint
            .unit
            .as_deref()
            .and_then(|iri| expand_policy_uri(iri, vocabularies)),
        datatype: constraint
            .datatype
            .as_deref()
            .and_then(|iri| expand_policy_uri(iri, vocabularies)),
    }
}

fn compile_entity(
    manifest: &MetadataManifest,
    _base_url: &str,
    codelists: &BTreeMap<String, CompiledCodelist>,
    _dataset_id: &str,
    entity: &EntityManifest,
) -> CompiledEntity {
    let fields = entity
        .fields
        .iter()
        .map(|field| {
            let codelist_scheme_iri = field
                .codelist
                .as_deref()
                .and_then(|id| codelists.get(id))
                .map(|codelist| codelist.scheme_iri.clone());
            (
                field.name.clone(),
                CompiledField {
                    name: field.name.clone(),
                    field_type: field.field_type,
                    required: field.required,
                    constraints: field.constraints.clone(),
                    concepts: field
                        .concepts
                        .iter()
                        .filter_map(|iri| expand_uri(iri, &manifest.vocabularies))
                        .collect(),
                    codelist: field.codelist.clone(),
                    codelist_scheme_iri,
                    unit: field.unit.clone(),
                    language: field.language.clone(),
                },
            )
        })
        .collect();
    let relationships = entity
        .relationships
        .iter()
        .filter_map(|relationship| {
            Some(CompiledRelationship {
                name: relationship.name.clone(),
                target: relationship.target_name()?.to_string(),
                cardinality: relationship
                    .cardinality
                    .clone()
                    .unwrap_or_else(|| "unspecified".to_string()),
                role: relationship.role.clone(),
                concept_uri: relationship
                    .concept_uri
                    .as_deref()
                    .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
            })
        })
        .collect();
    let primary_key = entity
        .identifiers
        .first()
        .map(|identifier| identifier.name.clone())
        .or_else(|| entity.fields.first().map(|field| field.name.clone()))
        .unwrap_or_else(|| "id".to_string());
    CompiledEntity {
        name: entity.name.clone(),
        title: entity
            .title
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_else(|| entity.name.clone()),
        description: entity
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        concept_uri: entity
            .concept_uri
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
        primary_key,
        identifiers: entity.identifiers.clone(),
        fields,
        relationships,
    }
}

fn catalog_dataset_json(dataset: &CompiledDataset) -> Value {
    let mut dataset_json = json!({
        "dataset_id": dataset.dataset_id,
        "title": dataset.title,
        "description": dataset.description,
        "owner": dataset.owner,
        "sensitivity": sensitivity_name(dataset.sensitivity),
        "access_rights": access_rights_name(dataset.access_rights),
        "update_frequency": update_frequency_name(dataset.update_frequency),
        "conforms_to": dataset.conforms_to,
        "entities": dataset.entities.values().map(catalog_entity_json).collect::<Vec<_>>(),
    });
    if !dataset.evidence_offerings.is_empty() {
        dataset_json["evidence_offerings"] =
            json!(dataset.evidence_offerings.values().collect::<Vec<_>>());
    }
    if !dataset.applicable_legislation.is_empty() {
        dataset_json["applicable_legislation"] = json!(dataset.applicable_legislation);
    }
    if !dataset.public_services.is_empty() {
        dataset_json["public_services"] = json!(dataset.public_services);
    }
    dataset_json
}

fn catalog_entity_json(entity: &CompiledEntity) -> Value {
    json!({
        "name": entity.name,
        "title": entity.title,
        "description": entity.description,
        "concept_uri": entity.concept_uri,
        "primary_key": entity.primary_key,
        "identifiers": entity.identifiers,
        "fields": entity.fields.values().map(catalog_field_json).collect::<Vec<_>>(),
        "relationships": entity.relationships,
    })
}

fn catalog_field_json(field: &CompiledField) -> Value {
    json!({
        "name": field.name,
        "type": field_type_name(field.field_type),
        "required": field.required,
        "concepts": field.concepts,
        "codelist": field.codelist,
        "codelist_scheme_iri": field.codelist_scheme_iri,
        "constraints": field.constraints,
        "unit": field.unit,
        "language": field.language,
    })
}

fn base_dcat_dataset(_compiled: &CompiledMetadata, dataset: &CompiledDataset) -> Value {
    let mut obj = json!({
        "@id": dataset_url(dataset),
        "@type": "dcat:Dataset",
        "dcterms:identifier": dataset.dataset_id,
        "dcterms:title": dataset.title,
        "dcterms:description": dataset.description,
        "dcterms:conformsTo": dataset.conforms_to,
        "dcat:landingPage": dataset_url(dataset),
    });
    obj["odrl:hasPolicy"] = render_dataset_policy(dataset);
    obj
}

fn breg_dcat_dataset(compiled: &CompiledMetadata, dataset: &CompiledDataset) -> Value {
    let mut obj = base_dcat_dataset(compiled, dataset);
    obj["dcterms:publisher"] = json!(publisher_agent(compiled.catalog()));
    obj["dcterms:rightsHolder"] = json!(dataset.owner);
    obj["dcterms:accessRights"] = json!(access_rights_uri(dataset.access_rights));
    obj["dcterms:accrualPeriodicity"] = json!(frequency_uri(dataset.update_frequency));
    obj["adms:status"] = json!(adms_status_uri(dataset.adms_status));
    let codelists = dataset_codelist_references(compiled, dataset);
    if !codelists.is_empty() {
        // Registry Relay interpretation: DCAT/BRegDCAT-AP do not define a
        // dedicated property for field codelist linkage. We use standard
        // `dcterms:references` from the dataset to the SKOS concept schemes
        // used by its field constraints, without claiming source-of-truth
        // semantics beyond "this dataset references these schemes".
        obj["dcterms:references"] = json!(codelists);
    }
    if !dataset.applicable_legislation.is_empty() {
        obj["dcatap:applicableLegislation"] = json!(dataset.applicable_legislation);
    }
    if let Some(spatial) = dataset.spatial_coverage.as_deref() {
        obj["dcterms:spatial"] = json!(spatial);
    }
    obj
}

fn dataset_codelist_references(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
) -> Vec<Value> {
    let mut schemes = BTreeSet::new();
    for entity in dataset.entities.values() {
        for field in entity.fields.values() {
            if let Some(scheme) = field.codelist_scheme_iri.as_deref() {
                schemes.insert(scheme.to_string());
            }
        }
    }
    schemes
        .into_iter()
        .filter_map(|scheme| {
            compiled
                .codelists()
                .find(|codelist| codelist.scheme_iri == scheme)
                .map(standards_codelist_shape)
        })
        .collect()
}

fn render_dataset_policy(dataset: &CompiledDataset) -> Value {
    let policy = &dataset.policy;
    let mut offer = json!({
        "@id": policy.uid,
        "@type": "odrl:Offer",
        "odrl:uid": policy.uid,
        "odrl:assigner": iri_object(&policy.assigner),
        "odrl:permission": policy
            .permissions
            .iter()
            .map(|rule| render_policy_rule(rule, policy))
            .collect::<Vec<_>>(),
    });
    if !policy.profile.is_empty() {
        offer["odrl:profile"] = json!(policy
            .profile
            .iter()
            .map(|iri| iri_object(iri))
            .collect::<Vec<_>>());
    }
    if !policy.prohibitions.is_empty() {
        offer["odrl:prohibition"] = json!(policy
            .prohibitions
            .iter()
            .map(|rule| render_policy_rule(rule, policy))
            .collect::<Vec<_>>());
    }
    offer
}

fn render_policy_rule(rule: &CompiledPolicyRule, policy: &CompiledDatasetPolicy) -> Value {
    let mut value = json!({
        "odrl:target": iri_object(&rule.target),
        "odrl:assigner": iri_object(&policy.assigner),
        "odrl:action": iri_object(&rule.action),
    });
    if let Some(assignee) = rule.assignee.as_deref() {
        value["odrl:assignee"] = iri_object(assignee);
    }
    if !rule.constraints.is_empty() {
        value["odrl:constraint"] = json!(rule
            .constraints
            .iter()
            .map(render_policy_constraint)
            .collect::<Vec<_>>());
    }
    if !rule.duties.is_empty() {
        value["odrl:duty"] = json!(rule
            .duties
            .iter()
            .map(render_policy_duty)
            .collect::<Vec<_>>());
    }
    value
}

fn render_policy_duty(duty: &CompiledPolicyDuty) -> Value {
    let mut value = json!({
        "odrl:action": iri_object(&duty.action),
    });
    if let Some(target) = duty.target.as_deref() {
        value["odrl:target"] = iri_object(target);
    }
    if let Some(assignee) = duty.assignee.as_deref() {
        value["odrl:assignee"] = iri_object(assignee);
    }
    if !duty.constraints.is_empty() {
        value["odrl:constraint"] = json!(duty
            .constraints
            .iter()
            .map(render_policy_constraint)
            .collect::<Vec<_>>());
    }
    value
}

fn render_policy_constraint(constraint: &CompiledPolicyConstraint) -> Value {
    let mut value = json!({
        "odrl:leftOperand": iri_object(&constraint.left_operand),
        "odrl:operator": iri_object(&constraint.operator),
        "odrl:rightOperand": render_policy_operand(&constraint.right_operand, constraint.datatype.as_deref()),
    });
    if let Some(unit) = constraint.unit.as_deref() {
        value["odrl:unit"] = iri_object(unit);
    }
    value
}

fn render_policy_operand(operand: &CompiledPolicyOperandValue, datatype: Option<&str>) -> Value {
    match operand {
        CompiledPolicyOperandValue::Iri(iri) => iri_object(iri),
        CompiledPolicyOperandValue::Literal(value) => {
            if let Some(datatype) = datatype {
                json!({
                    "@value": value,
                    "@type": policy_jsonld_iri(datatype),
                })
            } else {
                json!(value)
            }
        }
    }
}

fn iri_object(iri: &str) -> Value {
    json!({ "@id": policy_jsonld_iri(iri) })
}

fn policy_jsonld_iri(iri: &str) -> String {
    iri.strip_prefix("http://www.w3.org/ns/odrl/2/")
        .map(|suffix| format!("odrl:{suffix}"))
        .or_else(|| {
            iri.strip_prefix("http://www.w3.org/2001/XMLSchema#")
                .map(|suffix| format!("xsd:{suffix}"))
        })
        .or_else(|| {
            iri.strip_prefix("http://purl.org/dc/terms/")
                .map(|suffix| format!("dcterms:{suffix}"))
        })
        .unwrap_or_else(|| iri.to_string())
}

fn publisher_agent(catalog: &CompiledCatalog) -> Value {
    let mut agent = json!({
        "@type": "foaf:Agent",
        "foaf:name": catalog.publisher,
    });
    if let Some(iri) = catalog.publisher_iri.as_deref() {
        agent["@id"] = json!(iri);
        if iri.starts_with("http://publications.europa.eu/resource/authority/corporate-body/") {
            agent["skos:inScheme"] =
                json!("http://publications.europa.eu/resource/authority/corporate-body");
        }
    }
    if let Some(authority_type) = catalog.authority_type.as_deref() {
        agent["dcterms:type"] = json!(authority_type);
    }
    agent
}

fn public_service_node(
    catalog: &CompiledCatalog,
    dataset: &CompiledDataset,
    service: &CompiledPublicService,
) -> Value {
    let mut node = json!({
        "@id": service.id,
        "@type": "cpsv:PublicService",
        "dcterms:identifier": service.id,
        "dcterms:title": service.title,
        "dcterms:description": service.description,
        "cv:hasCompetentAuthority": public_organisation_agent(catalog),
        "cpsv:produces": dataset_url(dataset),
    });
    let requirements = dataset
        .evidence_offerings
        .values()
        .flat_map(|offering| offering.requirement_iris.iter())
        .map(|iri| iri_object(iri))
        .collect::<Vec<_>>();
    if !requirements.is_empty() {
        node["cpsv:holdsRequirement"] = Value::Array(requirements);
    }
    node
}

fn service_catalogue_public_service_node(
    compiled: &CompiledMetadata,
    service: &CompiledService,
) -> Value {
    let mut node = json!({
        "@id": service.iri,
        "@type": "cpsv:PublicService",
        "dcterms:identifier": service.id,
        "dcterms:title": service.title,
        "dcterms:description": service.description,
    });
    if let Some(authority_id) = service.competent_authority.as_deref() {
        if let Some(authority) = compiled.authority(authority_id) {
            node["cv:hasCompetentAuthority"] = iri_object(&authority.iri);
        }
    } else {
        node["cv:hasCompetentAuthority"] = public_organisation_agent(compiled.catalog());
    }
    if let Some(jurisdiction) = service.jurisdiction.as_deref() {
        node["dcterms:spatial"] = iri_object(jurisdiction);
    }
    if !service.channels.is_empty() {
        node["cv:hasChannel"] = Value::Array(
            service
                .channels
                .iter()
                .map(|channel| iri_object(&channel.iri))
                .collect(),
        );
    }
    let requirements = service
        .holds_requirements
        .iter()
        .filter_map(|id| compiled.requirement(id))
        .map(|requirement| iri_object(&requirement.iri))
        .collect::<Vec<_>>();
    if !requirements.is_empty() {
        node["cv:holdsRequirement"] = Value::Array(requirements);
    }
    let produced = service
        .produces
        .iter()
        .filter_map(|id| compiled.dataset(id))
        .map(dataset_url)
        .map(|iri| iri_object(&iri))
        .collect::<Vec<_>>();
    if !produced.is_empty() {
        node["cpsv:produces"] = Value::Array(produced);
    }
    let data_services = service
        .data_services
        .iter()
        .filter_map(|id| compiled.data_service(id))
        .map(|data_service| iri_object(&data_service.iri))
        .collect::<Vec<_>>();
    if !data_services.is_empty() {
        node["registry_manifest:usesDataService"] = Value::Array(data_services);
    }
    let forms = service
        .forms
        .iter()
        .filter_map(|id| compiled.form(id))
        .map(|form| iri_object(&form.iri))
        .collect::<Vec<_>>();
    if !forms.is_empty() {
        node["registry_manifest:hasForm"] = Value::Array(forms);
    }
    node
}

fn service_authority_node(authority: &CompiledAuthority) -> Value {
    let mut node = json!({
        "@id": authority.iri,
        "@type": "cv:PublicOrganisation",
        "dcterms:identifier": authority.id,
        "dcterms:title": authority.name,
        "skos:prefLabel": authority.name,
    });
    if let Some(authority_type) = authority.authority_type.as_deref() {
        node["dcterms:type"] = json!(authority_type);
    }
    if let Some(spatial) = authority.spatial.as_deref() {
        node["dcterms:spatial"] = iri_object(spatial);
    }
    node
}

fn service_channel_node(channel: &CompiledChannel) -> Value {
    let mut node = json!({
        "@id": channel.iri,
        "@type": "cv:Channel",
        "dcterms:identifier": channel.id,
        "dcterms:title": channel.title,
        "dcterms:description": channel.description,
    });
    if let Some(kind) = channel.kind.as_deref() {
        node["dcterms:type"] = iri_object(kind);
    }
    if let Some(access_url) = channel.access_url.as_deref() {
        node["dcat:accessURL"] = json!(access_url);
    }
    node
}

fn data_service_node(compiled: &CompiledMetadata, data_service: &CompiledDataService) -> Value {
    let mut node = json!({
        "@id": data_service.iri,
        "@type": "dcat:DataService",
        "dcterms:identifier": data_service.id,
        "dcterms:title": data_service.title,
        "dcterms:description": data_service.description,
    });
    if let Some(endpoint_url) = data_service.endpoint_url.as_deref() {
        node["dcat:endpointURL"] = json!(endpoint_url);
    }
    if let Some(endpoint_description) = data_service.endpoint_description.as_deref() {
        node["dcat:endpointDescription"] = json!(endpoint_description);
    }
    if let Some(conforms_to) = data_service.conforms_to.as_deref() {
        node["dcterms:conformsTo"] = json!(conforms_to);
    }
    let datasets = data_service
        .serves_datasets
        .iter()
        .filter_map(|id| compiled.dataset(id))
        .map(dataset_url)
        .map(|iri| iri_object(&iri))
        .collect::<Vec<_>>();
    if !datasets.is_empty() {
        node["dcat:servesDataset"] = Value::Array(datasets);
    }
    node
}

fn form_node(compiled: &CompiledMetadata, form: &CompiledForm) -> Value {
    let mut node = json!({
        "@id": form.iri,
        "@type": ["registry_manifest:FormDefinition", "registry_manifest:Form"],
        "dcterms:identifier": form.id,
        "dcterms:title": form.title,
        "dcterms:description": form.description,
    });
    if let Some(service) = compiled.public_service(&form.service) {
        node["registry_manifest:forPublicService"] = iri_object(&service.iri);
    }
    if let Some(channel_id) = form.channel.as_deref() {
        if let Some(service) = compiled.public_service(&form.service) {
            if let Some(channel) = service
                .channels
                .iter()
                .find(|candidate| candidate.id == channel_id)
            {
                node["registry_manifest:forChannel"] = iri_object(&channel.iri);
            }
        }
    }
    if let Some(validation) = form.validates_with.as_ref() {
        if let Some(json_schema) = validation.json_schema.as_deref() {
            node["registry_manifest:validatesWithJsonSchema"] = iri_object(json_schema);
        }
        if let Some(shacl) = validation.shacl.as_deref() {
            node["registry_manifest:validatesWithShacl"] = iri_object(shacl);
        }
    }
    if !form.sections.is_empty() {
        node["registry_manifest:hasSection"] = Value::Array(
            form.sections
                .iter()
                .map(|section| {
                    let mut section_node = json!({
                        "@id": format!("{}#section-{}", form.iri, section.id),
                        "@type": "registry_manifest:FormSection",
                        "dcterms:identifier": section.id,
                        "dcterms:title": section.title,
                        "registry_manifest:repeatable": section.repeatable,
                    });
                    if let Some(min_occurs) = section.min_occurs {
                        section_node["registry_manifest:minOccurs"] = json!(min_occurs);
                    }
                    if let Some(max_occurs) = section.max_occurs {
                        section_node["registry_manifest:maxOccurs"] = json!(max_occurs);
                    }
                    if let Some(visible_when) = section.visible_when.as_ref() {
                        section_node["registry_manifest:visibleWhen"] =
                            visibility_node(visible_when);
                    }
                    if !section.fields.is_empty() {
                        section_node["registry_manifest:hasField"] = Value::Array(
                            section
                                .fields
                                .iter()
                                .map(|field| form_field_node(compiled, form, field))
                                .collect(),
                        );
                    }
                    section_node
                })
                .collect(),
        );
    }
    let fields = compiled_form_fields(form);
    if !fields.is_empty() {
        node["registry_manifest:hasField"] = Value::Array(
            fields
                .into_iter()
                .map(|field| form_field_node(compiled, form, field))
                .collect(),
        );
    }
    node
}

fn compiled_form_fields(form: &CompiledForm) -> Vec<&CompiledFormField> {
    form.fields
        .iter()
        .chain(
            form.sections
                .iter()
                .flat_map(|section| section.fields.iter()),
        )
        .collect()
}

fn form_field_node(
    compiled: &CompiledMetadata,
    form: &CompiledForm,
    field: &CompiledFormField,
) -> Value {
    let mut node = json!({
        "@id": format!("{}#field-{}", form.iri, field.id),
        "@type": "registry_manifest:FormField",
        "dcterms:identifier": field.id,
        "registry_manifest:fieldName": field.name,
        "rdfs:label": field.label,
        "registry_manifest:required": field.required,
    });
    if let Some(widget_type) = field.widget_type.as_deref() {
        node["registry_manifest:widgetType"] = json!(widget_type);
    }
    if let Some(data_type) = field.data_type.as_deref() {
        node["registry_manifest:dataType"] = iri_object(data_type);
    }
    if let Some(concept) = field.concept.as_deref() {
        node["cccev:hasConcept"] = iri_object(concept);
    }
    if let Some(requirement_id) = field.supports_requirement.as_deref() {
        if let Some(requirement) = compiled.requirement(requirement_id) {
            node["registry_manifest:supportsRequirement"] = iri_object(&requirement.iri);
        }
    }
    if let Some(min_occurs) = field.min_occurs {
        node["registry_manifest:minOccurs"] = json!(min_occurs);
    }
    if let Some(max_occurs) = field.max_occurs {
        node["registry_manifest:maxOccurs"] = json!(max_occurs);
    }
    if let Some(visible_when) = field.visible_when.as_ref() {
        node["registry_manifest:visibleWhen"] = visibility_node(visible_when);
    }
    if let Some(fulfillment) = field.fulfillment.as_ref() {
        if !fulfillment.modes.is_empty() {
            node["registry_manifest:fulfillmentMode"] = json!(fulfillment.modes);
        }
        if let Some(preferred_mode) = fulfillment.preferred_mode.as_deref() {
            node["registry_manifest:preferredFulfillmentMode"] = json!(preferred_mode);
        }
    }
    node
}

fn visibility_node(visible_when: &FormVisibilityManifest) -> Value {
    json!({
        "registry_manifest:field": visible_when.field,
        "registry_manifest:equals": visible_when.equals,
    })
}

fn cpsv_output_dataset_node(compiled: &CompiledMetadata, dataset: &CompiledDataset) -> Value {
    let mut node = base_dcat_dataset(compiled, dataset);
    node["@type"] = json!(["dcat:Dataset", "cv:Output"]);
    node
}

fn public_organisation_agent(catalog: &CompiledCatalog) -> Value {
    let mut agent = publisher_agent(catalog);
    agent["@type"] = json!(["foaf:Agent", "cv:PublicOrganisation"]);
    agent["dcterms:identifier"] = json!(catalog
        .publisher_iri
        .as_deref()
        .and_then(|iri| iri.rsplit('/').next())
        .unwrap_or(&catalog.publisher));
    agent["dcterms:title"] = json!(catalog.publisher);
    agent["skos:prefLabel"] = json!(catalog.publisher);
    agent["dcterms:spatial"] = json!({
        "@id": EU_LOCATION_IRI,
        "@type": "dcterms:Location",
    });
    agent
}

fn evidence_jsonld_nodes(compiled: &CompiledMetadata) -> Vec<Value> {
    let mut nodes = Vec::new();
    for requirement in compiled.requirements() {
        let evidence_type_lists = evidence_type_lists_for_requirement(compiled, requirement);
        let information_concepts = compiled
            .evidence_types()
            .filter(|evidence_type| evidence_type.proves.contains(&requirement.id))
            .flat_map(|evidence_type| evidence_type.information_concepts.iter())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|iri| iri_object(iri))
            .collect::<Vec<_>>();
        let evidence_type_list_refs = evidence_type_lists
            .iter()
            .map(|list| iri_object(&list.iri))
            .collect::<Vec<_>>();
        let mut requirement_node = json!({
            "@id": requirement.iri,
            "@type": requirement.rdf_type,
            "dcterms:identifier": requirement.id,
            "dcterms:title": requirement.title,
            "skos:prefLabel": requirement.title,
            "dcterms:description": requirement.description,
            "cccev:hasEvidenceTypeList": evidence_type_list_refs,
        });
        if !information_concepts.is_empty() {
            requirement_node["cccev:hasConcept"] = Value::Array(information_concepts);
        }
        let derived_from = requirement
            .reference_frameworks
            .iter()
            .map(|framework| iri_object(&framework.iri))
            .collect::<Vec<_>>();
        if !derived_from.is_empty() {
            requirement_node["cccev:isDerivedFrom"] = Value::Array(derived_from);
        }
        nodes.push(requirement_node);
        for list in evidence_type_lists {
            let mut list_node = json!({
                "@id": list.iri,
                "@type": "cccev:EvidenceTypeList",
                "dcterms:identifier": list.id,
                "skos:prefLabel": list.title,
                "cccev:specifiesEvidenceType": list
                    .evidence_types
                    .iter()
                    .map(|evidence_type| iri_object(&evidence_type.iri))
                    .collect::<Vec<_>>(),
            });
            if !list.description.is_empty() {
                list_node["dcterms:description"] = json!(list.description);
            }
            nodes.push(list_node);
        }
        for framework in &requirement.reference_frameworks {
            nodes.push(json!({
                "@id": framework.iri,
                "@type": "cccev:ReferenceFramework",
                "dcterms:identifier": framework.identifier,
            }));
        }
    }
    for evidence_type in compiled.evidence_types() {
        nodes.push(json!({
            "@id": evidence_type.iri,
            "@type": "cccev:EvidenceType",
            "dcterms:identifier": evidence_type.id,
            "dcterms:title": evidence_type.title,
            "skos:prefLabel": evidence_type.title,
            "dcterms:description": evidence_type.description,
            "cccev:isSpecifiedIn": evidence_type
                .proves
                .iter()
                .filter_map(|requirement_id| {
                    let requirement = compiled
                        .requirements()
                        .find(|candidate| candidate.id == *requirement_id)?;
                    Some(
                        evidence_type_lists_for_requirement(compiled, requirement)
                            .into_iter()
                            .filter(|list| {
                                list.evidence_types
                                    .iter()
                                    .any(|candidate| candidate.id == evidence_type.id)
                            })
                            .map(|list| iri_object(&list.iri))
                            .collect::<Vec<_>>(),
                    )
                })
                .flatten()
                .collect::<Vec<_>>(),
        }));
    }
    for concept_iri in compiled
        .evidence_types()
        .flat_map(|evidence_type| evidence_type.information_concepts.iter())
        .chain(compiled.forms().flat_map(|form| {
            compiled_form_fields(form)
                .into_iter()
                .filter_map(|field| field.concept.as_ref())
        }))
        .collect::<BTreeSet<_>>()
    {
        let identifier = information_concept_identifier(concept_iri);
        nodes.push(json!({
            "@id": concept_iri,
            "@type": "cccev:InformationConcept",
            "dcterms:identifier": identifier,
            "skos:prefLabel": identifier,
        }));
    }
    for offering in compiled.evidence_offerings() {
        let mut node = json!({
            "@id": offering.iri,
            "@type": "registry_manifest:EvidenceOffering",
            "dcterms:identifier": offering.id,
            "dcterms:title": offering.title,
            "dcterms:description": offering.description,
            "registry_manifest:evidenceType": iri_object(&offering.evidence_type_iri),
            "registry_manifest:issuingAuthority": issuing_authority_node(&offering.issuing_authority),
            "registry_manifest:accessKind": offering.access.kind,
            "registry_manifest:servesEntity": serves_entity_iri(&dataset_url_from_id(&offering.dataset_id), &offering.entity),
        });
        if let Some(endpoint_url) = offering.access.endpoint_url.as_deref() {
            let mut service = json!({
                "@id": format!("{}#evidence-service", offering.iri),
                "@type": "dcat:DataService",
                "dcat:endpointURL": endpoint_url,
            });
            if let Some(discovery_url) = offering.access.discovery_url.as_deref() {
                service["dcat:endpointDescription"] = json!(discovery_url);
            }
            if let Some(conforms_to) = offering.access.conforms_to.as_deref() {
                service["dcterms:conformsTo"] = json!(conforms_to);
            }
            node["registry_manifest:evidenceService"] = service;
        }
        nodes.push(node);
    }
    nodes
}

struct EvidenceTypeListRendering<'a> {
    id: String,
    iri: String,
    title: String,
    description: String,
    evidence_types: Vec<&'a CompiledEvidenceType>,
}

fn evidence_type_lists_for_requirement<'a>(
    compiled: &'a CompiledMetadata,
    requirement: &'a CompiledRequirement,
) -> Vec<EvidenceTypeListRendering<'a>> {
    if !requirement.evidence_type_lists.is_empty() {
        return requirement
            .evidence_type_lists
            .iter()
            .map(|list| EvidenceTypeListRendering {
                id: list.id.clone(),
                iri: list.iri.clone(),
                title: list.title.clone(),
                description: list.description.clone(),
                evidence_types: list
                    .evidence_types
                    .iter()
                    .filter_map(|id| compiled.evidence_type(id))
                    .collect(),
            })
            .collect();
    }

    let evidence_types = evidence_types_for_requirement(compiled, &requirement.id);
    let disambiguate = evidence_types.len() > 1;
    evidence_types
        .into_iter()
        .map(|evidence_type| EvidenceTypeListRendering {
            id: evidence_type_list_identifier(&requirement.id, &evidence_type.id, disambiguate),
            iri: evidence_type_list_iri(&requirement.iri, &evidence_type.id, disambiguate),
            title: format!(
                "Evidence type {} for {}",
                evidence_type.title, requirement.title
            ),
            description: String::new(),
            evidence_types: vec![evidence_type],
        })
        .collect()
}

fn evidence_types_for_requirement<'a>(
    compiled: &'a CompiledMetadata,
    requirement_id: &str,
) -> Vec<&'a CompiledEvidenceType> {
    compiled
        .evidence_types()
        .filter(|evidence_type| evidence_type.proves.iter().any(|id| id == requirement_id))
        .collect()
}

fn evidence_type_list_iri(
    requirement_iri: &str,
    evidence_type_id: &str,
    disambiguate: bool,
) -> String {
    let suffix = if disambiguate {
        format!("evidence-type-list-{evidence_type_id}")
    } else {
        "evidence-type-list".to_string()
    };
    if requirement_iri.contains('#') {
        format!("{requirement_iri}-{suffix}")
    } else {
        format!("{requirement_iri}#{suffix}")
    }
}

fn evidence_type_list_manifest_id(
    list: &EvidenceTypeListManifest,
    index: usize,
    total_lists: usize,
) -> String {
    list.id.clone().unwrap_or_else(|| {
        if total_lists == 1 {
            "evidence-type-list".to_string()
        } else {
            format!("evidence-type-list-{}", index + 1)
        }
    })
}

fn evidence_type_list_iri_from_id(requirement_iri: &str, list_id: &str) -> String {
    if requirement_iri.contains('#') {
        format!("{requirement_iri}-{list_id}")
    } else {
        format!("{requirement_iri}#{list_id}")
    }
}

// RFC 3986 §3.5 permits only one fragment delimiter ('#') per URI. When the
// dataset IRI is a fragment reference (starts with '#'), appending another '#'
// would produce an invalid double-fragment URI. Use '-' as the separator in
// that case, matching the same convention used by `evidence_type_list_iri`.
fn serves_entity_iri(dataset_iri: &str, entity_name: &str) -> String {
    if dataset_iri.contains('#') {
        format!("{dataset_iri}-entity-{entity_name}")
    } else {
        format!("{dataset_iri}#entity-{entity_name}")
    }
}

fn evidence_type_list_identifier(
    requirement_id: &str,
    evidence_type_id: &str,
    disambiguate: bool,
) -> String {
    if disambiguate {
        format!("{requirement_id}-{evidence_type_id}-evidence-type-list")
    } else {
        format!("{requirement_id}-evidence-type-list")
    }
}

fn information_concept_identifier(concept_iri: &str) -> String {
    concept_iri
        .rsplit(['#', '/'])
        .find(|segment| !segment.is_empty())
        .unwrap_or(concept_iri)
        .to_string()
}

fn issuing_authority_node(authority: &CompiledIssuingAuthority) -> Value {
    let mut node = json!({
        "@type": "foaf:Agent",
        "dcterms:identifier": authority.id,
        "foaf:name": authority.name,
    });
    if let Some(iri) = authority.iri.as_deref() {
        node["@id"] = json!(iri);
    }
    if let Some(country) = authority.country.as_deref() {
        node["registry_manifest:country"] = json!(country);
    }
    node
}

fn entity_shape(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
) -> Value {
    let properties = entity
        .fields
        .values()
        .map(|field| field_shape(compiled, dataset, entity, field))
        .chain(
            entity
                .relationships
                .iter()
                .map(|rel| relationship_shape(compiled, dataset, entity, rel)),
        )
        .collect::<Vec<_>>();
    json!({
        "@id": entity_schema_id(compiled, dataset, entity),
        "@type": "sh:NodeShape",
        "sh:targetClass": entity_class_uri(compiled, dataset, entity),
        "dcterms:isPartOf": dataset_url(dataset),
        "dcterms:identifier": format!("{}:{}", dataset.dataset_id, entity.name),
        "sh:name": entity.name,
        "sh:nodeKind": "sh:IRI",
        "registry_manifest:primaryKey": entity.primary_key,
        "sh:property": properties,
    })
}

fn field_shape(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
    field: &CompiledField,
) -> Value {
    let mut shape = json!({
        "@type": "sh:PropertyShape",
        "sh:path": field_property_uri(compiled, dataset, entity, field),
        "sh:name": field.name,
        "sh:nodeKind": "sh:Literal",
        "sh:datatype": shacl_datatype(field.field_type),
        "sh:minCount": if field.required { 1 } else { 0 },
        "sh:maxCount": 1,
    });
    if let Some(pattern) = field.constraints.pattern.as_deref() {
        shape["sh:pattern"] = json!(pattern);
    }
    if let Some(min_length) = field.constraints.min_length {
        shape["sh:minLength"] = json!(min_length);
    }
    if let Some(max_length) = field.constraints.max_length {
        shape["sh:maxLength"] = json!(max_length);
    }
    if !field.constraints.values.is_empty() {
        shape["sh:in"] = json!(field.constraints.values);
    }
    if let Some(scheme) = field.codelist_scheme_iri.as_deref() {
        shape["skos:inScheme"] = json!(scheme);
    }
    shape
}

fn relationship_shape(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
    relationship: &CompiledRelationship,
) -> Value {
    let target_class = dataset
        .entities
        .get(&relationship.target)
        .map(|target| entity_class_uri(compiled, dataset, target))
        .unwrap_or_else(|| {
            format!(
                "{}/metadata/datasets/{}/entities/{}",
                compiled.catalog().base_url,
                dataset.dataset_id,
                relationship.target
            )
        });
    let mut shape = json!({
        "@type": "sh:PropertyShape",
        "sh:path": relationship.concept_uri.clone().unwrap_or_else(|| {
            format!(
                "{}/metadata/datasets/{}/entities/{}/relationships/{}",
                compiled.catalog().base_url,
                dataset.dataset_id,
                entity.name,
                relationship.name
            )
        }),
        "sh:name": relationship.name,
        "sh:nodeKind": "sh:IRI",
        "registry_manifest:relationshipKind": relationship.cardinality,
        "registry_manifest:targetEntity": relationship.target,
        "sh:class": target_class,
    });
    if relationship.cardinality == "zero_or_one" || relationship.cardinality == "one" {
        shape["sh:maxCount"] = json!(1);
    }
    if relationship.cardinality == "one" {
        shape["sh:minCount"] = json!(1);
    }
    shape
}

fn manifest_codelist_shape(codelist: &CompiledCodelist) -> Value {
    codelist_shape(codelist, true)
}

fn standards_codelist_shape(codelist: &CompiledCodelist) -> Value {
    codelist_shape(codelist, false)
}

fn codelist_shape(codelist: &CompiledCodelist, include_manifest_metadata: bool) -> Value {
    let mut scheme = json!({
        "@id": codelist.scheme_iri,
        "@type": "skos:ConceptScheme",
        "dcterms:identifier": codelist.id,
        "dcterms:title": humanize_identifier(&codelist.id),
        "skos:prefLabel": humanize_identifier(&codelist.id),
        "skos:hasTopConcept": codelist.concepts.iter().map(|concept| {
            json!({
                "@id": concept
                    .iri
                    .clone()
                    .unwrap_or_else(|| format!(
                        "{}/{}",
                        codelist.scheme_iri.trim_end_matches('/'),
                        percent_encode_iri_path_segment(&concept.code)
                    )),
                "@type": "skos:Concept",
                "skos:notation": concept.code,
                "skos:prefLabel": concept.label.as_ref().map(LocalizedText::text),
                "skos:inScheme": codelist.scheme_iri,
            })
        }).collect::<Vec<_>>(),
    });
    if let Some(external_ref) = codelist.external_ref.as_deref() {
        scheme["rdfs:seeAlso"] = json!(external_ref);
    }
    if include_manifest_metadata {
        scheme["schema_version"] = json!(CODELIST_SCHEMA_VERSION);
        if let Some(version) = codelist.version.as_deref() {
            scheme["version"] = json!(version);
        }
        if let Some(valid_from) = codelist.valid_from.as_deref() {
            scheme["valid_from"] = json!(valid_from);
        }
        if let Some(valid_to) = codelist.valid_to.as_deref() {
            scheme["valid_to"] = json!(valid_to);
        }
    }
    scheme
}

fn percent_encode_iri_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn humanize_identifier(value: &str) -> String {
    value
        .split(['_', '-', '/'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn entity_json_schema(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
) -> Value {
    let properties = entity
        .fields
        .values()
        .map(|field| {
            let mut schema = json_schema_for_field(field);
            if let Some(concept) = field.concepts.first() {
                schema["x-concept-uri"] = json!(concept);
            }
            if let Some(codelist) = field.codelist_scheme_iri.as_deref() {
                schema["x-codelist"] = json!(codelist);
            }
            (field.name.clone(), schema)
        })
        .collect::<serde_json::Map<_, _>>();
    let required = entity
        .fields
        .values()
        .filter(|field| field.required)
        .map(|field| field.name.clone())
        .collect::<Vec<_>>();
    json!({
        "schema_version": ENTITY_JSON_SCHEMA_VERSION,
        "$schema": JSON_SCHEMA_DRAFT_2020_12,
        "$id": entity_schema_id(compiled, dataset, entity),
        "title": entity.title,
        "description": entity.description,
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn form_json_schema(form: &CompiledForm) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    for field in &form.fields {
        add_form_field_schema(field, &mut properties, &mut required);
    }
    for section in &form.sections {
        if section.repeatable {
            let mut item_properties = serde_json::Map::new();
            let mut item_required = Vec::new();
            for field in &section.fields {
                add_form_field_schema(field, &mut item_properties, &mut item_required);
            }
            let mut item_schema = json!({
                "type": "object",
                "additionalProperties": false,
                "properties": item_properties,
                "required": item_required,
            });
            if let Some(min_occurs) = section.min_occurs {
                item_schema["minProperties"] = json!(min_occurs);
            }
            let mut section_schema = json!({
                "type": "array",
                "items": item_schema,
            });
            if let Some(min_occurs) = section.min_occurs {
                section_schema["minItems"] = json!(min_occurs);
            }
            if let Some(max_occurs) = section.max_occurs {
                section_schema["maxItems"] = json!(max_occurs);
            }
            properties.insert(section.id.clone(), section_schema);
            if section.min_occurs.unwrap_or_default() > 0 {
                required.push(section.id.clone());
            }
        } else {
            for field in &section.fields {
                add_form_field_schema(field, &mut properties, &mut required);
            }
        }
    }

    json!({
        "schema_version": FORM_JSON_SCHEMA_VERSION,
        "$schema": JSON_SCHEMA_DRAFT_2020_12,
        "$id": form
            .validates_with
            .as_ref()
            .and_then(|validation| validation.json_schema.as_deref())
            .unwrap_or(&form.iri),
        "title": form.title,
        "description": form.description,
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn add_form_field_schema(
    field: &CompiledFormField,
    properties: &mut serde_json::Map<String, Value>,
    required: &mut Vec<String>,
) {
    let mut schema = json_schema_for_form_field(field);
    schema["title"] = json!(field.label);
    if let Some(concept) = field.concept.as_deref() {
        schema["x-concept-uri"] = json!(concept);
    }
    if let Some(requirement_id) = field.supports_requirement.as_deref() {
        schema["x-supports-requirement"] = json!(requirement_id);
    }
    if let Some(min_occurs) = field.min_occurs {
        schema["minItems"] = json!(min_occurs);
    }
    if let Some(max_occurs) = field.max_occurs {
        schema["maxItems"] = json!(max_occurs);
    }
    properties.insert(field.name.clone(), schema);
    if field.required || field.min_occurs.unwrap_or_default() > 0 {
        required.push(field.name.clone());
    }
}

fn json_schema_for_form_field(field: &CompiledFormField) -> Value {
    match field.data_type.as_deref() {
        Some("http://www.w3.org/2001/XMLSchema#boolean") => json!({ "type": "boolean" }),
        Some("http://www.w3.org/2001/XMLSchema#decimal")
        | Some("http://www.w3.org/2001/XMLSchema#double")
        | Some("http://www.w3.org/2001/XMLSchema#float") => json!({ "type": "number" }),
        Some("http://www.w3.org/2001/XMLSchema#integer")
        | Some("http://www.w3.org/2001/XMLSchema#int")
        | Some("http://www.w3.org/2001/XMLSchema#long") => json!({ "type": "integer" }),
        Some("http://www.w3.org/2001/XMLSchema#date") => {
            json!({ "type": "string", "format": "date" })
        }
        Some("http://www.w3.org/2001/XMLSchema#dateTime") => {
            json!({ "type": "string", "format": "date-time" })
        }
        _ => json!({ "type": "string" }),
    }
}

fn json_schema_for_field(field: &CompiledField) -> Value {
    let mut schema = match field.field_type {
        FieldType::String | FieldType::Code => json!({ "type": "string" }),
        FieldType::Number => json!({ "type": "number" }),
        FieldType::Integer => json!({ "type": "integer" }),
        FieldType::Boolean => json!({ "type": "boolean" }),
        FieldType::Date => json!({ "type": "string", "format": "date" }),
        FieldType::Timestamp => json!({ "type": "string", "format": "date-time" }),
    };
    if let Some(min_length) = field.constraints.min_length {
        schema["minLength"] = json!(min_length);
    }
    if let Some(max_length) = field.constraints.max_length {
        schema["maxLength"] = json!(max_length);
    }
    if let Some(pattern) = field.constraints.pattern.as_deref() {
        schema["pattern"] = json!(pattern);
    }
    if !field.constraints.values.is_empty() {
        schema["enum"] = json!(field.constraints.values);
    }
    schema
}

fn record_feature_json(dataset: &CompiledDataset) -> Value {
    json!({
        "id": dataset.dataset_id,
        "type": "Feature",
        "geometry": Value::Null,
        "properties": {
            "type": "Record",
            "resourceType": "dcat:Dataset",
            "title": dataset.title,
            "description": dataset.description,
            "identifier": dataset.dataset_id,
            "owner": dataset.owner,
            "accessRights": access_rights_name(dataset.access_rights),
            "updateFrequency": update_frequency_name(dataset.update_frequency),
            "conformsTo": dataset.conforms_to,
            "entities": dataset.entities.values().map(entity_record_summary).collect::<Vec<_>>(),
        },
    })
}

fn entity_record_summary(entity: &CompiledEntity) -> Value {
    json!({
        "name": entity.name,
        "title": entity.title,
        "description": entity.description,
        "conceptUri": entity.concept_uri,
    })
}

#[allow(dead_code)]
fn records_collection_json() -> Value {
    json!({
        "id": DATASETS_COLLECTION_ID,
        "title": "Dataset catalog records",
        "description": "Records describing Registry Relay datasets visible to the caller.",
        "itemType": "record",
    })
}

fn validate_non_empty(value: &str, path: impl Into<String>, errors: &mut Vec<ValidationError>) {
    if value.trim().is_empty() {
        errors.push(ValidationError::new(path, "value must not be empty"));
    }
}

fn is_valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' => true,
            b'0'..=b'9' | b'_' | b'-' => index > 0,
            _ => false,
        })
}

fn validate_id(value: &str, path: impl Into<String>, errors: &mut Vec<ValidationError>) {
    if !is_valid_id(value) {
        errors.push(ValidationError::new(
            path,
            "id must use lower-case letters, digits, hyphen, or underscore and start with a letter",
        ));
    }
}

fn validate_vocabularies(
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    for (prefix, namespace) in vocabularies {
        let path = format!("vocabularies.{prefix}");
        if let Some(builtin) = builtin_namespace(prefix) {
            if namespace != builtin {
                errors.push(ValidationError::new(
                    path,
                    "built-in vocabulary prefix must not be redefined",
                ));
            }
            continue;
        }
        if !is_valid_custom_vocabulary_prefix(prefix) {
            errors.push(ValidationError::new(
                path.clone(),
                "vocabulary prefix must use lower-case ASCII letters, digits, hyphen, or underscore and start with a letter",
            ));
        }
        if !is_well_formed_http_https_iri(namespace) {
            errors.push(ValidationError::new(
                path,
                "vocabulary namespace must be an absolute http:// or https:// IRI",
            ));
        }
    }
}

fn is_valid_custom_vocabulary_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' => true,
            b'0'..=b'9' | b'_' | b'-' => index > 0,
            _ => false,
        })
}

fn builtin_namespace(prefix: &str) -> Option<&'static str> {
    BUILTIN_VOCABULARIES
        .iter()
        .find_map(|(builtin_prefix, namespace)| (*builtin_prefix == prefix).then_some(*namespace))
}

fn validate_cardinality(value: &str, path: impl Into<String>, errors: &mut Vec<ValidationError>) {
    if !matches!(value, "one" | "zero_or_one" | "many" | "zero_or_more") {
        errors.push(ValidationError::new(
            path,
            "cardinality must be one, zero_or_one, many, or zero_or_more",
        ));
    }
}

fn is_supported_application_profile(id: &str) -> bool {
    matches!(id, "bregdcat-ap" | "cpsv-ap" | "dcat-ap")
}

fn validate_http_url(value: &str, path: impl Into<String>, errors: &mut Vec<ValidationError>) {
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        errors.push(ValidationError::new(
            path,
            "URL must start with http:// or https://",
        ));
    }
}

fn validate_https_url(value: &str, path: impl Into<String>, errors: &mut Vec<ValidationError>) {
    if !value.starts_with("https://") || https_url_host(value).is_none() {
        errors.push(ValidationError::new(
            path,
            "URL must start with https:// and include a host",
        ));
    }
}

fn https_url_host(value: &str) -> Option<String> {
    value
        .strip_prefix("https://")
        .and_then(url_host_after_scheme)
}

fn url_host(value: &str) -> Option<String> {
    value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .and_then(url_host_after_scheme)
}

// Returns the full authority (host plus port when present), lower-cased, so that
// did:web bindings can match the issuer URL on origin boundary, not just host.
fn url_host_after_scheme(remainder: &str) -> Option<String> {
    let authority = remainder
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty())?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn did_web_host(node_id: &str) -> Option<String> {
    node_id
        .strip_prefix("did:web:")
        .and_then(|method_id| method_id.split(':').next())
        .filter(|host| !host.is_empty())
        .map(|host| {
            host.replace("%3A", ":")
                .replace("%3a", ":")
                .replace("%5B", "[")
                .replace("%5b", "[")
                .replace("%5D", "]")
                .replace("%5d", "]")
                .to_ascii_lowercase()
        })
}

fn validate_dataset_public_service_id(
    value: &str,
    path: impl Into<String>,
    errors: &mut Vec<ValidationError>,
) {
    if is_valid_id(value) || is_well_formed_http_https_iri(value) {
        return;
    }
    errors.push(ValidationError::new(
        path,
        "dataset public service id must be a local id or absolute http:// or https:// IRI",
    ));
}

fn validate_codelist_concept(
    concept: &CodelistConcept,
    path: &str,
    concept_codes: &mut BTreeSet<String>,
    errors: &mut Vec<ValidationError>,
) {
    if concept.code.trim().is_empty() {
        errors.push(ValidationError::new(
            format!("{path}.code"),
            "codelist concept code must not be empty",
        ));
    }
    if concept.code.chars().any(char::is_control) {
        errors.push(ValidationError::new(
            format!("{path}.code"),
            "codelist concept code must not contain control characters",
        ));
    }
    if !concept_codes.insert(concept.code.clone()) {
        errors.push(ValidationError::new(
            format!("{path}.code"),
            "codelist concept code must be unique within a codelist",
        ));
    }
}

fn validate_uri(
    value: &str,
    path: impl Into<String>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    validate_optional_uri(Some(value), path, vocabularies, errors);
}

fn validate_uri_list(
    values: &[String],
    path: impl Into<String>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    let path = path.into();
    for (index, value) in values.iter().enumerate() {
        validate_uri(value, format!("{path}[{index}]"), vocabularies, errors);
    }
}

fn validate_uri_or_code_list(
    values: &[String],
    path: impl Into<String>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    let path = path.into();
    for (index, value) in values.iter().enumerate() {
        if expand_uri(value, vocabularies).is_none()
            && (value.trim().is_empty() || value.contains(':'))
        {
            errors.push(ValidationError::new(
                format!("{path}[{index}]"),
                "value must be an IRI, compact IRI, or non-empty procedure code",
            ));
        }
    }
}

fn validate_optional_uri(
    value: Option<&str>,
    path: impl Into<String>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    let Some(value) = value else {
        return;
    };
    if expand_uri(value, vocabularies).is_none() {
        errors.push(ValidationError::new(
            path,
            "URI must be absolute or use a configured vocabulary prefix",
        ));
    }
}

fn expand_uri(uri: &str, vocabularies: &BTreeMap<String, String>) -> Option<String> {
    if is_well_formed_http_https_iri(uri)
        || ((uri.starts_with("urn:") || uri.starts_with("did:")) && is_sane_expanded_iri(uri))
    {
        return Some(uri.to_string());
    }
    let (prefix, suffix) = uri.split_once(':')?;
    let base =
        builtin_namespace(prefix).or_else(|| vocabularies.get(prefix).map(String::as_str))?;
    let expanded = format!("{base}{suffix}");
    is_well_formed_http_https_iri(&expanded).then_some(expanded)
}

fn expand_policy_uri(uri: &str, vocabularies: &BTreeMap<String, String>) -> Option<String> {
    if let Some(expanded) = expand_uri(uri, vocabularies) {
        return Some(expanded);
    }
    let (prefix, suffix) = uri.split_once(':')?;
    let base = match prefix {
        "odrl" => "http://www.w3.org/ns/odrl/2/",
        "dcterms" => "http://purl.org/dc/terms/",
        "xsd" => "http://www.w3.org/2001/XMLSchema#",
        _ => return None,
    };
    let expanded = format!("{base}{suffix}");
    is_sane_expanded_iri(&expanded).then_some(expanded)
}

fn is_well_formed_http_https_iri(value: &str) -> bool {
    let Ok(iri) = Iri::parse(value) else {
        return false;
    };
    (iri.scheme().eq_ignore_ascii_case("http") || iri.scheme().eq_ignore_ascii_case("https"))
        && iri
            .authority()
            .is_some_and(|authority| !authority.trim().is_empty())
        && is_sane_expanded_iri(value)
}

fn is_sane_expanded_iri(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(|ch| {
            ch.is_ascii_whitespace()
                || ch.is_control()
                || matches!(ch, '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`')
        })
}

fn normalized_base_url(base_url: &str) -> String {
    base_url.trim_end_matches('/').to_string()
}

fn dataset_url(dataset: &CompiledDataset) -> String {
    dataset_url_from_id(&dataset.dataset_id)
}

fn dataset_url_from_id(dataset_id: &str) -> String {
    format!("#dataset-{dataset_id}")
}

fn entity_schema_id(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
) -> String {
    format!(
        "{}/metadata/schema/{}/{}/schema.json",
        compiled.catalog().base_url,
        dataset.dataset_id,
        entity.name
    )
}

fn field_property_uri(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
    field: &CompiledField,
) -> String {
    field.concepts.first().cloned().unwrap_or_else(|| {
        format!(
            "{}/metadata/datasets/{}/entities/{}/fields/{}",
            compiled.catalog().base_url,
            dataset.dataset_id,
            entity.name,
            field.name
        )
    })
}

fn entity_class_uri(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
) -> String {
    entity.concept_uri.clone().unwrap_or_else(|| {
        format!(
            "{}/metadata/datasets/{}/entities/{}",
            compiled.catalog().base_url,
            dataset.dataset_id,
            entity.name
        )
    })
}

fn shacl_datatype(field_type: FieldType) -> &'static str {
    match field_type {
        FieldType::String | FieldType::Code => "xsd:string",
        FieldType::Number => "xsd:decimal",
        FieldType::Integer => "xsd:integer",
        FieldType::Boolean => "xsd:boolean",
        FieldType::Date => "xsd:date",
        FieldType::Timestamp => "xsd:dateTime",
    }
}

fn adms_status_uri(status: AdmsStatus) -> &'static str {
    match status {
        AdmsStatus::UnderDevelopment => "http://purl.org/adms/status/UnderDevelopment",
        AdmsStatus::Active => "http://purl.org/adms/status/Active",
        AdmsStatus::Completed => "http://purl.org/adms/status/Completed",
        AdmsStatus::Deprecated => "http://purl.org/adms/status/Deprecated",
        AdmsStatus::Withdrawn => "http://purl.org/adms/status/Withdrawn",
    }
}

fn access_rights_uri(access_rights: AccessRights) -> &'static str {
    match access_rights {
        AccessRights::Public => {
            "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
        }
        AccessRights::Restricted => {
            "http://publications.europa.eu/resource/authority/access-right/RESTRICTED"
        }
        AccessRights::NonPublic => {
            "http://publications.europa.eu/resource/authority/access-right/NON_PUBLIC"
        }
    }
}

fn frequency_uri(frequency: UpdateFrequency) -> &'static str {
    match frequency {
        UpdateFrequency::Continuous => {
            "http://publications.europa.eu/resource/authority/frequency/CONT"
        }
        UpdateFrequency::Daily => {
            "http://publications.europa.eu/resource/authority/frequency/DAILY"
        }
        UpdateFrequency::Weekly => {
            "http://publications.europa.eu/resource/authority/frequency/WEEKLY"
        }
        UpdateFrequency::Monthly => {
            "http://publications.europa.eu/resource/authority/frequency/MONTHLY"
        }
        UpdateFrequency::Quarterly => {
            "http://publications.europa.eu/resource/authority/frequency/QUARTERLY"
        }
        UpdateFrequency::Annual => {
            "http://publications.europa.eu/resource/authority/frequency/ANNUAL"
        }
        UpdateFrequency::Irregular => {
            "http://publications.europa.eu/resource/authority/frequency/IRREG"
        }
        UpdateFrequency::AsNeeded => {
            "http://publications.europa.eu/resource/authority/frequency/AS_NEEDED"
        }
        UpdateFrequency::Termly | UpdateFrequency::Unknown => {
            "http://publications.europa.eu/resource/authority/frequency/UNKNOWN"
        }
    }
}

fn sensitivity_name(sensitivity: Sensitivity) -> &'static str {
    match sensitivity {
        Sensitivity::Public => "public",
        Sensitivity::Internal => "internal",
        Sensitivity::Personal => "personal",
        Sensitivity::Confidential => "confidential",
        Sensitivity::Secret => "secret",
    }
}

fn access_rights_name(access_rights: AccessRights) -> &'static str {
    match access_rights {
        AccessRights::Public => "public",
        AccessRights::Restricted => "restricted",
        AccessRights::NonPublic => "non_public",
    }
}

fn update_frequency_name(update_frequency: UpdateFrequency) -> &'static str {
    match update_frequency {
        UpdateFrequency::Continuous => "continuous",
        UpdateFrequency::Daily => "daily",
        UpdateFrequency::Weekly => "weekly",
        UpdateFrequency::Termly => "termly",
        UpdateFrequency::Monthly => "monthly",
        UpdateFrequency::Quarterly => "quarterly",
        UpdateFrequency::Annual => "annual",
        UpdateFrequency::Irregular => "irregular",
        UpdateFrequency::AsNeeded => "as_needed",
        UpdateFrequency::Unknown => "unknown",
    }
}

fn field_type_name(field_type: FieldType) -> &'static str {
    match field_type {
        FieldType::String => "string",
        FieldType::Number => "number",
        FieldType::Integer => "integer",
        FieldType::Boolean => "boolean",
        FieldType::Date => "date",
        FieldType::Timestamp => "timestamp",
        FieldType::Code => "code",
    }
}

#[allow(dead_code)]
fn ogc_records_conformance() -> Value {
    json!([
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-core",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-collection",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-api",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/json",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/oas30",
    ])
}

fn jsonld_context() -> Value {
    let mut context = json!({
        "adms": "http://www.w3.org/ns/adms#",
        "dcat": "http://www.w3.org/ns/dcat#",
        "dcterms": "http://purl.org/dc/terms/",
        "foaf": "http://xmlns.com/foaf/0.1/",
        "odrl": "http://www.w3.org/ns/odrl/2/",
        "sh": "http://www.w3.org/ns/shacl#",
        "skos": "http://www.w3.org/2004/02/skos/core#",
        "registry_manifest": "https://registry-manifest.dev/ns/v1#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "adms:status": { "@type": "@id" },
        "dcat:accessURL": { "@type": "@id" },
        "dcat:accessService": { "@type": "@id" },
        "dcat:dataset": { "@type": "@id" },
        "dcat:distribution": { "@type": "@id" },
        "dcat:endpointDescription": { "@type": "@id" },
        "dcat:endpointURL": { "@type": "@id" },
        "dcat:landingPage": { "@type": "@id" },
        "dcat:mediaType": { "@type": "@id" },
        "dcat:servesDataset": { "@type": "@id" },
        "dcat:theme": { "@type": "@id" },
        "dcat:themeTaxonomy": { "@type": "@id" },
        "dcterms:accessRights": { "@type": "@id" },
        "dcterms:accrualPeriodicity": { "@type": "@id" },
        "dcterms:conformsTo": { "@type": "@id" },
        "dcterms:format": { "@type": "@id" },
        "dcterms:isPartOf": { "@type": "@id" },
        "dcterms:spatial": { "@type": "@id" },
        "dcterms:type": { "@type": "@id" },
        "sh:class": { "@type": "@id" },
        "sh:datatype": { "@type": "@id" },
        "sh:nodeKind": { "@type": "@id" },
        "sh:path": { "@type": "@id" },
        "sh:targetClass": { "@type": "@id" },
        "skos:hasTopConcept": { "@type": "@id" },
        "skos:inScheme": { "@type": "@id" },
        "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
        "rdfs:seeAlso": { "@type": "@id" },
    });
    if let Some(object) = context.as_object_mut() {
        object.insert(
            "schema_version".to_string(),
            json!("registry_manifest:schemaVersion"),
        );
        object.insert("version".to_string(), json!("registry_manifest:version"));
        object.insert(
            "valid_from".to_string(),
            json!("registry_manifest:validFrom"),
        );
        object.insert("valid_to".to_string(), json!("registry_manifest:validTo"));
    }
    context
}

fn standards_jsonld_context(mut context: Value) -> Value {
    if let Some(object) = context.as_object_mut() {
        for term in ["schema_version", "version", "valid_from", "valid_to"] {
            object.remove(term);
        }
    }
    context
}

fn jsonld_context_with_policy_terms() -> Value {
    let mut context = jsonld_context();
    if let Some(object) = context.as_object_mut() {
        for term in [
            "odrl:action",
            "odrl:assignee",
            "odrl:assigner",
            "odrl:hasPolicy",
            "odrl:leftOperand",
            "odrl:operator",
            "odrl:profile",
            "odrl:target",
            "odrl:uid",
            "odrl:unit",
        ] {
            object.insert(term.to_string(), json!({ "@type": "@id" }));
        }
    }
    context
}

fn jsonld_context_with_public_service_terms() -> Value {
    let mut context = jsonld_context_with_policy_terms();
    if let Some(object) = context.as_object_mut() {
        object.insert("cpsv".to_string(), json!("http://purl.org/vocab/cpsv#"));
        object.insert("cv".to_string(), json!("http://data.europa.eu/m8g/"));
        object.insert("dcatap".to_string(), json!("http://data.europa.eu/r5r/"));
        object.insert(
            "eli".to_string(),
            json!("http://data.europa.eu/eli/ontology#"),
        );
        object.insert(
            "dcatap:applicableLegislation".to_string(),
            json!({ "@type": "@id" }),
        );
        object.insert("cpsv:produces".to_string(), json!({ "@type": "@id" }));
        object.insert(
            "cpsv:holdsRequirement".to_string(),
            json!({ "@type": "@id" }),
        );
        object.insert("cv:hasChannel".to_string(), json!({ "@type": "@id" }));
        object.insert(
            "cv:hasCompetentAuthority".to_string(),
            json!({ "@type": "@id" }),
        );
        object.insert("cv:holdsRequirement".to_string(), json!({ "@type": "@id" }));
    }
    context
}

fn jsonld_context_with_evidence_terms() -> Value {
    let mut context = jsonld_context_with_public_service_terms();
    if let Some(object) = context.as_object_mut() {
        object.insert("cccev".to_string(), json!("http://data.europa.eu/m8g/"));
        object.insert(
            "skos".to_string(),
            json!("http://www.w3.org/2004/02/skos/core#"),
        );
        for term in [
            "cccev:hasConcept",
            "cccev:hasEvidenceTypeList",
            "cccev:isDerivedFrom",
            "cccev:isSpecifiedIn",
            "cccev:specifiesEvidenceType",
            "registry_manifest:evidenceType",
            "registry_manifest:evidenceService",
            "registry_manifest:issuingAuthority",
            "registry_manifest:servesEntity",
            "registry_manifest:usesDataService",
            "registry_manifest:dataType",
        ] {
            object.insert(term.to_string(), json!({ "@type": "@id" }));
        }
    }
    context
}

fn jsonld_context_with_service_catalogue_terms() -> Value {
    let mut context = jsonld_context_with_evidence_terms();
    if let Some(object) = context.as_object_mut() {
        for term in [
            "dcat:service",
            "registry_manifest:forChannel",
            "registry_manifest:forPublicService",
            "registry_manifest:hasField",
            "registry_manifest:hasForm",
            "registry_manifest:hasSection",
            "registry_manifest:supportsRequirement",
            "registry_manifest:validatesWithJsonSchema",
            "registry_manifest:validatesWithShacl",
        ] {
            object.insert(term.to_string(), json!({ "@type": "@id" }));
        }
    }
    context
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    fn manifest(raw: &str) -> MetadataManifest {
        serde_yaml_ng::from_str(raw).expect("manifest parses")
    }

    #[test]
    fn source_manifest_digest_is_stable_for_yaml_formatting_and_key_order() {
        let first = manifest(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
vocabularies:
  ex: https://example.test/
datasets: []
"#,
        );
        let second = manifest(
            r#"
# Comments and mapping order do not affect the typed canonical digest.
vocabularies: {ex: "https://example.test/"}
datasets: []
catalog:
  publisher: {name: "Publisher"}
  title: "Demo"
  base_url: "https://metadata.example.test"
  id: demo
schema_version: registry-manifest/v1
"#,
        );

        assert_eq!(
            source_manifest_digest(&first).expect("first digest"),
            source_manifest_digest(&second).expect("second digest")
        );
    }

    #[test]
    fn source_manifest_digest_moves_for_typed_changes_and_array_order() {
        let first = manifest(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
  conforms_to: [https://example.test/a, https://example.test/b]
datasets: []
"#,
        );
        let changed_field = manifest(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Changed
  publisher:
    name: Publisher
  conforms_to: [https://example.test/a, https://example.test/b]
datasets: []
"#,
        );
        let changed_order = manifest(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
  conforms_to: [https://example.test/b, https://example.test/a]
datasets: []
"#,
        );

        let digest = source_manifest_digest(&first).expect("first digest");
        assert_ne!(
            digest,
            source_manifest_digest(&changed_field).expect("field digest")
        );
        assert_ne!(
            digest,
            source_manifest_digest(&changed_order).expect("order digest")
        );
    }
}
