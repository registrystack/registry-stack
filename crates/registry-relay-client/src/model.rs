use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeStatus {
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceMetadata {
    pub registry_identifier: String,
    pub name: String,
    pub authority: Institution,
    pub operator: Option<Institution>,
    pub authoritative_scope: String,
    pub product: Product,
    pub api_binding: ApiBinding,
    pub alignment_targets: Vec<AlignmentTarget>,
    pub capabilities: Vec<Capability>,
    pub links: ServiceLinks,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Institution {
    pub identifier: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Product {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApiBinding {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AlignmentTarget {
    pub name: String,
    pub version: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfr_target: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceLinks {
    #[serde(rename = "self")]
    pub self_: String,
    pub resources: String,
    pub openapi: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "family")]
pub enum Capability {
    #[serde(rename = "consultation")]
    Consultation(ConsultationCapability),
    #[serde(rename = "aggregate-data")]
    AggregateData(AggregateDataCapability),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConsultationCapability {
    pub pattern: String,
    pub resource_identifier: String,
    pub operation_identifier: String,
    pub access_profile_identifier: String,
    pub is_default: bool,
    pub disclosure_profile: String,
    pub schema_reference: String,
    pub semantic_model_reference: String,
    pub context_reference: String,
    pub href: String,
    pub wire_formats: Vec<WireFormatCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spatial_query: Option<SpatialQueryCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processing_reference: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireFormatCapability {
    pub id: String,
    pub media_type: String,
    #[serde(default)]
    pub format_profiles: Vec<FormatProfileCapability>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FormatProfileCapability {
    pub id: String,
    pub uri: String,
    pub crs: String,
    #[serde(default)]
    pub conforms_to: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SpatialQueryCapability {
    pub bbox: BboxCapability,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BboxCapability {
    pub crs: String,
    pub predicate: String,
    pub maximum_longitude_span_degrees: f64,
    pub maximum_latitude_span_degrees: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AggregateDataCapability {
    pub pattern: String,
    pub statistical_dataset_identifier: String,
    pub operation_identifier: String,
    pub profile: SdmxProfile,
    pub wire_formats: Vec<SdmxWireFormat>,
    pub href: String,
    pub structure_links: SdmxStructureLinks,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SdmxProfile {
    pub sdmx_rest_version: String,
    pub sdmx_data_json_version: String,
    pub sdmx_data_csv_version: String,
    pub sdmx_structure_json_version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SdmxWireFormat {
    pub id: String,
    pub media_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SdmxStructureLinks {
    pub dataflow: String,
    pub datastructure: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceDocument {
    pub resource_identifier: String,
    pub title: String,
    pub description: String,
    pub semantic_class: String,
    pub enumeration_posture: String,
    pub capabilities: Vec<Capability>,
    pub links: ResourceLinks,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceLinks {
    #[serde(rename = "self")]
    pub self_: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceCollection {
    pub items: Vec<ResourceDocument>,
    pub page_info: CursorPageInfo,
    pub meta: RegistryMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceEnvelope {
    pub data: ResourceDocument,
    pub meta: RegistryMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryMetadata {
    pub registry_identifier: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CursorPageInfo {
    pub next_cursor: Option<String>,
}

/// The fixed shared context for one homogeneous Registry Record response.
///
/// This belongs to a JSON or JSON-LD response's `meta`, never to an individual
/// [`Record`]. GeoJSON is a separately named media profile and uses
/// [`GeoJsonRecordProperties`].
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryRecordContext {
    pub registry_identifier: String,
    pub dataset_identifier: String,
    pub entity_type_identifier: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Record {
    pub record_identifier: String,
    pub revision_identifier: String,
    pub lifecycle_state: String,
    pub schema_reference: String,
    pub semantic_model_reference: String,
    pub authority_identifier: String,
    pub recorded_at: String,
    pub domain_data: BTreeMap<String, Value>,
    #[serde(rename = "@id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_ld_id: Option<String>,
    #[serde(rename = "@type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_ld_type: Option<String>,
}

impl Record {
    fn has_json_ld_identity(&self) -> bool {
        self.json_ld_id.is_some() && self.json_ld_type.is_some()
    }

    fn has_no_json_ld_identity(&self) -> bool {
        self.json_ld_id.is_none() && self.json_ld_type.is_none()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordResponseMetadata {
    pub registry_identifier: String,
    pub dataset_identifier: String,
    pub entity_type_identifier: String,
    pub operation_identifier: String,
    pub access_profile: String,
    pub family: String,
    pub pattern: String,
    pub disclosure_profile: String,
    pub contract_revision: String,
    pub source_revision: SourceRevision,
    pub selected_fields: Vec<String>,
    pub links: RecordLinks,
}

impl RecordResponseMetadata {
    #[must_use]
    pub fn registry_record_context(&self) -> RegistryRecordContext {
        RegistryRecordContext {
            registry_identifier: self.registry_identifier.clone(),
            dataset_identifier: self.dataset_identifier.clone(),
            entity_type_identifier: self.entity_type_identifier.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceRevision {
    pub profile: String,
    pub status: String,
    pub value: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecordLinks {
    #[serde(rename = "self")]
    pub self_: String,
    pub context: String,
    pub schema: String,
    #[serde(rename = "semanticModel")]
    pub semantic_model: String,
}

/// The governed JSON-LD context array returned by Relay Record responses.
///
/// It always contains the fixed Registry Record context followed by the
/// Relay operation context. The latter is also exposed by `meta.links.context`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayJsonLdContext {
    relay_context: String,
}

impl RelayJsonLdContext {
    pub const REGISTRY_RECORD_CONTEXT_ID: &'static str =
        "https://id.registrystack.org/contexts/registry-record/v1";

    #[must_use]
    pub fn relay_context(&self) -> &str {
        &self.relay_context
    }
}

impl Serialize for RelayJsonLdContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        [
            Self::REGISTRY_RECORD_CONTEXT_ID,
            self.relay_context.as_str(),
        ]
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RelayJsonLdContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        let [registry_record_context, relay_context] = values.as_slice() else {
            return Err(serde::de::Error::custom(
                "a Relay JSON-LD context must contain exactly two context identifiers",
            ));
        };
        if registry_record_context != Self::REGISTRY_RECORD_CONTEXT_ID || relay_context.is_empty() {
            return Err(serde::de::Error::custom(
                "a Relay JSON-LD context must begin with the Registry Record context and include a Relay context",
            ));
        }
        Ok(Self {
            relay_context: relay_context.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordEnvelope {
    pub data: Record,
    pub meta: RecordResponseMetadata,
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_ld_context: Option<RelayJsonLdContext>,
}

impl RecordEnvelope {
    pub(crate) fn matches_json_ld_representation(&self) -> bool {
        self.json_ld_context
            .as_ref()
            .is_some_and(|context| context.relay_context() == self.meta.links.context)
            && self.data.has_json_ld_identity()
    }

    pub(crate) fn matches_json_representation(&self) -> bool {
        self.json_ld_context.is_none() && self.data.has_no_json_ld_identity()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordCollection {
    pub items: Vec<Record>,
    pub page_info: CursorPageInfo,
    pub meta: RecordResponseMetadata,
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_ld_context: Option<RelayJsonLdContext>,
}

impl RecordCollection {
    pub(crate) fn matches_json_ld_representation(&self) -> bool {
        self.json_ld_context
            .as_ref()
            .is_some_and(|context| context.relay_context() == self.meta.links.context)
            && self.items.iter().all(Record::has_json_ld_identity)
    }

    pub(crate) fn matches_json_representation(&self) -> bool {
        self.json_ld_context.is_none() && self.items.iter().all(Record::has_no_json_ld_identity)
    }
}

/// Relay's separate GeoJSON record-properties contract.
///
/// Unlike the Registry Record JSON and JSON-LD profiles, this media profile
/// keeps its Registry identifier in feature properties.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GeoJsonRecordProperties {
    pub registry_identifier: String,
    pub record_identifier: String,
    pub revision_identifier: String,
    pub lifecycle_state: String,
    pub schema_reference: String,
    pub semantic_model_reference: String,
    pub authority_identifier: String,
    pub recorded_at: String,
    pub domain_data: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GeoJsonFeature {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub geometry: Value,
    pub properties: GeoJsonRecordProperties,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<RelayRecordMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conforms_to: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coord_ref_sys: Option<String>,
}

/// Relay-owned metadata in GeoJSON, which does not use the shared Registry
/// Record response envelope.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelayRecordMetadata {
    pub operation_identifier: String,
    pub access_profile: String,
    pub family: String,
    pub pattern: String,
    pub disclosure_profile: String,
    pub contract_revision: String,
    pub source_revision: SourceRevision,
    pub selected_fields: Vec<String>,
    pub links: RecordLinks,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GeoJsonFeatureCollection {
    #[serde(rename = "type")]
    pub kind: String,
    pub features: Vec<GeoJsonFeature>,
    pub page_info: CursorPageInfo,
    pub meta: RelayRecordMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conforms_to: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coord_ref_sys: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(untagged)]
pub enum RecordResponse {
    Json(RecordEnvelope),
    GeoJson(GeoJsonFeature),
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(untagged)]
pub enum RecordCollectionResponse {
    Json(RecordCollection),
    GeoJson(GeoJsonFeatureCollection),
}

/// Lookup selectors are intentionally dynamic, but the outer body is exact.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LookupBody<'a> {
    pub selectors: &'a BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_record_context_is_response_metadata_not_record_data() {
        let probe = serde_json::from_value::<ProbeStatus>(serde_json::json!({
            "status": "ok",
            "canary": "must be refused"
        }));
        assert!(probe.is_err());

        let record = serde_json::from_value::<Record>(serde_json::json!({
            "recordIdentifier": "record-1",
            "revisionIdentifier": "revision-1",
            "lifecycleState": "active",
            "schemaReference": "https://example.invalid/schema",
            "semanticModelReference": "https://example.invalid/semantics",
            "authorityIdentifier": "authority",
            "recordedAt": "2026-08-11T00:00:00Z",
            "domainData": {"adopterOwnedNestedShape": {"answer": 42}}
        }))
        .expect("dynamic domain data is retained");
        assert_eq!(record.domain_data["adopterOwnedNestedShape"]["answer"], 42);

        assert!(serde_json::from_value::<Record>(serde_json::json!({
            "registryIdentifier": "legacy-placement",
            "recordIdentifier": "record-1",
            "revisionIdentifier": "revision-1",
            "lifecycleState": "active",
            "schemaReference": "https://example.invalid/schema",
            "semanticModelReference": "https://example.invalid/semantics",
            "authorityIdentifier": "authority",
            "recordedAt": "2026-08-11T00:00:00Z",
            "domainData": {}
        }))
        .is_err());
    }

    #[test]
    fn governed_json_ld_context_requires_the_fixed_shared_context_and_relay_context() {
        let valid = serde_json::json!([
            RelayJsonLdContext::REGISTRY_RECORD_CONTEXT_ID,
            "https://relay.example.invalid/contexts/record.jsonld"
        ]);
        let context =
            serde_json::from_value::<RelayJsonLdContext>(valid).expect("governed context parses");
        assert_eq!(
            context.relay_context(),
            "https://relay.example.invalid/contexts/record.jsonld"
        );

        for invalid in [
            serde_json::json!(RelayJsonLdContext::REGISTRY_RECORD_CONTEXT_ID),
            serde_json::json!([
                "https://example.invalid/wrong",
                "https://relay.example.invalid/context"
            ]),
            serde_json::json!([RelayJsonLdContext::REGISTRY_RECORD_CONTEXT_ID, ""]),
            serde_json::json!([
                RelayJsonLdContext::REGISTRY_RECORD_CONTEXT_ID,
                "https://relay.example.invalid/context",
                "extra"
            ]),
        ] {
            assert!(serde_json::from_value::<RelayJsonLdContext>(invalid).is_err());
        }
    }
}
