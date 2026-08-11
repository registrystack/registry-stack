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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Record {
    pub registry_identifier: String,
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordMetadata {
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordEnvelope {
    pub data: Record,
    pub meta: RecordMetadata,
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_ld_context: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordCollection {
    pub items: Vec<Record>,
    pub page_info: CursorPageInfo,
    pub meta: RecordMetadata,
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_ld_context: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GeoJsonFeature {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub geometry: Value,
    pub properties: Record,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<RecordMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conforms_to: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coord_ref_sys: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GeoJsonFeatureCollection {
    #[serde(rename = "type")]
    pub kind: String,
    pub features: Vec<GeoJsonFeature>,
    pub page_info: CursorPageInfo,
    pub meta: RecordMetadata,
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
    fn fixed_envelopes_reject_unknown_members_but_domain_records_remain_dynamic() {
        let probe = serde_json::from_value::<ProbeStatus>(serde_json::json!({
            "status": "ok",
            "canary": "must be refused"
        }));
        assert!(probe.is_err());

        let record = serde_json::from_value::<Record>(serde_json::json!({
            "registryIdentifier": "registry",
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
    }
}
