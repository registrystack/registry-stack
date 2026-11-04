// SPDX-License-Identifier: Apache-2.0

//! Authored deployment metadata for the built-in GovStack Consultation
//! facade. Protocol paths, envelopes, problems, and capability names remain
//! host-owned Rust definitions; the project supplies only deployment facts.

use registry_platform_yaml::{ExternalId, LocalId, UniqueIdList, UniqueList};
use serde::{Deserialize, Serialize};

/// One deployment of the built-in Consultation facade.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsultationFacade {
    /// Version-specific HTTPS OpenAPI contract published for this deployment.
    pub contract: String,
    /// Collection metadata, unique by the record type that also supplies the
    /// collection identifier on the wire.
    pub collections: UniqueIdList<ConsultationCollection>,
}

/// Deployment metadata for one project record type and public view.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsultationCollection {
    /// Project record type and literal Consultation collection identifier.
    pub record_type: LocalId,
    /// Stable identifier of the Registry that owns the Records.
    pub registry: String,
    /// Public view named by the concrete OpenAPI operation metadata.
    pub view: LocalId,
    /// Pinned project schema for the public `data` member of this view.
    pub data_schema: LocalId,
    /// Exact-selector metadata, required only when Lookup is bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup: Option<ConsultationLookup>,
    /// Named-search metadata, required only when Search is bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<ConsultationSearch>,
}

impl registry_platform_yaml::Identified for ConsultationCollection {
    fn id(&self) -> &str {
        self.record_type.as_str()
    }
}

/// One exact selector and the project schema of its `values` member.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsultationLookup {
    /// Exact, at-most-one selector promised by the selected source route.
    pub selector: LocalId,
    pub input_schema: LocalId,
}

/// One named Search and the project schema of its `criteria` member.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsultationSearch {
    pub search: LocalId,
    pub input_schema: LocalId,
}

/// Source-neutral read semantics a pack explicitly promises for one route.
/// Public Consultation capability, selector, Search, schema, and view names
/// belong to the project and never enter this reusable source contract.
/// The host never infers guarantees from a route name or a successfully
/// decoded body.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SourceReadSupport {
    /// Exact resolution that returns at most one source item for the complete
    /// native input key. A project can map this to Retrieve or Lookup.
    ReadOne { inputs: UniqueList<ExternalId> },
    /// A bounded page with explicit completion and a deterministic order.
    /// A project can map supported native inputs to List filters or a named
    /// Search without changing this source-owned contract.
    ReadPage {
        #[serde(default)]
        inputs: UniqueList<SourceReadInput>,
        order: UniqueList<SourceOrderTerm>,
        unique_tie_breaker: ExternalId,
    },
}

registry_platform_yaml::tagged_union!(SourceReadSupport, tag = "type");
crate::model::serialize_tagged_union!(SourceReadSupport, tag = "type");

/// One source-native page input and the comparisons the source route
/// implements for it. Names are pack-local, not public field names.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceReadInput {
    pub name: ExternalId,
    pub comparisons: UniqueList<SourceComparison>,
}

/// Closed reusable comparison semantics a source route can implement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SourceComparison {
    Equality,
    Range,
    SetMembership,
    Prefix,
}

/// One deterministic source order term. Direction is explicit so a project
/// and generated contract never infer it from a provider default.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceOrderTerm {
    pub name: ExternalId,
    pub direction: SourceOrderDirection,
}

impl registry_platform_yaml::Identified for SourceOrderTerm {
    fn id(&self) -> &str {
        self.name.as_str()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SourceOrderDirection {
    Ascending,
    Descending,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_id_is_the_record_type_without_a_duplicate_authored_name() {
        let parsed: ConsultationFacade = serde_json::from_value(serde_json::json!({
            "contract": "https://registry.example/contracts/1.0.0-draft/openapi.yaml",
            "collections": [{
                "recordType": "people",
                "registry": "https://registry.example/registries/people",
                "view": "person-public",
                "dataSchema": "person-public",
                "lookup": {"selector": "by-national-id", "inputSchema": "national-id"},
                "search": {"search": "by-criteria", "inputSchema": "criteria"}
            }]
        }))
        .expect("consultation metadata");

        let collection = parsed.collections.get("people").expect("collection");
        assert_eq!(collection.record_type.as_str(), "people");
        assert_eq!(
            collection.lookup.as_ref().unwrap().selector.as_str(),
            "by-national-id"
        );
        assert_eq!(
            collection.search.as_ref().unwrap().search.as_str(),
            "by-criteria"
        );
    }

    #[test]
    fn standard_protocol_members_are_not_authored() {
        let refusal = serde_json::from_value::<ConsultationFacade>(serde_json::json!({
            "contract": "https://registry.example/contracts/1.0.0-draft/openapi.yaml",
            "paths": {},
            "collections": []
        }))
        .expect_err("paths are host owned");
        assert!(refusal.to_string().contains("unknown field `paths`"));
    }

    #[test]
    fn source_page_support_names_native_inputs_order_and_unique_tie_breaker() {
        let parsed: SourceReadSupport = serde_json::from_value(serde_json::json!({
            "type": "read-page",
            "inputs": [{"name": "status", "comparisons": ["equality"]}],
            "order": [
                {"name": "updated-at", "direction": "descending"},
                {"name": "source-id", "direction": "ascending"}
            ],
            "uniqueTieBreaker": "source-id"
        }))
        .expect("source support");
        assert!(matches!(parsed, SourceReadSupport::ReadPage { .. }));
    }
}
