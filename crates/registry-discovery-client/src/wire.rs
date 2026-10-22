// SPDX-License-Identifier: Apache-2.0
//! Client-owned tolerant decoding for server-authored response documents.

use registry_discovery::{
    EvidenceTypeResolveResponse, ResolvedAlternative, ServiceKind, ServiceRecord,
    ServiceSearchResponse,
};
use serde::Deserialize;

/// These wire models deliberately omit `deny_unknown_fields`: response objects
/// may gain additive members in a compatible server release. Known members
/// keep their exact types here, then the client applies the existing semantic
/// validation to the shared public DTOs after conversion.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvidenceTypeResolveWire {
    requirement_id: String,
    #[serde(default)]
    jurisdiction: Option<String>,
    mapping_revision: String,
    alternatives: Vec<ResolvedAlternativeWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolvedAlternativeWire {
    evidence_type_list_id: String,
    evidence_type_ids: Vec<String>,
    mapping_id: String,
    mapping_authority_id: String,
}

impl From<EvidenceTypeResolveWire> for EvidenceTypeResolveResponse {
    fn from(value: EvidenceTypeResolveWire) -> Self {
        Self {
            requirement_id: value.requirement_id,
            jurisdiction: value.jurisdiction,
            mapping_revision: value.mapping_revision,
            alternatives: value
                .alternatives
                .into_iter()
                .map(ResolvedAlternative::from)
                .collect(),
        }
    }
}

impl From<ResolvedAlternativeWire> for ResolvedAlternative {
    fn from(value: ResolvedAlternativeWire) -> Self {
        Self {
            evidence_type_list_id: value.evidence_type_list_id,
            evidence_type_ids: value.evidence_type_ids,
            mapping_id: value.mapping_id,
            mapping_authority_id: value.mapping_authority_id,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServiceSearchWire {
    catalog_revision: String,
    items: Vec<ServiceRecordWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceRecordWire {
    record_id: String,
    binding_id: String,
    service_id: String,
    service_kind: ServiceKind,
    title: String,
    description: String,
    endpoint_url: String,
    #[serde(default)]
    publisher_id: Option<String>,
    #[serde(default)]
    operator_id: Option<String>,
    #[serde(default)]
    registry_authority_id: Option<String>,
    #[serde(default)]
    legal_issuer_id: Option<String>,
    #[serde(default)]
    technical_provider_id: Option<String>,
    jurisdictions: Vec<String>,
    conforms_to: Vec<String>,
    evidence_type_ids: Vec<String>,
    semantic_class_ids: Vec<String>,
    operation_family_ids: Vec<String>,
    origin_id: String,
    origin_url: String,
    origin_content_digest: String,
    origin_fetched_at: String,
}

impl From<ServiceSearchWire> for ServiceSearchResponse {
    fn from(value: ServiceSearchWire) -> Self {
        Self {
            catalog_revision: value.catalog_revision,
            items: value.items.into_iter().map(ServiceRecord::from).collect(),
        }
    }
}

impl From<ServiceRecordWire> for ServiceRecord {
    fn from(value: ServiceRecordWire) -> Self {
        Self {
            record_id: value.record_id,
            binding_id: value.binding_id,
            service_id: value.service_id,
            service_kind: value.service_kind,
            title: value.title,
            description: value.description,
            endpoint_url: value.endpoint_url,
            publisher_id: value.publisher_id,
            operator_id: value.operator_id,
            registry_authority_id: value.registry_authority_id,
            legal_issuer_id: value.legal_issuer_id,
            technical_provider_id: value.technical_provider_id,
            jurisdictions: value.jurisdictions,
            conforms_to: value.conforms_to,
            evidence_type_ids: value.evidence_type_ids,
            semantic_class_ids: value.semantic_class_ids,
            operation_family_ids: value.operation_family_ids,
            origin_id: value.origin_id,
            origin_url: value.origin_url,
            origin_content_digest: value.origin_content_digest,
            origin_fetched_at: value.origin_fetched_at,
        }
    }
}
