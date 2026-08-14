// SPDX-License-Identifier: Apache-2.0
//! Exact ambiguity-safe conversion from advertisements to inert public data.

use registry_discovery::{
    valid_digest, validate_service, ServiceKind, ServiceRecord, ServiceSearchResponse,
};
use serde::{Deserialize, Serialize};

use crate::DiscoveryClientError;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "id", rename_all = "kebab-case")]
pub enum MatchedCapability {
    EvidenceType(String),
    SemanticClass(String),
    OperationFamily(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectionRequest {
    pub record_id: String,
    pub matched_capability: MatchedCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping_revision: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceSelection {
    pub record_id: String,
    pub binding_id: String,
    pub service_id: String,
    pub service_kind: ServiceKind,
    pub endpoint_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_authority_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_issuer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub technical_provider_id: Option<String>,
    pub jurisdictions: Vec<String>,
    pub conforms_to: Vec<String>,
    pub evidence_type_ids: Vec<String>,
    pub semantic_class_ids: Vec<String>,
    pub operation_family_ids: Vec<String>,
    pub matched_capability: MatchedCapability,
    pub origin_id: String,
    pub origin_url: String,
    pub origin_content_digest: String,
    pub catalog_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping_revision: Option<String>,
}

pub trait ServiceSearchSelectionExt {
    fn select_exact(
        &self,
        request: SelectionRequest,
    ) -> Result<ServiceSelection, DiscoveryClientError>;
}

impl ServiceSearchSelectionExt for ServiceSearchResponse {
    fn select_exact(
        &self,
        request: SelectionRequest,
    ) -> Result<ServiceSelection, DiscoveryClientError> {
        if !valid_digest(&self.catalog_revision)
            || request
                .mapping_revision
                .as_deref()
                .is_some_and(|revision| !valid_digest(revision))
        {
            return Err(DiscoveryClientError::Query);
        }
        let matches = self
            .items
            .iter()
            .filter(|service| service.record_id == request.record_id)
            .collect::<Vec<_>>();
        let service = match matches.as_slice() {
            [service] => *service,
            [] => return Err(DiscoveryClientError::NoMatchingService),
            _ => return Err(DiscoveryClientError::AmbiguousSelection),
        };
        validate_service(service).map_err(|_| DiscoveryClientError::Protocol)?;
        if !capability_matches(service, &request.matched_capability) {
            return Err(DiscoveryClientError::CapabilityMismatch);
        }
        Ok(ServiceSelection {
            record_id: service.record_id.clone(),
            binding_id: service.binding_id.clone(),
            service_id: service.service_id.clone(),
            service_kind: service.service_kind,
            endpoint_url: service.endpoint_url.clone(),
            publisher_id: service.publisher_id.clone(),
            operator_id: service.operator_id.clone(),
            registry_authority_id: service.registry_authority_id.clone(),
            legal_issuer_id: service.legal_issuer_id.clone(),
            technical_provider_id: service.technical_provider_id.clone(),
            jurisdictions: service.jurisdictions.clone(),
            conforms_to: service.conforms_to.clone(),
            evidence_type_ids: service.evidence_type_ids.clone(),
            semantic_class_ids: service.semantic_class_ids.clone(),
            operation_family_ids: service.operation_family_ids.clone(),
            matched_capability: request.matched_capability,
            origin_id: service.origin_id.clone(),
            origin_url: service.origin_url.clone(),
            origin_content_digest: service.origin_content_digest.clone(),
            catalog_revision: self.catalog_revision.clone(),
            mapping_revision: request.mapping_revision,
        })
    }
}

fn capability_matches(service: &ServiceRecord, capability: &MatchedCapability) -> bool {
    match capability {
        MatchedCapability::EvidenceType(id) => {
            service.service_kind == ServiceKind::Evidence && service.evidence_type_ids.contains(id)
        }
        MatchedCapability::SemanticClass(id) => {
            service.service_kind == ServiceKind::Relay && service.semantic_class_ids.contains(id)
        }
        MatchedCapability::OperationFamily(id) => {
            service.service_kind == ServiceKind::Relay && service.operation_family_ids.contains(id)
        }
    }
}

#[cfg(test)]
mod tests {
    use registry_discovery::{catalog_revision, ServiceSearchResponse};

    use super::*;

    fn service() -> ServiceRecord {
        ServiceRecord {
            record_id: "record-a".into(),
            binding_id: "urn:binding:a".into(),
            service_id: "urn:service".into(),
            service_kind: ServiceKind::Evidence,
            title: "Evidence".into(),
            description: "Evidence service".into(),
            endpoint_url: "https://provider.example/evidence".into(),
            publisher_id: None,
            operator_id: None,
            registry_authority_id: None,
            legal_issuer_id: Some("urn:issuer".into()),
            technical_provider_id: Some("urn:provider".into()),
            jurisdictions: vec!["urn:jurisdiction".into()],
            conforms_to: vec!["urn:profile".into()],
            evidence_type_ids: vec!["urn:evidence".into()],
            semantic_class_ids: Vec::new(),
            operation_family_ids: Vec::new(),
            origin_id: "origin-a".into(),
            origin_url: "https://provider.example/catalog.jsonld".into(),
            origin_content_digest: format!("sha256:{}", "1".repeat(64)),
            origin_fetched_at: "2026-08-14T00:00:00Z".into(),
        }
    }

    #[test]
    fn exact_selection_refuses_absence_ambiguity_and_capability_mismatch() {
        let record = service();
        let response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record.clone()],
        };
        let request = SelectionRequest {
            record_id: "record-a".into(),
            matched_capability: MatchedCapability::EvidenceType("urn:evidence".into()),
            mapping_revision: None,
        };
        let selected = response.select_exact(request.clone()).unwrap();
        assert_eq!(selected.service_id, "urn:service");
        assert_eq!(selected.binding_id, "urn:binding:a");
        assert_eq!(selected.evidence_type_ids, ["urn:evidence"]);
        assert!(selected.semantic_class_ids.is_empty());
        assert!(selected.operation_family_ids.is_empty());
        let mut missing = request.clone();
        missing.record_id = "missing".into();
        assert_eq!(
            response.select_exact(missing),
            Err(DiscoveryClientError::NoMatchingService)
        );
        let ambiguous = ServiceSearchResponse {
            catalog_revision: response.catalog_revision.clone(),
            items: vec![record.clone(), record],
        };
        assert_eq!(
            ambiguous.select_exact(request.clone()),
            Err(DiscoveryClientError::AmbiguousSelection)
        );
        let mut wrong = request;
        wrong.matched_capability = MatchedCapability::EvidenceType("urn:other".into());
        assert_eq!(
            response.select_exact(wrong),
            Err(DiscoveryClientError::CapabilityMismatch)
        );
    }

    #[test]
    fn relay_selection_retains_the_exact_correlated_capability_tuple() {
        let mut record = service();
        record.service_kind = ServiceKind::Relay;
        record.legal_issuer_id = None;
        record.technical_provider_id = None;
        record.registry_authority_id = Some("urn:registry-authority".into());
        record.evidence_type_ids.clear();
        record.semantic_class_ids = vec!["urn:semantic:business".into()];
        record.operation_family_ids = vec!["urn:operation:list".into()];
        let response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record],
        };

        let selection = response
            .select_exact(SelectionRequest {
                record_id: "record-a".into(),
                matched_capability: MatchedCapability::OperationFamily("urn:operation:list".into()),
                mapping_revision: None,
            })
            .expect("exact Relay binding selection");

        assert_eq!(selection.binding_id, "urn:binding:a");
        assert_eq!(selection.semantic_class_ids, ["urn:semantic:business"]);
        assert_eq!(selection.operation_family_ids, ["urn:operation:list"]);
        assert!(selection.evidence_type_ids.is_empty());
    }

    #[test]
    fn discovery_metadata_has_no_trust_or_native_io_capability() {
        let record = service();
        let response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record],
        };
        let selection = response
            .select_exact(SelectionRequest {
                record_id: "record-a".into(),
                matched_capability: MatchedCapability::EvidenceType("urn:evidence".into()),
                mapping_revision: None,
            })
            .unwrap();
        let serialized = serde_json::to_string(&selection).unwrap();
        for forbidden in [
            "credential",
            "token",
            "privateKey",
            "trustAnchor",
            "selector",
            "subject",
            "nativeRequest",
            "claim",
            "response",
        ] {
            assert!(!serialized.contains(forbidden), "{forbidden}");
        }
    }
}
