// SPDX-License-Identifier: Apache-2.0
//! Exact ambiguity-safe conversion from advertisements to inert public data.

use registry_discovery::{
    valid_digest, valid_uri_identifier, validate_service, EvidenceTypeResolveResponse, ServiceKind,
    ServiceRecord, ServiceSearchResponse, MAXIMUM_EVIDENCE_TYPES_PER_ALTERNATIVE,
};
use registry_discovery_profile::derive_binding_id;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    client::{validate_resolve_response_shape, validate_search_response_shape},
    DiscoveryClientError, EvidenceServiceQuery,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "id", rename_all = "kebab-case")]
pub enum MatchedCapability {
    EvidenceType(String),
    SemanticClass(String),
    OperationFamily(String),
}

/// Complete, inert provenance for one resolved Evidence Type AND-list.
///
/// This is discovery metadata, not a request or a trust decision. Keeping the
/// whole list prevents a saved selection from turning one required set of
/// Evidence Types into a single, lossy type identifier.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceResolutionContext {
    pub requirement_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    pub mapping_revision: String,
    pub evidence_type_list_id: String,
    pub evidence_type_ids: Vec<String>,
    pub mapping_id: String,
    pub mapping_authority_id: String,
}

impl EvidenceResolutionContext {
    #[must_use]
    pub fn required_evidence_type_ids(&self) -> &[String] {
        &self.evidence_type_ids
    }

    /// Build the exact one-service search needed for one member of this
    /// required AND-list.
    pub fn service_query_for(
        &self,
        evidence_type_id: &str,
    ) -> Result<EvidenceServiceQuery, DiscoveryClientError> {
        validate_resolution(self)?;
        if !self
            .evidence_type_ids
            .iter()
            .any(|required| required == evidence_type_id)
        {
            return Err(DiscoveryClientError::CapabilityMismatch);
        }
        let query = EvidenceServiceQuery::new(evidence_type_id);
        Ok(match &self.jurisdiction {
            Some(jurisdiction) => query.with_jurisdiction(jurisdiction),
            None => query,
        })
    }
}

pub trait EvidenceTypeResolveSelectionExt {
    fn select_alternative(
        &self,
        evidence_type_list_id: &str,
    ) -> Result<EvidenceResolutionContext, DiscoveryClientError>;

    fn select_only_alternative(&self) -> Result<EvidenceResolutionContext, DiscoveryClientError>;
}

impl EvidenceTypeResolveSelectionExt for EvidenceTypeResolveResponse {
    fn select_alternative(
        &self,
        evidence_type_list_id: &str,
    ) -> Result<EvidenceResolutionContext, DiscoveryClientError> {
        validate_resolve_response_shape(self)?;
        let mut matches = self
            .alternatives
            .iter()
            .filter(|alternative| alternative.evidence_type_list_id == evidence_type_list_id);
        let alternative = matches
            .next()
            .ok_or(DiscoveryClientError::NoMatchingAlternative)?;
        if matches.next().is_some() {
            return Err(DiscoveryClientError::AmbiguousAlternative);
        }
        resolution_context(self, alternative)
    }

    fn select_only_alternative(&self) -> Result<EvidenceResolutionContext, DiscoveryClientError> {
        validate_resolve_response_shape(self)?;
        let [alternative] = self.alternatives.as_slice() else {
            return Err(if self.alternatives.is_empty() {
                DiscoveryClientError::NoMatchingAlternative
            } else {
                DiscoveryClientError::AmbiguousAlternative
            });
        };
        resolution_context(self, alternative)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceSelectionRequest {
    pub record_id: String,
    pub evidence_type_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<EvidenceResolutionContext>,
}

impl EvidenceSelectionRequest {
    #[must_use]
    pub fn new(record_id: impl Into<String>, evidence_type_id: impl Into<String>) -> Self {
        Self {
            record_id: record_id.into(),
            evidence_type_id: evidence_type_id.into(),
            resolution: None,
        }
    }

    #[must_use]
    pub fn with_resolution(mut self, resolution: EvidenceResolutionContext) -> Self {
        self.resolution = Some(resolution);
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelayCapabilityMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_class_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_family_id: Option<String>,
}

impl RelayCapabilityMatch {
    #[must_use]
    pub fn for_semantic_class(semantic_class_id: impl Into<String>) -> Self {
        Self {
            semantic_class_id: Some(semantic_class_id.into()),
            operation_family_id: None,
        }
    }

    #[must_use]
    pub fn for_operation_family(operation_family_id: impl Into<String>) -> Self {
        Self {
            semantic_class_id: None,
            operation_family_id: Some(operation_family_id.into()),
        }
    }

    #[must_use]
    pub fn with_semantic_class(mut self, semantic_class_id: impl Into<String>) -> Self {
        self.semantic_class_id = Some(semantic_class_id.into());
        self
    }

    #[must_use]
    pub fn with_operation_family(mut self, operation_family_id: impl Into<String>) -> Self {
        self.operation_family_id = Some(operation_family_id.into());
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelaySelectionRequest {
    pub record_id: String,
    pub capability_match: RelayCapabilityMatch,
}

impl RelaySelectionRequest {
    #[must_use]
    pub fn new(record_id: impl Into<String>, capability_match: RelayCapabilityMatch) -> Self {
        Self {
            record_id: record_id.into(),
            capability_match,
        }
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_resolution: Option<EvidenceResolutionContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_capability_match: Option<RelayCapabilityMatch>,
    pub origin_id: String,
    pub origin_url: String,
    pub origin_content_digest: String,
    pub origin_fetched_at: String,
    pub catalog_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping_revision: Option<String>,
}

impl ServiceSelection {
    /// Parse the advertised native base URL after the application has applied
    /// its own trust policy. Calling this method is not a trust decision.
    pub fn advertised_base_url(&self) -> Result<Url, DiscoveryClientError> {
        validate_service_selection_structure(self)?;
        parsed_base_url(&self.endpoint_url)
    }
}

/// An ephemeral handoff created only after adopter-owned local acceptance.
///
/// This wrapper is deliberately not serializable. Persist the inert
/// [`ServiceSelection`] and apply current local policy again before native
/// credentials or input and output.
#[derive(Debug)]
pub struct AcceptedServiceSelection<'a> {
    selection: &'a ServiceSelection,
    base_url: Url,
}

impl AcceptedServiceSelection<'_> {
    #[must_use]
    pub fn selection(&self) -> &ServiceSelection {
        self.selection
    }

    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }
}

fn parsed_base_url(value: &str) -> Result<Url, DiscoveryClientError> {
    let url = Url::parse(value).map_err(|_| DiscoveryClientError::Protocol)?;
    registry_platform_httputil::client::ServiceBaseUrl::new(url.clone())
        .map_err(|_| DiscoveryClientError::Protocol)?;
    Ok(url)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct EvidenceServiceSelection(ServiceSelection);

impl EvidenceServiceSelection {
    #[must_use]
    pub fn selection(&self) -> &ServiceSelection {
        &self.0
    }

    #[must_use]
    pub fn into_selection(self) -> ServiceSelection {
        self.0
    }

    pub fn advertised_base_url(&self) -> Result<Url, DiscoveryClientError> {
        self.0.advertised_base_url()
    }

    #[must_use]
    pub fn resolution(&self) -> Option<&EvidenceResolutionContext> {
        self.0.evidence_resolution.as_ref()
    }

    pub fn matched_evidence_type_id(&self) -> Result<&str, DiscoveryClientError> {
        let MatchedCapability::EvidenceType(id) = &self.0.matched_capability else {
            return Err(DiscoveryClientError::Protocol);
        };
        Ok(id)
    }
}

impl std::ops::Deref for EvidenceServiceSelection {
    type Target = ServiceSelection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct RelayServiceSelection(ServiceSelection);

impl RelayServiceSelection {
    #[must_use]
    pub fn selection(&self) -> &ServiceSelection {
        &self.0
    }

    #[must_use]
    pub fn into_selection(self) -> ServiceSelection {
        self.0
    }

    pub fn advertised_base_url(&self) -> Result<Url, DiscoveryClientError> {
        self.0.advertised_base_url()
    }

    pub fn capability_match(&self) -> Result<&RelayCapabilityMatch, DiscoveryClientError> {
        self.0
            .relay_capability_match
            .as_ref()
            .ok_or(DiscoveryClientError::Protocol)
    }
}

impl std::ops::Deref for RelayServiceSelection {
    type Target = ServiceSelection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait ServiceSearchSelectionExt {
    fn select_exact(
        &self,
        request: SelectionRequest,
    ) -> Result<ServiceSelection, DiscoveryClientError>;

    fn select_only(
        &self,
        matched_capability: MatchedCapability,
    ) -> Result<ServiceSelection, DiscoveryClientError>;

    fn select_evidence(
        &self,
        request: EvidenceSelectionRequest,
    ) -> Result<EvidenceServiceSelection, DiscoveryClientError>;

    fn select_relay(
        &self,
        request: RelaySelectionRequest,
    ) -> Result<RelayServiceSelection, DiscoveryClientError>;
}

impl ServiceSearchSelectionExt for ServiceSearchResponse {
    fn select_exact(
        &self,
        request: SelectionRequest,
    ) -> Result<ServiceSelection, DiscoveryClientError> {
        validate_search_response_shape(self)?;
        if request
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
        let expected_binding_id = derive_binding_id(
            &service.service_id,
            service.service_kind,
            &service.endpoint_url,
            &service.conforms_to,
            &service.evidence_type_ids,
            &service.semantic_class_ids,
            &service.operation_family_ids,
        )
        .map_err(|_| DiscoveryClientError::Protocol)?;
        if service.binding_id != expected_binding_id {
            return Err(DiscoveryClientError::Protocol);
        }
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
            evidence_resolution: None,
            relay_capability_match: None,
            origin_id: service.origin_id.clone(),
            origin_url: service.origin_url.clone(),
            origin_content_digest: service.origin_content_digest.clone(),
            origin_fetched_at: service.origin_fetched_at.clone(),
            catalog_revision: self.catalog_revision.clone(),
            mapping_revision: request.mapping_revision,
        })
    }

    fn select_only(
        &self,
        matched_capability: MatchedCapability,
    ) -> Result<ServiceSelection, DiscoveryClientError> {
        validate_search_response_shape(self)?;
        let [service] = self.items.as_slice() else {
            return Err(if self.items.is_empty() {
                DiscoveryClientError::NoMatchingService
            } else {
                DiscoveryClientError::AmbiguousSelection
            });
        };
        self.select_exact(SelectionRequest {
            record_id: service.record_id.clone(),
            matched_capability,
            mapping_revision: None,
        })
    }

    fn select_evidence(
        &self,
        request: EvidenceSelectionRequest,
    ) -> Result<EvidenceServiceSelection, DiscoveryClientError> {
        if let Some(resolution) = &request.resolution {
            validate_resolution(resolution)?;
            if !resolution
                .evidence_type_ids
                .iter()
                .any(|required| required == &request.evidence_type_id)
            {
                return Err(DiscoveryClientError::CapabilityMismatch);
            }
        }
        let mapping_revision = request
            .resolution
            .as_ref()
            .map(|resolution| resolution.mapping_revision.clone());
        let mut selection = self.select_exact(SelectionRequest {
            record_id: request.record_id,
            matched_capability: MatchedCapability::EvidenceType(request.evidence_type_id),
            mapping_revision,
        })?;
        if request.resolution.as_ref().is_some_and(|resolution| {
            resolution
                .jurisdiction
                .as_ref()
                .is_some_and(|jurisdiction| !selection.jurisdictions.contains(jurisdiction))
        }) {
            return Err(DiscoveryClientError::CapabilityMismatch);
        }
        selection.evidence_resolution = request.resolution;
        Ok(EvidenceServiceSelection(selection))
    }

    fn select_relay(
        &self,
        request: RelaySelectionRequest,
    ) -> Result<RelayServiceSelection, DiscoveryClientError> {
        let semantic_class_id = request.capability_match.semantic_class_id.as_deref();
        let operation_family_id = request.capability_match.operation_family_id.as_deref();
        if semantic_class_id.is_none() && operation_family_id.is_none() {
            return Err(DiscoveryClientError::Query);
        }
        if semantic_class_id.is_some_and(|id| !valid_uri_identifier(id))
            || operation_family_id.is_some_and(|id| !valid_uri_identifier(id))
        {
            return Err(DiscoveryClientError::Query);
        }
        let matched_capability = semantic_class_id
            .map(|id| MatchedCapability::SemanticClass(id.to_owned()))
            .or_else(|| {
                operation_family_id.map(|id| MatchedCapability::OperationFamily(id.to_owned()))
            })
            .ok_or(DiscoveryClientError::Query)?;
        let mut selection = self.select_exact(SelectionRequest {
            record_id: request.record_id,
            matched_capability,
            mapping_revision: None,
        })?;
        if semantic_class_id.is_some_and(|id| !selection.semantic_class_ids.iter().any(|v| v == id))
            || operation_family_id
                .is_some_and(|id| !selection.operation_family_ids.iter().any(|v| v == id))
        {
            return Err(DiscoveryClientError::CapabilityMismatch);
        }
        selection.relay_capability_match = Some(request.capability_match);
        Ok(RelayServiceSelection(selection))
    }
}

fn resolution_context(
    response: &EvidenceTypeResolveResponse,
    alternative: &registry_discovery::ResolvedAlternative,
) -> Result<EvidenceResolutionContext, DiscoveryClientError> {
    let context = EvidenceResolutionContext {
        requirement_id: response.requirement_id.clone(),
        jurisdiction: response.jurisdiction.clone(),
        mapping_revision: response.mapping_revision.clone(),
        evidence_type_list_id: alternative.evidence_type_list_id.clone(),
        evidence_type_ids: alternative.evidence_type_ids.clone(),
        mapping_id: alternative.mapping_id.clone(),
        mapping_authority_id: alternative.mapping_authority_id.clone(),
    };
    validate_resolution(&context)?;
    Ok(context)
}

fn validate_resolution(resolution: &EvidenceResolutionContext) -> Result<(), DiscoveryClientError> {
    if !valid_uri_identifier(&resolution.requirement_id)
        || resolution
            .jurisdiction
            .as_deref()
            .is_some_and(|value| !valid_uri_identifier(value))
        || !valid_digest(&resolution.mapping_revision)
        || !valid_uri_identifier(&resolution.evidence_type_list_id)
        || resolution.evidence_type_ids.is_empty()
        || resolution.evidence_type_ids.len() > MAXIMUM_EVIDENCE_TYPES_PER_ALTERNATIVE
        || resolution
            .evidence_type_ids
            .iter()
            .any(|value| !valid_uri_identifier(value))
        || resolution
            .evidence_type_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || !valid_uri_identifier(&resolution.mapping_id)
        || !valid_uri_identifier(&resolution.mapping_authority_id)
    {
        return Err(DiscoveryClientError::Query);
    }
    Ok(())
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

/// Validate the closed shape and capability binding of a persisted or foreign
/// selection.
///
/// This does not prove origin authenticity, catalog currentness, mapping
/// currency, authorization, or adopter trust.
pub fn validate_service_selection_structure(
    selection: &ServiceSelection,
) -> Result<(), DiscoveryClientError> {
    let record = ServiceRecord {
        record_id: selection.record_id.clone(),
        binding_id: selection.binding_id.clone(),
        service_id: selection.service_id.clone(),
        service_kind: selection.service_kind,
        title: "selected service".into(),
        description: "persisted Discovery selection".into(),
        endpoint_url: selection.endpoint_url.clone(),
        publisher_id: selection.publisher_id.clone(),
        operator_id: selection.operator_id.clone(),
        registry_authority_id: selection.registry_authority_id.clone(),
        legal_issuer_id: selection.legal_issuer_id.clone(),
        technical_provider_id: selection.technical_provider_id.clone(),
        jurisdictions: selection.jurisdictions.clone(),
        conforms_to: selection.conforms_to.clone(),
        evidence_type_ids: selection.evidence_type_ids.clone(),
        semantic_class_ids: selection.semantic_class_ids.clone(),
        operation_family_ids: selection.operation_family_ids.clone(),
        origin_id: selection.origin_id.clone(),
        origin_url: selection.origin_url.clone(),
        origin_content_digest: selection.origin_content_digest.clone(),
        origin_fetched_at: selection.origin_fetched_at.clone(),
    };
    validate_service(&record).map_err(|_| DiscoveryClientError::Protocol)?;
    let expected_binding_id = derive_binding_id(
        &selection.service_id,
        selection.service_kind,
        &selection.endpoint_url,
        &selection.conforms_to,
        &selection.evidence_type_ids,
        &selection.semantic_class_ids,
        &selection.operation_family_ids,
    )
    .map_err(|_| DiscoveryClientError::Protocol)?;
    if selection.binding_id != expected_binding_id
        || !capability_matches(&record, &selection.matched_capability)
        || !valid_digest(&selection.catalog_revision)
        || selection
            .mapping_revision
            .as_deref()
            .is_some_and(|revision| !valid_digest(revision))
        || parsed_base_url(&selection.endpoint_url).is_err()
    {
        return Err(DiscoveryClientError::Protocol);
    }
    match (
        selection.service_kind,
        &selection.evidence_resolution,
        &selection.relay_capability_match,
    ) {
        (ServiceKind::Evidence, Some(resolution), None) => {
            validate_resolution(resolution).map_err(|_| DiscoveryClientError::Protocol)?;
            let MatchedCapability::EvidenceType(evidence_type_id) = &selection.matched_capability
            else {
                return Err(DiscoveryClientError::Protocol);
            };
            if selection.mapping_revision.as_deref() != Some(&resolution.mapping_revision)
                || !resolution
                    .evidence_type_ids
                    .iter()
                    .any(|required| required == evidence_type_id)
                || resolution
                    .jurisdiction
                    .as_ref()
                    .is_some_and(|jurisdiction| !selection.jurisdictions.contains(jurisdiction))
            {
                return Err(DiscoveryClientError::Protocol);
            }
        }
        (ServiceKind::Evidence, None, None) => {}
        (ServiceKind::Relay, None, Some(capabilities)) => {
            if capabilities.semantic_class_id.is_none()
                && capabilities.operation_family_id.is_none()
                || capabilities.semantic_class_id.as_ref().is_some_and(|id| {
                    !valid_uri_identifier(id) || !selection.semantic_class_ids.contains(id)
                })
                || capabilities.operation_family_id.as_ref().is_some_and(|id| {
                    !valid_uri_identifier(id) || !selection.operation_family_ids.contains(id)
                })
                || match &selection.matched_capability {
                    MatchedCapability::SemanticClass(id) => {
                        capabilities.semantic_class_id.as_ref() != Some(id)
                    }
                    MatchedCapability::OperationFamily(id) => {
                        capabilities.operation_family_id.as_ref() != Some(id)
                    }
                    MatchedCapability::EvidenceType(_) => true,
                }
            {
                return Err(DiscoveryClientError::Protocol);
            }
        }
        (ServiceKind::Relay, None, None) => {}
        _ => return Err(DiscoveryClientError::Protocol),
    }
    Ok(())
}

/// Apply adopter-owned local policy and create an ephemeral native handoff.
///
/// The callback owns the trust decision. Discovery supplies no trust policy,
/// trust-store schema, credentials, or native client behavior.
pub fn accept_service_selection<'a>(
    selection: &'a ServiceSelection,
    accepts: impl FnOnce(&ServiceSelection) -> bool,
) -> Result<AcceptedServiceSelection<'a>, DiscoveryClientError> {
    validate_service_selection_structure(selection)?;
    if !accepts(selection) {
        return Err(DiscoveryClientError::LocalAcceptanceRefused);
    }
    Ok(AcceptedServiceSelection {
        selection,
        base_url: parsed_base_url(&selection.endpoint_url)?,
    })
}

/// Renew a selection only when a caller has freshly reselected the same
/// trust-relevant service semantics from an online Discovery lookup.
///
/// Fetch provenance and the global catalog revision may advance without
/// changing this service. Every service, role, jurisdiction, capability,
/// mapping, or resolution change requires explicit new local acceptance.
pub fn renew_unchanged_service_selection(
    previous: &ServiceSelection,
    current: &ServiceSelection,
) -> Result<ServiceSelection, DiscoveryClientError> {
    validate_service_selection_structure(previous)?;
    validate_service_selection_structure(current)?;
    if !same_acceptance_subject(previous, current) {
        return Err(DiscoveryClientError::SelectionChanged);
    }
    Ok(current.clone())
}

fn same_acceptance_subject(left: &ServiceSelection, right: &ServiceSelection) -> bool {
    left.record_id == right.record_id
        && left.binding_id == right.binding_id
        && left.service_id == right.service_id
        && left.service_kind == right.service_kind
        && left.endpoint_url == right.endpoint_url
        && left.publisher_id == right.publisher_id
        && left.operator_id == right.operator_id
        && left.registry_authority_id == right.registry_authority_id
        && left.legal_issuer_id == right.legal_issuer_id
        && left.technical_provider_id == right.technical_provider_id
        && left.jurisdictions == right.jurisdictions
        && left.conforms_to == right.conforms_to
        && left.evidence_type_ids == right.evidence_type_ids
        && left.semantic_class_ids == right.semantic_class_ids
        && left.operation_family_ids == right.operation_family_ids
        && left.matched_capability == right.matched_capability
        && left.evidence_resolution == right.evidence_resolution
        && left.relay_capability_match == right.relay_capability_match
        && left.origin_id == right.origin_id
        && left.origin_url == right.origin_url
        && left.mapping_revision == right.mapping_revision
}

#[cfg(test)]
mod tests {
    use registry_discovery::{
        catalog_revision, EvidenceTypeResolveResponse, ResolvedAlternative, ServiceSearchResponse,
        MAXIMUM_RESULT_ALTERNATIVES,
    };

    use super::*;

    fn service() -> ServiceRecord {
        let mut service = ServiceRecord {
            record_id: "record-a".into(),
            binding_id: String::new(),
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
        };
        refresh_binding_id(&mut service);
        service
    }

    fn refresh_binding_id(service: &mut ServiceRecord) {
        service.binding_id = derive_binding_id(
            &service.service_id,
            service.service_kind,
            &service.endpoint_url,
            &service.conforms_to,
            &service.evidence_type_ids,
            &service.semantic_class_ids,
            &service.operation_family_ids,
        )
        .unwrap();
    }

    fn refresh_selection_binding_id(selection: &mut ServiceSelection) {
        selection.binding_id = derive_binding_id(
            &selection.service_id,
            selection.service_kind,
            &selection.endpoint_url,
            &selection.conforms_to,
            &selection.evidence_type_ids,
            &selection.semantic_class_ids,
            &selection.operation_family_ids,
        )
        .unwrap();
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
        assert_eq!(selected.binding_id, record.binding_id);
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
    fn exact_selection_refuses_binding_identity_drift() {
        let mut record = service();
        record.endpoint_url = "https://other.example/evidence".into();
        let response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record],
        };
        assert_eq!(
            response.select_only(MatchedCapability::EvidenceType("urn:evidence".into())),
            Err(DiscoveryClientError::Protocol)
        );
    }

    #[test]
    fn selection_endpoint_validation_matches_native_client_base_urls() {
        let mut record = service();
        record.endpoint_url = "https://provider.example/a//b".into();
        let response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record],
        };
        assert_eq!(
            response.select_only(MatchedCapability::EvidenceType("urn:evidence".into())),
            Err(DiscoveryClientError::Protocol)
        );
    }

    #[test]
    fn evidence_alternative_retains_the_complete_and_list_and_drives_each_search() {
        let response = EvidenceTypeResolveResponse {
            requirement_id: "urn:requirement".into(),
            jurisdiction: Some("urn:jurisdiction".into()),
            mapping_revision: format!("sha256:{}", "2".repeat(64)),
            alternatives: vec![ResolvedAlternative {
                evidence_type_list_id: "urn:list".into(),
                evidence_type_ids: vec!["urn:evidence:a".into(), "urn:evidence:b".into()],
                mapping_id: "urn:mapping".into(),
                mapping_authority_id: "urn:mapping-authority".into(),
            }],
        };
        let context = response
            .select_only_alternative()
            .expect("the only complete AND-list is selected");
        assert_eq!(context.requirement_id, "urn:requirement");
        assert_eq!(
            context.required_evidence_type_ids(),
            ["urn:evidence:a", "urn:evidence:b"]
        );
        let query = context
            .service_query_for("urn:evidence:b")
            .expect("one required type creates one exact search");
        assert_eq!(query.evidence_type_id, "urn:evidence:b");
        assert_eq!(query.jurisdiction.as_deref(), Some("urn:jurisdiction"));
        assert_eq!(
            context.service_query_for("urn:evidence:other"),
            Err(DiscoveryClientError::CapabilityMismatch)
        );

        let mut record = service();
        record.evidence_type_ids = vec!["urn:evidence:b".into()];
        refresh_binding_id(&mut record);
        let search = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record],
        };
        let mut wrong_jurisdiction = context.clone();
        wrong_jurisdiction.jurisdiction = Some("urn:jurisdiction:other".into());
        assert_eq!(
            search.select_evidence(
                EvidenceSelectionRequest::new("record-a", "urn:evidence:b")
                    .with_resolution(wrong_jurisdiction)
            ),
            Err(DiscoveryClientError::CapabilityMismatch)
        );
        let selection = search
            .select_evidence(EvidenceSelectionRequest {
                record_id: "record-a".into(),
                evidence_type_id: "urn:evidence:b".into(),
                resolution: Some(context.clone()),
            })
            .expect("one required type selects one exact Evidence binding");
        assert_eq!(
            selection.selection().evidence_resolution,
            Some(context.clone())
        );
        validate_service_selection_structure(selection.selection())
            .expect("the saved selection revalidates structurally");

        let mut persisted = selection.into_selection();
        persisted
            .evidence_resolution
            .as_mut()
            .expect("the selection retains its resolution")
            .jurisdiction = Some("urn:jurisdiction:other".into());
        assert_eq!(
            validate_service_selection_structure(&persisted),
            Err(DiscoveryClientError::Protocol)
        );
    }

    #[test]
    fn evidence_resolution_refuses_an_over_bound_and_list() {
        let evidence_type_ids = (0..=MAXIMUM_EVIDENCE_TYPES_PER_ALTERNATIVE)
            .map(|index| format!("urn:evidence:{index:03}"))
            .collect::<Vec<_>>();
        let oversized = EvidenceResolutionContext {
            requirement_id: "urn:requirement".into(),
            jurisdiction: None,
            mapping_revision: format!("sha256:{}", "2".repeat(64)),
            evidence_type_list_id: "urn:list".into(),
            evidence_type_ids: evidence_type_ids.clone(),
            mapping_id: "urn:mapping".into(),
            mapping_authority_id: "urn:mapping-authority".into(),
        };
        assert_eq!(
            validate_resolution(&oversized),
            Err(DiscoveryClientError::Query)
        );

        let response = EvidenceTypeResolveResponse {
            requirement_id: oversized.requirement_id.clone(),
            jurisdiction: None,
            mapping_revision: oversized.mapping_revision.clone(),
            alternatives: vec![ResolvedAlternative {
                evidence_type_list_id: oversized.evidence_type_list_id.clone(),
                evidence_type_ids,
                mapping_id: oversized.mapping_id.clone(),
                mapping_authority_id: oversized.mapping_authority_id.clone(),
            }],
        };
        assert_eq!(
            response.select_only_alternative(),
            Err(DiscoveryClientError::Protocol)
        );

        let record = service();
        let search = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record],
        };
        let valid = EvidenceResolutionContext {
            evidence_type_ids: vec!["urn:evidence".into()],
            ..oversized.clone()
        };
        let mut persisted = search
            .select_evidence(
                EvidenceSelectionRequest::new("record-a", "urn:evidence").with_resolution(valid),
            )
            .expect("valid selection")
            .into_selection();
        persisted.evidence_resolution = Some(oversized);
        assert_eq!(
            validate_service_selection_structure(&persisted),
            Err(DiscoveryClientError::Protocol)
        );
    }

    #[test]
    fn evidence_alternative_selection_refuses_an_over_bound_response() {
        let alternatives = (0..=MAXIMUM_RESULT_ALTERNATIVES)
            .map(|index| ResolvedAlternative {
                evidence_type_list_id: format!("urn:list:{index:04}"),
                evidence_type_ids: vec![format!("urn:evidence:{index:04}")],
                mapping_id: "urn:mapping".into(),
                mapping_authority_id: "urn:mapping-authority".into(),
            })
            .collect::<Vec<_>>();
        let response = EvidenceTypeResolveResponse {
            requirement_id: "urn:requirement".into(),
            jurisdiction: None,
            mapping_revision: format!("sha256:{}", "2".repeat(64)),
            alternatives,
        };

        assert_eq!(
            response.select_alternative("urn:list:0000"),
            Err(DiscoveryClientError::Protocol)
        );
        assert_eq!(
            response.select_only_alternative(),
            Err(DiscoveryClientError::Protocol)
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
        record.semantic_class_ids =
            vec!["urn:semantic:business".into(), "urn:semantic:person".into()];
        record.operation_family_ids = vec!["urn:operation:list".into()];
        refresh_binding_id(&mut record);
        let expected_binding_id = record.binding_id.clone();
        let response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record],
        };

        let selection = response
            .select_relay(RelaySelectionRequest {
                record_id: "record-a".into(),
                capability_match: RelayCapabilityMatch {
                    semantic_class_id: Some("urn:semantic:business".into()),
                    operation_family_id: Some("urn:operation:list".into()),
                },
            })
            .expect("exact Relay binding selection");

        assert_eq!(selection.selection().binding_id, expected_binding_id);
        assert_eq!(
            selection.selection().semantic_class_ids,
            ["urn:semantic:business", "urn:semantic:person"]
        );
        assert_eq!(
            selection.selection().operation_family_ids,
            ["urn:operation:list"]
        );
        assert!(selection.selection().evidence_type_ids.is_empty());
        assert_eq!(
            selection.selection().relay_capability_match,
            Some(RelayCapabilityMatch {
                semantic_class_id: Some("urn:semantic:business".into()),
                operation_family_id: Some("urn:operation:list".into()),
            })
        );
        validate_service_selection_structure(selection.selection())
            .expect("the Relay tuple revalidates structurally");

        let mut persisted = selection.into_selection();
        persisted.matched_capability =
            MatchedCapability::SemanticClass("urn:semantic:person".into());
        assert_eq!(
            validate_service_selection_structure(&persisted),
            Err(DiscoveryClientError::Protocol)
        );
    }

    #[test]
    fn persisted_selection_refuses_binding_identity_drift() {
        let record = service();
        let response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record],
        };
        let selection = response
            .select_evidence(EvidenceSelectionRequest::new("record-a", "urn:evidence"))
            .expect("valid exact selection")
            .into_selection();

        let mutations: [fn(&mut ServiceSelection); 4] = [
            |selection: &mut ServiceSelection| {
                selection.service_id = "urn:service:other".into();
            },
            |selection: &mut ServiceSelection| {
                selection.endpoint_url = "https://other.example/evidence".into();
            },
            |selection: &mut ServiceSelection| {
                selection.conforms_to = vec!["urn:profile:other".into()];
            },
            |selection: &mut ServiceSelection| {
                selection.evidence_type_ids = vec!["urn:evidence:other".into()];
                selection.matched_capability =
                    MatchedCapability::EvidenceType("urn:evidence:other".into());
            },
        ];
        for mutate in mutations {
            let mut drifted = selection.clone();
            mutate(&mut drifted);
            assert_eq!(
                validate_service_selection_structure(&drifted),
                Err(DiscoveryClientError::Protocol)
            );
        }
    }

    #[test]
    fn structural_validation_does_not_turn_descriptive_metadata_into_binding_authority() {
        let record = service();
        let response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record],
        };
        let selection = response
            .select_only(MatchedCapability::EvidenceType("urn:evidence".into()))
            .expect("valid exact selection");

        let mut descriptive_change = selection.clone();
        descriptive_change.publisher_id = Some("urn:publisher:other".into());
        descriptive_change.jurisdictions = vec!["urn:jurisdiction:other".into()];
        validate_service_selection_structure(&descriptive_change)
            .expect("roles and jurisdictions remain outside capability binding");

        let accepted = accept_service_selection(&selection, |candidate| candidate == &selection)
            .expect("the exact local pin accepts");
        assert_eq!(accepted.selection(), &selection);
        assert_eq!(
            accepted.base_url().as_str(),
            "https://provider.example/evidence"
        );
        assert_eq!(
            accept_service_selection(&descriptive_change, |candidate| candidate == &selection)
                .map(|_| ()),
            Err(DiscoveryClientError::LocalAcceptanceRefused)
        );
    }

    #[test]
    fn unchanged_renewal_refreshes_provenance_but_requires_new_acceptance_for_semantic_change() {
        let record = service();
        let response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record],
        };
        let previous = response
            .select_only(MatchedCapability::EvidenceType("urn:evidence".into()))
            .expect("valid exact selection");
        let mut current = previous.clone();
        current.origin_content_digest = format!("sha256:{}", "3".repeat(64));
        current.origin_fetched_at = "2026-08-20T00:00:00Z".into();
        current.catalog_revision = format!("sha256:{}", "4".repeat(64));

        let renewed = renew_unchanged_service_selection(&previous, &current)
            .expect("fresh provenance for unchanged semantics renews");
        assert_eq!(renewed.origin_fetched_at, "2026-08-20T00:00:00Z");
        assert_eq!(renewed.catalog_revision, current.catalog_revision);

        let semantic_changes: [fn(&mut ServiceSelection); 3] = [
            |selection| selection.legal_issuer_id = Some("urn:issuer:other".into()),
            |selection| {
                selection.conforms_to = vec!["urn:profile:other".into()];
                refresh_selection_binding_id(selection);
            },
            |selection| {
                selection.evidence_type_ids = vec!["urn:evidence:other".into()];
                selection.matched_capability =
                    MatchedCapability::EvidenceType("urn:evidence:other".into());
                refresh_selection_binding_id(selection);
            },
        ];
        for mutate in semantic_changes {
            let mut changed = current.clone();
            mutate(&mut changed);
            validate_service_selection_structure(&changed)
                .expect("the changed selection remains structurally valid");

            let mut credentials_constructed = 0;
            let mut native_calls = 0;
            let result = renew_unchanged_service_selection(&previous, &changed).inspect(|_| {
                credentials_constructed += 1;
                native_calls += 1;
            });
            assert_eq!(result, Err(DiscoveryClientError::SelectionChanged));
            assert_eq!(credentials_constructed, 0);
            assert_eq!(native_calls, 0);
        }

        let mut relay = service();
        relay.service_kind = ServiceKind::Relay;
        relay.legal_issuer_id = None;
        relay.technical_provider_id = None;
        relay.registry_authority_id = Some("urn:registry-authority".into());
        relay.evidence_type_ids.clear();
        relay.semantic_class_ids = vec!["urn:semantic:business".into()];
        relay.operation_family_ids =
            vec!["urn:operation:list".into(), "urn:operation:search".into()];
        refresh_binding_id(&mut relay);
        let relay_response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&relay)).unwrap(),
            items: vec![relay],
        };
        let relay_previous = relay_response
            .select_relay(RelaySelectionRequest::new(
                "record-a",
                RelayCapabilityMatch::for_semantic_class("urn:semantic:business")
                    .with_operation_family("urn:operation:list"),
            ))
            .expect("valid Relay tuple")
            .into_selection();
        let relay_current = relay_response
            .select_relay(RelaySelectionRequest::new(
                "record-a",
                RelayCapabilityMatch::for_semantic_class("urn:semantic:business")
                    .with_operation_family("urn:operation:search"),
            ))
            .expect("a changed Relay tuple remains structurally valid")
            .into_selection();
        assert_eq!(relay_previous.binding_id, relay_current.binding_id);
        assert_eq!(
            relay_previous.matched_capability,
            relay_current.matched_capability
        );
        assert_eq!(
            renew_unchanged_service_selection(&relay_previous, &relay_current),
            Err(DiscoveryClientError::SelectionChanged)
        );
    }

    #[test]
    fn select_only_refuses_an_unranked_zero_or_many_result_set() {
        let record = service();
        let response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record.clone()],
        };
        let selected = response
            .select_only(MatchedCapability::EvidenceType("urn:evidence".into()))
            .expect("one result is unambiguous");
        assert_eq!(selected.record_id, "record-a");
        let mut empty = response.clone();
        empty.items.clear();
        assert_eq!(
            empty.select_only(MatchedCapability::EvidenceType("urn:evidence".into())),
            Err(DiscoveryClientError::NoMatchingService)
        );
        let mut many = response;
        let mut second = record;
        second.record_id = "record-b".into();
        many.items.push(second);
        assert_eq!(
            many.select_only(MatchedCapability::EvidenceType("urn:evidence".into())),
            Err(DiscoveryClientError::AmbiguousSelection)
        );
    }

    #[test]
    fn selection_retains_and_round_trips_complete_origin_provenance() {
        let record = service();
        let response = ServiceSearchResponse {
            catalog_revision: catalog_revision(std::slice::from_ref(&record)).unwrap(),
            items: vec![record],
        };
        let selection = response
            .select_exact(SelectionRequest {
                record_id: "record-a".into(),
                matched_capability: MatchedCapability::EvidenceType("urn:evidence".into()),
                mapping_revision: Some(format!("sha256:{}", "2".repeat(64))),
            })
            .expect("exact service selection");

        assert_eq!(selection.origin_id, "origin-a");
        assert_eq!(
            selection.origin_url,
            "https://provider.example/catalog.jsonld"
        );
        assert_eq!(
            selection.origin_content_digest,
            format!("sha256:{}", "1".repeat(64))
        );
        assert_eq!(selection.origin_fetched_at, "2026-08-14T00:00:00Z");

        let encoded = serde_json::to_vec(&selection).expect("selection serializes");
        let decoded: ServiceSelection =
            serde_json::from_slice(&encoded).expect("selection deserializes");
        assert_eq!(decoded, selection);
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
