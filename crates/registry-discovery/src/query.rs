// SPDX-License-Identifier: Apache-2.0
//! Exact, bounded, unranked queries over one immutable index.

use std::sync::Arc;

use thiserror::Error;

use crate::model::{
    valid_identifier, valid_uri_identifier, validate_index, CompiledEvidenceMapping,
    DiscoveryIndex, EvidenceTypeResolveRequest, EvidenceTypeResolveResponse, ResolvedAlternative,
    ServiceFilters, ServiceKind, ServiceRecord, ServiceSearchResponse, MAXIMUM_FILTER_VALUES,
    MAXIMUM_QUERY_BYTES, MAXIMUM_QUERY_VALUE_CHARACTERS, MAXIMUM_RESULT_ALTERNATIVES,
    MAXIMUM_RESULT_RECORDS,
};

const FILTER_NAMES: [&str; 8] = [
    "recordId",
    "serviceId",
    "serviceKind",
    "jurisdiction",
    "conformsTo",
    "evidenceType",
    "semanticClass",
    "operationFamily",
];

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueryError {
    #[error("the Discovery request is invalid")]
    InvalidRequest,
    #[error("the complete Discovery result exceeds the configured bound")]
    ResultBoundExceeded,
}

#[derive(Clone)]
pub struct Directory {
    index: Arc<DiscoveryIndex>,
    maximum_result_records: usize,
    maximum_result_alternatives: usize,
}

impl Directory {
    pub fn new(
        index: DiscoveryIndex,
        maximum_result_records: usize,
        maximum_result_alternatives: usize,
    ) -> Result<Self, QueryError> {
        if validate_index(&index).is_err()
            || maximum_result_records == 0
            || maximum_result_records > MAXIMUM_RESULT_RECORDS
            || maximum_result_alternatives == 0
            || maximum_result_alternatives > MAXIMUM_RESULT_ALTERNATIVES
        {
            return Err(QueryError::InvalidRequest);
        }
        Ok(Self {
            index: Arc::new(index),
            maximum_result_records,
            maximum_result_alternatives,
        })
    }

    #[must_use]
    pub fn index(&self) -> &DiscoveryIndex {
        &self.index
    }

    pub fn search_services(
        &self,
        filters: &ServiceFilters,
    ) -> Result<ServiceSearchResponse, QueryError> {
        validate_service_filters(filters)?;
        let mut items = Vec::new();
        for service in &self.index.services {
            if service_matches_filters(service, filters) {
                if items.len() == self.maximum_result_records {
                    return Err(QueryError::ResultBoundExceeded);
                }
                items.push(service.clone());
            }
        }
        Ok(ServiceSearchResponse {
            catalog_revision: self.index.catalog_revision.clone(),
            items,
        })
    }

    pub fn resolve_evidence_types(
        &self,
        request: &EvidenceTypeResolveRequest,
    ) -> Result<EvidenceTypeResolveResponse, QueryError> {
        validate_resolve_request(request)?;
        let mapping = self.index.mappings.iter().find(|mapping| {
            mapping.requirement_id == request.requirement_id
                && mapping.jurisdiction == request.jurisdiction
        });
        let alternatives = mapping.map_or_else(Vec::new, resolved_alternatives);
        if alternatives.len() > self.maximum_result_alternatives {
            return Err(QueryError::ResultBoundExceeded);
        }
        Ok(EvidenceTypeResolveResponse {
            requirement_id: request.requirement_id.clone(),
            jurisdiction: request.jurisdiction.clone(),
            mapping_revision: self.index.mapping_revision.clone(),
            alternatives,
        })
    }
}

fn resolved_alternatives(mapping: &CompiledEvidenceMapping) -> Vec<ResolvedAlternative> {
    mapping
        .alternatives
        .iter()
        .map(|alternative| ResolvedAlternative {
            evidence_type_list_id: alternative.evidence_type_list_id.clone(),
            evidence_type_ids: alternative.evidence_type_ids.clone(),
            mapping_id: mapping.mapping_id.clone(),
            mapping_authority_id: mapping.mapping_authority_id.clone(),
        })
        .collect()
}

pub fn parse_service_filters(raw_query: &str) -> Result<ServiceFilters, QueryError> {
    if raw_query.len() > MAXIMUM_QUERY_BYTES || !strict_form_encoding(raw_query) {
        return Err(QueryError::InvalidRequest);
    }
    let mut filters = ServiceFilters::default();
    let mut parameter_count = 0usize;
    let mut value_characters = 0usize;
    for (name, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        parameter_count = parameter_count
            .checked_add(1)
            .ok_or(QueryError::InvalidRequest)?;
        value_characters = value_characters
            .checked_add(value.chars().count())
            .ok_or(QueryError::InvalidRequest)?;
        if parameter_count > FILTER_NAMES.len() * MAXIMUM_FILTER_VALUES
            || value_characters > MAXIMUM_QUERY_VALUE_CHARACTERS
            || value.is_empty()
            || !valid_identifier(&value)
        {
            return Err(QueryError::InvalidRequest);
        }
        match name.as_ref() {
            "recordId" => filters.record_id.push(value.into_owned()),
            "serviceId" => filters.service_id.push(value.into_owned()),
            "serviceKind" => filters.service_kind.push(match value.as_ref() {
                "evidence" => ServiceKind::Evidence,
                "relay" => ServiceKind::Relay,
                _ => return Err(QueryError::InvalidRequest),
            }),
            "jurisdiction" => filters.jurisdiction.push(value.into_owned()),
            "conformsTo" => filters.conforms_to.push(value.into_owned()),
            "evidenceType" => filters.evidence_type.push(value.into_owned()),
            "semanticClass" => filters.semantic_class.push(value.into_owned()),
            "operationFamily" => filters.operation_family.push(value.into_owned()),
            _ => return Err(QueryError::InvalidRequest),
        }
    }
    validate_service_filters(&filters)?;
    Ok(filters)
}

fn strict_form_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut offset = 0usize;
    while offset < bytes.len() {
        match bytes[offset] {
            b'%' => {
                let Some(high) = bytes.get(offset + 1).and_then(|byte| hex_value(*byte)) else {
                    return false;
                };
                let Some(low) = bytes.get(offset + 2).and_then(|byte| hex_value(*byte)) else {
                    return false;
                };
                decoded.push((high << 4) | low);
                offset += 3;
            }
            b'+' => {
                decoded.push(b' ');
                offset += 1;
            }
            byte => {
                decoded.push(byte);
                offset += 1;
            }
        }
    }
    std::str::from_utf8(&decoded).is_ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn validate_service_filters(filters: &ServiceFilters) -> Result<(), QueryError> {
    let uri_values = [
        &filters.service_id,
        &filters.jurisdiction,
        &filters.conforms_to,
        &filters.evidence_type,
        &filters.semantic_class,
        &filters.operation_family,
    ];
    if query_value_characters(filters)
        .is_none_or(|characters| characters > MAXIMUM_QUERY_VALUE_CHARACTERS)
        || filters.service_kind.len() > 2
        || filters
            .service_kind
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        || filters.record_id.len() > MAXIMUM_FILTER_VALUES
        || filters
            .record_id
            .iter()
            .any(|value| !valid_identifier(value))
        || uri_values.iter().any(|values| {
            values.len() > MAXIMUM_FILTER_VALUES
                || values.iter().any(|value| !valid_uri_identifier(value))
        })
    {
        return Err(QueryError::InvalidRequest);
    }

    let only_evidence = filters.service_kind == [ServiceKind::Evidence];
    let only_relay = filters.service_kind == [ServiceKind::Relay];
    if only_relay && !filters.evidence_type.is_empty()
        || only_evidence
            && (!filters.semantic_class.is_empty() || !filters.operation_family.is_empty())
    {
        return Err(QueryError::InvalidRequest);
    }
    Ok(())
}

fn query_value_characters(filters: &ServiceFilters) -> Option<usize> {
    let string_values = [
        &filters.record_id,
        &filters.service_id,
        &filters.jurisdiction,
        &filters.conforms_to,
        &filters.evidence_type,
        &filters.semantic_class,
        &filters.operation_family,
    ];
    string_values
        .into_iter()
        .flatten()
        .map(|value| value.chars().count())
        .chain(filters.service_kind.iter().map(|kind| match kind {
            ServiceKind::Evidence => "evidence".len(),
            ServiceKind::Relay => "relay".len(),
        }))
        .try_fold(0usize, usize::checked_add)
}

pub fn service_matches_filters(service: &ServiceRecord, filters: &ServiceFilters) -> bool {
    any_exact(&filters.record_id, &service.record_id)
        && any_exact(&filters.service_id, &service.service_id)
        && (filters.service_kind.is_empty() || filters.service_kind.contains(&service.service_kind))
        && any_member(&filters.jurisdiction, &service.jurisdictions)
        && any_member(&filters.conforms_to, &service.conforms_to)
        && any_member(&filters.evidence_type, &service.evidence_type_ids)
        && any_member(&filters.semantic_class, &service.semantic_class_ids)
        && any_member(&filters.operation_family, &service.operation_family_ids)
}

fn any_exact(expected: &[String], actual: &str) -> bool {
    expected.is_empty() || expected.iter().any(|value| value == actual)
}

fn any_member(expected: &[String], actual: &[String]) -> bool {
    expected.is_empty()
        || expected
            .iter()
            .any(|value| actual.iter().any(|candidate| candidate == value))
}

fn validate_resolve_request(request: &EvidenceTypeResolveRequest) -> Result<(), QueryError> {
    if !valid_uri_identifier(&request.requirement_id)
        || request
            .jurisdiction
            .as_deref()
            .is_some_and(|value| !valid_uri_identifier(value))
    {
        return Err(QueryError::InvalidRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::example_index;

    #[test]
    fn exact_filters_are_or_within_one_name_and_and_across_names() {
        let directory = Directory::new(example_index(), 10, 10).unwrap();
        let filters = parse_service_filters(
            "serviceId=urn%3Anope&serviceId=urn%3Aexample%3Aservice%3Aa&jurisdiction=urn%3Aexample%3Ajurisdiction",
        )
        .unwrap();
        let response = directory.search_services(&filters).unwrap();
        assert_eq!(response.items.len(), 1);

        let none =
            parse_service_filters("serviceId=urn%3Aexample%3Aservice%3Aa&jurisdiction=urn%3Awrong")
                .unwrap();
        assert!(directory.search_services(&none).unwrap().items.is_empty());
    }

    #[test]
    fn exact_comparison_is_case_sensitive() {
        let directory = Directory::new(example_index(), 10, 10).unwrap();
        let filters = parse_service_filters("evidenceType=URN%3AEXAMPLE%3AEVIDENCE-TYPE").unwrap();
        assert!(directory
            .search_services(&filters)
            .unwrap()
            .items
            .is_empty());
    }

    #[test]
    fn fragment_iris_survive_exact_search_and_resolution() {
        let evidence_type = "https://example.org/vocabulary#AdultStatus";
        let requirement = "https://example.org/requirements#AdultStatus";
        let jurisdiction = "https://example.org/areas#North";
        let mut index = example_index();
        index.services[0].evidence_type_ids = vec![evidence_type.into()];
        index.mappings[0].requirement_id = requirement.into();
        index.mappings[0].jurisdiction = Some(jurisdiction.into());
        index.mappings[0].alternatives[0].evidence_type_ids = vec![evidence_type.into()];
        index.catalog_revision = crate::model::catalog_revision(&index.services).unwrap();
        index.mapping_revision = crate::model::mapping_revision(&index.mappings).unwrap();
        let directory = Directory::new(index, 10, 10).unwrap();

        let filters = parse_service_filters(
            "evidenceType=https%3A%2F%2Fexample.org%2Fvocabulary%23AdultStatus",
        )
        .unwrap();
        assert_eq!(directory.search_services(&filters).unwrap().items.len(), 1);
        let resolved = directory
            .resolve_evidence_types(&EvidenceTypeResolveRequest {
                requirement_id: requirement.into(),
                jurisdiction: Some(jurisdiction.into()),
            })
            .unwrap();
        assert_eq!(
            resolved.alternatives[0].evidence_type_ids,
            vec![evidence_type.to_owned()]
        );
    }

    #[test]
    fn incompatible_product_filters_are_invalid() {
        assert_eq!(
            parse_service_filters("serviceKind=relay&evidenceType=urn%3Atype"),
            Err(QueryError::InvalidRequest)
        );
        assert_eq!(
            parse_service_filters("serviceKind=evidence&semanticClass=urn%3Aclass"),
            Err(QueryError::InvalidRequest)
        );
    }

    #[test]
    fn malformed_percent_encoding_and_invalid_utf8_are_refused() {
        for invalid in [
            "serviceId=urn%",
            "serviceId=urn%2",
            "serviceId=urn%2Gexample",
            "serviceId=urn%FFexample",
            "serviceId=urn%C3%28example",
        ] {
            assert_eq!(
                parse_service_filters(invalid),
                Err(QueryError::InvalidRequest),
                "{invalid}"
            );
        }
        assert!(parse_service_filters("serviceId=urn%3Aexample%3Aservice").is_ok());
    }

    #[test]
    fn decoded_query_values_share_one_aggregate_character_budget() {
        let first = "a".repeat(crate::model::MAXIMUM_IDENTIFIER_CHARACTERS);
        let remaining = MAXIMUM_QUERY_VALUE_CHARACTERS - first.chars().count();
        let second = "b".repeat(remaining);
        let boundary = format!("recordId={first}&recordId={second}");
        assert!(boundary.len() <= MAXIMUM_QUERY_BYTES);
        assert!(parse_service_filters(&boundary).is_ok());

        let over = format!("{boundary}b");
        assert_eq!(
            parse_service_filters(&over),
            Err(QueryError::InvalidRequest)
        );
    }

    #[test]
    fn per_field_maxima_do_not_imply_aggregate_acceptance() {
        let maximum = "a".repeat(crate::model::MAXIMUM_IDENTIFIER_CHARACTERS);
        let raw = format!("recordId={maximum}&recordId={maximum}");
        assert!(raw.len() <= MAXIMUM_QUERY_BYTES);
        assert_eq!(parse_service_filters(&raw), Err(QueryError::InvalidRequest));
    }

    #[test]
    fn worst_case_percent_encoding_of_the_aggregate_budget_fits_the_wire_ceiling() {
        let first = "􏿿".repeat(crate::model::MAXIMUM_IDENTIFIER_CHARACTERS);
        let second = "􏿿"
            .repeat(MAXIMUM_QUERY_VALUE_CHARACTERS - crate::model::MAXIMUM_IDENTIFIER_CHARACTERS);
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("recordId", &first)
            .append_pair("recordId", &second)
            .finish();
        assert!(encoded.len() <= MAXIMUM_QUERY_BYTES, "{}", encoded.len());
        assert!(parse_service_filters(&encoded).is_ok());
    }

    #[test]
    fn complete_results_are_returned_or_refused_without_truncation() {
        let directory = Directory::new(example_index(), 1, 10).unwrap();
        assert_eq!(
            directory
                .search_services(&ServiceFilters::default())
                .unwrap()
                .items
                .len(),
            1
        );

        let mut index = example_index();
        let mut second = index.services[0].clone();
        second.record_id = "record-b".into();
        index.services.push(second);
        index.catalog_revision = crate::model::catalog_revision(&index.services).unwrap();
        let directory = Directory::new(index, 1, 10).unwrap();
        assert_eq!(
            directory.search_services(&ServiceFilters::default()),
            Err(QueryError::ResultBoundExceeded)
        );
    }

    #[test]
    fn resolver_matches_the_explicit_exact_key_and_never_infers_jurisdiction() {
        let directory = Directory::new(example_index(), 10, 10).unwrap();
        let absent = directory
            .resolve_evidence_types(&EvidenceTypeResolveRequest {
                requirement_id: "urn:example:requirement".into(),
                jurisdiction: None,
            })
            .unwrap();
        assert!(absent.alternatives.is_empty());

        let exact = directory
            .resolve_evidence_types(&EvidenceTypeResolveRequest {
                requirement_id: "urn:example:requirement".into(),
                jurisdiction: Some("urn:example:jurisdiction".into()),
            })
            .unwrap();
        assert_eq!(exact.alternatives.len(), 1);
        assert_eq!(exact.alternatives[0].mapping_id, "urn:example:mapping");
    }

    #[test]
    fn resolver_preserves_and_within_lists_or_across_alternatives_and_refuses_over_bound() {
        let mut index = example_index();
        index.mappings[0].alternatives[0]
            .evidence_type_ids
            .push("urn:example:evidence-type:second".into());
        index.mappings[0]
            .alternatives
            .push(crate::model::EvidenceTypeAlternative {
                evidence_type_list_id: "urn:example:list:second".into(),
                evidence_type_ids: vec!["urn:example:evidence-type:third".into()],
            });
        index.mapping_revision = crate::model::mapping_revision(&index.mappings).unwrap();

        let request = EvidenceTypeResolveRequest {
            requirement_id: "urn:example:requirement".into(),
            jurisdiction: Some("urn:example:jurisdiction".into()),
        };
        let directory = Directory::new(index.clone(), 10, 2).unwrap();
        let response = directory.resolve_evidence_types(&request).unwrap();
        assert_eq!(response.alternatives.len(), 2);
        assert_eq!(response.alternatives[0].evidence_type_ids.len(), 2);

        let bounded = Directory::new(index, 10, 1).unwrap();
        assert_eq!(
            bounded.resolve_evidence_types(&request),
            Err(QueryError::ResultBoundExceeded)
        );
    }
}
