// SPDX-License-Identifier: Apache-2.0
//! Strict immutable index and public wire models.

use std::collections::BTreeSet;

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::{Host, Url};

pub use registry_discovery_profile::ServiceKind;

pub const INDEX_SCHEMA: &str = "registry-discovery/index/v1alpha1";
pub const RUNTIME_SCHEMA: &str = "registry-discovery/runtime/v1alpha1";
pub const MAXIMUM_INDEX_BYTES: u64 = 64 * 1024 * 1024;
pub const MAXIMUM_ORIGINS: usize = 1_024;
pub const MAXIMUM_SERVICES: usize = 100_000;
pub const MAXIMUM_MAPPINGS: usize = 10_000;
pub const MAXIMUM_ALTERNATIVES_PER_MAPPING: usize = 128;
pub const MAXIMUM_EVIDENCE_TYPES_PER_ALTERNATIVE: usize = 128;
pub const MAXIMUM_VALUES_PER_FIELD: usize = 256;
pub const MAXIMUM_IDENTIFIER_CHARACTERS: usize = 4_096;
pub const MAXIMUM_TEXT_CHARACTERS: usize = 16 * 1024;
pub const MAXIMUM_LISTENER_ADDRESS_CHARACTERS: usize = 128;
pub const MAXIMUM_FILTER_VALUES: usize = 100;
pub const MAXIMUM_QUERY_BYTES: usize = 64 * 1024;
pub const MAXIMUM_RESULT_RECORDS: usize = 10_000;
pub const MAXIMUM_RESULT_ALTERNATIVES: usize = 1_000;
pub const MINIMUM_HTTP_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAXIMUM_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DiscoveryIndex {
    pub schema_version: String,
    pub catalog_revision: String,
    pub mapping_revision: String,
    pub built_at: String,
    pub origins: Vec<OriginSummary>,
    pub services: Vec<ServiceRecord>,
    pub mappings: Vec<CompiledEvidenceMapping>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OriginSummary {
    pub origin_id: String,
    pub catalog_url: String,
    pub content_digest: String,
    pub fetched_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceRecord {
    pub record_id: String,
    pub binding_id: String,
    pub service_id: String,
    pub service_kind: ServiceKind,
    pub title: String,
    pub description: String,
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
    pub origin_id: String,
    pub origin_url: String,
    pub origin_content_digest: String,
    pub origin_fetched_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEvidenceMapping {
    pub mapping_id: String,
    pub mapping_authority_id: String,
    pub requirement_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    pub alternatives: Vec<EvidenceTypeAlternative>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceTypeAlternative {
    pub evidence_type_list_id: String,
    pub evidence_type_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceTypeResolveRequest {
    pub requirement_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResolvedAlternative {
    pub evidence_type_list_id: String,
    pub evidence_type_ids: Vec<String>,
    pub mapping_id: String,
    pub mapping_authority_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceTypeResolveResponse {
    pub requirement_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    pub mapping_revision: String,
    pub alternatives: Vec<ResolvedAlternative>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceFilters {
    pub record_id: Vec<String>,
    pub service_id: Vec<String>,
    pub service_kind: Vec<ServiceKind>,
    pub jurisdiction: Vec<String>,
    pub conforms_to: Vec<String>,
    pub evidence_type: Vec<String>,
    pub semantic_class: Vec<String>,
    pub operation_family: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceSearchResponse {
    pub catalog_revision: String,
    pub items: Vec<ServiceRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListenerConfig {
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeLimits {
    pub maximum_request_bytes: usize,
    pub maximum_response_bytes: usize,
    pub maximum_result_records: usize,
    pub maximum_result_alternatives: usize,
    pub request_timeout_seconds: u64,
    pub shutdown_timeout_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeConfig {
    pub schema_version: String,
    pub listener: ListenerConfig,
    pub index_path: String,
    pub limits: RuntimeLimits,
    pub log_level: LogLevel,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexError {
    #[error("the Discovery index is not valid")]
    Invalid,
    #[error("the Discovery index exceeds a compiled bound")]
    BoundExceeded,
    #[error("the Discovery index is not canonical")]
    NotCanonical,
}

pub fn parse_index(bytes: &[u8]) -> Result<DiscoveryIndex, IndexError> {
    if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |len| len > MAXIMUM_INDEX_BYTES)
    {
        return Err(IndexError::BoundExceeded);
    }
    let value = parse_json_strict(bytes).map_err(|_| IndexError::Invalid)?;
    let index: DiscoveryIndex = serde_json::from_value(value).map_err(|_| IndexError::Invalid)?;
    validate_index(&index)?;
    let canonical = canonical_index_bytes(&index)?;
    if bytes != canonical {
        return Err(IndexError::NotCanonical);
    }
    Ok(index)
}

pub fn canonical_index_bytes(index: &DiscoveryIndex) -> Result<Vec<u8>, IndexError> {
    validate_index(index)?;
    let value = serde_json::to_value(index).map_err(|_| IndexError::Invalid)?;
    let bytes = canonicalize_json(&value).map_err(|_| IndexError::Invalid)?;
    enforce_index_byte_bound(bytes, MAXIMUM_INDEX_BYTES)
}

fn enforce_index_byte_bound(bytes: Vec<u8>, maximum: u64) -> Result<Vec<u8>, IndexError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err(IndexError::BoundExceeded);
    }
    Ok(bytes)
}

pub fn catalog_revision(services: &[ServiceRecord]) -> Result<String, IndexError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SemanticService<'a> {
        record_id: &'a str,
        binding_id: &'a str,
        service_id: &'a str,
        service_kind: ServiceKind,
        title: &'a str,
        description: &'a str,
        endpoint_url: &'a str,
        publisher_id: &'a Option<String>,
        operator_id: &'a Option<String>,
        registry_authority_id: &'a Option<String>,
        legal_issuer_id: &'a Option<String>,
        technical_provider_id: &'a Option<String>,
        jurisdictions: &'a [String],
        conforms_to: &'a [String],
        evidence_type_ids: &'a [String],
        semantic_class_ids: &'a [String],
        operation_family_ids: &'a [String],
        origin_id: &'a str,
        origin_url: &'a str,
    }
    let semantic = services
        .iter()
        .map(|service| SemanticService {
            record_id: &service.record_id,
            binding_id: &service.binding_id,
            service_id: &service.service_id,
            service_kind: service.service_kind,
            title: &service.title,
            description: &service.description,
            endpoint_url: &service.endpoint_url,
            publisher_id: &service.publisher_id,
            operator_id: &service.operator_id,
            registry_authority_id: &service.registry_authority_id,
            legal_issuer_id: &service.legal_issuer_id,
            technical_provider_id: &service.technical_provider_id,
            jurisdictions: &service.jurisdictions,
            conforms_to: &service.conforms_to,
            evidence_type_ids: &service.evidence_type_ids,
            semantic_class_ids: &service.semantic_class_ids,
            operation_family_ids: &service.operation_family_ids,
            origin_id: &service.origin_id,
            origin_url: &service.origin_url,
        })
        .collect::<Vec<_>>();
    semantic_revision(&semantic)
}

pub fn mapping_revision(mappings: &[CompiledEvidenceMapping]) -> Result<String, IndexError> {
    semantic_revision(mappings)
}

fn semantic_revision<T: Serialize + ?Sized>(value: &T) -> Result<String, IndexError> {
    let value = serde_json::to_value(value).map_err(|_| IndexError::Invalid)?;
    let bytes = canonicalize_json(&value).map_err(|_| IndexError::Invalid)?;
    Ok(format!("sha256:{}", hex_digest(&bytes)))
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

pub fn validate_index(index: &DiscoveryIndex) -> Result<(), IndexError> {
    if index.schema_version != INDEX_SCHEMA
        || !valid_digest(&index.catalog_revision)
        || !valid_digest(&index.mapping_revision)
        || !valid_timestamp(&index.built_at)
    {
        return Err(IndexError::Invalid);
    }
    if index.origins.len() > MAXIMUM_ORIGINS
        || index.services.len() > MAXIMUM_SERVICES
        || index.mappings.len() > MAXIMUM_MAPPINGS
    {
        return Err(IndexError::BoundExceeded);
    }

    let mut origin_ids = BTreeSet::new();
    let mut origin_urls = BTreeSet::new();
    for origin in &index.origins {
        validate_origin(origin)?;
        if !origin_ids.insert(origin.origin_id.as_str())
            || !origin_urls.insert(origin.catalog_url.as_str())
        {
            return Err(IndexError::Invalid);
        }
    }
    if !index
        .origins
        .windows(2)
        .all(|pair| pair[0].origin_id < pair[1].origin_id)
    {
        return Err(IndexError::Invalid);
    }

    let mut record_ids = BTreeSet::new();
    for service in &index.services {
        validate_service(service)?;
        if !record_ids.insert(service.record_id.as_str()) {
            return Err(IndexError::Invalid);
        }
        let origin = index
            .origins
            .iter()
            .find(|origin| origin.origin_id == service.origin_id)
            .ok_or(IndexError::Invalid)?;
        if origin.catalog_url != service.origin_url
            || origin.content_digest != service.origin_content_digest
            || origin.fetched_at != service.origin_fetched_at
        {
            return Err(IndexError::Invalid);
        }
    }
    if !index
        .services
        .windows(2)
        .all(|pair| pair[0].record_id < pair[1].record_id)
    {
        return Err(IndexError::Invalid);
    }

    let mut mapping_keys = BTreeSet::new();
    let mut mapping_ids = BTreeSet::new();
    for mapping in &index.mappings {
        validate_mapping(mapping)?;
        if !mapping_ids.insert(mapping.mapping_id.as_str())
            || !mapping_keys.insert((
                mapping.requirement_id.as_str(),
                mapping.jurisdiction.as_deref(),
            ))
        {
            return Err(IndexError::Invalid);
        }
    }
    if !index
        .mappings
        .windows(2)
        .all(|pair| mapping_sort_key(&pair[0]) < mapping_sort_key(&pair[1]))
    {
        return Err(IndexError::Invalid);
    }
    if catalog_revision(&index.services)? != index.catalog_revision
        || mapping_revision(&index.mappings)? != index.mapping_revision
    {
        return Err(IndexError::Invalid);
    }
    Ok(())
}

fn validate_origin(origin: &OriginSummary) -> Result<(), IndexError> {
    if !valid_identifier(&origin.origin_id)
        || !valid_public_url(&origin.catalog_url)
        || !valid_digest(&origin.content_digest)
        || !valid_timestamp(&origin.fetched_at)
    {
        return Err(IndexError::Invalid);
    }
    Ok(())
}

pub fn validate_service(service: &ServiceRecord) -> Result<(), IndexError> {
    if !valid_identifier(&service.record_id)
        || !valid_uri_identifier(&service.binding_id)
        || !valid_uri_identifier(&service.service_id)
        || !valid_text(&service.title)
        || !valid_text(&service.description)
        || !valid_public_url(&service.endpoint_url)
        || !valid_optional_uri_identifier(&service.publisher_id)
        || !valid_optional_uri_identifier(&service.operator_id)
        || !valid_optional_uri_identifier(&service.registry_authority_id)
        || !valid_optional_uri_identifier(&service.legal_issuer_id)
        || !valid_optional_uri_identifier(&service.technical_provider_id)
        || !valid_sorted_identifiers(&service.jurisdictions, false)
        || !valid_sorted_identifiers(&service.conforms_to, false)
        || !valid_sorted_identifiers(&service.evidence_type_ids, true)
        || !valid_sorted_identifiers(&service.semantic_class_ids, true)
        || !valid_sorted_identifiers(&service.operation_family_ids, true)
        || !valid_identifier(&service.origin_id)
        || !valid_public_url(&service.origin_url)
        || !valid_digest(&service.origin_content_digest)
        || !valid_timestamp(&service.origin_fetched_at)
    {
        return Err(IndexError::Invalid);
    }
    match service.service_kind {
        ServiceKind::Evidence
            if service.evidence_type_ids.is_empty()
                || !service.semantic_class_ids.is_empty()
                || !service.operation_family_ids.is_empty() =>
        {
            Err(IndexError::Invalid)
        }
        ServiceKind::Relay if !service.evidence_type_ids.is_empty() => Err(IndexError::Invalid),
        _ => Ok(()),
    }
}

fn validate_mapping(mapping: &CompiledEvidenceMapping) -> Result<(), IndexError> {
    if !valid_uri_identifier(&mapping.mapping_id)
        || !valid_uri_identifier(&mapping.mapping_authority_id)
        || !valid_uri_identifier(&mapping.requirement_id)
        || !valid_optional_uri_identifier(&mapping.jurisdiction)
        || mapping.alternatives.is_empty()
    {
        return Err(IndexError::Invalid);
    }
    if mapping.alternatives.len() > MAXIMUM_ALTERNATIVES_PER_MAPPING {
        return Err(IndexError::BoundExceeded);
    }
    for alternative in &mapping.alternatives {
        if !valid_uri_identifier(&alternative.evidence_type_list_id)
            || !valid_sorted_identifiers(&alternative.evidence_type_ids, false)
        {
            return Err(IndexError::Invalid);
        }
        if alternative.evidence_type_ids.len() > MAXIMUM_EVIDENCE_TYPES_PER_ALTERNATIVE {
            return Err(IndexError::BoundExceeded);
        }
    }
    if !mapping
        .alternatives
        .windows(2)
        .all(|pair| pair[0].evidence_type_list_id < pair[1].evidence_type_list_id)
    {
        return Err(IndexError::Invalid);
    }
    Ok(())
}

fn mapping_sort_key(mapping: &CompiledEvidenceMapping) -> (&str, Option<&str>, &str) {
    (
        mapping.requirement_id.as_str(),
        mapping.jurisdiction.as_deref(),
        mapping.mapping_id.as_str(),
    )
}

pub fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAXIMUM_IDENTIFIER_CHARACTERS
        && value.trim() == value
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

pub fn valid_uri_identifier(value: &str) -> bool {
    if !valid_identifier(value) {
        return false;
    }
    Url::parse(value).is_ok_and(|url| !url.scheme().is_empty())
}

fn valid_optional_uri_identifier(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(valid_uri_identifier)
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAXIMUM_TEXT_CHARACTERS
        && !value.chars().any(|character| character.is_control())
}

fn valid_sorted_identifiers(values: &[String], allow_empty: bool) -> bool {
    (allow_empty || !values.is_empty())
        && values.len() <= MAXIMUM_VALUES_PER_FIELD
        && values.iter().all(|value| valid_uri_identifier(value))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_timestamp(value: &str) -> bool {
    value.len() <= 64 && OffsetDateTime::parse(value, &Rfc3339).is_ok()
}

pub fn valid_public_url(value: &str) -> bool {
    if value.chars().count() > MAXIMUM_IDENTIFIER_CHARACTERS {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    match url.scheme() {
        "https" => url.host().is_some(),
        "http" => url.host().is_some_and(|host| match host {
            Host::Ipv4(address) => address.is_loopback(),
            Host::Ipv6(address) => address.is_loopback(),
            Host::Domain(name) => name == "localhost",
        }),
        _ => false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn example_index() -> DiscoveryIndex {
        let origin = OriginSummary {
            origin_id: "origin-a".into(),
            catalog_url: "https://provider.example/catalog.jsonld".into(),
            content_digest: format!("sha256:{}", "1".repeat(64)),
            fetched_at: "2026-08-14T00:00:00Z".into(),
        };
        let services = vec![ServiceRecord {
            record_id: "record-a".into(),
            binding_id: "urn:example:binding:a".into(),
            service_id: "urn:example:service:a".into(),
            service_kind: ServiceKind::Evidence,
            title: "Evidence service".into(),
            description: "Issues minimum-disclosure evidence".into(),
            endpoint_url: "https://provider.example/evidence".into(),
            publisher_id: Some("urn:example:publisher".into()),
            operator_id: None,
            registry_authority_id: None,
            legal_issuer_id: Some("urn:example:issuer".into()),
            technical_provider_id: Some("urn:example:provider".into()),
            jurisdictions: vec!["urn:example:jurisdiction".into()],
            conforms_to: vec!["urn:example:evidence-profile".into()],
            evidence_type_ids: vec!["urn:example:evidence-type".into()],
            semantic_class_ids: Vec::new(),
            operation_family_ids: Vec::new(),
            origin_id: origin.origin_id.clone(),
            origin_url: origin.catalog_url.clone(),
            origin_content_digest: origin.content_digest.clone(),
            origin_fetched_at: origin.fetched_at.clone(),
        }];
        let mappings = vec![CompiledEvidenceMapping {
            mapping_id: "urn:example:mapping".into(),
            mapping_authority_id: "urn:example:authority".into(),
            requirement_id: "urn:example:requirement".into(),
            jurisdiction: Some("urn:example:jurisdiction".into()),
            alternatives: vec![EvidenceTypeAlternative {
                evidence_type_list_id: "urn:example:list".into(),
                evidence_type_ids: vec!["urn:example:evidence-type".into()],
            }],
        }];
        DiscoveryIndex {
            schema_version: INDEX_SCHEMA.into(),
            catalog_revision: catalog_revision(&services).unwrap(),
            mapping_revision: mapping_revision(&mappings).unwrap(),
            built_at: "2026-08-14T00:00:01Z".into(),
            origins: vec![origin],
            services,
            mappings,
        }
    }

    #[test]
    fn canonical_index_round_trips_through_strict_startup_parser() {
        let index = example_index();
        let bytes = canonical_index_bytes(&index).unwrap();
        assert_eq!(parse_index(&bytes).unwrap(), index);
    }

    #[test]
    fn duplicate_members_and_noncanonical_indexes_are_refused() {
        assert_eq!(
            parse_index(br#"{"schemaVersion":"a","schemaVersion":"b"}"#),
            Err(IndexError::Invalid)
        );
        let pretty = serde_json::to_vec_pretty(&example_index()).unwrap();
        assert_eq!(parse_index(&pretty), Err(IndexError::NotCanonical));
    }

    #[test]
    fn canonical_index_output_enforces_the_runtime_byte_bound() {
        assert_eq!(
            enforce_index_byte_bound(vec![0; 5], 4),
            Err(IndexError::BoundExceeded)
        );
        assert_eq!(enforce_index_byte_bound(vec![0; 4], 4).unwrap().len(), 4);
    }

    #[test]
    fn record_and_origin_identifiers_refuse_surrounding_whitespace() {
        assert!(valid_identifier("origin-a"));
        assert!(!valid_identifier(" origin-a"));
        assert!(!valid_identifier("origin-a "));
    }

    #[test]
    fn semantic_uri_identifiers_accept_rdf_fragment_iris() {
        let fragment = "https://example.org/vocabulary#AdultStatus";
        assert!(valid_uri_identifier(fragment));

        let mut index = example_index();
        index.services[0].service_id = "https://example.org/services#evidence".into();
        index.services[0].jurisdictions = vec!["https://example.org/areas#north".into()];
        index.services[0].conforms_to = vec!["https://example.org/profiles#signed".into()];
        index.services[0].evidence_type_ids = vec![fragment.into()];
        index.mappings[0].mapping_id = "https://example.org/mappings#adult".into();
        index.mappings[0].mapping_authority_id = "https://example.org/authorities#one".into();
        index.mappings[0].requirement_id = "https://example.org/requirements#adult".into();
        index.mappings[0].jurisdiction = Some("https://example.org/areas#north".into());
        index.mappings[0].alternatives[0].evidence_type_list_id =
            "https://example.org/lists#adult".into();
        index.mappings[0].alternatives[0].evidence_type_ids = vec![fragment.into()];
        index.catalog_revision = catalog_revision(&index.services).unwrap();
        index.mapping_revision = mapping_revision(&index.mappings).unwrap();

        validate_index(&index).expect("fragment IRIs are valid semantic identifiers");
    }

    #[test]
    fn public_string_bounds_count_unicode_characters_not_utf8_bytes() {
        let text = "é".repeat(MAXIMUM_TEXT_CHARACTERS);
        assert!(text.len() > MAXIMUM_TEXT_CHARACTERS);
        assert!(valid_text(&text));
        assert!(!valid_text(&format!("{text}é")));

        let prefix = "https://example.org/vocabulary#";
        let identifier = format!(
            "{prefix}{}",
            "界".repeat(MAXIMUM_IDENTIFIER_CHARACTERS - prefix.chars().count())
        );
        assert!(identifier.len() > MAXIMUM_IDENTIFIER_CHARACTERS);
        assert!(valid_uri_identifier(&identifier));
        assert!(!valid_uri_identifier(&format!("{identifier}界")));
    }

    #[test]
    fn protected_only_relay_records_are_valid_without_public_capabilities() {
        let mut service = example_index().services.remove(0);
        service.service_kind = ServiceKind::Relay;
        service.evidence_type_ids.clear();
        assert_eq!(validate_service(&service), Ok(()));
    }

    #[test]
    fn duplicate_exact_mapping_keys_are_refused() {
        let mut index = example_index();
        let mut duplicate = index.mappings[0].clone();
        duplicate.mapping_id = "urn:example:mapping:duplicate".into();
        index.mappings.push(duplicate);
        index.mapping_revision = mapping_revision(&index.mappings).unwrap();
        assert_eq!(validate_index(&index), Err(IndexError::Invalid));
    }

    #[test]
    fn build_time_provenance_does_not_change_semantic_revisions() {
        let mut later = example_index();
        later.built_at = "2026-08-15T00:00:00Z".into();
        later.origins[0].fetched_at = "2026-08-15T00:00:00Z".into();
        later.services[0].origin_fetched_at = later.origins[0].fetched_at.clone();
        assert_eq!(
            catalog_revision(&later.services).unwrap(),
            example_index().catalog_revision
        );
    }

    #[test]
    fn records_from_distinct_origins_never_merge() {
        let mut index = example_index();
        let mut second_origin = index.origins[0].clone();
        second_origin.origin_id = "origin-b".into();
        second_origin.catalog_url = "https://other.example/catalog.jsonld".into();
        index.origins.push(second_origin.clone());
        let mut second = index.services[0].clone();
        second.record_id = "record-b".into();
        second.origin_id = second_origin.origin_id;
        second.origin_url = second_origin.catalog_url;
        index.services.push(second);
        index.catalog_revision = catalog_revision(&index.services).unwrap();
        validate_index(&index).unwrap();
        assert_eq!(index.services[0].service_id, index.services[1].service_id);
        assert_ne!(index.services[0].origin_id, index.services[1].origin_id);
    }
}
