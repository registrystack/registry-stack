//! Closed Registry Discovery provider-publication profile.
//!
//! This crate accepts exactly one JSON-LD document shape. It does not expand
//! JSON-LD, resolve contexts, fetch links, hold RDF graphs, or make trust or
//! native-service decisions. Those capabilities belong outside publication.

use std::collections::BTreeSet;

use registry_platform_canonical_json::{
    canonicalize_json, parse_json_strict, JcsError, StrictJsonError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::{Host, Url};

/// The sole Registry Discovery publication profile understood by this crate.
pub const PROFILE_ID: &str = "registry-discovery-v1alpha1";
/// The sole JSON-LD context a published description may name.
pub const CONTEXT_URL: &str = "https://registrystack.org/discovery/context/v1alpha1";
/// The media type for the closed provider-publication representation.
pub const MEDIA_TYPE: &str =
    "application/ld+json;profile=\"https://registrystack.org/discovery/profile/v1alpha1\"";
/// Maximum accepted provider-description size before JSON parsing.
pub const MAX_DESCRIPTION_BYTES: usize = 1024 * 1024;
/// Maximum advertised services in one provider description.
pub const MAX_SERVICES: usize = 1024;
/// Maximum values in a public identifier collection.
pub const MAX_IDENTIFIER_VALUES: usize = 128;
/// Maximum Unicode scalar values in a public string.
pub const MAX_STRING_CHARACTERS: usize = 4096;

const CATALOG_TYPE: &str = "dcat:Catalog";
const SERVICE_TYPE: &str = "dcat:DataService";

/// A closed provider-publication document. It contains public advertisements,
/// not a catalog index, origin provenance, mappings, trust policy, or native
/// client configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryDescription {
    #[serde(rename = "@context")]
    context: String,
    #[serde(rename = "@type")]
    type_: String,
    profile: String,
    services: Vec<ServiceDescription>,
}

impl DiscoveryDescription {
    /// Construct a description after enforcing the complete closed profile.
    pub fn new(services: Vec<ServiceDescription>) -> Result<Self, ProfileError> {
        let description = Self {
            context: CONTEXT_URL.to_owned(),
            type_: CATALOG_TYPE.to_owned(),
            profile: PROFILE_ID.to_owned(),
            services,
        };
        description.validate()?;
        Ok(description)
    }

    /// Public service advertisements in canonical input order.
    #[must_use]
    pub fn services(&self) -> &[ServiceDescription] {
        &self.services
    }

    /// Validate this value without reading files, resolving JSON-LD, or I/O.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.context != CONTEXT_URL {
            return Err(ProfileError::Context);
        }
        if self.type_ != CATALOG_TYPE {
            return Err(ProfileError::CatalogType);
        }
        if self.profile != PROFILE_ID {
            return Err(ProfileError::Profile);
        }
        if self.services.is_empty() || self.services.len() > MAX_SERVICES {
            return Err(ProfileError::ServiceCount);
        }
        let mut binding_ids = BTreeSet::new();
        for service in &self.services {
            service.validate()?;
            if !binding_ids.insert(service.binding_id.as_str()) {
                return Err(ProfileError::DuplicateServiceBinding);
            }
        }
        Ok(())
    }
}

/// A single advertised native service. Every collection must be in strict
/// Unicode code-point order. Enforcing the order makes rendered bytes stable
/// and makes an ordering drift a rejected provider publication rather than a
/// hidden normalization choice.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDescription {
    #[serde(rename = "@type")]
    type_: String,
    #[serde(rename = "bindingId")]
    binding_id: String,
    #[serde(rename = "serviceId")]
    service_id: String,
    #[serde(rename = "serviceKind")]
    service_kind: ServiceKind,
    title: String,
    description: String,
    #[serde(rename = "endpointURL")]
    endpoint_url: String,
    #[serde(flatten)]
    roles: ServiceRoles,
    jurisdictions: Vec<String>,
    #[serde(rename = "conformsTo")]
    conforms_to: Vec<String>,
    #[serde(
        rename = "evidenceTypeIds",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    evidence_type_ids: Vec<String>,
    #[serde(
        rename = "semanticClassIds",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    semantic_class_ids: Vec<String>,
    #[serde(
        rename = "operationFamilyIds",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    operation_family_ids: Vec<String>,
}

impl ServiceDescription {
    /// Construct a service advertisement after enforcing the closed profile.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service_id: String,
        service_kind: ServiceKind,
        title: String,
        description: String,
        endpoint_url: String,
        roles: ServiceRoles,
        jurisdictions: Vec<String>,
        conforms_to: Vec<String>,
        evidence_type_ids: Vec<String>,
        semantic_class_ids: Vec<String>,
        operation_family_ids: Vec<String>,
    ) -> Result<Self, ProfileError> {
        let binding_id = derive_binding_id(
            &service_id,
            service_kind,
            &endpoint_url,
            &conforms_to,
            &evidence_type_ids,
            &semantic_class_ids,
            &operation_family_ids,
        )?;
        let service = Self {
            type_: SERVICE_TYPE.to_owned(),
            binding_id,
            service_id,
            service_kind,
            title,
            description,
            endpoint_url,
            roles,
            jurisdictions,
            conforms_to,
            evidence_type_ids,
            semantic_class_ids,
            operation_family_ids,
        };
        service.validate()?;
        Ok(service)
    }

    #[must_use]
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }
    #[must_use]
    pub fn service_id(&self) -> &str {
        &self.service_id
    }
    #[must_use]
    pub const fn service_kind(&self) -> ServiceKind {
        self.service_kind
    }
    #[must_use]
    pub fn endpoint_url(&self) -> &str {
        &self.endpoint_url
    }
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
    #[must_use]
    pub const fn roles(&self) -> &ServiceRoles {
        &self.roles
    }
    #[must_use]
    pub fn jurisdictions(&self) -> &[String] {
        &self.jurisdictions
    }
    #[must_use]
    pub fn conforms_to(&self) -> &[String] {
        &self.conforms_to
    }
    #[must_use]
    pub fn evidence_type_ids(&self) -> &[String] {
        &self.evidence_type_ids
    }
    #[must_use]
    pub fn semantic_class_ids(&self) -> &[String] {
        &self.semantic_class_ids
    }
    #[must_use]
    pub fn operation_family_ids(&self) -> &[String] {
        &self.operation_family_ids
    }

    fn validate(&self) -> Result<(), ProfileError> {
        if self.type_ != SERVICE_TYPE {
            return Err(ProfileError::ServiceType);
        }
        validate_identifier("bindingId", &self.binding_id)?;
        validate_identifier("serviceId", &self.service_id)?;
        validate_text("title", &self.title)?;
        validate_text("description", &self.description)?;
        validate_endpoint(&self.endpoint_url)?;
        for value in self.roles.identifiers().into_iter().flatten() {
            validate_identifier("role identifier", value)?;
        }
        validate_identifier_collection("jurisdictions", &self.jurisdictions, true)?;
        validate_identifier_collection("conformsTo", &self.conforms_to, true)?;
        validate_identifier_collection("evidenceTypeIds", &self.evidence_type_ids, false)?;
        validate_identifier_collection("semanticClassIds", &self.semantic_class_ids, false)?;
        validate_identifier_collection("operationFamilyIds", &self.operation_family_ids, false)?;
        if self.binding_id
            != derive_binding_id(
                &self.service_id,
                self.service_kind,
                &self.endpoint_url,
                &self.conforms_to,
                &self.evidence_type_ids,
                &self.semantic_class_ids,
                &self.operation_family_ids,
            )?
        {
            return Err(ProfileError::BindingIdentity);
        }
        match self.service_kind {
            ServiceKind::Evidence
                if self.evidence_type_ids.is_empty()
                    || !self.semantic_class_ids.is_empty()
                    || !self.operation_family_ids.is_empty() =>
            {
                Err(ProfileError::KindCapabilities)
            }
            ServiceKind::Relay if !self.evidence_type_ids.is_empty() => {
                Err(ProfileError::KindCapabilities)
            }
            _ => Ok(()),
        }
    }
}

/// Public product roles that may be published when the owning product already
/// has them. They remain distinct and are not catalog trust statements.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRoles {
    #[serde(rename = "publisherId", skip_serializing_if = "Option::is_none")]
    pub publisher_id: Option<String>,
    #[serde(rename = "operatorId", skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<String>,
    #[serde(
        rename = "registryAuthorityId",
        skip_serializing_if = "Option::is_none"
    )]
    pub registry_authority_id: Option<String>,
    #[serde(rename = "legalIssuerId", skip_serializing_if = "Option::is_none")]
    pub legal_issuer_id: Option<String>,
    #[serde(
        rename = "technicalProviderId",
        skip_serializing_if = "Option::is_none"
    )]
    pub technical_provider_id: Option<String>,
}

impl ServiceRoles {
    fn identifiers(&self) -> [&Option<String>; 5] {
        [
            &self.publisher_id,
            &self.operator_id,
            &self.registry_authority_id,
            &self.legal_issuer_id,
            &self.technical_provider_id,
        ]
    }

    #[must_use]
    pub fn publisher_id(&self) -> Option<&str> {
        self.publisher_id.as_deref()
    }
    #[must_use]
    pub fn operator_id(&self) -> Option<&str> {
        self.operator_id.as_deref()
    }
    #[must_use]
    pub fn registry_authority_id(&self) -> Option<&str> {
        self.registry_authority_id.as_deref()
    }
    #[must_use]
    pub fn legal_issuer_id(&self) -> Option<&str> {
        self.legal_issuer_id.as_deref()
    }
    #[must_use]
    pub fn technical_provider_id(&self) -> Option<&str> {
        self.technical_provider_id.as_deref()
    }
}

/// The two native product families advertisement may identify.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceKind {
    Evidence,
    Relay,
}

/// A closed-profile parsing or validation refusal.
#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("Registry Discovery description exceeds the byte limit")]
    DocumentTooLarge,
    #[error("Registry Discovery description is not valid closed JSON")]
    Json(#[from] serde_json::Error),
    #[error("Registry Discovery description is not strict JSON")]
    StrictJson(#[from] StrictJsonError),
    #[error("Registry Discovery description cannot be rendered as canonical JSON")]
    CanonicalJson(#[from] JcsError),
    #[error("Registry Discovery description has an unsupported JSON-LD context")]
    Context,
    #[error("Registry Discovery description must be a dcat:Catalog")]
    CatalogType,
    #[error("Registry Discovery description has an unsupported profile")]
    Profile,
    #[error("Registry Discovery description must contain a bounded non-empty service list")]
    ServiceCount,
    #[error("Registry Discovery description has a duplicate service capability binding")]
    DuplicateServiceBinding,
    #[error("Registry Discovery service must be a dcat:DataService")]
    ServiceType,
    #[error("Registry Discovery binding identity does not match its exact capability tuple")]
    BindingIdentity,
    #[error("Registry Discovery public field {0} is invalid")]
    PublicField(&'static str),
    #[error("Registry Discovery endpoint must be HTTPS or an explicit loopback test endpoint")]
    Endpoint,
    #[error(
        "Registry Discovery identifier collection {0} must be strictly sorted, unique, and bounded"
    )]
    IdentifierCollection(&'static str),
    #[error("Registry Discovery service-kind capabilities do not match the service kind")]
    KindCapabilities,
}

/// Strictly parse and validate a provider description. This function performs
/// no network, context, schema, shape, link, vocabulary, or RDF resolution.
pub fn parse_description(bytes: &[u8]) -> Result<DiscoveryDescription, ProfileError> {
    if bytes.len() > MAX_DESCRIPTION_BYTES {
        return Err(ProfileError::DocumentTooLarge);
    }
    let strict = parse_json_strict(bytes)?;
    validate_kind_field_presence(&strict)?;
    let description: DiscoveryDescription = serde_json::from_value(strict)?;
    description.validate()?;
    Ok(description)
}

fn validate_kind_field_presence(value: &serde_json::Value) -> Result<(), ProfileError> {
    let Some(services) = value.get("services").and_then(serde_json::Value::as_array) else {
        return Ok(());
    };
    for service in services {
        let Some(fields) = service.as_object() else {
            continue;
        };
        match fields
            .get("serviceKind")
            .and_then(serde_json::Value::as_str)
        {
            Some("evidence")
                if fields.contains_key("semanticClassIds")
                    || fields.contains_key("operationFamilyIds") =>
            {
                return Err(ProfileError::KindCapabilities);
            }
            Some("relay") if fields.contains_key("evidenceTypeIds") => {
                return Err(ProfileError::KindCapabilities);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Render canonical bytes for a fully validated provider description.
pub fn render_description(description: &DiscoveryDescription) -> Result<Vec<u8>, ProfileError> {
    description.validate()?;
    let value =
        serde_json::to_value(description).expect("closed profile serialization cannot fail");
    let mut rendered = canonicalize_json(&value)?;
    rendered.push(b'\n');
    if rendered.len() > MAX_DESCRIPTION_BYTES {
        return Err(ProfileError::DocumentTooLarge);
    }
    Ok(rendered)
}

#[allow(clippy::too_many_arguments)]
/// Derive the stable identity for one exact provider capability binding.
///
/// Consumers that persist public Discovery metadata can use this function to
/// verify that the advertised identity still covers the service, endpoint,
/// profile, and complete capability tuple.
pub fn derive_binding_id(
    service_id: &str,
    service_kind: ServiceKind,
    endpoint_url: &str,
    conforms_to: &[String],
    evidence_type_ids: &[String],
    semantic_class_ids: &[String],
    operation_family_ids: &[String],
) -> Result<String, ProfileError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct BindingIdentity<'a> {
        service_id: &'a str,
        service_kind: ServiceKind,
        endpoint_url: &'a str,
        conforms_to: &'a [String],
        evidence_type_ids: &'a [String],
        semantic_class_ids: &'a [String],
        operation_family_ids: &'a [String],
    }

    let value = serde_json::to_value(BindingIdentity {
        service_id,
        service_kind,
        endpoint_url,
        conforms_to,
        evidence_type_ids,
        semantic_class_ids,
        operation_family_ids,
    })
    .expect("closed binding identity serialization cannot fail");
    let canonical = canonicalize_json(&value)?;
    let digest = Sha256::digest(canonical);
    let mut encoded = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(format!(
        "urn:registrystack:discovery:binding:sha256:{encoded}"
    ))
}

/// Whether a provider-public text value satisfies the shared character,
/// trimming, and control-character rules.
#[must_use]
pub fn is_valid_public_text(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_STRING_CHARACTERS
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn validate_text(field: &'static str, value: &str) -> Result<(), ProfileError> {
    if !is_valid_public_text(value) {
        return Err(ProfileError::PublicField(field));
    }
    Ok(())
}

/// Whether a globally scoped identifier satisfies the shared public profile.
#[must_use]
pub fn is_valid_identifier(value: &str) -> bool {
    is_valid_public_text(value) && Url::parse(value).is_ok_and(|parsed| !parsed.scheme().is_empty())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ProfileError> {
    if !is_valid_identifier(value) {
        return Err(ProfileError::PublicField(field));
    }
    Ok(())
}

fn validate_endpoint(value: &str) -> Result<(), ProfileError> {
    if !is_valid_endpoint_url(value, true) {
        return Err(ProfileError::Endpoint);
    }
    Ok(())
}

/// Whether a client base or provider-catalog URL satisfies the shared closed
/// URL predicate. Literal whitespace and controls are rejected before WHATWG
/// parsing can trim or percent-encode them. The optional cleartext exception
/// accepts only the three explicit loopback host identities.
#[must_use]
pub fn is_valid_endpoint_url(value: &str, allow_loopback_http: bool) -> bool {
    if !is_valid_public_text(value)
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return false;
    }
    let Ok(parsed) = Url::parse(value) else {
        return false;
    };
    if parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.query().is_some()
        || has_empty_non_trailing_path_segment(&parsed)
    {
        return false;
    }
    let explicit_loopback = exact_loopback_host(value, &parsed);
    parsed.scheme() == "https"
        || (allow_loopback_http && parsed.scheme() == "http" && explicit_loopback)
}

fn has_empty_non_trailing_path_segment(parsed: &Url) -> bool {
    parsed.path_segments().is_some_and(|segments| {
        let segments = segments.collect::<Vec<_>>();
        segments
            .iter()
            .enumerate()
            .any(|(index, segment)| segment.is_empty() && index + 1 < segments.len())
    })
}

fn exact_loopback_host(value: &str, parsed: &Url) -> bool {
    let Some(authority_and_path) = value.strip_prefix("http://") else {
        return false;
    };
    let authority = authority_and_path
        .split_once('/')
        .map_or(authority_and_path, |(authority, _)| authority);
    let raw_host = if authority.starts_with('[') {
        authority
            .find(']')
            .map(|end| &authority[..=end])
            .unwrap_or(authority)
    } else {
        authority
            .split_once(':')
            .map_or(authority, |(host, _)| host)
    };
    match parsed.host() {
        Some(Host::Domain(host)) => host == "localhost" && raw_host == "localhost",
        Some(Host::Ipv4(address)) => {
            address == std::net::Ipv4Addr::LOCALHOST && raw_host == "127.0.0.1"
        }
        Some(Host::Ipv6(address)) => {
            address == std::net::Ipv6Addr::LOCALHOST && raw_host == "[::1]"
        }
        None => false,
    }
}

fn validate_identifier_collection(
    field: &'static str,
    values: &[String],
    non_empty: bool,
) -> Result<(), ProfileError> {
    if (non_empty && values.is_empty()) || values.len() > MAX_IDENTIFIER_VALUES {
        return Err(ProfileError::IdentifierCollection(field));
    }
    let mut previous: Option<&str> = None;
    for value in values {
        validate_identifier(field, value)?;
        if previous.is_some_and(|last| last >= value.as_str()) {
            return Err(ProfileError::IdentifierCollection(field));
        }
        previous = Some(value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> DiscoveryDescription {
        let service = ServiceDescription::new(
            "urn:example:service:evidence".into(),
            ServiceKind::Evidence,
            "Example Evidence".into(),
            "Public signed evidence assertions".into(),
            "https://evidence.example.org".into(),
            ServiceRoles {
                publisher_id: Some("urn:example:publisher".into()),
                ..ServiceRoles::default()
            },
            vec!["https://publications.europa.eu/resource/authority/territory/DEU".into()],
            vec!["https://registrystack.org/evidence/profile/v1".into()],
            vec!["urn:example:evidence-type:adult-status".into()],
            vec![],
            vec![],
        )
        .expect("valid service");
        DiscoveryDescription::new(vec![service]).expect("valid description")
    }

    #[test]
    fn render_and_parse_are_deterministic() {
        let document = evidence();
        let first = render_description(&document).expect("render");
        let second = render_description(&document).expect("render");
        assert_eq!(first, second);
        assert_eq!(parse_description(&first).expect("parse"), document);
    }

    #[test]
    fn repeated_service_id_requires_distinct_exact_capability_bindings() {
        let first = evidence().services()[0].clone();
        let second = ServiceDescription::new(
            first.service_id.clone(),
            first.service_kind,
            first.title.clone(),
            first.description.clone(),
            first.endpoint_url.clone(),
            first.roles.clone(),
            first.jurisdictions.clone(),
            first.conforms_to.clone(),
            vec!["urn:example:evidence-type:residence".into()],
            vec![],
            vec![],
        )
        .expect("distinct exact binding");
        DiscoveryDescription::new(vec![first.clone(), second])
            .expect("one native service may publish distinct capability bindings");
        assert!(matches!(
            DiscoveryDescription::new(vec![first.clone(), first]),
            Err(ProfileError::DuplicateServiceBinding)
        ));
    }

    #[test]
    fn binding_identity_is_derived_and_drift_is_refused() {
        let description = evidence();
        let bytes = render_description(&description).expect("render");
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        value["services"][0]["bindingId"] = serde_json::json!(
            "urn:registrystack:discovery:binding:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(matches!(
            parse_description(&serde_json::to_vec(&value).expect("render")),
            Err(ProfileError::BindingIdentity)
        ));
    }

    #[test]
    fn unknown_or_remote_context_is_refused_without_resolution() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&render_description(&evidence()).expect("render"))
                .expect("json");
        value["@context"] = serde_json::json!("https://attacker.example/context");
        assert!(matches!(
            parse_description(&serde_json::to_vec(&value).expect("render")),
            Err(ProfileError::Context)
        ));
    }

    #[test]
    fn unknown_fields_are_refused_by_the_closed_profile() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&render_description(&evidence()).expect("render"))
                .expect("json");
        value["services"][0]["credential"] = serde_json::json!("private-canary");
        assert!(matches!(
            parse_description(&serde_json::to_vec(&value).expect("render")),
            Err(ProfileError::Json(_))
        ));
    }

    #[test]
    fn duplicate_members_are_refused_before_deserialization() {
        let document = br#"{"@context":"https://registrystack.org/discovery/context/v1alpha1","@type":"dcat:Catalog","profile":"registry-discovery-v1alpha1","services":[],"services":[]}"#;
        assert!(matches!(
            parse_description(document),
            Err(ProfileError::StrictJson(_))
        ));
    }

    #[test]
    fn maximum_description_bytes_are_refused_before_parsing() {
        let oversized = vec![b'{'; MAX_DESCRIPTION_BYTES + 1];
        assert!(matches!(
            parse_description(&oversized),
            Err(ProfileError::DocumentTooLarge)
        ));
    }

    #[test]
    fn rendering_counts_the_trailing_lf_and_every_successful_render_parses() {
        let services = (0..MAX_SERVICES)
            .map(|index| {
                ServiceDescription::new(
                    format!("urn:example:service:evidence:{index:04}"),
                    ServiceKind::Evidence,
                    "Evidence".into(),
                    "x".into(),
                    "https://evidence.example.org".into(),
                    ServiceRoles::default(),
                    vec!["urn:example:jurisdiction".into()],
                    vec!["https://registrystack.org/evidence/profile/v1".into()],
                    vec!["urn:example:evidence-type".into()],
                    vec![],
                    vec![],
                )
                .expect("bounded service")
            })
            .collect();
        let mut document = DiscoveryDescription::new(services).expect("bounded document");
        let baseline =
            canonicalize_json(&serde_json::to_value(&document).expect("closed profile serializes"))
                .expect("closed profile canonicalizes")
                .len();
        let mut remaining = MAX_DESCRIPTION_BYTES - 1 - baseline;
        for service in &mut document.services {
            let available = MAX_STRING_CHARACTERS - service.description.chars().count();
            let added = remaining.min(available);
            service.description.push_str(&"x".repeat(added));
            remaining -= added;
            if remaining == 0 {
                break;
            }
        }
        assert_eq!(remaining, 0, "the bounded strings can reach the byte edge");

        let rendered = render_description(&document).expect("exact maximum renders");
        assert_eq!(rendered.len(), MAX_DESCRIPTION_BYTES);
        assert_eq!(
            parse_description(&rendered).expect("every successful render parses"),
            document
        );

        document
            .services
            .iter_mut()
            .find(|service| service.description.chars().count() < MAX_STRING_CHARACTERS)
            .expect("one service retains character capacity")
            .description
            .push('x');
        assert!(matches!(
            render_description(&document),
            Err(ProfileError::DocumentTooLarge)
        ));
    }

    #[test]
    fn multibyte_public_strings_use_the_json_schema_character_bound() {
        let mut description = evidence();
        description.services[0].title = "é".repeat(MAX_STRING_CHARACTERS);
        assert!(description.services[0].title.len() > MAX_STRING_CHARACTERS);
        description
            .validate()
            .expect("the character boundary is valid despite its larger UTF-8 byte length");

        description.services[0].title.push('é');
        assert!(matches!(
            description.validate(),
            Err(ProfileError::PublicField("title"))
        ));
    }

    #[test]
    fn endpoint_urls_use_typed_exact_loopback_hosts_and_reject_preparser_whitespace() {
        for accepted in [
            "https://evidence.example.org/catalog.jsonld",
            "http://localhost:8080/catalog.jsonld",
            "http://127.0.0.1:8080/catalog.jsonld",
            "http://[::1]:8080/catalog.jsonld",
        ] {
            assert!(is_valid_endpoint_url(accepted, true), "rejected {accepted}");
        }
        for refused in [
            "http://localhost:8080/catalog.jsonld",
            "http://127.0.0.1:8080/catalog.jsonld",
            "http://[::1]:8080/catalog.jsonld",
        ] {
            assert!(
                !is_valid_endpoint_url(refused, false),
                "loopback HTTP did not require explicit allowance: {refused}"
            );
        }
        for refused in [
            "http://127.0.0.2:8080/catalog.jsonld",
            "http://127.1:8080/catalog.jsonld",
            "http://LOCALHOST:8080/catalog.jsonld",
            "http://[::2]:8080/catalog.jsonld",
            " http://127.0.0.1:8080/catalog.jsonld",
            "http://127.0.0.1:8080/catalog.jsonld\n",
            "https://evidence.example.org/catalog .jsonld",
            "https://evidence.example.org/catalog\u{0007}.jsonld",
            "https://evidence.example.org/a//b",
        ] {
            assert!(
                !is_valid_endpoint_url(refused, true),
                "accepted non-exact or pre-parser-normalized URL: {refused:?}"
            );
        }
    }

    #[test]
    fn shipped_product_fixtures_satisfy_the_closed_rust_profile() {
        for fixture in [
            include_bytes!("../../../products/discovery/fixtures/descriptions/evidence.jsonld")
                .as_slice(),
            include_bytes!("../../../products/discovery/fixtures/descriptions/relay.jsonld")
                .as_slice(),
        ] {
            parse_description(fixture).expect("shipped fixture satisfies the closed profile");
        }
    }

    #[test]
    fn collections_must_be_canonical_and_service_kind_specific() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&render_description(&evidence()).expect("render"))
                .expect("json");
        value["services"][0]["evidenceTypeIds"] =
            serde_json::json!(["urn:example:z", "urn:example:a"]);
        assert!(matches!(
            parse_description(&serde_json::to_vec(&value).expect("render")),
            Err(ProfileError::IdentifierCollection("evidenceTypeIds"))
        ));
        value["services"][0]["evidenceTypeIds"] = serde_json::json!(["urn:example:a"]);
        value["services"][0]["semanticClassIds"] = serde_json::json!([]);
        assert!(matches!(
            parse_description(&serde_json::to_vec(&value).expect("render")),
            Err(ProfileError::KindCapabilities)
        ));
    }
}
