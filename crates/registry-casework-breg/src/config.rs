// SPDX-License-Identifier: Apache-2.0
//! Closed operator binding and offline construction of the BReg adapter.

use crate::{
    valid_source_identifier, BregAdapter, BregRequestConfig, BregSourceConfig,
    MAXIMUM_REQUEST_ENTITIES,
};
use registry_breg_client::{
    decode_exact_json, BaseRegistryClient, BaseRegistryClientConfig, PrivateKeyJwt,
    PrivateKeyJwtConfig,
};
use registry_casework_core::{
    RoutingFieldDescriptor, RoutingSourceMetadata, SourceAdapterError, SourcePolicy,
    SourceRequestPolicy,
};
use registry_platform_config::{sha256_uri, SecretReference, SecretResolver};
use registry_platform_crypto::PrivateJwk;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
    sync::Arc,
    time::Duration,
};
use url::Url;

/// A description of one request entity, carried as `request`.
const DESCRIPTION_API_VERSION: &str =
    "registry.registrystack.org/casework-source-description/v1alpha1";
/// A description of every paired request entity, carried as `requests`.
const DESCRIPTION_API_VERSION_REQUESTS: &str =
    "registry.registrystack.org/casework-source-description/v1alpha2";
const DESCRIPTION_KIND: &str = "BRegCaseworkSourceDescription";
const DESCRIPTION_ORIGIN: &str = "bregctl explain change-requests";
const DEFAULT_REQUEST_TIMEOUT_MILLISECONDS: u64 = 30_000;
const DEFAULT_CONNECT_TIMEOUT_MILLISECONDS: u64 = 10_000;
const MAXIMUM_TIMEOUT_MILLISECONDS: u64 = 300_000;
const DEFAULT_RECONCILIATION_INTERVAL_MILLISECONDS: u64 = 60_000;
const MINIMUM_RECONCILIATION_INTERVAL_MILLISECONDS: u64 = 1_000;
const MAXIMUM_RECONCILIATION_INTERVAL_MILLISECONDS: u64 = 3_600_000;
const MAXIMUM_DESCRIPTION_BYTES: usize = 8 * 1024 * 1024;

/// Each policy request's imported entry, in policy order, and the registry
/// revision the description was exported from.
type ValidatedDescription = (Vec<BregRequestConfig>, String);

/// Launcher-owned BReg connection material for one authored Casework source.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BregBinding {
    #[serde(deserialize_with = "registry_casework_core::typed::url")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub base_url: String,
    pub reader_profile: String,
    pub token_endpoint: String,
    /// Explicit OAuth client assertion audience; omission preserves endpoint audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_assertion_audience: Option<String>,
    /// Exact resource indicator required by the configured authorization server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Explicit scopes for this source reader's service credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(deserialize_with = "secret_reference")]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub client_id_ref: String,
    #[serde(deserialize_with = "secret_reference")]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub client_assertion_key_ref: String,
    #[serde(deserialize_with = "secret_reference")]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub webhook_secret_ref: String,
    pub event_source: String,
    #[serde(
        default,
        deserialize_with = "optional_secret_reference",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<SecretReference>"))]
    pub trusted_root_certificates_ref: Option<String>,
    #[serde(
        default = "default_request_timeout",
        deserialize_with = "registry_casework_core::typed::bounded_u64::<_, 1, MAXIMUM_TIMEOUT_MILLISECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = MAXIMUM_TIMEOUT_MILLISECONDS))
    )]
    pub request_timeout_milliseconds: u64,
    #[serde(
        default = "default_connect_timeout",
        deserialize_with = "registry_casework_core::typed::bounded_u64::<_, 1, MAXIMUM_TIMEOUT_MILLISECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = MAXIMUM_TIMEOUT_MILLISECONDS))
    )]
    pub connect_timeout_milliseconds: u64,
    #[serde(
        default = "default_reconciliation_interval",
        deserialize_with = "registry_casework_core::typed::bounded_u64::<_, MINIMUM_RECONCILIATION_INTERVAL_MILLISECONDS, MAXIMUM_RECONCILIATION_INTERVAL_MILLISECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(
            min = MINIMUM_RECONCILIATION_INTERVAL_MILLISECONDS,
            max = MAXIMUM_RECONCILIATION_INTERVAL_MILLISECONDS
        ))
    )]
    pub reconciliation_interval_milliseconds: u64,
}

/// A secret reference, `secret:env/NAME` or `secret:file/name`, kept as
/// written. The reader refuses any other spelling at its position without
/// repeating it.
fn secret_reference<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    SecretReference::deserialize(deserializer).map(|reference| reference.as_str().to_owned())
}

/// An optional member holding a secret reference; absent reads as `None`
/// through `serde(default)`.
fn optional_secret_reference<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    secret_reference(deserializer).map(Some)
}

impl fmt::Debug for BregBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BregBinding")
            .field("base_url", &"[REDACTED]")
            .field("reader_profile", &self.reader_profile)
            .field("token_endpoint", &"[REDACTED]")
            .field("client_assertion_audience", &"[REDACTED]")
            .field("resource", &"[REDACTED]")
            .field("scopes", &"[REDACTED]")
            .field("client_id_ref", &"[REDACTED]")
            .field("client_assertion_key_ref", &"[REDACTED]")
            .field("webhook_secret_ref", &"[REDACTED]")
            .field("event_source", &self.event_source)
            .finish_non_exhaustive()
    }
}

impl BregBinding {
    /// Build without contacting BReg or its authorization server.
    pub fn build_adapter(
        &self,
        source: &SourcePolicy,
        project_root: &Path,
        secrets: &SecretResolver,
    ) -> Result<BregAdapter, SourceAdapterError> {
        build_adapter(self, source, project_root, secrets)
    }

    /// Build from source-description bytes captured by the runtime's verified
    /// package load.
    pub fn build_adapter_from_description(
        &self,
        source: &SourcePolicy,
        description: &[u8],
        secrets: &SecretResolver,
    ) -> Result<BregAdapter, SourceAdapterError> {
        build_adapter_from_description(self, source, description, secrets)
    }
}

/// Validate one authored description and construct its pooled BReg client.
pub fn build_adapter(
    binding: &BregBinding,
    source: &SourcePolicy,
    project_root: &Path,
    secrets: &SecretResolver,
) -> Result<BregAdapter, SourceAdapterError> {
    let description = read_description(project_root, &source.description)?;
    build_adapter_from_description(binding, source, &description, secrets)
}

/// Validate captured source-description bytes and construct its pooled BReg client.
pub fn build_adapter_from_description(
    binding: &BregBinding,
    source: &SourcePolicy,
    description: &[u8],
    secrets: &SecretResolver,
) -> Result<BregAdapter, SourceAdapterError> {
    validate_binding(binding)?;
    if source.adapter != "breg"
        || source.requests.is_empty()
        || source.requests.len() > MAXIMUM_REQUEST_ENTITIES
    {
        return Err(SourceAdapterError::Invalid);
    }
    if description.is_empty() || description.len() > MAXIMUM_DESCRIPTION_BYTES {
        return Err(SourceAdapterError::Invalid);
    }
    let (requests, expected_registry_revision) = validate_description(source, description)?;

    let client_id_secret = resolve_secret(secrets, &binding.client_id_ref)?;
    let client_id = std::str::from_utf8(client_id_secret.expose_secret())
        .ok()
        .filter(|value| valid_scalar(value, 512))
        .ok_or(SourceAdapterError::Invalid)?
        .to_owned();
    let key_secret = resolve_secret(secrets, &binding.client_assertion_key_ref)?;
    let key_json =
        std::str::from_utf8(key_secret.expose_secret()).map_err(|_| SourceAdapterError::Invalid)?;
    let key = PrivateJwk::parse(key_json).map_err(|_| SourceAdapterError::Invalid)?;
    let webhook_secret = resolve_secret(secrets, &binding.webhook_secret_ref)?;
    let trust = binding
        .trusted_root_certificates_ref
        .as_deref()
        .map(|reference| resolve_secret(secrets, reference))
        .transpose()?;
    let generation = binding_generation(binding, source, description)?;

    let request_timeout = Duration::from_millis(binding.request_timeout_milliseconds);
    let connect_timeout = Duration::from_millis(binding.connect_timeout_milliseconds);
    let mut token_config = source_token_config(binding, &client_id, key)?;
    if let Some(trust) = &trust {
        token_config = token_config.with_trusted_root_certificates(trust.expose_secret().to_vec());
    }
    let token_provider =
        PrivateKeyJwt::new(token_config).map_err(|_| SourceAdapterError::Invalid)?;
    let mut client_config = BaseRegistryClientConfig::new(parse_url(&binding.base_url)?)
        .with_token_provider(Arc::new(token_provider))
        .with_request_timeout(request_timeout)
        .with_connect_timeout(connect_timeout);
    if let Some(trust) = &trust {
        client_config =
            client_config.with_trusted_root_certificates(trust.expose_secret().to_vec());
    }
    let reader = BaseRegistryClient::new(client_config).map_err(|_| SourceAdapterError::Invalid)?;
    BregAdapter::new(
        BregSourceConfig {
            source_id: source.id.clone(),
            requests,
            expected_registry_revision,
            binding_generation: generation,
            reader_profile: binding.reader_profile.clone(),
            event_source: binding.event_source.clone(),
        },
        reader,
        webhook_secret.expose_secret().to_vec(),
    )
}

fn source_token_config(
    binding: &BregBinding,
    client_id: &str,
    key: PrivateJwk,
) -> Result<PrivateKeyJwtConfig, SourceAdapterError> {
    validate_binding(binding)?;
    let mut config = PrivateKeyJwtConfig::new(parse_url(&binding.token_endpoint)?, client_id, key)
        .with_request_timeout(Duration::from_millis(binding.request_timeout_milliseconds))
        .with_connect_timeout(Duration::from_millis(binding.connect_timeout_milliseconds));
    if let Some(audience) = &binding.client_assertion_audience {
        config = config.with_audience(audience);
    }
    if let Some(resource) = &binding.resource {
        config = config.with_resource(resource);
    }
    if let Some(scopes) = &binding.scopes {
        config = config.with_scopes(scopes.clone());
    }
    Ok(config)
}

fn validate_binding(binding: &BregBinding) -> Result<(), SourceAdapterError> {
    validate_binding_rules(binding).map_err(|_| SourceAdapterError::Invalid)
}

/// One rule an authored BReg binding must satisfy.
///
/// A rule carries no configured value: [`BindingRule::field`] names the
/// binding member it constrains and [`BindingRule::reason`] states the rule
/// and its bound, so a refusal names what to change without echoing what was
/// written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BindingRule {
    /// `readerProfile` is empty, too long, or not a bare scalar.
    ReaderProfile,
    /// `requestTimeoutMilliseconds` is zero.
    RequestTimeoutZero,
    /// `connectTimeoutMilliseconds` is zero.
    ConnectTimeoutZero,
    /// `requestTimeoutMilliseconds` exceeds the adapter's maximum.
    RequestTimeoutAboveMaximum,
    /// `connectTimeoutMilliseconds` exceeds `requestTimeoutMilliseconds`.
    ConnectTimeoutAboveRequestTimeout,
    /// `reconciliationIntervalMilliseconds` falls outside its range.
    ReconciliationIntervalOutOfRange,
    /// `eventSource` is not a Registry Stack registry instance URN.
    EventSource,
    /// `clientAssertionAudience` is not a bounded absolute URI.
    ClientAssertionAudience,
    /// `resource` is not a bounded absolute URI.
    Resource,
    /// `scopes` is present but lists no scope.
    ScopesEmpty,
    /// `scopes` lists more scopes than the token client sends.
    TooManyScopes,
    /// `scopes` lists one scope more than once.
    RepeatedScope,
    /// One of `scopes` is longer than the token client sends.
    ScopeTooLong,
    /// One of `scopes` is not an RFC 6749 scope-token.
    ScopeNotAToken,
}

impl BindingRule {
    /// The binding member this rule constrains, as its authored camelCase key.
    #[must_use]
    pub const fn field(self) -> &'static str {
        match self {
            Self::ReaderProfile => "readerProfile",
            Self::RequestTimeoutZero
            | Self::RequestTimeoutAboveMaximum
            | Self::ConnectTimeoutAboveRequestTimeout => "requestTimeoutMilliseconds",
            Self::ConnectTimeoutZero => "connectTimeoutMilliseconds",
            Self::ReconciliationIntervalOutOfRange => "reconciliationIntervalMilliseconds",
            Self::EventSource => "eventSource",
            Self::ClientAssertionAudience => "clientAssertionAudience",
            Self::Resource => "resource",
            Self::ScopesEmpty
            | Self::TooManyScopes
            | Self::RepeatedScope
            | Self::ScopeTooLong
            | Self::ScopeNotAToken => "scopes",
        }
    }

    /// The rule and its bound, stated without the configured value.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        // Bounds are spelled out because a static reason cannot format a
        // constant; `binding_rule_reasons_state_the_enforced_bounds` holds
        // each literal to the constant the check enforces.
        match self {
            Self::ReaderProfile => {
                "readerProfile must be 1 to 512 bytes with no control characters or surrounding whitespace"
            }
            Self::RequestTimeoutZero => "requestTimeoutMilliseconds must be greater than zero",
            Self::ConnectTimeoutZero => "connectTimeoutMilliseconds must be greater than zero",
            Self::RequestTimeoutAboveMaximum => "requestTimeoutMilliseconds must be at most 300000",
            Self::ConnectTimeoutAboveRequestTimeout => {
                "requestTimeoutMilliseconds must be at least connectTimeoutMilliseconds"
            }
            Self::ReconciliationIntervalOutOfRange => {
                "reconciliationIntervalMilliseconds must be between 1000 and 3600000"
            }
            Self::EventSource => {
                "eventSource must have the form urn:registrystack:registry:<package>:instance:<instance>, each segment 1 to 128 ASCII letters, digits, '.', '_', or '-'"
            }
            Self::ClientAssertionAudience => {
                "clientAssertionAudience must be an absolute URI of at most 4096 bytes, written in URI characters with complete percent escapes and no fragment or user information"
            }
            Self::Resource => {
                "resource must be an absolute URI of at most 4096 bytes, written in URI characters with complete percent escapes and no fragment or user information"
            }
            Self::ScopesEmpty => "scopes must list at least one scope when present",
            Self::TooManyScopes => "scopes must list at most 32 scopes",
            Self::RepeatedScope => "scopes must not repeat a scope",
            Self::ScopeTooLong => "each entry of scopes must be at most 256 bytes",
            Self::ScopeNotAToken => "each entry of scopes must be one RFC 6749 scope-token",
        }
    }
}

/// Check one binding against every [`BindingRule`], in a fixed order, and
/// return the first rule it breaks.
fn validate_binding_rules(binding: &BregBinding) -> Result<(), BindingRule> {
    use registry_platform_httputil::{
        valid_resource_uri, valid_scope_token, MAXIMUM_REQUESTED_SCOPES,
        MAXIMUM_REQUESTED_SCOPE_BYTES,
    };
    let request = binding.request_timeout_milliseconds;
    let connect = binding.connect_timeout_milliseconds;
    let interval = binding.reconciliation_interval_milliseconds;
    let checks = [
        (
            valid_scalar(&binding.reader_profile, 512),
            BindingRule::ReaderProfile,
        ),
        (request != 0, BindingRule::RequestTimeoutZero),
        (connect != 0, BindingRule::ConnectTimeoutZero),
        (
            request <= MAXIMUM_TIMEOUT_MILLISECONDS,
            BindingRule::RequestTimeoutAboveMaximum,
        ),
        (
            connect <= request,
            BindingRule::ConnectTimeoutAboveRequestTimeout,
        ),
        (
            (MINIMUM_RECONCILIATION_INTERVAL_MILLISECONDS
                ..=MAXIMUM_RECONCILIATION_INTERVAL_MILLISECONDS)
                .contains(&interval),
            BindingRule::ReconciliationIntervalOutOfRange,
        ),
        (
            valid_event_source(&binding.event_source),
            BindingRule::EventSource,
        ),
        (
            binding
                .client_assertion_audience
                .as_deref()
                .is_none_or(valid_resource_uri),
            BindingRule::ClientAssertionAudience,
        ),
        (
            binding.resource.as_deref().is_none_or(valid_resource_uri),
            BindingRule::Resource,
        ),
    ];
    if let Some((_, rule)) = checks.into_iter().find(|(holds, _)| !holds) {
        return Err(rule);
    }
    let Some(scopes) = &binding.scopes else {
        return Ok(());
    };
    if scopes.is_empty() {
        return Err(BindingRule::ScopesEmpty);
    }
    if scopes.len() > MAXIMUM_REQUESTED_SCOPES {
        return Err(BindingRule::TooManyScopes);
    }
    if scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len() {
        return Err(BindingRule::RepeatedScope);
    }
    if scopes
        .iter()
        .any(|scope| scope.len() > MAXIMUM_REQUESTED_SCOPE_BYTES)
    {
        return Err(BindingRule::ScopeTooLong);
    }
    if !scopes.iter().all(|scope| valid_scope_token(scope)) {
        return Err(BindingRule::ScopeNotAToken);
    }
    Ok(())
}

/// Validate one authored binding's scalar and bound fields with the same
/// rules `build_adapter` applies, without resolving secrets or connecting to
/// BReg. A runtime loads its configuration long before it builds adapters, so
/// an out-of-range binding is refused at load time through this entry point,
/// naming the first [`BindingRule`] it breaks.
pub fn validate_binding_input(binding: &BregBinding) -> Result<(), BindingRule> {
    validate_binding_rules(binding)
}

fn valid_scalar(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn valid_event_source(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("urn:registrystack:registry:") else {
        return false;
    };
    let Some((package, instance)) = rest.split_once(":instance:") else {
        return false;
    };
    valid_urn_segment(package) && valid_urn_segment(instance)
}

fn valid_urn_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn resolve_secret(
    resolver: &SecretResolver,
    reference: &str,
) -> Result<registry_platform_config::ProtectedSecret, SourceAdapterError> {
    resolver
        .resolve(reference)
        .map_err(|_| SourceAdapterError::Invalid)
}

fn parse_url(value: &str) -> Result<Url, SourceAdapterError> {
    value.parse().map_err(|_| SourceAdapterError::Invalid)
}

fn read_description(project_root: &Path, relative: &str) -> Result<Vec<u8>, SourceAdapterError> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(SourceAdapterError::Invalid);
    }
    let bytes = fs::read(project_root.join(path)).map_err(|_| SourceAdapterError::Invalid)?;
    if bytes.is_empty() || bytes.len() > MAXIMUM_DESCRIPTION_BYTES {
        return Err(SourceAdapterError::Invalid);
    }
    Ok(bytes)
}

fn validate_description(
    source: &SourcePolicy,
    bytes: &[u8],
) -> Result<ValidatedDescription, DescriptionRefusal> {
    let root = decode_exact_json(bytes).map_err(|_| SourceAdapterError::Invalid)?;
    let object = root.as_object().ok_or(SourceAdapterError::Invalid)?;
    let requests_key = match root["apiVersion"].as_str() {
        Some(DESCRIPTION_API_VERSION) => "request",
        Some(DESCRIPTION_API_VERSION_REQUESTS) => "requests",
        _ => return Err(DescriptionRefusal::ContractMismatch),
    };
    let expected = [
        "apiVersion",
        "authority",
        "kind",
        "origin",
        requests_key,
        "sourceId",
        "sourceRevision",
    ];
    if object.len() != expected.len()
        || expected.iter().any(|key| !object.contains_key(*key))
        || root["kind"] != DESCRIPTION_KIND
        || root["authority"] != "none"
        || root["origin"] != DESCRIPTION_ORIGIN
        || !valid_source_identifier(&source.id)
        || root["sourceId"] != source.id
        || !root["sourceRevision"]
            .as_str()
            .is_some_and(|value| valid_scalar(value, 512))
    {
        return Err(DescriptionRefusal::ContractMismatch);
    }
    let expected_registry_revision = root["sourceRevision"]
        .as_str()
        .ok_or(SourceAdapterError::Invalid)?
        .to_owned();
    let described = match &root[requests_key] {
        Value::Object(request) if requests_key == "request" => vec![request],
        Value::Array(requests) if requests_key == "requests" => requests
            .iter()
            .map(|request| request.as_object().ok_or(SourceAdapterError::Invalid))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(DescriptionRefusal::ContractMismatch),
    };
    // The description and the policy pair exactly the same request entities:
    // an undeclared description entry is as much drift as a missing one.
    if described.len() != source.requests.len() {
        return Err(DescriptionRefusal::ContractMismatch);
    }
    let mut by_entity = BTreeMap::new();
    for request in described {
        let entity = string_field(request, "requestEntity")?;
        if by_entity.insert(entity, request).is_some() {
            return Err(DescriptionRefusal::ContractMismatch);
        }
    }
    // Every paired entry is held to the closed contract before any policy
    // field is resolved against it, so a description that drifted is always
    // reported as drift, never as a field the policy names.
    let described = source
        .requests
        .iter()
        .map(|policy| {
            let request = by_entity
                .get(policy.entity.as_str())
                .ok_or(SourceAdapterError::Invalid)?;
            validate_description_request(request)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let requests = source
        .requests
        .iter()
        .zip(described)
        .enumerate()
        .map(|(index, (policy, described))| resolve_policy_fields(index, policy, described))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((requests, expected_registry_revision))
}

fn validate_description_request(
    request: &serde_json::Map<String, Value>,
) -> Result<DescribedRequest, SourceAdapterError> {
    let entity = string_field(request, "requestEntity")?;
    let route = string_field(request, "requestRoute")?;
    string_field(request, "contractFingerprint")?;
    validate_review_requirement(request.get("review").ok_or(SourceAdapterError::Invalid)?)?;
    validate_on_approved(
        request
            .get("onApproved")
            .ok_or(SourceAdapterError::Invalid)?,
    )?;
    request
        .get("application")
        .and_then(Value::as_object)
        .ok_or(SourceAdapterError::Invalid)?;
    Ok(DescribedRequest {
        entity: entity.to_owned(),
        route: route.to_owned(),
        fields: published_fields(request)?,
    })
}

/// One paired description entry that already meets the closed contract,
/// before the policy's field names are resolved against it.
struct DescribedRequest {
    entity: String,
    route: String,
    fields: BTreeMap<String, RoutingFieldDescriptor>,
}

/// Resolve every field the policy's request `index` names against the
/// fields its paired description entry publishes.
fn resolve_policy_fields(
    index: usize,
    policy: &SourceRequestPolicy,
    described: DescribedRequest,
) -> Result<BregRequestConfig, DescriptionRefusal> {
    let published = |field: &String, path: String| {
        described.fields.get(field).cloned().ok_or_else(|| {
            DescriptionRefusal::UnpublishedPolicyField {
                path: format!("/requests/{index}{path}"),
                field: field.clone(),
            }
        })
    };
    let fields = policy
        .projection
        .iter()
        .enumerate()
        .map(|(position, field)| published(field, format!("/projection/{position}")))
        .collect::<Result<Vec<_>, _>>()?;
    let context_projection = policy
        .context_projection
        .iter()
        .enumerate()
        .map(|(position, field)| published(field, format!("/contextProjection/{position}")))
        .collect::<Result<Vec<_>, _>>()?;
    let display_reference = policy
        .display_reference
        .as_ref()
        .map(|configured| {
            let descriptor = published(&configured.field, "/displayReference/field".to_owned())?;
            let schema = descriptor
                .schema
                .as_object()
                .ok_or(DescriptionRefusal::ContractMismatch)?;
            if schema.get("type").and_then(Value::as_str) != Some("string") {
                return Err(DescriptionRefusal::ContractMismatch);
            }
            Ok(descriptor)
        })
        .transpose()?;
    Ok(BregRequestConfig {
        entity: described.entity,
        route: described.route,
        routing_metadata: RoutingSourceMetadata {
            stages: Vec::new(),
            fields,
        },
        context_projection,
        display_reference,
    })
}

/// Why an imported source description was refused for one source policy.
///
/// Neither variant carries a description value: a field name is authored
/// policy configuration, and a key path names where the policy wrote it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DescriptionRefusal {
    /// The description meets the closed adapter contract, but the policy
    /// names a field the description does not publish for that request. The
    /// `path` is a JSON Pointer relative to the source policy entry, as
    /// `/requests/<index>/contextProjection/<index>`,
    /// `/requests/<index>/projection/<index>`, or
    /// `/requests/<index>/displayReference/field`.
    UnpublishedPolicyField { path: String, field: String },
    /// The description is not exactly the closed BReg adapter contract for
    /// this source: malformed, drifted, or paired with other request
    /// entities.
    ContractMismatch,
}

impl From<SourceAdapterError> for DescriptionRefusal {
    fn from(_: SourceAdapterError) -> Self {
        Self::ContractMismatch
    }
}

impl From<DescriptionRefusal> for SourceAdapterError {
    fn from(_: DescriptionRefusal) -> Self {
        Self::Invalid
    }
}

/// Validate an imported description with the same strict decoder used by
/// adapter construction, without loading operator bindings or secrets.
///
/// Returns each request entity's routing metadata, keyed by entity.
pub fn validate_description_input(
    source: &SourcePolicy,
    bytes: &[u8],
) -> Result<BTreeMap<String, RoutingSourceMetadata>, SourceAdapterError> {
    check_description_input(source, bytes).map_err(SourceAdapterError::from)
}

/// Validate an imported description as [`validate_description_input`] does,
/// distinguishing a policy that names a field the description does not
/// publish from a description that does not meet the adapter contract.
pub fn check_description_input(
    source: &SourcePolicy,
    bytes: &[u8],
) -> Result<BTreeMap<String, RoutingSourceMetadata>, DescriptionRefusal> {
    let (requests, _) = validate_description(source, bytes)?;
    Ok(requests
        .into_iter()
        .map(|request| (request.entity, request.routing_metadata))
        .collect())
}

fn validate_review_requirement(value: &Value) -> Result<(), SourceAdapterError> {
    let review = value.as_object().ok_or(SourceAdapterError::Invalid)?;
    match review.get("mode").and_then(Value::as_str) {
        Some("none") if review.len() == 1 => Ok(()),
        None if review.len() == 2 => {
            string_field(review, "authority")?;
            string_field(review, "policyId")?;
            Ok(())
        }
        _ => Err(SourceAdapterError::Invalid),
    }
}

fn validate_on_approved(value: &Value) -> Result<(), SourceAdapterError> {
    let on_approved = value.as_object().ok_or(SourceAdapterError::Invalid)?;
    match on_approved.get("mode").and_then(Value::as_str) {
        Some("manual") if on_approved.len() == 1 => Ok(()),
        Some("automatic") if on_approved.len() == 2 => {
            string_field(on_approved, "executor")?;
            Ok(())
        }
        _ => Err(SourceAdapterError::Invalid),
    }
}

/// Read one paired entry's published fields, keyed by logical field name.
fn published_fields(
    request: &serde_json::Map<String, Value>,
) -> Result<BTreeMap<String, RoutingFieldDescriptor>, SourceAdapterError> {
    let fields = request
        .get("fields")
        .and_then(Value::as_array)
        .ok_or(SourceAdapterError::Invalid)?;
    let mut by_logical_name = BTreeMap::new();
    let mut api_names = BTreeSet::new();
    for field in fields {
        let field = field.as_object().ok_or(SourceAdapterError::Invalid)?;
        if field.len() != 3
            || !["field", "apiName", "schema"]
                .iter()
                .all(|key| field.contains_key(*key))
        {
            return Err(SourceAdapterError::Invalid);
        }
        let logical_name = string_field(field, "field")?;
        let api_name = string_field(field, "apiName")?;
        if !api_names.insert(api_name) {
            return Err(SourceAdapterError::Invalid);
        }
        let descriptor = RoutingFieldDescriptor {
            field: logical_name.to_owned(),
            api_name: api_name.to_owned(),
            schema: field
                .get("schema")
                .cloned()
                .ok_or(SourceAdapterError::Invalid)?,
        };
        if by_logical_name
            .insert(logical_name.to_owned(), descriptor)
            .is_some()
        {
            return Err(SourceAdapterError::Invalid);
        }
    }
    Ok(by_logical_name)
}

fn string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, SourceAdapterError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| valid_scalar(value, 512))
        .ok_or(SourceAdapterError::Invalid)
}

/// The binding generation names what the source means, not how Casework
/// reaches it: the source id, the BReg instance that emits its events, and the
/// imported source description. Work observed under one generation is
/// superseded when the generation changes, so credential rotation, transport
/// tuning, and presentation settings stay outside it.
fn binding_generation(
    binding: &BregBinding,
    source: &SourcePolicy,
    description: &[u8],
) -> Result<String, SourceAdapterError> {
    let identity = serde_json::to_vec(&json!({
        "sourceId": source.id,
        "eventSource": binding.event_source,
        "descriptionSha256": sha256_uri(description),
    }))
    .map_err(|_| SourceAdapterError::Invalid)?;
    Ok(sha256_uri(&identity))
}

const fn default_request_timeout() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_MILLISECONDS
}
const fn default_connect_timeout() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_MILLISECONDS
}
const fn default_reconciliation_interval() -> u64 {
    DEFAULT_RECONCILIATION_INTERVAL_MILLISECONDS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SourcePolicy {
        serde_json::from_value(json!({
            "id":"professional-register", "adapter":"breg",
            "description":"sources/professional-register.json",
            "requests":[{"entity":"correction","queue":"review"}]
        }))
        .unwrap()
    }

    fn description(entity: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "apiVersion":DESCRIPTION_API_VERSION, "kind":DESCRIPTION_KIND,
            "sourceId":"professional-register", "authority":"none",
            "origin":DESCRIPTION_ORIGIN, "sourceRevision":"sha256:source",
            "request":{"requestEntity":entity,"requestRoute":"corrections",
                "contractFingerprint":"sha256:contract",
                "fields":[{"field":"region","apiName":"serviceRegion",
                    "schema":{"type":"string","enum":["north","south"]}}],
                "review":{"authority":"casework-main","policyId":"registry-correction"},
                "onApproved":{"mode":"manual"},"application":{}}
        }))
        .unwrap()
    }

    fn binding() -> BregBinding {
        BregBinding {
            base_url: "https://registry.example".into(),
            reader_profile: "casework-reader".into(),
            token_endpoint: "https://issuer.example/token".into(),
            client_assertion_audience: None,
            resource: None,
            scopes: None,
            client_id_ref: "secret:file/client-id".into(),
            client_assertion_key_ref: "secret:file/client-key.jwk".into(),
            webhook_secret_ref: "secret:file/webhook".into(),
            event_source: "urn:registrystack:registry:package:instance:pilot".into(),
            trusted_root_certificates_ref: None,
            request_timeout_milliseconds: 30_000,
            connect_timeout_milliseconds: 10_000,
            reconciliation_interval_milliseconds: DEFAULT_RECONCILIATION_INTERVAL_MILLISECONDS,
        }
    }

    fn minimal_binding_json() -> Value {
        json!({
            "baseUrl": "https://registry.example",
            "readerProfile": "casework-reader",
            "tokenEndpoint": "https://issuer.example/token",
            "clientIdRef": "secret:file/client-id",
            "clientAssertionKeyRef": "secret:file/client-key.jwk",
            "webhookSecretRef": "secret:file/webhook",
            "eventSource": "urn:registrystack:registry:package:instance:pilot"
        })
    }

    #[test]
    fn reconciliation_interval_defaults_when_absent() {
        let binding: BregBinding = serde_json::from_value(minimal_binding_json()).unwrap();
        assert_eq!(
            binding.reconciliation_interval_milliseconds,
            DEFAULT_RECONCILIATION_INTERVAL_MILLISECONDS
        );
    }

    /// The lifecycle event type is derived from each paired request entity,
    /// so a binding that still names one is refused rather than ignored.
    #[test]
    fn a_binding_that_names_an_event_type_is_refused() {
        let mut value = minimal_binding_json();
        value["eventType"] = json!("casework-lifecycle-v1");
        assert!(serde_json::from_value::<BregBinding>(value).is_err());
    }

    #[test]
    fn reconciliation_interval_parses_an_explicit_value() {
        let mut value = minimal_binding_json();
        value["reconciliationIntervalMilliseconds"] = json!(120_000);
        let binding: BregBinding = serde_json::from_value(value).unwrap();
        assert_eq!(binding.reconciliation_interval_milliseconds, 120_000);
    }

    #[test]
    fn reconciliation_interval_bounds_are_enforced() {
        for accepted in [
            MINIMUM_RECONCILIATION_INTERVAL_MILLISECONDS,
            DEFAULT_RECONCILIATION_INTERVAL_MILLISECONDS,
            MAXIMUM_RECONCILIATION_INTERVAL_MILLISECONDS,
        ] {
            let mut candidate = binding();
            candidate.reconciliation_interval_milliseconds = accepted;
            assert!(validate_binding(&candidate).is_ok());
        }
        for refused in [
            0,
            MINIMUM_RECONCILIATION_INTERVAL_MILLISECONDS - 1,
            MAXIMUM_RECONCILIATION_INTERVAL_MILLISECONDS + 1,
        ] {
            let mut candidate = binding();
            candidate.reconciliation_interval_milliseconds = refused;
            assert!(validate_binding(&candidate).is_err());
        }
    }

    #[test]
    fn each_binding_rule_is_reported_on_its_own() {
        let scopes = |values: Vec<String>| BregBinding {
            scopes: Some(values),
            ..binding()
        };
        let cases = [
            (
                BindingRule::ReaderProfile,
                BregBinding {
                    reader_profile: String::new(),
                    ..binding()
                },
            ),
            (
                BindingRule::ReaderProfile,
                BregBinding {
                    reader_profile: "r".repeat(513),
                    ..binding()
                },
            ),
            (
                BindingRule::ReaderProfile,
                BregBinding {
                    reader_profile: "casework-reader ".into(),
                    ..binding()
                },
            ),
            (
                BindingRule::RequestTimeoutZero,
                BregBinding {
                    request_timeout_milliseconds: 0,
                    ..binding()
                },
            ),
            (
                BindingRule::ConnectTimeoutZero,
                BregBinding {
                    connect_timeout_milliseconds: 0,
                    ..binding()
                },
            ),
            (
                BindingRule::RequestTimeoutAboveMaximum,
                BregBinding {
                    request_timeout_milliseconds: MAXIMUM_TIMEOUT_MILLISECONDS + 1,
                    ..binding()
                },
            ),
            (
                BindingRule::ConnectTimeoutAboveRequestTimeout,
                BregBinding {
                    request_timeout_milliseconds: 9_000,
                    ..binding()
                },
            ),
            (
                BindingRule::ReconciliationIntervalOutOfRange,
                BregBinding {
                    reconciliation_interval_milliseconds:
                        MINIMUM_RECONCILIATION_INTERVAL_MILLISECONDS - 1,
                    ..binding()
                },
            ),
            (
                BindingRule::ReconciliationIntervalOutOfRange,
                BregBinding {
                    reconciliation_interval_milliseconds:
                        MAXIMUM_RECONCILIATION_INTERVAL_MILLISECONDS + 1,
                    ..binding()
                },
            ),
            (
                BindingRule::EventSource,
                BregBinding {
                    event_source: "urn:registrystack:registry:package:pilot".into(),
                    ..binding()
                },
            ),
            (
                BindingRule::EventSource,
                BregBinding {
                    event_source: format!(
                        "urn:registrystack:registry:{}:instance:pilot",
                        "p".repeat(129)
                    ),
                    ..binding()
                },
            ),
            (
                BindingRule::ClientAssertionAudience,
                BregBinding {
                    client_assertion_audience: Some("https://issuer.example/#aud".into()),
                    ..binding()
                },
            ),
            (
                BindingRule::Resource,
                BregBinding {
                    resource: Some(" urn:breg:example".into()),
                    ..binding()
                },
            ),
            (BindingRule::ScopesEmpty, scopes(vec![])),
            (
                BindingRule::TooManyScopes,
                scopes(
                    (0..=registry_platform_httputil::MAXIMUM_REQUESTED_SCOPES)
                        .map(|index| format!("scope-{index}"))
                        .collect(),
                ),
            ),
            (
                BindingRule::RepeatedScope,
                scopes(vec!["casework:read".into(), "casework:read".into()]),
            ),
            (
                BindingRule::ScopeTooLong,
                scopes(vec!["s".repeat(
                    registry_platform_httputil::MAXIMUM_REQUESTED_SCOPE_BYTES + 1,
                )]),
            ),
            (
                BindingRule::ScopeNotAToken,
                scopes(vec!["casework read".into()]),
            ),
            (BindingRule::ScopeNotAToken, scopes(vec![String::new()])),
        ];
        for (rule, candidate) in &cases {
            assert_eq!(validate_binding_input(candidate), Err(*rule), "{rule:?}");
            assert!(validate_binding(candidate).is_err(), "{rule:?}");
            assert!(
                rule.reason().starts_with(rule.field())
                    || rule.reason().starts_with("each entry of scopes"),
                "{rule:?} reason does not lead with its member"
            );
        }
        assert_eq!(validate_binding_input(&binding()), Ok(()));
    }

    #[test]
    fn binding_rule_reasons_state_the_enforced_bounds() {
        let states = |rule: BindingRule, bound: String| {
            assert!(
                rule.reason().contains(&bound),
                "{rule:?} reason does not state {bound}"
            );
        };
        states(
            BindingRule::RequestTimeoutAboveMaximum,
            MAXIMUM_TIMEOUT_MILLISECONDS.to_string(),
        );
        states(
            BindingRule::ReconciliationIntervalOutOfRange,
            format!(
                "between {MINIMUM_RECONCILIATION_INTERVAL_MILLISECONDS} and {MAXIMUM_RECONCILIATION_INTERVAL_MILLISECONDS}"
            ),
        );
        states(
            BindingRule::TooManyScopes,
            format!(
                "at most {} scopes",
                registry_platform_httputil::MAXIMUM_REQUESTED_SCOPES
            ),
        );
        states(
            BindingRule::ScopeTooLong,
            format!(
                "at most {} bytes",
                registry_platform_httputil::MAXIMUM_REQUESTED_SCOPE_BYTES
            ),
        );
    }

    #[test]
    fn validate_binding_input_agrees_with_validate_binding() {
        let mut candidate = binding();
        assert!(validate_binding_input(&candidate).is_ok());
        candidate.reconciliation_interval_milliseconds = 0;
        assert!(validate_binding_input(&candidate).is_err());
    }

    #[test]
    fn debug_output_never_discloses_secret_bearing_fields() {
        let binding = binding();
        let rendered = format!("{binding:?}");
        for secret in [
            binding.base_url.as_str(),
            binding.token_endpoint.as_str(),
            binding.client_id_ref.as_str(),
            binding.client_assertion_key_ref.as_str(),
            binding.webhook_secret_ref.as_str(),
        ] {
            assert!(
                !rendered.contains(secret),
                "debug output leaked a secret-bearing field: {rendered}"
            );
        }
        assert!(rendered.contains(&binding.reader_profile));
        assert!(rendered.contains(&binding.event_source));
    }

    #[test]
    fn imported_description_drift_is_refused() {
        assert!(validate_description(&source(), &description("another-entity")).is_err());
        let mut wrong_mode: Value = serde_json::from_slice(&description("correction")).unwrap();
        wrong_mode["request"]["onApproved"]["mode"] = json!("automatic");
        assert!(
            validate_description(&source(), &serde_json::to_vec(&wrong_mode).unwrap()).is_err()
        );
    }

    #[test]
    fn imported_description_refuses_a_source_id_the_adapter_cannot_use() {
        let mut source = source();
        source.id = "source:primary".into();
        let mut imported: Value = serde_json::from_slice(&description("correction")).unwrap();
        imported["sourceId"] = json!(source.id);

        assert!(
            validate_description_input(&source, &serde_json::to_vec(&imported).unwrap()).is_err()
        );
    }

    #[test]
    fn imported_description_requires_closed_review_and_application_contracts() {
        let mut value: Value = serde_json::from_slice(&description("correction")).unwrap();
        value["request"]["review"]["stages"] = json!([]);
        assert!(validate_description(&source(), &serde_json::to_vec(&value).unwrap()).is_err());

        let mut value: Value = serde_json::from_slice(&description("correction")).unwrap();
        value["request"]["onApproved"] =
            json!({"mode":"automatic","executor":"breg-application-worker"});
        assert!(validate_description(&source(), &serde_json::to_vec(&value).unwrap()).is_ok());

        value["request"]["review"] = json!({"mode":"none"});
        assert!(validate_description(&source(), &serde_json::to_vec(&value).unwrap()).is_ok());
    }

    #[test]
    fn imported_description_maps_only_the_configured_routing_projection() {
        let mut source = source();
        source.requests[0].projection = vec!["region".to_owned()];
        let (requests, _) = validate_description(&source, &description("correction")).unwrap();
        let metadata = &requests[0].routing_metadata;
        assert!(metadata.stages.is_empty());
        assert_eq!(metadata.fields.len(), 1);
        assert_eq!(metadata.fields[0].field, "region");
        assert_eq!(metadata.fields[0].api_name, "serviceRegion");
        assert_eq!(
            metadata.fields[0].schema,
            json!({"type":"string","enum":["north","south"]})
        );

        source.requests[0].projection = vec!["region".to_owned(), "not-imported".to_owned()];
        assert_eq!(
            check_description_input(&source, &description("correction")).unwrap_err(),
            DescriptionRefusal::UnpublishedPolicyField {
                path: "/requests/0/projection/1".to_owned(),
                field: "not-imported".to_owned(),
            }
        );
        assert!(validate_description_input(&source, &description("correction")).is_err());

        source.requests[0].projection = vec!["region".to_owned()];
        let mut duplicate: Value = serde_json::from_slice(&description("correction")).unwrap();
        duplicate["request"]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({"field":"region","apiName":"otherRegion","schema":{"type":"string"}}));
        assert!(validate_description(&source, &serde_json::to_vec(&duplicate).unwrap()).is_err());
    }

    #[test]
    fn display_reference_is_explicit_and_accepts_an_unbounded_source_string_schema() {
        let mut source = source();
        source.requests[0].display_reference =
            Some(registry_casework_core::DisplayReferencePolicy {
                field: "region".to_owned(),
            });
        let (requests, _) = validate_description(&source, &description("correction")).unwrap();
        let reference = requests[0]
            .display_reference
            .clone()
            .expect("configured reference");
        assert_eq!(reference.field, "region");
        assert_eq!(reference.api_name, "serviceRegion");

        source.requests[0].display_reference.as_mut().unwrap().field = "missing".to_owned();
        assert_eq!(
            check_description_input(&source, &description("correction")).unwrap_err(),
            DescriptionRefusal::UnpublishedPolicyField {
                path: "/requests/0/displayReference/field".to_owned(),
                field: "missing".to_owned(),
            }
        );
    }

    #[test]
    fn context_projection_is_an_explicit_imported_allowlist() {
        let mut source = source();
        source.requests[0].context_projection = vec!["region".to_owned()];
        let (requests, _) = validate_description(&source, &description("correction")).unwrap();
        let context = &requests[0].context_projection;
        assert_eq!(context.len(), 1);
        assert_eq!(context[0].field, "region");
        assert_eq!(context[0].api_name, "serviceRegion");

        source.requests[0].context_projection = vec!["not-imported".to_owned()];
        assert_eq!(
            check_description_input(&source, &description("correction")).unwrap_err(),
            DescriptionRefusal::UnpublishedPolicyField {
                path: "/requests/0/contextProjection/0".to_owned(),
                field: "not-imported".to_owned(),
            }
        );

        // Drift in the description is reported as drift even when the
        // policy also names a field the description does not publish.
        let mut drifted: Value = serde_json::from_slice(&description("correction")).unwrap();
        drifted["request"]
            .as_object_mut()
            .unwrap()
            .remove("contractFingerprint");
        assert_eq!(
            check_description_input(&source, &serde_json::to_vec(&drifted).unwrap()).unwrap_err(),
            DescriptionRefusal::ContractMismatch
        );
    }

    fn generation(binding: &BregBinding, source: &SourcePolicy) -> String {
        binding_generation(binding, source, &description("correction")).unwrap()
    }

    /// A source pairing `correction` and `renewal`, described by `v1alpha2`.
    fn two_entity_source() -> SourcePolicy {
        let mut source = source();
        let mut renewal = source.requests[0].clone();
        renewal.entity = "renewal".to_owned();
        source.requests.push(renewal);
        source
    }

    fn requests_description(entities: &[(&str, &str)]) -> Value {
        let single: Value = serde_json::from_slice(&description("correction")).unwrap();
        let mut value = single.clone();
        let object = value.as_object_mut().unwrap();
        object.remove("request");
        object.insert(
            "apiVersion".to_owned(),
            json!(DESCRIPTION_API_VERSION_REQUESTS),
        );
        object.insert(
            "requests".to_owned(),
            entities
                .iter()
                .map(|(entity, route)| {
                    let mut request = single["request"].clone();
                    request["requestEntity"] = json!(entity);
                    request["requestRoute"] = json!(route);
                    request
                })
                .collect(),
        );
        value
    }

    #[test]
    fn a_requests_description_pairs_every_declared_entity_in_policy_order() {
        let described =
            requests_description(&[("renewal", "renewals"), ("correction", "corrections")]);
        let (requests, revision) = validate_description(
            &two_entity_source(),
            &serde_json::to_vec(&described).unwrap(),
        )
        .unwrap();
        assert_eq!(revision, "sha256:source");
        assert_eq!(
            requests
                .iter()
                .map(|request| (request.entity.as_str(), request.route.as_str()))
                .collect::<Vec<_>>(),
            [("correction", "corrections"), ("renewal", "renewals")]
        );
        let metadata = validate_description_input(
            &two_entity_source(),
            &serde_json::to_vec(&described).unwrap(),
        )
        .unwrap();
        assert_eq!(
            metadata.keys().map(String::as_str).collect::<Vec<_>>(),
            ["correction", "renewal"]
        );
    }

    #[test]
    fn a_requests_description_must_describe_exactly_the_declared_entities() {
        let source = two_entity_source();
        for described in [
            requests_description(&[("correction", "corrections")]),
            requests_description(&[("correction", "corrections"), ("licence", "licences")]),
            requests_description(&[("correction", "corrections"), ("correction", "renewals")]),
            requests_description(&[
                ("correction", "corrections"),
                ("renewal", "renewals"),
                ("licence", "licences"),
            ]),
        ] {
            assert!(
                validate_description(&source, &serde_json::to_vec(&described).unwrap()).is_err(),
                "{described}"
            );
        }
        // The single-request form cannot describe a two-entity source.
        assert!(validate_description(&source, &description("correction")).is_err());
    }

    #[test]
    fn each_description_version_carries_only_its_own_request_member() {
        let mut single: Value = serde_json::from_slice(&description("correction")).unwrap();
        single["apiVersion"] = json!(DESCRIPTION_API_VERSION_REQUESTS);
        assert!(validate_description(&source(), &serde_json::to_vec(&single).unwrap()).is_err());

        let mut several = requests_description(&[("correction", "corrections")]);
        assert!(validate_description(&source(), &serde_json::to_vec(&several).unwrap()).is_ok());
        several["apiVersion"] = json!(DESCRIPTION_API_VERSION);
        assert!(validate_description(&source(), &serde_json::to_vec(&several).unwrap()).is_err());
    }

    #[test]
    fn generation_covers_every_paired_entity_description_but_not_its_presentation() {
        let described =
            requests_description(&[("correction", "corrections"), ("renewal", "renewals")]);
        let bytes = serde_json::to_vec(&described).unwrap();
        let source = two_entity_source();
        let first = binding_generation(&binding(), &source, &bytes).unwrap();

        let mut presented = source.clone();
        presented.requests[1].context_projection = vec!["region".to_owned()];
        assert_eq!(
            first,
            binding_generation(&binding(), &presented, &bytes).unwrap()
        );

        let mut redescribed = described.clone();
        redescribed["requests"][1]["fields"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_ne!(
            first,
            binding_generation(
                &binding(),
                &source,
                &serde_json::to_vec(&redescribed).unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn generation_changes_with_source_id_event_source_or_description() {
        let first = generation(&binding(), &source());

        let mut changed_description = description("correction");
        changed_description.push(b'\n');
        let changed_import =
            binding_generation(&binding(), &source(), &changed_description).unwrap();
        assert_ne!(first, changed_import);

        let mut renamed = source();
        renamed.id = "licence-register".to_owned();
        assert_ne!(first, generation(&binding(), &renamed));

        let mut other_instance = binding();
        other_instance.event_source = "urn:registrystack:registry:package:instance:other".into();
        assert_ne!(first, generation(&other_instance, &source()));
    }

    /// The resolved client id is not an input to the formula, so rotating the
    /// credential behind `clientIdRef` cannot reach the generation either.
    #[test]
    fn generation_ignores_credentials_transport_and_presentation_settings() {
        let first = generation(&binding(), &source());
        let operational: Vec<(&str, BregBinding)> = vec![
            (
                "baseUrl",
                BregBinding {
                    base_url: "https://registry-2.example".into(),
                    ..binding()
                },
            ),
            (
                "readerProfile",
                BregBinding {
                    reader_profile: "casework-reader-2".into(),
                    ..binding()
                },
            ),
            (
                "tokenEndpoint",
                BregBinding {
                    token_endpoint: "https://issuer-2.example/token".into(),
                    ..binding()
                },
            ),
            (
                "clientAssertionAudience",
                BregBinding {
                    client_assertion_audience: Some("https://issuer.example".into()),
                    ..binding()
                },
            ),
            (
                "resource",
                BregBinding {
                    resource: Some("urn:breg:example".into()),
                    ..binding()
                },
            ),
            (
                "scopes",
                BregBinding {
                    scopes: Some(vec!["casework:source-reader".into()]),
                    ..binding()
                },
            ),
            (
                "clientIdRef",
                BregBinding {
                    client_id_ref: "secret:file/client-id-2".into(),
                    ..binding()
                },
            ),
            (
                "clientAssertionKeyRef",
                BregBinding {
                    client_assertion_key_ref: "secret:file/client-key-2.jwk".into(),
                    ..binding()
                },
            ),
            (
                "webhookSecretRef",
                BregBinding {
                    webhook_secret_ref: "secret:env/CASEWORK_WEBHOOK_2".into(),
                    ..binding()
                },
            ),
            (
                "trustedRootCertificatesRef",
                BregBinding {
                    trusted_root_certificates_ref: Some("secret:file/roots.pem".into()),
                    ..binding()
                },
            ),
            (
                "requestTimeoutMilliseconds",
                BregBinding {
                    request_timeout_milliseconds: 45_000,
                    ..binding()
                },
            ),
            (
                "connectTimeoutMilliseconds",
                BregBinding {
                    connect_timeout_milliseconds: 5_000,
                    ..binding()
                },
            ),
        ];
        for (field, changed) in &operational {
            assert!(validate_binding(changed).is_ok(), "{field}");
            assert_eq!(first, generation(changed, &source()), "{field}");
        }

        let mut presented = source();
        presented.requests[0].display_reference =
            Some(registry_casework_core::DisplayReferencePolicy {
                field: "region".to_owned(),
            });
        presented.requests[0].context_projection = vec!["region".to_owned()];
        assert_eq!(first, generation(&binding(), &presented));
    }

    #[test]
    fn generation_ignores_reconciliation_cadence() {
        let source = source();
        let binding = binding();
        let first = binding_generation(&binding, &source, &description("correction")).unwrap();
        let changed_cadence = binding_generation(
            &BregBinding {
                reconciliation_interval_milliseconds: 120_000,
                ..binding
            },
            &source,
            &description("correction"),
        )
        .unwrap();

        assert_eq!(first, changed_cadence);
    }

    #[test]
    fn source_token_authority_is_explicit_and_bounded() {
        let mut configured = binding();
        configured.client_assertion_audience = Some("https://issuer.example".into());
        configured.resource = Some("urn:breg:example".into());
        configured.scopes = Some(vec!["casework:source-reader".into()]);
        assert!(validate_binding(&configured).is_ok());
        configured.scopes = Some(vec![]);
        assert!(validate_binding(&configured).is_err());
        configured.scopes = Some(vec![
            "casework:source-reader".into(),
            "casework:source-reader".into(),
        ]);
        assert!(validate_binding(&configured).is_err());
        configured.scopes = None;
        configured.resource = Some(" not a resource".into());
        assert!(validate_binding(&configured).is_err());
    }

    #[tokio::test]
    async fn source_reader_posts_configured_assertion_audience_resource_and_scopes() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use registry_platform_httputil::TokenProvider;
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token":"synthetic-reader-token","token_type":"Bearer","expires_in":300
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut configured = binding();
        configured.token_endpoint = format!("{}/oauth2/token", server.uri());
        configured.client_assertion_audience = Some(server.uri());
        configured.resource = Some("urn:breg:configured".into());
        configured.scopes = Some(vec!["casework:source-reader".into()]);
        let mut key = registry_platform_crypto::generate_private_jwk(
            registry_platform_crypto::GeneratedKeyAlgorithm::Es384,
        )
        .unwrap();
        key.kid = Some("synthetic-reader-key".into());
        let provider =
            PrivateKeyJwt::new(source_token_config(&configured, "casework-reader", key).unwrap())
                .unwrap();
        assert!(provider.bearer_token().await.is_ok());
        let requests = server.received_requests().await.unwrap();
        let fields: BTreeMap<_, _> = url::form_urlencoded::parse(&requests[0].body)
            .into_owned()
            .collect();
        assert_eq!(fields["resource"], "urn:breg:configured");
        assert_eq!(fields["scope"], "casework:source-reader");
        let assertion = fields["client_assertion"].split('.').nth(1).unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(assertion).unwrap()).unwrap();
        assert_eq!(claims["aud"], server.uri());
        assert_eq!(claims["iss"], "casework-reader");
        assert_eq!(claims["sub"], "casework-reader");
    }
}
