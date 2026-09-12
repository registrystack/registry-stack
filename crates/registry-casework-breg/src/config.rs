// SPDX-License-Identifier: Apache-2.0
//! Closed operator binding and offline construction of the BReg adapter.

use crate::{
    valid_source_identifier, valid_stage_identifier, BregAdapter, BregReviewStage, BregSourceConfig,
};
use registry_breg_client::{
    decode_exact_json, BaseRegistryClient, BaseRegistryClientConfig, PrivateKeyJwt,
    PrivateKeyJwtConfig, MAX_BREG_REVIEW_STAGES,
};
use registry_casework_core::{
    RoutingFieldDescriptor, RoutingSourceMetadata, SourceAdapterError, SourcePolicy,
};
use registry_platform_config::{sha256_uri, SecretResolver};
use registry_platform_crypto::PrivateJwk;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
    sync::Arc,
    time::Duration,
};
use url::Url;

const DESCRIPTION_API_VERSION: &str =
    "registry.registrystack.org/casework-source-description/v1alpha1";
const DESCRIPTION_KIND: &str = "BRegCaseworkSourceDescription";
const DESCRIPTION_ORIGIN: &str = "bregctl explain change-requests";
const DEFAULT_EVENT_TYPE: &str = "casework-lifecycle-v1";
const DEFAULT_REQUEST_TIMEOUT_MILLISECONDS: u64 = 30_000;
const DEFAULT_CONNECT_TIMEOUT_MILLISECONDS: u64 = 10_000;
const MAXIMUM_TIMEOUT_MILLISECONDS: u64 = 300_000;
const MAXIMUM_DESCRIPTION_BYTES: usize = 8 * 1024 * 1024;

type ValidatedDescription = (
    String,
    String,
    Vec<BregReviewStage>,
    RoutingSourceMetadata,
    Option<RoutingFieldDescriptor>,
    String,
);

/// Launcher-owned BReg connection material for one authored Casework source.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BregBinding {
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
    pub client_id_ref: String,
    pub client_assertion_key_ref: String,
    pub webhook_secret_ref: String,
    pub event_source: String,
    #[serde(default = "default_event_type")]
    pub event_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_root_certificates_ref: Option<String>,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_milliseconds: u64,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_milliseconds: u64,
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
            .field("event_type", &self.event_type)
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
}

/// Validate one authored description and construct its pooled BReg client.
pub fn build_adapter(
    binding: &BregBinding,
    source: &SourcePolicy,
    project_root: &Path,
    secrets: &SecretResolver,
) -> Result<BregAdapter, SourceAdapterError> {
    validate_binding(binding)?;
    if source.adapter != "breg" || source.requests.len() != 1 {
        return Err(SourceAdapterError::Invalid);
    }
    let description_bytes = read_description(project_root, &source.description)?;
    let (entity, route, stages, routing_metadata, display_reference, expected_registry_revision) =
        validate_description(source, &description_bytes)?;

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
    let generation = binding_generation(binding, source, &client_id, &description_bytes)?;

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
            entity,
            route,
            stages,
            routing_metadata,
            display_reference,
            expected_registry_revision,
            binding_generation: generation,
            reader_profile: binding.reader_profile.clone(),
            event_source: binding.event_source.clone(),
            event_type: binding.event_type.clone(),
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
    if !valid_scalar(&binding.reader_profile, 512)
        || !valid_scalar(&binding.event_type, 512)
        || binding.request_timeout_milliseconds == 0
        || binding.connect_timeout_milliseconds == 0
        || binding.request_timeout_milliseconds > MAXIMUM_TIMEOUT_MILLISECONDS
        || binding.connect_timeout_milliseconds > binding.request_timeout_milliseconds
        || !valid_event_source(&binding.event_source)
        || [&binding.client_assertion_audience, &binding.resource]
            .iter()
            .any(|value| {
                value
                    .as_ref()
                    .is_some_and(|value| !registry_platform_httputil::valid_resource_uri(value))
            })
        || binding.scopes.as_ref().is_some_and(|scopes| {
            scopes.is_empty()
                || scopes.len() > registry_platform_httputil::MAXIMUM_REQUESTED_SCOPES
                || scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len()
                || scopes.iter().any(|scope| {
                    scope.len() > registry_platform_httputil::MAXIMUM_REQUESTED_SCOPE_BYTES
                        || !registry_platform_httputil::valid_scope_token(scope)
                })
        })
    {
        return Err(SourceAdapterError::Invalid);
    }
    Ok(())
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
) -> Result<ValidatedDescription, SourceAdapterError> {
    let root = decode_exact_json(bytes).map_err(|_| SourceAdapterError::Invalid)?;
    let object = root.as_object().ok_or(SourceAdapterError::Invalid)?;
    let expected = [
        "apiVersion",
        "authority",
        "kind",
        "origin",
        "request",
        "sourceId",
        "sourceRevision",
    ];
    if object.len() != expected.len()
        || expected.iter().any(|key| !object.contains_key(*key))
        || root["apiVersion"] != DESCRIPTION_API_VERSION
        || root["kind"] != DESCRIPTION_KIND
        || root["authority"] != "none"
        || root["origin"] != DESCRIPTION_ORIGIN
        || !valid_source_identifier(&source.id)
        || root["sourceId"] != source.id
        || !root["sourceRevision"]
            .as_str()
            .is_some_and(|value| valid_scalar(value, 512))
    {
        return Err(SourceAdapterError::Invalid);
    }
    let expected_registry_revision = root["sourceRevision"]
        .as_str()
        .ok_or(SourceAdapterError::Invalid)?
        .to_owned();
    let request = root["request"]
        .as_object()
        .ok_or(SourceAdapterError::Invalid)?;
    let entity = string_field(request, "requestEntity")?;
    let route = string_field(request, "requestRoute")?;
    string_field(request, "contractFingerprint")?;
    if entity != source.requests[0].entity
        || request.get("reviewMode") != Some(&Value::String("staged".into()))
        || request
            .get("application")
            .and_then(Value::as_object)
            .and_then(|application| application.get("mode"))
            != Some(&Value::String("manual".into()))
    {
        return Err(SourceAdapterError::Invalid);
    }
    let stages = request
        .get("stages")
        .and_then(Value::as_array)
        .filter(|stages| !stages.is_empty() && stages.len() <= MAX_BREG_REVIEW_STAGES)
        .ok_or(SourceAdapterError::Invalid)?;
    let mut parsed_stages = Vec::with_capacity(stages.len());
    for stage in stages {
        let stage = stage.as_object().ok_or(SourceAdapterError::Invalid)?;
        if stage.len() > 4
            || !["id", "approvals", "excludeSubmitter"]
                .iter()
                .all(|field| stage.contains_key(*field))
            || stage.keys().any(|field| {
                !matches!(
                    field.as_str(),
                    "id" | "approvals" | "excludeSubmitter" | "excludePreviousReviewers"
                )
            })
        {
            return Err(SourceAdapterError::Invalid);
        }
        let id = stage
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| valid_stage_identifier(value))
            .ok_or(SourceAdapterError::Invalid)?;
        let approvals = stage
            .get("approvals")
            .and_then(Value::as_u64)
            .filter(|approvals| (1..=32).contains(approvals))
            .ok_or(SourceAdapterError::Invalid)?;
        let exclude_submitter = stage
            .get("excludeSubmitter")
            .and_then(Value::as_bool)
            .ok_or(SourceAdapterError::Invalid)?;
        let exclude_previous_reviewers = match stage.get("excludePreviousReviewers") {
            None => false,
            Some(value) => value.as_bool().ok_or(SourceAdapterError::Invalid)?,
        };
        if parsed_stages
            .iter()
            .any(|prior: &BregReviewStage| prior.id == id)
        {
            return Err(SourceAdapterError::Invalid);
        }
        parsed_stages.push(BregReviewStage {
            id: id.to_owned(),
            approvals,
            exclude_submitter,
            exclude_previous_reviewers,
        });
    }
    let (routing_metadata, fields_by_name) =
        routing_metadata(request, &source.requests[0].projection, &parsed_stages)?;
    let display_reference = source.requests[0]
        .display_reference
        .as_ref()
        .map(|configured| {
            let descriptor = fields_by_name
                .get(&configured.field)
                .cloned()
                .ok_or(SourceAdapterError::Invalid)?;
            let schema = descriptor
                .schema
                .as_object()
                .ok_or(SourceAdapterError::Invalid)?;
            if schema.get("type").and_then(Value::as_str) != Some("string") {
                return Err(SourceAdapterError::Invalid);
            }
            Ok(descriptor)
        })
        .transpose()?;
    Ok((
        entity.to_owned(),
        route.to_owned(),
        parsed_stages,
        routing_metadata,
        display_reference,
        expected_registry_revision,
    ))
}

/// Validate an imported description with the same strict decoder used by
/// adapter construction, without loading operator bindings or secrets.
pub fn validate_description_input(
    source: &SourcePolicy,
    bytes: &[u8],
) -> Result<RoutingSourceMetadata, SourceAdapterError> {
    let (_, _, _, routing_metadata, _, _) = validate_description(source, bytes)?;
    Ok(routing_metadata)
}

fn routing_metadata(
    request: &serde_json::Map<String, Value>,
    projection: &[String],
    stages: &[BregReviewStage],
) -> Result<
    (
        RoutingSourceMetadata,
        BTreeMap<String, RoutingFieldDescriptor>,
    ),
    SourceAdapterError,
> {
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
    let fields = projection
        .iter()
        .map(|field| {
            by_logical_name
                .get(field)
                .cloned()
                .ok_or(SourceAdapterError::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        RoutingSourceMetadata {
            stages: stages.iter().map(|stage| stage.id.clone()).collect(),
            fields,
        },
        by_logical_name,
    ))
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

fn binding_generation(
    binding: &BregBinding,
    source: &SourcePolicy,
    client_id: &str,
    description: &[u8],
) -> Result<String, SourceAdapterError> {
    let mut identity = json!({
        "sourceId": source.id,
        "baseUrl": binding.base_url,
        "readerProfile": binding.reader_profile,
        "tokenEndpoint": binding.token_endpoint,
        "clientIdRef": binding.client_id_ref,
        "clientIdSha256": sha256_uri(client_id.as_bytes()),
        "clientAssertionKeyRef": binding.client_assertion_key_ref,
        "webhookSecretRef": binding.webhook_secret_ref,
        "eventSource": binding.event_source,
        "eventType": binding.event_type,
        "trustedRootCertificatesRef": binding.trusted_root_certificates_ref,
        "requestTimeoutMilliseconds": binding.request_timeout_milliseconds,
        "connectTimeoutMilliseconds": binding.connect_timeout_milliseconds,
        "descriptionSha256": sha256_uri(description),
    });
    if let Some(audience) = &binding.client_assertion_audience {
        identity["clientAssertionAudience"] = json!(audience);
    }
    if let Some(resource) = &binding.resource {
        identity["resource"] = json!(resource);
    }
    if let Some(scopes) = &binding.scopes {
        identity["scopes"] = json!(scopes);
    }
    if let Some(display_reference) = source
        .requests
        .first()
        .and_then(|request| request.display_reference.as_ref())
    {
        identity["displayReference"] =
            serde_json::to_value(display_reference).map_err(|_| SourceAdapterError::Invalid)?;
    }
    let identity = serde_json::to_vec(&identity).map_err(|_| SourceAdapterError::Invalid)?;
    Ok(sha256_uri(&identity))
}

fn default_event_type() -> String {
    DEFAULT_EVENT_TYPE.to_owned()
}
const fn default_request_timeout() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_MILLISECONDS
}
const fn default_connect_timeout() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_MILLISECONDS
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
                "contractFingerprint":"sha256:contract","reviewMode":"staged",
                "fields":[{"field":"region","apiName":"serviceRegion",
                    "schema":{"type":"string","enum":["north","south"]}}],
                "application":{"mode":"manual"},"stages":[{
                    "id":"review","approvals":1,"excludeSubmitter":false
                }]}
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
            event_type: DEFAULT_EVENT_TYPE.into(),
            trusted_root_certificates_ref: None,
            request_timeout_milliseconds: 30_000,
            connect_timeout_milliseconds: 10_000,
        }
    }

    #[test]
    fn imported_description_drift_is_refused() {
        assert!(validate_description(&source(), &description("another-entity")).is_err());
        let mut wrong_mode: Value = serde_json::from_slice(&description("correction")).unwrap();
        wrong_mode["request"]["application"]["mode"] = json!("automatic");
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
    fn imported_description_preserves_the_complete_ordered_stage_policy() {
        let mut value: Value = serde_json::from_slice(&description("correction")).unwrap();
        value["request"]["stages"] = json!([
            {"id":"technical","approvals":2,"excludeSubmitter":true},
            {"id":"authorization","approvals":1,"excludeSubmitter":true,
                "excludePreviousReviewers":true}
        ]);
        let (_, _, stages, _, _, _) =
            validate_description(&source(), &serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            stages,
            vec![
                BregReviewStage {
                    id: "technical".into(),
                    approvals: 2,
                    exclude_submitter: true,
                    exclude_previous_reviewers: false,
                },
                BregReviewStage {
                    id: "authorization".into(),
                    approvals: 1,
                    exclude_submitter: true,
                    exclude_previous_reviewers: true,
                },
            ]
        );

        value["request"]["stages"][1]["id"] = json!("technical");
        assert!(validate_description(&source(), &serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn imported_description_maps_only_the_configured_routing_projection() {
        let mut source = source();
        source.requests[0].projection = vec!["region".to_owned()];
        let (_, _, _, metadata, _, _) =
            validate_description(&source, &description("correction")).unwrap();
        assert_eq!(metadata.stages, ["review"]);
        assert_eq!(metadata.fields.len(), 1);
        assert_eq!(metadata.fields[0].field, "region");
        assert_eq!(metadata.fields[0].api_name, "serviceRegion");
        assert_eq!(
            metadata.fields[0].schema,
            json!({"type":"string","enum":["north","south"]})
        );

        source.requests[0].projection = vec!["not-imported".to_owned()];
        assert!(validate_description(&source, &description("correction")).is_err());

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
        let (_, _, _, _, reference, _) =
            validate_description(&source, &description("correction")).unwrap();
        let reference = reference.expect("configured reference");
        assert_eq!(reference.field, "region");
        assert_eq!(reference.api_name, "serviceRegion");

        source.requests[0].display_reference.as_mut().unwrap().field = "missing".to_owned();
        assert!(validate_description(&source, &description("correction")).is_err());
    }

    #[test]
    fn generation_changes_with_description_or_resolved_client_identity() {
        let source = source();
        let first = binding_generation(
            &binding(),
            &source,
            "casework-client",
            &description("correction"),
        )
        .unwrap();
        let changed_client = binding_generation(
            &binding(),
            &source,
            "replacement-client",
            &description("correction"),
        )
        .unwrap();
        let mut changed_description = description("correction");
        changed_description.push(b'\n');
        let changed_import =
            binding_generation(&binding(), &source, "casework-client", &changed_description)
                .unwrap();
        assert_ne!(first, changed_client);
        assert_ne!(first, changed_import);

        let mut source_with_reference = source;
        source_with_reference.requests[0].display_reference =
            Some(registry_casework_core::DisplayReferencePolicy {
                field: "region".to_owned(),
            });
        let changed_reference = binding_generation(
            &binding(),
            &source_with_reference,
            "casework-client",
            &description("correction"),
        )
        .unwrap();
        assert_ne!(first, changed_reference);
    }
    #[test]
    fn source_token_authority_is_explicit_bounded_and_part_of_generation() {
        let baseline =
            binding_generation(&binding(), &source(), "reader", &description("correction"))
                .unwrap();
        let mut configured = binding();
        configured.client_assertion_audience = Some("https://issuer.example".into());
        configured.resource = Some("urn:breg:example".into());
        configured.scopes = Some(vec!["casework:source-reader".into()]);
        assert!(validate_binding(&configured).is_ok());
        assert_ne!(
            baseline,
            binding_generation(&configured, &source(), "reader", &description("correction"))
                .unwrap()
        );
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
