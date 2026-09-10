// SPDX-License-Identifier: Apache-2.0
//! Closed operator binding and offline construction of the BReg adapter.

use crate::{BregAdapter, BregSourceConfig};
use registry_breg_client::{
    decode_exact_json, BaseRegistryClient, BaseRegistryClientConfig, PrivateKeyJwt,
    PrivateKeyJwtConfig,
};
use registry_casework_core::{SourceAdapterError, SourcePolicy};
use registry_platform_config::{sha256_uri, SecretResolver};
use registry_platform_crypto::PrivateJwk;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fmt, fs, path::Path, sync::Arc, time::Duration};
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

/// Launcher-owned BReg connection material for one authored Casework source.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BregBinding {
    pub base_url: String,
    pub reader_profile: String,
    pub token_endpoint: String,
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
    let (entity, route, stage, expected_registry_revision) =
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
    let token_endpoint = parse_url(&binding.token_endpoint)?;
    let mut token_config = PrivateKeyJwtConfig::new(token_endpoint, client_id, key)
        .with_request_timeout(request_timeout)
        .with_connect_timeout(connect_timeout);
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
            stage,
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

fn validate_binding(binding: &BregBinding) -> Result<(), SourceAdapterError> {
    if !valid_scalar(&binding.reader_profile, 512)
        || !valid_scalar(&binding.event_type, 512)
        || binding.request_timeout_milliseconds == 0
        || binding.connect_timeout_milliseconds == 0
        || binding.request_timeout_milliseconds > MAXIMUM_TIMEOUT_MILLISECONDS
        || binding.connect_timeout_milliseconds > binding.request_timeout_milliseconds
        || !valid_event_source(&binding.event_source)
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
) -> Result<(String, String, String, String), SourceAdapterError> {
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
        .filter(|stages| stages.len() == 1)
        .ok_or(SourceAdapterError::Invalid)?;
    if stages[0].get("approvals").and_then(Value::as_u64) != Some(1) {
        return Err(SourceAdapterError::Invalid);
    }
    let stage = stages[0]
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| valid_scalar(value, 512))
        .ok_or(SourceAdapterError::Invalid)?;
    Ok((
        entity.to_owned(),
        route.to_owned(),
        stage.to_owned(),
        expected_registry_revision,
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
    let identity = serde_json::to_vec(&json!({
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
    }))
    .map_err(|_| SourceAdapterError::Invalid)?;
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
                "application":{"mode":"manual"},"stages":[{"id":"review","approvals":1}]}
        }))
        .unwrap()
    }

    fn binding() -> BregBinding {
        BregBinding {
            base_url: "https://registry.example".into(),
            reader_profile: "casework-reader".into(),
            token_endpoint: "https://issuer.example/token".into(),
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
    }
}
