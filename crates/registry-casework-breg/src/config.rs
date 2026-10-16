// SPDX-License-Identifier: Apache-2.0
//! Operator transport binding and inert producer export. Never a source action bridge.
use registry_casework_core::{ReviewContextContract, ReviewContextError};
use registry_platform_config::sha256_uri;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DESCRIPTION_API_VERSION: &str =
    "id.registrystack.org/formats/casework/breg-context-export/v1alpha1";
pub const DESCRIPTION_KIND: &str = "CaseworkBregContextExport";

/// The schema bytes are exported by BReg before the consumer policy is compiled.
/// Its contract revision covers the exact source, projection meaning and field semantics.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BregContextExport {
    pub api_version: String,
    pub kind: String,
    pub source_namespace: String,
    pub action_id: String,
    pub context_id: String,
    pub contract: ReviewContextContract,
    pub schema: Value,
    /// Exact UTF-8 file bytes whose digest is pinned by the consumer closure.
    pub schema_bytes: String,
}
impl BregContextExport {
    pub fn check(&self) -> Result<(), ReviewContextError> {
        let bytes = self.schema_bytes.as_bytes();
        let mut revision_schema = self.schema.clone();
        let observed_revision = revision_schema
            .as_object_mut()
            .and_then(|object| object.remove("x-registry-definition-revision"));
        let canonical = registry_platform_canonical_json::canonicalize_json(&revision_schema)
            .map_err(|_| ReviewContextError::Invalid)?;
        if self.api_version != DESCRIPTION_API_VERSION
            || self.kind != DESCRIPTION_KIND
            || self.source_namespace.is_empty()
            || self.action_id.is_empty()
            || self.context_id.is_empty()
            || bytes.len() > 1024 * 1024
            || sha256_uri(bytes) != self.contract.schema_digest.as_str()
            || serde_json::from_slice::<Value>(bytes).ok().as_ref() != Some(&self.schema)
            || self.schema.get("$id").and_then(Value::as_str) != Some(self.contract.id.as_str())
            || self
                .schema
                .get("x-registry-definition-revision")
                .and_then(Value::as_str)
                != Some(self.contract.revision.as_str())
            || observed_revision.as_ref().and_then(Value::as_str)
                != Some(self.contract.revision.as_str())
            || sha256_uri(&canonical) != self.contract.revision.as_str()
            || self.schema["x-registry-review-context"]["sourceNamespace"].as_str()
                != Some(self.source_namespace.as_str())
            || self.schema["x-registry-review-context"]["actionId"].as_str()
                != Some(self.action_id.as_str())
            || self.schema["x-registry-review-context"]["contextId"].as_str()
                != Some(self.context_id.as_str())
        {
            return Err(ReviewContextError::Invalid);
        }
        Ok(())
    }
}

/// Environment-specific transport and reader identity. Human display always replaces it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BregBinding {
    #[serde(deserialize_with = "registry_casework_core::typed::url")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub base_url: String,
    pub status_profile: String,
    #[serde(deserialize_with = "registry_casework_core::typed::url")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub token_endpoint: String,
    #[serde(deserialize_with = "secret_reference")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_config::SecretReference")
    )]
    pub client_id_ref: String,
    #[serde(deserialize_with = "secret_reference")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_config::SecretReference")
    )]
    pub client_assertion_key_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_assertion_audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}
impl std::fmt::Debug for BregBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BregBinding(<operator transport and secret references>)")
    }
}

pub fn build_provider(
    binding: &BregBinding,
    policy: &registry_casework_core::ReviewContextProviderPolicy,
    description: &[u8],
    secrets: &registry_platform_config::SecretResolver,
) -> Result<crate::BregContextProvider, ReviewContextError> {
    use registry_breg_client::{
        BaseRegistryClient, BaseRegistryClientConfig, PrivateKeyJwt, PrivateKeyJwtConfig,
    };
    use registry_platform_crypto::PrivateJwk;
    use std::{sync::Arc, time::Duration};
    if description.is_empty()
        || description.len() > 1024 * 1024
        || !registry_casework_core::valid_profile_identifier(&binding.status_profile)
    {
        return Err(ReviewContextError::Invalid);
    }
    let export: BregContextExport = serde_json::from_value(
        registry_breg_client::decode_exact_json(description)
            .map_err(|_| ReviewContextError::Invalid)?,
    )
    .map_err(|_| ReviewContextError::Invalid)?;
    export.check()?;
    if export.source_namespace != policy.source_namespace
        || policy
            .service_profiles
            .get(&registry_casework_core::ReviewContextCapability::ServiceStatus)
            != Some(&binding.status_profile)
        || policy
            .capabilities
            .iter()
            .any(|cap| !crate::SERVED_CAPABILITIES.contains(cap))
    {
        return Err(ReviewContextError::Unsupported);
    }
    let client_id = secrets
        .resolve(&binding.client_id_ref)
        .map_err(|_| ReviewContextError::Unavailable)?;
    let client_id =
        std::str::from_utf8(client_id.expose_secret()).map_err(|_| ReviewContextError::Invalid)?;
    if client_id.is_empty() || client_id.len() > 512 {
        return Err(ReviewContextError::Invalid);
    }
    let key = secrets
        .resolve(&binding.client_assertion_key_ref)
        .map_err(|_| ReviewContextError::Unavailable)?;
    let key = PrivateJwk::parse(
        std::str::from_utf8(key.expose_secret()).map_err(|_| ReviewContextError::Invalid)?,
    )
    .map_err(|_| ReviewContextError::Invalid)?;
    let endpoint =
        url::Url::parse(&binding.token_endpoint).map_err(|_| ReviewContextError::Invalid)?;
    let mut token = PrivateKeyJwtConfig::new(endpoint, client_id, key)
        .with_request_timeout(Duration::from_secs(30))
        .with_connect_timeout(Duration::from_secs(10));
    if let Some(audience) = &binding.client_assertion_audience {
        token = token.with_audience(audience);
    }
    if let Some(resource) = &binding.resource {
        token = token.with_resource(resource);
    }
    if let Some(scopes) = &binding.scopes {
        token = token.with_scopes(scopes.clone());
    }
    let token = PrivateKeyJwt::new(token).map_err(|_| ReviewContextError::Invalid)?;
    let config = BaseRegistryClientConfig::new(
        url::Url::parse(&binding.base_url).map_err(|_| ReviewContextError::Invalid)?,
    )
    .with_token_provider(Arc::new(token))
    .with_max_response_bytes(1024 * 1024)
    .with_request_timeout(Duration::from_secs(30))
    .with_connect_timeout(Duration::from_secs(10));
    let client = BaseRegistryClient::new(config).map_err(|_| ReviewContextError::Invalid)?;
    crate::BregContextProvider::new(
        policy.id.clone(),
        export,
        client,
        binding.status_profile.clone(),
    )
}

fn secret_reference<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    registry_platform_config::SecretReference::deserialize(deserializer)
        .map(|reference| reference.as_str().to_owned())
}
