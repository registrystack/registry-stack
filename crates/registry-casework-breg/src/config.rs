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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_grant_profile: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_display_exchange: Option<DelegatedDisplayExchangeBinding>,
}
/// The member of a context-provider binding that provider construction would
/// refuse, and the rule it breaks. The reason names the rule and never the
/// configured value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingRefusal {
    /// JSON pointer to the refused member, relative to the binding.
    pub member: String,
    pub reason: String,
}

impl BindingRefusal {
    fn new(member: &str, reason: impl Into<String>) -> Self {
        Self {
            member: member.to_owned(),
            reason: reason.into(),
        }
    }

    fn within(mut self, parent: &str) -> Self {
        self.member.insert_str(0, parent);
        self
    }
}

const PROFILE_IDENTIFIER_RULE: &str =
    "the profile identifier must be 1..=128 bytes of ASCII letters, digits, `-`, `_`, `.`, or `:`";
const RESOURCE_URI_RULE: &str =
    "the resource must be one absolute URI without a fragment or userinfo";

impl BregBinding {
    /// Checks the binding as provider construction reads it, without
    /// resolving a secret or reading a context export. The client identifier
    /// is a secret, so the identity check runs with a stand-in; the key and
    /// the identifier themselves are checked when the provider is built.
    pub fn check_offline(&self) -> Result<(), BindingRefusal> {
        use registry_platform_httputil::{valid_resource_uri, validate_requested_scopes};
        if !registry_casework_core::valid_profile_identifier(&self.status_profile) {
            return Err(BindingRefusal::new(
                "/statusProfile",
                PROFILE_IDENTIFIER_RULE,
            ));
        }
        if let Some(profile) = &self.task_grant_profile {
            if !registry_casework_core::valid_profile_identifier(profile) {
                return Err(BindingRefusal::new(
                    "/taskGrantProfile",
                    PROFILE_IDENTIFIER_RULE,
                ));
            }
            if profile == &self.status_profile {
                return Err(BindingRefusal::new(
                    "/taskGrantProfile",
                    "the task grant profile must differ from the status profile",
                ));
            }
        }
        check_client(
            &self.token_endpoint,
            self.client_assertion_audience.as_deref(),
        )?;
        if self
            .resource
            .as_deref()
            .is_some_and(|resource| !valid_resource_uri(resource))
        {
            return Err(BindingRefusal::new("/resource", RESOURCE_URI_RULE));
        }
        if let Some(scopes) = &self.scopes {
            validate_requested_scopes(scopes)
                .map_err(|error| BindingRefusal::new("/scopes", token_rule(error)))?;
        }
        let base_url = url::Url::parse(&self.base_url)
            .map_err(|_| BindingRefusal::new("/baseUrl", "the service base URL must be a URL"))?;
        registry_platform_httputil::ServiceBaseUrl::new(base_url)
            .map_err(|error| BindingRefusal::new("/baseUrl", error.to_string()))?;
        if let Some(delegated) = &self.delegated_display_exchange {
            delegated
                .check_offline()
                .map_err(|refusal| refusal.within("/delegatedDisplayExchange"))?;
        }
        Ok(())
    }
}

/// The identity and transport checks a private-key JWT client runs before it
/// holds a key. The client identifier is a secret, so a stand-in takes its place.
fn check_client(token_endpoint: &str, audience: Option<&str>) -> Result<(), BindingRefusal> {
    use registry_platform_httputil::PrivateKeyJwtConfig;
    let token_endpoint = url::Url::parse(token_endpoint)
        .map_err(|_| BindingRefusal::new("/tokenEndpoint", "the token endpoint must be a URL"))?;
    PrivateKeyJwtConfig::check_identity(&token_endpoint, "offline-check", None)
        .map_err(|error| BindingRefusal::new("/tokenEndpoint", token_rule(error)))?;
    PrivateKeyJwtConfig::check_identity(&token_endpoint, "offline-check", audience)
        .map_err(|error| BindingRefusal::new("/clientAssertionAudience", token_rule(error)))
}

fn token_rule(error: registry_platform_httputil::TokenError) -> String {
    match error {
        registry_platform_httputil::TokenError::Configuration { reason } => reason.to_owned(),
        other => other.to_string(),
    }
}

/// The value rules a delegated display exchange enforces on its resource,
/// scopes and generation before it builds a token client.
pub(crate) fn check_exchange_values(
    resource: &str,
    scopes: &[String],
    generation: &str,
) -> Result<(), BindingRefusal> {
    let valid_token = |value: &str, maximum| {
        !value.is_empty()
            && value.len() <= maximum
            && !value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    };
    if !valid_token(resource, 2048) {
        return Err(BindingRefusal::new(
            "/resource",
            "the resource must be 1..=2048 bytes without control or whitespace characters",
        ));
    }
    if scopes.is_empty()
        || scopes.len() > 128
        || scopes.iter().any(|scope| !valid_token(scope, 512))
        || scopes
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != scopes.len()
    {
        return Err(BindingRefusal::new(
            "/scopes",
            "the scopes must be 1..=128 distinct values of 1..=512 bytes without control or whitespace characters",
        ));
    }
    if !valid_token(generation, 512) {
        return Err(BindingRefusal::new(
            "/generation",
            "the generation must be 1..=512 bytes without control or whitespace characters",
        ));
    }
    Ok(())
}

impl std::fmt::Debug for BregBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BregBinding(<operator transport and secret references>)")
    }
}

/// Dedicated per-call delegation for staff-subject source disclosure. This is
/// separate from the provider's status and task-context service credential.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegatedDisplayExchangeBinding {
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
    pub resource: String,
    pub scopes: Vec<String>,
    pub generation: String,
}

impl std::fmt::Debug for DelegatedDisplayExchangeBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedDisplayExchangeBinding")
            .field("resource", &"<configured>")
            .field("scopes", &self.scopes.len())
            .field("generation", &"<configured>")
            .finish_non_exhaustive()
    }
}

impl DelegatedDisplayExchangeBinding {
    /// Checks the exchange as provider construction reads it, without
    /// resolving its client identifier or key.
    pub fn check_offline(&self) -> Result<(), BindingRefusal> {
        use registry_platform_httputil::{valid_resource_uri, validate_requested_scopes};
        check_exchange_values(&self.resource, &self.scopes, &self.generation)?;
        check_client(
            &self.token_endpoint,
            self.client_assertion_audience.as_deref(),
        )?;
        if !valid_resource_uri(&self.resource) {
            return Err(BindingRefusal::new("/resource", RESOURCE_URI_RULE));
        }
        validate_requested_scopes(&self.scopes)
            .map_err(|error| BindingRefusal::new("/scopes", token_rule(error)))
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
    if description.is_empty() || description.len() > 1024 * 1024 {
        return Err(ReviewContextError::Invalid);
    }
    binding
        .check_offline()
        .map_err(|_| ReviewContextError::Invalid)?;
    let export: BregContextExport = serde_json::from_value(
        registry_breg_client::decode_exact_json(description)
            .map_err(|_| ReviewContextError::Invalid)?,
    )
    .map_err(|_| ReviewContextError::Invalid)?;
    export.check()?;
    let task_capability = policy
        .capabilities
        .contains(&registry_casework_core::ReviewContextCapability::TaskGrantContext);
    let task_profile = policy
        .service_profiles
        .get(&registry_casework_core::ReviewContextCapability::TaskGrantContext);
    if export.source_namespace != policy.source_namespace
        || policy
            .service_profiles
            .get(&registry_casework_core::ReviewContextCapability::ServiceStatus)
            != Some(&binding.status_profile)
        || task_capability != binding.task_grant_profile.is_some()
        || task_profile != binding.task_grant_profile.as_ref()
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
        .with_attempt_timeout(Duration::from_secs(30))
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
    .with_maximum_response_bytes(1024 * 1024)
    .with_attempt_timeout(Duration::from_secs(30))
    .with_connect_timeout(Duration::from_secs(10));
    let client = BaseRegistryClient::new(config).map_err(|_| ReviewContextError::Invalid)?;
    let mut provider = crate::BregContextProvider::new(
        policy.id.clone(),
        export,
        client,
        binding.status_profile.clone(),
    )?;
    if let Some(delegated) = &binding.delegated_display_exchange {
        let delegated_client_id = secrets
            .resolve(&delegated.client_id_ref)
            .map_err(|_| ReviewContextError::Unavailable)?;
        let delegated_client_id = std::str::from_utf8(delegated_client_id.expose_secret())
            .map_err(|_| ReviewContextError::Invalid)?;
        // Keep the OAuth clients distinct so the authorization server can
        // grant subject delegation without granting it to the unattended
        // service-status identity. This is policy separation, not a claim
        // that the configured key material is necessarily different.
        if delegated_client_id.is_empty()
            || delegated_client_id.len() > 512
            || delegated_client_id == client_id
        {
            return Err(ReviewContextError::Invalid);
        }
        let delegated_key = secrets
            .resolve(&delegated.client_assertion_key_ref)
            .map_err(|_| ReviewContextError::Unavailable)?;
        let delegated_key = PrivateJwk::parse(
            std::str::from_utf8(delegated_key.expose_secret())
                .map_err(|_| ReviewContextError::Invalid)?,
        )
        .map_err(|_| ReviewContextError::Invalid)?;
        let exchange = crate::DelegatedDisplayExchange::new(
            url::Url::parse(&delegated.token_endpoint).map_err(|_| ReviewContextError::Invalid)?,
            delegated_client_id.to_owned(),
            delegated_key,
            delegated.client_assertion_audience.clone(),
            delegated.resource.clone(),
            delegated.scopes.clone(),
            delegated.generation.clone(),
        )?;
        provider = provider.with_delegated_display_exchange(exchange);
    }
    match &binding.task_grant_profile {
        Some(profile) => provider.with_task_grant_profile(profile.clone()),
        None => Ok(provider),
    }
}

fn secret_reference<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    registry_platform_config::SecretReference::deserialize(deserializer)
        .map(|reference| reference.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn offline_binding() -> serde_json::Value {
        json!({
            "baseUrl": "http://127.0.0.1:31001",
            "statusProfile": "casework-review-status",
            "tokenEndpoint": "http://127.0.0.1:31003/oauth2/token",
            "clientIdRef": "secret:file/status-client-id",
            "clientAssertionKeyRef": "secret:file/status-client-key",
            "clientAssertionAudience": "https://idp.example.test",
            "resource": "urn:example:registry",
            "scopes": ["registry:read"]
        })
    }

    fn offline_check(value: serde_json::Value) -> Result<(), BindingRefusal> {
        serde_json::from_value::<BregBinding>(value)
            .expect("the binding parses")
            .check_offline()
    }

    fn delegated_exchange() -> serde_json::Value {
        json!({
            "tokenEndpoint": "http://127.0.0.1:31003/oauth2/token",
            "clientIdRef": "secret:file/source-client-id",
            "clientAssertionKeyRef": "secret:file/source-client-key",
            "resource": "urn:example:registry",
            "scopes": ["registry:proposal:review"],
            "generation": "casework-source-v1"
        })
    }

    #[test]
    fn offline_check_accepts_a_binding_without_resolving_secrets() {
        offline_check(offline_binding()).expect("the binding is acceptable");
        let mut binding = offline_binding();
        binding["delegatedDisplayExchange"] = delegated_exchange();
        offline_check(binding).expect("the delegated exchange is acceptable");
    }

    #[test]
    fn offline_check_names_the_member_and_rule_provider_construction_refuses() {
        for (member, value, rule) in [
            (
                "/statusProfile",
                json!("not a profile"),
                "profile identifier",
            ),
            (
                "/taskGrantProfile",
                json!("casework-review-status"),
                "differ from the status profile",
            ),
            (
                "/taskGrantProfile",
                json!("not a profile"),
                "profile identifier",
            ),
            ("/resource", json!("registry"), "absolute URI"),
            (
                "/resource",
                json!("urn:example:registry#fragment"),
                "absolute URI",
            ),
            ("/scopes", json!([]), "at least one scope"),
            (
                "/scopes",
                json!(["registry:read", "registry:read"]),
                "repeat",
            ),
            ("/scopes", json!(["has space"]), "scope-tokens"),
            (
                "/clientAssertionAudience",
                json!(" "),
                "audience must not be empty",
            ),
            (
                "/tokenEndpoint",
                json!("http://idp.example.test/token"),
                "HTTPS",
            ),
            (
                "/tokenEndpoint",
                json!("https://idp.example.test/token#top"),
                "fragment",
            ),
            ("/baseUrl", json!("http://breg.example.test"), "HTTPS"),
            (
                "/baseUrl",
                json!("https://breg.example.test/?view=all"),
                "query",
            ),
            (
                "/baseUrl",
                json!("https://breg.example.test/#top"),
                "fragment",
            ),
            (
                "/baseUrl",
                json!("https://breg.example.test//api"),
                "empty segment",
            ),
            (
                "/delegatedDisplayExchange/tokenEndpoint",
                json!("http://idp.example.test/token"),
                "HTTPS",
            ),
            (
                "/delegatedDisplayExchange/clientAssertionAudience",
                json!(""),
                "audience must not be empty",
            ),
            (
                "/delegatedDisplayExchange/resource",
                json!("registry"),
                "absolute URI",
            ),
            (
                "/delegatedDisplayExchange/resource",
                json!("urn:example:registry two"),
                "whitespace",
            ),
            ("/delegatedDisplayExchange/scopes", json!([]), "1..=128"),
            (
                "/delegatedDisplayExchange/scopes",
                json!(["registry:\"quoted\""]),
                "scope-tokens",
            ),
            (
                "/delegatedDisplayExchange/generation",
                json!(""),
                "generation",
            ),
        ] {
            let mut binding = offline_binding();
            binding["delegatedDisplayExchange"] = delegated_exchange();
            let mut target = &mut binding;
            for segment in member.split('/').skip(1) {
                target = &mut target[segment];
            }
            *target = value.clone();
            let refusal =
                offline_check(binding).expect_err(&format!("{member} {value} was accepted"));
            assert_eq!(refusal.member, member, "{value}: {refusal:?}");
            assert!(
                refusal.reason.contains(rule),
                "{member} {value}: {refusal:?}"
            );
            if let Some(text) = value.as_str().filter(|text| text.trim().len() > 1) {
                assert!(!refusal.reason.contains(text), "{member}: {refusal:?}");
            }
        }
    }

    #[test]
    fn delegated_display_exchange_is_explicit_and_redacted() {
        let binding: BregBinding = serde_json::from_value(json!({
            "baseUrl": "https://breg.example.test",
            "statusProfile": "casework-review-status",
            "tokenEndpoint": "https://idp.example.test/token",
            "clientIdRef": "secret:file/status-client-id",
            "clientAssertionKeyRef": "secret:file/status-client-key",
            "delegatedDisplayExchange": {
                "tokenEndpoint": "https://idp.example.test/token",
                "clientIdRef": "secret:file/source-client-id",
                "clientAssertionKeyRef": "secret:file/source-client-key",
                "clientAssertionAudience": "https://idp.example.test",
                "resource": "urn:casework:facility-breg",
                "scopes": ["registry:proposal:review"],
                "generation": "casework-source-v1"
            }
        }))
        .expect("the dedicated source exchange binding parses");
        let delegated = binding
            .delegated_display_exchange
            .as_ref()
            .expect("delegated exchange is opt in");
        assert_eq!(delegated.client_id_ref, "secret:file/source-client-id");
        assert_eq!(delegated.resource, "urn:casework:facility-breg");
        assert_eq!(delegated.scopes, ["registry:proposal:review"]);
        let debug = format!("{binding:?} {delegated:?}");
        for hidden in [
            "source-client-id",
            "source-client-key",
            "idp.example.test",
            "urn:casework:facility-breg",
            "casework-source-v1",
        ] {
            assert!(!debug.contains(hidden), "Debug exposed {hidden}");
        }
    }
}
