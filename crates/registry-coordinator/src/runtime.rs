// SPDX-License-Identifier: Apache-2.0
//! Shared strict configuration loading and deployment policy.

use crate::{CoordinatorError, Result};
use registry_breg_client::BRegRecordOptions;
use registry_platform_config::{
    DatabaseConfig, RemovedKey, RuntimeConfigLoader, RuntimeEnvelope, RuntimeFileCheck,
    SecretProvider, SecretProvidersConfig, SecretReference,
};
use registry_platform_httputil::{
    valid_resource_uri, valid_scope_token, validate_requested_scopes, ServiceBaseUrl,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use std::{collections::BTreeMap, path::Path};
use url::{Host, Url};
use zeroize::Zeroizing;

pub const API_VERSION: &str = "id.registrystack.org/formats/coordinator/runtime/v1alpha1";
pub const KIND: &str = "CoordinatorRuntimeConfig";

const REMOVED_KEYS: &[RemovedKey] = &[RemovedKey {
    path: "deployment.authentication.jwksSource.kind",
    replacement: "Write `deployment.authentication.jwksSource.type` with the same value.",
}];

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Product {
    Breg,
    Casework,
    Messaging,
    Scheduling,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskAuthorityConfig {
    #[serde(deserialize_with = "endpoint")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub base_url: Url,
    #[serde(deserialize_with = "external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub issuer: String,
    #[serde(deserialize_with = "external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub subject: String,
    #[serde(deserialize_with = "external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub exchange_audience: String,
    #[serde(deserialize_with = "external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub bootstrap_resource: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationConfig {
    #[serde(deserialize_with = "endpoint")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub token_endpoint: Url,
    #[serde(deserialize_with = "external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "optional_external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::ExternalId>")
    )]
    pub client_assertion_audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_authority: Option<TaskAuthorityConfig>,
    pub signing_key_ref: SecretReference,
    #[serde(deserialize_with = "external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub resource: String,
    #[serde(deserialize_with = "unique_strings")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<registry_platform_yaml::ExternalId>",
            length(min = 1, max = 32)
        )
    )]
    pub scopes: Vec<String>,
}

impl AuthorizationConfig {
    pub(crate) fn findings(
        &self,
        field: &str,
        secrets: Option<&SecretProvidersConfig>,
    ) -> Vec<CoordinatorError> {
        let mut errors = Vec::new();
        check_endpoint(&self.token_endpoint).map_err(|_| config_error(&format!("{field}.tokenEndpoint"), "use an HTTPS token endpoint or explicit loopback HTTP IP URL without credentials, query or fragment")).unwrap_or_else(|error| errors.push(error));
        if self.client_id.trim().is_empty() || self.client_id.len() > 256 {
            errors.push(config_error(
                &format!("{field}.clientId"),
                "supply a bounded client identity registered with the configured issuer",
            ));
        }
        if !valid_resource_uri(&self.resource) {
            errors.push(config_error(&format!("{field}.resource"),
                    "declare one bounded absolute resource URI without credentials, whitespace or fragment"));
        }
        if self
            .client_assertion_audience
            .as_ref()
            .is_some_and(|audience| !valid_resource_uri(audience))
        {
            errors.push(config_error(
                &format!("{field}.clientAssertionAudience"),
                "declare the issuer's bounded absolute client assertion audience URI",
            ));
        }
        for (index, scope) in self.scopes.iter().enumerate() {
            if !valid_scope_token(scope) {
                errors.push(config_error(&format!("{field}.scopes[{index}]"),
                        "declare one OAuth scope token per item, without whitespace or control characters"));
            }
        }
        validate_requested_scopes(&self.scopes)
            .map_err(|error| config_error(&format!("{field}.scopes"), &error.to_string()))
            .unwrap_or_else(|error| errors.push(error));
        if self.signing_key_ref.provider() != SecretProvider::File {
            errors.push(config_error(
                &format!("{field}.signingKeyRef"),
                "use secret:file/name for the client signing key",
            ));
        }
        if let Some(secrets) = secrets {
            errors.extend(self.secret_reference_finding(field, secrets));
        }
        errors
    }

    fn secret_reference_finding(
        &self,
        field: &str,
        secrets: &SecretProvidersConfig,
    ) -> Option<CoordinatorError> {
        secrets
            .check_reference(
                &format!("{field}.signingKeyRef"),
                self.signing_key_ref.as_str(),
            )
            .err()
            .map(|_| {
                config_error(
                    &format!("{field}.signingKeyRef"),
                    "enable secretProviders.file for the client signing key",
                )
            })
    }
}

/// One logical connection namespace. The discriminator selects its complete
/// deployment contract; a connection cannot borrow another variant's authority.
#[derive(Clone, Deserialize)]
#[serde(remote = "Self", rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum ConnectionConfig {
    Breg(BregConnectionConfig),
    CaseworkReviewProducer(CaseworkConnectionConfig),
    Messaging(MessagingConnectionConfig),
    Scheduling(Box<SchedulingConnectionConfig>),
    ExternalHttp(crate::external_http::ExternalHttpConfig),
    Evaluation(crate::decision::DecisionConfig),
}
registry_platform_yaml::tagged_union!(ConnectionConfig);

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BregConnectionConfig {
    #[serde(deserialize_with = "endpoint")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub base_url: Url,
    pub authorization: AuthorizationConfig,
    #[serde(deserialize_with = "external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub profile: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessagingConnectionConfig {
    #[serde(deserialize_with = "endpoint")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub base_url: Url,
    pub authorization: AuthorizationConfig,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingConnectionConfig {
    #[serde(deserialize_with = "endpoint")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub base_url: Url,
    pub authorization: AuthorizationConfig,
    /// Ordinary receipt reads under the original owner, without taskAuthority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_authorization: Option<AuthorizationConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkConnectionConfig {
    #[serde(deserialize_with = "endpoint")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub base_url: Url,
    pub authorization: AuthorizationConfig,
    #[serde(deserialize_with = "external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub profile: String,
    #[serde(deserialize_with = "local")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub producer: String,
    /// Authenticated minimized wake-ups; omission uses polling only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<ReviewCompletionConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(extend("default" = DEFAULT_RESULT_CHECK_SECONDS)))]
    pub result_check_seconds: Option<registry_platform_yaml::BoundedU32<60, 86_400>>,
}

pub const DEFAULT_RESULT_CHECK_SECONDS: u32 = 900;

/// A borrowed adapter view, never a second decoded configuration model.
pub struct ProductBinding<'a> {
    pub product: Product,
    pub base_url: &'a Url,
    pub authorization: &'a AuthorizationConfig,
    pub observation_authorization: Option<&'a AuthorizationConfig>,
    pub profile: Option<&'a String>,
    pub producer: Option<&'a String>,
    pub completion: Option<&'a ReviewCompletionConfig>,
    pub result_check_seconds: Option<registry_platform_yaml::BoundedU32<60, 86_400>>,
}

impl ConnectionConfig {
    pub fn product_binding(&self) -> Option<ProductBinding<'_>> {
        let (
            product,
            base_url,
            authorization,
            observation_authorization,
            profile,
            producer,
            completion,
            result_check_seconds,
        ) = match self {
            Self::Breg(c) => (
                Product::Breg,
                &c.base_url,
                &c.authorization,
                None,
                Some(&c.profile),
                None,
                None,
                None,
            ),
            Self::Messaging(c) => (
                Product::Messaging,
                &c.base_url,
                &c.authorization,
                None,
                None,
                None,
                None,
                None,
            ),
            Self::Scheduling(c) => (
                Product::Scheduling,
                &c.base_url,
                &c.authorization,
                c.observation_authorization.as_ref(),
                None,
                None,
                None,
                None,
            ),
            Self::CaseworkReviewProducer(c) => (
                Product::Casework,
                &c.base_url,
                &c.authorization,
                None,
                Some(&c.profile),
                Some(&c.producer),
                c.completion.as_ref(),
                c.result_check_seconds,
            ),
            Self::ExternalHttp(_) | Self::Evaluation(_) => return None,
        };
        Some(ProductBinding {
            product,
            base_url,
            authorization,
            observation_authorization,
            profile,
            producer,
            completion,
            result_check_seconds,
        })
    }

    pub fn external_http(&self) -> Option<&crate::external_http::ExternalHttpConfig> {
        match self {
            Self::ExternalHttp(config) => Some(config),
            _ => None,
        }
    }

    pub fn decision(&self) -> Option<&crate::decision::DecisionConfig> {
        match self {
            Self::Evaluation(config) => Some(config),
            _ => None,
        }
    }

    pub fn authorization(&self) -> Option<&AuthorizationConfig> {
        self.product_binding().map(|b| b.authorization)
    }

    pub fn authorization_mut(&mut self) -> Option<&mut AuthorizationConfig> {
        match self {
            Self::Breg(c) => Some(&mut c.authorization),
            Self::Messaging(c) => Some(&mut c.authorization),
            Self::Scheduling(c) => Some(&mut c.authorization),
            Self::CaseworkReviewProducer(c) => Some(&mut c.authorization),
            Self::ExternalHttp(_) | Self::Evaluation(_) => None,
        }
    }

    pub fn result_check_seconds(&self) -> u32 {
        self.product_binding()
            .and_then(|b| b.result_check_seconds)
            .map_or(
                DEFAULT_RESULT_CHECK_SECONDS,
                registry_platform_yaml::BoundedU32::get,
            )
    }

    fn interface(&self) -> &'static str {
        match self {
            Self::Breg(_) => "breg",
            Self::CaseworkReviewProducer(_) => "casework",
            Self::Messaging(_) => "messaging",
            Self::Scheduling(_) => "scheduling",
            Self::ExternalHttp(_) => "external-http",
            Self::Evaluation(_) => "evaluation",
        }
    }
}

impl Serialize for ConnectionConfig {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let (kind, value) = match self {
            Self::Breg(c) => ("breg", serde_json::to_value(c)),
            Self::CaseworkReviewProducer(c) => {
                ("casework-review-producer", serde_json::to_value(c))
            }
            Self::Messaging(c) => ("messaging", serde_json::to_value(c)),
            Self::Scheduling(c) => ("scheduling", serde_json::to_value(c)),
            Self::ExternalHttp(c) => ("external-http", serde_json::to_value(c)),
            Self::Evaluation(c) => ("evaluation", serde_json::to_value(c)),
        };
        let mut value = value.map_err(serde::ser::Error::custom)?;
        value["type"] = json!(kind);
        value.serialize(serializer)
    }
}

/// How Casework's completion event for this connection's review requests is
/// authenticated. The event only wakes a waiting run: the run reads the result
/// itself with its own producer authorization.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCompletionConfig {
    /// The recipientBinding the Casework project names for this producer's
    /// completion destination: 1 to 256 printable ASCII characters without
    /// spaces. Casework sends it in the registry-recipient-binding header.
    #[cfg_attr(
        feature = "schema",
        schemars(extend("pattern" = "^[!-~]{1,256}$", "minLength" = 1, "maxLength" = 256))
    )]
    pub recipient_binding: String,
    /// The bearer token Casework's completion destination sends.
    pub bearer_token_ref: SecretReference,
}

/// A completion recipient binding as Casework accepts one.
pub(crate) fn valid_recipient_binding(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// A Casework access profile as the Casework client sends one.
fn valid_casework_profile(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Optional trusted event producers keyed by the logical IDs used in Workflow triggers.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "event_source_keys"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "BTreeMap<registry_platform_yaml::LocalId, crate::event_trigger::EventSourceConfig>", extend("maxProperties" = 16)))]
    pub event_sources: BTreeMap<String, crate::event_trigger::EventSourceConfig>,
    pub secret_providers: SecretProvidersConfig,
    #[serde(serialize_with = "serialize_database")]
    pub database: DatabaseConfig,
    #[cfg_attr(feature="schema", schemars(extend("pattern"="^coordinator_[a-z0-9_]*$", "maxLength"=60)))]
    pub namespace: String,
    /// Stricter deployment spacing for every product completion observation.
    #[serde(default = "minimum_observation_interval")]
    pub minimum_observation_interval_seconds: registry_platform_yaml::BoundedU32<30, 86_400>,
    /// One to sixteen named bindings, each selecting its own typed interface.
    #[serde(deserialize_with = "connection_keys")]
    #[cfg_attr(feature = "schema", schemars(with = "BTreeMap<registry_platform_yaml::LocalId, ConnectionConfig>", extend("minProperties" = 1, "maxProperties" = 16)))]
    pub connections: BTreeMap<String, ConnectionConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<crate::deployment::DeploymentConfig>,
}

fn minimum_observation_interval() -> registry_platform_yaml::BoundedU32<30, 86_400> {
    registry_platform_yaml::BoundedU32::new(30).expect("bounded default")
}

/// The shared reader checks the envelope before directly decoding RuntimeConfig.
impl RuntimeConfig {
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(RuntimeEnvelope {
            api_version: API_VERSION,
            kind: KIND,
        })
        .removed_keys(REMOVED_KEYS)
    }

    /// Serialize the complete configuration envelope without resolving credentials.
    pub fn document(&self) -> Result<serde_json::Value> {
        self.validate()?;
        let mut document = serde_json::to_value(self)
            .map_err(|_| config_error("", "correct the runtime document model"))?;
        document["apiVersion"] = json!(API_VERSION);
        document["kind"] = json!(KIND);
        Ok(document)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let checked = Self::check_file(path, true);
        if checked
            .diagnostics
            .iter()
            .any(|d| d.severity == registry_platform_yaml::Severity::Error)
        {
            return Err(CoordinatorError::from_diagnostics(&checked.diagnostics));
        }
        checked
            .loaded
            .map(|loaded| loaded.config)
            .ok_or_else(|| config_error("", "correct the runtime document"))
    }

    /// Check syntax, references and offline values without reading secret material.
    pub fn check_file(path: &Path, substitute: bool) -> RuntimeFileCheck<Self> {
        Self::check_file_with(path, substitute, |_, _| Vec::new())
    }

    /// Check one runtime file and include product diagnostics that depend on
    /// an already decoded companion before applying the file's single report
    /// budget. The callback is never invoked after a decode refusal.
    pub(crate) fn check_file_with(
        path: &Path,
        substitute: bool,
        additional: impl FnOnce(
            &RuntimeFileCheck<Self>,
            &Self,
        ) -> Vec<registry_platform_yaml::Diagnostic>,
    ) -> RuntimeFileCheck<Self> {
        let mut checked = Self::loader().check_offline::<Self>(path, substitute, stand_in);
        let mut diagnostics = checked.loaded.as_ref().map_or_else(Vec::new, |loaded| {
            runtime_id_collision_diagnostics(&checked, &loaded.config)
        });
        if let Some(loaded) = &checked.loaded {
            for error in loaded.config.findings() {
                let pointer = pointer(error.field.as_deref().unwrap_or(""));
                if !checked.defers_within(&pointer) {
                    diagnostics.push(
                        checked.error_at(
                            KIND,
                            &error.code,
                            &pointer,
                            error.message,
                            error
                                .suggested_action
                                .unwrap_or_else(|| "Correct the named runtime member.".into()),
                        ),
                    );
                }
            }
            diagnostics.extend(additional(&checked, &loaded.config));
        }
        checked.diagnostics = checked.report_with(KIND, diagnostics).into_diagnostics();
        checked
    }

    pub fn validate(&self) -> Result<()> {
        if !registry_platform_yaml::lookalike_local_id_pairs(
            self.connections.keys().map(String::as_str),
        )
        .is_empty()
        {
            return Err(config_error(
                "connections",
                "rename separator-lookalike connection identifiers",
            ));
        }
        if !registry_platform_yaml::lookalike_local_id_pairs(
            self.event_sources.keys().map(String::as_str),
        )
        .is_empty()
        {
            return Err(config_error(
                "eventSources",
                "rename separator-lookalike event source identifiers",
            ));
        }
        match self.findings().into_iter().next() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn findings(&self) -> Vec<CoordinatorError> {
        let mut errors =
            crate::event_trigger::source_findings(&self.event_sources, &self.secret_providers);
        self.secret_providers
            .check()
            .map_err(|_| config_error("secretProviders", "declare valid shared secret providers"))
            .unwrap_or_else(|error| errors.push(error));
        for (field, reference) in self.database.references() {
            self.secret_providers
                .check_reference(field, reference)
                .map_err(|_| {
                    config_error(
                        field,
                        "enable the provider named by the database secret reference",
                    )
                })
                .unwrap_or_else(|error| errors.push(error));
        }
        if self.database.test_only_plaintext {
            errors.push(config_error("database.testOnlyPlaintext", "remove testOnlyPlaintext; only explicit development-loopback deployment permits local plaintext database transport"));
        }
        if !self.namespace.starts_with("coordinator_")
            || self.namespace.len() > 60
            || !self
                .namespace
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            errors.push(config_error(
                "namespace",
                "use a coordinator_ namespace with lowercase letters, digits or underscores",
            ));
        }
        let connection_count = self.connections.len();
        if connection_count == 0 || connection_count > 16 {
            errors.push(config_error(
                "connections",
                "declare between one and sixteen typed connections",
            ));
        }
        if let Some(deployment) = &self.deployment {
            errors.extend(deployment.findings(&self.secret_providers));
        }
        let mut recipients = std::collections::BTreeSet::new();
        for (name, binding) in &self.connections {
            if name.parse::<registry_platform_yaml::LocalId>().is_err() {
                errors.push(config_error(
                    "connections",
                    "use bounded connection names with letters, digits, hyphens or underscores",
                ));
            }
            let field = format!("connections.{name}");
            let Some(binding) = binding.product_binding() else {
                if let Some(binding) = binding.external_http() {
                    errors.extend(binding.findings(&field));
                    if let Some(auth) = &binding.authorization {
                        errors.extend(auth.secret_reference_finding(
                            &format!("{field}.authorization"),
                            &self.secret_providers,
                        ));
                    }
                } else if let Some(binding) = binding.decision() {
                    errors.extend(binding.findings(&field));
                    if let Some(reference) = binding.token_ref() {
                        let member = format!("{field}.authorization.bearer.tokenRef");
                        if self
                            .secret_providers
                            .check_reference(&member, reference.as_str())
                            .is_err()
                        {
                            errors.push(config_error(&member, "enable the shared secret provider named by the evaluation credential reference"));
                        }
                    }
                }
                continue;
            };
            check_endpoint(binding.base_url).map_err(|_| config_error(&format!("{field}.baseUrl"), "use an HTTPS endpoint or explicit loopback HTTP IP URL without credentials, query or fragment")).map(|_| ()).unwrap_or_else(|error| errors.push(error));
            ServiceBaseUrl::new(binding.base_url.clone())
                .map(|_| ())
                .map_err(|_| {
                    config_error(
                        &format!("{field}.baseUrl"),
                        "use a service base URL without empty interior path segments",
                    )
                })
                .unwrap_or_else(|error| errors.push(error));
            if binding.product == Product::Scheduling
                && binding.authorization.task_authority.is_some()
                && binding.observation_authorization.is_none()
            {
                errors.push(config_error(
                    &format!("{field}.observationAuthorization"),
                    "configure ordinary receipt-read scopes with the primary token endpoint, client and resource, and no taskAuthority; recovery must remain available after the original grant expires",
                ));
            }
            if let Some(observation) = &binding.observation_authorization {
                if binding.product != Product::Scheduling
                    || binding.authorization.task_authority.is_none()
                {
                    errors.push(config_error(&format!("{field}.observationAuthorization"),
                        "remove observationAuthorization; only task-bound Scheduling receipt recovery consumes this identity"));
                }
                let primary = &binding.authorization;
                if observation.token_endpoint != primary.token_endpoint
                    || observation.client_id != primary.client_id
                    || observation.resource != primary.resource
                    || observation.task_authority.is_some()
                    || observation
                        .client_assertion_audience
                        .as_ref()
                        .is_some_and(|a| !valid_resource_uri(a))
                    || observation.signing_key_ref.provider() != SecretProvider::File
                {
                    errors.push(config_error(&format!("{field}.observationAuthorization"),
                        "use the primary endpoint, client and resource, bounded observation scopes and no taskAuthority"));
                }
                validate_requested_scopes(&observation.scopes)
                    .map_err(|error| {
                        config_error(
                            &format!("{field}.observationAuthorization.scopes"),
                            &error.to_string(),
                        )
                    })
                    .unwrap_or_else(|error| errors.push(error));
                self.secret_providers
                    .check_reference(
                        &format!("{field}.observationAuthorization.signingKeyRef"),
                        observation.signing_key_ref.as_str(),
                    )
                    .map_err(|_| {
                        config_error(
                            &format!("{field}.observationAuthorization.signingKeyRef"),
                            "enable secretProviders.file for the observation client signing key",
                        )
                    })
                    .unwrap_or_else(|error| errors.push(error));
            }
            let auth = &binding.authorization;
            errors.extend(auth.findings(
                &format!("{field}.authorization"),
                Some(&self.secret_providers),
            ));
            if let Some(task) = &auth.task_authority {
                if !matches!(binding.product, Product::Breg | Product::Scheduling) {
                    errors.push(config_error(
                        &format!("{field}.authorization.taskAuthority"),
                        "taskAuthority is supported only for BReg or Scheduling connections",
                    ));
                }
                check_endpoint(&task.base_url)
                    .map_err(|_| {
                        config_error(
                            &format!("{field}.authorization.taskAuthority.baseUrl"),
                            "use an HTTPS Casework endpoint or explicit loopback HTTP IP URL",
                        )
                    })
                    .unwrap_or_else(|error| errors.push(error));
                ServiceBaseUrl::new(task.base_url.clone())
                    .map(|_| ())
                    .map_err(|_| {
                        config_error(
                            &format!("{field}.authorization.taskAuthority.baseUrl"),
                            "use a Casework service base URL without empty interior path segments",
                        )
                    })
                    .unwrap_or_else(|error| errors.push(error));
                for (member, value) in [
                    ("issuer", &task.issuer),
                    ("subject", &task.subject),
                    ("exchangeAudience", &task.exchange_audience),
                    ("bootstrapResource", &task.bootstrap_resource),
                ] {
                    if value.trim().is_empty()
                        || value.len() > 512
                        || value.chars().any(char::is_control)
                        || (member != "subject" && !valid_resource_uri(value))
                    {
                        errors.push(config_error(
                            &format!("{field}.authorization.taskAuthority.{member}"),
                            "declare a bounded Casework identity and exchange setting without control characters",
                        ));
                    }
                }
            }
            match binding.product {
                Product::Breg
                    if binding.profile.as_ref().is_none_or(|p| {
                        BRegRecordOptions::default()
                            .access_profile(p.as_str())
                            .is_err()
                    }) =>
                {
                    errors.push(config_error(
                        &format!("{field}.profile"),
                        "declare a bounded BReg access profile accepted by the BReg client",
                    ));
                }
                Product::Casework => {
                    if binding
                        .profile
                        .is_none_or(|profile| !valid_casework_profile(profile))
                    {
                        errors.push(config_error(
                            &format!("{field}.profile"),
                            "declare the bounded Casework access profile the review producer authenticates with",
                        ));
                    }
                    if binding.producer.is_none() {
                        errors.push(config_error(
                            &format!("{field}.producer"),
                            "declare the review producer id the Casework project lists under reviewProducers",
                        ));
                    }
                    if let Some(completion) = &binding.completion {
                        let member = format!("{field}.completion.recipientBinding");
                        if !valid_recipient_binding(&completion.recipient_binding) {
                            errors.push(config_error(
                                &member,
                                "write the recipientBinding the Casework producer's completion names: 1 to 256 printable ASCII characters without spaces",
                            ));
                        } else if !recipients.insert(completion.recipient_binding.as_str()) {
                            errors.push(config_error(
                                &member,
                                "use a recipientBinding no other Casework connection declares, so every completion event names one connection",
                            ));
                        }
                        let member = format!("{field}.completion.bearerTokenRef");
                        if self
                            .secret_providers
                            .check_reference(&member, completion.bearer_token_ref.as_str())
                            .is_err()
                        {
                            errors.push(config_error(
                                &member,
                                "enable the secretProviders entry named by the completion token reference",
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        errors
    }

    pub fn validate_workflow(&self, workflow: &crate::definition::Workflow) -> Result<()> {
        for (id, trigger) in &workflow.event_triggers {
            if !self.event_sources.contains_key(&trigger.source) {
                return Err(config_error(
                    &format!("eventSources.{}", trigger.source),
                    &format!("configure the source named by event trigger {id}"),
                ));
            }
        }
        self.validate_workflow_effect_bindings(workflow)
    }

    /// Retained Runs require their effect bindings, independently of whether
    /// the event source that admitted them is still enabled for new starts.
    fn validate_workflow_effect_bindings(
        &self,
        workflow: &crate::definition::Workflow,
    ) -> Result<()> {
        for (name, interface) in &workflow.connections {
            if self
                .connections
                .get(name)
                .is_none_or(|binding| binding.interface() != interface)
            {
                return Err(CoordinatorError::new("workflow-binding", "the declared workflow connection has no matching interface binding")
                    .at("runtime.yaml", pointer(&format!("connections.{name}")))
                    .suggest("Configure the same logical name and required connection type in runtime.yaml before admission."));
            }
        }
        for (name, step) in &workflow.steps {
            if let crate::definition::Step::Call { call, .. } = step {
                if call.operation == crate::protocol::Operation::InvokeBregAction
                    && self
                        .connections
                        .get(&call.connection)
                        .is_some_and(|binding| {
                            binding
                                .authorization()
                                .is_some_and(|auth| auth.task_authority.is_some())
                        })
                {
                    return Err(CoordinatorError::new("workflow-binding", "this BReg operation requires an explicitly permitted service profile")
                        .at("workflow.yaml", format!("/workflow/steps/{name}/operation"))
                        .suggest("Use a separately authorized BReg connection without taskAuthority for this operation; task authority cannot fall back to service authority."));
                }
                if call.operation.product() == "scheduling"
                    && call.operation.is_mutating()
                    && self
                        .connections
                        .get(&call.connection)
                        .is_some_and(|binding| {
                            binding
                                .authorization()
                                .is_some_and(|auth| auth.task_authority.is_none())
                        })
                {
                    return Err(CoordinatorError::new(
                        "workflow-binding",
                        "Scheduling commitments require task-bound Scheduling authorization",
                    )
                    .at("workflow.yaml", format!("steps.{name}.call"))
                    .suggest(format!(
                        "Configure connections.{}.authorization.taskAuthority in runtime.yaml before checking or activating this workflow.",
                        call.connection,
                    )));
                }
            }
        }
        Ok(())
    }

    /// Configured semantic identity only. No secret is resolved or endpoint contacted.
    pub fn binding_digest(&self) -> Result<String> {
        self.binding_digest_names(self.connections.keys().map(String::as_str))
    }

    /// Hash this workflow's effect bindings. Ingress removal cannot strand a
    /// retained Run, while active package validation still checks its sources.
    pub fn binding_digest_for(&self, workflow: &crate::definition::Workflow) -> Result<String> {
        self.validate_workflow_effect_bindings(workflow)?;
        self.binding_digest_names(workflow.connections.keys().map(String::as_str))
    }

    fn binding_digest_names<'a>(&self, names: impl Iterator<Item = &'a str>) -> Result<String> {
        self.validate()?;
        let mut identities = BTreeMap::new();
        for name in names {
            if let Some(binding) = self
                .connections
                .get(name)
                .and_then(ConnectionConfig::decision)
            {
                let mut identity = serde_json::to_value(binding).map_err(|_| {
                    config_error("connections", "correct the evaluation binding model")
                })?;
                if let Some(bearer) = identity["authorization"]
                    .get_mut("bearer")
                    .and_then(serde_json::Value::as_object_mut)
                {
                    bearer.remove("tokenRef");
                }
                identity["product"] = json!("decision");
                identity["abi"] = json!("coordinator-decision/v1");
                identities.insert(name, identity);
                continue;
            }
            if let Some(binding) = self
                .connections
                .get(name)
                .and_then(ConnectionConfig::external_http)
            {
                let mut identity = serde_json::to_value(binding).map_err(|_| {
                    config_error("connections", "correct the external binding model")
                })?;
                if let Some(auth) = identity
                    .get_mut("authorization")
                    .and_then(serde_json::Value::as_object_mut)
                {
                    auth.remove("signingKeyRef");
                    if !auth.contains_key("clientAssertionAudience") {
                        if let Some(endpoint) = auth.get("tokenEndpoint").cloned() {
                            auth.insert("clientAssertionAudience".into(), endpoint);
                        }
                    }
                    if let Some(scopes) = auth
                        .get_mut("scopes")
                        .and_then(serde_json::Value::as_array_mut)
                    {
                        scopes.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                    }
                }
                for member in ["paths", "queryParameters"] {
                    if let Some(values) = identity
                        .get_mut(member)
                        .and_then(serde_json::Value::as_array_mut)
                    {
                        values.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                    }
                }
                identity["product"] = json!("external-http");
                identity["abi"] = json!("coordinator-external-http/v1");
                identities.insert(name, identity);
                continue;
            }
            let binding = self.connections[name]
                .product_binding()
                .expect("validated product binding");
            let auth = &binding.authorization;
            let mut scopes = auth.scopes.clone();
            scopes.sort();
            let mut identity = json!({"product":binding.product,"baseUrl":binding.base_url,
                "clientId":auth.client_id,"tokenEndpoint":auth.token_endpoint,
                "clientAssertionAudience":auth.client_assertion_audience.as_deref().unwrap_or(auth.token_endpoint.as_str()),
                "resource":auth.resource,"scopes":scopes,"profile":binding.profile,"taskAuthority":auth.task_authority,"observationAuthorization":binding.observation_authorization.as_ref().map(|auth| json!({"tokenEndpoint":auth.token_endpoint,"clientId":auth.client_id,"resource":auth.resource,"clientAssertionAudience":auth.client_assertion_audience.as_deref().unwrap_or(auth.token_endpoint.as_str()),"scopes":({let mut s=auth.scopes.clone();s.sort();s})})),"abi":"coordinator-adapters/v1"});
            // Casework binds every submission to its producer. The completion
            // settings only decide how a waiting run is woken, so changing them
            // never strands an admitted run.
            if binding.product == Product::Casework {
                identity["producer"] = json!(binding.producer);
            }
            identities.insert(name, identity);
        }
        let value = json!({"connections":identities,"minimumObservationIntervalSeconds":self.minimum_observation_interval_seconds});
        let bytes = registry_platform_canonical_json::canonicalize_json(&value)
            .map_err(|_| config_error("connections", "correct the binding model"))?;
        Ok(registry_platform_config::sha256_uri(&bytes))
    }

    pub fn database_url(&self) -> Result<Zeroizing<String>> {
        let value = self
            .secret_providers
            .resolver()
            .map_err(|_| config_error("secretProviders", "correct the secret provider setup"))?
            .resolve(&self.database.runtime_url_ref)
            .map_err(|_| {
                config_error(
                    "database.runtimeUrlRef",
                    "make the referenced local database setting available",
                )
            })?;
        let text = std::str::from_utf8(value.expose_secret()).map_err(|_| {
            config_error(
                "database.runtimeUrlRef",
                "supply a UTF-8 PostgreSQL connection setting",
            )
        })?;
        Ok(Zeroizing::new(text.to_owned()))
    }
}

fn runtime_id_collision_diagnostics(
    checked: &RuntimeFileCheck<RuntimeConfig>,
    config: &RuntimeConfig,
) -> Vec<registry_platform_yaml::Diagnostic> {
    fn collisions<T>(
        checked: &RuntimeFileCheck<RuntimeConfig>,
        code: &str,
        pointer: &str,
        values: &BTreeMap<String, T>,
    ) -> Vec<registry_platform_yaml::Diagnostic> {
        let ids = values.keys().map(String::as_str).collect::<Vec<_>>();
        registry_platform_yaml::lookalike_local_id_pairs(ids.iter().copied())
            .into_iter()
            .map(|(first, second)| {
                let first_pointer = format!(
                    "{pointer}/{}",
                    registry_platform_yaml::escape_pointer_segment(ids[first])
                );
                let second_pointer = format!(
                    "{pointer}/{}",
                    registry_platform_yaml::escape_pointer_segment(ids[second])
                );
                let mut diagnostic = checked.error_at_key(
                    KIND,
                    code,
                    &second_pointer,
                    format!(
                        "local identifiers `{}` and `{}` differ only by `-` versus `_`",
                        ids[first], ids[second]
                    ),
                    "Rename one identifier so the two definitions remain distinct after separator normalization.",
                );
                checked.add_related_key(
                    &mut diagnostic,
                    &first_pointer,
                    format!("the other definition is `{}`", ids[first]),
                );
                diagnostic
            })
            .collect()
    }

    let mut diagnostics = collisions(
        checked,
        "coordinator.runtime.connection-id-collision",
        "/connections",
        &config.connections,
    );
    diagnostics.extend(collisions(
        checked,
        "coordinator.runtime.event-source-id-collision",
        "/eventSources",
        &config.event_sources,
    ));
    diagnostics
}

fn config_error(field: &str, action: &str) -> CoordinatorError {
    CoordinatorError::new(
        "coordinator.runtime-config.refused",
        "the runtime configuration was refused",
    )
    .at("runtime.yaml", pointer(field))
    .suggest(action)
}
fn check_endpoint(url: &Url) -> Result<()> {
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if !(url.scheme() == "https" || (loopback && url.scheme() == "http"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(config_error(
            "connections",
            "use HTTPS endpoints or explicit loopback HTTP IP URLs",
        ));
    }
    Ok(())
}

#[cfg(feature = "schema")]
pub fn runtime_schema() -> Result<String> {
    let mut schema = serde_json::to_value(schemars::schema_for!(RuntimeConfig))
        .map_err(|_| config_error("", "restore the runtime schema generator"))?;
    let shared: serde_json::Value = serde_json::from_str(
        &registry_platform_config::schema::shared_blocks_document()
            .map_err(|_| config_error("", "restore the shared schema generator"))?,
    )
    .map_err(|_| config_error("", "restore the shared schema generator"))?;
    let shared_names = shared["$defs"].as_object().unwrap();
    for (key, value) in schema.as_object_mut().unwrap() {
        if key == "$defs" {
            for (name, definition) in value.as_object_mut().unwrap() {
                if !shared_names.contains_key(name) {
                    refuse_null(definition);
                }
            }
        } else {
            refuse_null(value);
        }
    }
    schema["$defs"]["LocalId"] = serde_json::to_value(
        <registry_platform_yaml::LocalId as schemars::JsonSchema>::json_schema(
            &mut schemars::SchemaGenerator::default(),
        ),
    )
    .map_err(|_| config_error("", "restore the identifier schema generator"))?;
    schema["properties"]["connections"] = json!({"type":"object", "minProperties":1, "maxProperties":16,
        "description":"Named deployment bindings with one explicit type per connection.",
        "propertyNames":{"$ref":"#/$defs/LocalId"}, "additionalProperties":{"$ref":"#/$defs/ConnectionConfig"}});
    schema["properties"]["eventSources"] = json!({"type":"object", "maxProperties":16,
        "description":"Optional trusted event producers keyed by the logical IDs used in Workflow triggers.",
        "propertyNames":{"$ref":"#/$defs/LocalId"}, "additionalProperties":{"$ref":"#/$defs/EventSourceConfig"}});
    schema["properties"]["database"] = json!({"allOf":[
        {"$ref":"#/$defs/DatabaseConfig"},
        {"properties":{"testOnlyPlaintext":{"const":false}}}
    ], "unevaluatedProperties":false});
    // Distinct roots and digests per pin, and one package per workflow id, are
    // load-time checks: JSON Schema compares whole items only.
    schema["$defs"]["DeploymentConfig"]["properties"]["packages"] = json!({
        "type":"array", "minItems":1, "maxItems":crate::deployment::MAX_WORKFLOWS, "uniqueItems":true,
        "description":"One pinned package per workflow. List each package root and digest once.",
        "items":{"allOf":[
            {"$ref":"#/$defs/PackageConfig"},
            {"required":["expectedDigest"], "properties":{"expectedDigest":{"$ref":"#/$defs/Digest"}}}
        ], "unevaluatedProperties":false}
    });
    schema["$defs"]["ClientPolicy"]["properties"]["workflows"]["items"] = json!({
        "$ref":"#/$defs/ExternalId", "maxLength":64, "pattern":"^[A-Za-z0-9_-]+$"
    });
    schema["$defs"]["AuthorizationConfig"]["properties"]["clientId"]["maxLength"] = json!(256);
    schema["$defs"]["AccessConfig"]["properties"]["scopeClaim"]["maxLength"] = json!(128);
    schema["$defs"]["AccessConfig"]["properties"]["policies"] = json!({
        "type":"object", "minProperties":1, "maxProperties":64,
        "propertyNames":{"$ref":"#/$defs/ExternalId", "maxLength":128},
        "additionalProperties":{"$ref":"#/$defs/ClientPolicy"}
    });
    schema["$defs"]["AccessConfig"]["properties"]["assertionIssuers"] =
        shared["$defs"]["OidcClientsConfig"]["properties"]["assertionIssuers"].clone();
    schema["$defs"]["ClientPolicy"]["allOf"] = json!([{
        "if":{"properties":{"actions":{"items":{"enum":["doctor", "restore-hold", "release-restore-hold", "release-admission-hold", "complete-execution-recovery", "retain"]}}}},
        "then":{"not":{"required":["workflows"]}},
        "else":{"required":["workflows"]}
    }]);
    schema["$id"] = json!(
        "https://id.registrystack.org/schemas/coordinator/runtime/runtime.v1alpha1.schema.json"
    );
    schema["properties"]["apiVersion"] = json!({"type":"string", "const":API_VERSION});
    schema["properties"]["kind"] = json!({"type":"string", "const":KIND});
    schema["required"]
        .as_array_mut()
        .unwrap()
        .extend([json!("apiVersion"), json!("kind")]);
    // Only task-bound Scheduling consumes an observation identity. Its
    // ordinary receipt read remains available after the original grant expires.
    let scheduling = schema["$defs"]["ConnectionConfig"]["oneOf"]
        .as_array_mut()
        .and_then(|variants| {
            variants
                .iter_mut()
                .find(|variant| variant["properties"]["type"]["const"] == "scheduling")
        })
        .ok_or_else(|| config_error("", "restore the typed connection schema"))?;
    scheduling["allOf"] = json!([{
        "if": {"properties": {"authorization": {
            "required": ["taskAuthority"], "properties": {"taskAuthority": {"type": "object"}}
        }}},
        "then": {"required": ["observationAuthorization"]},
        "else": {"not": {"required": ["observationAuthorization"]}}
    }]);
    let mut text = serde_json::to_string_pretty(&schema)
        .map_err(|_| config_error("/", "restore the runtime schema generator"))?;
    text.push('\n');
    Ok(text)
}

fn endpoint<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Url, D::Error> {
    let value = registry_platform_yaml::Url::deserialize(d)?;
    Url::parse(value.as_str()).map_err(serde::de::Error::custom)
}

pub(crate) fn unique_strings<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<String>, D::Error> {
    registry_platform_yaml::UniqueList::<registry_platform_yaml::ExternalId>::deserialize(d).map(
        |items| {
            items
                .into_vec()
                .into_iter()
                .map(registry_platform_yaml::ExternalId::into_string)
                .collect()
        },
    )
}

fn connection_keys<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<String, ConnectionConfig>, D::Error> {
    BTreeMap::<registry_platform_yaml::LocalId, ConnectionConfig>::deserialize(d).map(|map| {
        map.into_iter()
            .map(|(key, value)| (key.into_string(), value))
            .collect()
    })
}

fn event_source_keys<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<String, crate::event_trigger::EventSourceConfig>, D::Error> {
    BTreeMap::<registry_platform_yaml::LocalId,crate::event_trigger::EventSourceConfig>::deserialize(d).map(|map|map.into_iter().map(|(id,source)|(id.into_string(),source)).collect())
}

pub(crate) fn key_version<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<u32, D::Error> {
    registry_platform_yaml::BoundedU32::<1, { u32::MAX }>::deserialize(d)
        .map(registry_platform_yaml::BoundedU32::get)
}

pub(crate) fn pointer(field: &str) -> String {
    if field.starts_with('/') {
        field.into()
    } else if field.is_empty() {
        String::new()
    } else {
        format!("/{}", field.replace(['.', '['], "/").replace(']', ""))
    }
}

fn stand_in(pointer: &str) -> &'static str {
    if pointer.ends_with("/baseUrl")
        || pointer.ends_with("/tokenEndpoint")
        || pointer.ends_with("/issuer")
    {
        "https://stand-in.invalid"
    } else if pointer.ends_with("/resource")
        || pointer.ends_with("/exchangeAudience")
        || pointer.ends_with("/bootstrapResource")
    {
        "urn:example:stand-in"
    } else if pointer.ends_with("/namespace") {
        "coordinator_stand_in"
    } else if pointer.ends_with("/auditFile") {
        "/stand-in/audit.jsonl"
    } else {
        registry_platform_config::DEFAULT_STAND_IN
    }
}

pub(crate) fn external<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    registry_platform_yaml::ExternalId::deserialize(d)
        .map(registry_platform_yaml::ExternalId::into_string)
}
pub(crate) fn optional_external<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    external(d).map(Some)
}
fn local<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    registry_platform_yaml::LocalId::deserialize(d)
        .map(registry_platform_yaml::LocalId::into_string)
}

#[cfg(feature = "schema")]
fn refuse_null(schema: &mut serde_json::Value) {
    use serde_json::Value;
    match schema {
        Value::Object(object) => {
            if object.get("default") == Some(&Value::Null) {
                object.remove("default");
            }
            if let Some(Value::Array(types)) = object.get_mut("type") {
                types.retain(|kind| kind != "null");
                if let [only] = types.as_slice() {
                    let only = only.clone();
                    object.insert("type".into(), only);
                }
            }
            if let Some(Value::Array(branches)) = object.get_mut("anyOf") {
                branches.retain(|branch| branch.get("type") != Some(&Value::from("null")));
                if let [only] = branches.as_slice() {
                    let only = only.clone();
                    object.remove("anyOf");
                    if let Value::Object(only) = only {
                        object.extend(only);
                    }
                }
            }
            object.values_mut().for_each(refuse_null);
        }
        Value::Array(items) => items.iter_mut().for_each(refuse_null),
        _ => {}
    }
}

fn serialize_database<S: serde::Serializer>(
    database: &DatabaseConfig,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(None)?;
    map.serialize_entry("runtimeUrlRef", &database.runtime_url_ref)?;
    map.serialize_entry("migrationUrlRef", &database.migration_url_ref)?;
    if let Some(reference) = &database.trusted_root_certificate_ref {
        map.serialize_entry("trustedRootCertificateRef", reference)?;
    }
    if database.test_only_plaintext {
        map.serialize_entry("testOnlyPlaintext", &true)?;
    }
    map.end()
}
