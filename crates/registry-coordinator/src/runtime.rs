// SPDX-License-Identifier: Apache-2.0
//! Shared strict configuration loading and controlled-pilot deployment policy.

use crate::{PocError, Result};
use registry_breg_client::BRegRecordOptions;
use registry_platform_config::{
    DatabaseConfig, RuntimeConfigLoader, RuntimeEnvelope, RuntimeFileCheck, SecretProvider,
    SecretProvidersConfig, SecretReference,
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

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Product {
    Breg,
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

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionConfig {
    pub product: Product,
    #[serde(deserialize_with = "endpoint")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub base_url: Url,
    pub authorization: AuthorizationConfig,
    /// Required for Scheduling connections with taskAuthority. Uses ordinary
    /// read scopes under the original receipt owner, without taskAuthority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_authorization: Option<AuthorizationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "optional_external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::ExternalId>")
    )]
    pub profile: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub secret_providers: SecretProvidersConfig,
    #[serde(serialize_with = "serialize_database")]
    pub database: DatabaseConfig,
    #[cfg_attr(feature="schema", schemars(extend("pattern"="^coordinator_[a-z0-9_]*$", "maxLength"=60)))]
    pub namespace: String,
    #[serde(deserialize_with = "connection_keys")]
    #[cfg_attr(feature = "schema", schemars(with = "BTreeMap<registry_platform_yaml::LocalId, ConnectionConfig>", extend("minProperties" = 1, "maxProperties" = 16)))]
    pub connections: BTreeMap<String, ConnectionConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<crate::deployment::DeploymentConfig>,
}

/// The shared reader checks the envelope before directly decoding RuntimeConfig.
impl RuntimeConfig {
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(RuntimeEnvelope {
            api_version: API_VERSION,
            kind: KIND,
        })
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
            return Err(PocError::from_diagnostics(&checked.diagnostics));
        }
        checked
            .loaded
            .map(|loaded| loaded.config)
            .ok_or_else(|| config_error("", "correct the runtime document"))
    }

    /// Check syntax, references and offline values without reading secret material.
    pub fn check_file(path: &Path, substitute: bool) -> RuntimeFileCheck<Self> {
        let mut checked = Self::loader().check_offline::<Self>(path, substitute, stand_in);
        if let Some(loaded) = &checked.loaded {
            for error in loaded.config.findings() {
                let pointer = pointer(error.field.as_deref().unwrap_or(""));
                if !checked.defers_within(&pointer) {
                    checked.diagnostics.push(
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
        }
        checked
    }

    pub fn validate(&self) -> Result<()> {
        match self.findings().into_iter().next() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn findings(&self) -> Vec<PocError> {
        let mut errors = Vec::new();
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
        if self.connections.is_empty() || self.connections.len() > 16 {
            errors.push(config_error(
                "connections",
                "declare between one and sixteen logical product connections",
            ));
        }
        if let Some(deployment) = &self.deployment {
            errors.extend(deployment.findings(&self.secret_providers));
        }
        for (name, binding) in &self.connections {
            if name.parse::<registry_platform_yaml::LocalId>().is_err() {
                errors.push(config_error(
                    "connections",
                    "use bounded connection names with letters, digits, hyphens or underscores",
                ));
            }
            let field = format!("connections.{name}");
            check_endpoint(&binding.base_url).map_err(|_| config_error(&format!("{field}.baseUrl"), "use an HTTPS endpoint or explicit loopback HTTP IP URL without credentials, query or fragment")).map(|_| ()).unwrap_or_else(|error| errors.push(error));
            ServiceBaseUrl::new(binding.base_url.clone())
                .map(|_| ())
                .map_err(|_| {
                    config_error(
                        &format!("{field}.baseUrl"),
                        "use a service base URL without empty interior path segments",
                    )
                })
                .unwrap_or_else(|error| errors.push(error));
            check_endpoint(&binding.authorization.token_endpoint).map_err(|_| config_error(&format!("{field}.authorization.tokenEndpoint"), "use an HTTPS token endpoint or explicit loopback HTTP IP URL without credentials, query or fragment")).map(|_| ()).unwrap_or_else(|error| errors.push(error));
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
            if auth.client_id.trim().is_empty() || auth.client_id.len() > 256 {
                errors.push(config_error(
                    &format!("{field}.authorization.clientId"),
                    "supply a bounded client identity registered with the configured issuer",
                ));
            }
            if !valid_resource_uri(&auth.resource) {
                errors.push(config_error(&format!("{field}.authorization.resource"),
                    "declare one bounded absolute resource URI without credentials, whitespace or fragment"));
            }
            if auth
                .client_assertion_audience
                .as_ref()
                .is_some_and(|audience| !valid_resource_uri(audience))
            {
                errors.push(config_error(
                    &format!("{field}.authorization.clientAssertionAudience"),
                    "declare the issuer's bounded absolute client assertion audience URI",
                ));
            }
            for (index, scope) in auth.scopes.iter().enumerate() {
                if !valid_scope_token(scope) {
                    errors.push(config_error(&format!("{field}.authorization.scopes[{index}]"),
                        "declare one OAuth scope token per item, without whitespace or control characters"));
                }
            }
            validate_requested_scopes(&auth.scopes)
                .map_err(|error| {
                    config_error(&format!("{field}.authorization.scopes"), &error.to_string())
                })
                .unwrap_or_else(|error| errors.push(error));
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
            if auth.signing_key_ref.provider() != SecretProvider::File {
                errors.push(config_error(
                    &format!("{field}.authorization.signingKeyRef"),
                    "use secret:file/name for the client signing key",
                ));
            }
            self.secret_providers
                .check_reference(
                    &format!("{field}.authorization.signingKeyRef"),
                    auth.signing_key_ref.as_str(),
                )
                .map_err(|_| {
                    config_error(
                        &format!("{field}.authorization.signingKeyRef"),
                        "enable secretProviders.file for the client signing key",
                    )
                })
                .unwrap_or_else(|error| errors.push(error));
            match binding.product {
                Product::Breg
                    if binding.profile.as_ref().is_none_or(|p| {
                        BRegRecordOptions::default().access_profile(p).is_err()
                    }) =>
                {
                    errors.push(config_error(
                        &format!("{field}.profile"),
                        "declare a bounded BReg reader access profile accepted by the BReg client",
                    ));
                }
                Product::Messaging | Product::Scheduling if binding.profile.is_some() => {
                    errors.push(config_error(
                        &format!("{field}.profile"),
                        "remove profile; this product applies its own access policy",
                    ));
                }
                _ => {}
            }
        }
        errors
    }

    pub fn validate_workflow(&self, workflow: &crate::definition::Workflow) -> Result<()> {
        for (name, product) in &workflow.connections {
            let expected = match product.as_str() {
                "breg" => Product::Breg,
                "messaging" => Product::Messaging,
                "scheduling" => Product::Scheduling,
                _ => {
                    return Err(config_error(
                        "connections",
                        "use a supported workflow product",
                    ))
                }
            };
            if !self
                .connections
                .get(name)
                .is_some_and(|b| b.product == expected)
            {
                return Err(PocError::new(
                    "workflow-binding",
                    "the declared workflow connection has no matching product binding",
                )
                .at("workflow.yaml", format!("connections.{name}"))
                .suggest(
                    "Configure the same logical name and product in runtime.yaml before admission.",
                ));
            }
        }
        for (name, step) in &workflow.steps {
            if let crate::definition::Step::Call { call, .. } = step {
                if call.operation == crate::protocol::Operation::CreateAppointment
                    && self
                        .connections
                        .get(&call.connection)
                        .is_some_and(|binding| binding.authorization.task_authority.is_none())
                {
                    return Err(PocError::new(
                        "workflow-binding",
                        "appointment creation requires task-bound Scheduling authorization",
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

    /// Hash only this workflow's bindings. Unrelated deployment additions are compatible.
    pub fn binding_digest_for(&self, workflow: &crate::definition::Workflow) -> Result<String> {
        self.validate_workflow(workflow)?;
        self.binding_digest_names(workflow.connections.keys().map(String::as_str))
    }

    fn binding_digest_names<'a>(&self, names: impl Iterator<Item = &'a str>) -> Result<String> {
        self.validate()?;
        let mut identities = BTreeMap::new();
        for name in names {
            let binding = &self.connections[name];
            let auth = &binding.authorization;
            let mut scopes = auth.scopes.clone();
            scopes.sort();
            identities.insert(name, json!({"product":binding.product,"baseUrl":binding.base_url,
                "clientId":auth.client_id,"tokenEndpoint":auth.token_endpoint,
                "clientAssertionAudience":auth.client_assertion_audience.as_deref().unwrap_or(auth.token_endpoint.as_str()),
                "resource":auth.resource,"scopes":scopes,"profile":binding.profile,"taskAuthority":auth.task_authority,"observationAuthorization":binding.observation_authorization.as_ref().map(|auth| json!({"tokenEndpoint":auth.token_endpoint,"clientId":auth.client_id,"resource":auth.resource,"clientAssertionAudience":auth.client_assertion_audience.as_deref().unwrap_or(auth.token_endpoint.as_str()),"scopes":({let mut s=auth.scopes.clone();s.sort();s})})),"abi":"coordinator-adapters/v3"}));
        }
        let value = serde_json::to_value(identities)
            .map_err(|_| config_error("connections", "correct the binding model"))?;
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

fn config_error(field: &str, action: &str) -> PocError {
    PocError::new(
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
    schema["properties"]["connections"] = json!({"type":"object", "minProperties":1,"maxProperties":16,
        "propertyNames":{"$ref":"#/$defs/LocalId"}, "additionalProperties":{"$ref":"#/$defs/ConnectionConfig"}});
    schema["properties"]["database"] = json!({"allOf":[
        {"$ref":"#/$defs/DatabaseConfig"},
        {"properties":{"testOnlyPlaintext":{"const":false}}}
    ], "unevaluatedProperties":false});
    schema["$defs"]["DeploymentConfig"]["properties"]["package"] = json!({"allOf":[
        {"$ref":"#/$defs/PackageConfig"},
        {"required":["expectedDigest"], "properties":{"expectedDigest":{"$ref":"#/$defs/Digest"}}}
    ], "unevaluatedProperties":false});
    schema["$defs"]["ClientPolicy"]["properties"]["flows"]["items"] = json!({
        "$ref":"#/$defs/ExternalId", "maxLength":64, "pattern":"^[A-Za-z0-9_-]+$"
    });
    schema["$defs"]["ClientPolicy"]["properties"]["clientId"]["maxLength"] = json!(128);
    schema["$defs"]["AuthorizationConfig"]["properties"]["clientId"]["maxLength"] = json!(256);
    schema["$defs"]["AccessConfig"]["properties"]["scopeClaim"]["maxLength"] = json!(128);
    // Admission policy requires a closed list, even though the reusable
    // shared client block leaves the product to decide an empty-list policy.
    let access = &mut schema["$defs"]["AccessConfig"];
    access["required"]
        .as_array_mut()
        .unwrap()
        .push(json!("allowedClients"));
    let clients = &mut access["properties"]["allowedClients"];
    clients.as_object_mut().unwrap().remove("default");
    clients["minItems"] = json!(1);
    clients["maxItems"] = json!(64);
    clients["uniqueItems"] = json!(true);
    clients["items"] = json!({"$ref":"#/$defs/ExternalId", "maxLength":128});

    schema["$id"] = json!(
        "https://id.registrystack.org/schemas/coordinator/runtime/runtime.v1alpha1.schema.json"
    );
    schema["properties"]["apiVersion"] = json!({"type":"string", "const":API_VERSION});
    schema["properties"]["kind"] = json!({"type":"string", "const":KIND});
    schema["required"]
        .as_array_mut()
        .unwrap()
        .extend([json!("apiVersion"), json!("kind")]);
    // Only task-bound Scheduling consumes an observation identity, and it
    // must remain observable after the grant ends.
    schema
        .get_mut("$defs")
        .ok_or_else(|| config_error("/", "restore the runtime schema generator"))?
        ["ConnectionConfig"]["allOf"] = json!([{
        "if": {
            "required": ["product", "authorization"],
            "properties": {
                "product": {"const": "scheduling"},
                "authorization": {
                    "required": ["taskAuthority"],
                    "properties": {"taskAuthority": {"type": "object"}}
                }
            }
        },
        "then": {
            "required": ["observationAuthorization"],
            "properties": {"observationAuthorization": {"type": "object"}}
        },
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
fn optional_external<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    external(d).map(Some)
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
