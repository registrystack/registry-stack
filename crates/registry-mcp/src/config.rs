// SPDX-License-Identifier: Apache-2.0
//! Offline-checked bindings for one independently operated MCP resource server.
use registry_breg_mcp::config::{
    AuditConfig, ExchangeConfig, LimitsConfig, LogLevel, RateLimitConfig, RegistryConfig,
    ResourceServerConfig, ResourceUri, ScopeToken, ServiceConfig,
};
use registry_mcp_edge::{AccessTokenAlgorithm, ResourceServerOptions};
use registry_platform_config::{
    PrivateListenerConfig, RuntimeConfigLoader, RuntimeEnvelope, SecretProvidersConfig,
    SecretReference, TlsTermination, MAX_OIDC_AUDIENCE_CHARACTERS,
};
use registry_platform_yaml::{Diagnostic, Digest, LocalId, Report, UniqueList, Url};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};
use url::Host;

pub const API_VERSION: &str = "id.registrystack.org/formats/platform/mcp-runtime/v1alpha1";
pub const KIND: &str = "PlatformMcpRuntimeConfig";

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
    pub name: String,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(default))]
    pub log_level: LogLevel,
    pub listener: PrivateListenerConfig,
    pub secret_providers: SecretProvidersConfig,
    pub resource_server: ResourceServerConfig,
    pub audit: AuditConfig,
    pub rate_limits: RateLimits,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(default))]
    pub limits: LimitsConfig,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 32)))]
    pub bindings: Vec<Binding>,
}
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimits {
    pub per_principal: RateLimitConfig,
    pub per_client: RateLimitConfig,
}
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub name: LocalId,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 128)))]
    pub tools: UniqueList<String>,
    pub provider: ProviderConfig,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum ProviderConfig {
    /// Citizen-facing Base Registry Engine capabilities, delegated per call.
    Breg {
        registry: RegistryConfig,
        exchange: ExchangeConfig,
        service: ServiceConfig,
    },
    /// Assigned-task reads under the backend's explicitly opted-in delegated-reader policy.
    Casework {
        authority: CaseworkAuthority,
        #[serde(rename = "baseUrl")]
        base_url: Url,
        #[serde(rename = "readerPolicy")]
        reader_policy: LocalId,
        #[serde(rename = "sourceProfile")]
        source_profile: LocalId,
        #[serde(rename = "pageSize")]
        #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 100)))]
        page_size: usize,
        authorization: DelegationConfig,
    },
    /// Non-personal reads from a separately operated Adapter deployment.
    Adapter {
        #[serde(rename = "baseUrl")]
        base_url: Url,
        #[serde(rename = "contractFile")]
        #[cfg_attr(feature = "schema", schemars(with = "String"))]
        contract_file: PathBuf,
        #[serde(rename = "contractDigest")]
        contract_digest: Digest,
        #[serde(rename = "dataClass")]
        data_class: AdapterDataClass,
        #[cfg_attr(
            feature = "schema",
            schemars(
                length(min = 1, max = 512),
                extend("pattern" = "^[^\\u0000-\\u001F\\u007F-\\u009F]+$")
            )
        )]
        audience: String,
        #[serde(rename = "machineTokenRef")]
        machine_token_ref: SecretReference,
        #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 128)))]
        operations: std::collections::BTreeMap<String, String>,
    },
}
registry_platform_yaml::tagged_union!(ProviderConfig);

/// This selector declares the intended backend contract; Casework independently
/// admits the trusted gateway and enforces current task and source authority.
#[derive(Clone, Copy, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum CaseworkAuthority {
    DelegatedStaffRead,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum AdapterDataClass {
    NonPersonal,
}
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegationConfig {
    pub exchange: ExchangeConfig,
    pub audience: ResourceUri,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub scopes: UniqueList<ScopeToken>,
}

impl RuntimeConfig {
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(RuntimeEnvelope {
            api_version: API_VERSION,
            kind: KIND,
        })
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        let checked = Self::loader().check_offline::<Self>(path, true, stand_in);
        let report = semantic_report(&checked);
        if report.has_errors() {
            return Err(report.render_human());
        }
        checked
            .loaded
            .map(|loaded| loaded.config)
            .ok_or_else(|| report.render_human())
    }
    pub fn check(path: &Path, environment: bool) -> Report {
        Self::check_status(path, environment).0
    }
    pub fn check_status(path: &Path, environment: bool) -> (Report, bool) {
        let checked = Self::loader().check_offline::<Self>(path, environment, stand_in);
        let unavailable = checked.unavailable;
        (semantic_report(&checked), unavailable)
    }
    pub fn validate(&self) -> Result<(), Report> {
        let findings = self.findings();
        if findings.is_empty() {
            Ok(())
        } else {
            Err(Report::new(findings))
        }
    }
    pub fn development_loopback(&self) -> bool {
        self.listener.tls_termination == TlsTermination::DevelopmentLoopback
    }
    pub fn resource_options(&self) -> ResourceServerOptions {
        let resource = &self.resource_server;
        ResourceServerOptions {
            resource: resource.resource.as_str().to_owned(),
            issuer: resource.issuer.as_str().to_owned(),
            allow_insecure_http: resource.allow_insecure_http,
            algorithms: resource
                .algorithms
                .iter()
                .map(|algorithm| match algorithm {
                    registry_breg_mcp::config::AccessTokenAlgorithm::RS256 => {
                        AccessTokenAlgorithm::RS256
                    }
                    registry_breg_mcp::config::AccessTokenAlgorithm::RS384 => {
                        AccessTokenAlgorithm::RS384
                    }
                    registry_breg_mcp::config::AccessTokenAlgorithm::ES256 => {
                        AccessTokenAlgorithm::ES256
                    }
                    registry_breg_mcp::config::AccessTokenAlgorithm::ES384 => {
                        AccessTokenAlgorithm::ES384
                    }
                    registry_breg_mcp::config::AccessTokenAlgorithm::EdDSA => {
                        AccessTokenAlgorithm::EdDSA
                    }
                })
                .collect(),
            allowed_clients: resource
                .allowed_clients
                .iter()
                .map(|value| value.as_str().to_owned())
                .collect(),
            required_scopes: resource
                .required_scopes
                .iter()
                .map(|value| value.as_str().to_owned())
                .collect(),
            scope_claim: resource.scope_claim.to_string(),
            maximum_token_lifetime: Duration::from_secs(
                resource.maximum_token_lifetime_seconds.get(),
            ),
            resource_name: self.name.clone(),
            principal_audit_namespace: "mcp.principal".to_owned(),
            client_audit_namespace: "mcp.client".to_owned(),
        }
    }
    fn findings(&self) -> Vec<Diagnostic> {
        let mut result = Vec::new();
        let mut reject = |location: &str, message: &str, action: &str| {
            result.push(Diagnostic::error(
                "platform.mcp-runtime.invalid-binding",
                location,
                message,
                action,
            ))
        };
        if self.name.trim().is_empty()
            || self.name.chars().count() > 256
            || self.name.chars().any(char::is_control)
        {
            reject(
                "/name",
                "The gateway name is invalid.",
                "Write a non-blank display name of at most 256 characters.",
            );
        }
        if !self.listener.is_valid() {
            reject(
                "/listener",
                "The listener does not meet its private network boundary.",
                "Bind to an allowed private or development loopback address.",
            );
        }
        if self.secret_providers.check().is_err()
            || self.audit.key.check(&self.secret_providers).is_err()
            || self.audit.destination().is_err()
        {
            reject(
                "/audit",
                "The audit destination or declared secret providers are invalid.",
                "Check the audit destination and declare the hash key's secret provider.",
            );
        }
        if self.resource_options().validate().is_err() {
            reject(
                "/resourceServer",
                "The resource-server settings are invalid.",
                "Use a valid MCP resource, issuer, asymmetric algorithms, clients and scopes.",
            );
        }
        if !self.development_loopback()
            && (self.resource_server.resource.to_url().scheme() != "https"
                || (!self.resource_server.allow_insecure_http
                    && self.resource_server.issuer.to_url().scheme() != "https"))
        {
            reject(
                "/resourceServer",
                "Production resource-server URLs must protect credentials.",
                "Use HTTPS, or declare development-loopback for a local fixture.",
            );
        }
        if self
            .resource_server
            .jwks_source
            .check_with_insecure_http(
                "resourceServer.jwksSource",
                self.development_loopback(),
                self.resource_server.allow_insecure_http,
            )
            .is_err()
        {
            reject(
                "/resourceServer/jwksSource",
                "The JWKS source is invalid.",
                "Use a permitted HTTPS source or a declared static document reference.",
            );
        }
        if let registry_platform_config::JwksSource::Static { document_ref } =
            &self.resource_server.jwks_source
        {
            if self
                .secret_providers
                .check_reference("documentRef", document_ref)
                .is_err()
            {
                reject(
                    "/resourceServer/jwksSource/documentRef",
                    "The static JWKS secret provider is not declared.",
                    "Declare the file or environment provider used by documentRef.",
                );
            }
        }
        let protected_endpoint = |url: url::Url| {
            registry_platform_httputil::client::ServiceBaseUrl::new(url.clone()).is_ok()
                && (url.scheme() == "https"
                    || (url.scheme() == "http"
                        && self.development_loopback()
                        && loopback_host(&url)))
        };
        let mut names = BTreeSet::new();
        let mut tools = BTreeSet::new();
        if self.bindings.is_empty() || self.bindings.len() > 32 {
            reject(
                "/bindings",
                "Configure between one and 32 bindings.",
                "Keep a bounded list of explicit provider bindings.",
            );
        }
        for (index, binding) in self.bindings.iter().enumerate() {
            let pointer = format!("/bindings/{index}");
            if !names.insert(binding.name.as_str())
                || binding.tools.is_empty()
                || binding.tools.len() > 128
                || binding.tools.iter().any(|name| {
                    registry_mcp_edge::ResolvedTool::new(name, "config", "config", "1").is_err()
                })
                || binding
                    .tools
                    .iter()
                    .any(|name| !tools.insert(name.as_str()))
            {
                reject(
                    &pointer,
                    "Binding names and public tools must be unique and non-empty.",
                    "Remove duplicates and explicitly name every public tool.",
                );
            }
            let check_exchange = |exchange: &ExchangeConfig| {
                !self
                    .resource_server
                    .allowed_clients
                    .iter()
                    .any(|client| client == &exchange.client_id)
                    && protected_endpoint(exchange.token_endpoint.to_url())
                    && self
                        .secret_providers
                        .check_reference("privateKeyRef", exchange.private_key_ref.as_str())
                        .is_ok()
            };
            match &binding.provider {
                ProviderConfig::Breg {
                    registry,
                    exchange,
                    service,
                } => {
                    let review = service.review_base_url.to_url();
                    if registry.audience.as_str() == self.resource_server.resource.as_str()
                        || review.path() != "/"
                        || review.query().is_some()
                        || review.fragment().is_some()
                        || !protected_endpoint(review)
                    {
                        reject(&pointer, "The downstream audience or review origin is invalid.", "Use a distinct BReg audience and an HTTPS review origin with no path, query or fragment.");
                    }
                    if !check_exchange(exchange)
                        || registry.scopes.is_empty()
                        || !protected_endpoint(registry.base_url.to_url())
                        || binding.tools.iter().any(|name| {
                            !registry_breg_mcp::BREG_TOOL_NAMES.contains(&name.as_str())
                        })
                    {
                        reject(&pointer, "The BReg capability or credential binding is invalid.", "Use supported citizen tools and a separate configured exchange identity.");
                    }
                }
                ProviderConfig::Casework {
                    authority: CaseworkAuthority::DelegatedStaffRead,
                    base_url,
                    reader_policy,
                    source_profile,
                    page_size,
                    authorization,
                } => {
                    if !check_exchange(&authorization.exchange)
                        || authorization.audience.as_str() == self.resource_server.resource.as_str()
                        || authorization.scopes.is_empty()
                        || !protected_endpoint(base_url.to_url())
                        || crate::casework::CaseworkOptions::new(
                            base_url.to_url(),
                            reader_policy.to_string(),
                            source_profile.to_string(),
                            *page_size,
                        )
                        .is_err()
                        || binding
                            .tools
                            .iter()
                            .any(|name| !crate::casework::TOOL_NAMES.contains(&name.as_str()))
                    {
                        reject(&pointer, "The Casework read or delegation binding is invalid.", "Use assigned task reads, bounded pages and a separate staff delegation credential.");
                    }
                }
                ProviderConfig::Adapter {
                    base_url,
                    contract_file,
                    contract_digest,
                    machine_token_ref,
                    operations,
                    audience,
                    ..
                } => {
                    let provider = format!("{pointer}/provider");
                    if !protected_endpoint(base_url.to_url()) {
                        reject(
                            &format!("{provider}/baseUrl"),
                            "The Adapter base URL is outside the configured network boundary.",
                            "Use HTTPS, or numeric loopback HTTP only with a development-loopback listener.",
                        );
                    }
                    if !contract_file.is_absolute() {
                        reject(
                            &format!("{provider}/contractFile"),
                            "The Adapter effective-contract file path is not absolute.",
                            "Write the absolute path of the reviewed effective-contract export.",
                        );
                    }
                    if !valid_digest(contract_digest) {
                        reject(
                            &format!("{provider}/contractDigest"),
                            "The Adapter contract digest is not a SHA-256 digest.",
                            "Write sha256: followed by the 64 lowercase hexadecimal digits from the reviewed export.",
                        );
                    }
                    if self
                        .secret_providers
                        .check_reference("machineTokenRef", machine_token_ref.as_str())
                        .is_err()
                    {
                        reject(
                            &format!("{provider}/machineTokenRef"),
                            "The Adapter machine-token secret provider is not declared.",
                            "Declare the environment or file provider used by machineTokenRef.",
                        );
                    }
                    if !valid_adapter_audience(audience) {
                        reject(
                            &format!("{provider}/audience"),
                            "The Adapter audience is invalid.",
                            "Use the exact non-empty Adapter OIDC audience of at most 512 characters, without control characters.",
                        );
                    }
                    if audience.as_str() == self.resource_server.resource.as_str() {
                        reject(
                            &format!("{provider}/audience"),
                            "The Adapter audience reuses the inbound MCP resource identifier.",
                            "Configure the distinct audience stated by the Adapter effective contract.",
                        );
                    }
                    if binding
                        .tools
                        .iter()
                        .any(|name| !operations.contains_key(name))
                        || operations.len() != binding.tools.len()
                    {
                        reject(
                            &format!("{provider}/operations"),
                            "The Adapter operation map does not exactly cover the binding's public tools.",
                            "Map each configured public tool exactly once and remove every unlisted mapping.",
                        );
                    }
                    if contract_file.is_absolute() && valid_digest(contract_digest) {
                        match crate::adapter::AdapterContract::load(contract_file, contract_digest) {
                            Ok(contract)
                                if contract
                                    .validate_binding(operations, audience.as_str())
                                    .is_ok() => {}
                            Ok(_) => reject(
                                &provider,
                                "The Adapter audience or operation mapping does not match the pinned effective contract.",
                                "Use the audience and served operation identifiers from the exact reviewed export.",
                            ),
                            Err(_) => reject(
                                &format!("{provider}/contractFile"),
                                "The exact pinned Adapter effective contract could not be loaded.",
                                "Export the contract again, review it, and configure its absolute file path and exact digest.",
                            ),
                        }
                    }
                }
            }
        }
        result
    }
}

fn loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_adapter_audience(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_OIDC_AUDIENCE_CHARACTERS
        && !value.chars().any(char::is_control)
}
fn stand_in(pointer: &str) -> &'static str {
    if let Some(index) = pointer.strip_prefix("/resourceServer/algorithms/") {
        const ALGORITHMS: [&str; 5] = ["RS256", "RS384", "ES256", "ES384", "EdDSA"];
        return ALGORITHMS[index.parse::<usize>().unwrap_or(0) % ALGORITHMS.len()];
    }
    if pointer == "/listener/bind" {
        "127.0.0.1:8080"
    } else if pointer == "/listener/tlsTermination" {
        "operator-controlled-upstream"
    } else if pointer == "/listener/networkExposure" {
        "private-address"
    } else if pointer == "/logLevel" {
        "info"
    } else if pointer.ends_with("/baseUrl") || pointer.ends_with("/tokenEndpoint") {
        "https://deferred.invalid/"
    } else if pointer.ends_with("/resource") {
        "https://deferred.invalid/mcp"
    } else if pointer.ends_with("/issuer") || pointer.ends_with("/jwksSource/uri") {
        "https://deferred.invalid/"
    } else if pointer.ends_with("/audience") {
        "urn:deferred"
    } else if pointer.ends_with("Ref") {
        "secret:env/DEFERRED"
    } else if pointer.ends_with("/contractFile") {
        "/deferred/effective-contract.json"
    } else if pointer.ends_with("/contractDigest") {
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    } else if pointer == "/audit/destination" {
        "file"
    } else if pointer == "/audit/path" {
        "/audit.jsonl"
    } else {
        registry_platform_config::DEFAULT_STAND_IN
    }
}

fn semantic_report(check: &registry_platform_config::RuntimeFileCheck<RuntimeConfig>) -> Report {
    let diagnostics = check
        .loaded
        .as_ref()
        .map(|loaded| {
            loaded
                .config
                .findings()
                .into_iter()
                .filter(|finding| !check.defers_within(&finding.path))
                .map(|finding| {
                    check.error_at(
                        KIND,
                        &finding.code,
                        &finding.path,
                        finding.message,
                        finding.suggested_action,
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    check.report_with(KIND, diagnostics)
}
