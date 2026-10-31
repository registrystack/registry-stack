// SPDX-License-Identifier: Apache-2.0
//! Offline-checked bindings for one independently operated MCP resource server.
use registry_breg_mcp::config::{RegistryConfig, ServiceConfig};
use registry_mcp_edge::config::{
    AuditConfig, ExchangeConfig, LimitsConfig, LogLevel, RateLimitConfig, ResourceServerConfig,
    ResourceServerConfigError, ResourceUri, ScopeToken,
};
use registry_mcp_edge::ResourceServerOptions;
use registry_platform_config::{
    PrivateListenerConfig, RemovedKey, RuntimeConfigLoader, RuntimeEnvelope, SecretProvidersConfig,
    SecretReference, TlsTermination, MAX_OIDC_AUDIENCE_CHARACTERS,
};
use registry_platform_yaml::{Diagnostic, Digest, LocalId, Report, UniqueList, Url};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
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
        #[serde(default)]
        source_profile: Option<LocalId>,
        #[serde(rename = "pageSize", default = "default_casework_page_size")]
        #[cfg_attr(feature = "schema", schemars(default = "default_casework_page_size"))]
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
        operations: std::collections::BTreeMap<String, crate::adapter::AdapterToolBinding>,
    },
}
registry_platform_yaml::tagged_union!(ProviderConfig);

const fn default_casework_page_size() -> usize {
    25
}

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
        }).removed_keys(&[RemovedKey {
            path: "rateLimits.perCitizen",
            replacement: "Rename rateLimits.perCitizen to rateLimits.perPrincipal in PlatformMcpRuntimeConfig; breg-mcp retains perCitizen.",
        }])
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
        self.resource_server
            .options(&self.name, "mcp.principal", "mcp.client")
    }
    fn findings(&self) -> Vec<Diagnostic> {
        let mut result = Vec::new();
        let mut reject = |code: &str, location: &str, message: &str, action: &str| {
            result.push(Diagnostic::error(
                format!("platform.mcp-runtime.{code}"),
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
                "name-invalid",
                "/name",
                "The gateway name is invalid.",
                "Write a non-blank display name of at most 256 characters.",
            );
        }
        if !self.listener.is_valid() {
            reject(
                "listener-invalid",
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
                "audit-invalid",
                "/audit",
                "The audit destination or declared secret providers are invalid.",
                "Check the audit destination and declare the hash key's secret provider.",
            );
        }
        if self.resource_options().validate().is_err() {
            reject(
                "resource-server-invalid",
                "/resourceServer",
                "The resource-server settings are invalid.",
                "Use a valid MCP resource, issuer, asymmetric algorithms, clients and scopes.",
            );
        }
        let resource_errors = self
            .resource_server
            .validate(self.development_loopback(), &self.secret_providers);
        if resource_errors.iter().any(|error| {
            matches!(
                error,
                ResourceServerConfigError::InsecureResource
                    | ResourceServerConfigError::InsecureIssuer
            )
        }) {
            reject(
                "insecure-resource-server",
                "/resourceServer",
                "Production resource-server URLs must protect credentials.",
                "Use HTTPS, or declare development-loopback for a local fixture.",
            );
        }
        if resource_errors.iter().any(|error| {
            matches!(
                error,
                ResourceServerConfigError::JwksSource(_)
                    | ResourceServerConfigError::JwksDocumentReference(_)
            )
        }) {
            reject(
                "jwks-source-invalid",
                "/resourceServer/jwksSource",
                "The JWKS source is invalid.",
                "Use a permitted HTTPS source or a declared static document reference.",
            );
        }
        let protected_endpoint = |url: url::Url| {
            registry_platform_httputil::client::ServiceBaseUrl::new(url.clone()).is_ok()
                && (url.scheme() == "https"
                    || (url.scheme() == "http"
                        && self.development_loopback()
                        && loopback_host(&url)))
        };
        if self
            .bindings
            .iter()
            .any(|binding| matches!(&binding.provider, ProviderConfig::Breg { .. }))
            && self
                .bindings
                .iter()
                .any(|binding| matches!(&binding.provider, ProviderConfig::Casework { .. }))
        {
            reject("mixed-personas", "/bindings", "Citizen and staff providers cannot share one inbound MCP resource.", "Deploy separate citizen and staff configurations with distinct resources, clients, scopes and credentials.");
        }
        let mut names = BTreeSet::new();
        let mut tools = BTreeSet::new();
        if self.bindings.is_empty() || self.bindings.len() > 32 {
            reject(
                "binding-count",
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
                    "tool-ceiling-invalid",
                    &pointer,
                    "Binding names and public tools must be unique and non-empty.",
                    "Remove duplicates and explicitly name every public tool.",
                );
            }
            match &binding.provider {
                ProviderConfig::Breg {
                    registry,
                    exchange,
                    service,
                } => {
                    let provider = format!("{pointer}/provider");
                    let review = service.review_base_url.to_url();
                    if registry.audience.as_str() == self.resource_server.resource.as_str() {
                        reject(
                            "downstream-audience-reused",
                            &format!("{provider}/registry/audience"),
                            "The BReg audience reuses the inbound MCP resource identifier.",
                            "Configure the distinct downstream audience admitted by BReg.",
                        );
                    }
                    if review.path() != "/"
                        || review.query().is_some()
                        || review.fragment().is_some()
                        || !protected_endpoint(review)
                    {
                        reject(
                            "breg-review-origin-invalid",
                            &format!("{provider}/service/reviewBaseUrl"),
                            "The BReg review origin is invalid.",
                            "Use an HTTPS review origin with no path, query or fragment, or an explicitly isolated loopback fixture.",
                        );
                    }
                    if self
                        .resource_server
                        .allowed_clients
                        .iter()
                        .any(|client| client == &exchange.client_id)
                    {
                        reject(
                            "exchange-client-reused",
                            &format!("{provider}/exchange/clientId"),
                            "The BReg exchange client is also admitted as an inbound MCP client.",
                            "Configure a distinct client identity for the downstream token exchange.",
                        );
                    }
                    if !protected_endpoint(exchange.token_endpoint.to_url()) {
                        reject(
                            "exchange-url-invalid",
                            &format!("{provider}/exchange/tokenEndpoint"),
                            "The BReg exchange endpoint is outside the configured network boundary.",
                            "Use HTTPS, or loopback HTTP only with a development-loopback listener.",
                        );
                    }
                    if self
                        .secret_providers
                        .check_reference("privateKeyRef", exchange.private_key_ref.as_str())
                        .is_err()
                    {
                        reject(
                            "exchange-secret-provider-undeclared",
                            &format!("{provider}/exchange/privateKeyRef"),
                            "The BReg exchange-key secret provider is not declared.",
                            "Declare the environment or file provider used by privateKeyRef.",
                        );
                    }
                    if !protected_endpoint(registry.base_url.to_url()) {
                        reject(
                            "provider-url-invalid",
                            &format!("{provider}/registry/baseUrl"),
                            "The BReg service URL is outside the configured network boundary.",
                            "Use HTTPS, or loopback HTTP only with a development-loopback listener.",
                        );
                    }
                    for (tool_index, name) in binding.tools.iter().enumerate() {
                        if !registry_breg_mcp::BREG_TOOL_NAMES.contains(&name.as_str()) {
                            reject(
                                "provider-tool-unsupported",
                                &format!("{pointer}/tools/{tool_index}"),
                                "The BReg provider does not support this public tool.",
                                "Remove the tool or bind it to a provider that implements it.",
                            );
                        }
                    }
                }
                ProviderConfig::Casework {
                    authority: CaseworkAuthority::DelegatedStaffRead,
                    base_url,
                    reader_policy: _,
                    source_profile: _,
                    page_size,
                    authorization,
                } => {
                    let provider = format!("{pointer}/provider");
                    let exchange = &authorization.exchange;
                    if self
                        .resource_server
                        .allowed_clients
                        .iter()
                        .any(|client| client == &exchange.client_id)
                    {
                        reject(
                            "exchange-client-reused",
                            &format!("{provider}/authorization/exchange/clientId"),
                            "The Casework exchange client is also admitted as an inbound MCP client.",
                            "Configure a distinct client identity for the downstream token exchange.",
                        );
                    }
                    if !protected_endpoint(exchange.token_endpoint.to_url()) {
                        reject(
                            "exchange-url-invalid",
                            &format!("{provider}/authorization/exchange/tokenEndpoint"),
                            "The Casework exchange endpoint is outside the configured network boundary.",
                            "Use HTTPS, or loopback HTTP only with a development-loopback listener.",
                        );
                    }
                    if self
                        .secret_providers
                        .check_reference("privateKeyRef", exchange.private_key_ref.as_str())
                        .is_err()
                    {
                        reject(
                            "exchange-secret-provider-undeclared",
                            &format!("{provider}/authorization/exchange/privateKeyRef"),
                            "The Casework exchange-key secret provider is not declared.",
                            "Declare the environment or file provider used by privateKeyRef.",
                        );
                    }
                    if authorization.audience.as_str() == self.resource_server.resource.as_str() {
                        reject(
                            "downstream-audience-reused",
                            &format!("{provider}/authorization/audience"),
                            "The Casework audience reuses the inbound MCP resource identifier.",
                            "Configure the distinct downstream audience admitted by Casework.",
                        );
                    }
                    if authorization.scopes.is_empty() {
                        reject(
                            "downstream-scopes-empty",
                            &format!("{provider}/authorization/scopes"),
                            "The Casework downstream scope set is empty.",
                            "Configure the least-privileged delegated-reader scopes required by Casework.",
                        );
                    }
                    if !protected_endpoint(base_url.to_url()) {
                        reject(
                            "provider-url-invalid",
                            &format!("{provider}/baseUrl"),
                            "The Casework service URL is outside the configured network boundary.",
                            "Use HTTPS, or loopback HTTP only with a development-loopback listener.",
                        );
                    }
                    if !(1..=100).contains(page_size) {
                        reject(
                            "casework-page-size-invalid",
                            &format!("{provider}/pageSize"),
                            "The Casework page size is outside its supported bounds.",
                            "Configure pageSize between 1 and 100.",
                        );
                    }
                    for (tool_index, name) in binding.tools.iter().enumerate() {
                        if !crate::casework::TOOL_NAMES.contains(&name.as_str()) {
                            reject(
                                "provider-tool-unsupported",
                                &format!("{pointer}/tools/{tool_index}"),
                                "The Casework provider does not support this public tool.",
                                "Remove the tool or bind it to a provider that implements it.",
                            );
                        }
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
                            "adapter-url-invalid", &format!("{provider}/baseUrl"),
                            "The Adapter base URL is outside the configured network boundary.",
                            "Use HTTPS, or numeric loopback HTTP only with a development-loopback listener.",
                        );
                    }
                    if !contract_file.is_absolute() {
                        reject(
                            "adapter-path-invalid",
                            &format!("{provider}/contractFile"),
                            "The Adapter effective-contract file path is not absolute.",
                            "Write the absolute path of the reviewed effective-contract export.",
                        );
                    }
                    if !valid_digest(contract_digest) {
                        reject(
                            "adapter-digest-invalid", &format!("{provider}/contractDigest"),
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
                            "adapter-secret-provider-undeclared",
                            &format!("{provider}/machineTokenRef"),
                            "The Adapter machine-token secret provider is not declared.",
                            "Declare the environment or file provider used by machineTokenRef.",
                        );
                    }
                    if !valid_adapter_audience(audience) {
                        reject(
                            "adapter-audience-invalid", &format!("{provider}/audience"),
                            "The Adapter audience is invalid.",
                            "Use the exact non-empty Adapter OIDC audience of at most 512 characters, without control characters.",
                        );
                    }
                    if audience.as_str() == self.resource_server.resource.as_str() {
                        reject(
                            "adapter-audience-reused", &format!("{provider}/audience"),
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
                            "adapter-tool-ceiling-mismatch", &format!("{provider}/operations"),
                            "The Adapter operation map does not exactly cover the binding's public tools.",
                            "Map each configured public tool exactly once and remove every unlisted mapping.",
                        );
                    }
                    if contract_file.is_absolute() && valid_digest(contract_digest) {
                        match crate::adapter::AdapterContract::load_bound_checked(
                            contract_file, contract_digest,
                            &operations.values().map(|binding| binding.operation.clone()).collect(),
                        ) {
                            Ok(contract)
                                if contract
                                    .validate_binding(operations, audience.as_str())
                                    .is_ok() => {}
                            Ok(_) => reject(
                                "adapter-binding-mismatch", &provider,
                                "The Adapter audience or operation mapping does not match the pinned effective contract.",
                                "Use the audience and served operation identifiers from the exact reviewed export.",
                            ),
                            Err(crate::adapter::AdapterContractLoadError::Unreadable) => reject(
                                "adapter-contract-unreadable", &format!("{provider}/contractFile"),
                                "The Adapter effective-contract file could not be read.",
                                "Check the absolute file path, readability and bounded file size.",
                            ),
                            Err(crate::adapter::AdapterContractLoadError::Malformed) => reject(
                                "adapter-contract-invalid", &format!("{provider}/contractFile"),
                                "The Adapter effective contract or selected operation schema is unsupported.",
                                "Use a compatible producer export and supported configured read operations.",
                            ),
                            Err(crate::adapter::AdapterContractLoadError::DigestMismatch) => reject(
                                "adapter-digest-mismatch", &format!("{provider}/contractDigest"),
                                "The Adapter export does not match the reviewed digest pin.",
                                "Review the producer export and copy its digest member; do not use a file checksum.",
                            ),
                            Err(crate::adapter::AdapterContractLoadError::UnsupportedSelection) => reject(
                                "adapter-operation-not-read", &format!("{provider}/operations"),
                                "A configured Adapter operation is outside the supported read-only contract.",
                                "Select a served GET or explicitly read-only POST operation; external writes are not supported.",
                            ),
                            Err(crate::adapter::AdapterContractLoadError::SelectionMismatch) => reject(
                                "adapter-operation-missing", &format!("{provider}/operations"),
                                "A selected Adapter operation is absent from the pinned effective contract.",
                                "Use only served operation identifiers from the reviewed producer export.",
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
