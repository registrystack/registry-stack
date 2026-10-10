// SPDX-License-Identifier: Apache-2.0
//! Configured, bounded external JSON reads. This capability never sends a mutation.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use jsonschema::JSONSchema;
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httputil::{
    client::TokenProvider, read_bounded, BoundedReadError, FetchUrlError, FetchUrlPolicy,
    ServiceBaseUrl,
};
use registry_platform_yaml::{BoundedU64, ExternalId, ForeignValue, UniqueList};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use url::{Host, Url};

use crate::{protocol::CallOutcome, runtime::AuthorizationConfig, PocError, Result};

/// The reviewed directory contract and environment-specific destination.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalHttpConfig {
    #[serde(deserialize_with = "endpoint")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    #[cfg_attr(feature = "schema", schemars(extend("pattern" = "^[^\\s\\\\]+$")))]
    pub base_url: Url,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 16)))]
    pub paths: UniqueList<ExternalId>,
    /// Omission permits no query parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 16)))]
    pub query_parameters: Option<UniqueList<ExternalId>>,
    /// Omission makes the configured read public; it never inherits a caller token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(extend("not" = json!({"required":["taskAuthority"]}))))]
    pub authorization: Option<AuthorizationConfig>,
    /// Local JSON Schema for the complete {status, body} response.
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-foreign" = "json-schema-2020-12")))]
    pub response_schema: ForeignValue,
    #[serde(default = "default_timeout")]
    pub attempt_timeout_milliseconds: BoundedU64<1, 2000>,
    #[serde(default = "default_response_bytes")]
    pub maximum_response_bytes: BoundedU64<1, 65536>,
}

fn endpoint<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Url, D::Error> {
    let written = registry_platform_yaml::Url::deserialize(d)?;
    if written.as_str().contains('\\') || written.as_str().chars().any(char::is_whitespace) {
        return Err(serde::de::Error::custom(
            "use an absolute service URL without whitespace or backslashes",
        ));
    }
    written.as_str().parse().map_err(serde::de::Error::custom)
}

fn default_timeout() -> BoundedU64<1, 2000> {
    BoundedU64::new(2000).expect("the default is within the declared bound")
}

fn default_response_bytes() -> BoundedU64<1, 65536> {
    BoundedU64::new(65536).expect("the default is within the declared bound")
}

impl ExternalHttpConfig {
    /// Offline contract and authorization identity validation. The runtime also
    /// checks secret-reference compatibility with its configured providers.
    pub fn validate(&self) -> Result<()> {
        self.findings("").into_iter().next().map_or(Ok(()), Err)
    }

    pub fn findings(&self, prefix: &str) -> Vec<PocError> {
        let mut errors = Vec::new();
        let mut refuse = |member: &str, repair: &str| {
            let field = if prefix.is_empty() {
                member.to_owned()
            } else {
                format!("{prefix}.{member}")
            };
            errors.push(
                PocError::new(
                    "coordinator.external-http.configuration",
                    "the configured external read contract was refused",
                )
                .at("runtime.yaml", field)
                .suggest(repair),
            );
        };
        let base = ServiceBaseUrl::new(self.base_url.clone());
        let numeric_loopback = match self.base_url.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if base.is_err() || (self.base_url.scheme() == "http" && !numeric_loopback) {
            refuse("baseUrl", "Use HTTPS or explicit numeric loopback HTTP, without credentials, query, fragment or empty interior path segments.");
        }
        if self.paths.is_empty()
            || self.paths.len() > 16
            || self.paths.iter().any(|path| {
                path.as_str().contains('\\')
                    || base
                        .as_ref()
                        .is_ok_and(|base| base.join(path.as_str()).is_err())
            })
        {
            refuse("paths", "Declare between one and sixteen exact relative service paths without empty or dot segments, query, fragment or backslashes.");
        }
        if self
            .query_parameters
            .as_ref()
            .is_some_and(|parameters| parameters.is_empty() || parameters.len() > 16)
        {
            refuse("queryParameters", "Declare between one and sixteen bounded query names, or omit queryParameters to permit none.");
        }
        if self
            .authorization
            .as_ref()
            .is_some_and(|authorization| authorization.task_authority.is_some())
        {
            refuse(
                "authorization.taskAuthority",
                "Remove taskAuthority; external GET uses its separately configured read identity.",
            );
        }
        if crate::definition::compile_schema(&self.response_schema.0).is_err() {
            refuse("responseSchema", "Declare a local JSON Schema for {status, body}; external references and schema resource identifiers are unsupported.");
        }
        if let Some(authorization) = &self.authorization {
            let field = if prefix.is_empty() {
                "authorization".to_owned()
            } else {
                format!("{prefix}.authorization")
            };
            errors.extend(authorization.findings(&field, None));
        }
        errors
    }
}

/// Credentials remain attempt-local; no request body, headers or URL can be
/// supplied by a workflow. The parent durable boundary records successful reads.
pub struct ExternalHttpConnection {
    config: ExternalHttpConfig,
    base: ServiceBaseUrl,
    response_schema: JSONSchema,
    tokens: Option<Arc<dyn TokenProvider>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetRequest {
    path: String,
    #[serde(default)]
    query: BTreeMap<String, String>,
}

impl ExternalHttpConnection {
    pub fn new(
        config: &ExternalHttpConfig,
        tokens: Option<Arc<dyn TokenProvider>>,
    ) -> Result<Self> {
        config.validate()?;
        if config.authorization.is_some() != tokens.is_some() {
            return Err(PocError::new(
                "coordinator.external-http.configuration",
                "the external read credential provider does not match its configured identity",
            )
            .suggest(
                "Supply the configured read token provider, or remove it for a public read.",
            ));
        }
        Ok(Self {
            config: config.clone(),
            base: ServiceBaseUrl::new(config.base_url.clone()).map_err(|_| {
                PocError::new(
                    "coordinator.external-http.configuration",
                    "invalid service base URL",
                )
            })?,
            response_schema: crate::definition::compile_schema(&config.response_schema.0)?,
            tokens,
        })
    }

    pub async fn get(&self, input: &Value) -> CallOutcome {
        let request: GetRequest = match serde_json::from_value(input.clone()) {
            Ok(request) => request,
            Err(_) => return refused("external-invalid-command"),
        };
        if !self
            .config
            .paths
            .iter()
            .any(|path| path.as_str() == request.path)
            || request.query.len() > 16
            || request.query.iter().any(|(name, value)| {
                value.len() > 1024
                    || value.chars().any(char::is_control)
                    || !self
                        .config
                        .query_parameters
                        .as_ref()
                        .is_some_and(|names| names.iter().any(|allowed| allowed.as_str() == name))
            })
        {
            return refused("external-invalid-command");
        }
        let mut url = match self.base.join(&request.path) {
            Ok(url) => url,
            Err(_) => return refused("external-invalid-command"),
        };
        if !request.query.is_empty() {
            url.query_pairs_mut().extend_pairs(&request.query);
        }
        let timeout = Duration::from_millis(self.config.attempt_timeout_milliseconds.get());
        match tokio::time::timeout(timeout, self.fetch(url, timeout)).await {
            Ok(outcome) => outcome,
            Err(_) => unavailable(),
        }
    }

    async fn fetch(&self, url: Url, timeout: Duration) -> CallOutcome {
        // The destination was reviewed by the operator. Institutional HTTPS
        // peers may be private, but metadata and non-loopback cleartext remain
        // denied. Each request connects to only the addresses validated here.
        let policy = if url.scheme() == "http" {
            FetchUrlPolicy::dev()
        } else {
            FetchUrlPolicy {
                allowed_schemes: vec!["https".into()],
                allow_localhost: true,
                allow_http_private_network: false,
                deny_private_ranges: false,
                deny_cloud_metadata: true,
            }
        };
        let validated = match policy
            .validate_dns_pinned_for_immediate_fetch_with_timeout(&url, timeout)
            .await
        {
            Ok(validated) => validated,
            Err(
                FetchUrlError::Dns { .. }
                | FetchUrlError::NoAddresses
                | FetchUrlError::ValidationTimeout { .. }
                | FetchUrlError::ValidationTask(_),
            ) => return unavailable(),
            Err(_) => return refused("external-destination-refused"),
        };
        let mut request = match validated.immediate_get_with_timeout(timeout) {
            Ok(request) => request.header(reqwest::header::ACCEPT, "application/json"),
            Err(_) => return refused("external-destination-refused"),
        };
        if let Some(tokens) = &self.tokens {
            let token = match tokens.bearer_token().await {
                Ok(token) => token,
                Err(error) => return crate::adapters::token_failure(&error),
            };
            request = request.header(
                reqwest::header::AUTHORIZATION,
                token.authorization_header_value(),
            );
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) => return unavailable(),
        };
        let status = response.status();
        if status.is_redirection() {
            return refused("external-redirect");
        }
        let bytes = match read_bounded(response, self.config.maximum_response_bytes.get()).await {
            Ok(bytes) => bytes,
            Err(BoundedReadError::Transport(_)) => return unavailable(),
            Err(_) => return refused("external-invalid-response"),
        };
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            match parse_json_strict(&bytes) {
                Ok(body) => body,
                Err(_) => return refused("external-invalid-response"),
            }
        };
        let reply = json!({"status": status.as_u16(), "body": body});
        if !self.response_schema.is_valid(&reply) {
            return refused("external-invalid-response");
        }
        CallOutcome::Success(reply)
    }
}

fn refused(code: &str) -> CallOutcome {
    CallOutcome::Refused { code: code.into() }
}

fn unavailable() -> CallOutcome {
    CallOutcome::Retryable {
        code: "external-unavailable".into(),
    }
}
