// SPDX-License-Identifier: Apache-2.0
//! Configured, bounded external JSON reads and one configured external command.
//! A read never sends a mutation. A command sends one JSON object by POST to
//! the operator's configured command path and nowhere else.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use jsonschema::JSONSchema;
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httputil::{
    client::{RetryAfter, TokenProvider},
    read_bounded, BoundedReadError, FetchUrlError, FetchUrlPolicy, ServiceBaseUrl,
};
use registry_platform_yaml::{BoundedU64, ExternalId, ForeignValue, UniqueList};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use url::{Host, Url};

use crate::{protocol::CallOutcome, runtime::AuthorizationConfig, CoordinatorError, Result};

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
    #[cfg_attr(feature = "schema", schemars(extend("not" = serde_json::json!({"required":["taskAuthority"]}))))]
    pub authorization: Option<AuthorizationConfig>,
    /// The one exact relative path that `external.command/v1` may POST to.
    /// Omission keeps the connection read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_path: Option<ExternalId>,
    /// Local JSON Schema for the complete {status, body} response.
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-foreign" = "json-schema-2020-12")))]
    pub response_schema: ForeignValue,
    #[serde(default = "default_timeout")]
    pub attempt_timeout_milliseconds:
        BoundedU64<1, { crate::operations::HTTP_REQUEST_TIMEOUT_MILLISECONDS }>,
    #[serde(default = "default_response_bytes")]
    pub maximum_response_bytes: BoundedU64<1, { crate::operations::MAXIMUM_HTTP_RESPONSE_BYTES }>,
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

fn default_timeout() -> BoundedU64<1, { crate::operations::HTTP_REQUEST_TIMEOUT_MILLISECONDS }> {
    BoundedU64::new(crate::operations::HTTP_REQUEST_TIMEOUT_MILLISECONDS)
        .expect("the default is within the declared bound")
}

fn default_response_bytes() -> BoundedU64<1, { crate::operations::MAXIMUM_HTTP_RESPONSE_BYTES }> {
    BoundedU64::new(crate::operations::MAXIMUM_HTTP_RESPONSE_BYTES)
        .expect("the default is within the declared bound")
}

/// The longest `Retry-After` wait taken from a directory, the bound the
/// Messaging client applies. Dispatch still caps every wait at its maximum
/// backoff delay.
const MAXIMUM_RETRY_AFTER_SECONDS: u64 = 24 * 60 * 60;

impl ExternalHttpConfig {
    /// Offline contract and authorization identity validation. The runtime also
    /// checks secret-reference compatibility with its configured providers.
    pub fn validate(&self) -> Result<()> {
        self.findings("").into_iter().next().map_or(Ok(()), Err)
    }

    pub fn findings(&self, prefix: &str) -> Vec<CoordinatorError> {
        let mut errors = Vec::new();
        let mut refuse = |member: &str, repair: &str| {
            let field = if prefix.is_empty() {
                member.to_owned()
            } else {
                format!("{prefix}.{member}")
            };
            errors.push(
                CoordinatorError::new(
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
        if self.command_path.as_ref().is_some_and(|path| {
            path.as_str().contains('\\')
                || base
                    .as_ref()
                    .is_ok_and(|base| base.join(path.as_str()).is_err())
        }) {
            refuse("commandPath", "Declare one exact relative service path without empty or dot segments, query, fragment or backslashes, or omit commandPath to keep the connection read-only.");
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

/// Credentials remain attempt-local; no headers, URL or credential can be
/// supplied by a workflow, which supplies only a command body. The parent
/// durable boundary records successful reads and freezes each command first.
pub struct ExternalHttpConnection {
    config: ExternalHttpConfig,
    base: ServiceBaseUrl,
    response_schema: JSONSchema,
    tokens: Option<Arc<dyn TokenProvider>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) struct GetRequest {
    path: String,
    #[serde(default)]
    query: BTreeMap<String, String>,
}

/// The external-get call output. The body is open here: the connection's
/// operator-owned response schema constrains it in the runtime configuration.
#[derive(Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) struct ExternalResponse {
    status: u16,
    /// The parsed JSON response body, or null for an empty body.
    body: Value,
}

impl ExternalHttpConnection {
    pub fn new(
        config: &ExternalHttpConfig,
        tokens: Option<Arc<dyn TokenProvider>>,
    ) -> Result<Self> {
        config.validate()?;
        if config.authorization.is_some() != tokens.is_some() {
            return Err(CoordinatorError::new(
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
                CoordinatorError::new(
                    "coordinator.external-http.configuration",
                    "invalid service base URL",
                )
            })?,
            response_schema: crate::definition::compile_schema(&config.response_schema.0)?,
            tokens,
        })
    }

    /// One attempt at the configured read. Before the final attempt, a busy or
    /// failing gateway (429, 502, 503 or 504) is retryable with the wait its
    /// `Retry-After` names; on the final attempt the workflow receives it as
    /// it receives every other status.
    pub async fn get(&self, input: &Value, final_attempt: bool) -> CallOutcome {
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
        match tokio::time::timeout(timeout, self.fetch(url, timeout, final_attempt)).await {
            Ok(outcome) => outcome,
            Err(_) => unavailable(),
        }
    }

    /// One attempt at the configured command: a single POST of the exact
    /// command body to the operator's command path, carrying the frozen
    /// request id as `Idempotency-Key` so the provider can deduplicate a
    /// repeated attempt. Nothing is retried inside the attempt. Once the
    /// request may have reached the provider, a lost, ambiguous or unusable
    /// answer is uncertain, never a provider failure. The response is returned
    /// for the operation's pinned interpretation Function.
    pub async fn command(
        &self,
        input: &Value,
        request_id: &str,
        final_attempt: bool,
    ) -> CallOutcome {
        let Some(path) = &self.config.command_path else {
            return refused("operation-unbound");
        };
        if !crate::adapters::valid_key(request_id) {
            return refused("invalid-command");
        }
        let body = match serde_json::to_vec(input) {
            Ok(body)
                if input.is_object()
                    && body.len() as u64 <= crate::operations::MAXIMUM_HTTP_RESPONSE_BYTES =>
            {
                body
            }
            _ => return refused("external-invalid-command"),
        };
        let url = match self.base.join(path.as_str()) {
            Ok(url) => url,
            Err(_) => return refused("external-invalid-command"),
        };
        let timeout = Duration::from_millis(self.config.attempt_timeout_milliseconds.get());
        let deadline = tokio::time::Instant::now() + timeout;
        // Nothing has been sent while the destination and credential are prepared.
        let request = match tokio::time::timeout_at(
            deadline,
            self.request(url, reqwest::Method::POST, timeout),
        )
        .await
        {
            Ok(Ok(request)) => request,
            Ok(Err(outcome)) => return outcome,
            Err(_) => return unavailable(),
        };
        let request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", request_id)
            .body(body);
        match tokio::time::timeout_at(deadline, self.send_command(request, final_attempt)).await {
            Ok(outcome) => outcome,
            Err(_) => uncertain("attempt-timeout"),
        }
    }

    async fn send_command(
        &self,
        request: reqwest::RequestBuilder,
        final_attempt: bool,
    ) -> CallOutcome {
        let response = match request.send().await {
            Ok(response) => response,
            // A refused or failed connection carried no request.
            Err(error) if error.is_connect() => return unavailable(),
            Err(error) if error.is_timeout() => return uncertain("attempt-timeout"),
            Err(_) => return uncertain("transport-uncertain"),
        };
        let status = response.status();
        // A redirect is never followed. It may answer an accepted command.
        if status.is_redirection() {
            return uncertain("external-redirect");
        }
        // Only an explicit busy answer is retried; any other server failure
        // may follow an effect, so the run holds for same-command recovery.
        match status.as_u16() {
            429 => return busy("external-rate-limited", response.headers()),
            503 if !final_attempt => return busy("external-unavailable", response.headers()),
            500..=599 => return uncertain("external-uncertain"),
            _ => {}
        }
        let bytes = match read_bounded(response, self.config.maximum_response_bytes.get()).await {
            Ok(bytes) => bytes,
            Err(BoundedReadError::Transport(_)) => return uncertain("transport-uncertain"),
            Err(_) => return uncertain("external-invalid-response"),
        };
        match self.reply(status, &bytes) {
            Some(reply) => CallOutcome::Success(reply),
            None => uncertain("external-invalid-response"),
        }
    }

    async fn fetch(&self, url: Url, timeout: Duration, final_attempt: bool) -> CallOutcome {
        let request = match self.request(url, reqwest::Method::GET, timeout).await {
            Ok(request) => request,
            Err(outcome) => return outcome,
        };
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) => return unavailable(),
        };
        let status = response.status();
        if status.is_redirection() {
            return refused("external-redirect");
        }
        if !final_attempt {
            // A gateway's error page is rarely JSON, so a retried status is
            // reported before its body is read.
            let code = match status.as_u16() {
                429 => Some("external-rate-limited"),
                502..=504 => Some("external-unavailable"),
                _ => None,
            };
            if let Some(code) = code {
                return busy(code, response.headers());
            }
        }
        let bytes = match read_bounded(response, self.config.maximum_response_bytes.get()).await {
            Ok(bytes) => bytes,
            Err(BoundedReadError::Transport(_)) => return unavailable(),
            Err(_) => return refused("external-invalid-response"),
        };
        match self.reply(status, &bytes) {
            Some(reply) => CallOutcome::Success(reply),
            None => refused("external-invalid-response"),
        }
    }

    /// A request to the validated destination with its attempt credential.
    async fn request(
        &self,
        url: Url,
        method: reqwest::Method,
        timeout: Duration,
    ) -> std::result::Result<reqwest::RequestBuilder, CallOutcome> {
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
                allow_http_non_loopback: false,
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
            ) => return Err(unavailable()),
            Err(_) => return Err(refused("external-destination-refused")),
        };
        let mut request = match validated.immediate_request_with_timeout(method, timeout) {
            Ok(request) => request.header(reqwest::header::ACCEPT, "application/json"),
            Err(_) => return Err(refused("external-destination-refused")),
        };
        if let Some(tokens) = &self.tokens {
            let token = match tokens.bearer_token().await {
                Ok(token) => token,
                Err(error) => return Err(crate::adapters::token_failure(&error)),
            };
            request = request.header(
                reqwest::header::AUTHORIZATION,
                token.authorization_header_value(),
            );
        }
        Ok(request)
    }

    /// The typed `{status, body}` reply, when the body is strict JSON (or
    /// empty) and the operator's response schema accepts it.
    fn reply(&self, status: reqwest::StatusCode, bytes: &[u8]) -> Option<Value> {
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            parse_json_strict(bytes).ok()?
        };
        let reply = serde_json::to_value(ExternalResponse {
            status: status.as_u16(),
            body,
        })
        .ok()?;
        self.response_schema.is_valid(&reply).then_some(reply)
    }
}

/// Interpret one provider response to an `external.command/v1` call with the
/// project's pinned pure Function. The response is held to its declared
/// schema before the Function reads it. Anything the Function cannot turn into
/// an accepted result or a declared refusal leaves the command uncertain,
/// never failed: the provider may already have applied it. No code carries a
/// response or command value.
pub fn interpret_command(
    definition: &crate::definition::Definition,
    call: &crate::definition::Call,
    command: &Value,
    response: Value,
    synthetic: bool,
) -> CallOutcome {
    const FAILED: &str = "external-interpretation-failed";
    let Ok(contract) = definition.operation_contract(call) else {
        return uncertain(FAILED);
    };
    if contract.check_response(&response).is_err() {
        return uncertain("external-invalid-response");
    }
    let Some(interpret) = definition
        .workflow
        .operations
        .get(&call.alias)
        .and_then(|operation| operation.interpret.as_deref())
    else {
        return uncertain(FAILED);
    };
    let inputs = serde_json::json!({"command":command,"response":response});
    let Ok(mut value) = definition.evaluate_function(interpret, &inputs, synthetic) else {
        return uncertain(FAILED);
    };
    // The accepted result and the refusal are held to the step's own
    // contracts, so no other value can take either route.
    match value.get("state").and_then(Value::as_str) {
        Some("accepted") => match value.get_mut("result").map(Value::take) {
            Some(result) if contract.check_output(&result).is_ok() => CallOutcome::Success(result),
            _ => uncertain(FAILED),
        },
        Some("refused") => match value
            .get("code")
            .and_then(Value::as_str)
            .and_then(crate::protocol::DeclaredRefusal::new)
        {
            Some(refusal)
                if serde_json::to_value(&refusal)
                    .is_ok_and(|value| contract.check_refusal(&value).is_ok()) =>
            {
                CallOutcome::DeclaredRefusal(refusal)
            }
            _ => uncertain(FAILED),
        },
        Some("uncertain") => uncertain("external-uncertain"),
        _ => uncertain(FAILED),
    }
}

/// A busy answer that names a usable wait.
fn busy(code: &str, headers: &reqwest::header::HeaderMap) -> CallOutcome {
    CallOutcome::Retryable {
        code: code.into(),
        retry_after: match RetryAfter::from_headers(headers) {
            RetryAfter::Absent => None,
            RetryAfter::Seconds(seconds) if seconds <= MAXIMUM_RETRY_AFTER_SECONDS => {
                Some(Duration::from_secs(seconds))
            }
            _ => return refused("external-unusable-retry-after"),
        },
    }
}

fn uncertain(code: &str) -> CallOutcome {
    CallOutcome::Uncertain { code: code.into() }
}

fn refused(code: &str) -> CallOutcome {
    CallOutcome::Refused { code: code.into() }
}

fn unavailable() -> CallOutcome {
    CallOutcome::Retryable {
        code: "external-unavailable".into(),
        retry_after: None,
    }
}
