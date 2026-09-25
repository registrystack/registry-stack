// SPDX-License-Identifier: Apache-2.0

//! The HTTP provider kind: one send attempt to a configured HTTP provider,
//! shaped and read by the package's scripts, over the fixed destination
//! substrate.
//!
//! An attempt runs in this order, under one deadline of the configured
//! `timeoutMilliseconds`:
//!
//! 1. The prepare script turns the rendered message and the sender profile
//!    into a request target relative to `baseUrl`, a set of declared
//!    headers, and a body. Rust serializes the body as JSON or a form; the
//!    script never builds request bytes.
//! 2. Rust adds the credential. For OAuth client credentials the token is
//!    fetched from the token endpoint first, and cached.
//! 3. The substrate resolves the provider's host, refuses a metadata,
//!    private, or otherwise non-public address outside `allowedPrivateCidrs`,
//!    pins the connection to the checked address, and sends without
//!    following redirects.
//! 4. The interpret script, when the package ships one, classifies the
//!    response; otherwise the status code does.
//!
//! The outcome is the dispatch core's neutral [`SendOutcome`]:
//!
//! - a refusal before the connection is established is transient, since
//!   nothing reached the provider;
//! - a failure once it is established is maybe-sent;
//! - without an interpret script, `2xx` is accepted, `408`, `429`, and `5xx`
//!   are transient honouring a delta-seconds `Retry-After`, and any other
//!   status is permanent with the code `http.<status>`;
//! - a script failure, or a response the interpret script cannot read, falls
//!   back to the status, except that an unreadable `2xx` is maybe-sent, since
//!   a provider may answer `200` with an error body;
//! - a prepare script that fails, or a request the substrate refuses, is
//!   permanent: every later attempt would build the same request.
//!
//! Nothing here logs a recipient, a body, a credential, or a provider
//! response. The attempt detail is value-free: a stage, a status, and a
//! failure class.

mod script;
mod settings;
#[cfg(test)]
mod tests;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use registry_messaging_core::{CallbackRequest, Channel, Receipt, RenderedParts, SenderProfile};
use registry_platform_config::SecretResolver;
use registry_platform_dispatch::{FailureCode, ReceiverReference, SendOutcome, Sent};
use registry_platform_httputil::destination::json::decode_script_json;
use registry_platform_httputil::destination::oauth::{
    decode_strict_oauth_token, ParsedBearerToken, StrictOAuthTokenSchema,
};
use registry_platform_httputil::destination::{
    CredentialDestinationPolicy, CredentialDestinationRequestTemplate, DataDestinationPolicy,
    DataDestinationRequestTemplate, DestinationAuthorizationTemplate,
    DestinationAuthorizationValue, DestinationDeliveryCertainty, DestinationProfile,
    DestinationSendError, DestinationTlsMaterial, FixedDestinationPolicy,
    OAuth2ClientCredentialsBodyFormat, QueryStringContentAcknowledgement, ScriptRequestBodyFormat,
    SideEffectingSendMethod, MAX_DESTINATION_REQUEST_BODY_BYTES,
    MAX_DESTINATION_REQUEST_HEADER_BYTES, MAX_DESTINATION_TARGET_BYTES,
};
use rhai::AST;
use serde_json::{json, Map, Value};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::Instant;
use zeroize::Zeroizing;

pub use script::{
    ScriptFailure, MAXIMUM_PREPARE_OUTPUT_BYTES, MAXIMUM_SCRIPT_OPERATIONS,
    MAXIMUM_SCRIPT_OUTPUT_BYTES, MAXIMUM_SCRIPT_SOURCE_BYTES,
};
pub use settings::{
    CredentialPlacement, HttpProviderAuthentication, HttpProviderCapabilities, HttpProviderError,
    HttpProviderPackage, HttpProviderRequest, HttpProviderSettings, HttpSendMethod,
    ReceiptCapability, RedirectPolicy, MAXIMUM_CONCURRENCY_LIMIT, MAXIMUM_RATE_PER_SECOND,
    MAXIMUM_RESPONSE_BYTES, MAXIMUM_SCRIPT_HEADERS, MAXIMUM_SCRIPT_PATH_BYTES,
    MAXIMUM_TOKEN_CACHE_SECONDS, MINIMUM_TOKEN_CACHE_SECONDS,
};

use script::{
    BodyFormat, Interpretation, InterpretedOutcome, PreparedRequest, ScriptReceipt,
    INTERPRET_ENTRYPOINT, PREPARE_ENTRYPOINT, RECEIPT_ENTRYPOINT,
};
use settings::{invalid, ResolvedAuthentication, ResolvedOAuth2};

/// The longest `Retry-After` pause honoured, in seconds, from a header or a
/// script. A longer one is capped here; the dispatch core caps it again at
/// the job's maximum backoff.
pub const MAXIMUM_RETRY_AFTER_SECONDS: u64 = 3_600;

/// The largest token endpoint response read.
const MAXIMUM_TOKEN_RESPONSE_BYTES: usize = 16_384;

/// The longest access token accepted.
const MAXIMUM_ACCESS_TOKEN_BYTES: usize = 4_096;

/// How much earlier than its stated expiry a cached token is dropped.
const TOKEN_EXPIRY_SKEW_MILLISECONDS: u32 = 5_000;

/// The shortest `expires_in` a token endpoint may state.
const MINIMUM_TOKEN_EXPIRES_IN_SECONDS: u32 = 10;

/// The largest callback body a receipt script's JSON view is decoded from.
const MAXIMUM_RECEIPT_BODY_BYTES: usize = 65_536;

/// How long a receipt script may run.
const RECEIPT_SCRIPT_BUDGET: Duration = Duration::from_secs(1);

/// The script sources a package ships for one provider, read by the package
/// loader from the paths its [`HttpProviderPackage`] names.
#[derive(Clone, Copy)]
pub struct HttpProviderScripts<'a> {
    pub prepare: &'a str,
    pub interpret: Option<&'a str>,
    pub receipt: Option<&'a str>,
}

impl fmt::Debug for HttpProviderScripts<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProviderScripts")
            .field("interpret", &self.interpret.is_some())
            .field("receipt", &self.receipt.is_some())
            .finish_non_exhaustive()
    }
}

/// One message to hand to the provider: the persisted content of one send
/// and the identifiers of this attempt.
#[derive(Clone, Copy)]
pub struct HttpProviderMessage<'a> {
    pub message_id: &'a str,
    pub attempt: i16,
    pub generation: i64,
    pub channel: Channel,
    pub profile: &'a SenderProfile,
    pub recipient: &'a str,
    pub parts: &'a RenderedParts,
    /// The key a provider that declares `idempotentSubmit` deduplicates on,
    /// stable across every attempt of one message.
    pub idempotency_key: Option<&'a str>,
}

impl fmt::Debug for HttpProviderMessage<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProviderMessage")
            .field("message_id", &self.message_id)
            .field("attempt", &self.attempt)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// Where an attempt ended.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HttpStage {
    /// Waiting for a free send slot under `concurrencyLimit`.
    Queue,
    /// Running the prepare script and rendering the request.
    Prepare,
    /// Fetching an OAuth access token.
    Authenticate,
    /// Resolving, connecting, and sending.
    Send,
    /// Reading the response and classifying it.
    Interpret,
}

impl HttpStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queue => "queue",
            Self::Prepare => "prepare",
            Self::Authenticate => "authenticate",
            Self::Send => "send",
            Self::Interpret => "interpret",
        }
    }
}

/// Why an attempt did not end with a classified response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpFailure {
    /// A script produced no usable output.
    Script(ScriptFailure),
    /// The substrate refused the request the prepare script shaped.
    RequestRefused,
    /// The substrate refused or failed the send.
    Destination(DestinationSendError),
    /// The response body could not be read within its bound.
    ResponseUnreadable,
    /// The token endpoint did not issue a usable token.
    Token,
    /// The deadline passed before a send slot was free.
    Deadline,
}

impl HttpFailure {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Script(failure) => failure.as_str(),
            Self::RequestRefused => "request-refused",
            Self::Destination(_) => "destination",
            Self::ResponseUnreadable => "response-unreadable",
            Self::Token => "token",
            Self::Deadline => "deadline",
        }
    }
}

/// The value-free account of one attempt, for the product's audit and
/// attempt record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpAttemptDetail {
    pub stage: HttpStage,
    /// The provider's HTTP status, when a response arrived.
    pub status: Option<u16>,
    pub failure: Option<HttpFailure>,
}

/// Why a receipt script could not read a verified callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReceiptScriptError {
    #[error("the provider declares no receipt script")]
    NotDeclared,
    #[error("the callback carries a form field more than once")]
    DuplicateField,
    #[error("the receipt script produced no usable receipt: {}", .0.as_str())]
    Script(ScriptFailure),
    #[error("the receipt script returned an invalid receipt")]
    InvalidReceipt,
}

/// An activated HTTP provider, built by [`HttpProviderSettings::activate`].
pub struct HttpProvider {
    policy: DataDestinationPolicy,
    template: DataDestinationRequestTemplate,
    base_path: String,
    method: HttpSendMethod,
    response_headers: Vec<String>,
    authentication: Authentication,
    prepare: AST,
    interpret: Option<AST>,
    receipt: Option<AST>,
    timeout: Duration,
    maximum_response_bytes: usize,
    slots: Arc<Semaphore>,
    capabilities: HttpProviderCapabilities,
}

impl fmt::Debug for HttpProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProvider")
            .field("origin_id", &self.policy.origin_id())
            .field("method", &self.method)
            .field("timeout", &self.timeout)
            .field("interpret", &self.interpret.is_some())
            .field("receipt", &self.receipt.is_some())
            .finish_non_exhaustive()
    }
}

enum Authentication {
    None,
    Basic(Zeroizing<Vec<u8>>),
    Bearer(Zeroizing<Vec<u8>>),
    ApiKeyHeader(Zeroizing<Vec<u8>>),
    ApiKeyQuery(Zeroizing<Vec<u8>>),
    OAuth2(Box<OAuth2>),
}

struct OAuth2 {
    policy: CredentialDestinationPolicy,
    template: CredentialDestinationRequestTemplate,
    form_body: Zeroizing<Vec<u8>>,
    schema: StrictOAuthTokenSchema,
    maximum_cache_milliseconds: u32,
    assumed_lifetime_milliseconds: Option<u32>,
    cached: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    token: ParsedBearerToken,
    usable_until: Instant,
}

impl HttpProviderSettings {
    /// Check both halves of one provider, resolve its credentials, compile
    /// its scripts, and freeze its destination.
    ///
    /// `provider_id` is the package's provider id and becomes the
    /// destination's non-secret origin id. `trust_bundle_pem` is the PEM the
    /// runtime resolved for `tlsTrustProfile`, supplied exactly when that
    /// member is set.
    ///
    /// # Errors
    ///
    /// [`HttpProviderError`] naming the first member, secret reference, or
    /// script that cannot be used.
    pub fn activate(
        &self,
        provider_id: &str,
        package: &HttpProviderPackage,
        scripts: HttpProviderScripts<'_>,
        trust_bundle_pem: Option<&[u8]>,
        secrets: &SecretResolver,
    ) -> Result<HttpProvider, HttpProviderError> {
        package.validate()?;
        let connection = self.check_connection(package, trust_bundle_pem)?;
        let (prepare, interpret, receipt) = compile_scripts(package, scripts)?;
        let resolved = self.resolve_authentication(package, connection.development, secrets)?;
        let origin_id = destination_origin_id(provider_id)?;
        let profile = if connection.development {
            DestinationProfile::LoopbackDevelopmentHttp
        } else {
            DestinationProfile::ProductionHttps
        };
        let policy = freeze_policy(
            &origin_id,
            &connection.origin,
            profile,
            &connection.allowed_private_cidrs,
            trust_bundle_pem,
            "baseUrl",
        )?;
        let (authorization, api_key_header, api_key_query, authentication) = match resolved {
            ResolvedAuthentication::None => (
                DestinationAuthorizationTemplate::Forbidden,
                None,
                None,
                Authentication::None,
            ),
            ResolvedAuthentication::Basic(value) => (
                DestinationAuthorizationTemplate::Basic {
                    max_value_bytes: settings::MAXIMUM_CREDENTIAL_VALUE_BYTES * 2,
                },
                None,
                None,
                Authentication::Basic(value),
            ),
            ResolvedAuthentication::Bearer(value) => (
                DestinationAuthorizationTemplate::Bearer {
                    max_value_bytes: settings::MAXIMUM_CREDENTIAL_VALUE_BYTES,
                },
                None,
                None,
                Authentication::Bearer(value),
            ),
            ResolvedAuthentication::ApiKeyHeader { name, value } => (
                DestinationAuthorizationTemplate::Forbidden,
                Some(name),
                None,
                Authentication::ApiKeyHeader(value),
            ),
            ResolvedAuthentication::ApiKeyQuery { name, value } => (
                DestinationAuthorizationTemplate::Forbidden,
                None,
                Some(name),
                Authentication::ApiKeyQuery(value),
            ),
            ResolvedAuthentication::OAuth2(oauth) => (
                DestinationAuthorizationTemplate::Bearer {
                    max_value_bytes: MAXIMUM_ACCESS_TOKEN_BYTES,
                },
                None,
                None,
                Authentication::OAuth2(Box::new(freeze_oauth(
                    &origin_id,
                    oauth,
                    &connection.allowed_private_cidrs,
                    trust_bundle_pem,
                )?)),
            ),
        };
        let method = match package.request.method {
            HttpSendMethod::Post => SideEffectingSendMethod::Post,
            HttpSendMethod::Get => SideEffectingSendMethod::Get(
                QueryStringContentAcknowledgement::acknowledge_content_in_access_logs(),
            ),
        };
        let request_headers = package
            .request
            .headers
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let template = DataDestinationRequestTemplate::new_script_send(
            method,
            &format!("{}**", connection.base_path),
            &request_headers,
            authorization,
            api_key_header
                .as_deref()
                .map(|name| (name, settings::MAXIMUM_CREDENTIAL_VALUE_BYTES)),
            api_key_query
                .as_deref()
                .map(|name| (name, settings::MAXIMUM_CREDENTIAL_VALUE_BYTES)),
            MAX_DESTINATION_TARGET_BYTES
                + MAX_DESTINATION_REQUEST_HEADER_BYTES
                + MAX_DESTINATION_REQUEST_BODY_BYTES,
        )
        .map_err(|_| invalid("request", "the request shape could not be compiled"))?;
        Ok(HttpProvider {
            policy,
            template,
            base_path: connection.base_path,
            method: package.request.method,
            response_headers: package.response_headers.clone(),
            authentication,
            prepare,
            interpret,
            receipt,
            timeout: connection.timeout,
            maximum_response_bytes: connection.maximum_response_bytes,
            slots: Arc::new(Semaphore::new(usize::from(self.concurrency_limit))),
            capabilities: package.capabilities.clone(),
        })
    }
}

/// Compile the scripts one provider package names, each under its
/// entry-point contract. The package loader runs this to refuse a script
/// that does not compile; activation runs it to keep the result.
pub(crate) fn compile_scripts(
    package: &HttpProviderPackage,
    scripts: HttpProviderScripts<'_>,
) -> Result<(AST, Option<AST>, Option<AST>), HttpProviderError> {
    let prepare = script::compile("prepareScript", scripts.prepare, PREPARE_ENTRYPOINT, 2)?;
    let interpret = match (&package.interpret_script, scripts.interpret) {
        (Some(_), Some(source)) => Some(script::compile(
            "interpretScript",
            source,
            INTERPRET_ENTRYPOINT,
            1,
        )?),
        (None, None) => None,
        _ => {
            return Err(invalid(
                "interpretScript",
                "a source is supplied exactly when the package names one",
            ))
        }
    };
    let receipt = match (&package.receipt_script, scripts.receipt) {
        (Some(_), Some(source)) => Some(script::compile(
            "receiptScript",
            source,
            RECEIPT_ENTRYPOINT,
            1,
        )?),
        (None, None) => None,
        _ => {
            return Err(invalid(
                "receiptScript",
                "a source is supplied exactly when the package names one",
            ))
        }
    };
    Ok((prepare, interpret, receipt))
}

fn destination_origin_id(provider_id: &str) -> Result<String, HttpProviderError> {
    let valid = !provider_id.is_empty()
        && provider_id.len() <= 64
        && provider_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !provider_id.starts_with('-')
        && !provider_id.ends_with('-');
    if valid {
        Ok(format!("messaging-provider:{provider_id}"))
    } else {
        Err(invalid(
            "id",
            "the provider id must be 1 to 64 lowercase letters, digits, or inner hyphens",
        ))
    }
}

fn freeze_policy<S: registry_platform_httputil::destination::DestinationSlot>(
    origin_id: &str,
    origin: &str,
    profile: DestinationProfile,
    allowed_private_cidrs: &[ipnet::IpNet],
    trust_bundle_pem: Option<&[u8]>,
    field: &'static str,
) -> Result<FixedDestinationPolicy<S>, HttpProviderError> {
    let mut policy = FixedDestinationPolicy::new(origin_id, origin, profile, allowed_private_cidrs)
        .map_err(|error| invalid(field, format!("cannot be frozen as a destination: {error}")))?;
    if let Some(pem) = trust_bundle_pem {
        let material = DestinationTlsMaterial::from_pem(Some(pem), None)
            .map_err(|_| invalid("tlsTrustProfile", "the trust bundle is not valid PEM"))?;
        policy = policy.require_configured_tls();
        policy
            .install_configured_tls(material)
            .map_err(|_| invalid("tlsTrustProfile", "the trust bundle could not be installed"))?;
    }
    Ok(policy)
}

fn freeze_oauth(
    origin_id: &str,
    oauth: ResolvedOAuth2,
    allowed_private_cidrs: &[ipnet::IpNet],
    trust_bundle_pem: Option<&[u8]>,
) -> Result<OAuth2, HttpProviderError> {
    let profile = if oauth.development {
        DestinationProfile::LoopbackDevelopmentHttp
    } else {
        DestinationProfile::ProductionHttps
    };
    let policy = freeze_policy(
        &format!("{origin_id}:token"),
        &oauth.origin,
        profile,
        allowed_private_cidrs,
        trust_bundle_pem,
        "authentication.tokenEndpoint",
    )?;
    let template = CredentialDestinationRequestTemplate::oauth2_client_credentials(
        &oauth.path,
        OAuth2ClientCredentialsBodyFormat::FormClientSecretBody,
        8_192,
        MAX_DESTINATION_TARGET_BYTES + MAX_DESTINATION_REQUEST_HEADER_BYTES + 8_192,
    )
    .map_err(|_| {
        invalid(
            "authentication.tokenEndpoint",
            "the token request shape could not be compiled",
        )
    })?;
    if oauth.form_body.len() > 8_192 {
        return Err(invalid(
            "authentication",
            "the token request body exceeds 8192 bytes",
        ));
    }
    let (schema, assumed_lifetime_milliseconds) = match oauth.assumed_lifetime_seconds {
        Some(seconds) => (
            StrictOAuthTokenSchema::Rfc6749BearerWithoutExpiry,
            Some(seconds.saturating_mul(1_000)),
        ),
        None => (StrictOAuthTokenSchema::Rfc6749BearerWithExpiresIn, None),
    };
    Ok(OAuth2 {
        policy,
        template,
        form_body: oauth.form_body,
        schema,
        maximum_cache_milliseconds: oauth.maximum_cache_seconds.saturating_mul(1_000),
        assumed_lifetime_milliseconds,
        cached: Mutex::new(None),
    })
}

/// How one attempt ended before classification.
struct Ended {
    outcome: SendOutcome,
    stage: HttpStage,
    status: Option<u16>,
    failure: Option<HttpFailure>,
}

impl Ended {
    const fn failed(outcome: SendOutcome, stage: HttpStage, failure: HttpFailure) -> Self {
        Self {
            outcome,
            stage,
            status: None,
            failure: Some(failure),
        }
    }
}

impl HttpProvider {
    /// The configured attempt timeout.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The capabilities the package declared.
    #[must_use]
    pub fn capabilities(&self) -> &HttpProviderCapabilities {
        &self.capabilities
    }

    /// Make one send attempt and classify it.
    pub async fn send(&self, message: &HttpProviderMessage<'_>) -> Sent<HttpAttemptDetail> {
        let deadline = Instant::now() + self.timeout;
        let ended = self.attempt(message, deadline).await;
        tracing::debug!(
            stage = ended.stage.as_str(),
            status = ended.status,
            failure = ended.failure.map(HttpFailure::as_str),
            outcome = outcome_class(&ended.outcome),
            "http provider attempt finished"
        );
        Sent {
            outcome: ended.outcome,
            detail: HttpAttemptDetail {
                stage: ended.stage,
                status: ended.status,
                failure: ended.failure,
            },
        }
    }

    async fn attempt(&self, message: &HttpProviderMessage<'_>, deadline: Instant) -> Ended {
        let Ok(Ok(_slot)) = tokio::time::timeout_at(deadline, self.slots.acquire()).await else {
            return Ended::failed(
                SendOutcome::Transient { retry_after: None },
                HttpStage::Queue,
                HttpFailure::Deadline,
            );
        };
        let prepared = match self.prepare(message, deadline.into_std()) {
            Ok(prepared) => prepared,
            Err(failure) => {
                return Ended::failed(prepare_outcome(failure), HttpStage::Prepare, failure)
            }
        };
        let (authorization, api_key) = match self.credential(deadline).await {
            Ok(credential) => credential,
            Err(ended) => return ended,
        };
        let request = match self.template.render_script(
            &prepared.target,
            &prepared
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes()))
                .collect::<Vec<_>>(),
            authorization,
            api_key,
            prepared.body_format,
            prepared.body,
        ) {
            Ok(request) => request,
            Err(_) => {
                return Ended::failed(
                    permanent("provider.request-refused"),
                    HttpStage::Prepare,
                    HttpFailure::RequestRefused,
                )
            }
        };
        let response = match self.policy.send_with_deadline(request, deadline).await {
            Ok(response) => response,
            Err(error) => {
                return Ended::failed(
                    send_error_outcome(error),
                    HttpStage::Send,
                    HttpFailure::Destination(error),
                )
            }
        };
        let status = response.status().as_u16();
        if status == 401 {
            if let Authentication::OAuth2(oauth) = &self.authentication {
                oauth.cached.lock().await.take();
                return Ended {
                    outcome: SendOutcome::Transient { retry_after: None },
                    stage: HttpStage::Interpret,
                    status: Some(status),
                    failure: Some(HttpFailure::Token),
                };
            }
        }
        let mut header_names = self
            .response_headers
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if !header_names.contains(&"retry-after") {
            header_names.push("retry-after");
        }
        let selected = response
            .selected_script_response_headers(header_names.iter().copied())
            .ok();
        let retry_after = selected.as_ref().and_then(|values| {
            let index = header_names
                .iter()
                .position(|name| *name == "retry-after")?;
            parse_retry_after(values[index].as_deref()?)
        });
        let Some(interpret) = &self.interpret else {
            return Ended {
                outcome: default_outcome(status, retry_after),
                stage: HttpStage::Interpret,
                status: Some(status),
                failure: None,
            };
        };
        let unclassifiable = |failure: HttpFailure| Ended {
            outcome: unclassifiable_outcome(status, retry_after),
            stage: HttpStage::Interpret,
            status: Some(status),
            failure: Some(failure),
        };
        let Some(selected) = selected else {
            return unclassifiable(HttpFailure::ResponseUnreadable);
        };
        let body = match response.read_bounded(self.maximum_response_bytes).await {
            Ok(body) => body,
            Err(_) => return unclassifiable(HttpFailure::ResponseUnreadable),
        };
        let body = decode_script_json(body).map_or(Value::Null, |decoded| decoded.into_parts().0);
        let mut headers = Map::new();
        for (name, value) in header_names.iter().zip(selected) {
            if let Some(value) = value {
                if self.response_headers.iter().any(|allowed| allowed == name) {
                    headers.insert((*name).to_owned(), Value::String(value));
                }
            }
        }
        let view = json!({"status": status, "headers": headers, "body": body});
        match interpret_response(interpret, view, retry_after, deadline.into_std()) {
            Ok(outcome) => Ended {
                outcome,
                stage: HttpStage::Interpret,
                status: Some(status),
                failure: None,
            },
            Err(failure) => unclassifiable(HttpFailure::Script(failure)),
        }
    }

    fn prepare(
        &self,
        message: &HttpProviderMessage<'_>,
        deadline: std::time::Instant,
    ) -> Result<RenderedRequest, HttpFailure> {
        let output = script::run(
            &self.prepare,
            PREPARE_ENTRYPOINT,
            vec![message_view(message), profile_view(message.profile)],
            deadline,
            MAXIMUM_PREPARE_OUTPUT_BYTES,
        )
        .map_err(HttpFailure::Script)?;
        let prepared: PreparedRequest = script::read_output(output).map_err(HttpFailure::Script)?;
        let target =
            join_target(&self.base_path, &prepared.target).ok_or(HttpFailure::RequestRefused)?;
        let (body_format, body) = match (self.method, prepared.body_format, prepared.body) {
            (HttpSendMethod::Get, None, None | Some(Value::Null)) => (None, None),
            (HttpSendMethod::Post, Some(format), Some(body)) => {
                let bytes = serialize_body(format, &body).map_err(HttpFailure::Script)?;
                let format = match format {
                    BodyFormat::Json => ScriptRequestBodyFormat::Json,
                    BodyFormat::Form => ScriptRequestBodyFormat::Form,
                };
                (Some(format), Some(bytes))
            }
            _ => return Err(HttpFailure::Script(ScriptFailure::OutputInvalid)),
        };
        Ok(RenderedRequest {
            target,
            headers: prepared.headers,
            body_format,
            body,
        })
    }

    async fn credential(
        &self,
        deadline: Instant,
    ) -> Result<
        (
            Option<DestinationAuthorizationValue>,
            Option<Zeroizing<Vec<u8>>>,
        ),
        Ended,
    > {
        let refused = || {
            Ended::failed(
                permanent("provider.request-refused"),
                HttpStage::Prepare,
                HttpFailure::RequestRefused,
            )
        };
        match &self.authentication {
            Authentication::None => Ok((None, None)),
            Authentication::Basic(value) => {
                DestinationAuthorizationValue::basic_zeroizing(value.clone())
                    .map(|value| (Some(value), None))
                    .map_err(|_| refused())
            }
            Authentication::Bearer(value) => {
                DestinationAuthorizationValue::bearer_zeroizing(value.clone())
                    .map(|value| (Some(value), None))
                    .map_err(|_| refused())
            }
            Authentication::ApiKeyHeader(value) | Authentication::ApiKeyQuery(value) => {
                Ok((None, Some(value.clone())))
            }
            Authentication::OAuth2(oauth) => oauth
                .authorization(deadline)
                .await
                .map(|value| (Some(value), None)),
        }
    }

    /// Read one verified delivery callback through the receipt script.
    ///
    /// The route verifies `request` first; this only reads it. The script
    /// sees the method, the form fields, the query parameters of the
    /// callback URL, and the body decoded as JSON when it is JSON. It never
    /// sees the URL itself, the headers, or the path token. It returns a
    /// receipt, or `()` for a callback that reports nothing this runtime
    /// records.
    ///
    /// # Errors
    ///
    /// [`ReceiptScriptError`] when the provider has no receipt script, the
    /// callback repeats a form field, or the script's output is unusable.
    pub fn receipt(
        &self,
        request: &CallbackRequest<'_>,
    ) -> Result<Option<Receipt>, ReceiptScriptError> {
        let script = self
            .receipt
            .as_ref()
            .ok_or(ReceiptScriptError::NotDeclared)?;
        let mut form = Map::new();
        for (name, value) in request.form_parameters {
            if form
                .insert((*name).to_owned(), Value::String((*value).to_owned()))
                .is_some()
            {
                return Err(ReceiptScriptError::DuplicateField);
            }
        }
        let mut query = Map::new();
        if let Some((_, raw)) = request.url.split_once('?') {
            let raw = raw.split_once('#').map_or(raw, |(query, _)| query);
            for (name, value) in url::form_urlencoded::parse(raw.as_bytes()) {
                if query
                    .insert(name.into_owned(), Value::String(value.into_owned()))
                    .is_some()
                {
                    return Err(ReceiptScriptError::DuplicateField);
                }
            }
        }
        let body = if request.body.is_empty() || request.body.len() > MAXIMUM_RECEIPT_BODY_BYTES {
            Value::Null
        } else {
            serde_json::from_slice(request.body).unwrap_or(Value::Null)
        };
        let view = json!({
            "method": request.method,
            "form": form,
            "query": query,
            "json": body,
        });
        let output = script::run(
            script,
            RECEIPT_ENTRYPOINT,
            vec![view],
            std::time::Instant::now() + RECEIPT_SCRIPT_BUDGET,
            MAXIMUM_SCRIPT_OUTPUT_BYTES,
        )
        .map_err(ReceiptScriptError::Script)?;
        if output.is_null() {
            return Ok(None);
        }
        let read: ScriptReceipt =
            script::read_output(output).map_err(ReceiptScriptError::Script)?;
        let receipt = Receipt {
            provider_reference: read.provider_reference,
            report: read.report,
            code: read.code,
        };
        receipt
            .validate()
            .map_err(|_| ReceiptScriptError::InvalidReceipt)?;
        Ok(Some(receipt))
    }
}

impl OAuth2 {
    async fn authorization(
        &self,
        deadline: Instant,
    ) -> Result<DestinationAuthorizationValue, Ended> {
        let failed = || {
            Ended::failed(
                SendOutcome::Transient { retry_after: None },
                HttpStage::Authenticate,
                HttpFailure::Token,
            )
        };
        let mut cached = self.cached.lock().await;
        if let Some(token) = cached.as_ref() {
            if Instant::now() < token.usable_until {
                return token.token.authorization().map_err(|_| failed());
            }
        }
        cached.take();
        let request = self
            .template
            .render_zeroizing(&[], &[], None, Some(self.form_body.clone()))
            .map_err(|_| failed())?;
        let response = self
            .policy
            .send_with_deadline(request, deadline)
            .await
            .map_err(|error| {
                Ended::failed(
                    SendOutcome::Transient { retry_after: None },
                    HttpStage::Authenticate,
                    HttpFailure::Destination(error),
                )
            })?;
        if !response.status().is_success() {
            return Err(Ended {
                outcome: SendOutcome::Transient { retry_after: None },
                stage: HttpStage::Authenticate,
                status: Some(response.status().as_u16()),
                failure: Some(HttpFailure::Token),
            });
        }
        let body = response
            .read_bounded(MAXIMUM_TOKEN_RESPONSE_BYTES)
            .await
            .map_err(|_| failed())?;
        let token = match self.schema {
            StrictOAuthTokenSchema::BearerWithExpiresIn
            | StrictOAuthTokenSchema::Rfc6749BearerWithExpiresIn => decode_strict_oauth_token(
                body,
                self.schema,
                MAXIMUM_TOKEN_RESPONSE_BYTES,
                MAXIMUM_ACCESS_TOKEN_BYTES,
                Some(MINIMUM_TOKEN_EXPIRES_IN_SECONDS),
                Some(u32::MAX / 1_000),
                Some(self.maximum_cache_milliseconds),
                Some(TOKEN_EXPIRY_SKEW_MILLISECONDS),
            ),
            StrictOAuthTokenSchema::BearerWithoutExpiry
            | StrictOAuthTokenSchema::Rfc6749BearerWithoutExpiry => decode_strict_oauth_token(
                body,
                self.schema,
                MAXIMUM_TOKEN_RESPONSE_BYTES,
                MAXIMUM_ACCESS_TOKEN_BYTES,
                None,
                None,
                None,
                None,
            ),
        }
        .map_err(|_| failed())?;
        let lifetime_milliseconds = token
            .usable_lifetime_ms()
            .or_else(|| {
                self.assumed_lifetime_milliseconds.map(|assumed| {
                    assumed
                        .min(self.maximum_cache_milliseconds)
                        .saturating_sub(TOKEN_EXPIRY_SKEW_MILLISECONDS)
                })
            })
            .unwrap_or(0);
        let authorization = token.authorization().map_err(|_| failed())?;
        *cached = Some(CachedToken {
            token,
            usable_until: Instant::now() + Duration::from_millis(u64::from(lifetime_milliseconds)),
        });
        Ok(authorization)
    }
}

struct RenderedRequest {
    target: String,
    headers: std::collections::BTreeMap<String, String>,
    body_format: Option<ScriptRequestBodyFormat>,
    body: Option<Zeroizing<Vec<u8>>>,
}

/// The message as the prepare script sees it. No secret is ever in it.
fn message_view(message: &HttpProviderMessage<'_>) -> Value {
    let mut parts = Map::new();
    if let Some(subject) = &message.parts.subject {
        parts.insert("subject".to_owned(), Value::String(subject.clone()));
    }
    parts.insert("text".to_owned(), Value::String(message.parts.text.clone()));
    if let Some(html) = &message.parts.html {
        parts.insert("html".to_owned(), Value::String(html.clone()));
    }
    json!({
        "messageId": message.message_id,
        "attempt": message.attempt,
        "generation": message.generation,
        "channel": message.channel,
        "recipient": message.recipient,
        "idempotencyKey": message.idempotency_key,
        "parts": parts,
    })
}

fn profile_view(profile: &SenderProfile) -> Value {
    json!({
        "id": profile.id,
        "channel": profile.channel,
        "sender": profile.sender,
        "maximumSegments": profile.maximum_segments,
    })
}

/// Join a script's relative target to the base path. An absolute path, a
/// scheme, a fragment, or a backslash is refused here; the substrate then
/// refuses a non-canonical target or one outside the base path.
fn join_target(base_path: &str, target: &str) -> Option<String> {
    if target.is_empty()
        || target.starts_with('/')
        || target.contains("://")
        || target.contains(['#', '\\'])
        || target.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    Some(format!("{base_path}{target}"))
}

fn serialize_body(format: BodyFormat, body: &Value) -> Result<Zeroizing<Vec<u8>>, ScriptFailure> {
    match format {
        BodyFormat::Json => match body {
            Value::Object(_) | Value::Array(_) => serde_json::to_vec(body)
                .map(Zeroizing::new)
                .map_err(|_| ScriptFailure::OutputInvalid),
            _ => Err(ScriptFailure::OutputInvalid),
        },
        BodyFormat::Form => {
            let Value::Object(fields) = body else {
                return Err(ScriptFailure::OutputInvalid);
            };
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in fields {
                let value = match value {
                    Value::String(value) => value.clone(),
                    Value::Number(value) => value.to_string(),
                    Value::Bool(value) => value.to_string(),
                    Value::Null => continue,
                    Value::Array(_) | Value::Object(_) => return Err(ScriptFailure::OutputInvalid),
                };
                serializer.append_pair(name, &value);
            }
            Ok(Zeroizing::new(serializer.finish().into_bytes()))
        }
    }
}

/// Run the interpret script and check its output. A transient outcome
/// without its own `retryAfter` keeps the response's `Retry-After`.
fn interpret_response(
    interpret: &AST,
    view: Value,
    header_retry_after: Option<Duration>,
    deadline: std::time::Instant,
) -> Result<SendOutcome, ScriptFailure> {
    let output = script::run(
        interpret,
        INTERPRET_ENTRYPOINT,
        vec![view],
        deadline,
        MAXIMUM_SCRIPT_OUTPUT_BYTES,
    )?;
    let read: Interpretation = script::read_output(output)?;
    match read.outcome {
        InterpretedOutcome::Accepted if read.retry_after.is_none() && read.code.is_none() => {
            let provider_reference = read
                .provider_reference
                .map(ReceiverReference::new)
                .transpose()
                .map_err(|_| ScriptFailure::OutputInvalid)?;
            Ok(SendOutcome::Accepted {
                receiver_reference: provider_reference,
            })
        }
        InterpretedOutcome::Transient
            if read.provider_reference.is_none() && read.code.is_none() =>
        {
            let retry_after = match read.retry_after {
                Some(seconds) if seconds >= 1 => Some(Duration::from_secs(
                    seconds.min(MAXIMUM_RETRY_AFTER_SECONDS),
                )),
                Some(_) => return Err(ScriptFailure::OutputInvalid),
                None => header_retry_after,
            };
            Ok(SendOutcome::Transient { retry_after })
        }
        InterpretedOutcome::Permanent
            if read.provider_reference.is_none() && read.retry_after.is_none() =>
        {
            let code = read
                .code
                .ok_or(ScriptFailure::OutputInvalid)
                .and_then(|code| {
                    FailureCode::new(code).map_err(|_| ScriptFailure::OutputInvalid)
                })?;
            Ok(SendOutcome::Permanent { code })
        }
        InterpretedOutcome::MaybeSent
            if read.provider_reference.is_none()
                && read.retry_after.is_none()
                && read.code.is_none() =>
        {
            Ok(SendOutcome::MaybeSent)
        }
        _ => Err(ScriptFailure::OutputInvalid),
    }
}

/// Classify a response by its status alone.
fn default_outcome(status: u16, retry_after: Option<Duration>) -> SendOutcome {
    match status {
        200..=299 => SendOutcome::Accepted {
            receiver_reference: None,
        },
        408 | 429 | 500..=599 => SendOutcome::Transient { retry_after },
        _ => permanent(&format!("http.{status}")),
    }
}

/// Classify a response the interpret script could not read: a success
/// status may still carry an error body, so it is maybe-sent.
fn unclassifiable_outcome(status: u16, retry_after: Option<Duration>) -> SendOutcome {
    if (200..=299).contains(&status) {
        SendOutcome::MaybeSent
    } else {
        default_outcome(status, retry_after)
    }
}

fn prepare_outcome(failure: HttpFailure) -> SendOutcome {
    match failure {
        HttpFailure::Script(ScriptFailure::Deadline) => {
            SendOutcome::Transient { retry_after: None }
        }
        HttpFailure::RequestRefused => permanent("provider.request-refused"),
        _ => permanent("provider.prepare-failed"),
    }
}

fn send_error_outcome(error: DestinationSendError) -> SendOutcome {
    match error.delivery_certainty() {
        DestinationDeliveryCertainty::NotSent => SendOutcome::Transient { retry_after: None },
        DestinationDeliveryCertainty::MaybeSent => SendOutcome::MaybeSent,
    }
}

fn permanent(code: &str) -> SendOutcome {
    SendOutcome::Permanent {
        code: FailureCode::new(code).expect("product failure codes are within the dispatch bound"),
    }
}

/// Read one `Retry-After` value: delta-seconds only, capped at
/// [`MAXIMUM_RETRY_AFTER_SECONDS`]. An HTTP date or a zero is ignored.
fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() || value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let seconds = value.parse::<u64>().ok()?;
    (seconds >= 1).then(|| Duration::from_secs(seconds.min(MAXIMUM_RETRY_AFTER_SECONDS)))
}

const fn outcome_class(outcome: &SendOutcome) -> &'static str {
    match outcome {
        SendOutcome::Accepted { .. } => "accepted",
        SendOutcome::Transient { .. } => "transient",
        SendOutcome::Permanent { .. } => "permanent",
        SendOutcome::MaybeSent => "maybe-sent",
    }
}
