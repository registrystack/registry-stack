// SPDX-License-Identifier: Apache-2.0

//! The two authored halves of one HTTP provider and their checks.
//!
//! [`HttpProviderPackage`] is package material: the scripts that shape a
//! request and read a response, the request headers a script may set, the
//! response headers it may read, and what the provider can do. It carries no
//! endpoint and no credential. [`HttpProviderSettings`] is runtime
//! configuration: the connection, the authentication, and the callback
//! verifier. Every credential is a `secret:env/` or `secret:file/` reference in
//! a member ending in `Ref`.
//!
//! The authentication grammar mirrors Evidence's fixed-source
//! `SourceAuthentication` member for member where the substrate can honour
//! it, and adds `static-api-key-query`. It is a copy, not a dependency:
//! Messaging may not depend on the Evidence runtime crate, and a shared
//! platform grammar is a later extraction.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;
use registry_messaging_core::{valid_header_name, CallbackVerifierConfig};
use registry_platform_config::{ProtectedSecret, SecretReference, SecretResolver};
use registry_platform_httputil::destination::{
    is_script_writable_request_header_name, MAX_DESTINATION_OPERATION_TIMEOUT,
    MAX_DESTINATION_PRIVATE_CIDRS,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::config::describe_secret_failure;

/// The longest script artifact path a package may name.
pub const MAXIMUM_SCRIPT_PATH_BYTES: usize = 256;

/// The most request headers a prepare script may set, and the most response
/// headers an interpret script may read.
pub const MAXIMUM_SCRIPT_HEADERS: usize = 16;

/// The most sends one provider may have in flight.
pub const MAXIMUM_CONCURRENCY_LIMIT: u16 = 64;

/// The highest declared send rate.
pub const MAXIMUM_RATE_PER_SECOND: u32 = 1_000;

/// The largest provider response body a send reads.
pub const MAXIMUM_RESPONSE_BYTES: u64 = 1_048_576;

/// The longest OAuth token cache lifetime an operator may configure.
pub const MAXIMUM_TOKEN_CACHE_SECONDS: u64 = 86_400;

/// The shortest OAuth token cache lifetime an operator may configure; a
/// shorter lifetime would not survive the expiry safety skew.
pub const MINIMUM_TOKEN_CACHE_SECONDS: u64 = 10;

/// The longest static credential value placed in a header or a query
/// parameter.
pub(crate) const MAXIMUM_CREDENTIAL_VALUE_BYTES: usize = 4_096;

/// Package material for one HTTP provider.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpProviderPackage {
    /// Package path of the script whose `prepare(message, profile)` returns
    /// the request.
    pub prepare_script: String,
    /// Package path of the script whose `interpret(response)` classifies the
    /// response. Without one, the status code decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpret_script: Option<String>,
    /// Package path of the script whose `receipt(request)` reads a verified
    /// delivery callback. Required exactly when `capabilities.receipts` is
    /// `callback`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_script: Option<String>,
    pub request: HttpProviderRequest,
    /// Response headers the interpret script may read, lowercase.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_headers: Vec<String>,
    pub capabilities: HttpProviderCapabilities,
}

/// The request shape a prepare script fills.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpProviderRequest {
    pub method: HttpSendMethod,
    /// Request headers the prepare script may set, lowercase. The
    /// authorization, host, content, cookie, and forwarding headers are never
    /// script-writable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<String>,
}

/// The method one send uses.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpSendMethod {
    /// A JSON or form body.
    Post,
    /// The message in the query string, for gateways that accept nothing
    /// else. The runtime settings must acknowledge that the content reaches
    /// the provider's access logs.
    Get,
}

/// What a provider can do, declared by the package.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpProviderCapabilities {
    pub receipts: ReceiptCapability,
    /// Whether the provider deduplicates submissions on a key the request
    /// carries. Only then may an uncertain send be retried without the
    /// operator accepting duplicates.
    pub idempotent_submit: bool,
    /// The most sends the provider accepts at once, 1 to 64.
    pub concurrency_limit: u16,
    /// The provider's documented send rate. The worker enforces it at claim
    /// time; this module only checks it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_per_second: Option<u32>,
}

/// How a provider reports delivery after accepting a message.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptCapability {
    None,
    Callback,
    Reconcile,
}

/// Runtime settings for one HTTP provider.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpProviderSettings {
    /// The provider's origin and path prefix, ending in `/`. Every request
    /// target a script returns is relative to it and stays under it.
    /// `https` in production; `http` only to a loopback host.
    pub base_url: String,
    /// The operator-declared trust bundle the provider's certificate chains
    /// to, instead of the public web roots. The runtime resolves the name to
    /// PEM and passes it to [`HttpProviderSettings::activate`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_trust_profile: Option<String>,
    /// One send's whole budget: resolution, connection, request, and
    /// response, at most 10000.
    pub timeout_milliseconds: u64,
    /// The largest response body read, at most 1 MiB.
    pub maximum_response_bytes: u64,
    /// The most sends this deployment has in flight to the provider, at most
    /// the package's declared `capabilities.concurrencyLimit`.
    pub concurrency_limit: u16,
    pub redirects: RedirectPolicy,
    /// Exact RFC 1918, CGNAT, or unique-local networks an `https` provider may
    /// resolve into, for an in-country gateway on a private network. Every
    /// other non-public address is refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_private_cidrs: Vec<String>,
    /// Required, and only allowed, when the package sends with `get`: the
    /// message content travels in the query string, where provider access
    /// logs keep it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub acknowledge_query_string_content: bool,
    pub authentication: HttpProviderAuthentication,
    /// How the provider's delivery callbacks are authenticated. Required
    /// exactly when the package declares `receipts: callback`.
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<serde_json::Map<String, serde_json::Value>>")
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_verifier: Option<CallbackVerifierConfig>,
}

impl fmt::Debug for HttpProviderSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProviderSettings")
            .field("base_url", &self.base_url)
            .field("tls_trust_profile", &self.tls_trust_profile)
            .field("timeout_milliseconds", &self.timeout_milliseconds)
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .field("concurrency_limit", &self.concurrency_limit)
            .field("allowed_private_cidrs", &self.allowed_private_cidrs)
            .field(
                "acknowledge_query_string_content",
                &self.acknowledge_query_string_content,
            )
            .field("authentication", &self.authentication)
            .field("callback_verifier", &self.callback_verifier.is_some())
            .finish()
    }
}

/// Redirect handling. A provider redirect is never followed.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RedirectPolicy {
    Deny,
}

/// How a send authenticates to the provider. The credential is added by
/// Rust after the prepare script returns; no script ever sees it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HttpProviderAuthentication {
    /// No credential. Only for a loopback development provider.
    None {},
    /// `Authorization: Basic` over the two resolved values.
    Basic {
        username_ref: String,
        password_ref: String,
    },
    /// `Authorization: <scheme> <token>`. Absent, the scheme is `Bearer`,
    /// the only one the destination substrate presents today.
    StaticAuthorization {
        token_ref: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
    },
    /// The resolved value in the named request header.
    StaticApiKey {
        header_name: String,
        value_ref: String,
    },
    /// The resolved value in the named query parameter, appended after the
    /// script's own target.
    StaticApiKeyQuery {
        parameter_name: String,
        value_ref: String,
    },
    /// An OAuth 2.0 client-credentials bearer token, fetched from
    /// `tokenEndpoint` and cached.
    Oauth2ClientCredentials {
        token_endpoint: String,
        client_id_ref: String,
        client_secret_ref: String,
        /// Where the client secret travels. The token request carries it in
        /// the form body; `basic-header` is refused until the substrate can
        /// place it there.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential_placement: Option<CredentialPlacement>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource: Option<String>,
        maximum_cache_seconds: u64,
        /// The lifetime assumed when the token response carries no
        /// `expires_in`. Absent, `expires_in` is required.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        assumed_lifetime_seconds: Option<u64>,
    },
}

impl HttpProviderAuthentication {
    /// The authentication kind, as written in configuration.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::None {} => "none",
            Self::Basic { .. } => "basic",
            Self::StaticAuthorization { .. } => "static-authorization",
            Self::StaticApiKey { .. } => "static-api-key",
            Self::StaticApiKeyQuery { .. } => "static-api-key-query",
            Self::Oauth2ClientCredentials { .. } => "oauth2-client-credentials",
        }
    }
}

impl fmt::Debug for HttpProviderAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProviderAuthentication")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// Where an OAuth client secret travels in the token request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialPlacement {
    BasicHeader,
    FormBody,
}

/// Why an HTTP provider cannot be activated. Each message names the field and
/// never a secret value or a secret reference's name.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HttpProviderError {
    #[error("{field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("{0}")]
    Secret(String),
    #[error("{script}: {reason}")]
    Script {
        script: &'static str,
        reason: &'static str,
    },
}

pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> HttpProviderError {
    HttpProviderError::Invalid {
        field,
        reason: reason.into(),
    }
}

/// Why `onUncertain: retry` is refused for a sender profile.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error(
    "onUncertain: retry needs a provider that declares idempotentSubmit: true, or acceptDuplicates: true on the profile"
)]
pub struct UncertainRetryRefused;

/// The startup check behind `onUncertain: retry`: retrying a send that may
/// already have reached the provider is safe only when the provider
/// deduplicates on the key the request carries, or when the operator has
/// accepted duplicates for the profile.
///
/// # Errors
///
/// [`UncertainRetryRefused`] when neither holds.
pub const fn check_uncertain_retry(
    capabilities: &HttpProviderCapabilities,
    accept_duplicates: bool,
) -> Result<(), UncertainRetryRefused> {
    if capabilities.idempotent_submit || accept_duplicates {
        Ok(())
    } else {
        Err(UncertainRetryRefused)
    }
}

impl HttpProviderPackage {
    /// Check the package half on its own.
    ///
    /// # Errors
    ///
    /// [`HttpProviderError::Invalid`] naming the first member that fails.
    pub fn validate(&self) -> Result<(), HttpProviderError> {
        check_script_path("prepareScript", &self.prepare_script)?;
        if let Some(path) = &self.interpret_script {
            check_script_path("interpretScript", path)?;
        }
        if let Some(path) = &self.receipt_script {
            check_script_path("receiptScript", path)?;
        }
        check_header_names("request.headers", &self.request.headers, |name| {
            is_script_writable_request_header_name(name) && name != "content-type"
        })?;
        check_header_names("responseHeaders", &self.response_headers, |_| true)?;
        let capabilities = &self.capabilities;
        if !(1..=MAXIMUM_CONCURRENCY_LIMIT).contains(&capabilities.concurrency_limit) {
            return Err(invalid(
                "capabilities.concurrencyLimit",
                format!("must be 1 to {MAXIMUM_CONCURRENCY_LIMIT}"),
            ));
        }
        if capabilities
            .rate_per_second
            .is_some_and(|rate| !(1..=MAXIMUM_RATE_PER_SECOND).contains(&rate))
        {
            return Err(invalid(
                "capabilities.ratePerSecond",
                format!("must be 1 to {MAXIMUM_RATE_PER_SECOND}"),
            ));
        }
        match (capabilities.receipts, self.receipt_script.is_some()) {
            (ReceiptCapability::Callback, false) => Err(invalid(
                "receiptScript",
                "is required when capabilities.receipts is callback",
            )),
            (ReceiptCapability::None | ReceiptCapability::Reconcile, true) => Err(invalid(
                "receiptScript",
                "is allowed only when capabilities.receipts is callback",
            )),
            _ => Ok(()),
        }
    }
}

fn check_script_path(field: &'static str, path: &str) -> Result<(), HttpProviderError> {
    let valid = !path.is_empty()
        && path.len() <= MAXIMUM_SCRIPT_PATH_BYTES
        && path.ends_with(".rhai")
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        });
    if valid {
        Ok(())
    } else {
        Err(invalid(
            field,
            "must be a relative package path of lowercase segments ending in .rhai",
        ))
    }
}

fn check_header_names(
    field: &'static str,
    names: &[String],
    allowed: impl Fn(&str) -> bool,
) -> Result<(), HttpProviderError> {
    if names.len() > MAXIMUM_SCRIPT_HEADERS {
        return Err(invalid(
            field,
            format!("may name at most {MAXIMUM_SCRIPT_HEADERS} headers"),
        ));
    }
    for (index, name) in names.iter().enumerate() {
        if !valid_header_name(name) || name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(invalid(field, "every name must be a lowercase header name"));
        }
        if !allowed(name) {
            return Err(invalid(
                field,
                format!("`{name}` is set by the runtime and cannot be named"),
            ));
        }
        if names[..index].contains(name) {
            return Err(invalid(field, format!("`{name}` is named twice")));
        }
    }
    Ok(())
}

/// The connection an activated provider sends through, checked.
pub(crate) struct CheckedConnection {
    pub origin: String,
    pub base_path: String,
    pub development: bool,
    pub allowed_private_cidrs: Vec<IpNet>,
    pub timeout: Duration,
    pub maximum_response_bytes: usize,
}

/// A resolved credential, ready to be placed by Rust.
pub(crate) enum ResolvedAuthentication {
    None,
    /// The base64 `user:password` payload.
    Basic(Zeroizing<Vec<u8>>),
    Bearer(Zeroizing<Vec<u8>>),
    ApiKeyHeader {
        name: String,
        value: Zeroizing<Vec<u8>>,
    },
    ApiKeyQuery {
        name: String,
        value: Zeroizing<Vec<u8>>,
    },
    OAuth2(ResolvedOAuth2),
}

pub(crate) struct ResolvedOAuth2 {
    pub origin: String,
    pub path: String,
    pub development: bool,
    pub form_body: Zeroizing<Vec<u8>>,
    pub maximum_cache_seconds: u32,
    pub assumed_lifetime_seconds: Option<u32>,
}

impl HttpProviderSettings {
    pub(crate) fn check_connection(
        &self,
        package: &HttpProviderPackage,
        trust_bundle_pem: Option<&[u8]>,
    ) -> Result<CheckedConnection, HttpProviderError> {
        let (origin, base_path, development) = split_base_url("baseUrl", &self.base_url, true)?;
        match (&self.tls_trust_profile, trust_bundle_pem) {
            (Some(name), Some(_)) if !name.is_empty() && !development => {}
            (None, None) => {}
            (Some(_), _) if development => {
                return Err(invalid(
                    "tlsTrustProfile",
                    "applies only to an https baseUrl",
                ))
            }
            _ => {
                return Err(invalid(
                    "tlsTrustProfile",
                    "names a trust bundle exactly when one is supplied for it",
                ))
            }
        }
        let maximum_timeout =
            u64::try_from(MAX_DESTINATION_OPERATION_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
        if !(1..=maximum_timeout).contains(&self.timeout_milliseconds) {
            return Err(invalid(
                "timeoutMilliseconds",
                format!("must be 1 to {maximum_timeout}"),
            ));
        }
        if !(1..=MAXIMUM_RESPONSE_BYTES).contains(&self.maximum_response_bytes) {
            return Err(invalid(
                "maximumResponseBytes",
                format!("must be 1 to {MAXIMUM_RESPONSE_BYTES}"),
            ));
        }
        if self.concurrency_limit == 0
            || self.concurrency_limit > package.capabilities.concurrency_limit
        {
            return Err(invalid(
                "concurrencyLimit",
                "must be 1 to the package's capabilities.concurrencyLimit",
            ));
        }
        if self.allowed_private_cidrs.len() > MAX_DESTINATION_PRIVATE_CIDRS {
            return Err(invalid(
                "allowedPrivateCidrs",
                format!("may list at most {MAX_DESTINATION_PRIVATE_CIDRS} networks"),
            ));
        }
        if development && !self.allowed_private_cidrs.is_empty() {
            return Err(invalid(
                "allowedPrivateCidrs",
                "applies only to an https baseUrl",
            ));
        }
        let allowed_private_cidrs = self
            .allowed_private_cidrs
            .iter()
            .map(|raw| {
                raw.parse::<IpNet>()
                    .map_err(|_| invalid("allowedPrivateCidrs", "every entry must be a CIDR"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        match (
            package.request.method,
            self.acknowledge_query_string_content,
        ) {
            (HttpSendMethod::Get, false) => {
                return Err(invalid(
                    "acknowledgeQueryStringContent",
                    "must be true for a provider that sends with get",
                ))
            }
            (HttpSendMethod::Post, true) => {
                return Err(invalid(
                    "acknowledgeQueryStringContent",
                    "applies only to a provider that sends with get",
                ))
            }
            _ => {}
        }
        match (
            package.capabilities.receipts,
            self.callback_verifier.as_ref(),
        ) {
            (ReceiptCapability::Callback, None) => {
                return Err(invalid(
                    "callbackVerifier",
                    "is required when the package declares receipts: callback",
                ))
            }
            (ReceiptCapability::None | ReceiptCapability::Reconcile, Some(_)) => {
                return Err(invalid(
                    "callbackVerifier",
                    "is allowed only when the package declares receipts: callback",
                ))
            }
            (_, Some(verifier)) => {
                verifier
                    .validate()
                    .map_err(|error| invalid("callbackVerifier", error.to_string()))?;
                let (field, reference) = match verifier {
                    CallbackVerifierConfig::HmacSha1UrlForm { secret_ref, .. }
                    | CallbackVerifierConfig::HmacSha256Body { secret_ref, .. } => {
                        ("callbackVerifier.secretRef", secret_ref)
                    }
                    CallbackVerifierConfig::PathToken { token_ref } => {
                        ("callbackVerifier.tokenRef", token_ref)
                    }
                };
                SecretReference::parse(reference.as_str()).map_err(|error| {
                    HttpProviderError::Secret(describe_secret_failure(field, reference, &error))
                })?;
            }
            (_, None) => {}
        }
        Ok(CheckedConnection {
            origin,
            base_path,
            development,
            allowed_private_cidrs,
            timeout: Duration::from_millis(self.timeout_milliseconds),
            maximum_response_bytes: usize::try_from(self.maximum_response_bytes)
                .unwrap_or(usize::MAX),
        })
    }

    pub(crate) fn resolve_authentication(
        &self,
        package: &HttpProviderPackage,
        development: bool,
        secrets: &SecretResolver,
    ) -> Result<ResolvedAuthentication, HttpProviderError> {
        match &self.authentication {
            HttpProviderAuthentication::None {} => {
                if development {
                    Ok(ResolvedAuthentication::None)
                } else {
                    Err(invalid(
                        "authentication",
                        "kind none is allowed only for a loopback http baseUrl",
                    ))
                }
            }
            HttpProviderAuthentication::Basic {
                username_ref,
                password_ref,
            } => {
                let username = resolve(secrets, "authentication.usernameRef", username_ref)?;
                let password = resolve(secrets, "authentication.passwordRef", password_ref)?;
                if username.expose_secret().contains(&b':') {
                    return Err(invalid(
                        "authentication.usernameRef",
                        "the resolved username must not contain a colon",
                    ));
                }
                let mut joined =
                    Zeroizing::new(Vec::with_capacity(username.len() + 1 + password.len()));
                joined.extend_from_slice(username.expose_secret());
                joined.push(b':');
                joined.extend_from_slice(password.expose_secret());
                let encoded = encode_basic(&joined);
                if encoded.len() > MAXIMUM_CREDENTIAL_VALUE_BYTES * 2 {
                    return Err(invalid(
                        "authentication.passwordRef",
                        "the encoded username and password must be at most 8192 bytes",
                    ));
                }
                Ok(ResolvedAuthentication::Basic(encoded))
            }
            HttpProviderAuthentication::StaticAuthorization { token_ref, scheme } => {
                if scheme
                    .as_deref()
                    .is_some_and(|scheme| !scheme.eq_ignore_ascii_case("bearer"))
                {
                    return Err(invalid(
                        "authentication.scheme",
                        "only Bearer is presented today",
                    ));
                }
                Ok(ResolvedAuthentication::Bearer(resolve_bounded(
                    secrets,
                    "authentication.tokenRef",
                    token_ref,
                )?))
            }
            HttpProviderAuthentication::StaticApiKey {
                header_name,
                value_ref,
            } => {
                let name = header_name.to_ascii_lowercase();
                if !valid_header_name(&name)
                    || !is_script_writable_request_header_name(&name)
                    || name == "content-type"
                {
                    return Err(invalid(
                        "authentication.headerName",
                        "must be a header name the runtime does not own",
                    ));
                }
                if package.request.headers.contains(&name) {
                    return Err(invalid(
                        "authentication.headerName",
                        "must not also be a script-writable request header",
                    ));
                }
                Ok(ResolvedAuthentication::ApiKeyHeader {
                    name,
                    value: resolve_bounded(secrets, "authentication.valueRef", value_ref)?,
                })
            }
            HttpProviderAuthentication::StaticApiKeyQuery {
                parameter_name,
                value_ref,
            } => {
                if parameter_name.is_empty()
                    || parameter_name.len() > 64
                    || !parameter_name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                    })
                {
                    return Err(invalid(
                        "authentication.parameterName",
                        "must be 1 to 64 ASCII letters, digits, `_`, `-`, or `.`",
                    ));
                }
                Ok(ResolvedAuthentication::ApiKeyQuery {
                    name: parameter_name.clone(),
                    value: resolve_bounded(secrets, "authentication.valueRef", value_ref)?,
                })
            }
            HttpProviderAuthentication::Oauth2ClientCredentials {
                token_endpoint,
                client_id_ref,
                client_secret_ref,
                credential_placement,
                scope,
                audience,
                resource,
                maximum_cache_seconds,
                assumed_lifetime_seconds,
            } => {
                if matches!(credential_placement, Some(CredentialPlacement::BasicHeader)) {
                    return Err(invalid(
                        "authentication.credentialPlacement",
                        "basic-header is not supported; the client secret travels in the form body",
                    ));
                }
                let (origin, path, token_development) =
                    split_base_url("authentication.tokenEndpoint", token_endpoint, false)?;
                if token_development != development {
                    return Err(invalid(
                        "authentication.tokenEndpoint",
                        "must use the same scheme as baseUrl",
                    ));
                }
                let cache_range = MINIMUM_TOKEN_CACHE_SECONDS..=MAXIMUM_TOKEN_CACHE_SECONDS;
                if !cache_range.contains(maximum_cache_seconds) {
                    return Err(invalid(
                        "authentication.maximumCacheSeconds",
                        format!(
                            "must be {MINIMUM_TOKEN_CACHE_SECONDS} to {MAXIMUM_TOKEN_CACHE_SECONDS}"
                        ),
                    ));
                }
                if assumed_lifetime_seconds.is_some_and(|value| !cache_range.contains(&value)) {
                    return Err(invalid(
                        "authentication.assumedLifetimeSeconds",
                        format!(
                            "must be {MINIMUM_TOKEN_CACHE_SECONDS} to {MAXIMUM_TOKEN_CACHE_SECONDS}"
                        ),
                    ));
                }
                for (field, value) in [
                    ("authentication.scope", scope),
                    ("authentication.audience", audience),
                    ("authentication.resource", resource),
                ] {
                    if value
                        .as_deref()
                        .is_some_and(|value| value.is_empty() || value.len() > 1_024)
                    {
                        return Err(invalid(field, "must be 1 to 1024 bytes when present"));
                    }
                }
                let client_id = resolve(secrets, "authentication.clientIdRef", client_id_ref)?;
                let client_secret =
                    resolve(secrets, "authentication.clientSecretRef", client_secret_ref)?;
                let form_body = token_form_body(
                    client_id.expose_secret(),
                    client_secret.expose_secret(),
                    [
                        ("scope", scope.as_deref()),
                        ("audience", audience.as_deref()),
                        ("resource", resource.as_deref()),
                    ],
                )
                .map_err(|()| {
                    invalid(
                        "authentication.clientIdRef",
                        "the resolved client credentials must be UTF-8",
                    )
                })?;
                Ok(ResolvedAuthentication::OAuth2(ResolvedOAuth2 {
                    origin,
                    path,
                    development: token_development,
                    form_body,
                    maximum_cache_seconds: u32::try_from(*maximum_cache_seconds)
                        .unwrap_or(u32::MAX),
                    assumed_lifetime_seconds: assumed_lifetime_seconds
                        .map(|value| u32::try_from(value).unwrap_or(u32::MAX)),
                }))
            }
        }
    }
}

/// Split a configured URL into the origin a destination policy freezes and
/// its path. A base URL's path must end in `/`, so a relative script target
/// joins it without ambiguity; a token endpoint's path is used as written.
fn split_base_url(
    field: &'static str,
    configured: &str,
    base: bool,
) -> Result<(String, String, bool), HttpProviderError> {
    let parsed = Url::parse(configured).map_err(|_| invalid(field, "must be an absolute URL"))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid(
            field,
            "must not carry credentials, a query, or a fragment",
        ));
    }
    let development = match parsed.scheme() {
        "https" => false,
        "http" => {
            let loopback = match parsed.host() {
                Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
                Some(url::Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
                Some(url::Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
                None => false,
            };
            if !loopback {
                return Err(invalid(
                    field,
                    "http is allowed only to a loopback host; use https",
                ));
            }
            true
        }
        _ => return Err(invalid(field, "must use https, or http to a loopback host")),
    };
    // The URL parser resolves dot segments and their escapes, so the
    // configured text is checked too: the path sent is the path written.
    let path = parsed.path().to_owned();
    if !path.is_ascii()
        || path.contains(['%', '\\', '*'])
        || path.contains("//")
        || configured.contains(['%', '\\'])
        || configured
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(invalid(
            field,
            "the path must be plain ASCII segments without escapes or wildcards",
        ));
    }
    if base && !path.ends_with('/') {
        return Err(invalid(field, "the path must end in /"));
    }
    let mut origin = parsed;
    origin.set_path("");
    Ok((origin.to_string(), path, development))
}

fn resolve(
    secrets: &SecretResolver,
    field: &'static str,
    reference: &str,
) -> Result<ProtectedSecret, HttpProviderError> {
    SecretReference::parse(reference).map_err(|error| {
        HttpProviderError::Secret(describe_secret_failure(field, reference, &error))
    })?;
    secrets.resolve(reference).map_err(|error| {
        HttpProviderError::Secret(describe_secret_failure(field, reference, &error))
    })
}

fn resolve_bounded(
    secrets: &SecretResolver,
    field: &'static str,
    reference: &str,
) -> Result<Zeroizing<Vec<u8>>, HttpProviderError> {
    let value = resolve(secrets, field, reference)?;
    if value.len() > MAXIMUM_CREDENTIAL_VALUE_BYTES {
        return Err(invalid(
            field,
            format!("the resolved value must be at most {MAXIMUM_CREDENTIAL_VALUE_BYTES} bytes"),
        ));
    }
    Ok(Zeroizing::new(value.expose_secret().to_vec()))
}

fn encode_basic(joined: &[u8]) -> Zeroizing<Vec<u8>> {
    use base64::Engine as _;
    Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .encode(joined)
            .into_bytes(),
    )
}

fn token_form_body(
    client_id: &[u8],
    client_secret: &[u8],
    extra: [(&'static str, Option<&str>); 3],
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let client_id = std::str::from_utf8(client_id).map_err(|_| ())?;
    let client_secret = std::str::from_utf8(client_secret).map_err(|_| ())?;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("grant_type", "client_credentials")
        .append_pair("client_id", client_id)
        .append_pair("client_secret", client_secret);
    for (name, value) in extra {
        if let Some(value) = value {
            serializer.append_pair(name, value);
        }
    }
    Ok(Zeroizing::new(serializer.finish().into_bytes()))
}
