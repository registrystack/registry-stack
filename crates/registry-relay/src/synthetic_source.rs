// SPDX-License-Identifier: Apache-2.0
//! Fixed-purpose synthetic source for the disposable development runtime.
//!
//! This is deliberately not a mock-server API. A compiler-owned plan selects
//! one closed source scenario and, optionally, one exact OAuth response
//! profile. Methods, routes, response headers, listener, TLS, secret root,
//! request limits, timeouts, and counters remain owned by this module.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fs::{self, File};
use std::future::Future;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::State;
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use registry_platform_crypto::parse_json_strict;
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use zeroize::Zeroizing;

/// Internal container listener. The development renderer must not publish it.
pub const SYNTHETIC_SOURCE_BIND: &str = "0.0.0.0:8099";

/// Fixed source origin used by the compiler-owned development projection.
pub const SYNTHETIC_SOURCE_ORIGIN: &str = "https://registry-synthetic-source:8099";
const COUNTERS_URL: &str = "https://registry-synthetic-source:8099/__registry/counters";

/// Fixed directory mounted by the development renderer for source-only
/// credentials and TLS material.
pub const SYNTHETIC_SOURCE_SECRET_ROOT: &str = "/run/registry/synthetic-source-secrets";

pub const SYNTHETIC_SOURCE_PLAN_VERSION: &str = "registry.relay.synthetic-source-plan.v1";
pub const TOKEN_ROUTE: &str = "/oauth/token";
pub const COUNTERS_ROUTE: &str = "/__registry/counters";
pub const HEALTH_ROUTE: &str = "/healthz";

const MAX_PLAN_BYTES: usize = 1024 * 1024;
const MAX_AUTHORED_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
const MAX_EXPECTED_OAUTH_FIELDS_BYTES: usize = 8 * 1024;
const MAX_SOURCE_PATH_BYTES: usize = 2 * 1024;
const MAX_SOURCE_QUERY_FIELDS: usize = 16;
const MAX_SOURCE_HEADERS: usize = 16;
const MAX_SOURCE_FIELD_NAME_BYTES: usize = 96;
const MAX_SOURCE_FIELD_VALUE_BYTES: usize = 2 * 1024;
const MAX_SOURCE_EXPECTATION_BYTES: usize = 16 * 1024;
const MAX_SECRET_BYTES: usize = 4 * 1024;
const MAX_TLS_FILE_BYTES: usize = 256 * 1024;
const MAX_CONNECTIONS: usize = 8;
const CONNECTION_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_COUNTER_RESPONSE_BYTES: u64 = 128;
const AUTHORED_DEVELOPMENT_SOURCE_DEADLINE_SECONDS: u64 = 10;
const SOURCE_TIMEOUT: Duration = Duration::from_secs(15);
const _: () = assert!(SOURCE_TIMEOUT.as_secs() > AUTHORED_DEVELOPMENT_SOURCE_DEADLINE_SECONDS);
const GLOBAL_SOURCE_RESPONSE_CEILING: usize = 8 * 1024 * 1024;
const OVERSIZE_RESPONSE_BYTES: usize = GLOBAL_SOURCE_RESPONSE_CEILING + 1;
const TOKEN_EXPIRES_IN_SECONDS: u64 = 60;
const REDIRECT_LOCATION: &str = "https://synthetic-redirect.invalid/oauth/token";

/// A value-free failure at the synthetic-source startup boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SyntheticSourceError {
    #[error("synthetic-source plan could not be loaded")]
    PlanLoadFailed,
    #[error("synthetic-source plan is invalid")]
    InvalidPlan,
    #[error("synthetic-source secret material could not be loaded securely")]
    SecretLoadFailed,
    #[error("synthetic-source TLS material is invalid")]
    InvalidTlsMaterial,
    #[error("synthetic-source listener could not bind")]
    BindFailed,
    #[error("synthetic-source serving failed")]
    ServeFailed,
    #[error("synthetic-source randomness is unavailable")]
    RandomUnavailable,
    #[error("synthetic-source counter probe failed")]
    ProbeFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum PlanVersion {
    #[serde(rename = "registry.relay.synthetic-source-plan.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceScenario {
    AuthoredResponse,
    NoMatch,
    Ambiguity,
    SubjectMismatch,
    SourceRejected,
    SourceMalformed,
    SourceTimeout,
    SourceOversize,
}

impl SourceScenario {
    const fn needs_authored_response(self) -> bool {
        matches!(
            self,
            Self::AuthoredResponse | Self::NoMatch | Self::Ambiguity | Self::SubjectMismatch
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceRequestMethod {
    Get,
    Post,
}

impl SourceRequestMethod {
    const fn as_http(self) -> Method {
        match self {
            Self::Get => Method::GET,
            Self::Post => Method::POST,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRequestExpectation {
    method: SourceRequestMethod,
    path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<Value>,
}

impl std::fmt::Debug for SourceRequestExpectation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceRequestExpectation")
            .field("method", &self.method)
            .field("path", &"<redacted>")
            .field("query_field_count", &self.query.len())
            .field("header_count", &self.headers.len())
            .field("body", &self.body.as_ref().map(|_| "<configured>"))
            .finish()
    }
}

impl SourceRequestExpectation {
    fn validate(&self) -> Result<(), SyntheticSourceError> {
        if self.path.is_empty()
            || self.path.len() > MAX_SOURCE_PATH_BYTES
            || !self.path.starts_with('/')
            || self
                .path
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'?' | b'#' | b'\\'))
            || self
                .path
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
            || matches!(
                self.path.as_str(),
                HEALTH_ROUTE | TOKEN_ROUTE | COUNTERS_ROUTE
            )
            || self.query.len() > MAX_SOURCE_QUERY_FIELDS
            || self.headers.len() > MAX_SOURCE_HEADERS
        {
            return Err(SyntheticSourceError::InvalidPlan);
        }
        let mut total = self.path.len();
        for (name, value) in &self.query {
            validate_expected_field(name, value)?;
            total = total
                .checked_add(name.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or(SyntheticSourceError::InvalidPlan)?;
        }
        for (name, value) in &self.headers {
            validate_expected_field(name, value)?;
            if name.bytes().any(|byte| byte.is_ascii_uppercase())
                || HeaderName::from_bytes(name.as_bytes()).is_err()
                || HeaderValue::from_str(value).is_err()
                || is_reserved_source_header(name)
            {
                return Err(SyntheticSourceError::InvalidPlan);
            }
            total = total
                .checked_add(name.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or(SyntheticSourceError::InvalidPlan)?;
        }
        if let Some(body) = &self.body {
            total = total
                .checked_add(
                    serde_json::to_vec(body)
                        .map_err(|_| SyntheticSourceError::InvalidPlan)?
                        .len(),
                )
                .ok_or(SyntheticSourceError::InvalidPlan)?;
        }
        if total > MAX_SOURCE_EXPECTATION_BYTES {
            return Err(SyntheticSourceError::InvalidPlan);
        }
        Ok(())
    }
}

fn validate_expected_field(name: &str, value: &str) -> Result<(), SyntheticSourceError> {
    if name.is_empty()
        || name.len() > MAX_SOURCE_FIELD_NAME_BYTES
        || value.len() > MAX_SOURCE_FIELD_VALUE_BYTES
        || name
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'&' | b'=' | b'%' | b'+'))
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(SyntheticSourceError::InvalidPlan);
    }
    Ok(())
}

fn is_reserved_source_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "host"
            | "connection"
            | "content-length"
            | "transfer-encoding"
            | "accept-encoding"
            | "content-type"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-real-ip"
            | "x-api-key"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StaticBearerSourceAuthType {
    StaticBearer,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticBearerSourceAuthPlan {
    #[serde(rename = "type")]
    auth_type: StaticBearerSourceAuthType,
    secret: SecretFileReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OAuthRequestEncoding {
    Json,
    Form,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OAuthResponseProfile {
    Oauth2Bearer,
    Oauth2BearerNoExpiry,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OAuthResponseCase {
    #[default]
    Valid,
    MissingAccessToken,
    WrongTokenType,
    MissingExpiresIn,
    UnexpectedExpiresIn,
    DuplicateAccessToken,
    UnknownField,
    RefreshToken,
    IdToken,
    Redirect,
    Rejected,
    UnexpectedContentType,
    Oversize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretFileReference {
    file: String,
    generation: u64,
}

impl SecretFileReference {
    fn validate(&self) -> Result<(), SyntheticSourceError> {
        if self.generation == 0
            || self.file.is_empty()
            || self.file.len() > 64
            || !self
                .file
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || self.file == "."
            || self.file == ".."
        {
            return Err(SyntheticSourceError::InvalidPlan);
        }
        Ok(())
    }

    fn resolve(&self, root: &Path) -> PathBuf {
        root.join(&self.file)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthSecretReferences {
    client_id: SecretFileReference,
    client_secret: SecretFileReference,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthPlan {
    response_profile: OAuthResponseProfile,
    #[serde(default)]
    response_case: OAuthResponseCase,
    request: OAuthRequestExpectation,
    secrets: OAuthSecretReferences,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthRequestExpectation {
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    resource: Option<String>,
}

impl OAuthRequestExpectation {
    fn validate(&self) -> Result<(), SyntheticSourceError> {
        let fields = [
            self.audience.as_deref(),
            self.scope.as_deref(),
            self.resource.as_deref(),
        ];
        if fields
            .iter()
            .flatten()
            .any(|value| value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()))
            || fields
                .iter()
                .flatten()
                .try_fold(0_usize, |total, value| total.checked_add(value.len()))
                .is_none_or(|total| total > MAX_EXPECTED_OAUTH_FIELDS_BYTES)
        {
            return Err(SyntheticSourceError::InvalidPlan);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeSecretReferences {
    control_token: SecretFileReference,
    tls_certificate: SecretFileReference,
    tls_private_key: SecretFileReference,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticSourcePlan {
    version: PlanVersion,
    scenario: SourceScenario,
    source_request: SourceRequestExpectation,
    #[serde(default)]
    source_auth: Option<StaticBearerSourceAuthPlan>,
    request_encoding: OAuthRequestEncoding,
    #[serde(default)]
    oauth: Option<OAuthPlan>,
    #[serde(default)]
    response_body: Option<Value>,
    secrets: RuntimeSecretReferences,
}

impl std::fmt::Debug for SyntheticSourcePlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyntheticSourcePlan")
            .field("version", &self.version)
            .field("scenario", &self.scenario)
            .field("source_request", &self.source_request)
            .field(
                "source_auth",
                &self.source_auth.as_ref().map(|_| "static_bearer"),
            )
            .field("request_encoding", &self.request_encoding)
            .field(
                "oauth_profile",
                &self.oauth.as_ref().map(|oauth| oauth.response_profile),
            )
            .field(
                "oauth_response_case",
                &self.oauth.as_ref().map(|oauth| oauth.response_case),
            )
            .field(
                "response_body",
                &self.response_body.as_ref().map(|_| "<redacted>"),
            )
            .field("secret_references", &"<configured>")
            .finish()
    }
}

impl SyntheticSourcePlan {
    fn validate(&self) -> Result<(), SyntheticSourceError> {
        let _ = self.version;
        self.source_request.validate()?;
        if self.source_auth.is_some() && self.oauth.is_some() {
            return Err(SyntheticSourceError::InvalidPlan);
        }
        let mut secret_files = BTreeSet::new();
        validate_distinct_secret_reference(&self.secrets.control_token, &mut secret_files)?;
        validate_distinct_secret_reference(&self.secrets.tls_certificate, &mut secret_files)?;
        validate_distinct_secret_reference(&self.secrets.tls_private_key, &mut secret_files)?;
        self.secrets.control_token.validate()?;
        self.secrets.tls_certificate.validate()?;
        self.secrets.tls_private_key.validate()?;
        if let Some(source_auth) = &self.source_auth {
            let _ = source_auth.auth_type;
            validate_distinct_secret_reference(&source_auth.secret, &mut secret_files)?;
        }
        if let Some(oauth) = &self.oauth {
            validate_distinct_secret_reference(&oauth.secrets.client_id, &mut secret_files)?;
            validate_distinct_secret_reference(&oauth.secrets.client_secret, &mut secret_files)?;
            oauth.secrets.client_id.validate()?;
            oauth.secrets.client_secret.validate()?;
            oauth.request.validate()?;
            match (oauth.response_profile, oauth.response_case) {
                (OAuthResponseProfile::Oauth2Bearer, OAuthResponseCase::UnexpectedExpiresIn)
                | (
                    OAuthResponseProfile::Oauth2BearerNoExpiry,
                    OAuthResponseCase::MissingExpiresIn,
                ) => return Err(SyntheticSourceError::InvalidPlan),
                _ => {}
            }
        }
        if self.scenario.needs_authored_response() != self.response_body.is_some() {
            return Err(SyntheticSourceError::InvalidPlan);
        }
        if self.response_body.as_ref().is_some_and(|body| {
            serde_json::to_vec(body)
                .map(|bytes| bytes.len() > MAX_AUTHORED_RESPONSE_BYTES)
                .unwrap_or(true)
        }) {
            return Err(SyntheticSourceError::InvalidPlan);
        }
        Ok(())
    }
}

fn validate_distinct_secret_reference<'a>(
    reference: &'a SecretFileReference,
    files: &mut BTreeSet<&'a str>,
) -> Result<(), SyntheticSourceError> {
    reference.validate()?;
    if !files.insert(&reference.file) {
        return Err(SyntheticSourceError::InvalidPlan);
    }
    Ok(())
}

struct OAuthRuntime {
    request_encoding: OAuthRequestEncoding,
    expected_request: OAuthRequestExpectationRuntime,
    response_profile: OAuthResponseProfile,
    response_case: OAuthResponseCase,
    client_id: Zeroizing<Vec<u8>>,
    client_secret: Zeroizing<Vec<u8>>,
    access_token: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for OAuthRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthRuntime")
            .field("request_encoding", &self.request_encoding)
            .field("expected_request", &self.expected_request)
            .field("response_profile", &self.response_profile)
            .field("response_case", &self.response_case)
            .field("credential_material", &"<redacted>")
            .finish()
    }
}

struct OAuthRequestExpectationRuntime {
    audience: Option<Zeroizing<Vec<u8>>>,
    scope: Option<Zeroizing<Vec<u8>>>,
    resource: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for OAuthRequestExpectationRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthRequestExpectation")
            .field("audience", &self.audience.as_ref().map(|_| "<configured>"))
            .field("scope", &self.scope.as_ref().map(|_| "<configured>"))
            .field("resource", &self.resource.as_ref().map(|_| "<configured>"))
            .finish()
    }
}

#[derive(Debug, Default)]
struct Counters {
    token_requests: AtomicU64,
    source_requests: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CounterSnapshot {
    token_requests: u64,
    source_requests: u64,
}

struct SyntheticSourceState {
    scenario: SourceScenario,
    source_request: SourceRequestExpectation,
    response_body: Option<Bytes>,
    static_bearer: Option<Zeroizing<Vec<u8>>>,
    oauth: Option<OAuthRuntime>,
    control_token: Zeroizing<Vec<u8>>,
    counters: Counters,
    oversize_body: Bytes,
}

impl std::fmt::Debug for SyntheticSourceState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyntheticSourceState")
            .field("scenario", &self.scenario)
            .field("source_request", &self.source_request)
            .field(
                "static_bearer",
                &self.static_bearer.as_ref().map(|_| "<configured>"),
            )
            .field("oauth", &self.oauth)
            .field(
                "response_body",
                &self.response_body.as_ref().map(Bytes::len),
            )
            .field("control_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Run the fixed TLS source until SIGINT or SIGTERM.
pub async fn run(plan_path: &Path) -> Result<(), SyntheticSourceError> {
    let secret_root = Path::new(SYNTHETIC_SOURCE_SECRET_ROOT);
    let (state, tls) = load_runtime(plan_path, secret_root)?;
    let listener = TcpListener::bind(SYNTHETIC_SOURCE_BIND)
        .await
        .map_err(|_| SyntheticSourceError::BindFailed)?;
    serve_tls(listener, router(state), tls, shutdown_signal()).await
}

/// Read the private synthetic-source effect counters through the fixed,
/// certificate-pinned development endpoint.
pub async fn probe(plan_path: &Path) -> Result<String, SyntheticSourceError> {
    probe_with_options(
        plan_path,
        Path::new(SYNTHETIC_SOURCE_SECRET_ROOT),
        ProbeTarget::Fixed,
    )
    .await
}

enum ProbeTarget {
    Fixed,
    #[cfg(test)]
    Test {
        url: String,
        resolved_address: std::net::SocketAddr,
    },
}

async fn probe_with_options(
    plan_path: &Path,
    secret_root: &Path,
    target: ProbeTarget,
) -> Result<String, SyntheticSourceError> {
    let plan = load_plan(plan_path)?;
    let control_token =
        read_secret_reference(&plan.secrets.control_token, secret_root, MAX_SECRET_BYTES)?;
    let certificate_pem = Zeroizing::new(read_bounded_file(
        &plan.secrets.tls_certificate.resolve(secret_root),
        MAX_TLS_FILE_BYTES,
        true,
    )?);
    let roots = reqwest::Certificate::from_pem_bundle(&certificate_pem)
        .map_err(|_| SyntheticSourceError::InvalidTlsMaterial)?;
    if roots.is_empty() || roots.len() > 8 {
        return Err(SyntheticSourceError::InvalidTlsMaterial);
    }

    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .https_only(true)
        .timeout(PROBE_TIMEOUT)
        .connect_timeout(PROBE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .retry(reqwest::retry::never())
        .pool_max_idle_per_host(0)
        .http1_only()
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate();
    for root in roots {
        builder = builder.add_root_certificate(root);
    }
    #[cfg(test)]
    if let ProbeTarget::Test {
        resolved_address, ..
    } = &target
    {
        builder = builder.resolve("registry-synthetic-source", *resolved_address);
    }
    let client = builder
        .build()
        .map_err(|_| SyntheticSourceError::ProbeFailed)?;

    let mut authorization_bytes = Zeroizing::new(Vec::with_capacity(
        b"Bearer ".len().saturating_add(control_token.len()),
    ));
    authorization_bytes.extend_from_slice(b"Bearer ");
    authorization_bytes.extend_from_slice(control_token.as_slice());
    let mut authorization = HeaderValue::from_bytes(&authorization_bytes)
        .map_err(|_| SyntheticSourceError::SecretLoadFailed)?;
    authorization.set_sensitive(true);
    let url = match &target {
        ProbeTarget::Fixed => COUNTERS_URL,
        #[cfg(test)]
        ProbeTarget::Test { url, .. } => url,
    };
    let response = client
        .get(url)
        .header(AUTHORIZATION, authorization)
        .header(ACCEPT, HeaderValue::from_static("application/json"))
        .send()
        .await
        .map_err(|_| SyntheticSourceError::ProbeFailed)?;
    if response.status() != StatusCode::OK
        || response.headers().get(CONTENT_TYPE)
            != Some(&HeaderValue::from_static("application/json"))
    {
        return Err(SyntheticSourceError::ProbeFailed);
    }
    let body = registry_platform_httputil::read_bounded(response, MAX_COUNTER_RESPONSE_BYTES)
        .await
        .map_err(|_| SyntheticSourceError::ProbeFailed)?;
    let counters = parse_counter_snapshot(&body)?;
    serde_json::to_string(&counters).map_err(|_| SyntheticSourceError::ProbeFailed)
}

fn parse_counter_snapshot(body: &[u8]) -> Result<CounterSnapshot, SyntheticSourceError> {
    let value = parse_json_strict(body).map_err(|_| SyntheticSourceError::ProbeFailed)?;
    serde_json::from_value(value).map_err(|_| SyntheticSourceError::ProbeFailed)
}

fn load_runtime(
    plan_path: &Path,
    secret_root: &Path,
) -> Result<(Arc<SyntheticSourceState>, TlsAcceptor), SyntheticSourceError> {
    let plan = load_plan(plan_path)?;
    let control_token =
        read_secret_reference(&plan.secrets.control_token, secret_root, MAX_SECRET_BYTES)?;
    let static_bearer = plan
        .source_auth
        .as_ref()
        .map(|source_auth| {
            read_secret_reference(&source_auth.secret, secret_root, MAX_SECRET_BYTES)
        })
        .transpose()?;
    let oauth = plan
        .oauth
        .as_ref()
        .map(|oauth| {
            let client_id =
                read_secret_reference(&oauth.secrets.client_id, secret_root, MAX_SECRET_BYTES)?;
            let client_secret =
                read_secret_reference(&oauth.secrets.client_secret, secret_root, MAX_SECRET_BYTES)?;
            let mut random = [0_u8; 32];
            getrandom::fill(&mut random).map_err(|_| SyntheticSourceError::RandomUnavailable)?;
            let access_token = Zeroizing::new(URL_SAFE_NO_PAD.encode(random).into_bytes());
            Ok(OAuthRuntime {
                request_encoding: plan.request_encoding,
                expected_request: OAuthRequestExpectationRuntime {
                    audience: oauth
                        .request
                        .audience
                        .as_ref()
                        .map(|value| Zeroizing::new(value.as_bytes().to_vec())),
                    scope: oauth
                        .request
                        .scope
                        .as_ref()
                        .map(|value| Zeroizing::new(value.as_bytes().to_vec())),
                    resource: oauth
                        .request
                        .resource
                        .as_ref()
                        .map(|value| Zeroizing::new(value.as_bytes().to_vec())),
                },
                response_profile: oauth.response_profile,
                response_case: oauth.response_case,
                client_id,
                client_secret,
                access_token,
            })
        })
        .transpose()?;
    let response_body = plan
        .response_body
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| SyntheticSourceError::InvalidPlan)?
        .map(Bytes::from);
    let state = Arc::new(SyntheticSourceState {
        scenario: plan.scenario,
        source_request: plan.source_request,
        response_body,
        static_bearer,
        oauth,
        control_token,
        counters: Counters::default(),
        oversize_body: Bytes::from(vec![b' '; OVERSIZE_RESPONSE_BYTES]),
    });
    let tls = load_tls_acceptor(&plan.secrets, secret_root)?;
    Ok((state, tls))
}

fn load_plan(plan_path: &Path) -> Result<SyntheticSourcePlan, SyntheticSourceError> {
    let plan_bytes = read_bounded_file(plan_path, MAX_PLAN_BYTES, false)
        .map_err(|_| SyntheticSourceError::PlanLoadFailed)?;
    let plan_value =
        parse_json_strict(&plan_bytes).map_err(|_| SyntheticSourceError::InvalidPlan)?;
    let plan: SyntheticSourcePlan =
        serde_json::from_value(plan_value).map_err(|_| SyntheticSourceError::InvalidPlan)?;
    plan.validate()?;
    Ok(plan)
}

fn router(state: Arc<SyntheticSourceState>) -> Router {
    Router::new()
        .route(HEALTH_ROUTE, get(health))
        .route(COUNTERS_ROUTE, get(counters))
        .route(TOKEN_ROUTE, post(token))
        .fallback(source)
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn counters(
    State(state): State<Arc<SyntheticSourceState>>,
    headers: HeaderMap,
) -> Response<Body> {
    if !bearer_matches(&headers, state.control_token.as_slice()) {
        return static_json_response(
            StatusCode::UNAUTHORIZED,
            br#"{"error":"control_credential_required"}"#,
        );
    }
    let body = serde_json::to_vec(&json!({
        "token_requests": state.counters.token_requests.load(Ordering::SeqCst),
        "source_requests": state.counters.source_requests.load(Ordering::SeqCst),
    }))
    .expect("counter response is always serializable");
    json_response(StatusCode::OK, Bytes::from(body))
}

async fn token(
    State(state): State<Arc<SyntheticSourceState>>,
    request: Request<Body>,
) -> Response<Body> {
    token_with_timeout(state, request, REQUEST_BODY_TIMEOUT).await
}

async fn token_with_timeout(
    state: Arc<SyntheticSourceState>,
    request: Request<Body>,
    body_timeout: Duration,
) -> Response<Body> {
    increment_counter(&state.counters.token_requests);
    let (parts, body) = request.into_parts();
    let body = match read_request_body(body, body_timeout).await {
        Ok(body) => body,
        Err(RequestBodyFailure::TooLarge) => {
            return empty_response(StatusCode::PAYLOAD_TOO_LARGE);
        }
        Err(RequestBodyFailure::Timeout) => {
            return empty_response(StatusCode::REQUEST_TIMEOUT);
        }
    };
    let Some(oauth) = &state.oauth else {
        return static_json_response(StatusCode::NOT_FOUND, br#"{"error":"oauth_disabled"}"#);
    };
    if !valid_oauth_request(&parts.headers, &body, oauth) {
        return static_json_response(StatusCode::UNAUTHORIZED, br#"{"error":"invalid_client"}"#);
    }
    oauth_response(oauth, &state.oversize_body)
}

async fn source(
    State(state): State<Arc<SyntheticSourceState>>,
    request: Request<Body>,
) -> Response<Body> {
    source_with_timeout(state, request, REQUEST_BODY_TIMEOUT).await
}

async fn source_with_timeout(
    state: Arc<SyntheticSourceState>,
    request: Request<Body>,
    body_timeout: Duration,
) -> Response<Body> {
    increment_counter(&state.counters.source_requests);
    let (parts, body) = request.into_parts();
    if !source_authorization_matches(&state, &parts.headers) {
        return static_json_response(
            StatusCode::UNAUTHORIZED,
            br#"{"error":"source_credential_required"}"#,
        );
    }
    let body = match read_request_body(body, body_timeout).await {
        Ok(body) => body,
        Err(RequestBodyFailure::TooLarge) => {
            return empty_response(StatusCode::PAYLOAD_TOO_LARGE);
        }
        Err(RequestBodyFailure::Timeout) => {
            return empty_response(StatusCode::REQUEST_TIMEOUT);
        }
    };
    if !source_request_matches(&state.source_request, &parts, &body) {
        return static_json_response(
            StatusCode::BAD_REQUEST,
            br#"{"error":"source_request_mismatch"}"#,
        );
    }
    match state.scenario {
        SourceScenario::AuthoredResponse | SourceScenario::SubjectMismatch => json_response(
            StatusCode::OK,
            state
                .response_body
                .clone()
                .expect("validated authored response is installed"),
        ),
        SourceScenario::NoMatch => json_response(
            StatusCode::NOT_FOUND,
            state
                .response_body
                .clone()
                .expect("validated authored response is installed"),
        ),
        SourceScenario::Ambiguity => json_response(
            StatusCode::CONFLICT,
            state
                .response_body
                .clone()
                .expect("validated authored response is installed"),
        ),
        SourceScenario::SourceRejected => Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::empty())
            .expect("static response"),
        SourceScenario::SourceMalformed => {
            static_json_response(StatusCode::OK, br#"{"malformed":"#)
        }
        SourceScenario::SourceTimeout => {
            tokio::time::sleep(SOURCE_TIMEOUT).await;
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .expect("static response")
        }
        SourceScenario::SourceOversize => {
            json_response(StatusCode::OK, state.oversize_body.clone())
        }
    }
}

fn source_authorization_matches(state: &SyntheticSourceState, headers: &HeaderMap) -> bool {
    if let Some(oauth) = &state.oauth {
        exact_bearer_matches(headers, oauth.access_token.as_slice())
    } else if let Some(static_bearer) = &state.static_bearer {
        exact_bearer_matches(headers, static_bearer.as_slice())
    } else {
        headers.get_all(AUTHORIZATION).iter().next().is_none()
    }
}

fn source_request_matches(
    expected: &SourceRequestExpectation,
    parts: &axum::http::request::Parts,
    body: &[u8],
) -> bool {
    if parts.method != expected.method.as_http()
        || parts.uri.path() != expected.path
        || !source_query_matches(parts.uri.query(), &expected.query)
        || !source_headers_match(&parts.headers, &expected.headers)
    {
        return false;
    }
    match &expected.body {
        Some(expected_body) => {
            if parts.headers.get(CONTENT_TYPE)
                != Some(&HeaderValue::from_static("application/json"))
            {
                return false;
            }
            parse_json_strict(body)
                .map(|actual| actual == *expected_body)
                .unwrap_or(false)
        }
        None => body.is_empty() && !parts.headers.contains_key(CONTENT_TYPE),
    }
}

fn source_query_matches(query: Option<&str>, expected: &BTreeMap<String, String>) -> bool {
    let mut actual = BTreeMap::new();
    for pair in query
        .unwrap_or_default()
        .as_bytes()
        .split(|byte| *byte == b'&')
    {
        if pair.is_empty() {
            if query.is_some_and(|query| !query.is_empty()) {
                return false;
            }
            continue;
        }
        let Some(separator) = pair.iter().position(|byte| *byte == b'=') else {
            return false;
        };
        let (name, value) = pair.split_at(separator);
        let Some(name) = decode_form_component(name) else {
            return false;
        };
        let Some(value) = decode_form_component(&value[1..]) else {
            return false;
        };
        if actual.insert(name, value).is_some() {
            return false;
        }
    }
    actual.len() == expected.len()
        && expected.iter().all(|(name, value)| {
            actual
                .get(name.as_bytes())
                .is_some_and(|actual| constant_time_eq(actual, value.as_bytes()))
        })
}

fn source_headers_match(headers: &HeaderMap, expected: &BTreeMap<String, String>) -> bool {
    let mut seen = BTreeSet::new();
    for (name, value) in headers {
        if matches!(
            name.as_str(),
            "host"
                | "authorization"
                | "content-type"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "accept-encoding"
        ) {
            continue;
        }
        let Some(expected_value) = expected.get(name.as_str()) else {
            return false;
        };
        if !seen.insert(name.as_str())
            || !constant_time_eq(value.as_bytes(), expected_value.as_bytes())
        {
            return false;
        }
    }
    seen.len() == expected.len()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestBodyFailure {
    TooLarge,
    Timeout,
}

async fn read_request_body(body: Body, timeout: Duration) -> Result<Bytes, RequestBodyFailure> {
    match tokio::time::timeout(timeout, to_bytes(body, MAX_REQUEST_BODY_BYTES)).await {
        Ok(Ok(body)) => Ok(body),
        Ok(Err(_)) => Err(RequestBodyFailure::TooLarge),
        Err(_) => Err(RequestBodyFailure::Timeout),
    }
}

fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("static response")
}

fn valid_oauth_request(headers: &HeaderMap, body: &[u8], oauth: &OAuthRuntime) -> bool {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    match oauth.request_encoding {
        OAuthRequestEncoding::Json if content_type == Some("application/json") => {
            valid_oauth_json_request(body, oauth)
        }
        OAuthRequestEncoding::Form if content_type == Some("application/x-www-form-urlencoded") => {
            valid_oauth_form_request(body, oauth)
        }
        OAuthRequestEncoding::Json | OAuthRequestEncoding::Form => false,
    }
}

fn valid_oauth_json_request(body: &[u8], oauth: &OAuthRuntime) -> bool {
    let Ok(Value::Object(mut object)) = parse_json_strict(body) else {
        return false;
    };
    if !(3..=6).contains(&object.len())
        || object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "grant_type" | "client_id" | "client_secret" | "audience" | "scope" | "resource"
            )
        })
        || object
            .remove("grant_type")
            .and_then(|value| value.as_str().map(str::to_owned))
            .as_deref()
            != Some("client_credentials")
    {
        return false;
    }
    let Some(client_id) = object
        .remove("client_id")
        .and_then(|value| value.as_str().map(str::as_bytes).map(Vec::from))
    else {
        return false;
    };
    let Some(client_secret) = object
        .remove("client_secret")
        .and_then(|value| value.as_str().map(str::as_bytes).map(Vec::from))
    else {
        return false;
    };
    constant_time_eq(&client_id, oauth.client_id.as_slice())
        && constant_time_eq(&client_secret, oauth.client_secret.as_slice())
        && exact_json_optional_field(
            &mut object,
            "audience",
            oauth
                .expected_request
                .audience
                .as_ref()
                .map(|value| value.as_slice()),
        )
        && exact_json_optional_field(
            &mut object,
            "scope",
            oauth
                .expected_request
                .scope
                .as_ref()
                .map(|value| value.as_slice()),
        )
        && exact_json_optional_field(
            &mut object,
            "resource",
            oauth
                .expected_request
                .resource
                .as_ref()
                .map(|value| value.as_slice()),
        )
        && object.is_empty()
}

fn exact_json_optional_field(
    object: &mut serde_json::Map<String, Value>,
    name: &str,
    expected: Option<&[u8]>,
) -> bool {
    match (object.remove(name), expected) {
        (None, None) => true,
        (Some(Value::String(actual)), Some(expected)) => {
            constant_time_eq(actual.as_bytes(), expected)
        }
        _ => false,
    }
}

fn valid_oauth_form_request(body: &[u8], oauth: &OAuthRuntime) -> bool {
    let mut fields = std::collections::BTreeMap::new();
    for pair in body.split(|byte| *byte == b'&') {
        let Some(separator) = pair.iter().position(|byte| *byte == b'=') else {
            return false;
        };
        let (name, value) = pair.split_at(separator);
        let value = &value[1..];
        let Some(name) = decode_form_component(name) else {
            return false;
        };
        let Some(value) = decode_form_component(value) else {
            return false;
        };
        if !matches!(
            name.as_slice(),
            b"grant_type" | b"client_id" | b"client_secret" | b"audience" | b"scope" | b"resource"
        ) || fields.insert(name, value).is_some()
        {
            return false;
        }
    }
    if !(3..=6).contains(&fields.len())
        || fields.remove(b"grant_type".as_slice()).as_deref() != Some(b"client_credentials")
    {
        return false;
    }
    let Some(client_id) = fields.remove(b"client_id".as_slice()) else {
        return false;
    };
    let Some(client_secret) = fields.remove(b"client_secret".as_slice()) else {
        return false;
    };
    constant_time_eq(&client_id, oauth.client_id.as_slice())
        && constant_time_eq(&client_secret, oauth.client_secret.as_slice())
        && exact_form_optional_field(
            &mut fields,
            b"audience",
            oauth
                .expected_request
                .audience
                .as_ref()
                .map(|value| value.as_slice()),
        )
        && exact_form_optional_field(
            &mut fields,
            b"scope",
            oauth
                .expected_request
                .scope
                .as_ref()
                .map(|value| value.as_slice()),
        )
        && exact_form_optional_field(
            &mut fields,
            b"resource",
            oauth
                .expected_request
                .resource
                .as_ref()
                .map(|value| value.as_slice()),
        )
        && fields.is_empty()
}

fn exact_form_optional_field(
    fields: &mut std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    name: &[u8],
    expected: Option<&[u8]>,
) -> bool {
    match (fields.remove(name), expected) {
        (None, None) => true,
        (Some(actual), Some(expected)) => constant_time_eq(&actual, expected),
        _ => false,
    }
}

fn decode_form_component(encoded: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        match encoded[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = *encoded.get(index + 1)?;
                let low = *encoded.get(index + 2)?;
                decoded.push(hex_value(high)? << 4 | hex_value(low)?);
                index += 3;
            }
            byte if byte.is_ascii() && !byte.is_ascii_control() => {
                decoded.push(byte);
                index += 1;
            }
            _ => return None,
        }
    }
    Some(decoded)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn oauth_response(oauth: &OAuthRuntime, oversize_body: &Bytes) -> Response<Body> {
    use OAuthResponseCase as Case;

    let token = std::str::from_utf8(oauth.access_token.as_slice())
        .expect("generated access token is ASCII");
    match oauth.response_case {
        Case::Valid => json_value_response(valid_oauth_response_value(oauth)),
        Case::MissingAccessToken => json_value_response(match oauth.response_profile {
            OAuthResponseProfile::Oauth2Bearer => {
                json!({"token_type": "Bearer", "expires_in": TOKEN_EXPIRES_IN_SECONDS})
            }
            OAuthResponseProfile::Oauth2BearerNoExpiry => json!({"token_type": "Bearer"}),
        }),
        Case::WrongTokenType => json_value_response(match oauth.response_profile {
            OAuthResponseProfile::Oauth2Bearer => json!({
                "access_token": token,
                "token_type": "bearer",
                "expires_in": TOKEN_EXPIRES_IN_SECONDS,
            }),
            OAuthResponseProfile::Oauth2BearerNoExpiry => {
                json!({"access_token": token, "token_type": "bearer"})
            }
        }),
        Case::MissingExpiresIn => {
            json_value_response(json!({"access_token": token, "token_type": "Bearer"}))
        }
        Case::UnexpectedExpiresIn => json_value_response(json!({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": TOKEN_EXPIRES_IN_SECONDS,
        })),
        Case::DuplicateAccessToken => {
            let body = match oauth.response_profile {
                OAuthResponseProfile::Oauth2Bearer => format!(
                    r#"{{"access_token":"{token}","access_token":"{token}","token_type":"Bearer","expires_in":{TOKEN_EXPIRES_IN_SECONDS}}}"#
                ),
                OAuthResponseProfile::Oauth2BearerNoExpiry => format!(
                    r#"{{"access_token":"{token}","access_token":"{token}","token_type":"Bearer"}}"#
                ),
            };
            json_response(StatusCode::OK, Bytes::from(body))
        }
        Case::UnknownField | Case::RefreshToken | Case::IdToken => {
            let mut response = valid_oauth_response_value(oauth);
            let object = response
                .as_object_mut()
                .expect("valid OAuth response is an object");
            match oauth.response_case {
                Case::UnknownField => {
                    object.insert("unexpected".to_string(), Value::Bool(true));
                }
                Case::RefreshToken => {
                    object.insert(
                        "refresh_token".to_string(),
                        Value::String("synthetic-refresh-token".to_string()),
                    );
                }
                Case::IdToken => {
                    object.insert(
                        "id_token".to_string(),
                        Value::String("synthetic-id-token".to_string()),
                    );
                }
                _ => unreachable!("matched one of three extra-field cases"),
            }
            json_value_response(response)
        }
        Case::Redirect => Response::builder()
            .status(StatusCode::FOUND)
            .header(LOCATION, HeaderValue::from_static(REDIRECT_LOCATION))
            .body(Body::empty())
            .expect("static redirect response"),
        Case::Rejected => Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::empty())
            .expect("static rejection response"),
        Case::UnexpectedContentType => {
            let body = serde_json::to_vec(&valid_oauth_response_value(oauth))
                .expect("valid OAuth response is serializable");
            Response::builder()
                .status(StatusCode::OK)
                .header(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                )
                .body(Body::from(body))
                .expect("static content-type response")
        }
        Case::Oversize => {
            let valid = serde_json::to_vec(&valid_oauth_response_value(oauth))
                .expect("valid OAuth response is serializable");
            let mut body = oversize_body.to_vec();
            body[..valid.len()].copy_from_slice(&valid);
            json_response(StatusCode::OK, Bytes::from(body))
        }
    }
}

fn valid_oauth_response_value(oauth: &OAuthRuntime) -> Value {
    let token = std::str::from_utf8(oauth.access_token.as_slice())
        .expect("generated access token is ASCII");
    match oauth.response_profile {
        OAuthResponseProfile::Oauth2Bearer => json!({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": TOKEN_EXPIRES_IN_SECONDS,
        }),
        OAuthResponseProfile::Oauth2BearerNoExpiry => json!({
            "access_token": token,
            "token_type": "Bearer",
        }),
    }
}

fn json_value_response(value: Value) -> Response<Body> {
    let body = serde_json::to_vec(&value).expect("synthetic OAuth response is serializable");
    json_response(StatusCode::OK, Bytes::from(body))
}

fn static_json_response(status: StatusCode, body: &'static [u8]) -> Response<Body> {
    json_response(status, Bytes::from_static(body))
}

fn json_response(status: StatusCode, body: Bytes) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(Body::from(body))
        .expect("static response")
}

fn bearer_matches(headers: &HeaderMap, expected: &[u8]) -> bool {
    exact_bearer_matches(headers, expected)
}

fn exact_bearer_matches(headers: &HeaderMap, expected: &[u8]) -> bool {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let value = value.as_bytes();
    value
        .strip_prefix(b"Bearer ")
        .is_some_and(|actual| constant_time_eq(actual, expected))
}

fn constant_time_eq(actual: &[u8], expected: &[u8]) -> bool {
    actual.len() == expected.len() && bool::from(actual.ct_eq(expected))
}

fn increment_counter(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
        Some(value.saturating_add(1))
    });
}

fn read_secret_reference(
    reference: &SecretFileReference,
    root: &Path,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SyntheticSourceError> {
    let bytes = read_bounded_file(&reference.resolve(root), max_bytes, true)?;
    let mut bytes = Zeroizing::new(bytes);
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    if bytes.is_empty() || bytes.iter().any(|byte| byte.is_ascii_control()) {
        return Err(SyntheticSourceError::SecretLoadFailed);
    }
    Ok(bytes)
}

fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    owner_only: bool,
) -> Result<Vec<u8>, SyntheticSourceError> {
    let mut file = open_read_only_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| SyntheticSourceError::SecretLoadFailed)?;
    if !metadata.is_file() {
        return Err(SyntheticSourceError::SecretLoadFailed);
    }
    if owner_only {
        validate_owner_only(&metadata)?;
    }
    let max_bytes_u64 =
        u64::try_from(max_bytes).map_err(|_| SyntheticSourceError::SecretLoadFailed)?;
    if metadata.len() > max_bytes_u64 {
        return Err(SyntheticSourceError::SecretLoadFailed);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_bytes_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| SyntheticSourceError::SecretLoadFailed)?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(SyntheticSourceError::SecretLoadFailed);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_read_only_no_follow(path: &Path) -> Result<File, SyntheticSourceError> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| SyntheticSourceError::SecretLoadFailed)?;
    Ok(File::from(descriptor))
}

#[cfg(windows)]
fn open_read_only_no_follow(path: &Path) -> Result<File, SyntheticSourceError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| SyntheticSourceError::SecretLoadFailed)
}

#[cfg(not(any(unix, windows)))]
fn open_read_only_no_follow(path: &Path) -> Result<File, SyntheticSourceError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| SyntheticSourceError::SecretLoadFailed)?;
    if metadata.file_type().is_symlink() {
        return Err(SyntheticSourceError::SecretLoadFailed);
    }
    File::open(path).map_err(|_| SyntheticSourceError::SecretLoadFailed)
}

#[cfg(unix)]
fn validate_owner_only(metadata: &fs::Metadata) -> Result<(), SyntheticSourceError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode();
    let owner = metadata.uid();
    let effective_user = rustix::process::geteuid().as_raw();
    if mode & 0o177 != 0 || mode & 0o400 == 0 || (owner != 0 && owner != effective_user) {
        return Err(SyntheticSourceError::SecretLoadFailed);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only(_metadata: &fs::Metadata) -> Result<(), SyntheticSourceError> {
    Ok(())
}

fn load_tls_acceptor(
    references: &RuntimeSecretReferences,
    root: &Path,
) -> Result<TlsAcceptor, SyntheticSourceError> {
    let certificate_pem = Zeroizing::new(read_bounded_file(
        &references.tls_certificate.resolve(root),
        MAX_TLS_FILE_BYTES,
        true,
    )?);
    let private_key_pem = Zeroizing::new(read_bounded_file(
        &references.tls_private_key.resolve(root),
        MAX_TLS_FILE_BYTES,
        true,
    )?);
    let certificates = decode_pem_blocks(&certificate_pem, "CERTIFICATE")?
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    if certificates.is_empty() {
        return Err(SyntheticSourceError::InvalidTlsMaterial);
    }
    let mut keys = decode_pem_blocks(&private_key_pem, "PRIVATE KEY")?;
    if keys.len() != 1 {
        return Err(SyntheticSourceError::InvalidTlsMaterial);
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        keys.pop().ok_or(SyntheticSourceError::InvalidTlsMaterial)?,
    ));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| SyntheticSourceError::InvalidTlsMaterial)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn decode_pem_blocks(bytes: &[u8], label: &str) -> Result<Vec<Vec<u8>>, SyntheticSourceError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SyntheticSourceError::InvalidTlsMaterial)?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut encoded = String::new();
    let mut inside = false;
    for line in text.lines().map(str::trim) {
        if line == begin {
            if inside {
                return Err(SyntheticSourceError::InvalidTlsMaterial);
            }
            inside = true;
            encoded.clear();
        } else if line == end {
            if !inside || encoded.is_empty() {
                return Err(SyntheticSourceError::InvalidTlsMaterial);
            }
            blocks.push(
                STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(|_| SyntheticSourceError::InvalidTlsMaterial)?,
            );
            inside = false;
        } else if inside {
            if line.is_empty()
                || !line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
            {
                return Err(SyntheticSourceError::InvalidTlsMaterial);
            }
            encoded.push_str(line);
        } else if !line.is_empty() {
            return Err(SyntheticSourceError::InvalidTlsMaterial);
        }
    }
    if inside {
        return Err(SyntheticSourceError::InvalidTlsMaterial);
    }
    Ok(blocks)
}

async fn serve_tls<F>(
    listener: TcpListener,
    app: Router,
    acceptor: TlsAcceptor,
    shutdown: F,
) -> Result<(), SyntheticSourceError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let connection_cap = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        while tasks.try_join_next().is_some() {}
        let permit = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            permit = Arc::clone(&connection_cap).acquire_owned() => {
                permit.map_err(|_| SyntheticSourceError::ServeFailed)?
            }
        };
        let (stream, _) = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                accepted.map_err(|_| SyntheticSourceError::ServeFailed)?
            }
        };
        let app = app.clone();
        let acceptor = acceptor.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let Ok(Ok(stream)) =
                tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
            else {
                return;
            };
            let service = service_fn(move |request: Request<Incoming>| {
                let app = app.clone();
                async move {
                    let request = request.map(Body::new);
                    match app.oneshot(request).await {
                        Ok(response) => Ok::<_, Infallible>(response),
                        Err(error) => match error {},
                    }
                }
            });
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(CONNECTION_HEADER_TIMEOUT)
                .keep_alive(false);
            let _ = builder
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use axum::http::header::AUTHORIZATION;
    use axum::http::Request;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;
    use tower::ServiceExt;

    use super::*;

    const CLIENT_ID_CANARY: &[u8] = b"client-id-canary";
    const CLIENT_SECRET_CANARY: &[u8] = b"client-secret-canary";
    const CONTROL_CANARY: &[u8] = b"control-canary";
    const ACCESS_TOKEN_CANARY: &[u8] = b"access-token-canary";
    const SOURCE_VALUE_CANARY: &str = "source-value-canary";
    const EXPECTED_SOURCE_PATH: &str = "/people/AB-123456";
    const EXPECTED_SOURCE_URI: &str = "/people/AB-123456?fields=active";

    fn secret_reference(file: &str) -> SecretFileReference {
        SecretFileReference {
            file: file.to_string(),
            generation: 1,
        }
    }

    fn plan(
        scenario: SourceScenario,
        oauth_profile: Option<OAuthResponseProfile>,
    ) -> SyntheticSourcePlan {
        SyntheticSourcePlan {
            version: PlanVersion::V1,
            scenario,
            source_request: expected_source_request(),
            source_auth: None,
            request_encoding: OAuthRequestEncoding::Json,
            oauth: oauth_profile.map(|response_profile| OAuthPlan {
                response_profile,
                response_case: OAuthResponseCase::Valid,
                request: OAuthRequestExpectation {
                    audience: None,
                    scope: None,
                    resource: None,
                },
                secrets: OAuthSecretReferences {
                    client_id: secret_reference("oauth-client-id"),
                    client_secret: secret_reference("oauth-client-secret"),
                },
            }),
            response_body: scenario
                .needs_authored_response()
                .then(|| json!({"eligible": true, "source_value": SOURCE_VALUE_CANARY})),
            secrets: RuntimeSecretReferences {
                control_token: secret_reference("control-token"),
                tls_certificate: secret_reference("tls.crt"),
                tls_private_key: secret_reference("tls.key"),
            },
        }
    }

    fn expected_source_request() -> SourceRequestExpectation {
        SourceRequestExpectation {
            method: SourceRequestMethod::Get,
            path: EXPECTED_SOURCE_PATH.to_string(),
            query: BTreeMap::from([("fields".to_string(), "active".to_string())]),
            headers: BTreeMap::new(),
            body: None,
        }
    }

    fn state(
        scenario: SourceScenario,
        oauth_profile: Option<OAuthResponseProfile>,
    ) -> Arc<SyntheticSourceState> {
        state_with_encoding(scenario, oauth_profile, OAuthRequestEncoding::Json)
    }

    fn state_with_encoding(
        scenario: SourceScenario,
        oauth_profile: Option<OAuthResponseProfile>,
        request_encoding: OAuthRequestEncoding,
    ) -> Arc<SyntheticSourceState> {
        state_with_request(
            scenario,
            oauth_profile,
            request_encoding,
            OAuthRequestExpectationRuntime {
                audience: None,
                scope: None,
                resource: None,
            },
        )
    }

    fn state_with_request(
        scenario: SourceScenario,
        oauth_profile: Option<OAuthResponseProfile>,
        request_encoding: OAuthRequestEncoding,
        expected_request: OAuthRequestExpectationRuntime,
    ) -> Arc<SyntheticSourceState> {
        Arc::new(SyntheticSourceState {
            scenario,
            source_request: expected_source_request(),
            response_body: scenario.needs_authored_response().then(|| {
                Bytes::from(
                    serde_json::to_vec(
                        &json!({"eligible": true, "source_value": SOURCE_VALUE_CANARY}),
                    )
                    .unwrap(),
                )
            }),
            static_bearer: None,
            oauth: oauth_profile.map(|response_profile| OAuthRuntime {
                request_encoding,
                expected_request,
                response_profile,
                response_case: OAuthResponseCase::Valid,
                client_id: Zeroizing::new(CLIENT_ID_CANARY.to_vec()),
                client_secret: Zeroizing::new(CLIENT_SECRET_CANARY.to_vec()),
                access_token: Zeroizing::new(ACCESS_TOKEN_CANARY.to_vec()),
            }),
            control_token: Zeroizing::new(CONTROL_CANARY.to_vec()),
            counters: Counters::default(),
            oversize_body: Bytes::from(vec![b' '; OVERSIZE_RESPONSE_BYTES]),
        })
    }

    async fn response_body(response: Response<Body>, max: usize) -> Vec<u8> {
        to_bytes(response.into_body(), max)
            .await
            .expect("bounded test response")
            .to_vec()
    }

    fn token_request() -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(TOKEN_ROUTE)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "grant_type": "client_credentials",
                    "client_id": std::str::from_utf8(CLIENT_ID_CANARY).unwrap(),
                    "client_secret": std::str::from_utf8(CLIENT_SECRET_CANARY).unwrap(),
                })
                .to_string(),
            ))
            .unwrap()
    }

    #[test]
    fn plan_contract_is_closed_and_bounded() {
        assert!(SOURCE_TIMEOUT.as_secs() > AUTHORED_DEVELOPMENT_SOURCE_DEADLINE_SECONDS);
        let raw = json!({
            "version": SYNTHETIC_SOURCE_PLAN_VERSION,
            "scenario": "authored_response",
            "source_request": {
                "method": "get",
                "path": EXPECTED_SOURCE_PATH,
                "query": {"fields": "active"},
                "headers": {}
            },
            "request_encoding": "json",
            "oauth": {
                "response_profile": "oauth2_bearer",
                "request": {"scope": "scope-value-canary"},
                "secrets": {
                    "client_id": {"file": "oauth-client-id", "generation": 1},
                    "client_secret": {"file": "oauth-client-secret", "generation": 1}
                }
            },
            "response_body": {"eligible": true},
            "secrets": {
                "control_token": {"file": "control-token", "generation": 1},
                "tls_certificate": {"file": "tls.crt", "generation": 1},
                "tls_private_key": {"file": "tls.key", "generation": 1}
            }
        });
        let admitted: SyntheticSourcePlan = serde_json::from_value(raw.clone()).unwrap();
        admitted.validate().unwrap();
        let diagnostic = format!("{admitted:?}");
        assert!(!diagnostic.contains("eligible"));
        assert!(!diagnostic.contains("scope-value-canary"));
        assert!(!diagnostic.contains(EXPECTED_SOURCE_PATH));

        for forbidden in ["destination", "route", "headers", "proxy"] {
            let mut candidate = raw.clone();
            candidate[forbidden] = json!("https://attacker.invalid");
            assert!(serde_json::from_value::<SyntheticSourcePlan>(candidate).is_err());
        }
        let mut missing_encoding = raw.clone();
        missing_encoding
            .as_object_mut()
            .unwrap()
            .remove("request_encoding");
        assert!(serde_json::from_value::<SyntheticSourcePlan>(missing_encoding).is_err());
        let mut unknown_encoding = raw.clone();
        unknown_encoding["request_encoding"] = json!("auto");
        assert!(serde_json::from_value::<SyntheticSourcePlan>(unknown_encoding).is_err());
        let mut missing_source_request = raw.clone();
        missing_source_request
            .as_object_mut()
            .unwrap()
            .remove("source_request");
        assert!(serde_json::from_value::<SyntheticSourcePlan>(missing_source_request).is_err());
        for reserved in [HEALTH_ROUTE, TOKEN_ROUTE, COUNTERS_ROUTE] {
            let mut reserved_path = raw.clone();
            reserved_path["source_request"]["path"] = json!(reserved);
            let reserved_path: SyntheticSourcePlan = serde_json::from_value(reserved_path).unwrap();
            assert_eq!(
                reserved_path.validate(),
                Err(SyntheticSourceError::InvalidPlan)
            );
        }
        let mut sensitive_header = raw.clone();
        sensitive_header["source_request"]["headers"]["authorization"] = json!("secret");
        let sensitive_header: SyntheticSourcePlan =
            serde_json::from_value(sensitive_header).unwrap();
        assert_eq!(
            sensitive_header.validate(),
            Err(SyntheticSourceError::InvalidPlan)
        );
        let mut missing_oauth_request = raw.clone();
        missing_oauth_request["oauth"]
            .as_object_mut()
            .unwrap()
            .remove("request");
        assert!(serde_json::from_value::<SyntheticSourcePlan>(missing_oauth_request).is_err());
        let mut unknown_oauth_request_field = raw.clone();
        unknown_oauth_request_field["oauth"]["request"]["headers"] = json!("forbidden");
        assert!(
            serde_json::from_value::<SyntheticSourcePlan>(unknown_oauth_request_field).is_err()
        );
        let mut oversized_oauth_request = raw.clone();
        oversized_oauth_request["oauth"]["request"]["scope"] =
            json!("x".repeat(MAX_EXPECTED_OAUTH_FIELDS_BYTES + 1));
        let oversized_oauth_request: SyntheticSourcePlan =
            serde_json::from_value(oversized_oauth_request).unwrap();
        assert_eq!(
            oversized_oauth_request.validate(),
            Err(SyntheticSourceError::InvalidPlan)
        );
        let mut traversal = raw.clone();
        traversal["secrets"]["control_token"]["file"] = json!("../secret");
        let traversal: SyntheticSourcePlan = serde_json::from_value(traversal).unwrap();
        assert_eq!(traversal.validate(), Err(SyntheticSourceError::InvalidPlan));

        for (left, right) in [
            (
                &["secrets", "tls_private_key", "file"][..],
                &["secrets", "tls_certificate", "file"][..],
            ),
            (
                &["oauth", "secrets", "client_secret", "file"][..],
                &["oauth", "secrets", "client_id", "file"][..],
            ),
            (
                &["oauth", "secrets", "client_id", "file"][..],
                &["secrets", "control_token", "file"][..],
            ),
        ] {
            let mut aliased = raw.clone();
            let alias = right
                .iter()
                .fold(&aliased, |value, segment| &value[*segment])
                .clone();
            let target = left
                .iter()
                .fold(&mut aliased, |value, segment| &mut value[*segment]);
            *target = alias;
            let aliased: SyntheticSourcePlan = serde_json::from_value(aliased).unwrap();
            assert_eq!(aliased.validate(), Err(SyntheticSourceError::InvalidPlan));
        }

        let mut static_and_oauth = raw.clone();
        static_and_oauth["source_auth"] = json!({
            "type": "static_bearer",
            "secret": {"file": "source-bearer", "generation": 1}
        });
        let static_and_oauth: SyntheticSourcePlan =
            serde_json::from_value(static_and_oauth).unwrap();
        assert_eq!(
            static_and_oauth.validate(),
            Err(SyntheticSourceError::InvalidPlan)
        );
        let mut static_alias = raw.clone();
        static_alias.as_object_mut().unwrap().remove("oauth");
        static_alias["source_auth"] = json!({
            "type": "static_bearer",
            "secret": {"file": "control-token", "generation": 1}
        });
        let static_alias: SyntheticSourcePlan = serde_json::from_value(static_alias).unwrap();
        assert_eq!(
            static_alias.validate(),
            Err(SyntheticSourceError::InvalidPlan)
        );

        let mut oversized = raw;
        oversized["response_body"] = json!("x".repeat(MAX_AUTHORED_RESPONSE_BYTES + 1));
        let oversized: SyntheticSourcePlan = serde_json::from_value(oversized).unwrap();
        assert_eq!(oversized.validate(), Err(SyntheticSourceError::InvalidPlan));
    }

    #[tokio::test]
    async fn denial_before_source_keeps_value_free_counters_at_zero() {
        let state = state(
            SourceScenario::AuthoredResponse,
            Some(OAuthResponseProfile::Oauth2Bearer),
        );
        let app = router(Arc::clone(&state));
        let health = app
            .clone()
            .oneshot(Request::get(HEALTH_ROUTE).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::NO_CONTENT);
        assert_eq!(state.counters.token_requests.load(Ordering::Relaxed), 0);
        assert_eq!(state.counters.source_requests.load(Ordering::Relaxed), 0);

        let counters = app
            .oneshot(
                Request::get(COUNTERS_ROUTE)
                    .header(
                        AUTHORIZATION,
                        format!("Bearer {}", std::str::from_utf8(CONTROL_CANARY).unwrap()),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: Value =
            serde_json::from_slice(&response_body(counters, 1024).await).expect("counter JSON");
        assert_eq!(body, json!({"source_requests": 0, "token_requests": 0}));
        let rendered = body.to_string();
        for canary in [
            std::str::from_utf8(CLIENT_ID_CANARY).unwrap(),
            std::str::from_utf8(CLIENT_SECRET_CANARY).unwrap(),
            std::str::from_utf8(CONTROL_CANARY).unwrap(),
            std::str::from_utf8(ACCESS_TOKEN_CANARY).unwrap(),
            SOURCE_VALUE_CANARY,
        ] {
            assert!(!rendered.contains(canary));
        }
    }

    #[tokio::test]
    async fn oauth_and_authorized_source_path_return_only_closed_responses() {
        let state = state(
            SourceScenario::AuthoredResponse,
            Some(OAuthResponseProfile::Oauth2Bearer),
        );
        let app = router(Arc::clone(&state));
        let token = app.clone().oneshot(token_request()).await.unwrap();
        assert_eq!(token.status(), StatusCode::OK);
        let token_body: Value =
            serde_json::from_slice(&response_body(token, 1024).await).expect("token JSON");
        assert_eq!(token_body["token_type"], "Bearer");
        assert_eq!(token_body["expires_in"], TOKEN_EXPIRES_IN_SECONDS);
        assert_eq!(
            token_body["access_token"],
            std::str::from_utf8(ACCESS_TOKEN_CANARY).unwrap()
        );

        let source = app
            .oneshot(
                Request::get(EXPECTED_SOURCE_URI)
                    .header(
                        AUTHORIZATION,
                        format!(
                            "Bearer {}",
                            std::str::from_utf8(ACCESS_TOKEN_CANARY).unwrap()
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(source.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Value>(&response_body(source, 1024).await).unwrap(),
            json!({"eligible": true, "source_value": SOURCE_VALUE_CANARY})
        );
        assert_eq!(state.counters.token_requests.load(Ordering::Relaxed), 1);
        assert_eq!(state.counters.source_requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn source_scenarios_use_their_exact_authored_statuses() {
        for (scenario, expected_status) in [
            (SourceScenario::AuthoredResponse, StatusCode::OK),
            (SourceScenario::NoMatch, StatusCode::NOT_FOUND),
            (SourceScenario::Ambiguity, StatusCode::CONFLICT),
            (SourceScenario::SubjectMismatch, StatusCode::OK),
        ] {
            let response = router(state(scenario, None))
                .oneshot(
                    Request::get(EXPECTED_SOURCE_URI)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status);
            assert_eq!(
                serde_json::from_slice::<Value>(&response_body(response, 1024).await).unwrap(),
                json!({"eligible": true, "source_value": SOURCE_VALUE_CANARY})
            );
        }
    }

    #[tokio::test]
    async fn exact_source_request_and_static_bearer_are_both_required() {
        let mut state = state(SourceScenario::AuthoredResponse, None);
        let state_mut = Arc::get_mut(&mut state).unwrap();
        state_mut.source_request = SourceRequestExpectation {
            method: SourceRequestMethod::Post,
            path: "/records/AB-123456".to_string(),
            query: BTreeMap::from([("view".to_string(), "minimal".to_string())]),
            headers: BTreeMap::from([("accept".to_string(), "application/json".to_string())]),
            body: Some(json!({"person_id": "AB-123456"})),
        };
        state_mut.static_bearer = Some(Zeroizing::new(b"static-bearer-canary".to_vec()));
        let app = router(Arc::clone(&state));
        let request = |uri: &str, bearer: &str, body: &'static str, extra_header: bool| {
            let mut request = Request::post(uri)
                .header(ACCEPT, "application/json")
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Bearer {bearer}"));
            if extra_header {
                request = request.header("x-unexpected", "value-canary");
            }
            request.body(Body::from(body)).unwrap()
        };

        let accepted = app
            .clone()
            .oneshot(request(
                "/records/AB-123456?view=minimal",
                "static-bearer-canary",
                r#"{"person_id":"AB-123456"}"#,
                false,
            ))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);

        for (uri, bearer, body, extra_header, expected_status) in [
            (
                "/records/AB-123456?view=minimal",
                "wrong-bearer-canary",
                r#"{"person_id":"AB-123456"}"#,
                false,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "/records/other?view=minimal",
                "static-bearer-canary",
                r#"{"person_id":"AB-123456"}"#,
                false,
                StatusCode::BAD_REQUEST,
            ),
            (
                "/records/AB-123456?view=expanded",
                "static-bearer-canary",
                r#"{"person_id":"AB-123456"}"#,
                false,
                StatusCode::BAD_REQUEST,
            ),
            (
                "/records/AB-123456?view=minimal",
                "static-bearer-canary",
                r#"{"person_id":"other"}"#,
                false,
                StatusCode::BAD_REQUEST,
            ),
            (
                "/records/AB-123456?view=minimal",
                "static-bearer-canary",
                r#"{"person_id":"AB-123456"}"#,
                true,
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(request(uri, bearer, body, extra_header))
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status);
            let rendered = String::from_utf8(response_body(response, 1024).await).unwrap();
            assert!(!rendered.contains("value-canary"));
            assert!(!rendered.contains("wrong-bearer-canary"));
            assert!(!rendered.contains("other"));
        }
        assert_eq!(state.counters.source_requests.load(Ordering::Relaxed), 6);
    }

    #[tokio::test]
    async fn source_auth_mode_is_enforced_before_body_or_request_shape() {
        let oauth_state = state(
            SourceScenario::AuthoredResponse,
            Some(OAuthResponseProfile::Oauth2Bearer),
        );
        let oauth_app = router(Arc::clone(&oauth_state));
        let expected_denial = br#"{"error":"source_credential_required"}"#;

        let mut duplicate = Request::get(EXPECTED_SOURCE_URI)
            .header(AUTHORIZATION, "Bearer access-token-canary")
            .body(Body::empty())
            .unwrap();
        duplicate.headers_mut().append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer second-token"),
        );
        let oauth_denials = [
            Request::get(EXPECTED_SOURCE_URI)
                .body(Body::empty())
                .unwrap(),
            Request::get(EXPECTED_SOURCE_URI)
                .header(AUTHORIZATION, "Basic access-token-canary")
                .body(Body::empty())
                .unwrap(),
            Request::get(EXPECTED_SOURCE_URI)
                .header(AUTHORIZATION, "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
            Request::get(EXPECTED_SOURCE_URI)
                .header(AUTHORIZATION, "Bearer")
                .body(Body::empty())
                .unwrap(),
            duplicate,
            Request::post("/wrong-shape")
                .header(AUTHORIZATION, "Bearer wrong-token")
                .body(Body::from(vec![b'x'; MAX_REQUEST_BODY_BYTES + 1]))
                .unwrap(),
        ];
        for request in oauth_denials {
            let response = oauth_app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response_body(response, 1024).await, expected_denial);
        }

        let never_polled = Body::from_stream(futures::stream::poll_fn(
            |_| -> std::task::Poll<Option<Result<Bytes, Infallible>>> {
                panic!("unauthenticated source body must not be polled")
            },
        ));
        let response = source_with_timeout(
            Arc::clone(&oauth_state),
            Request::post("/wrong-shape").body(never_polled).unwrap(),
            Duration::from_millis(10),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response_body(response, 1024).await, expected_denial);

        let authenticated_wrong_shape = oauth_app
            .oneshot(
                Request::post("/wrong-shape")
                    .header(AUTHORIZATION, "Bearer access-token-canary")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated_wrong_shape.status(), StatusCode::BAD_REQUEST);

        let mut static_state = state(SourceScenario::AuthoredResponse, None);
        Arc::get_mut(&mut static_state).unwrap().static_bearer =
            Some(Zeroizing::new(b"static-bearer-canary".to_vec()));
        for request in [
            Request::get(EXPECTED_SOURCE_URI)
                .body(Body::empty())
                .unwrap(),
            Request::get(EXPECTED_SOURCE_URI)
                .header(AUTHORIZATION, "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
        ] {
            let response = router(Arc::clone(&static_state))
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response_body(response, 1024).await, expected_denial);
        }

        let unauthenticated_state = state(SourceScenario::AuthoredResponse, None);
        let disallowed = router(Arc::clone(&unauthenticated_state))
            .oneshot(
                Request::post("/wrong-shape")
                    .header(AUTHORIZATION, "Bearer any-token")
                    .body(Body::from(vec![b'x'; MAX_REQUEST_BODY_BYTES + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disallowed.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response_body(disallowed, 1024).await, expected_denial);

        let unauthenticated_wrong_shape = router(unauthenticated_state)
            .oneshot(Request::post("/wrong-shape").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            unauthenticated_wrong_shape.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn oauth_request_encoding_accepts_only_the_selected_closed_shape() {
        let json_state = state(
            SourceScenario::AuthoredResponse,
            Some(OAuthResponseProfile::Oauth2Bearer),
        );
        let json_app = router(Arc::clone(&json_state));
        assert_eq!(
            json_app
                .clone()
                .oneshot(token_request())
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let valid_form_body = concat!(
            "grant_type=client_credentials",
            "&client_id=client%2Did%2Dcanary",
            "&client_secret=client%2Dsecret%2Dcanary",
            "&scope=records.read+registry.read",
            "&audience=https%3A%2F%2Fregistry.invalid"
        );
        let form_request = || {
            Request::post(TOKEN_ROUTE)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(valid_form_body))
                .unwrap()
        };
        assert_eq!(
            json_app.oneshot(form_request()).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let form_state = state_with_request(
            SourceScenario::AuthoredResponse,
            Some(OAuthResponseProfile::Oauth2Bearer),
            OAuthRequestEncoding::Form,
            OAuthRequestExpectationRuntime {
                audience: Some(Zeroizing::new(b"https://registry.invalid".to_vec())),
                scope: Some(Zeroizing::new(b"records.read registry.read".to_vec())),
                resource: None,
            },
        );
        let form_app = router(Arc::clone(&form_state));
        assert_eq!(
            form_app
                .clone()
                .oneshot(form_request())
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            form_app
                .clone()
                .oneshot(token_request())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        for invalid_body in [
            "grant_type=client_credentials&client_id=client-id-canary&client_secret=client-secret-canary&extra=value",
            "grant_type=client_credentials&client_id=client-id-canary&client_id=client-id-canary&client_secret=client-secret-canary",
            "grant_type=client_credentials&client_id=client%2&client_secret=client-secret-canary",
            "grant_type=client_credentials&client_id=client-id-canary&client_secret",
            "grant_type=client_credentials&client_id=client-id-canary&client_secret=client-secret-canary&scope=wrong.scope&audience=https%3A%2F%2Fregistry.invalid",
            "grant_type=client_credentials&client_id=client-id-canary&client_secret=client-secret-canary&scope=records.read+registry.read&audience=https%3A%2F%2Fregistry.invalid&resource=https%3A%2F%2Funexpected.invalid",
        ] {
            let response = form_app
                .clone()
                .oneshot(
                    Request::post(TOKEN_ROUTE)
                        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .body(Body::from(invalid_body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        assert_eq!(
            json_state.counters.token_requests.load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            form_state.counters.token_requests.load(Ordering::Relaxed),
            8
        );
    }

    #[tokio::test]
    async fn no_expiry_profile_has_exact_shape_and_each_exchange_is_counted() {
        let state = state(
            SourceScenario::AuthoredResponse,
            Some(OAuthResponseProfile::Oauth2BearerNoExpiry),
        );
        let app = router(Arc::clone(&state));
        for _ in 0..2 {
            let response = app.clone().oneshot(token_request()).await.unwrap();
            let body: Value = serde_json::from_slice(&response_body(response, 1024).await).unwrap();
            assert_eq!(
                body.as_object()
                    .unwrap()
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>(),
                vec!["access_token".to_string(), "token_type".to_string()]
            );
        }
        assert_eq!(state.counters.token_requests.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn invalid_credentials_and_control_access_are_value_free() {
        let state = state(
            SourceScenario::AuthoredResponse,
            Some(OAuthResponseProfile::Oauth2Bearer),
        );
        let app = router(Arc::clone(&state));
        let invalid = Request::builder()
            .method("POST")
            .uri(TOKEN_ROUTE)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"grant_type":"client_credentials","client_id":"{}","client_secret":"wrong"}}"#,
                std::str::from_utf8(CLIENT_ID_CANARY).unwrap()
            )))
            .unwrap();
        let response = app.clone().oneshot(invalid).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let rendered = String::from_utf8(response_body(response, 1024).await).unwrap();
        assert!(!rendered.contains(std::str::from_utf8(CLIENT_ID_CANARY).unwrap()));
        assert!(!rendered.contains(std::str::from_utf8(CLIENT_SECRET_CANARY).unwrap()));

        let counters = app
            .oneshot(Request::get(COUNTERS_ROUTE).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(counters.status(), StatusCode::UNAUTHORIZED);
        let rendered = String::from_utf8(response_body(counters, 1024).await).unwrap();
        assert!(!rendered.contains(std::str::from_utf8(CONTROL_CANARY).unwrap()));
    }

    #[tokio::test]
    async fn arbitrary_routes_are_absent_and_oversized_requests_are_bounded_and_counted() {
        let state = state(
            SourceScenario::AuthoredResponse,
            Some(OAuthResponseProfile::Oauth2Bearer),
        );
        let app = router(Arc::clone(&state));
        let absent = app
            .clone()
            .oneshot(
                Request::post("/proxy")
                    .header(AUTHORIZATION, "Bearer access-token-canary")
                    .body(Body::from("ignored"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(absent.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.counters.token_requests.load(Ordering::Relaxed), 0);
        assert_eq!(state.counters.source_requests.load(Ordering::Relaxed), 1);

        let oversized = app
            .oneshot(
                Request::post(TOKEN_ROUTE)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(vec![b'x'; MAX_REQUEST_BODY_BYTES + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(state.counters.token_requests.load(Ordering::Relaxed), 1);
        assert_eq!(state.counters.source_requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn token_and_source_body_reads_have_a_fixed_deadline() {
        let state = state(
            SourceScenario::AuthoredResponse,
            Some(OAuthResponseProfile::Oauth2Bearer),
        );
        let pending_body =
            || Body::from_stream(futures::stream::pending::<Result<Bytes, Infallible>>());
        let token = token_with_timeout(
            Arc::clone(&state),
            Request::post(TOKEN_ROUTE).body(pending_body()).unwrap(),
            Duration::from_millis(10),
        )
        .await;
        assert_eq!(token.status(), StatusCode::REQUEST_TIMEOUT);
        let source = source_with_timeout(
            Arc::clone(&state),
            Request::post(EXPECTED_SOURCE_URI)
                .header(AUTHORIZATION, "Bearer access-token-canary")
                .body(pending_body())
                .unwrap(),
            Duration::from_millis(10),
        )
        .await;
        assert_eq!(source.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(state.counters.token_requests.load(Ordering::Relaxed), 1);
        assert_eq!(state.counters.source_requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn malformed_oauth_cases_are_strict_and_redirect_is_fixed() {
        let mut runtime = OAuthRuntime {
            request_encoding: OAuthRequestEncoding::Json,
            expected_request: OAuthRequestExpectationRuntime {
                audience: None,
                scope: None,
                resource: None,
            },
            response_profile: OAuthResponseProfile::Oauth2Bearer,
            response_case: OAuthResponseCase::DuplicateAccessToken,
            client_id: Zeroizing::new(CLIENT_ID_CANARY.to_vec()),
            client_secret: Zeroizing::new(CLIENT_SECRET_CANARY.to_vec()),
            access_token: Zeroizing::new(ACCESS_TOKEN_CANARY.to_vec()),
        };
        let oversize = Bytes::from(vec![b' '; OVERSIZE_RESPONSE_BYTES]);
        let duplicate = oauth_response(&runtime, &oversize);
        let duplicate_body = String::from_utf8(response_body(duplicate, 1024).await).unwrap();
        assert_eq!(duplicate_body.matches("\"access_token\"").count(), 2);
        assert!(duplicate_body.contains("\"expires_in\":60"));

        for (case, extra) in [
            (OAuthResponseCase::UnknownField, "unexpected"),
            (OAuthResponseCase::RefreshToken, "refresh_token"),
            (OAuthResponseCase::IdToken, "id_token"),
        ] {
            runtime.response_case = case;
            let response = oauth_response(&runtime, &oversize);
            let mut body: Value =
                serde_json::from_slice(&response_body(response, 1024).await).unwrap();
            body.as_object_mut().unwrap().remove(extra);
            assert_eq!(body, valid_oauth_response_value(&runtime));
        }

        runtime.response_case = OAuthResponseCase::UnexpectedContentType;
        let unexpected_content_type = oauth_response(&runtime, &oversize);
        assert_eq!(
            unexpected_content_type.headers().get(CONTENT_TYPE).unwrap(),
            HeaderValue::from_static("application/octet-stream")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&response_body(unexpected_content_type, 1024).await)
                .unwrap(),
            valid_oauth_response_value(&runtime)
        );

        runtime.response_case = OAuthResponseCase::Redirect;
        let redirect = oauth_response(&runtime, &oversize);
        assert_eq!(redirect.status(), StatusCode::FOUND);
        assert_eq!(
            redirect.headers().get(LOCATION).unwrap(),
            HeaderValue::from_static(REDIRECT_LOCATION)
        );

        runtime.response_case = OAuthResponseCase::Oversize;
        let oversized = oauth_response(&runtime, &oversize);
        let oversized = response_body(oversized, OVERSIZE_RESPONSE_BYTES).await;
        assert_eq!(oversized.len(), OVERSIZE_RESPONSE_BYTES);
        assert_eq!(
            serde_json::from_slice::<Value>(&oversized).unwrap(),
            valid_oauth_response_value(&runtime)
        );
    }

    #[tokio::test]
    async fn tls_material_serves_health_and_secret_failures_are_value_free() {
        let directory = TempDir::new().unwrap();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["synthetic-source".to_string()]).unwrap();
        let certificate_der = cert.der().clone();
        write_owner_only(
            &directory.path().join("tls.crt"),
            pem("CERTIFICATE", certificate_der.as_ref()).as_bytes(),
        );
        write_owner_only(
            &directory.path().join("tls.key"),
            pem("PRIVATE KEY", &key_pair.serialize_der()).as_bytes(),
        );
        write_owner_only(&directory.path().join("control-token"), CONTROL_CANARY);
        write_owner_only(&directory.path().join("oauth-client-id"), CLIENT_ID_CANARY);
        write_owner_only(
            &directory.path().join("oauth-client-secret"),
            CLIENT_SECRET_CANARY,
        );
        let plan = plan(
            SourceScenario::AuthoredResponse,
            Some(OAuthResponseProfile::Oauth2Bearer),
        );
        let acceptor = load_tls_acceptor(&plan.secrets, directory.path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_tls(
            listener,
            router(state(SourceScenario::AuthoredResponse, None)),
            acceptor,
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();
        let mut client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut stream = connector
            .connect(
                ServerName::try_from("synthetic-source").unwrap().to_owned(),
                stream,
            )
            .await
            .unwrap();
        stream
            .write_all(
                b"GET /healthz HTTP/1.1\r\nHost: synthetic-source\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 204 No Content\r\n"));
        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();

        let missing = SecretFileReference {
            file: "missing".to_string(),
            generation: 1,
        };
        let error =
            read_secret_reference(&missing, directory.path(), MAX_SECRET_BYTES).unwrap_err();
        let diagnostic = format!("{error:?} {error}");
        for canary in [
            std::str::from_utf8(CLIENT_ID_CANARY).unwrap(),
            std::str::from_utf8(CLIENT_SECRET_CANARY).unwrap(),
            std::str::from_utf8(CONTROL_CANARY).unwrap(),
        ] {
            assert!(!diagnostic.contains(canary));
        }
    }

    #[tokio::test]
    async fn counter_probe_uses_only_fixed_tls_control_material_and_emits_exact_json() {
        let directory = TempDir::new().unwrap();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["registry-synthetic-source".to_string()]).unwrap();
        write_owner_only(
            &directory.path().join("tls.crt"),
            pem("CERTIFICATE", cert.der().as_ref()).as_bytes(),
        );
        write_owner_only(
            &directory.path().join("server.key"),
            pem("PRIVATE KEY", &key_pair.serialize_der()).as_bytes(),
        );
        write_owner_only(&directory.path().join("control-token"), CONTROL_CANARY);

        let plan_path = directory.path().join("plan.json");
        fs::write(
            &plan_path,
            serde_json::to_vec(&json!({
                "version": SYNTHETIC_SOURCE_PLAN_VERSION,
                "scenario": "authored_response",
                "source_request": {
                    "method": "get",
                    "path": EXPECTED_SOURCE_PATH,
                    "query": {"fields": "active"},
                    "headers": {}
                },
                "request_encoding": "form",
                "oauth": {
                    "response_profile": "oauth2_bearer",
                    "request": {"scope": "records.read"},
                    "secrets": {
                        "client_id": {"file": "not-mounted-client-id", "generation": 1},
                        "client_secret": {"file": "not-mounted-client-secret", "generation": 1}
                    }
                },
                "response_body": {"eligible": true},
                "secrets": {
                    "control_token": {"file": "control-token", "generation": 1},
                    "tls_certificate": {"file": "tls.crt", "generation": 1},
                    "tls_private_key": {"file": "not-mounted-private-key", "generation": 1}
                }
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(!directory.path().join("not-mounted-client-id").exists());
        assert!(!directory.path().join("not-mounted-client-secret").exists());
        assert!(!directory.path().join("not-mounted-private-key").exists());

        let server_tls = load_tls_acceptor(
            &RuntimeSecretReferences {
                control_token: secret_reference("control-token"),
                tls_certificate: secret_reference("tls.crt"),
                tls_private_key: secret_reference("server.key"),
            },
            directory.path(),
        )
        .unwrap();
        let state = state(SourceScenario::AuthoredResponse, None);
        increment_counter(&state.counters.token_requests);
        increment_counter(&state.counters.token_requests);
        increment_counter(&state.counters.source_requests);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_tls(listener, router(state), server_tls, async move {
            let _ = shutdown_rx.await;
        }));
        let target = || ProbeTarget::Test {
            url: format!(
                "https://registry-synthetic-source:{}{COUNTERS_ROUTE}",
                address.port()
            ),
            resolved_address: address,
        };

        let output = probe_with_options(&plan_path, directory.path(), target())
            .await
            .unwrap();
        assert_eq!(output, r#"{"token_requests":2,"source_requests":1}"#);

        write_owner_only(
            &directory.path().join("control-token"),
            b"wrong-control-token-canary",
        );
        let error = probe_with_options(&plan_path, directory.path(), target())
            .await
            .unwrap_err();
        assert_eq!(error, SyntheticSourceError::ProbeFailed);
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("wrong-control-token-canary"));
        assert!(!diagnostic.contains(std::str::from_utf8(CONTROL_CANARY).unwrap()));

        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[test]
    fn counter_probe_rejects_non_exact_or_value_bearing_responses() {
        assert_eq!(
            parse_counter_snapshot(br#"{"token_requests":2,"source_requests":1}"#).unwrap(),
            CounterSnapshot {
                token_requests: 2,
                source_requests: 1
            }
        );
        for body in [
            br#"{"token_requests":2}"#.as_slice(),
            br#"{"token_requests":2,"source_requests":1,"value":"canary"}"#.as_slice(),
            br#"{"token_requests":2,"token_requests":3,"source_requests":1}"#.as_slice(),
            br#"{"token_requests":"2","source_requests":1}"#.as_slice(),
        ] {
            let error = parse_counter_snapshot(body).unwrap_err();
            let diagnostic = format!("{error:?} {error}");
            assert_eq!(error, SyntheticSourceError::ProbeFailed);
            assert!(!diagnostic.contains("canary"));
            assert!(!diagnostic.contains(std::str::from_utf8(body).unwrap()));
        }
    }

    fn pem(label: &str, der: &[u8]) -> String {
        let encoded = STANDARD.encode(der);
        let body = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
    }

    fn write_owner_only(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}
