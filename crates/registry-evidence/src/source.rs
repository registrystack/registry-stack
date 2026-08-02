//! Exact, bounded HTTP/JSON source execution for Evidence Version 1.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, HeaderName, HeaderValue};
use registry_platform_httputil::{read_bounded, BoundedReadError};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::config::{
    AcquisitionPosture, CredentialPlacement, FixedRequest, HttpMethod, OutboundTlsConfig,
    PathBindingConfig, PreparationChannelPolicy, SecretRef, SourceAuthentication, SourceConfig,
    SourceSelectorSet,
};
use crate::model::SelectorValue;
use crate::rhai_runtime::RequestParts;
use crate::secrets::{ProtectedSecret, SecretResolver};

const TOKEN_RESPONSE_MAXIMUM_BYTES: u64 = 8 * 1024;
const PRIVATE_CA_MAXIMUM_BYTES: u64 = 1024 * 1024;
const PROJECTED_RESPONSE_MAXIMUM_BYTES: usize = 65_536;
const JSON_MEDIA_TYPE: &str = "application/json";
const GRAPHQL_JSON_MEDIA_TYPE: &str = "application/graphql-response+json";

/// A role-bound selector that has already passed authentication,
/// authorization, exact-field, type, and size validation.
///
/// This type intentionally has no `Debug` implementation because its values
/// are protected request material.
pub struct ResolvedSourceSelector {
    pub role: String,
    pub profile: String,
    pub values: BTreeMap<String, SelectorValue>,
}

/// A safe status category that does not retain a response or request URL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceStatus {
    Unauthorized,
    Forbidden,
    RateLimited,
    ServerError,
    Other,
}

/// Closed source failures. No variant retains request, response, selector, or
/// credential material.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum SourceError {
    #[error("the fixed source plan is invalid")]
    InvalidPlan,
    #[error("the resolved source selector set is invalid")]
    InvalidSelectors,
    #[error("source credentials are unavailable or invalid")]
    Credential,
    #[error("the source concurrency boundary is unavailable")]
    Concurrency,
    #[error("the source request timed out")]
    Timeout,
    #[error("the source transport is unavailable")]
    Transport,
    #[error("the source attempted a redirect")]
    Redirect,
    #[error("the source returned a rejected status category")]
    Status(SourceStatus),
    #[error("the source returned an unsupported media type")]
    WrongMediaType,
    #[error("the source response exceeded a configured bound")]
    ResponseTooLarge,
    #[error("the source returned invalid JSON")]
    InvalidJson,
    #[error("the source returned an error envelope")]
    ErrorEnvelope,
    #[error("the source response did not satisfy its acquisition projection")]
    ProjectionViolation,
}

/// Executes one immutable source plan. The client has redirects, retries,
/// ambient proxies, pagination, cookies, and caller-controlled headers absent.
pub struct SourceExecutor {
    client: reqwest::Client,
    request: RequestPlan,
    authentication: AuthenticationPlan,
    secrets: Arc<SecretResolver>,
    concurrency: Semaphore,
    concurrency_admission_timeout: Duration,
}

/// The validated non-credential transport material for one fixed source request.
///
/// The full URL remains private so callers cannot obtain source authority, and
/// this type deliberately exposes no fixed headers or authentication material.
/// Path, query, and body access is intended for the trusted offline fixture
/// harness. Its diagnostic representation is always value-free.
#[derive(Clone, PartialEq)]
pub struct MaterializedSourceRequest {
    url: Url,
    body: Option<JsonValue>,
}

impl MaterializedSourceRequest {
    pub fn path(&self) -> &str {
        self.url.path()
    }

    pub fn query(&self) -> Option<&str> {
        self.url.query()
    }

    pub fn body(&self) -> Option<&JsonValue> {
        self.body.as_ref()
    }
}

impl fmt::Debug for MaterializedSourceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedSourceRequest")
            .field("path", &"<redacted>")
            .field("query", &self.query().map(|_| "<redacted>"))
            .field("body", &self.body().map(|_| "<redacted>"))
            .finish()
    }
}

struct RequestPlan {
    base_url: Url,
    path: SourcePath,
    method: HttpMethod,
    fixed_headers: HeaderMap,
    selector_inputs: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    allowed_selector_sets: Vec<SourceSelectorSet>,
    posture: AcquisitionPosture,
    projection: ProjectionNode,
    maximum_response_bytes: u64,
}

enum SourcePath {
    Fixed(String),
    Template {
        template: String,
        bindings: BTreeMap<String, PathBindingPlan>,
    },
}

struct PathBindingPlan {
    role: String,
    profile: String,
    field: String,
}

enum AuthenticationPlan {
    Basic {
        username_ref: SecretRef,
        password_ref: SecretRef,
    },
    StaticBearer {
        token_ref: SecretRef,
    },
    StaticApiKey {
        header_name: HeaderName,
        value_ref: SecretRef,
    },
    Oauth2(Box<OauthPlan>),
}

struct OauthPlan {
    token_endpoint: Url,
    client_id_ref: SecretRef,
    client_secret_ref: SecretRef,
    scope: Option<String>,
    credential_placement: CredentialPlacement,
    maximum_cache_lifetime: Duration,
    admission_timeout: Duration,
    cache: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    token: ProtectedToken,
    expires_at: Instant,
}

struct ProtectedToken(Zeroizing<Vec<u8>>);

impl ProtectedToken {
    fn from_string(value: String) -> Result<Self, SourceError> {
        if value.is_empty() || value.len() > TOKEN_RESPONSE_MAXIMUM_BYTES as usize {
            return Err(SourceError::Credential);
        }
        Ok(Self(Zeroizing::new(value.into_bytes())))
    }

    fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Clone for ProtectedToken {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.0.to_vec()))
    }
}

#[derive(Default)]
struct ProjectionNode {
    terminal: bool,
    keys: BTreeMap<String, ProjectionNode>,
    wildcard: Option<Box<ProjectionNode>>,
}

impl SourceExecutor {
    /// Compile a standalone source with system TLS roots. Sources that name a
    /// private trust profile require `new_with_selector_sets_and_tls`.
    pub fn new(source: &SourceConfig, secrets: Arc<SecretResolver>) -> Result<Self, SourceError> {
        let allowed = conservative_selector_sets(source)?;
        Self::new_with_selector_sets(source, &allowed, secrets)
    }

    /// Compile a source with system TLS roots and explicitly allowed selector
    /// tuples.
    pub fn new_with_selector_sets(
        source: &SourceConfig,
        allowed_selector_sets: &[SourceSelectorSet],
        secrets: Arc<SecretResolver>,
    ) -> Result<Self, SourceError> {
        if source.tls_trust_profile.is_some() {
            return Err(SourceError::InvalidPlan);
        }
        Self::compile(source, allowed_selector_sets, None, secrets)
    }

    /// Compile a source against runtime-owned TLS trust bindings. System roots
    /// remain enabled and the selected private CA bundle is additive.
    pub fn new_with_selector_sets_and_tls(
        source: &SourceConfig,
        allowed_selector_sets: &[SourceSelectorSet],
        outbound_tls: &OutboundTlsConfig,
        captured_ca_bundles: &BTreeMap<String, Vec<u8>>,
        secrets: Arc<SecretResolver>,
    ) -> Result<Self, SourceError> {
        Self::compile(
            source,
            allowed_selector_sets,
            Some((outbound_tls, captured_ca_bundles)),
            secrets,
        )
    }

    fn compile(
        source: &SourceConfig,
        allowed_selector_sets: &[SourceSelectorSet],
        outbound_tls: Option<(&OutboundTlsConfig, &BTreeMap<String, Vec<u8>>)>,
        secrets: Arc<SecretResolver>,
    ) -> Result<Self, SourceError> {
        let timeout = Duration::from_millis(source.request.timeout_milliseconds);
        if timeout.is_zero()
            || source.request.timeout_milliseconds > 30_000
            || source.request.maximum_response_bytes == 0
            || source.request.maximum_response_bytes > 1_048_576
            || source.request.concurrency_limit == 0
            || source.request.concurrency_limit > 256
        {
            return Err(SourceError::InvalidPlan);
        }
        let base_url = validate_url(&source.base_url, true)?;
        let authentication = compile_authentication(&source.authentication, timeout)?;
        let request = compile_request(
            &source.request,
            allowed_selector_sets,
            source.posture,
            base_url,
            &authentication,
        )?;
        let client = build_client(timeout, source, outbound_tls)?;
        Ok(Self {
            client,
            request,
            authentication,
            secrets,
            concurrency: Semaphore::new(usize::from(source.request.concurrency_limit)),
            concurrency_admission_timeout: timeout,
        })
    }

    /// Make exactly one evidence-data request using validated Rhai preparation
    /// output. Path expansion remains Rust-owned and selector-bound.
    pub async fn execute(
        &self,
        selectors: &[ResolvedSourceSelector],
        request_parts: &RequestParts,
    ) -> Result<JsonValue, SourceError> {
        let materialized = self.materialize_request(selectors, request_parts)?;
        let _permit =
            acquire_source_slot(&self.concurrency, self.concurrency_admission_timeout).await?;
        let (authentication_name, authentication_value) = self.authentication_header().await?;
        let method = match self.request.method {
            HttpMethod::GET => reqwest::Method::GET,
            HttpMethod::POST => reqwest::Method::POST,
        };
        let mut request = self
            .client
            .request(method, materialized.url.clone())
            .headers(self.request.fixed_headers.clone())
            .header(authentication_name, authentication_value);
        if !self.request.fixed_headers.contains_key(ACCEPT) {
            request = request.header(ACCEPT, HeaderValue::from_static(JSON_MEDIA_TYPE));
        }
        if let Some(body) = materialized.body() {
            request = request.json(body);
        }
        let response = request.send().await.map_err(map_transport_error)?;
        parse_data_response(
            response,
            self.request.maximum_response_bytes,
            self.request.posture,
            &self.request.projection,
        )
        .await
    }

    /// Validate and materialize only path, encoded query, and JSON body.
    ///
    /// This performs no concurrency admission, credential resolution, or I/O.
    /// The same result is consumed directly by [`Self::execute`].
    pub fn materialize_request(
        &self,
        selectors: &[ResolvedSourceSelector],
        request_parts: &RequestParts,
    ) -> Result<MaterializedSourceRequest, SourceError> {
        if matches!(self.request.method, HttpMethod::GET) && request_parts.body.is_some() {
            return Err(SourceError::InvalidPlan);
        }
        let selectors = self.request.validate_selectors(selectors)?;
        let url = self.request.materialize_url(&selectors, request_parts)?;
        Ok(MaterializedSourceRequest {
            url,
            body: request_parts.body.clone(),
        })
    }

    /// Resolve and validate credentials without making an evidence-data
    /// request. OAuth may perform its bounded token bootstrap.
    pub async fn credentials_ready(&self) -> Result<(), SourceError> {
        self.authentication_header().await.map(|_| ())
    }

    async fn authentication_header(&self) -> Result<(HeaderName, HeaderValue), SourceError> {
        let value = match &self.authentication {
            AuthenticationPlan::Basic {
                username_ref,
                password_ref,
            } => {
                let username = resolve(&self.secrets, username_ref)?;
                let password = resolve(&self.secrets, password_ref)?;
                basic_authorization(&username, &password)?
            }
            AuthenticationPlan::StaticBearer { token_ref } => {
                let token = resolve(&self.secrets, token_ref)?;
                bearer_authorization(token.expose_secret())?
            }
            AuthenticationPlan::StaticApiKey {
                header_name,
                value_ref,
            } => {
                let secret = resolve(&self.secrets, value_ref)?;
                return Ok((
                    header_name.clone(),
                    sensitive_header(secret.expose_secret())?,
                ));
            }
            AuthenticationPlan::Oauth2(plan) => {
                let token = plan.access_token(&self.client, &self.secrets).await?;
                bearer_authorization(token.expose())?
            }
        };
        Ok((AUTHORIZATION, value))
    }
}

/// Apply the exact production response-size, envelope, and projection rules
/// to an already parsed synthetic fixture response.
pub fn project_fixture_response(
    source: &SourceConfig,
    response: &JsonValue,
) -> Result<JsonValue, SourceError> {
    let raw = serde_json::to_vec(response).map_err(|_| SourceError::InvalidJson)?;
    if raw.len()
        > usize::try_from(source.request.maximum_response_bytes)
            .map_err(|_| SourceError::ResponseTooLarge)?
    {
        return Err(SourceError::ResponseTooLarge);
    }
    if response
        .as_object()
        .is_some_and(|object| object.contains_key("errors"))
    {
        return Err(SourceError::ErrorEnvelope);
    }
    let projection = compile_projection(&source.request.projection)?;
    let projected = project_value(response, &projection)?;
    if serde_json::to_vec(&projected)
        .map_err(|_| SourceError::ProjectionViolation)?
        .len()
        > PROJECTED_RESPONSE_MAXIMUM_BYTES
    {
        return Err(SourceError::ResponseTooLarge);
    }
    Ok(projected)
}

fn build_client(
    timeout: Duration,
    source: &SourceConfig,
    outbound_tls: Option<(&OutboundTlsConfig, &BTreeMap<String, Vec<u8>>)>,
) -> Result<reqwest::Client, SourceError> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        // Select rustls explicitly. Cargo unifies reqwest's feature set across
        // the whole workspace, so another workspace member enabling
        // reqwest's native-tls feature must not silently change which TLS
        // backend this client uses.
        .use_rustls_tls()
        // Evidence source execution is exactly one request per plan step; a
        // transport-level retry would duplicate an outbound call the caller
        // did not ask for and is not accounted for in the one-request
        // contract.
        .retry(reqwest::retry::never());
    if let Some(profile_name) = source.tls_trust_profile.as_deref() {
        let (tls, captured_ca_bundles) = outbound_tls.ok_or(SourceError::InvalidPlan)?;
        if !tls.system_roots {
            return Err(SourceError::InvalidPlan);
        }
        let binding = tls
            .trust_profiles
            .get(profile_name)
            .ok_or(SourceError::InvalidPlan)?;
        if binding.ca_bundle_file.is_empty() {
            return Err(SourceError::InvalidPlan);
        }
        let pem = captured_ca_bundles
            .get(profile_name)
            .ok_or(SourceError::InvalidPlan)?;
        if pem.is_empty() || pem.len() as u64 > PRIVATE_CA_MAXIMUM_BYTES {
            return Err(SourceError::InvalidPlan);
        }
        let certificates =
            reqwest::Certificate::from_pem_bundle(pem).map_err(|_| SourceError::InvalidPlan)?;
        if certificates.is_empty() {
            return Err(SourceError::InvalidPlan);
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    builder.build().map_err(|_| SourceError::InvalidPlan)
}

fn conservative_selector_sets(
    source: &SourceConfig,
) -> Result<Vec<SourceSelectorSet>, SourceError> {
    let mut sets = vec![Vec::new()];
    for input in &source.request.selector_inputs {
        if input.alternatives.is_empty() {
            return Err(SourceError::InvalidPlan);
        }
        let mut next = Vec::new();
        for set in &sets {
            for alternative in &input.alternatives {
                let mut candidate = set.clone();
                candidate.push((input.role.clone(), alternative.profile.clone()));
                next.push(candidate);
            }
        }
        sets = next;
    }
    if sets.is_empty() {
        return Err(SourceError::InvalidPlan);
    }
    Ok(sets)
}

fn compile_request(
    request: &FixedRequest,
    allowed_selector_sets: &[SourceSelectorSet],
    posture: AcquisitionPosture,
    base_url: Url,
    authentication: &AuthenticationPlan,
) -> Result<RequestPlan, SourceError> {
    if request.method == HttpMethod::GET
        && request.preparation_limits.json_body != PreparationChannelPolicy::Forbidden
    {
        return Err(SourceError::InvalidPlan);
    }
    let selector_inputs = compile_selector_inputs(request)?;
    let allowed_selector_sets =
        compile_allowed_selector_sets(&selector_inputs, allowed_selector_sets)?;
    let path = compile_source_path(request, &selector_inputs)?;
    let fixed_headers = compile_fixed_headers(request, authentication)?;
    let projection = compile_projection(&request.projection)?;
    Ok(RequestPlan {
        base_url,
        path,
        method: request.method,
        fixed_headers,
        selector_inputs,
        allowed_selector_sets,
        posture,
        projection,
        maximum_response_bytes: request.maximum_response_bytes,
    })
}

async fn acquire_source_slot<'a>(
    semaphore: &'a Semaphore,
    timeout: Duration,
) -> Result<tokio::sync::SemaphorePermit<'a>, SourceError> {
    tokio::time::timeout(timeout, semaphore.acquire())
        .await
        .map_err(|_| SourceError::Timeout)?
        .map_err(|_| SourceError::Concurrency)
}

fn compile_selector_inputs(
    request: &FixedRequest,
) -> Result<BTreeMap<String, BTreeMap<String, BTreeSet<String>>>, SourceError> {
    let mut output = BTreeMap::new();
    for input in &request.selector_inputs {
        let profiles = output
            .entry(input.role.clone())
            .or_insert_with(BTreeMap::new);
        for alternative in &input.alternatives {
            let fields = alternative.fields.iter().cloned().collect::<BTreeSet<_>>();
            if fields.len() != alternative.fields.len()
                || profiles
                    .insert(alternative.profile.clone(), fields)
                    .is_some()
            {
                return Err(SourceError::InvalidPlan);
            }
        }
        if profiles.is_empty() {
            return Err(SourceError::InvalidPlan);
        }
    }
    if output.is_empty() {
        return Err(SourceError::InvalidPlan);
    }
    Ok(output)
}

fn compile_allowed_selector_sets(
    inputs: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    configured: &[SourceSelectorSet],
) -> Result<Vec<SourceSelectorSet>, SourceError> {
    let mut unique = BTreeSet::new();
    for configured_set in configured {
        if configured_set.is_empty() || configured_set.len() > inputs.len() {
            return Err(SourceError::InvalidPlan);
        }
        let mut set = configured_set.clone();
        set.sort();
        let mut roles = BTreeSet::new();
        for (role, profile) in &set {
            if !roles.insert(role)
                || !inputs
                    .get(role)
                    .is_some_and(|profiles| profiles.contains_key(profile))
            {
                return Err(SourceError::InvalidPlan);
            }
        }
        if !unique.insert(set) {
            return Err(SourceError::InvalidPlan);
        }
    }
    if unique.is_empty() {
        return Err(SourceError::InvalidPlan);
    }
    Ok(unique.into_iter().collect())
}

fn compile_source_path(
    request: &FixedRequest,
    inputs: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
) -> Result<SourcePath, SourceError> {
    match (&request.path, &request.path_template) {
        (Some(path), None) if request.path_bindings.is_empty() => {
            validate_request_path(path)?;
            Ok(SourcePath::Fixed(path.clone()))
        }
        (None, Some(template)) => {
            validate_template_shape(template, &request.path_bindings)?;
            let mut bindings = BTreeMap::new();
            for (name, binding) in request.path_bindings.iter() {
                validate_path_binding(binding, inputs)?;
                bindings.insert(
                    name.to_owned(),
                    PathBindingPlan {
                        role: binding.role.clone(),
                        profile: binding.profile.clone(),
                        field: binding.field.clone(),
                    },
                );
            }
            Ok(SourcePath::Template {
                template: template.clone(),
                bindings,
            })
        }
        _ => Err(SourceError::InvalidPlan),
    }
}

fn validate_path_binding(
    binding: &PathBindingConfig,
    inputs: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
) -> Result<(), SourceError> {
    if inputs
        .get(&binding.role)
        .and_then(|profiles| profiles.get(&binding.profile))
        .is_some_and(|fields| fields.contains(&binding.field))
    {
        Ok(())
    } else {
        Err(SourceError::InvalidPlan)
    }
}

fn validate_template_shape(
    template: &str,
    bindings: &crate::config::OrderedMap<PathBindingConfig>,
) -> Result<(), SourceError> {
    if !template.starts_with('/')
        || template.starts_with("//")
        || template.contains(['?', '#', '\\'])
    {
        return Err(SourceError::InvalidPlan);
    }
    let mut names = BTreeSet::new();
    for segment in template.split('/').skip(1) {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return Err(SourceError::InvalidPlan);
        }
        if let Some(name) = segment
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
        {
            if name.is_empty() || !names.insert(name) {
                return Err(SourceError::InvalidPlan);
            }
        } else if segment.contains(['{', '}']) {
            return Err(SourceError::InvalidPlan);
        }
    }
    if names == bindings.keys().collect::<BTreeSet<_>>() {
        Ok(())
    } else {
        Err(SourceError::InvalidPlan)
    }
}

fn compile_fixed_headers(
    request: &FixedRequest,
    authentication: &AuthenticationPlan,
) -> Result<HeaderMap, SourceError> {
    let mut headers = HeaderMap::new();
    for fixed in &request.fixed_headers {
        if reserved_configured_header(&fixed.name) {
            return Err(SourceError::InvalidPlan);
        }
        let name =
            HeaderName::from_bytes(fixed.name.as_bytes()).map_err(|_| SourceError::InvalidPlan)?;
        let value = HeaderValue::from_str(&fixed.value).map_err(|_| SourceError::InvalidPlan)?;
        if headers.insert(name, value).is_some() {
            return Err(SourceError::InvalidPlan);
        }
    }
    let authentication_name = match authentication {
        AuthenticationPlan::StaticApiKey { header_name, .. } => header_name,
        _ => &AUTHORIZATION,
    };
    if headers.contains_key(authentication_name) {
        return Err(SourceError::InvalidPlan);
    }
    Ok(headers)
}

/// Reject a bundle-configured header name before any credential is resolved.
///
/// Startup configuration validation already rejects these names. This is the
/// defensive second check on the request path, and it deliberately calls the
/// one shared closed classifier so the two deny sets cannot drift apart.
fn reserved_configured_header(name: &str) -> bool {
    crate::config::is_reserved_header_name(name)
}

fn compile_authentication(
    authentication: &SourceAuthentication,
    admission_timeout: Duration,
) -> Result<AuthenticationPlan, SourceError> {
    match authentication {
        SourceAuthentication::Basic {
            username_ref,
            password_ref,
        } => Ok(AuthenticationPlan::Basic {
            username_ref: username_ref.clone(),
            password_ref: password_ref.clone(),
        }),
        SourceAuthentication::StaticBearer { token_ref } => Ok(AuthenticationPlan::StaticBearer {
            token_ref: token_ref.clone(),
        }),
        SourceAuthentication::StaticApiKey {
            header_name,
            value_ref,
        } => {
            if reserved_configured_header(header_name) {
                return Err(SourceError::InvalidPlan);
            }
            Ok(AuthenticationPlan::StaticApiKey {
                header_name: HeaderName::from_bytes(header_name.as_bytes())
                    .map_err(|_| SourceError::InvalidPlan)?,
                value_ref: value_ref.clone(),
            })
        }
        SourceAuthentication::Oauth2ClientCredentials {
            token_endpoint,
            client_id_ref,
            client_secret_ref,
            scope,
            credential_placement,
            maximum_cache_seconds,
        } => {
            let token_endpoint = validate_url(token_endpoint, false)?;
            if token_endpoint.query().is_some() {
                return Err(SourceError::InvalidPlan);
            }
            Ok(AuthenticationPlan::Oauth2(Box::new(OauthPlan {
                token_endpoint,
                client_id_ref: client_id_ref.clone(),
                client_secret_ref: client_secret_ref.clone(),
                scope: scope.clone(),
                credential_placement: *credential_placement,
                maximum_cache_lifetime: Duration::from_secs(*maximum_cache_seconds),
                admission_timeout,
                cache: Mutex::new(None),
            })))
        }
    }
}

impl RequestPlan {
    fn validate_selectors<'a>(
        &self,
        selectors: &'a [ResolvedSourceSelector],
    ) -> Result<BTreeMap<(&'a str, &'a str), &'a ResolvedSourceSelector>, SourceError> {
        let mut index = BTreeMap::new();
        let mut active = Vec::new();
        let mut roles = BTreeSet::new();
        for selector in selectors {
            if !roles.insert(selector.role.as_str())
                || index
                    .insert(
                        (selector.role.as_str(), selector.profile.as_str()),
                        selector,
                    )
                    .is_some()
            {
                return Err(SourceError::InvalidSelectors);
            }
            let fields = self
                .selector_inputs
                .get(&selector.role)
                .and_then(|profiles| profiles.get(&selector.profile))
                .ok_or(SourceError::InvalidSelectors)?;
            if selector.values.keys().collect::<BTreeSet<_>>()
                != fields.iter().collect::<BTreeSet<_>>()
            {
                return Err(SourceError::InvalidSelectors);
            }
            active.push((selector.role.clone(), selector.profile.clone()));
        }
        active.sort();
        if !self.allowed_selector_sets.contains(&active) {
            return Err(SourceError::InvalidSelectors);
        }
        Ok(index)
    }

    fn materialize_url(
        &self,
        selectors: &BTreeMap<(&str, &str), &ResolvedSourceSelector>,
        parts: &RequestParts,
    ) -> Result<Url, SourceError> {
        let path = match &self.path {
            SourcePath::Fixed(path) => path.clone(),
            SourcePath::Template { template, bindings } => {
                let mut rendered = String::new();
                for segment in template.split('/').skip(1) {
                    rendered.push('/');
                    if let Some(name) = segment
                        .strip_prefix('{')
                        .and_then(|value| value.strip_suffix('}'))
                    {
                        let binding = bindings.get(name).ok_or(SourceError::InvalidPlan)?;
                        let selector = selectors
                            .get(&(binding.role.as_str(), binding.profile.as_str()))
                            .ok_or(SourceError::InvalidSelectors)?;
                        let value = selector
                            .values
                            .get(&binding.field)
                            .ok_or(SourceError::InvalidSelectors)?;
                        rendered.push_str(&encode_path_selector(value)?);
                    } else {
                        rendered.push_str(segment);
                    }
                }
                rendered
            }
        };
        let mut url = join_source_path(&self.base_url, &path)?;
        if !parts.query.is_empty() {
            let mut query = String::new();
            for pair in &parts.query {
                if pair.name.is_empty()
                    || pair.name.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
                    || pair.value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
                {
                    return Err(SourceError::InvalidPlan);
                }
                if !query.is_empty() {
                    query.push('&');
                }
                encode_query_component(&pair.name, &mut query);
                query.push('=');
                encode_query_component(&pair.value, &mut query);
            }
            url.set_query(Some(&query));
        }
        Ok(url)
    }
}

fn encode_query_component(value: &str, output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

fn encode_path_selector(value: &SelectorValue) -> Result<String, SourceError> {
    let text = match value {
        SelectorValue::String(value) => value.clone(),
        SelectorValue::Integer(value) => value.to_string(),
        SelectorValue::Boolean(value) => value.to_string(),
    };
    if text.is_empty()
        || matches!(text.as_str(), "." | "..")
        || text.chars().any(char::is_control)
        || text.contains(['/', '\\', '%'])
    {
        return Err(SourceError::InvalidSelectors);
    }
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").map_err(|_| SourceError::InvalidSelectors)?;
        }
    }
    Ok(encoded)
}

impl OauthPlan {
    async fn access_token(
        &self,
        client: &reqwest::Client,
        secrets: &SecretResolver,
    ) -> Result<ProtectedToken, SourceError> {
        let mut cache = tokio::time::timeout(self.admission_timeout, self.cache.lock())
            .await
            .map_err(|_| SourceError::Timeout)?;
        let now = Instant::now();
        if let Some(cached) = cache.as_ref() {
            if cached.expires_at > now {
                return Ok(cached.token.clone());
            }
        }
        *cache = None;
        let client_id = resolve(secrets, &self.client_id_ref)?;
        let client_secret = resolve(secrets, &self.client_secret_ref)?;
        let client_id_text = protected_text(&client_id)?;
        let client_secret_text = protected_text(&client_secret)?;
        let mut endpoint = self.token_endpoint.clone();
        let mut form = vec![("grant_type", "client_credentials")];
        if let Some(scope) = self.scope.as_deref() {
            form.push(("scope", scope));
        }
        let mut request = client
            .post(endpoint.clone())
            .header(ACCEPT, JSON_MEDIA_TYPE);
        let send_form = match self.credential_placement {
            CredentialPlacement::BasicHeader => {
                request = request.header(
                    AUTHORIZATION,
                    basic_authorization(&client_id, &client_secret)?,
                );
                true
            }
            CredentialPlacement::FormBody => {
                form.push(("client_id", client_id_text));
                form.push(("client_secret", client_secret_text));
                true
            }
            CredentialPlacement::QueryString => {
                {
                    let mut pairs = endpoint.query_pairs_mut();
                    for (key, value) in &form {
                        pairs.append_pair(key, value);
                    }
                    pairs.append_pair("client_id", client_id_text);
                    pairs.append_pair("client_secret", client_secret_text);
                }
                request = client.post(endpoint).header(ACCEPT, JSON_MEDIA_TYPE);
                false
            }
        };
        if send_form {
            request = request.form(&form);
        }
        drop(form);
        drop(client_id);
        drop(client_secret);
        let response = request.send().await.map_err(map_transport_error)?;
        let (token, provider_lifetime) =
            parse_token_response(response, self.scope.as_deref()).await?;
        let cache_lifetime = provider_lifetime.min(self.maximum_cache_lifetime);
        if !cache_lifetime.is_zero() {
            let expires_at = Instant::now()
                .checked_add(cache_lifetime)
                .ok_or(SourceError::Credential)?;
            *cache = Some(CachedToken {
                token: token.clone(),
                expires_at,
            });
        }
        Ok(token)
    }
}

fn compile_projection(paths: &[String]) -> Result<ProjectionNode, SourceError> {
    if paths.is_empty() {
        return Err(SourceError::InvalidPlan);
    }
    let mut root = ProjectionNode::default();
    for path in paths {
        let segments = parse_projection_pointer(path)?;
        let mut node = &mut root;
        for segment in segments {
            if node.terminal {
                return Err(SourceError::InvalidPlan);
            }
            match segment {
                ProjectionSegment::Key(key) => {
                    if node.wildcard.is_some() {
                        return Err(SourceError::InvalidPlan);
                    }
                    node = node.keys.entry(key).or_default();
                }
                ProjectionSegment::Wildcard => {
                    if !node.keys.is_empty() {
                        return Err(SourceError::InvalidPlan);
                    }
                    node = node
                        .wildcard
                        .get_or_insert_with(|| Box::new(ProjectionNode::default()));
                }
            }
        }
        if node.terminal || !node.keys.is_empty() || node.wildcard.is_some() {
            return Err(SourceError::InvalidPlan);
        }
        node.terminal = true;
    }
    Ok(root)
}

enum ProjectionSegment {
    Key(String),
    Wildcard,
}

fn parse_projection_pointer(pointer: &str) -> Result<Vec<ProjectionSegment>, SourceError> {
    if !pointer.starts_with('/')
        || pointer.starts_with("//")
        || pointer.chars().any(char::is_control)
    {
        return Err(SourceError::InvalidPlan);
    }
    pointer[1..]
        .split('/')
        .map(|raw| {
            if raw.is_empty() {
                return Err(SourceError::InvalidPlan);
            }
            if raw == "*" {
                return Ok(ProjectionSegment::Wildcard);
            }
            let mut decoded = String::with_capacity(raw.len());
            let mut chars = raw.chars();
            while let Some(character) = chars.next() {
                if character == '~' {
                    match chars.next() {
                        Some('0') => decoded.push('~'),
                        Some('1') => decoded.push('/'),
                        _ => return Err(SourceError::InvalidPlan),
                    }
                } else {
                    decoded.push(character);
                }
            }
            if decoded.is_empty() || decoded.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(SourceError::InvalidPlan);
            }
            Ok(ProjectionSegment::Key(decoded))
        })
        .collect()
}

fn project_value(value: &JsonValue, node: &ProjectionNode) -> Result<JsonValue, SourceError> {
    if node.terminal {
        return Ok(value.clone());
    }
    if let Some(wildcard) = &node.wildcard {
        let array = value.as_array().ok_or(SourceError::ProjectionViolation)?;
        return array
            .iter()
            .map(|item| project_value(item, wildcard))
            .collect::<Result<Vec<_>, _>>()
            .map(JsonValue::Array);
    }
    let object = value.as_object().ok_or(SourceError::ProjectionViolation)?;
    let mut projected = JsonMap::new();
    for (key, child) in &node.keys {
        match object.get(key) {
            Some(value) => {
                projected.insert(key.clone(), project_value(value, child)?);
            }
            None if child.terminal => {}
            None => return Err(SourceError::ProjectionViolation),
        }
    }
    Ok(JsonValue::Object(projected))
}

fn resolve(
    resolver: &SecretResolver,
    reference: &SecretRef,
) -> Result<ProtectedSecret, SourceError> {
    resolver
        .resolve(reference.as_str())
        .map_err(|_| SourceError::Credential)
}

fn protected_text(secret: &ProtectedSecret) -> Result<&str, SourceError> {
    std::str::from_utf8(secret.expose_secret()).map_err(|_| SourceError::Credential)
}

fn basic_authorization(
    username: &ProtectedSecret,
    password: &ProtectedSecret,
) -> Result<HeaderValue, SourceError> {
    if username.is_empty() || password.is_empty() || username.expose_secret().contains(&b':') {
        return Err(SourceError::Credential);
    }
    let mut joined = Zeroizing::new(Vec::with_capacity(username.len() + password.len() + 1));
    joined.extend_from_slice(username.expose_secret());
    joined.push(b':');
    joined.extend_from_slice(password.expose_secret());
    let encoded =
        Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(joined.as_slice()));
    let mut header = Zeroizing::new(Vec::with_capacity(6 + encoded.len()));
    header.extend_from_slice(b"Basic ");
    header.extend_from_slice(encoded.as_bytes());
    sensitive_header(&header)
}

fn bearer_authorization(token: &[u8]) -> Result<HeaderValue, SourceError> {
    if token.is_empty() {
        return Err(SourceError::Credential);
    }
    let mut header = Zeroizing::new(Vec::with_capacity(7 + token.len()));
    header.extend_from_slice(b"Bearer ");
    header.extend_from_slice(token);
    sensitive_header(&header)
}

fn sensitive_header(bytes: &[u8]) -> Result<HeaderValue, SourceError> {
    let mut value = HeaderValue::from_bytes(bytes).map_err(|_| SourceError::Credential)?;
    value.set_sensitive(true);
    Ok(value)
}

async fn parse_data_response(
    response: reqwest::Response,
    maximum_bytes: u64,
    _posture: AcquisitionPosture,
    projection: &ProjectionNode,
) -> Result<JsonValue, SourceError> {
    reject_response_status(&response)?;
    let media_type = response_media_type(&response)?;
    if media_type != JSON_MEDIA_TYPE && media_type != GRAPHQL_JSON_MEDIA_TYPE {
        return Err(SourceError::WrongMediaType);
    }
    let bytes = Zeroizing::new(
        read_bounded(response, maximum_bytes)
            .await
            .map_err(map_bounded_read_error)?,
    );
    let value = parse_strict_json(&bytes)?;
    drop(bytes);
    if value
        .as_object()
        .is_some_and(|object| object.contains_key("errors"))
    {
        return Err(SourceError::ErrorEnvelope);
    }
    let projected = project_value(&value, projection)?;
    if serde_json::to_vec(&projected)
        .map_err(|_| SourceError::ProjectionViolation)?
        .len()
        > PROJECTED_RESPONSE_MAXIMUM_BYTES
    {
        return Err(SourceError::ResponseTooLarge);
    }
    Ok(projected)
}

async fn parse_token_response(
    response: reqwest::Response,
    expected_scope: Option<&str>,
) -> Result<(ProtectedToken, Duration), SourceError> {
    // `reject_response_status` classifies only redirect/status outcomes, never a
    // timeout, so every rejection here is a credential-exchange failure.
    reject_response_status(&response).map_err(|_| SourceError::Credential)?;
    if response_media_type(&response).map_err(|_| SourceError::Credential)? != JSON_MEDIA_TYPE {
        return Err(SourceError::Credential);
    }
    let bytes = Zeroizing::new(
        read_bounded(response, TOKEN_RESPONSE_MAXIMUM_BYTES)
            .await
            .map_err(|_| SourceError::Credential)?,
    );
    let mut object = parse_strict_json(&bytes)
        .map_err(|_| SourceError::Credential)?
        .as_object()
        .cloned()
        .ok_or(SourceError::Credential)?;
    drop(bytes);
    let access_token = match object.remove("access_token") {
        Some(JsonValue::String(value)) => value,
        _ => return Err(SourceError::Credential),
    };
    let token_type = match object.remove("token_type") {
        Some(JsonValue::String(value)) => value,
        _ => return Err(SourceError::Credential),
    };
    if !token_type.eq_ignore_ascii_case("bearer") {
        return Err(SourceError::Credential);
    }
    let expires_in = match object.remove("expires_in") {
        Some(JsonValue::Number(value)) => value.as_u64().filter(|value| *value > 0),
        _ => None,
    }
    .ok_or(SourceError::Credential)?;
    if let Some(scope) = object.remove("scope") {
        let JsonValue::String(scope) = scope else {
            return Err(SourceError::Credential);
        };
        if scope.is_empty()
            || scope.len() > 512
            || expected_scope.is_some_and(|expected| scope != expected)
        {
            return Err(SourceError::Credential);
        }
    }
    if !object.is_empty() {
        return Err(SourceError::Credential);
    }
    Ok((
        ProtectedToken::from_string(access_token)?,
        Duration::from_secs(expires_in),
    ))
}

fn reject_response_status(response: &reqwest::Response) -> Result<(), SourceError> {
    let status = response.status();
    if status.is_redirection() {
        return Err(SourceError::Redirect);
    }
    if status.is_success() {
        return Ok(());
    }
    Err(SourceError::Status(match status.as_u16() {
        401 => SourceStatus::Unauthorized,
        403 => SourceStatus::Forbidden,
        429 => SourceStatus::RateLimited,
        500..=599 => SourceStatus::ServerError,
        _ => SourceStatus::Other,
    }))
}

fn response_media_type(response: &reqwest::Response) -> Result<&str, SourceError> {
    let mut values = response.headers().get_all(CONTENT_TYPE).iter();
    let value = values.next().ok_or(SourceError::WrongMediaType)?;
    if values.next().is_some() {
        return Err(SourceError::WrongMediaType);
    }
    let value = value.to_str().map_err(|_| SourceError::WrongMediaType)?;
    let media_type = value.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case(JSON_MEDIA_TYPE) {
        Ok(JSON_MEDIA_TYPE)
    } else if media_type.eq_ignore_ascii_case(GRAPHQL_JSON_MEDIA_TYPE) {
        Ok(GRAPHQL_JSON_MEDIA_TYPE)
    } else {
        Ok(media_type)
    }
}

fn map_transport_error(error: reqwest::Error) -> SourceError {
    if error.is_timeout() {
        SourceError::Timeout
    } else {
        SourceError::Transport
    }
}

fn map_bounded_read_error(error: BoundedReadError) -> SourceError {
    match error {
        BoundedReadError::Transport(error) => map_transport_error(error),
        BoundedReadError::ContentLengthExceeded { .. }
        | BoundedReadError::BodyTooLarge { .. }
        | BoundedReadError::LengthOverflow => SourceError::ResponseTooLarge,
        _ => SourceError::Transport,
    }
}

fn validate_url(value: &str, origin_only: bool) -> Result<Url, SourceError> {
    let url = Url::parse(value).map_err(|_| SourceError::InvalidPlan)?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(SourceError::InvalidPlan);
    }
    if origin_only && (url.path() != "/" || url.query().is_some()) {
        return Err(SourceError::InvalidPlan);
    }
    match url.scheme() {
        "https" if url.host().is_some() => {}
        "http" => match url.host() {
            Some(Host::Ipv4(ip)) if ip.is_loopback() => {}
            Some(Host::Ipv6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST => {}
            _ => return Err(SourceError::InvalidPlan),
        },
        _ => return Err(SourceError::InvalidPlan),
    }
    Ok(url)
}

fn validate_request_path(path: &str) -> Result<(), SourceError> {
    if path.len() < 2
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['?', '#', '\\'])
        || path
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(SourceError::InvalidPlan);
    }
    Ok(())
}

fn join_source_path(base: &Url, path: &str) -> Result<Url, SourceError> {
    validate_request_path(path)?;
    let value = format!("{}{}", base.as_str().trim_end_matches('/'), path);
    let url = Url::parse(&value).map_err(|_| SourceError::InvalidPlan)?;
    if url.scheme() != base.scheme()
        || url.host() != base.host()
        || url.port_or_known_default() != base.port_or_known_default()
    {
        return Err(SourceError::InvalidPlan);
    }
    Ok(url)
}

struct StrictJson(JsonValue);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a duplicate-free JSON value")
    }
    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson(JsonValue::Bool(value)))
    }
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJson(JsonValue::Number(value.into())))
    }
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson(JsonValue::Number(value.into())))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        JsonNumber::from_f64(value)
            .map(JsonValue::Number)
            .map(StrictJson)
            .ok_or_else(|| de::Error::custom("invalid JSON number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.visit_string(value.to_owned())
    }
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJson(JsonValue::String(value)))
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(JsonValue::Null))
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(JsonValue::Null))
    }
    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        StrictJson::deserialize(deserializer)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element::<StrictJson>()? {
            values.push(value.0);
        }
        Ok(StrictJson(JsonValue::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut mapping: A) -> Result<Self::Value, A::Error> {
        let mut object = JsonMap::new();
        while let Some((key, value)) = mapping.next_entry::<String, StrictJson>()? {
            if object.insert(key, value.0).is_some() {
                return Err(de::Error::custom("duplicate JSON object member"));
            }
        }
        Ok(StrictJson(JsonValue::Object(object)))
    }
}

fn parse_strict_json(bytes: &[u8]) -> Result<JsonValue, SourceError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJson::deserialize(&mut deserializer).map_err(|_| SourceError::InvalidJson)?;
    deserializer.end().map_err(|_| SourceError::InvalidJson)?;
    Ok(value.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn projection_supports_nested_arrays_escapes_and_literal_dots() {
        let plan = compile_projection(&[
            "/total".into(),
            "/results/*/declaration/mother.personReference".into(),
            "/results/*/a~1b/~0value".into(),
        ])
        .expect("projection compiles");
        let input = json!({
            "total": 1,
            "ignored": "gone",
            "results": [{
                "declaration": {"mother.personReference": "P-1", "private": "gone"},
                "a/b": {"~value": true, "ignored": false}
            }]
        });
        assert_eq!(
            project_value(&input, &plan),
            Ok(json!({
                "total": 1,
                "results": [{
                    "declaration": {"mother.personReference": "P-1"},
                    "a/b": {"~value": true}
                }]
            }))
        );
    }

    #[test]
    fn projection_omits_missing_leaves_but_rejects_missing_or_mistyped_intermediates() {
        let plan =
            compile_projection(&["/results/*/optional".into()]).expect("projection compiles");
        assert_eq!(
            project_value(&json!({"results": [{}]}), &plan),
            Ok(json!({"results": [{}]}))
        );
        assert_eq!(
            project_value(&json!({}), &plan),
            Err(SourceError::ProjectionViolation)
        );
        assert_eq!(
            project_value(&json!({"results": {}}), &plan),
            Err(SourceError::ProjectionViolation)
        );
    }

    #[test]
    fn projection_rejects_duplicates_conflicts_indexes_and_mixed_container_shapes() {
        for paths in [
            vec!["/a".into(), "/a".into()],
            vec!["/a".into(), "/a/b".into()],
            vec!["/a/0".into()],
            vec!["/a/*/x".into(), "/a/b".into()],
        ] {
            assert!(compile_projection(&paths).is_err());
        }
    }

    #[test]
    fn path_selector_encoding_is_single_pass_and_hostile_values_fail_closed() {
        assert_eq!(
            encode_path_selector(&SelectorValue::String("A B".into())),
            Ok("A%20B".into())
        );
        for value in [".", "..", "a/b", "a\\b", "a%2Fb", "a\nb"] {
            assert_eq!(
                encode_path_selector(&SelectorValue::String(value.into())),
                Err(SourceError::InvalidSelectors)
            );
        }
    }

    #[test]
    fn duplicate_json_members_are_rejected() {
        assert_eq!(
            parse_strict_json(br#"{"a":1,"a":2}"#),
            Err(SourceError::InvalidJson)
        );
    }

    #[tokio::test]
    async fn saturated_source_admission_fails_at_the_configured_timeout() {
        let server = wiremock::MockServer::start().await;
        let source: SourceConfig = serde_json::from_value(json!({
            "transport": "http-json",
            "baseUrl": server.uri(),
            "posture": "source-derived",
            "authentication": {
                "kind": "static-bearer",
                "tokenRef": "secret:file/missing-source-token"
            },
            "request": {
                "method": "POST",
                "path": "/data",
                "fixedHeaders": [],
                "selectorInputs": [{
                    "role": "subject",
                    "alternatives": [{"profile": "record-v1", "fields": ["record_id"]}]
                }],
                "prepareScript": "adapters/prepare.rhai",
                "adapterParameters": {},
                "adapterParametersSchema": "schemas/parameters.schema.yaml",
                "preparationLimits": {
                    "query": "forbidden",
                    "jsonBody": "required",
                    "maximumJsonDepth": 4,
                    "maximumCollectionItems": 4,
                    "maximumStringBytes": 64,
                    "maximumNormalizedBytes": 1024
                },
                "projection": ["/ok"],
                "redirects": "deny",
                "timeoutMilliseconds": 20,
                "maximumResponseBytes": 1024,
                "concurrencyLimit": 1
            },
            "extractScript": "adapters/extract.rhai",
            "factSchema": "schemas/facts.schema.yaml"
        }))
        .expect("source config deserializes");
        let secret_root = tempfile::tempdir().expect("temporary secret root");
        let secrets = Arc::new(
            SecretResolver::new([crate::secrets::SecretProvider::File], secret_root.path())
                .expect("secret resolver builds"),
        );
        let executor = SourceExecutor::new(&source, secrets).expect("source executor builds");
        let _occupied = executor
            .concurrency
            .acquire()
            .await
            .expect("source slot is available");
        let selectors = [ResolvedSourceSelector {
            role: "subject".into(),
            profile: "record-v1".into(),
            values: BTreeMap::from([(
                "record_id".into(),
                SelectorValue::String("synthetic-record".into()),
            )]),
        }];
        let started = Instant::now();
        assert!(matches!(
            executor
                .execute(
                    &selectors,
                    &RequestParts {
                        query: Vec::new(),
                        body: Some(json!({"requested": true})),
                    },
                )
                .await,
            Err(SourceError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty());
    }

    /// Spins up a TLS server whose certificate is signed by a private
    /// certificate authority that the client under test is never told to
    /// trust. The resulting handshake failure is specific to whichever TLS
    /// backend the client actually uses, which makes it a proof that the
    /// backend selected in `build_client` is the one in effect at runtime.
    async fn spawn_untrusted_tls_server(
        server_subject_alt_name: &str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let mut ca_parameters = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("private CA parameters are valid");
        ca_parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("private CA key generates");
        let ca_certificate = ca_parameters
            .self_signed(&ca_key)
            .expect("private CA certificate generates");

        let server_parameters =
            rcgen::CertificateParams::new(vec![server_subject_alt_name.to_owned()])
                .expect("server certificate parameters are valid");
        let server_key = rcgen::KeyPair::generate().expect("server key generates");
        let server_certificate = server_parameters
            .signed_by(&server_key, &ca_certificate, &ca_key)
            .expect("private CA signs server certificate");
        let private_key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
            tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
        );
        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_certificate.der().clone()], private_key)
            .expect("TLS server configuration builds");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("TLS test server binds");
        let address = listener.local_addr().expect("TLS server address");
        let handle = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            // The client is expected to abort the handshake once it
            // evaluates the certificate chain, so no request or response
            // handling is needed here.
            let _ = acceptor.accept(stream).await;
        });
        (address, handle)
    }

    #[tokio::test]
    async fn evidence_client_uses_rustls_and_fails_closed_on_an_unrecognized_certificate_authority()
    {
        let (address, _server) = spawn_untrusted_tls_server("127.0.0.1").await;
        let source: SourceConfig = serde_json::from_value(json!({
            "transport": "http-json",
            "baseUrl": format!("https://{address}"),
            "posture": "source-derived",
            "authentication": {
                "kind": "static-bearer",
                "tokenRef": "secret:file/missing-source-token"
            },
            "request": {
                "method": "POST",
                "path": "/data",
                "fixedHeaders": [],
                "selectorInputs": [{
                    "role": "subject",
                    "alternatives": [{"profile": "record-v1", "fields": ["record_id"]}]
                }],
                "prepareScript": "adapters/prepare.rhai",
                "adapterParameters": {},
                "adapterParametersSchema": "schemas/parameters.schema.yaml",
                "preparationLimits": {
                    "query": "forbidden",
                    "jsonBody": "required",
                    "maximumJsonDepth": 4,
                    "maximumCollectionItems": 4,
                    "maximumStringBytes": 64,
                    "maximumNormalizedBytes": 1024
                },
                "projection": ["/ok"],
                "redirects": "deny",
                "timeoutMilliseconds": 2000,
                "maximumResponseBytes": 1024,
                "concurrencyLimit": 1
            },
            "extractScript": "adapters/extract.rhai",
            "factSchema": "schemas/facts.schema.yaml"
        }))
        .expect("source config deserializes");
        let client = build_client(Duration::from_secs(5), &source, None).expect("client builds");
        let error = client
            .get(format!("https://{address}/"))
            .send()
            .await
            .expect_err("an unrecognized certificate authority is rejected");
        let mut messages = Vec::new();
        let mut current: &dyn std::error::Error = &error;
        while let Some(source) = current.source() {
            messages.push(source.to_string());
            current = source;
        }
        assert!(
            messages
                .iter()
                .any(|message| message.contains("invalid peer certificate")),
            "expected a rustls certificate-validation error in the source chain, got: {messages:?}"
        );
    }

    #[tokio::test]
    async fn saturated_oauth_single_flight_fails_before_credentials_or_transport() {
        let secret_root = tempfile::tempdir().expect("temporary secret root");
        let secrets =
            SecretResolver::new([crate::secrets::SecretProvider::File], secret_root.path())
                .expect("secret resolver builds");
        let plan = OauthPlan {
            token_endpoint: Url::parse("http://127.0.0.1:1/token")
                .expect("synthetic endpoint parses"),
            client_id_ref: SecretRef::parse("secret:file/missing-client-id")
                .expect("secret reference parses"),
            client_secret_ref: SecretRef::parse("secret:file/missing-client-secret")
                .expect("secret reference parses"),
            scope: Some("fixture.read".into()),
            credential_placement: CredentialPlacement::QueryString,
            maximum_cache_lifetime: Duration::from_secs(60),
            admission_timeout: Duration::from_millis(20),
            cache: Mutex::new(None),
        };
        let _occupied = plan.cache.lock().await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("HTTP client builds");
        let started = Instant::now();
        let result =
            tokio::time::timeout(Duration::from_secs(1), plan.access_token(&client, &secrets))
                .await
                .expect("OAuth admission is bounded by its configured timeout");
        assert!(matches!(result, Err(SourceError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
