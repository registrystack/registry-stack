//! Exact, bounded source execution for Evidence Version 1, over an HTTP/JSON
//! request or a reviewed statement against a SQLite extract.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use chrono::{DateTime, Utc};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, HeaderName, HeaderValue};
use registry_platform_authcommon::client_assertion::{
    sign_client_assertion, ClientAssertionRequest, DEFAULT_ASSERTION_LIFETIME_SECONDS,
};
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::{read_bounded, BoundedReadError};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

use crate::bundle::{ArtifactFault, Bundle, SourceExtract};
use crate::config::{
    is_http_token_byte, is_uri_byte, validate_local_unauthenticated_source_origin,
    AcquisitionPosture, CredentialPlacement, FixedRequest, HttpMethod, OutboundTlsConfig,
    PathBindingConfig, PreparationChannelPolicy, SchemaFault, SecretRef, SelectorInput,
    SourceAuthentication, SourceConfig, SourceSelectorSet, SqliteParameterBinding, SqliteRequest,
    RESERVED_SQL_PARAMETER,
};
use crate::model::SelectorValue;
use crate::rhai_runtime::{RequestParts, StatementParameters};
use crate::secrets::{ProtectedSecret, SecretResolver};
use crate::source_sqlite::{
    cause, check_statement_offline, SqliteExtractSource, SqliteSourceError,
};

const TOKEN_RESPONSE_MAXIMUM_BYTES: u64 = 8 * 1024;
const PRIVATE_CA_MAXIMUM_BYTES: u64 = 1024 * 1024;
const PROJECTED_RESPONSE_MAXIMUM_BYTES: usize = 65_536;
const JSON_MEDIA_TYPE: &str = "application/json";
const GRAPHQL_JSON_MEDIA_TYPE: &str = "application/graphql-response+json";
/// Scheme used when a source states no other, and the only scheme RFC 6750
/// admits for an access token the runtime acquired itself.
const DEFAULT_AUTHORIZATION_SCHEME: &str = "Bearer";
/// RFC 7523 section 2.2 fixes this identifier for a JWT client assertion.
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// Proves a client assertion key can sign and that its two halves belong
/// together, without producing anything a server would accept as an assertion.
const CLIENT_KEY_PROBE: &[u8] = b"registry-evidence source client key usability probe";
/// Causes this module raises about a statement source's preparation, beside the
/// ones `source_sqlite` raises about the statement itself.
const PREPARED_PARAMETER_UNDECLARED: &str =
    "the preparation returned a parameter the statement does not declare";
const PREPARED_PARAMETER_RESERVED: &str =
    "the preparation returned the parameter name the runtime reserves";
const PREPARED_PARAMETER_NOT_PREPARED: &str =
    "the preparation returned a parameter the statement fills from a selector";
const MISSING_PREPARED_PARAMETER: &str =
    "the preparation returned no value for a parameter declared prepared";
const STATEMENT_ARTIFACT_UNREADABLE: &str = "the statement artifact is not readable UTF-8 text";
const STATEMENT_EXTRACT_UNBOUND: &str =
    "the deployment binds no file for the extract profile this statement reads";

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
    #[error("the source extract could not be read")]
    ExtractUnavailable(ArtifactFault),
    #[error("the source extract is older than the source allows")]
    ExtractTooOld(ArtifactFault),
    #[error("the source statement was refused")]
    StatementRefused(ArtifactFault),
    #[error("the source statement parameters are invalid")]
    StatementParameter(ArtifactFault),
    #[error("the source statement exceeded a declared budget")]
    StatementBudget(ArtifactFault),
    #[error("the source statement result left its declared contract")]
    StatementResult(ArtifactFault),
    #[error("the source statement could not be executed")]
    StatementUnavailable,
}

impl SourceError {
    /// The artifact an adopter can open, where the failure named one.
    ///
    /// The fault never reaches a request-time rendering, which stays value-free
    /// and categorical. It is the deployment path that wants it, so a statement
    /// refused at startup names `queries/<name>.sql` and a line inside it rather
    /// than reporting that a source is unavailable.
    pub fn artifact_fault(&self) -> Option<&ArtifactFault> {
        match self {
            Self::ExtractUnavailable(fault)
            | Self::ExtractTooOld(fault)
            | Self::StatementRefused(fault)
            | Self::StatementParameter(fault)
            | Self::StatementBudget(fault)
            | Self::StatementResult(fault) => Some(fault),
            Self::InvalidPlan
            | Self::InvalidSelectors
            | Self::Credential
            | Self::Concurrency
            | Self::Timeout
            | Self::Transport
            | Self::Redirect
            | Self::Status(_)
            | Self::WrongMediaType
            | Self::ResponseTooLarge
            | Self::InvalidJson
            | Self::ErrorEnvelope
            | Self::ProjectionViolation
            | Self::StatementUnavailable => None,
        }
    }
}

/// Carry a statement-source failure across into the closed source vocabulary.
///
/// The engine's own words never travel: `source_sqlite` has already classified
/// the failure to one of its closed causes, and that cause is what selects the
/// category here.
fn map_statement_error(error: SqliteSourceError) -> SourceError {
    let cause = error.cause();
    let fault = match error {
        SqliteSourceError::Statement(fault) | SqliteSourceError::Extract(fault) => fault,
        SqliteSourceError::InvalidPlan => return SourceError::InvalidPlan,
        SqliteSourceError::Concurrency => return SourceError::Concurrency,
        SqliteSourceError::Timeout => return SourceError::Timeout,
        SqliteSourceError::Unavailable => return SourceError::StatementUnavailable,
    };
    match cause {
        Some(cause::EXTRACT_UNAVAILABLE | cause::NO_METADATA_TABLE | cause::MALFORMED_METADATA) => {
            SourceError::ExtractUnavailable(fault)
        }
        Some(cause::EXTRACT_TOO_OLD) => SourceError::ExtractTooOld(fault),
        Some(cause::MISSING_PARAMETER) => SourceError::StatementParameter(fault),
        Some(cause::STEP_BUDGET_EXCEEDED | cause::TIME_BUDGET_EXCEEDED) => {
            SourceError::StatementBudget(fault)
        }
        Some(cause::TOO_MANY_ROWS | cause::CELL_TOO_LARGE | cause::VALUE_TYPE_MISMATCH) => {
            SourceError::StatementResult(fault)
        }
        // Every remaining cause, including a statement that failed while its
        // result was read, says the statement itself did not hold up against
        // the extract. That is one fix, in the one file the fault names.
        _ => SourceError::StatementRefused(fault),
    }
}

/// Executes one immutable source plan on the transport that plan names.
///
/// One executor type serves every transport, so a caller holds a source without
/// holding a transport decision. The HTTP client has redirects, retries,
/// ambient proxies, pagination, cookies, and caller-controlled headers absent.
pub struct SourceExecutor {
    transport: SourceTransport,
}

/// The transports this build has an executor for.
enum SourceTransport {
    Http(Box<HttpTransport>),
    Statement(Box<StatementTransport>),
}

struct HttpTransport {
    client: reqwest::Client,
    request: RequestPlan,
    authentication: AuthenticationPlan,
    secrets: Arc<SecretResolver>,
    concurrency: Semaphore,
    concurrency_admission_timeout: Duration,
}

/// One reviewed statement, and the extract it reads.
struct StatementTransport {
    request: StatementRequestPlan,
    /// The opened extract. Absent only in the offline fixture evaluator, which
    /// has no runtime document to bind an extract profile to a file with. Such
    /// an executor materializes a request and fails closed if asked to run one,
    /// rather than standing in for an extract it does not have.
    extract: Option<SqliteExtractSource>,
}

/// What a statement source needs from outside its own configuration.
#[derive(Clone, Copy)]
pub struct StatementInputs<'a> {
    /// The reviewed statement, read from the bundle artifact the source names.
    pub statement_sql: &'a str,
    /// The file the runtime document bound the source's extract profile to.
    pub extract_path: Option<&'a Path>,
}

/// Bind one source to what a statement transport needs from outside its own
/// configuration, so every caller assembles it the same way.
///
/// `extracts` is `Some` wherever a runtime document was loaded, and a profile
/// missing from it is a deployment fault rather than an executor that quietly
/// cannot run. `None` says there is no runtime document at all, which is the
/// offline fixture and bundle-check position: the statement is still compiled
/// and checked, and no file is opened. A source on any other transport needs
/// nothing here and binds nothing.
pub fn statement_inputs<'a>(
    source: &SourceConfig,
    bundle: &'a Bundle,
    extracts: Option<&'a BTreeMap<String, SourceExtract>>,
) -> Result<Option<StatementInputs<'a>>, SourceError> {
    let Some(artifact) = source.statement() else {
        return Ok(None);
    };
    let artifact = artifact.as_str();
    let statement_sql = bundle
        .artifact(artifact)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or_else(|| {
            SourceError::StatementRefused(ArtifactFault::new(
                artifact,
                SchemaFault::because(STATEMENT_ARTIFACT_UNREADABLE),
            ))
        })?;
    let extract_path = match extracts {
        Some(extracts) => {
            let profile = source.extract_profile().ok_or(SourceError::InvalidPlan)?;
            let extract = extracts.get(profile).ok_or_else(|| {
                SourceError::ExtractUnavailable(ArtifactFault::new(
                    artifact,
                    SchemaFault::because(STATEMENT_EXTRACT_UNBOUND),
                ))
            })?;
            Some(extract.path())
        }
        None => None,
    };
    Ok(Some(StatementInputs {
        statement_sql,
        extract_path,
    }))
}

/// The validated non-credential transport material for one fixed source request.
///
/// For HTTP the full URL remains private so callers cannot obtain source
/// authority, and this type deliberately exposes no fixed headers or
/// authentication material. Path, query, body, statement, and parameter access
/// is intended for the trusted offline fixture harness. Its diagnostic
/// representation is always value-free.
#[derive(Clone, PartialEq)]
pub enum MaterializedSourceRequest {
    Http {
        url: Url,
        body: Option<JsonValue>,
    },
    /// The statement about to run, and the values bound into it. The runtime's
    /// own evaluation instant is not among them: it is bound where the
    /// statement executes, so no caller can observe or replace it.
    Sqlite {
        statement: String,
        parameters: BTreeMap<String, SelectorValue>,
    },
}

impl MaterializedSourceRequest {
    /// The request path, for a transport that has one.
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Http { url, .. } => Some(url.path()),
            Self::Sqlite { .. } => None,
        }
    }

    pub fn query(&self) -> Option<&str> {
        match self {
            Self::Http { url, .. } => url.query(),
            Self::Sqlite { .. } => None,
        }
    }

    pub fn body(&self) -> Option<&JsonValue> {
        match self {
            Self::Http { body, .. } => body.as_ref(),
            Self::Sqlite { .. } => None,
        }
    }

    /// The reviewed statement text, for a transport that runs one.
    pub fn statement(&self) -> Option<&str> {
        match self {
            Self::Http { .. } => None,
            Self::Sqlite { statement, .. } => Some(statement),
        }
    }

    /// The values bound into the statement, for a transport that binds any.
    pub fn parameters(&self) -> Option<&BTreeMap<String, SelectorValue>> {
        match self {
            Self::Http { .. } => None,
            Self::Sqlite { parameters, .. } => Some(parameters),
        }
    }
}

impl fmt::Debug for MaterializedSourceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { .. } => formatter
                .debug_struct("MaterializedSourceRequest::Http")
                .field("path", &"<redacted>")
                .field("query", &self.query().map(|_| "<redacted>"))
                .field("body", &self.body().map(|_| "<redacted>"))
                .finish(),
            Self::Sqlite { parameters, .. } => formatter
                .debug_struct("MaterializedSourceRequest::Sqlite")
                .field("statement", &"<redacted>")
                .field("parameters", &parameters.len())
                .finish(),
        }
    }
}

/// The validated preparation output for one source, in the shape its transport
/// consumes.
#[derive(Clone, Debug, PartialEq)]
pub enum PreparedSourceRequest {
    Http(RequestParts),
    Statement(StatementParameters),
}

impl PreparedSourceRequest {
    /// The HTTP request parts, where an HTTP source prepared them. Absent on
    /// every other transport, which prepares something else entirely.
    pub fn http_parts(&self) -> Option<&RequestParts> {
        match self {
            Self::Http(parts) => Some(parts),
            Self::Statement(_) => None,
        }
    }

    fn http(&self) -> Result<&RequestParts, SourceError> {
        match self {
            Self::Http(parts) => Ok(parts),
            Self::Statement(_) => Err(SourceError::InvalidPlan),
        }
    }

    fn statement(&self) -> Result<&StatementParameters, SourceError> {
        match self {
            Self::Statement(parameters) => Ok(parameters),
            Self::Http(_) => Err(SourceError::InvalidPlan),
        }
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

struct StatementRequestPlan {
    /// The bundle-relative statement artifact, so a fault this module raises
    /// names the file an adopter opens.
    artifact: String,
    statement_sql: String,
    selector_inputs: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    allowed_selector_sets: Vec<SourceSelectorSet>,
    parameter_bindings: BTreeMap<String, StatementParameterPlan>,
    projection: ProjectionNode,
    maximum_response_bytes: u64,
}

/// Where one statement parameter's value comes from. An enum rather than an
/// optional selector, so the match that fills a parameter is exhaustive and a
/// later origin cannot be added without being handled.
enum StatementParameterPlan {
    Selector {
        role: String,
        profile: String,
        field: String,
    },
    Prepared,
}

enum SourcePath {
    Fixed(String),
    Template {
        template: String,
        bindings: BTreeMap<String, PathBindingPlan>,
    },
}

enum PathBindingPlan {
    Selector {
        role: String,
        profile: String,
        field: String,
    },
    PriorFact {
        field: String,
    },
}

enum AuthenticationPlan {
    None,
    Basic {
        username_ref: SecretRef,
        password_ref: SecretRef,
    },
    StaticAuthorization {
        token_ref: SecretRef,
        scheme: String,
    },
    StaticApiKey {
        header_name: HeaderName,
        value_ref: SecretRef,
    },
    Oauth2(Box<OauthPlan>),
}

/// How the client proves its identity at the token endpoint.
///
/// The bundle states the two forms as alternative flat keys, and compilation
/// is where that alternation becomes a choice the runtime cannot get wrong.
enum OauthClientAuthentication {
    ClientSecret {
        secret_ref: SecretRef,
        placement: CredentialPlacement,
    },
    PrivateKeyJwt {
        key_ref: SecretRef,
        /// Resolved at compile time to the configured audience or, when the
        /// bundle names none, the token endpoint.
        audience: String,
    },
}

struct OauthPlan {
    token_endpoint: Url,
    client_id_ref: SecretRef,
    client_authentication: OauthClientAuthentication,
    scope: Option<String>,
    audience: Option<String>,
    maximum_cache_lifetime: Duration,
    /// Lifetime used when the provider omits `expires_in`.
    assumed_lifetime: Option<Duration>,
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
    /// Compile a standalone HTTP source with system TLS roots. Sources that name
    /// a private trust profile require `new_with_selector_sets_and_tls`.
    pub fn new(source: &SourceConfig, secrets: Arc<SecretResolver>) -> Result<Self, SourceError> {
        let allowed = conservative_selector_sets(source)?;
        Self::new_with_selector_sets(source, &allowed, secrets)
    }

    /// Compile an HTTP source with system TLS roots and explicitly allowed
    /// selector tuples.
    pub fn new_with_selector_sets(
        source: &SourceConfig,
        allowed_selector_sets: &[SourceSelectorSet],
        secrets: Arc<SecretResolver>,
    ) -> Result<Self, SourceError> {
        if source.tls_trust_profile().is_some() {
            return Err(SourceError::InvalidPlan);
        }
        Self::compile(source, allowed_selector_sets, None, false, None, secrets)
    }

    /// Compile a source against runtime-owned TLS trust bindings. System roots
    /// remain enabled and the selected private CA bundle is additive.
    ///
    /// `statement` carries what a statement source needs from outside its own
    /// configuration, and is absent for every other transport.
    pub fn new_with_selector_sets_and_tls(
        source: &SourceConfig,
        allowed_selector_sets: &[SourceSelectorSet],
        outbound_tls: &OutboundTlsConfig,
        captured_ca_bundles: &BTreeMap<String, Vec<u8>>,
        statement: Option<StatementInputs<'_>>,
        secrets: Arc<SecretResolver>,
    ) -> Result<Self, SourceError> {
        Self::compile(
            source,
            allowed_selector_sets,
            Some((outbound_tls, captured_ca_bundles)),
            false,
            statement,
            secrets,
        )
    }

    /// Compile the non-credential request material used only by the hidden
    /// bundle fixture evaluator. Runtime-owned private CA bytes are not needed
    /// because this executor can materialize requests but is never executed,
    /// and a statement source compiled here is given no extract for the same
    /// reason.
    pub fn new_for_offline_fixture(
        source: &SourceConfig,
        allowed_selector_sets: &[SourceSelectorSet],
        statement: Option<StatementInputs<'_>>,
        secrets: Arc<SecretResolver>,
    ) -> Result<Self, SourceError> {
        Self::compile(
            source,
            allowed_selector_sets,
            None,
            true,
            statement,
            secrets,
        )
    }

    fn compile(
        source: &SourceConfig,
        allowed_selector_sets: &[SourceSelectorSet],
        outbound_tls: Option<(&OutboundTlsConfig, &BTreeMap<String, Vec<u8>>)>,
        offline_fixture: bool,
        statement: Option<StatementInputs<'_>>,
        secrets: Arc<SecretResolver>,
    ) -> Result<Self, SourceError> {
        // The source's own transport selects the executor. A source whose
        // transport this build has no executor for is refused here rather than
        // served by a substitute.
        let transport = match source {
            SourceConfig::HttpJson { .. } => {
                SourceTransport::Http(Box::new(HttpTransport::compile(
                    source,
                    allowed_selector_sets,
                    outbound_tls,
                    offline_fixture,
                    secrets,
                )?))
            }
            SourceConfig::SqliteExtract { .. } => {
                SourceTransport::Statement(Box::new(StatementTransport::compile(
                    source,
                    allowed_selector_sets,
                    statement.ok_or(SourceError::InvalidPlan)?,
                )?))
            }
        };
        Ok(Self { transport })
    }

    /// Make exactly one evidence-data acquisition using validated Rhai
    /// preparation output. Path expansion and parameter binding remain
    /// Rust-owned and selector-bound.
    ///
    /// `evaluation_instant` is the runtime's one clock, captured before
    /// acquisition begins. A transport that exposes an instant to its source
    /// exposes this one, so an assertion and the data behind it are read as of
    /// the same moment.
    pub async fn execute(
        &self,
        selectors: &[ResolvedSourceSelector],
        request: &PreparedSourceRequest,
        evaluation_instant: DateTime<Utc>,
    ) -> Result<JsonValue, SourceError> {
        self.execute_with_prior_facts(selectors, &BTreeMap::new(), request, evaluation_instant)
            .await
    }

    pub async fn execute_with_prior_facts(
        &self,
        selectors: &[ResolvedSourceSelector],
        prior_facts: &BTreeMap<String, JsonValue>,
        request: &PreparedSourceRequest,
        evaluation_instant: DateTime<Utc>,
    ) -> Result<JsonValue, SourceError> {
        let materialized =
            self.materialize_request_with_prior_facts(selectors, prior_facts, request)?;
        match &self.transport {
            SourceTransport::Http(http) => http.execute(&materialized).await,
            SourceTransport::Statement(statement) => {
                statement.execute(&materialized, evaluation_instant).await
            }
        }
    }

    /// Validate and materialize only the transport material: path, encoded
    /// query, and JSON body for HTTP, statement and bound parameters for a
    /// statement source.
    ///
    /// This performs no concurrency admission, credential resolution, or I/O.
    /// The same result is consumed directly by [`Self::execute`].
    pub fn materialize_request(
        &self,
        selectors: &[ResolvedSourceSelector],
        request: &PreparedSourceRequest,
    ) -> Result<MaterializedSourceRequest, SourceError> {
        self.materialize_request_with_prior_facts(selectors, &BTreeMap::new(), request)
    }

    pub fn materialize_request_with_prior_facts(
        &self,
        selectors: &[ResolvedSourceSelector],
        prior_facts: &BTreeMap<String, JsonValue>,
        request: &PreparedSourceRequest,
    ) -> Result<MaterializedSourceRequest, SourceError> {
        match &self.transport {
            SourceTransport::Http(http) => {
                http.materialize_request(selectors, prior_facts, request.http()?)
            }
            SourceTransport::Statement(statement) => {
                statement.materialize_request(selectors, request.statement()?)
            }
        }
    }

    /// Resolve and validate credentials without making an evidence-data
    /// request. OAuth may perform its bounded token bootstrap.
    pub async fn credentials_ready(&self) -> Result<(), SourceError> {
        match &self.transport {
            SourceTransport::Http(http) => http.authentication_header().await.map(|_| ()),
            // A statement source reads a file the deployment mounted beside the
            // process. There are no credentials to hold, which is the point of
            // the transport, so it is ready as soon as it has compiled.
            SourceTransport::Statement(_) => Ok(()),
        }
    }

    /// The HTTP transport's concurrency boundary, for the tests that occupy it.
    #[cfg(test)]
    fn http_concurrency(&self) -> &Semaphore {
        match &self.transport {
            SourceTransport::Http(http) => &http.concurrency,
            SourceTransport::Statement(_) => panic!("the source is not an HTTP source"),
        }
    }
}

impl HttpTransport {
    fn compile(
        source: &SourceConfig,
        allowed_selector_sets: &[SourceSelectorSet],
        outbound_tls: Option<(&OutboundTlsConfig, &BTreeMap<String, Vec<u8>>)>,
        offline_fixture: bool,
        secrets: Arc<SecretResolver>,
    ) -> Result<Self, SourceError> {
        let SourceConfig::HttpJson {
            base_url: configured_base_url,
            posture,
            tls_trust_profile,
            authentication: configured_authentication,
            request: configured_request,
            ..
        } = source
        else {
            return Err(SourceError::InvalidPlan);
        };
        if matches!(**configured_authentication, SourceAuthentication::None {})
            && (tls_trust_profile.is_some()
                || validate_local_unauthenticated_source_origin(configured_base_url).is_err())
        {
            return Err(SourceError::InvalidPlan);
        }
        let timeout = Duration::from_millis(configured_request.timeout_milliseconds);
        if timeout.is_zero()
            || configured_request.timeout_milliseconds > 30_000
            || configured_request.maximum_response_bytes == 0
            || configured_request.maximum_response_bytes > 1_048_576
            || configured_request.concurrency_limit == 0
            || configured_request.concurrency_limit > 256
        {
            return Err(SourceError::InvalidPlan);
        }
        let base_url = validate_url(configured_base_url, true)?;
        let authentication = compile_authentication(configured_authentication, timeout)?;
        let request = compile_request(
            configured_request,
            allowed_selector_sets,
            *posture,
            base_url,
            &authentication,
        )?;
        let client = build_client(
            timeout,
            tls_trust_profile.as_deref(),
            outbound_tls,
            offline_fixture,
        )?;
        Ok(Self {
            client,
            request,
            authentication,
            secrets,
            concurrency: Semaphore::new(usize::from(configured_request.concurrency_limit)),
            concurrency_admission_timeout: timeout,
        })
    }

    async fn execute(
        &self,
        materialized: &MaterializedSourceRequest,
    ) -> Result<JsonValue, SourceError> {
        let MaterializedSourceRequest::Http { url, .. } = materialized else {
            return Err(SourceError::InvalidPlan);
        };
        let _permit =
            acquire_source_slot(&self.concurrency, self.concurrency_admission_timeout).await?;
        let method = match self.request.method {
            HttpMethod::GET => reqwest::Method::GET,
            HttpMethod::POST => reqwest::Method::POST,
        };
        let mut request = self
            .client
            .request(method, url.clone())
            .headers(self.request.fixed_headers.clone());
        if let Some((authentication_name, authentication_value)) =
            self.authentication_header().await?
        {
            request = request.header(authentication_name, authentication_value);
        }
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

    fn materialize_request(
        &self,
        selectors: &[ResolvedSourceSelector],
        prior_facts: &BTreeMap<String, JsonValue>,
        request_parts: &RequestParts,
    ) -> Result<MaterializedSourceRequest, SourceError> {
        if matches!(self.request.method, HttpMethod::GET) && request_parts.body.is_some() {
            return Err(SourceError::InvalidPlan);
        }
        let selectors = self.request.validate_selectors(selectors)?;
        let url = self
            .request
            .materialize_url(&selectors, prior_facts, request_parts)?;
        Ok(MaterializedSourceRequest::Http {
            url,
            body: request_parts.body.clone(),
        })
    }

    async fn authentication_header(
        &self,
    ) -> Result<Option<(HeaderName, HeaderValue)>, SourceError> {
        let value = match &self.authentication {
            AuthenticationPlan::None => return Ok(None),
            AuthenticationPlan::Basic {
                username_ref,
                password_ref,
            } => {
                let username = resolve(&self.secrets, username_ref)?;
                let password = resolve(&self.secrets, password_ref)?;
                basic_authorization(&username, &password)?
            }
            AuthenticationPlan::StaticAuthorization { token_ref, scheme } => {
                let token = resolve(&self.secrets, token_ref)?;
                scheme_authorization(scheme, token.expose_secret())?
            }
            AuthenticationPlan::StaticApiKey {
                header_name,
                value_ref,
            } => {
                let secret = resolve(&self.secrets, value_ref)?;
                return Ok(Some((
                    header_name.clone(),
                    sensitive_header(secret.expose_secret())?,
                )));
            }
            AuthenticationPlan::Oauth2(plan) => {
                let token = plan.access_token(&self.client, &self.secrets).await?;
                bearer_authorization(token.expose())?
            }
        };
        Ok(Some((AUTHORIZATION, value)))
    }
}

impl StatementTransport {
    fn compile(
        source: &SourceConfig,
        allowed_selector_sets: &[SourceSelectorSet],
        inputs: StatementInputs<'_>,
    ) -> Result<Self, SourceError> {
        let SourceConfig::SqliteExtract {
            request: configured_request,
            ..
        } = source
        else {
            return Err(SourceError::InvalidPlan);
        };
        let selector_inputs = compile_selector_inputs(&configured_request.selector_inputs)?;
        let allowed_selector_sets =
            compile_allowed_selector_sets(&selector_inputs, allowed_selector_sets)?;
        let parameter_bindings = compile_parameter_bindings(
            configured_request,
            &selector_inputs,
            &allowed_selector_sets,
        )?;
        let projection = compile_projection(&configured_request.projection)?;
        let request = StatementRequestPlan {
            artifact: configured_request.statement.as_str().to_owned(),
            statement_sql: inputs.statement_sql.to_owned(),
            selector_inputs,
            allowed_selector_sets,
            parameter_bindings,
            projection,
            maximum_response_bytes: configured_request.maximum_response_bytes,
        };
        // The statement is checked as strongly as the caller's inputs allow.
        // Opening the extract checks it against the schema it will actually
        // read, so a statement that disagrees with the extract fails at startup
        // rather than at the first request. Without an extract there is no
        // schema to check against, so what is settleable without data is
        // settled here instead of going unchecked.
        let extract = match inputs.extract_path {
            Some(path) => Some(
                SqliteExtractSource::open(source, inputs.statement_sql, path)
                    .map_err(map_statement_error)?,
            ),
            None => {
                check_statement_offline(source, inputs.statement_sql)
                    .map_err(map_statement_error)?;
                None
            }
        };
        Ok(Self { request, extract })
    }

    async fn execute(
        &self,
        materialized: &MaterializedSourceRequest,
        evaluation_instant: DateTime<Utc>,
    ) -> Result<JsonValue, SourceError> {
        let MaterializedSourceRequest::Sqlite { parameters, .. } = materialized else {
            return Err(SourceError::InvalidPlan);
        };
        let extract = self
            .extract
            .as_ref()
            .ok_or(SourceError::StatementUnavailable)?;
        // How old an extract may be is an evaluation-time question, not a
        // load-time one, so it is asked here, against the instant this
        // evaluation carries, and before a single row is read.
        extract
            .validate_extract_age(evaluation_instant)
            .map_err(map_statement_error)?;
        let response = extract
            .execute(parameters, evaluation_instant)
            .await
            .map_err(map_statement_error)?;
        if serde_json::to_vec(&response)
            .map_err(|_| SourceError::InvalidJson)?
            .len()
            > usize::try_from(self.request.maximum_response_bytes)
                .map_err(|_| SourceError::ResponseTooLarge)?
        {
            return Err(SourceError::ResponseTooLarge);
        }
        project_bounded_response(&response, &self.request.projection)
    }

    fn materialize_request(
        &self,
        selectors: &[ResolvedSourceSelector],
        prepared: &StatementParameters,
    ) -> Result<MaterializedSourceRequest, SourceError> {
        let selectors = validate_selectors(
            &self.request.selector_inputs,
            &self.request.allowed_selector_sets,
            selectors,
        )?;
        let mut parameters = BTreeMap::new();
        for (name, binding) in &self.request.parameter_bindings {
            let StatementParameterPlan::Selector {
                role,
                profile,
                field,
            } = binding
            else {
                continue;
            };
            let selector = selectors
                .get(&(role.as_str(), profile.as_str()))
                .ok_or(SourceError::InvalidSelectors)?;
            let value = selector
                .values
                .get(field)
                .ok_or(SourceError::InvalidSelectors)?;
            parameters.insert(name.clone(), value.clone());
        }
        // Preparation fills the parameters the source declared prepared, and
        // those only. It cannot introduce a parameter the source did not
        // declare, it cannot reach the name the runtime keeps for its own
        // instant, and it cannot stand in for a selector the source named as a
        // parameter's origin.
        for (name, value) in &prepared.parameters {
            let cause = if name == RESERVED_SQL_PARAMETER {
                PREPARED_PARAMETER_RESERVED
            } else {
                match self.request.parameter_bindings.get(name) {
                    None => PREPARED_PARAMETER_UNDECLARED,
                    Some(StatementParameterPlan::Selector { .. }) => {
                        PREPARED_PARAMETER_NOT_PREPARED
                    }
                    Some(StatementParameterPlan::Prepared) => {
                        parameters.insert(name.clone(), value.clone());
                        continue;
                    }
                }
            };
            return Err(SourceError::StatementParameter(ArtifactFault::new(
                &self.request.artifact,
                SchemaFault::because(cause),
            )));
        }
        // A prepared parameter the script returned nothing for has no other
        // origin to fall back on, so it is named here rather than reaching the
        // statement as an unbound parameter.
        if self
            .request
            .parameter_bindings
            .iter()
            .any(|(name, binding)| {
                matches!(binding, StatementParameterPlan::Prepared)
                    && !parameters.contains_key(name)
            })
        {
            return Err(SourceError::StatementParameter(ArtifactFault::new(
                &self.request.artifact,
                SchemaFault::because(MISSING_PREPARED_PARAMETER),
            )));
        }
        Ok(MaterializedSourceRequest::Sqlite {
            statement: self.request.statement_sql.clone(),
            parameters,
        })
    }
}

fn compile_parameter_bindings(
    request: &SqliteRequest,
    inputs: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    allowed: &[SourceSelectorSet],
) -> Result<BTreeMap<String, StatementParameterPlan>, SourceError> {
    let mut bindings = BTreeMap::new();
    for (name, binding) in request.parameter_bindings.iter() {
        if name == RESERVED_SQL_PARAMETER {
            return Err(SourceError::InvalidPlan);
        }
        let plan = match binding {
            SqliteParameterBinding::Selector {
                role,
                profile,
                field,
            } => {
                if !inputs
                    .get(role)
                    .and_then(|profiles| profiles.get(profile))
                    .is_some_and(|fields| fields.contains(field))
                {
                    return Err(SourceError::InvalidPlan);
                }
                // A parameter bound to a selector some admissible set does not
                // carry could never be filled under that set, so it is refused
                // as a plan fault here rather than as a missing value at
                // request time.
                for set in allowed {
                    if !set.iter().any(|(active_role, active_profile)| {
                        active_role == role && active_profile == profile
                    }) {
                        return Err(SourceError::InvalidPlan);
                    }
                }
                StatementParameterPlan::Selector {
                    role: role.clone(),
                    profile: profile.clone(),
                    field: field.clone(),
                }
            }
            // A prepared parameter names no selector, so there is no selector
            // input and no admissible set for it to be reachable under.
            SqliteParameterBinding::Prepared {} => StatementParameterPlan::Prepared,
        };
        if bindings.insert(name.to_owned(), plan).is_some() {
            return Err(SourceError::InvalidPlan);
        }
    }
    Ok(bindings)
}

/// Apply the exact production response-size, envelope, and projection rules
/// to an already parsed synthetic fixture response.
pub fn project_fixture_response(
    source: &SourceConfig,
    response: &JsonValue,
) -> Result<JsonValue, SourceError> {
    let raw = serde_json::to_vec(response).map_err(|_| SourceError::InvalidJson)?;
    if raw.len()
        > usize::try_from(source.maximum_response_bytes())
            .map_err(|_| SourceError::ResponseTooLarge)?
    {
        return Err(SourceError::ResponseTooLarge);
    }
    let projection = compile_projection(source.projection())?;
    project_bounded_response(response, &projection)
}

/// Refuse an error envelope, apply the acquisition projection, and hold the
/// projected result to its own size bound.
///
/// Every transport and the fixture evaluator share this tail, so what reaches
/// extraction is the same shape under the same rules whatever produced it. The
/// bound each producer sets on the response it read is its own, and is applied
/// before this.
fn project_bounded_response(
    response: &JsonValue,
    projection: &ProjectionNode,
) -> Result<JsonValue, SourceError> {
    if response
        .as_object()
        .is_some_and(|object| object.contains_key("errors"))
    {
        return Err(SourceError::ErrorEnvelope);
    }
    let projected = project_value(response, projection)?;
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
    tls_trust_profile: Option<&str>,
    outbound_tls: Option<(&OutboundTlsConfig, &BTreeMap<String, Vec<u8>>)>,
    offline_fixture: bool,
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
    if let Some(profile_name) = tls_trust_profile {
        if offline_fixture && outbound_tls.is_none() {
            return builder.build().map_err(|_| SourceError::InvalidPlan);
        }
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
    for input in source.selector_inputs() {
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
    let selector_inputs = compile_selector_inputs(&request.selector_inputs)?;
    let allowed_selector_sets =
        compile_allowed_selector_sets(&selector_inputs, allowed_selector_sets)?;
    let path = compile_source_path(request, &selector_inputs)?;
    validate_bindings_are_reachable(&path, &allowed_selector_sets)?;
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
    selector_inputs: &[SelectorInput],
) -> Result<BTreeMap<String, BTreeMap<String, BTreeSet<String>>>, SourceError> {
    let mut output = BTreeMap::new();
    for input in selector_inputs {
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
    Ok(output)
}

fn compile_allowed_selector_sets(
    inputs: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    configured: &[SourceSelectorSet],
) -> Result<Vec<SourceSelectorSet>, SourceError> {
    let mut unique = BTreeSet::new();
    for configured_set in configured {
        if configured_set.len() > inputs.len() || (configured_set.is_empty() && !inputs.is_empty())
        {
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
    if unique.is_empty() || (inputs.is_empty() && !unique.contains(&Vec::new())) {
        return Err(SourceError::InvalidPlan);
    }
    Ok(unique.into_iter().collect())
}

/// Refuse any allowed selector set that cannot fill the path template.
///
/// `materialize_url` resolves each placeholder against the set the request
/// actually activated, so a binding is mandatory per set, not across their
/// union. A set missing one has no value to substitute and fails every request
/// it serves. That set exists because an authority grant produced it, which is
/// a startup fact, so refuse it at startup rather than per request.
fn validate_bindings_are_reachable(
    path: &SourcePath,
    allowed: &[SourceSelectorSet],
) -> Result<(), SourceError> {
    let SourcePath::Template { bindings, .. } = path else {
        return Ok(());
    };
    for set in allowed {
        let activated = set
            .iter()
            .map(|(role, profile)| (role.as_str(), profile.as_str()))
            .collect::<BTreeSet<_>>();
        if bindings.values().any(|binding| {
            matches!(
                binding,
                PathBindingPlan::Selector { role, profile, .. }
                    if !activated.contains(&(role.as_str(), profile.as_str()))
            )
        }) {
            return Err(SourceError::InvalidPlan);
        }
    }
    Ok(())
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
                let plan = match binding {
                    PathBindingConfig::Selector {
                        role,
                        profile,
                        field,
                    } => PathBindingPlan::Selector {
                        role: role.clone(),
                        profile: profile.clone(),
                        field: field.clone(),
                    },
                    PathBindingConfig::PriorFact { field } => PathBindingPlan::PriorFact {
                        field: field.clone(),
                    },
                };
                bindings.insert(name.to_owned(), plan);
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
    match binding {
        PathBindingConfig::Selector {
            role,
            profile,
            field,
        } if inputs
            .get(role)
            .and_then(|profiles| profiles.get(profile))
            .is_some_and(|fields| fields.contains(field)) =>
        {
            Ok(())
        }
        PathBindingConfig::PriorFact { field } if !field.is_empty() => Ok(()),
        _ => Err(SourceError::InvalidPlan),
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
        SourceAuthentication::None {} => Ok(AuthenticationPlan::None),
        SourceAuthentication::Basic {
            username_ref,
            password_ref,
        } => Ok(AuthenticationPlan::Basic {
            username_ref: username_ref.clone(),
            password_ref: password_ref.clone(),
        }),
        SourceAuthentication::StaticAuthorization { token_ref, scheme } => {
            let scheme = scheme.as_deref().unwrap_or(DEFAULT_AUTHORIZATION_SCHEME);
            if scheme.is_empty() || !scheme.bytes().all(is_http_token_byte) {
                return Err(SourceError::InvalidPlan);
            }
            Ok(AuthenticationPlan::StaticAuthorization {
                token_ref: token_ref.clone(),
                scheme: scheme.to_owned(),
            })
        }
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
            client_assertion_key_ref,
            client_assertion_audience,
            scope,
            audience,
            credential_placement,
            maximum_cache_seconds,
            assumed_lifetime_seconds,
        } => {
            // The audience the assertion falls back to is the endpoint as the
            // operator wrote it, not as a parser renders it. RFC 7523 section 3
            // has the server compare `aud` by Simple String Comparison against
            // the endpoint it published, and parsing drops a default port and
            // resolves dot segments, so the parsed form can differ from the
            // spelling the operator copied from that server. A configured
            // `clientAssertionAudience` already travels byte for byte for this
            // reason; the default it stands in for has to do the same.
            let configured_token_endpoint = token_endpoint.as_str();
            let token_endpoint = validate_url(token_endpoint, false)?;
            if token_endpoint.query().is_some() {
                return Err(SourceError::InvalidPlan);
            }
            let client_authentication = match (
                client_secret_ref,
                credential_placement,
                client_assertion_key_ref,
            ) {
                (Some(secret_ref), Some(placement), None) => {
                    // An assertion audience has no assertion to travel in.
                    if client_assertion_audience.is_some() {
                        return Err(SourceError::InvalidPlan);
                    }
                    OauthClientAuthentication::ClientSecret {
                        secret_ref: secret_ref.clone(),
                        placement: *placement,
                    }
                }
                (None, None, Some(key_ref)) => OauthClientAuthentication::PrivateKeyJwt {
                    key_ref: key_ref.clone(),
                    audience: client_assertion_audience
                        .clone()
                        .unwrap_or_else(|| configured_token_endpoint.to_owned()),
                },
                _ => return Err(SourceError::InvalidPlan),
            };
            Ok(AuthenticationPlan::Oauth2(Box::new(OauthPlan {
                token_endpoint,
                client_id_ref: client_id_ref.clone(),
                client_authentication,
                scope: scope.clone(),
                audience: audience.clone(),
                maximum_cache_lifetime: Duration::from_secs(*maximum_cache_seconds),
                assumed_lifetime: assumed_lifetime_seconds.map(Duration::from_secs),
                admission_timeout,
                cache: Mutex::new(None),
            })))
        }
    }
}

/// Hold a resolved selector set to one source's declared inputs: one selector
/// per role, exactly the declared fields, and an admissible role and profile
/// combination. Every transport asks the same question of the same material.
fn validate_selectors<'a>(
    inputs: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    allowed: &[SourceSelectorSet],
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
        let fields = inputs
            .get(&selector.role)
            .and_then(|profiles| profiles.get(&selector.profile))
            .ok_or(SourceError::InvalidSelectors)?;
        if selector.values.keys().collect::<BTreeSet<_>>() != fields.iter().collect::<BTreeSet<_>>()
        {
            return Err(SourceError::InvalidSelectors);
        }
        active.push((selector.role.clone(), selector.profile.clone()));
    }
    active.sort();
    if !allowed.contains(&active) {
        return Err(SourceError::InvalidSelectors);
    }
    Ok(index)
}

impl RequestPlan {
    fn validate_selectors<'a>(
        &self,
        selectors: &'a [ResolvedSourceSelector],
    ) -> Result<BTreeMap<(&'a str, &'a str), &'a ResolvedSourceSelector>, SourceError> {
        validate_selectors(
            &self.selector_inputs,
            &self.allowed_selector_sets,
            selectors,
        )
    }

    fn materialize_url(
        &self,
        selectors: &BTreeMap<(&str, &str), &ResolvedSourceSelector>,
        prior_facts: &BTreeMap<String, JsonValue>,
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
                        match binding {
                            PathBindingPlan::Selector {
                                role,
                                profile,
                                field,
                            } => {
                                let selector = selectors
                                    .get(&(role.as_str(), profile.as_str()))
                                    .ok_or(SourceError::InvalidSelectors)?;
                                let value = selector
                                    .values
                                    .get(field)
                                    .ok_or(SourceError::InvalidSelectors)?;
                                rendered.push_str(&encode_path_selector(value)?);
                            }
                            PathBindingPlan::PriorFact { field } => {
                                let value =
                                    prior_facts.get(field).ok_or(SourceError::InvalidPlan)?;
                                rendered.push_str(&encode_path_prior_fact(value)?);
                            }
                        }
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
    encode_path_text(&text, true)
}

fn encode_path_prior_fact(value: &JsonValue) -> Result<String, SourceError> {
    let text = match value {
        JsonValue::String(value) => value.clone(),
        JsonValue::Number(value) => value
            .as_i64()
            .map(|value| value.to_string())
            .ok_or(SourceError::InvalidPlan)?,
        JsonValue::Bool(value) => value.to_string(),
        _ => return Err(SourceError::InvalidPlan),
    };
    encode_path_text(&text, false)
}

fn encode_path_text(text: &str, invalid_selectors: bool) -> Result<String, SourceError> {
    let error = || {
        if invalid_selectors {
            SourceError::InvalidSelectors
        } else {
            SourceError::InvalidPlan
        }
    };
    if text.is_empty()
        || matches!(text, "." | "..")
        || text.chars().any(char::is_control)
        || text.contains(['/', '\\', '%'])
    {
        return Err(error());
    }
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").map_err(|_| error())?;
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
        let request = self.token_request(client, secrets)?;
        // `expires_in` is measured from issuance, and issuance happens at the
        // authorization server while this request is in flight. Anchoring here
        // rather than after the response arrives assumes the token was issued at
        // the earliest moment it could have been, which is the only assumption
        // that cannot outlive the real expiry: anchoring later would add the
        // whole round trip to the token's apparent life and let a cached token
        // be presented after the issuer had stopped honouring it.
        let requested_at = Instant::now();
        let response = request.send().await.map_err(map_transport_error)?;
        let (token, lifetime) =
            parse_token_response(response, self.scope.as_deref(), self.assumed_lifetime).await?;
        let cache_lifetime = lifetime.min(self.maximum_cache_lifetime);
        if !cache_lifetime.is_zero() {
            let expires_at = requested_at
                .checked_add(cache_lifetime)
                .ok_or(SourceError::Credential)?;
            *cache = Some(CachedToken {
                token: token.clone(),
                expires_at,
            });
        }
        Ok(token)
    }

    /// Resolve the client credentials and build the token request.
    ///
    /// `RequestBuilder::form` serializes the body as it is called, so every
    /// resolved secret is zeroized when this returns rather than being held
    /// across the token round trip.
    fn token_request(
        &self,
        client: &reqwest::Client,
        secrets: &SecretResolver,
    ) -> Result<reqwest::RequestBuilder, SourceError> {
        let client_id = resolve(secrets, &self.client_id_ref)?;
        let client_id_text = protected_text(&client_id)?;
        let mut form = vec![("grant_type", "client_credentials")];
        if let Some(scope) = self.scope.as_deref() {
            form.push(("scope", scope));
        }
        if let Some(audience) = self.audience.as_deref() {
            form.push(("audience", audience));
        }
        // No supported form places a client credential in the request URI,
        // where proxy and ingress logs would capture it.
        let mut request = client
            .post(self.token_endpoint.clone())
            .header(ACCEPT, JSON_MEDIA_TYPE);
        match &self.client_authentication {
            OauthClientAuthentication::ClientSecret {
                secret_ref,
                placement,
            } => {
                let client_secret = resolve(secrets, secret_ref)?;
                // A secret that is not UTF-8 is a misconfigured file rather
                // than a credential, and which placement carries it does not
                // change that. The check stays ahead of the match so neither
                // arm can be the one that accepts it.
                let client_secret_text = protected_text(&client_secret)?;
                match placement {
                    CredentialPlacement::BasicHeader => {
                        request = request.header(
                            AUTHORIZATION,
                            basic_authorization(&client_id, &client_secret)?,
                        );
                        Ok(request.form(&form))
                    }
                    CredentialPlacement::FormBody => {
                        form.push(("client_id", client_id_text));
                        form.push(("client_secret", client_secret_text));
                        Ok(request.form(&form))
                    }
                }
            }
            OauthClientAuthentication::PrivateKeyJwt { key_ref, audience } => {
                let assertion =
                    self.client_assertion(secrets, key_ref, audience, client_id_text)?;
                // RFC 7523 section 2.2 lets the client identifier travel beside
                // the assertion, and an authorization server that keys its
                // client lookup on it rejects the request without it.
                form.push(("client_id", client_id_text));
                form.push(("client_assertion_type", CLIENT_ASSERTION_TYPE));
                form.push(("client_assertion", assertion.as_str()));
                Ok(request.form(&form))
            }
        }
    }

    /// Sign the RFC 7523 section 2.2 client assertion.
    ///
    /// The audience is resolved at compile time: the token endpoint the
    /// assertion is sent to, which is what SMART on FHIR Backend Services
    /// requires, unless the bundle names one. RFC 7523 section 3 has the
    /// authorization server compare it by Simple String Comparison, so the
    /// resolved value is signed byte for byte and never reparsed here.
    fn client_assertion(
        &self,
        secrets: &SecretResolver,
        key_ref: &SecretRef,
        audience: &str,
        client_id: &str,
    ) -> Result<Zeroizing<String>, SourceError> {
        let key_material = resolve(secrets, key_ref)?;
        // `PrivateJwk::parse` is the crate's own entry point for untrusted key
        // material: it bounds the document size, rejects duplicate JSON
        // members, refuses unsupported private members, and validates that the
        // private half is present and well formed. Deserializing straight into
        // the type skips all four, so a key this runtime cannot actually sign
        // with would only fail later, at the signing call.
        let key = PrivateJwk::parse(protected_text(&key_material)?).map_err(|_| {
            // The parse error names JWK members, so it is never surfaced.
            SourceError::Credential
        })?;
        // Parsing each half does not make the two belong together. EdDSA
        // derives the public key from the seed and never reads `x`, and RSA
        // imports the private half alone, so a document pairing one pair's
        // private half with another's public half signs a valid assertion that
        // verifies under nothing the authorization server holds: what an
        // adopter registers is the public half. Signing a probe and verifying
        // it against this key's own public half is what proves the two belong
        // together, and it costs one operation per token acquisition instead
        // of a request to an authorization server that can only refuse it.
        //
        // The probe is deliberately not shaped like a JWS signing input, so
        // the signature discarded here could not be presented as an assertion.
        let probe = registry_platform_crypto::sign(CLIENT_KEY_PROBE, &key)
            .map_err(|_| SourceError::Credential)?;
        registry_platform_crypto::verify(CLIENT_KEY_PROBE, &probe, &key.public())
            .map_err(|_| SourceError::Credential)?;
        let issued_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| SourceError::Credential)?
            .as_secs();
        let issued_at = i64::try_from(issued_at).map_err(|_| SourceError::Credential)?;
        sign_client_assertion(
            &key,
            &ClientAssertionRequest {
                client_id,
                audience,
                lifetime_seconds: DEFAULT_ASSERTION_LIFETIME_SECONDS,
                issued_at,
            },
        )
        .map_err(|_| SourceError::Credential)
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

/// Build an Authorization value from a scheme name and a resolved token.
///
/// The scheme is already an HTTP token by the time it arrives, so the only
/// value that can carry a space or a line break into the header is the
/// credential, which `sensitive_header` refuses.
fn scheme_authorization(scheme: &str, token: &[u8]) -> Result<HeaderValue, SourceError> {
    if token.is_empty() {
        return Err(SourceError::Credential);
    }
    let mut header = Zeroizing::new(Vec::with_capacity(scheme.len() + 1 + token.len()));
    header.extend_from_slice(scheme.as_bytes());
    header.push(b' ');
    header.extend_from_slice(token);
    sensitive_header(&header)
}

/// RFC 6750 fixes the scheme an OAuth access token is presented under, so the
/// token the runtime acquires itself is never configurable.
fn bearer_authorization(token: &[u8]) -> Result<HeaderValue, SourceError> {
    scheme_authorization(DEFAULT_AUTHORIZATION_SCHEME, token)
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
    assumed_lifetime: Option<Duration>,
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
    // RFC 6749 section 5.1 makes `expires_in` recommended rather than required.
    // A provider that omits it is accepted only when the bundle states the
    // lifetime to assume; a present but unusable value is never rescued by it.
    let lifetime = match object.remove("expires_in") {
        Some(JsonValue::Number(value)) => Duration::from_secs(
            value
                .as_u64()
                .filter(|seconds| *seconds > 0)
                .ok_or(SourceError::Credential)?,
        ),
        Some(_) => return Err(SourceError::Credential),
        None => assumed_lifetime.ok_or(SourceError::Credential)?,
    };
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
    // RFC 6749 section 5.1 permits members beyond the ones it defines, and
    // deployed authorization servers send them: `refresh_expires_in` and
    // `not-before-policy` from Keycloak, `ext_expires_in` from Entra ID.
    // Refusing them would refuse the providers Evidence is documented against.
    //
    // Ignoring is not trusting. Nothing here reads an unread member, no script
    // ever sees the token response, and `parse_strict_json` refuses duplicate
    // members, so an extension cannot arrive as a second `access_token`. What
    // remains is that one of them may carry credential material of its own, so
    // scrub the strings before the map is dropped rather than leaving them for
    // the allocator, the same reason the response bytes are zeroized above.
    for (_, value) in &mut object {
        if let JsonValue::String(value) = value {
            value.zeroize();
        }
    }
    drop(object);
    Ok((ProtectedToken::from_string(access_token)?, lifetime))
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
    if !value.bytes().all(is_uri_byte) {
        return Err(SourceError::InvalidPlan);
    }
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
        assert_eq!(
            encode_path_prior_fact(&json!("record 1")),
            Ok("record%201".into())
        );
        for value in [json!(".."), json!("a/b"), json!(["record-1"]), json!(null)] {
            assert_eq!(
                encode_path_prior_fact(&value),
                Err(SourceError::InvalidPlan)
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
                "kind": "static-authorization",
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
            "responseSchema": "schemas/response.schema.yaml",
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
            .http_concurrency()
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
                    &PreparedSourceRequest::Http(RequestParts {
                        query: Vec::new(),
                        body: Some(json!({"requested": true})),
                    }),
                    Utc::now(),
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
                "kind": "static-authorization",
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
            "responseSchema": "schemas/response.schema.yaml",
            "extractScript": "adapters/extract.rhai",
            "factSchema": "schemas/facts.schema.yaml"
        }))
        .expect("source config deserializes");
        let client = build_client(
            Duration::from_secs(5),
            source.tls_trust_profile(),
            None,
            false,
        )
        .expect("client builds");
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
            client_authentication: OauthClientAuthentication::ClientSecret {
                secret_ref: SecretRef::parse("secret:file/missing-client-secret")
                    .expect("secret reference parses"),
                placement: CredentialPlacement::FormBody,
            },
            scope: Some("fixture.read".into()),
            audience: None,
            maximum_cache_lifetime: Duration::from_secs(60),
            assumed_lifetime: None,
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

    /// `expires_in` is measured from issuance, which happens at the authorization
    /// server while the token request is still in flight. Anchoring the cache
    /// deadline after the response has arrived and been parsed adds the whole
    /// round trip to the token's apparent life, so a cached token stays eligible
    /// past the point the issuer stops honouring it and a request near that
    /// boundary intermittently fails with 401. The anchor has to be taken before
    /// the request goes out: that is the earliest moment issuance can have
    /// happened, and so the only conservative choice available to a client.
    #[tokio::test]
    async fn the_oauth_cache_deadline_excludes_the_token_round_trip() {
        use std::fs;
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let secret_root = tempfile::tempdir().expect("temporary secret root");
        for (name, value) in [
            ("oauth-client-id", "fixture-client"),
            ("oauth-client-secret", "fixture-secret"),
        ] {
            let path = secret_root.path().join(name);
            fs::write(&path, value).expect("write synthetic secret");
            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("protect synthetic secret");
        }
        let secrets =
            SecretResolver::new([crate::secrets::SecretProvider::File], secret_root.path())
                .expect("secret resolver builds");

        // Stands in for round-trip latency. It only has to separate the two
        // candidate anchors by more than the slack allowed below.
        let latency = Duration::from_millis(500);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_delay(latency)
                    .set_body_json(json!({
                        "access_token": "fixture-access-token",
                        "token_type": "Bearer",
                        "expires_in": 1
                    })),
            )
            .mount(&server)
            .await;

        let plan = OauthPlan {
            token_endpoint: Url::parse(&format!("{}/token", server.uri()))
                .expect("token endpoint parses"),
            client_id_ref: SecretRef::parse("secret:file/oauth-client-id")
                .expect("secret reference parses"),
            client_authentication: OauthClientAuthentication::ClientSecret {
                secret_ref: SecretRef::parse("secret:file/oauth-client-secret")
                    .expect("secret reference parses"),
                placement: CredentialPlacement::FormBody,
            },
            scope: None,
            audience: None,
            maximum_cache_lifetime: Duration::from_secs(60),
            assumed_lifetime: None,
            admission_timeout: Duration::from_secs(5),
            cache: Mutex::new(None),
        };
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("HTTP client builds");

        let before = Instant::now();
        plan.access_token(&client, &secrets)
            .await
            .expect("the token exchange succeeds");
        let elapsed = before.elapsed();
        assert!(
            elapsed >= latency,
            "the round trip has to be delayed for this test to tell the anchors apart, took {elapsed:?}"
        );

        let expires_at = plan
            .cache
            .lock()
            .await
            .as_ref()
            .expect("the token is cached")
            .expires_at;
        // The slack covers only what happens between `before` and the request
        // going out: taking the mutex and reading two secret files. Half the
        // measured round trip is the bound rather than a fixed figure, because
        // a fixed one has to be picked for the slowest host this ever runs on
        // and a loaded runner will still beat it eventually. The two candidate
        // anchors are a whole round trip apart, and a host slow enough to spend
        // half of one on two file reads has inflated the round trip it is being
        // measured against by the same stall, so the bound moves with it while
        // staying below where the wrong anchor would put the deadline.
        let slack = elapsed / 2;
        assert!(
            expires_at <= before + Duration::from_secs(1) + slack,
            "the cache deadline outlives the token by about the round trip: \
             deadline is {:?} past the anchor, round trip took {elapsed:?}",
            expires_at.saturating_duration_since(before + Duration::from_secs(1))
        );
    }
}
