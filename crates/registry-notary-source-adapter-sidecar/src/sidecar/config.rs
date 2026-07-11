use super::*;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub audit: SidecarAuditConfig,
    #[serde(default)]
    pub config_trust: Option<SidecarConfigTrustConfig>,
    pub limits: LimitConfig,
    pub sources: BTreeMap<String, SourceConfig>,
    #[serde(default)]
    pub assurance: Option<SidecarAssurance>,
    #[serde(skip)]
    pub(super) governed_acceptance: Option<GovernedAcceptance>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_request_body_timeout_ms")]
    pub request_body_timeout_ms: u64,
    #[serde(default = "default_http1_header_read_timeout_ms")]
    pub http1_header_read_timeout_ms: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// When `true`, the `/metrics` endpoint requires the same bearer token as
    /// other protected endpoints. Defaults to `false` so existing Prometheus
    /// scrapers that poll `/metrics` without authentication continue to work.
    #[serde(default)]
    pub metrics_require_auth: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub bearer_tokens: Vec<BearerTokenConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarAuditConfig {
    #[serde(default = "default_sidecar_audit_sink")]
    pub sink: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub hash_secret_env: Option<String>,
    #[serde(default)]
    pub max_size_mb: Option<u64>,
    #[serde(default)]
    pub max_files: Option<u32>,
}

impl Default for SidecarAuditConfig {
    fn default() -> Self {
        Self {
            sink: default_sidecar_audit_sink(),
            path: None,
            hash_secret_env: None,
            max_size_mb: None,
            max_files: None,
        }
    }
}

impl SidecarAuditConfig {
    const DEFAULT_MAX_SIZE_MB: u64 = 100;
    const DEFAULT_MAX_FILES: u32 = 14;

    pub(super) fn max_size_bytes(&self) -> u64 {
        self.max_size_mb.unwrap_or(Self::DEFAULT_MAX_SIZE_MB) * 1024 * 1024
    }

    pub(super) fn max_files(&self) -> u32 {
        self.max_files.unwrap_or(Self::DEFAULT_MAX_FILES)
    }
}

pub(super) fn default_sidecar_audit_sink() -> String {
    "none".to_string()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarConfigTrustConfig {
    pub product: String,
    pub instance_id: String,
    pub environment: String,
    pub stream_id: String,
    pub root_path: PathBuf,
    pub metadata_dir: PathBuf,
    pub targets_dir: PathBuf,
    pub datastore_dir: PathBuf,
    pub target_name: String,
    pub antirollback_state_path: PathBuf,
    #[serde(default)]
    pub accepted_roots: Vec<Value>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BearerTokenConfig {
    pub id: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub hash_env: Option<String>,
}

impl fmt::Debug for BearerTokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerTokenConfig")
            .field("id", &self.id)
            .field("token", &"<redacted>")
            .field("hash_env", &self.hash_env)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitConfig {
    pub max_workers: usize,
    pub worker_timeout_ms: u64,
    pub max_output_bytes: usize,
    pub max_request_bytes: usize,
    pub max_query_parameter_bytes: usize,
    #[serde(default = "default_liveness_window_ms")]
    pub liveness_window_ms: u64,
    #[serde(default = "default_retry_after_seconds")]
    pub retry_after_seconds: u64,
    #[serde(default = "default_max_batch_items")]
    pub max_batch_items: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_timeout_ms: Option<u64>,
    pub max_worker_memory_mb: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    pub dataset: String,
    pub entity: String,
    #[serde(default)]
    pub engine: SourceEngine,
    #[serde(default)]
    pub credential_env: String,
    #[serde(default)]
    pub credential_public_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "SourceBatchConfig::is_default")]
    pub batch: SourceBatchConfig,
    #[serde(default, skip_serializing_if = "SourceRuntimeLimitConfig::is_default")]
    pub limits: SourceRuntimeLimitConfig,
    #[serde(default)]
    pub allowed_base_urls: Vec<String>,
    #[serde(default)]
    pub allow_insecure_localhost: bool,
    #[serde(default)]
    pub allow_insecure_private_network: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_json: Option<HttpJsonSourceConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_flow: Option<HttpFlowSourceConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fhir: Option<FhirSourceConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rhai: Option<RhaiScriptConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<SourceCacheConfig>,
    #[serde(default)]
    pub smoke_lookup: Option<SmokeLookupConfig>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceEngine {
    #[default]
    HttpJson,
    HttpFlow,
    Fhir,
    ScriptRhai,
}

impl SourceEngine {
    pub(super) fn worker_id(self) -> &'static str {
        match self {
            SourceEngine::HttpJson => "http_json",
            SourceEngine::HttpFlow => "http_flow",
            SourceEngine::Fhir => "fhir",
            SourceEngine::ScriptRhai => "script_rhai",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FhirSourceConfig {
    #[serde(default = "default_fhir_version")]
    pub version: String,
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token_env: Option<String>,
    #[serde(default = "default_true")]
    pub forward_data_purpose: bool,
    #[serde(default = "default_fhir_search_method")]
    pub search_method: String,
    #[serde(default = "default_fhir_prefer_handling")]
    pub prefer_handling: String,
    #[serde(default = "default_fhir_accept")]
    pub accept: String,
    #[serde(default = "default_fhir_max_search_results")]
    pub max_search_results: usize,
    #[serde(default = "default_fhir_max_source_bundle_bytes")]
    pub max_source_bundle_bytes: usize,
    pub anchor: FhirNodeConfig,
    #[serde(default)]
    pub relations: Vec<FhirRelationConfig>,
    #[serde(default)]
    pub project: BTreeMap<String, FhirProjectionConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FhirNodeConfig {
    pub id: String,
    pub resource_type: String,
    #[serde(default = "default_fhir_cardinality_one")]
    pub cardinality: String,
    #[serde(default)]
    pub search: Vec<FhirSearchParamConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FhirRelationConfig {
    pub id: String,
    pub resource_type: String,
    #[serde(default = "default_fhir_cardinality_one")]
    pub cardinality: String,
    #[serde(default)]
    pub search: Vec<FhirSearchParamConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FhirSearchParamConfig {
    pub param: String,
    #[serde(rename = "type")]
    pub search_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_from_lookup: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_from_query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_from_node: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FhirProjectionConfig {
    pub node: String,
    pub pointer: String,
    #[serde(default, rename = "default", skip_serializing_if = "Option::is_none")]
    pub default_value: Option<Value>,
}

/// Configuration for the `script_rhai` engine: an inline sandboxed Rhai script
/// plus the set of named upstream targets it may reach. The script resolves a
/// lookup by calling explicit `source.*` capabilities against these targets;
/// all outbound machinery (allow-listing, SSRF policy, auth, rate limiting) is
/// reused from the `http_json` path and never exposed to the script.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RhaiScriptConfig {
    /// Inline Rhai source (v1: inline only).
    pub script: String,
    /// The entrypoint function name. Defaults to `lookup`.
    #[serde(default = "default_rhai_entrypoint")]
    pub entrypoint: String,
    /// Sandbox resource/budget limits mapped to the engine policy.
    #[serde(default, skip_serializing_if = "RhaiLimitsConfig::is_default")]
    pub limits: RhaiLimitsConfig,
    /// The named upstream targets the script may select. Must be non-empty.
    pub targets: BTreeMap<String, RhaiTargetConfig>,
}

/// A single named upstream target a `script_rhai` script may call. The
/// `base_url` must appear in the source's `allowed_base_urls`; auth reuses the
/// `http_json` credential machinery.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RhaiTargetConfig {
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<HttpJsonAuthConfig>,
    /// Static request headers added to every call to this target (e.g. `Accept`
    /// or a vendor API-version header). Values are non-secret config and flow
    /// through the governed `config_hash`. Restricted headers (auth, cookie,
    /// host, hop-by-hop, forwarding) are rejected at validation; credentials
    /// belong in `auth`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Non-2xx statuses this target's responses the script is allowed to
    /// observe (rather than terminating the run). Per-target; the engine is
    /// compiled with the union across all targets and the per-target gate is
    /// applied in the host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visible_statuses: Vec<u16>,
}

/// Sandbox limits for a `script_rhai` source. Every field defaults to the
/// matching value from the rhai engine's `RhaiPolicy::default()` /
/// `RhaiLimits::default()`, so an omitted `limits` block yields the engine's
/// own defaults. `max_modules` is always `0` (module loading is forbidden) and
/// is therefore not configurable here.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RhaiLimitsConfig {
    #[serde(default = "default_rhai_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_rhai_max_http_calls")]
    pub max_http_calls: u32,
    #[serde(default = "default_rhai_max_output_bytes")]
    pub max_output_bytes: usize,
    #[serde(default = "default_rhai_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default = "default_rhai_max_operations")]
    pub max_operations: u64,
    #[serde(default = "default_rhai_max_call_levels")]
    pub max_call_levels: usize,
    #[serde(default = "default_rhai_max_string_bytes")]
    pub max_string_bytes: usize,
    #[serde(default = "default_rhai_max_array_items")]
    pub max_array_items: usize,
    #[serde(default = "default_rhai_max_map_entries")]
    pub max_map_entries: usize,
}

impl Default for RhaiLimitsConfig {
    fn default() -> Self {
        let policy = RhaiPolicy::default();
        let limits = RhaiLimits::default();
        Self {
            timeout_ms: policy.timeout.as_millis() as u64,
            max_http_calls: policy.max_http_calls,
            max_output_bytes: policy.max_output_bytes,
            max_concurrent: policy.max_concurrent,
            max_operations: limits.max_operations,
            max_call_levels: limits.max_call_levels,
            max_string_bytes: limits.max_string_bytes,
            max_array_items: limits.max_array_items,
            max_map_entries: limits.max_map_entries,
        }
    }
}

impl RhaiLimitsConfig {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// Build the engine policy from these limits. `visible_statuses` is the
    /// union of every target's observable statuses; `max_modules` is always 0.
    pub(super) fn to_policy(&self, visible_statuses: BTreeSet<u16>) -> RhaiPolicy {
        RhaiPolicy {
            limits: RhaiLimits {
                max_operations: self.max_operations,
                max_call_levels: self.max_call_levels,
                max_string_bytes: self.max_string_bytes,
                max_array_items: self.max_array_items,
                max_map_entries: self.max_map_entries,
                max_modules: 0,
            },
            timeout: Duration::from_millis(self.timeout_ms),
            max_http_calls: self.max_http_calls,
            max_output_bytes: self.max_output_bytes,
            max_concurrent: self.max_concurrent,
            visible_statuses,
        }
    }
}

pub(super) fn default_rhai_entrypoint() -> String {
    "lookup".into()
}

pub(super) fn default_rhai_timeout_ms() -> u64 {
    RhaiPolicy::default().timeout.as_millis() as u64
}

pub(super) fn default_rhai_max_http_calls() -> u32 {
    RhaiPolicy::default().max_http_calls
}

pub(super) fn default_rhai_max_output_bytes() -> usize {
    RhaiPolicy::default().max_output_bytes
}

pub(super) fn default_rhai_max_concurrent() -> usize {
    RhaiPolicy::default().max_concurrent
}

pub(super) fn default_rhai_max_operations() -> u64 {
    RhaiLimits::default().max_operations
}

pub(super) fn default_rhai_max_call_levels() -> usize {
    RhaiLimits::default().max_call_levels
}

pub(super) fn default_rhai_max_string_bytes() -> usize {
    RhaiLimits::default().max_string_bytes
}

pub(super) fn default_rhai_max_array_items() -> usize {
    RhaiLimits::default().max_array_items
}

pub(super) fn default_rhai_max_map_entries() -> usize {
    RhaiLimits::default().max_map_entries
}

/// The union of every target's `visible_statuses`, used to compile the engine
/// so it surfaces any status some target allows. Per-target gating is then
/// applied in the host (see `execute_rhai`).
pub(super) fn rhai_union_visible_statuses(rhai: &RhaiScriptConfig) -> BTreeSet<u16> {
    rhai.targets
        .values()
        .flat_map(|target| target.visible_statuses.iter().copied())
        .collect()
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBatchConfig {
    #[serde(default)]
    pub mode: SourceBatchMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_parallel: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceBatchMode {
    #[default]
    SequentialLookup,
    WorkflowBatch,
    ParallelLookup,
    NativeBatch,
}

impl SourceBatchConfig {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRuntimeLimitConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_in_flight: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_second: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u64>,
}

impl SourceRuntimeLimitConfig {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpJsonSourceConfig {
    #[serde(default)]
    pub method: HttpJsonMethod,
    pub base_url: HttpJsonCelExpression,
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, HttpJsonCelExpression>,
    #[serde(default)]
    pub headers: BTreeMap<String, HttpJsonCelExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<HttpJsonAuthConfig>,
    pub response: HttpJsonResponseConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<HttpJsonBatchConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCacheConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_match_ttl_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_found_ttl_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpJsonMethod {
    #[default]
    Get,
    Post,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpJsonCelExpression {
    pub cel: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpJsonAuthConfig {
    #[serde(rename = "type")]
    pub kind: HttpJsonAuthKind,
    /// The secret credential field used as the bearer token (`bearer`) or the
    /// API-key value (`api_key_header` / `api_key_query`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<HttpJsonSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<HttpJsonSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<HttpJsonSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<HttpJsonSecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<HttpJsonSecretRef>,
    /// OAuth2 client-credentials token endpoint. The URL must be explicitly
    /// present in `allowed_base_urls`, just like ordinary source targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    /// OAuth2 token request body format. Defaults to form when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Seconds to subtract from `expires_in` when caching OAuth2 access tokens.
    /// Defaults to 60 when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_skew_seconds: Option<u64>,
    /// Header name carrying the API key for `api_key_header` (e.g. `X-API-Key`).
    /// The value is the resolved `token` secret. Restricted headers (auth,
    /// cookie, host, hop-by-hop, forwarding) are rejected at validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// Query-parameter name carrying the API key for `api_key_query` (e.g.
    /// `api_key`). The value is the resolved `token` secret; it is appended to
    /// the request URL by the host and is never logged or used in cache keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_param: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpJsonAuthKind {
    Bearer,
    Basic,
    /// Send the `token` secret in a configured request header (`header`).
    ApiKeyHeader,
    /// Send the `token` secret in a configured query parameter (`query_param`).
    ApiKeyQuery,
    /// Fetch a host-owned bearer token via OAuth2 client credentials.
    #[serde(rename = "oauth2_client_credentials")]
    OAuth2ClientCredentials,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpJsonSecretRef {
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpJsonResponseConfig {
    pub records: HttpJsonCelExpression,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpJsonBatchConfig {
    #[serde(default)]
    pub method: HttpJsonMethod,
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, HttpJsonCelExpression>,
    #[serde(default)]
    pub headers: BTreeMap<String, HttpJsonCelExpression>,
    pub response: HttpJsonBatchResponseConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpJsonBatchResponseConfig {
    pub records: HttpJsonCelExpression,
    pub record_key: HttpJsonCelExpression,
    pub item_key: HttpJsonCelExpression,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpFlowSourceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_steps: Option<usize>,
    pub steps: Vec<HttpFlowStepConfig>,
    pub output: HttpFlowOutputConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpFlowStepConfig {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<HttpJsonCelExpression>,
    pub request: HttpFlowRequestConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<HttpFlowResponseConfig>,
    #[serde(default)]
    pub on_status: BTreeMap<String, HttpFlowStatusAction>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpFlowRequestConfig {
    #[serde(default)]
    pub method: HttpJsonMethod,
    pub base_url: String,
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, HttpJsonCelExpression>,
    #[serde(default)]
    pub headers: BTreeMap<String, HttpJsonCelExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<HttpJsonAuthConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpFlowResponseConfig {
    #[serde(default)]
    pub bind: BTreeMap<String, HttpJsonCelExpression>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpFlowOutputConfig {
    pub records: HttpJsonCelExpression,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpFlowStatusAction {
    Continue,
    SourceUnavailable,
    TargetAuth,
    TargetRateLimit,
    Timeout,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarAssurance {
    pub status: String,
    pub product: String,
    pub instance_id: String,
    pub environment: String,
    pub stream_id: String,
    pub bundle_id: String,
    pub sequence: u64,
    pub config_hash: String,
    pub signer_kids: Vec<String>,
    pub expression_hashes_verified: bool,
    pub runtime_verified: bool,
    pub smoke_verified: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeLookupConfig {
    pub field: String,
    pub value: String,
    #[serde(default)]
    pub query_values: BTreeMap<String, String>,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default = "default_smoke_purpose")]
    pub purpose: String,
}

pub(super) fn default_liveness_window_ms() -> u64 {
    30_000
}

pub(super) fn default_retry_after_seconds() -> u64 {
    1
}

pub(super) fn default_max_batch_items() -> usize {
    100
}

pub(super) const MAX_URI_BYTES: usize = 8 * 1024;
pub(super) const DEFAULT_SOURCE_CACHE_MAX_ENTRIES: usize = 10_000;

pub(super) fn default_request_timeout_ms() -> u64 {
    30_000
}

pub(super) fn default_request_body_timeout_ms() -> u64 {
    10_000
}

pub(super) fn default_http1_header_read_timeout_ms() -> u64 {
    10_000
}

pub(super) fn default_max_connections() -> usize {
    1024
}

pub(super) fn default_smoke_purpose() -> String {
    "startup-readiness-smoke".to_string()
}

pub(super) fn default_fhir_version() -> String {
    "R4".to_string()
}

pub(super) fn default_fhir_search_method() -> String {
    "get".to_string()
}

pub(super) fn default_fhir_prefer_handling() -> String {
    "strict".to_string()
}

pub(super) fn default_fhir_accept() -> String {
    "application/fhir+json".to_string()
}

pub(super) const fn default_true() -> bool {
    true
}

pub(super) const fn default_fhir_max_search_results() -> usize {
    2
}

pub(super) const fn default_fhir_max_source_bundle_bytes() -> usize {
    5 * 1024 * 1024
}

pub(super) fn default_fhir_cardinality_one() -> String {
    "one".to_string()
}
