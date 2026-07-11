use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BatchMatchRequest {
    pub(super) fields: Vec<String>,
    pub(super) query_signature: Vec<BatchQueryTerm>,
    pub(super) items: Vec<BatchMatchItem>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BatchQueryTerm {
    pub(super) field: String,
    pub(super) op: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BatchMatchItem {
    pub(super) id: String,
    pub(super) values: Vec<Value>,
}

#[derive(Clone)]
pub(super) struct AppState {
    pub(super) config: Arc<SidecarConfig>,
    pub(super) auth_tokens: Arc<Vec<ResolvedBearerToken>>,
    pub(super) fhir_bearer_tokens: Arc<BTreeMap<String, String>>,
    pub(super) credentials: Arc<BTreeMap<String, Value>>,
    pub(super) source_limiters: Arc<BTreeMap<String, Arc<Semaphore>>>,
    pub(super) source_runtime: Arc<BTreeMap<String, Arc<SourceRuntimeState>>>,
    pub(super) http_json_clients: Arc<Mutex<BTreeMap<String, reqwest::Client>>>,
    pub(super) oauth2_tokens: Arc<Mutex<BTreeMap<String, CachedOAuth2Token>>>,
    pub(super) oauth2_token_locks: Arc<Mutex<BTreeMap<String, Arc<Mutex<()>>>>>,
    /// Compiled `script_rhai` engines, keyed by `source_id`. Each script is
    /// compiled once at startup and reused for every request; a compile failure
    /// is a configuration error that fails startup.
    pub(super) rhai_engines: Arc<BTreeMap<String, Arc<ScriptEngine>>>,
    pub(super) metrics: Arc<Mutex<BTreeMap<MetricKey, MetricValue>>>,
    pub(super) audit: Option<Arc<SidecarAuditPipeline>>,
}

#[derive(Clone)]
pub(super) struct CachedOAuth2Token {
    pub(super) access_token: String,
    pub(super) refresh_after: Instant,
}

pub(super) struct SourceRuntimeState {
    pub(super) source_config_hash: String,
    pub(super) rate_limiter: Option<Mutex<TokenBucket>>,
    pub(super) backoff_until: Mutex<Option<Instant>>,
    pub(super) cache: Mutex<BTreeMap<String, CacheEntry>>,
}

pub(super) struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_second: f64,
    last_refill: Instant,
}

pub(super) struct CacheEntry {
    pub(super) expires_at: Instant,
    pub(super) last_accessed: Instant,
    pub(super) value: Value,
}

impl SourceRuntimeState {
    pub(super) fn new(source: &SourceConfig) -> Result<Self, SidecarError> {
        let source_config_hash =
            registry_platform_config::sha256_uri(&serde_json::to_vec(source).map_err(|error| {
                SidecarError::Config(format!("source config hash failed: {error}"))
            })?);
        let limits = &source.limits;
        let rate_limiter = limits.requests_per_second.map(|requests_per_second| {
            let capacity = limits.burst.unwrap_or(requests_per_second).max(1) as f64;
            Mutex::new(TokenBucket {
                capacity,
                tokens: capacity,
                refill_per_second: requests_per_second.max(1) as f64,
                last_refill: Instant::now(),
            })
        });
        Ok(Self {
            source_config_hash,
            rate_limiter,
            backoff_until: Mutex::new(None),
            cache: Mutex::new(BTreeMap::new()),
        })
    }
}

impl TokenBucket {
    pub(super) fn try_take(&mut self, now: Instant) -> Result<(), Duration> {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let missing = 1.0 - self.tokens;
            let wait_seconds = (missing / self.refill_per_second).max(0.001);
            Err(Duration::from_secs_f64(wait_seconds))
        }
    }
}

#[derive(Clone)]
pub(super) struct ResolvedBearerToken {
    pub(super) fingerprint: String,
}

pub(super) struct SourceExecution {
    pub(super) value: Value,
    pub(super) worker_id: String,
}

pub(super) struct PreparedHttpJsonRequest {
    pub(super) url: reqwest::Url,
    pub(super) client: reqwest::Client,
}

// All variants are http_json-engine error categories; the shared prefix is
// intentional now that the older worker engine variants are retired. Renaming
// would churn ~110 call sites for no clarity.
#[allow(clippy::enum_variant_names)]
pub(super) enum SourceExecutionError {
    HttpJson,
    HttpJsonBadRequest,
    HttpJsonTimeout,
}
