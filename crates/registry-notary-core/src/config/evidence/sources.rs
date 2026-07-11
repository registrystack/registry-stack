// SPDX-License-Identifier: Apache-2.0
//! Source connection and dependent-lookup configuration.

use super::*;

/// A source connection fetches over an insecure URL when its base URL is plain
/// `http://` and no localhost or private-network escape hatch is enabled.
///
/// The escape hatches (`allow_insecure_localhost`, `allow_insecure_private_network`)
/// are reported by their own gate, so this predicate covers only the case of an
/// insecure URL on the strict outbound policy.
pub(in crate::config) fn source_connection_uses_insecure_url(
    connection: &SourceConnectionConfig,
) -> bool {
    let base = connection.base_url.trim();
    base.starts_with("http://")
        && !connection.allow_insecure_localhost
        && !connection.allow_insecure_private_network
}

/// A parsed dependent source-lookup reference of the form
/// `sources.<binding>.<field>` (the `source.` prefix is an accepted alias).
/// `field_path` may be a dotted path into nested JSON on the referenced source
/// row. Both the config validator and the runtime enforcer parse references
/// through [`parse_source_lookup_reference`] so they can never disagree about
/// what counts as a dependent reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLookupReference<'a> {
    pub binding_id: &'a str,
    pub field_path: &'a str,
}

#[must_use]
pub fn parse_source_lookup_reference(input: &str) -> Option<SourceLookupReference<'_>> {
    let remainder = input
        .strip_prefix("sources.")
        .or_else(|| input.strip_prefix("source."))?;
    let (binding_id, field_path) = remainder.split_once('.')?;
    if binding_id.is_empty() || field_path.is_empty() {
        return None;
    }
    Some(SourceLookupReference {
        binding_id,
        field_path,
    })
}

pub(in crate::config) fn source_lookup_dependencies(
    claim: &str,
    binding: &str,
    source_binding: &SourceBindingConfig,
    source_bindings: &BTreeMap<String, SourceBindingConfig>,
) -> Result<BTreeSet<String>, EvidenceConfigError> {
    let mut dependencies = BTreeSet::new();
    let inputs = std::iter::once(source_binding.lookup.input.as_str()).chain(
        source_binding
            .query_fields
            .iter()
            .map(|field| field.input.as_str()),
    );
    for input in inputs {
        let Some(reference) = parse_source_lookup_reference(input) else {
            continue;
        };
        let referenced_binding = reference.binding_id;
        if !source_bindings.contains_key(referenced_binding) {
            return Err(EvidenceConfigError::UnknownSourceLookupBinding {
                claim: claim.to_string(),
                binding: binding.to_string(),
                input: input.to_string(),
                unknown: referenced_binding.to_string(),
            });
        }
        dependencies.insert(referenced_binding.to_string());
    }
    Ok(dependencies)
}

/// Detect a dependency cycle in a binding dependency graph using Kahn's
/// algorithm. Returns `None` when the graph is acyclic, otherwise `Some` with
/// the sorted set of bindings that could not be resolved (those participating
/// in or blocked by a cycle).
///
/// Shared by config-time validation and runtime enforcement so the two can
/// never disagree about which graphs are acceptable. Precondition: every
/// referenced binding exists as a key in the map (callers verify references
/// first), so a non-empty remainder here is necessarily a cycle, including a
/// self-reference.
#[must_use]
pub fn detect_dependency_cycle(
    dependencies_by_binding: &BTreeMap<String, BTreeSet<String>>,
) -> Option<Vec<String>> {
    let mut pending: BTreeSet<String> = dependencies_by_binding.keys().cloned().collect();
    let mut resolved = BTreeSet::new();
    while !pending.is_empty() {
        let ready: Vec<String> = pending
            .iter()
            .filter_map(|id| {
                let dependencies = dependencies_by_binding.get(id)?;
                dependencies
                    .iter()
                    .all(|dependency| resolved.contains(dependency))
                    .then_some(id.clone())
            })
            .collect();
        if ready.is_empty() {
            return Some(pending.into_iter().collect());
        }
        for id in ready {
            pending.remove(&id);
            resolved.insert(id);
        }
    }
    None
}

pub(in crate::config) fn validate_source_lookup_dependency_graph(
    claim: &str,
    dependencies_by_binding: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), EvidenceConfigError> {
    match detect_dependency_cycle(dependencies_by_binding) {
        Some(bindings) => Err(EvidenceConfigError::SourceLookupDependencyCycle {
            claim: claim.to_string(),
            bindings,
        }),
        None => Ok(()),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBindingConfig {
    pub connector: SourceConnectorKind,
    #[serde(default)]
    pub connection: Option<String>,
    #[serde(default)]
    pub required_scope: Option<String>,
    pub dataset: String,
    pub entity: String,
    pub lookup: SourceLookupConfig,
    #[serde(default)]
    pub query_fields: Vec<SourceQueryFieldConfig>,
    #[serde(default)]
    pub fields: BTreeMap<String, SourceFieldConfig>,
    #[serde(default)]
    pub matching: SourceMatchingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryFieldConfig {
    pub input: String,
    pub field: String,
    #[serde(default = "default_lookup_op")]
    pub op: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConnectionConfig {
    pub base_url: String,
    /// Development escape hatch for local demos and tests. Production source
    /// fetches stay on the strict outbound URL policy by default.
    #[serde(default)]
    pub allow_insecure_localhost: bool,
    /// Development escape hatch for Docker Compose and other private-network
    /// demos. This permits HTTP and private RFC1918 targets, while still
    /// blocking cloud metadata endpoints. Leave false for production.
    #[serde(default)]
    pub allow_insecure_private_network: bool,
    #[serde(default)]
    pub token_env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_auth: Option<SourceAuthConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sidecar: Option<ExpectedSidecarConfig>,
    #[serde(default)]
    pub dci: DciSourceConnectionConfig,
    /// Process-global cap on concurrent outbound requests to this connection.
    /// Enforced by a shared `Semaphore` so the notary cannot DOS an upstream
    /// regardless of inbound load. Must be >= 1.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: usize,
    /// Retry one time on transport errors or HTTP 5xx responses. Disable this
    /// for synchronous sidecars whose worker executions must not be repeated.
    #[serde(default = "default_retry_on_5xx")]
    pub retry_on_5xx: bool,
    /// Bulk-read mode for this connection. `none` (default) keeps the wire
    /// behavior of pre-Stage-3 deployments; `rda_in_filter` and
    /// `dci_batched_search` are connector-specific specializations.
    #[serde(default)]
    pub bulk_mode: BulkMode,
    /// Operator attestation that, for `rda_in_filter`, every subject's
    /// lookup value yields at most one upstream row. The runtime still
    /// guards against violations and falls back to per-subject reads if
    /// detected.
    #[serde(default)]
    pub bulk_mode_lookup_unique: bool,
    /// Upper bound on the per-call timeout for bulk `read_many` requests.
    /// The actual budget scales with batch size up to this cap.
    #[serde(default = "default_bulk_timeout_max_ms")]
    pub bulk_timeout_max_ms: u64,
}

impl SourceConnectionConfig {
    pub fn validate_auth(&self, connection_id: &str) -> Result<(), EvidenceConfigError> {
        let has_static_token = !self.token_env.trim().is_empty();
        if has_static_token && self.source_auth.is_some() {
            return Err(EvidenceConfigError::InvalidSourceAuthConfig {
                connection: connection_id.to_string(),
                reason: "token_env and source_auth are mutually exclusive".to_string(),
            });
        }
        if !has_static_token && self.source_auth.is_none() {
            return Err(EvidenceConfigError::InvalidSourceAuthConfig {
                connection: connection_id.to_string(),
                reason: "either token_env or source_auth must be configured".to_string(),
            });
        }
        if let Some(source_auth) = &self.source_auth {
            source_auth.validate(connection_id)?;
        }
        Ok(())
    }

    pub fn effective_dci(&self) -> Result<DciSourceConnectionConfig, EvidenceConfigError> {
        Ok(self.dci.clone())
    }

    pub fn validate_expected_sidecar(
        &self,
        connection_id: &str,
    ) -> Result<(), EvidenceConfigError> {
        let Some(expected) = &self.expected_sidecar else {
            return Ok(());
        };
        for (field, value) in [
            ("product", expected.product.as_str()),
            ("instance_id", expected.instance_id.as_str()),
            ("environment", expected.environment.as_str()),
            ("stream_id", expected.stream_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(EvidenceConfigError::InvalidExpectedSidecarConfig {
                    connection: connection_id.to_string(),
                    reason: format!("{field} must not be empty"),
                });
            }
        }
        validate_sha256_uri(&expected.config_hash).map_err(|reason| {
            EvidenceConfigError::InvalidExpectedSidecarConfig {
                connection: connection_id.to_string(),
                reason: format!("config_hash {reason}"),
            }
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSidecarConfig {
    pub product: String,
    pub instance_id: String,
    pub environment: String,
    pub stream_id: String,
    pub config_hash: String,
    #[serde(default)]
    pub require_expression_hashes_verified: bool,
    #[serde(default)]
    pub require_runtime_verified: bool,
    #[serde(default)]
    pub require_smoke_verified: bool,
    #[serde(default = "default_expected_sidecar_assurance_ttl_ms")]
    pub assurance_ttl_ms: u64,
}

pub(in crate::config) const fn default_expected_sidecar_assurance_ttl_ms() -> u64 {
    30_000
}

pub(in crate::config) fn validate_sha256_uri(value: &str) -> Result<(), &'static str> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err("must start with sha256:");
    };
    if hex.len() != 64 {
        return Err("must contain 64 lowercase hex characters");
    }
    if !hex
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("must contain only lowercase hex characters");
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceAuthConfig {
    Oauth2ClientCredentials(Oauth2ClientCredentialsSourceAuthConfig),
}

impl SourceAuthConfig {
    fn validate(&self, connection_id: &str) -> Result<(), EvidenceConfigError> {
        match self {
            SourceAuthConfig::Oauth2ClientCredentials(config) => config.validate(connection_id),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oauth2ClientCredentialsSourceAuthConfig {
    pub token_url: String,
    pub client_id_env: String,
    pub client_secret_env: String,
    #[serde(default = "default_oauth_request_format")]
    pub request_format: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default = "default_oauth_refresh_skew_seconds")]
    pub refresh_skew_seconds: u64,
}

impl Oauth2ClientCredentialsSourceAuthConfig {
    fn validate(&self, connection_id: &str) -> Result<(), EvidenceConfigError> {
        if self.token_url.trim().is_empty() {
            return Err(invalid_source_auth(
                connection_id,
                "token_url must not be empty",
            ));
        }
        if self.client_id_env.trim().is_empty() {
            return Err(invalid_source_auth(
                connection_id,
                "client_id_env must not be empty",
            ));
        }
        if self.client_secret_env.trim().is_empty() {
            return Err(invalid_source_auth(
                connection_id,
                "client_secret_env must not be empty",
            ));
        }
        if !matches!(self.request_format.as_str(), "json" | "form") {
            return Err(invalid_source_auth(
                connection_id,
                "request_format must be json or form",
            ));
        }
        Ok(())
    }
}

pub(in crate::config) fn default_oauth_request_format() -> String {
    "form".to_string()
}

pub(in crate::config) const fn default_oauth_refresh_skew_seconds() -> u64 {
    60
}

pub(in crate::config) fn invalid_source_auth(
    connection: &str,
    reason: &str,
) -> EvidenceConfigError {
    EvidenceConfigError::InvalidSourceAuthConfig {
        connection: connection.to_string(),
        reason: reason.to_string(),
    }
}

pub(in crate::config) const fn default_max_in_flight() -> usize {
    8
}

pub(in crate::config) const fn default_retry_on_5xx() -> bool {
    true
}

pub(in crate::config) const fn default_bulk_timeout_max_ms() -> u64 {
    30_000
}

/// Per-connection bulk-read mode. Default `None` preserves the existing wire
/// behavior; the other variants enable connector-specific request batching.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BulkMode {
    #[default]
    None,
    RdaInFilter,
    DciBatchedSearch,
    #[serde(rename = "source_adapter_sidecar_batch")]
    SourceAdapterSidecarBatch,
}

/// Per-request fan-out caps. `subjects=1, bindings=1` reproduces the strictly
/// sequential behavior that existed before Stage 1 of the scalability spec.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyConfig {
    #[serde(default = "default_concurrency_subjects")]
    pub subjects: usize,
    #[serde(default = "default_concurrency_bindings")]
    pub bindings: usize,
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            subjects: default_concurrency_subjects(),
            bindings: default_concurrency_bindings(),
        }
    }
}

impl ConcurrencyConfig {
    pub fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.subjects < 1 || self.bindings < 1 {
            return Err(EvidenceConfigError::InvalidConcurrency);
        }
        Ok(())
    }
}

pub(in crate::config) const fn default_concurrency_subjects() -> usize {
    16
}

pub(in crate::config) const fn default_concurrency_bindings() -> usize {
    8
}

/// Per-principal quota for machine `evaluate`/`batch_evaluate` traffic.
/// Budget is counted in subjects per principal over a fixed one-minute
/// window: a single `/v1/evaluations` call consumes 1, a batch consumes
/// `items.len()`. Disabled by default so existing deployments are unaffected.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineQuotaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_machine_quota_subjects_per_minute")]
    pub subjects_per_minute: u32,
}

impl Default for MachineQuotaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            subjects_per_minute: default_machine_quota_subjects_per_minute(),
        }
    }
}

impl MachineQuotaConfig {
    pub fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.enabled && self.subjects_per_minute == 0 {
            return Err(EvidenceConfigError::InvalidMachineQuotaConfig {
                reason: "subjects_per_minute must be greater than zero when enabled".to_string(),
            });
        }
        Ok(())
    }
}

pub(in crate::config) const fn default_machine_quota_subjects_per_minute() -> u32 {
    6000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DciSourceConnectionConfig {
    #[serde(default = "default_dci_search_path")]
    pub search_path: String,
    #[serde(default = "default_dci_sender_id")]
    pub sender_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_id: Option<String>,
    #[serde(default = "default_dci_query_type")]
    pub query_type: String,
    #[serde(default = "default_dci_records_path")]
    pub records_path: String,
    /// JSON-pointer to the records array INSIDE one `search_response[i]`
    /// entry, used by `read_many` for `dci_batched_search`. The default
    /// matches the shape produced by registry-relay (`/data/reg_records`).
    /// `read_one` continues to use `records_path` which addresses the full
    /// envelope and is hardcoded to index 0.
    #[serde(default = "default_dci_bulk_records_path")]
    pub bulk_records_path: String,
    #[serde(default = "default_dci_max_results")]
    pub max_results: usize,
    #[serde(default)]
    pub registry_type: Option<String>,
    #[serde(default)]
    pub registry_event_type: Option<String>,
    #[serde(default)]
    pub record_type: Option<String>,
    #[serde(default)]
    pub field_paths: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Default for DciSourceConnectionConfig {
    fn default() -> Self {
        Self {
            search_path: default_dci_search_path(),
            sender_id: default_dci_sender_id(),
            receiver_id: None,
            query_type: default_dci_query_type(),
            records_path: default_dci_records_path(),
            bulk_records_path: default_dci_bulk_records_path(),
            max_results: default_dci_max_results(),
            registry_type: None,
            registry_event_type: None,
            record_type: None,
            field_paths: BTreeMap::new(),
            signature: None,
        }
    }
}

pub(in crate::config) fn default_dci_search_path() -> String {
    "/registry/sync/search".to_string()
}

pub(in crate::config) fn default_dci_sender_id() -> String {
    "registry-notary".to_string()
}

pub(in crate::config) fn default_dci_query_type() -> String {
    "idtype-value".to_string()
}

pub(in crate::config) fn default_dci_records_path() -> String {
    "/message/search_response/0/data/reg_records".to_string()
}

pub(in crate::config) fn default_dci_bulk_records_path() -> String {
    "/data/reg_records".to_string()
}

pub(in crate::config) const fn default_dci_max_results() -> usize {
    2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceConnectorKind {
    RegistryDataApi,
    Dci,
    #[serde(rename = "source_adapter_sidecar")]
    SourceAdapterSidecar,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLookupConfig {
    pub input: String,
    pub field: String,
    #[serde(default = "default_lookup_op")]
    pub op: String,
    #[serde(default = "default_lookup_cardinality")]
    pub cardinality: String,
}

pub(in crate::config) fn default_lookup_op() -> String {
    "eq".to_string()
}

pub(in crate::config) fn default_lookup_cardinality() -> String {
    "one".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFieldConfig {
    pub field: String,
    #[serde(rename = "type", default)]
    pub field_type: Option<String>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub semantic_term: Option<String>,
}
