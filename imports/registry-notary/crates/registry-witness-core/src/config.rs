// SPDX-License-Identifier: Apache-2.0
//! Registry Witness configuration model.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandaloneRegistryWitnessConfig {
    #[serde(default)]
    pub server: RegistryWitnessHttpConfig,
    pub evidence: EvidenceConfig,
    pub auth: EvidenceAuthConfig,
    #[serde(default)]
    pub audit: EvidenceAuditConfig,
}

impl StandaloneRegistryWitnessConfig {
    pub fn validate(&self) -> Result<(), EvidenceConfigError> {
        if !self.evidence.enabled {
            return Err(EvidenceConfigError::EvidenceDisabled);
        }
        match self.auth.mode.as_str() {
            "api_key" => {
                if self.auth.api_keys.is_empty() && self.auth.bearer_tokens.is_empty() {
                    return Err(EvidenceConfigError::NoCredentialsConfigured);
                }
            }
            "oidc" => {
                let oidc = self
                    .auth
                    .oidc
                    .as_ref()
                    .ok_or(EvidenceConfigError::MissingOidcConfig)?;
                oidc.validate()?;
            }
            _ => {
                return Err(EvidenceConfigError::UnsupportedAuthMode {
                    mode: self.auth.mode.clone(),
                });
            }
        }
        self.evidence.concurrency.validate()?;
        for connection in self.evidence.source_connections.values() {
            if connection.max_in_flight < 1 {
                return Err(EvidenceConfigError::InvalidConcurrency);
            }
        }
        // bulk_mode preconditions are enforced at config load so the runtime
        // never observes a misconfigured combination. rda_in_filter requires
        // operator attestation + cardinality=one on every binding pointing
        // at this connection. dci_batched_search requires the dci connector.
        for (connection_id, connection) in &self.evidence.source_connections {
            match connection.bulk_mode {
                BulkMode::None => {}
                BulkMode::RdaInFilter => {
                    if !connection.bulk_mode_lookup_unique {
                        return Err(EvidenceConfigError::BulkModeRequiresUniqueLookup {
                            connection: connection_id.clone(),
                        });
                    }
                    for claim in &self.evidence.claims {
                        for (binding_id, binding) in &claim.source_bindings {
                            if binding.connection.as_deref() != Some(connection_id.as_str()) {
                                continue;
                            }
                            if binding.lookup.cardinality != "one" {
                                return Err(EvidenceConfigError::BulkModeRequiresCardinalityOne {
                                    connection: connection_id.clone(),
                                    claim: claim.id.clone(),
                                    binding: binding_id.clone(),
                                });
                            }
                        }
                    }
                }
                BulkMode::DciBatchedSearch => {
                    for claim in &self.evidence.claims {
                        for (binding_id, binding) in &claim.source_bindings {
                            if binding.connection.as_deref() != Some(connection_id.as_str()) {
                                continue;
                            }
                            if binding.connector != SourceConnectorKind::Dci {
                                return Err(EvidenceConfigError::BulkModeRequiresDciConnector {
                                    connection: connection_id.clone(),
                                    claim: claim.id.clone(),
                                    binding: binding_id.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
        for claim in &self.evidence.claims {
            if claim.id.trim().is_empty() {
                return Err(EvidenceConfigError::InvalidClaim);
            }
            for binding in claim.source_bindings.values() {
                if binding.connection.is_none() {
                    return Err(EvidenceConfigError::MissingSourceConnection);
                }
                if !self
                    .evidence
                    .source_connections
                    .contains_key(binding.connection.as_deref().unwrap_or_default())
                {
                    return Err(EvidenceConfigError::MissingSourceConnection);
                }
            }
        }
        // Finding 3: when proof_of_possession is required, only did:jwk is
        // supported by holder_jwk(). Reject configs that list any other method
        // so the mismatch is caught at startup rather than at request time.
        for (profile_id, profile) in &self.evidence.credential_profiles {
            if profile.holder_binding.proof_of_possession.as_deref() == Some("required") {
                let unsupported: Vec<String> = profile
                    .holder_binding
                    .allowed_did_methods
                    .iter()
                    .filter(|m| m.as_str() != "did:jwk")
                    .cloned()
                    .collect();
                if !unsupported.is_empty() {
                    return Err(
                        EvidenceConfigError::UnsupportedDidMethodsForProofOfPossession {
                            profile: profile_id.clone(),
                            methods: unsupported,
                        },
                    );
                }
            }
            // An empty allowed_claims short-circuits the issuance-time filter
            // in api.rs (`is_empty()` means "any claim allowed"). Require
            // operators to enumerate the claims a profile may bind to. A list
            // composed only of blank entries is treated the same as empty so
            // operators cannot trip the short-circuit via `[""]`.
            if profile
                .allowed_claims
                .iter()
                .all(|claim| claim.trim().is_empty())
            {
                return Err(EvidenceConfigError::EmptyAllowedClaims {
                    profile: profile_id.clone(),
                });
            }
        }
        // Finding 8: detect cycles in the depends_on graph using DFS with
        // grey (in-progress) and black (done) sets.
        let claim_ids: HashSet<&str> = self.evidence.claims.iter().map(|c| c.id.as_str()).collect();
        for claim in &self.evidence.claims {
            for dep in &claim.depends_on {
                if !claim_ids.contains(dep.as_str()) {
                    return Err(EvidenceConfigError::DependsOnUnknownClaim {
                        claim: claim.id.clone(),
                        unknown: dep.clone(),
                    });
                }
            }
        }
        let mut grey: HashSet<String> = HashSet::new();
        let mut black: HashSet<String> = HashSet::new();
        for claim in &self.evidence.claims {
            if !black.contains(&claim.id) {
                detect_depends_on_cycle(
                    &self.evidence.claims,
                    &claim.id,
                    &mut grey,
                    &mut black,
                    &mut Vec::new(),
                )?;
            }
        }
        Ok(())
    }
}

fn detect_depends_on_cycle(
    claims: &[ClaimDefinition],
    claim_id: &str,
    grey: &mut HashSet<String>,
    black: &mut HashSet<String>,
    path: &mut Vec<String>,
) -> Result<(), EvidenceConfigError> {
    grey.insert(claim_id.to_string());
    path.push(claim_id.to_string());
    let claim = claims.iter().find(|c| c.id == claim_id);
    if let Some(claim) = claim {
        for dep in &claim.depends_on {
            if grey.contains(dep.as_str()) {
                // Back edge found: build the cycle path from where dep appears.
                let cycle_start = path.iter().position(|id| id == dep).unwrap_or(0);
                let mut cycle = path[cycle_start..].to_vec();
                cycle.push(dep.clone());
                return Err(EvidenceConfigError::DependsOnCycle { cycle });
            }
            if !black.contains(dep.as_str()) {
                detect_depends_on_cycle(claims, dep, grey, black, path)?;
            }
        }
    }
    path.pop();
    grey.remove(claim_id);
    black.insert(claim_id.to_string());
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryWitnessHttpConfig {
    #[serde(default = "default_bind_addr")]
    pub bind: SocketAddr,
    #[serde(default)]
    pub cors: RegistryWitnessCorsConfig,
}

impl Default for RegistryWitnessHttpConfig {
    fn default() -> Self {
        Self {
            bind: default_bind_addr(),
            cors: RegistryWitnessCorsConfig::default(),
        }
    }
}

fn default_bind_addr() -> SocketAddr {
    "127.0.0.1:8081"
        .parse()
        .expect("default bind address is valid")
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryWitnessCorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub allow_credentials: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuthConfig {
    #[serde(default = "default_auth_mode")]
    pub mode: String,
    #[serde(default)]
    pub api_keys: Vec<EvidenceCredentialConfig>,
    #[serde(default)]
    pub bearer_tokens: Vec<EvidenceCredentialConfig>,
    #[serde(default)]
    pub oidc: Option<EvidenceOidcAuthConfig>,
}

impl Default for EvidenceAuthConfig {
    fn default() -> Self {
        Self {
            mode: default_auth_mode(),
            api_keys: Vec::new(),
            bearer_tokens: Vec::new(),
            oidc: None,
        }
    }
}

fn default_auth_mode() -> String {
    "api_key".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCredentialConfig {
    pub id: String,
    pub hash_env: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceOidcAuthConfig {
    pub issuer: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    #[serde(default = "default_oidc_allowed_algorithms")]
    pub allowed_algorithms: Vec<String>,
    #[serde(default = "default_oidc_allowed_typ")]
    pub allowed_typ: Vec<String>,
    #[serde(default = "default_oidc_scope_claim")]
    pub scope_claim: String,
    #[serde(default = "default_oidc_scope_separator")]
    pub scope_separator: String,
    #[serde(default)]
    pub scope_map: BTreeMap<String, Vec<String>>,
    #[serde(default = "default_oidc_principal_claim")]
    pub principal_claim: String,
    #[serde(default = "default_oidc_leeway_seconds")]
    pub leeway_seconds: u64,
    #[serde(default)]
    pub allow_insecure_localhost: bool,
}

fn default_oidc_allowed_algorithms() -> Vec<String> {
    vec!["EdDSA".to_string()]
}

fn default_oidc_allowed_typ() -> Vec<String> {
    vec!["JWT".to_string()]
}

fn default_oidc_scope_claim() -> String {
    "scope".to_string()
}

fn default_oidc_scope_separator() -> String {
    " ".to_string()
}

fn default_oidc_principal_claim() -> String {
    "sub".to_string()
}

fn default_oidc_leeway_seconds() -> u64 {
    60
}

impl EvidenceOidcAuthConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.issuer.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "issuer must not be empty".to_string(),
            });
        }
        if self.jwks_uri.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "jwks_uri must not be empty".to_string(),
            });
        }
        if self.audiences.is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "audiences must list at least one accepted audience".to_string(),
            });
        }
        if self.scope_separator.chars().count() != 1 {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "scope_separator must be exactly one character".to_string(),
            });
        }
        if self.principal_claim.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "principal_claim must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuditConfig {
    #[serde(default = "default_audit_sink")]
    pub sink: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub hash_secret_env: Option<String>,
}

impl Default for EvidenceAuditConfig {
    fn default() -> Self {
        Self {
            sink: default_audit_sink(),
            path: None,
            hash_secret_env: None,
        }
    }
}

fn default_audit_sink() -> String {
    "stdout".to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceConfigError {
    #[error("evidence.enabled must be true for the standalone Registry Witness")]
    EvidenceDisabled,
    #[error("at least one API key or bearer token must be configured")]
    NoCredentialsConfigured,
    #[error("unsupported auth.mode '{mode}'; supported values are 'api_key' and 'oidc'")]
    UnsupportedAuthMode { mode: String },
    #[error("auth.mode = oidc requires an auth.oidc block")]
    MissingOidcConfig,
    #[error("invalid auth.oidc config: {reason}")]
    InvalidOidcConfig { reason: String },
    #[error("claim id must not be empty")]
    InvalidClaim,
    #[error("each standalone source binding must reference a configured source connection")]
    MissingSourceConnection,
    #[error(
        "concurrency.subjects, concurrency.bindings, and source_connection.max_in_flight \
         must all be >= 1"
    )]
    InvalidConcurrency,
    /// proof_of_possession = "required" only works with did:jwk because
    /// holder_jwk() only implements did:jwk resolution. Restrict
    /// allowed_did_methods to ["did:jwk"] or remove proof_of_possession.
    #[error(
        "credential profile '{profile}': proof_of_possession = \"required\" is only supported \
         with did:jwk, but allowed_did_methods contains unsupported method(s): {methods}; \
         restrict allowed_did_methods to [\"did:jwk\"] or remove proof_of_possession",
        methods = methods.join(", ")
    )]
    UnsupportedDidMethodsForProofOfPossession {
        profile: String,
        methods: Vec<String>,
    },
    #[error("claim '{claim}' depends_on unknown claim '{unknown}'")]
    DependsOnUnknownClaim { claim: String, unknown: String },
    #[error(
        "depends_on cycle detected: {cycle}",
        cycle = cycle.join(" -> ")
    )]
    DependsOnCycle { cycle: Vec<String> },
    /// A credential profile with an empty `allowed_claims` would short-circuit
    /// the issuance-time claim filter (api.rs treats empty as "all claims
    /// allowed"). Reject at load time so operators must explicitly enumerate
    /// the claims a profile may bind to.
    #[error(
        "credential profile '{profile}': allowed_claims must list at least one \
         claim; an empty list would permit any claim at issuance"
    )]
    EmptyAllowedClaims { profile: String },
    /// `rda_in_filter` requires the operator to attest that lookup values are
    /// unique per subject. Without this we cannot disambiguate per-subject
    /// rows from a single collection response.
    #[error(
        "source_connection '{connection}': bulk_mode = rda_in_filter requires \
         bulk_mode_lookup_unique = true (operator attestation that each \
         subject's lookup value yields at most one upstream row)"
    )]
    BulkModeRequiresUniqueLookup { connection: String },
    /// `rda_in_filter` requires every binding pointing at this connection to
    /// have `lookup.cardinality = one`. Bindings expecting many rows per
    /// subject cannot be batched into a single collection response.
    #[error(
        "source_connection '{connection}': bulk_mode = rda_in_filter requires \
         every binding (claim '{claim}', binding '{binding}') to set \
         lookup.cardinality = one"
    )]
    BulkModeRequiresCardinalityOne {
        connection: String,
        claim: String,
        binding: String,
    },
    /// `dci_batched_search` is DCI-specific. Bindings using the RDA connector
    /// against the same connection cannot be batched through the DCI search
    /// envelope.
    #[error(
        "source_connection '{connection}': bulk_mode = dci_batched_search \
         requires all bindings to use connector = dci (binding '{binding}' \
         in claim '{claim}' uses a different connector)"
    )]
    BulkModeRequiresDciConnector {
        connection: String,
        claim: String,
        binding: String,
    },
}

/// Registry Witness configuration. Disabled by default so existing
/// Registry Relay deployments load unchanged.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_service_id")]
    pub service_id: String,
    #[serde(default = "default_api_version")]
    pub api_version: String,
    #[serde(default = "default_api_base_url")]
    pub api_base_url: String,
    #[serde(default = "default_claims_url")]
    pub claims_url: String,
    #[serde(default = "default_formats_url")]
    pub formats_url: String,
    #[serde(default = "default_inline_batch_limit")]
    pub inline_batch_limit: usize,
    #[serde(default)]
    pub claims: Vec<ClaimDefinition>,
    #[serde(default)]
    pub credential_profiles: BTreeMap<String, CredentialProfileConfig>,
    #[serde(default)]
    pub source_connections: BTreeMap<String, SourceConnectionConfig>,
    /// Per-request fan-out caps. Setting both `subjects=1` and `bindings=1`
    /// reproduces today's strictly-sequential behavior (Stage 1 kill switch).
    #[serde(default)]
    pub concurrency: ConcurrencyConfig,
}

fn default_service_id() -> String {
    "registry-witness".to_string()
}

fn default_api_version() -> String {
    "2026-05".to_string()
}

fn default_api_base_url() -> String {
    "/".to_string()
}

fn default_claims_url() -> String {
    "/claims".to_string()
}

fn default_formats_url() -> String {
    "/formats".to_string()
}

const fn default_inline_batch_limit() -> usize {
    100
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimDefinition {
    pub id: String,
    pub title: String,
    pub version: String,
    pub subject_type: String,
    #[serde(default)]
    pub value: ClaimValueConfig,
    #[serde(default)]
    pub inputs: Vec<ClaimInputConfig>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub source_bindings: BTreeMap<String, SourceBindingConfig>,
    pub rule: RuleConfig,
    #[serde(default)]
    pub operations: ClaimOperationsConfig,
    #[serde(default)]
    pub disclosure: DisclosureConfig,
    #[serde(default)]
    pub formats: Vec<String>,
    #[serde(default)]
    pub credential_profiles: Vec<String>,
    #[serde(default)]
    pub cccev: Option<CccevConfig>,
    #[serde(default)]
    pub oots: Option<OotsConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimValueConfig {
    #[serde(rename = "type", default)]
    pub value_type: String,
    #[serde(default)]
    pub unit: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimInputConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub input_type: String,
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
    pub fields: BTreeMap<String, SourceFieldConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConnectionConfig {
    pub base_url: String,
    /// Development escape hatch for local demos and tests. Production source
    /// fetches stay on the strict outbound URL policy by default.
    #[serde(default)]
    pub allow_insecure_localhost: bool,
    pub token_env: String,
    #[serde(default)]
    pub dci: DciSourceConnectionConfig,
    /// Process-global cap on concurrent outbound requests to this connection.
    /// Enforced by a shared `Semaphore` so the witness cannot DOS an upstream
    /// regardless of inbound load. Must be >= 1.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: usize,
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

const fn default_max_in_flight() -> usize {
    8
}

const fn default_bulk_timeout_max_ms() -> u64 {
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

const fn default_concurrency_subjects() -> usize {
    16
}

const fn default_concurrency_bindings() -> usize {
    8
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DciSourceConnectionConfig {
    #[serde(default = "default_dci_search_path")]
    pub search_path: String,
    #[serde(default = "default_dci_sender_id")]
    pub sender_id: String,
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
    pub record_type: Option<String>,
    #[serde(default)]
    pub field_paths: BTreeMap<String, String>,
}

impl Default for DciSourceConnectionConfig {
    fn default() -> Self {
        Self {
            search_path: default_dci_search_path(),
            sender_id: default_dci_sender_id(),
            query_type: default_dci_query_type(),
            records_path: default_dci_records_path(),
            bulk_records_path: default_dci_bulk_records_path(),
            max_results: default_dci_max_results(),
            registry_type: None,
            record_type: None,
            field_paths: BTreeMap::new(),
        }
    }
}

fn default_dci_search_path() -> String {
    "/registry/sync/search".to_string()
}

fn default_dci_sender_id() -> String {
    "registry-witness".to_string()
}

fn default_dci_query_type() -> String {
    "idtype-value".to_string()
}

fn default_dci_records_path() -> String {
    "/message/search_response/0/data/reg_records".to_string()
}

fn default_dci_bulk_records_path() -> String {
    "/data/reg_records".to_string()
}

const fn default_dci_max_results() -> usize {
    2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceConnectorKind {
    RegistryDataApi,
    Dci,
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

fn default_lookup_op() -> String {
    "eq".to_string()
}

fn default_lookup_cardinality() -> String {
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleConfig {
    Extract {
        source: String,
        field: String,
    },
    Exists {
        source: String,
    },
    Cel {
        expression: String,
        #[serde(default)]
        bindings: CelBindingsConfig,
    },
    Plugin {
        plugin: String,
    },
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CelBindingsConfig {
    #[serde(default)]
    pub claims: BTreeMap<String, ClaimBindingConfig>,
    #[serde(default)]
    pub vars: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimBindingConfig {
    pub claim: String,
    #[serde(default)]
    pub binding_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimOperationsConfig {
    #[serde(default = "default_enabled_operation")]
    pub evaluate: OperationConfig,
    #[serde(default)]
    pub batch_evaluate: BatchOperationConfig,
}

impl Default for ClaimOperationsConfig {
    fn default() -> Self {
        Self {
            evaluate: OperationConfig { enabled: true },
            batch_evaluate: BatchOperationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationConfig {
    #[serde(default)]
    pub enabled: bool,
}

fn default_enabled_operation() -> OperationConfig {
    OperationConfig { enabled: true }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchOperationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_inline_batch_limit")]
    pub max_subjects: usize,
}

impl Default for BatchOperationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_subjects: default_inline_batch_limit(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureConfig {
    #[serde(default = "default_disclosure_profile")]
    pub default: String,
    #[serde(default = "default_disclosure_allowed")]
    pub allowed: Vec<String>,
    #[serde(default = "default_disclosure_downgrade")]
    pub downgrade: String,
}

impl Default for DisclosureConfig {
    fn default() -> Self {
        Self {
            default: default_disclosure_profile(),
            allowed: default_disclosure_allowed(),
            downgrade: default_disclosure_downgrade(),
        }
    }
}

fn default_disclosure_profile() -> String {
    "redacted".to_string()
}

fn default_disclosure_allowed() -> Vec<String> {
    vec!["redacted".to_string()]
}

fn default_disclosure_downgrade() -> String {
    "deny".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProfileConfig {
    pub format: String,
    pub issuer: String,
    pub issuer_key_env: String,
    #[serde(default)]
    pub issuer_kid: Option<String>,
    pub vct: String,
    #[serde(default = "default_credential_validity_seconds")]
    pub validity_seconds: i64,
    #[serde(default)]
    pub holder_binding: HolderBindingConfig,
    #[serde(default)]
    pub allowed_claims: Vec<String>,
    #[serde(default)]
    pub disclosure: CredentialDisclosureConfig,
}

const fn default_credential_validity_seconds() -> i64 {
    24 * 60 * 60
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HolderBindingConfig {
    #[serde(default = "default_holder_binding_mode")]
    pub mode: String,
    #[serde(default)]
    pub proof_of_possession: Option<String>,
    #[serde(default)]
    pub allowed_did_methods: Vec<String>,
}

impl Default for HolderBindingConfig {
    fn default() -> Self {
        Self {
            mode: default_holder_binding_mode(),
            proof_of_possession: None,
            allowed_did_methods: Vec::new(),
        }
    }
}

fn default_holder_binding_mode() -> String {
    "none".to_string()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDisclosureConfig {
    #[serde(default)]
    pub allowed: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CccevConfig {
    #[serde(default)]
    pub requirement_type: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OotsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub requirement: Option<String>,
    #[serde(default)]
    pub reference_framework: Option<String>,
    #[serde(default)]
    pub evidence_type_classification: Option<String>,
    #[serde(default)]
    pub evidence_type_list: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub authentication_level_of_assurance: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal valid config from which individual tests can deviate.
    fn minimal_config() -> StandaloneRegistryWitnessConfig {
        serde_norway::from_str(
            r#"
evidence:
  enabled: true
auth:
  mode: api_key
  api_keys:
    - id: test-key
      hash_env: TEST_TOKEN_HASH
"#,
        )
        .expect("minimal config is valid YAML")
    }

    fn minimal_claim(id: &str) -> ClaimDefinition {
        serde_norway::from_str(&format!(
            r#"
id: {id}
title: Test Claim
version: "1.0"
subject_type: person
rule:
  type: exists
  source: src
"#
        ))
        .expect("minimal claim is valid YAML")
    }

    // -----------------------------------------------------------------------
    // Finding 3: holder binding / did-method mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn proof_of_possession_required_with_only_did_jwk_is_valid() {
        let mut config = minimal_config();
        let profile: CredentialProfileConfig = serde_norway::from_str(
            r#"
format: sd_jwt_vc
issuer: https://issuer.example
issuer_key_env: ISSUER_KEY
vct: https://vct.example/test
holder_binding:
  mode: did
  proof_of_possession: required
  allowed_did_methods:
    - did:jwk
allowed_claims:
  - some-claim
"#,
        )
        .expect("profile YAML is valid");
        config
            .evidence
            .credential_profiles
            .insert("test-profile".to_string(), profile);
        assert!(
            config.validate().is_ok(),
            "did:jwk only should pass validation"
        );
    }

    #[test]
    fn proof_of_possession_required_with_non_jwk_method_is_rejected() {
        let mut config = minimal_config();
        let profile: CredentialProfileConfig = serde_norway::from_str(
            r#"
format: sd_jwt_vc
issuer: https://issuer.example
issuer_key_env: ISSUER_KEY
vct: https://vct.example/test
holder_binding:
  mode: did
  proof_of_possession: required
  allowed_did_methods:
    - did:jwk
    - did:key
allowed_claims:
  - some-claim
"#,
        )
        .expect("profile YAML is valid");
        config
            .evidence
            .credential_profiles
            .insert("test-profile".to_string(), profile);

        let err = config
            .validate()
            .expect_err("did:key with proof_of_possession required must fail");
        match &err {
            EvidenceConfigError::UnsupportedDidMethodsForProofOfPossession { profile, methods } => {
                assert_eq!(profile, "test-profile");
                assert!(
                    methods.contains(&"did:key".to_string()),
                    "error must name did:key, got: {methods:?}"
                );
                assert!(
                    !methods.contains(&"did:jwk".to_string()),
                    "did:jwk must not appear in the unsupported list"
                );
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn proof_of_possession_not_required_allows_any_did_methods() {
        let mut config = minimal_config();
        let profile: CredentialProfileConfig = serde_norway::from_str(
            r#"
format: sd_jwt_vc
issuer: https://issuer.example
issuer_key_env: ISSUER_KEY
vct: https://vct.example/test
holder_binding:
  mode: did
  allowed_did_methods:
    - did:jwk
    - did:key
    - did:web
allowed_claims:
  - some-claim
"#,
        )
        .expect("profile YAML is valid");
        config
            .evidence
            .credential_profiles
            .insert("test-profile".to_string(), profile);
        assert!(
            config.validate().is_ok(),
            "proof_of_possession absent should allow any did method"
        );
    }

    // -----------------------------------------------------------------------
    // Finding 8: depends_on cycle detection
    // -----------------------------------------------------------------------

    #[test]
    fn valid_dag_passes_cycle_detection() {
        // A -> B -> C (no cycle)
        let mut config = minimal_config();
        let mut claim_a = minimal_claim("claim-a");
        claim_a.depends_on = vec!["claim-b".to_string()];
        let mut claim_b = minimal_claim("claim-b");
        claim_b.depends_on = vec!["claim-c".to_string()];
        let claim_c = minimal_claim("claim-c");
        config.evidence.claims = vec![claim_a, claim_b, claim_c];
        assert!(config.validate().is_ok(), "A->B->C DAG should pass");
    }

    #[test]
    fn two_node_cycle_is_detected() {
        // A -> B -> A
        let mut config = minimal_config();
        let mut claim_a = minimal_claim("claim-a");
        claim_a.depends_on = vec!["claim-b".to_string()];
        let mut claim_b = minimal_claim("claim-b");
        claim_b.depends_on = vec!["claim-a".to_string()];
        config.evidence.claims = vec![claim_a, claim_b];

        let err = config
            .validate()
            .expect_err("A->B->A cycle must fail validation");
        match &err {
            EvidenceConfigError::DependsOnCycle { cycle } => {
                assert!(
                    cycle.contains(&"claim-a".to_string()),
                    "cycle must mention claim-a, got: {cycle:?}"
                );
                assert!(
                    cycle.contains(&"claim-b".to_string()),
                    "cycle must mention claim-b, got: {cycle:?}"
                );
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn self_loop_is_detected() {
        // A -> A
        let mut config = minimal_config();
        let mut claim_a = minimal_claim("claim-a");
        claim_a.depends_on = vec!["claim-a".to_string()];
        config.evidence.claims = vec![claim_a];

        let err = config
            .validate()
            .expect_err("self-loop must fail validation");
        match &err {
            EvidenceConfigError::DependsOnCycle { cycle } => {
                assert!(
                    cycle.contains(&"claim-a".to_string()),
                    "cycle must mention claim-a, got: {cycle:?}"
                );
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn unknown_depends_on_is_rejected() {
        let mut config = minimal_config();
        let mut claim_a = minimal_claim("claim-a");
        claim_a.depends_on = vec!["claim-nonexistent".to_string()];
        config.evidence.claims = vec![claim_a];

        let err = config
            .validate()
            .expect_err("depends_on unknown claim must fail validation");
        match &err {
            EvidenceConfigError::DependsOnUnknownClaim { claim, unknown } => {
                assert_eq!(claim, "claim-a");
                assert_eq!(unknown, "claim-nonexistent");
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn empty_allowed_claims_is_rejected() {
        // A credential profile with an empty allowed_claims would silently
        // accept every claim at issue time (see api.rs `is_empty()` short
        // circuit). Reject at config-load time so the operator must opt in.
        let mut config = minimal_config();
        let profile: CredentialProfileConfig = serde_norway::from_str(
            r#"
format: sd_jwt_vc
issuer: https://issuer.example
issuer_key_env: ISSUER_KEY
vct: https://vct.example/test
"#,
        )
        .expect("profile YAML is valid");
        config
            .evidence
            .credential_profiles
            .insert("the_profile_id".to_string(), profile);

        let err = config
            .validate()
            .expect_err("empty allowed_claims must fail validation");
        match &err {
            EvidenceConfigError::EmptyAllowedClaims { profile } => {
                assert_eq!(profile, "the_profile_id");
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    // -----------------------------------------------------------------------
    // Stage 1: concurrency config and the kill-switch
    // -----------------------------------------------------------------------

    #[test]
    fn default_concurrency_has_documented_defaults() {
        let cfg = ConcurrencyConfig::default();
        assert_eq!(cfg.subjects, 16);
        assert_eq!(cfg.bindings, 8);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn concurrency_zero_subjects_is_rejected() {
        let mut config = minimal_config();
        config.evidence.concurrency = ConcurrencyConfig {
            subjects: 0,
            bindings: 1,
        };
        let err = config
            .validate()
            .expect_err("subjects=0 must fail validation");
        assert!(matches!(err, EvidenceConfigError::InvalidConcurrency));
    }

    #[test]
    fn concurrency_zero_bindings_is_rejected() {
        let mut config = minimal_config();
        config.evidence.concurrency = ConcurrencyConfig {
            subjects: 1,
            bindings: 0,
        };
        let err = config
            .validate()
            .expect_err("bindings=0 must fail validation");
        assert!(matches!(err, EvidenceConfigError::InvalidConcurrency));
    }

    #[test]
    fn kill_switch_subjects_one_bindings_one_validates() {
        // The documented kill switch: concurrency.subjects=1 and
        // concurrency.bindings=1 reproduces today's strictly-sequential
        // behavior. Must validate successfully.
        let mut config = minimal_config();
        config.evidence.concurrency = ConcurrencyConfig {
            subjects: 1,
            bindings: 1,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn oidc_auth_mode_requires_oidc_block() {
        let mut config = minimal_config();
        config.auth.mode = "oidc".to_string();

        let err = config
            .validate()
            .expect_err("oidc mode requires OIDC settings");

        assert!(matches!(err, EvidenceConfigError::MissingOidcConfig));
    }

    #[test]
    fn oidc_auth_mode_validates_required_settings() {
        let mut config = minimal_config();
        config.auth.mode = "oidc".to_string();
        config.auth.api_keys.clear();
        config.auth.oidc = Some(EvidenceOidcAuthConfig {
            issuer: "https://issuer.example".to_string(),
            jwks_uri: "https://issuer.example/jwks.json".to_string(),
            audiences: vec!["registry-witness".to_string()],
            allowed_clients: vec!["registry-client".to_string()],
            allowed_algorithms: vec!["EdDSA".to_string()],
            allowed_typ: vec!["JWT".to_string()],
            scope_claim: "scope".to_string(),
            scope_separator: " ".to_string(),
            scope_map: BTreeMap::new(),
            principal_claim: "sub".to_string(),
            leeway_seconds: 60,
            allow_insecure_localhost: false,
        });

        assert!(config.validate().is_ok());
    }

    #[test]
    fn api_key_plaintext_is_never_loaded_only_fingerprint() {
        let err = serde_norway::from_str::<StandaloneRegistryWitnessConfig>(
            r#"
evidence:
  enabled: true
auth:
  mode: api_key
  api_keys:
    - id: test-key
      token_env: TEST_TOKEN
"#,
        )
        .expect_err("plaintext token_env is not part of the credential schema");

        assert!(
            err.to_string().contains("unknown field `token_env`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unsupported_auth_mode_is_rejected() {
        let mut config = minimal_config();
        config.auth.mode = "oauth2".to_string();

        let err = config
            .validate()
            .expect_err("unknown auth mode must fail validation");

        assert!(matches!(
            err,
            EvidenceConfigError::UnsupportedAuthMode { .. }
        ));
    }

    #[test]
    fn source_connection_max_in_flight_zero_is_rejected() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "src".to_string(),
            SourceConnectionConfig {
                base_url: "https://upstream.example".to_string(),
                allow_insecure_localhost: false,
                token_env: "UPSTREAM_TOKEN".to_string(),
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 0,
                bulk_mode: BulkMode::None,
                bulk_mode_lookup_unique: false,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let err = config
            .validate()
            .expect_err("max_in_flight=0 must fail validation");
        assert!(matches!(err, EvidenceConfigError::InvalidConcurrency));
    }

    #[test]
    fn source_connection_max_in_flight_defaults_to_eight() {
        // The YAML default for `max_in_flight` must be 8; operators do not
        // need to set it explicitly to get the documented politeness cap.
        let yaml = r#"
base_url: https://upstream.example
token_env: SRC_TOKEN
"#;
        let connection: SourceConnectionConfig =
            serde_norway::from_str(yaml).expect("connection YAML parses");
        assert!(!connection.allow_insecure_localhost);
        assert_eq!(connection.max_in_flight, 8);
    }

    // -----------------------------------------------------------------------
    // Stage 3: bulk_mode validation
    // -----------------------------------------------------------------------

    fn rda_binding(connection: &str, cardinality: &str) -> SourceBindingConfig {
        SourceBindingConfig {
            connector: SourceConnectorKind::RegistryDataApi,
            connection: Some(connection.to_string()),
            required_scope: None,
            dataset: "farmer_registry".to_string(),
            entity: "farmer".to_string(),
            lookup: SourceLookupConfig {
                input: "subject_id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: cardinality.to_string(),
            },
            fields: BTreeMap::new(),
        }
    }

    fn dci_binding(connection: &str) -> SourceBindingConfig {
        SourceBindingConfig {
            connector: SourceConnectorKind::Dci,
            connection: Some(connection.to_string()),
            required_scope: None,
            dataset: "farmer_registry".to_string(),
            entity: "farmer".to_string(),
            lookup: SourceLookupConfig {
                input: "subject_id".to_string(),
                field: "id_type".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            fields: BTreeMap::new(),
        }
    }

    #[test]
    fn bulk_mode_default_is_none_and_round_trips() {
        let yaml = r#"
base_url: https://upstream.example
token_env: SRC_TOKEN
"#;
        let connection: SourceConnectionConfig =
            serde_norway::from_str(yaml).expect("connection YAML parses");
        assert!(!connection.allow_insecure_localhost);
        assert_eq!(connection.bulk_mode, BulkMode::None);
        assert!(!connection.bulk_mode_lookup_unique);
        assert_eq!(connection.bulk_timeout_max_ms, 30_000);
    }

    #[test]
    fn bulk_mode_unknown_variant_is_rejected_at_deserialize() {
        let yaml = r#"
base_url: https://upstream.example
token_env: SRC_TOKEN
bulk_mode: unsupported_mode
"#;
        let err = serde_norway::from_str::<SourceConnectionConfig>(yaml)
            .expect_err("unknown variant fails");
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported_mode") || msg.contains("variant") || msg.contains("unknown"),
            "deserialize error mentions the bad variant: {msg}"
        );
    }

    #[test]
    fn rda_in_filter_without_unique_attestation_is_rejected() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "farmer_registry".to_string(),
            SourceConnectionConfig {
                base_url: "https://upstream.example".to_string(),
                allow_insecure_localhost: false,
                token_env: "SRC_TOKEN".to_string(),
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                bulk_mode: BulkMode::RdaInFilter,
                bulk_mode_lookup_unique: false,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let mut claim = minimal_claim("a-claim");
        claim
            .source_bindings
            .insert("farmer".to_string(), rda_binding("farmer_registry", "one"));
        config.evidence.claims = vec![claim];

        let err = config
            .validate()
            .expect_err("rda_in_filter without unique attestation must fail");
        match &err {
            EvidenceConfigError::BulkModeRequiresUniqueLookup { connection } => {
                assert_eq!(connection, "farmer_registry");
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn rda_in_filter_with_many_cardinality_binding_is_rejected() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "farmer_registry".to_string(),
            SourceConnectionConfig {
                base_url: "https://upstream.example".to_string(),
                allow_insecure_localhost: false,
                token_env: "SRC_TOKEN".to_string(),
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                bulk_mode: BulkMode::RdaInFilter,
                bulk_mode_lookup_unique: true,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let mut claim = minimal_claim("a-claim");
        claim
            .source_bindings
            .insert("farmer".to_string(), rda_binding("farmer_registry", "many"));
        config.evidence.claims = vec![claim];

        let err = config
            .validate()
            .expect_err("rda_in_filter with many-cardinality binding must fail");
        match &err {
            EvidenceConfigError::BulkModeRequiresCardinalityOne {
                connection,
                claim,
                binding,
            } => {
                assert_eq!(connection, "farmer_registry");
                assert_eq!(claim, "a-claim");
                assert_eq!(binding, "farmer");
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn dci_batched_search_on_rda_binding_is_rejected() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "registry".to_string(),
            SourceConnectionConfig {
                base_url: "https://upstream.example".to_string(),
                allow_insecure_localhost: false,
                token_env: "SRC_TOKEN".to_string(),
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                bulk_mode: BulkMode::DciBatchedSearch,
                bulk_mode_lookup_unique: false,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let mut claim = minimal_claim("a-claim");
        claim
            .source_bindings
            .insert("farmer".to_string(), rda_binding("registry", "one"));
        config.evidence.claims = vec![claim];

        let err = config
            .validate()
            .expect_err("dci_batched_search on RDA binding must fail");
        match &err {
            EvidenceConfigError::BulkModeRequiresDciConnector {
                connection,
                claim,
                binding,
            } => {
                assert_eq!(connection, "registry");
                assert_eq!(claim, "a-claim");
                assert_eq!(binding, "farmer");
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn dci_batched_search_with_dci_bindings_validates() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "registry".to_string(),
            SourceConnectionConfig {
                base_url: "https://upstream.example".to_string(),
                allow_insecure_localhost: false,
                token_env: "SRC_TOKEN".to_string(),
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                bulk_mode: BulkMode::DciBatchedSearch,
                bulk_mode_lookup_unique: false,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let mut claim = minimal_claim("a-claim");
        claim
            .source_bindings
            .insert("record".to_string(), dci_binding("registry"));
        config.evidence.claims = vec![claim];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rda_in_filter_with_unique_and_cardinality_one_validates() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "farmer_registry".to_string(),
            SourceConnectionConfig {
                base_url: "https://upstream.example".to_string(),
                allow_insecure_localhost: false,
                token_env: "SRC_TOKEN".to_string(),
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                bulk_mode: BulkMode::RdaInFilter,
                bulk_mode_lookup_unique: true,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let mut claim = minimal_claim("a-claim");
        claim
            .source_bindings
            .insert("farmer".to_string(), rda_binding("farmer_registry", "one"));
        config.evidence.claims = vec![claim];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn blank_only_allowed_claims_is_rejected() {
        // `allowed_claims: [""]` would pass an `is_empty()` guard but still
        // fail every issuance with EvaluationBindingMismatch. Treat blank-only
        // lists the same as empty so operators see the error at config load.
        let mut config = minimal_config();
        let profile: CredentialProfileConfig = serde_norway::from_str(
            r#"
format: sd_jwt_vc
issuer: https://issuer.example
issuer_key_env: ISSUER_KEY
vct: https://vct.example/test
allowed_claims: ["", "   "]
"#,
        )
        .expect("profile YAML is valid");
        config
            .evidence
            .credential_profiles
            .insert("blank_profile".to_string(), profile);

        let err = config
            .validate()
            .expect_err("blank-only allowed_claims must fail validation");
        match &err {
            EvidenceConfigError::EmptyAllowedClaims { profile } => {
                assert_eq!(profile, "blank_profile");
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }
}
