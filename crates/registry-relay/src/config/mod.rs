// SPDX-License-Identifier: Apache-2.0
//! Configuration data model and loader.
//!
//! The YAML contract is documented for operators in
//! `docs/configuration.md`; [`Config`] is the runtime representation of
//! that contract. Config hot reload is out of scope for V1: the document
//! is read once at startup, validated, and then held behind `Arc<Config>`.
//!
//! Every struct uses `#[serde(deny_unknown_fields)]` so YAML typos
//! surface as `config.parse_error`. Cross-field invariants (id format,
//! uniqueness, scope references, env var presence, vocabulary prefix
//! resolution, allowed-filter and aggregate column references) live in
//! [`validate`] and run after `serde` deserialisation.
//!
//! Operator-visible context (offending dataset id, env var name, etc.)
//! is logged via `tracing` at error level. The returned [`crate::error::Error`]
//! carries the stable `config.*` code; per the scrubbing policy in
//! `src/error.rs`, response and audit detail strings never carry paths,
//! secrets, or row data.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use registry_platform_authcommon::CredentialFingerprintRef;
use registry_platform_ops::{AuditWritePolicy, DeploymentProfile};
use serde::{Deserialize, Serialize};

pub mod capabilities;
pub mod governed;
pub mod loader;
pub mod provenance;
#[cfg(test)]
#[doc(hidden)]
pub mod test_support;
pub mod validate;
pub mod vocabularies;

pub use loader::{
    load, load_config_metadata, load_metadata_manifest, load_with_metadata,
    load_with_metadata_options, validate_verified_bundle_runtime, BundleStateAction, LoadOptions,
    LoadedConfig, PendingBundleAcceptance,
};
pub use provenance::{
    ClaimValidity, DelegatedIssuerConfig, FileWatchSignerConfig, GatewayIssuerConfig, IssuerConfig,
    KmsProvider, KmsSignerConfig, ProvenanceAlgorithm, ProvenanceConfig, RetiredKeyConfig,
    SignerConfig, SoftwareSignerConfig,
};

/// Root configuration document. Parsed from YAML at startup.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub instance: InstanceConfig,
    pub server: ServerConfig,
    #[serde(default)]
    pub config_trust: Option<ConfigTrustConfig>,
    #[serde(default)]
    pub metadata: Option<MetadataConfig>,
    pub catalog: CatalogConfig,
    #[serde(default)]
    pub vocabularies: BTreeMap<String, String>,
    pub auth: AuthConfig,
    pub audit: AuditConfig,
    pub datasets: Vec<DatasetConfig>,
    /// Optional data provenance configuration. Disabled by default:
    /// deployments without this block load unchanged.
    #[serde(default)]
    pub provenance: Option<ProvenanceConfig>,
    /// Optional external standards adapters. The config model is parsed
    /// in every build so feature-disabled binaries can reject it with a
    /// stable taxonomy code.
    #[serde(default)]
    pub standards: StandardsConfig,
    /// Operator-declared deployment profile, gate waivers, and assurance
    /// evidence. Omitting the profile leaves the deployment undeclared, which
    /// refuses startup. Use `profile: local` as the explicit development opt-out.
    #[serde(default)]
    pub deployment: DeploymentConfig,
}

/// Operator-declared deployment posture.
///
/// The profile is an explicit assurance claim, never inferred from
/// environment or network position. When `profile` is absent the deployment
/// is undeclared and refuses startup. A profile value that is not one of the
/// known variants fails startup (fail closed on typos).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    #[serde(default)]
    pub profile: Option<DeploymentProfile>,
    /// Per-deployment waivers. Each names one finding id, a free-text reason,
    /// and a mandatory expiry date. Expired waivers stop suppressing their
    /// finding and raise `deployment.waiver_expired`.
    #[serde(default)]
    pub waivers: Vec<DeploymentWaiverConfig>,
    /// Operator declarations of assurance evidence the runtime cannot observe
    /// for itself (out-of-band ingress rate limiting, API-key rotation).
    /// Absent declarations leave the corresponding gates active.
    #[serde(default)]
    pub evidence: DeploymentEvidenceConfig,
}

/// One declared waiver. `expires` is an ISO 8601 `YYYY-MM-DD` date; format is
/// validated at load time. Reasons must not carry secrets.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentWaiverConfig {
    pub finding: String,
    pub reason: String,
    pub expires: String,
}

/// Operator-asserted assurance evidence for conditions the runtime cannot
/// observe directly. Each flag defaults to `false`, meaning "no evidence
/// declared", which keeps the corresponding gate active until the operator
/// asserts the control is in place out of band.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentEvidenceConfig {
    /// Operator asserts ingress rate limiting is enforced (for example by a
    /// gateway or reverse proxy in front of the relay).
    #[serde(default)]
    pub ingress_rate_limit: bool,
    /// Operator asserts an API-key rotation process is in place.
    #[serde(default)]
    pub api_key_rotation: bool,
    /// Operator asserts audit records are shipped off-host (for example to a
    /// log collector or SIEM) rather than relying solely on local retention.
    #[serde(default)]
    pub audit_offhost_shipping: bool,
}

/// Stable deployment identity surfaced in redacted operations posture.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceConfig {
    #[serde(default = "default_instance_id")]
    pub id: String,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub jurisdiction: Option<String>,
}

impl Default for InstanceConfig {
    fn default() -> Self {
        Self {
            id: default_instance_id(),
            environment: None,
            owner: None,
            jurisdiction: None,
        }
    }
}

fn default_instance_id() -> String {
    "registry-relay-local".to_string()
}

/// Optional signed configuration bundle trust state.
///
/// Simple local deployments omit this block. Bundle-aware deployments pin the
/// local trust anchor, bundle, and anti-rollback state paths explicitly.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConfigTrustConfig {
    pub trust_anchor_path: PathBuf,
    pub bundle_path: PathBuf,
    pub antirollback_state_path: PathBuf,
    #[serde(default)]
    pub break_glass_override_path: Option<PathBuf>,
}

/// Optional split metadata manifest loaded alongside the runtime config.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetadataConfig {
    pub source: MetadataSourceConfig,
    #[serde(default)]
    pub ecosystem_binding: Option<EcosystemBindingSelectorConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetadataSourceConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EcosystemBindingSelectorConfig {
    pub id: String,
    #[serde(default)]
    pub version: Option<String>,
}

/// External standards adapters layered over configured entities.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StandardsConfig {
    #[serde(default)]
    pub spdci: Option<SpdciStandardsConfig>,
}

/// Social Protection Digital Convergence Initiative (SP DCI) adapter
/// configuration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SpdciStandardsConfig {
    #[serde(default)]
    pub disability_registry: Option<SpdciDisabilityRegistryConfig>,
    #[serde(default)]
    pub registries: BTreeMap<String, SpdciRegistryConfig>,
}

/// Runtime binding from a DCI registry sync search API to one configured
/// Registry Relay entity.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SpdciRegistryConfig {
    pub dataset: DatasetId,
    pub entity: String,
    #[serde(default = "default_spdci_registry_type")]
    pub registry_type: String,
    #[serde(default = "default_spdci_record_type")]
    pub record_type: String,
    /// DCI identifier type to entity field mappings for `idtype-value`.
    #[serde(default)]
    pub identifiers: BTreeMap<String, String>,
    /// DCI expression or predicate attribute to entity field mappings.
    #[serde(default)]
    pub expression_fields: BTreeMap<String, String>,
    /// SP DCI output path to entity field mappings for direct response
    /// projection. A CEL mapping takes precedence when both are set.
    #[serde(default)]
    pub response_fields: BTreeMap<String, String>,
    /// Optional local CEL mapping document used to shape response records.
    #[serde(default)]
    pub response_mapping_path: Option<PathBuf>,
    /// Optional local JSON Schema used to validate shaped response records.
    #[serde(default)]
    pub response_schema_path: Option<PathBuf>,
    #[serde(default = "default_spdci_search_limit")]
    pub default_limit: u32,
}

/// Runtime binding from SP DCI Disability Registry sync APIs to one
/// configured Registry Relay entity.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SpdciDisabilityRegistryConfig {
    pub dataset: DatasetId,
    pub entity: String,
    /// Query key accepted from SP DCI `disabled_criteria.query`.
    #[serde(default = "default_spdci_disability_query_key")]
    pub query_key: String,
    /// Entity field filtered when the SP DCI query key is present.
    #[serde(default = "default_spdci_disability_query_field")]
    pub query_field: String,
    /// Entity field whose value determines the SP DCI disabled response.
    #[serde(default = "default_spdci_disabled_status_field")]
    pub disabled_status_field: String,
    /// Case-insensitive values interpreted as disabled.
    #[serde(default = "default_spdci_disabled_positive_values")]
    pub disabled_positive_values: Vec<String>,
}

fn default_spdci_disability_query_key() -> String {
    "member.member_identifier".to_string()
}

fn default_spdci_disability_query_field() -> String {
    "id".to_string()
}

fn default_spdci_disabled_status_field() -> String {
    "disability_status".to_string()
}

fn default_spdci_disabled_positive_values() -> Vec<String> {
    ["approved", "yes", "true", "disabled"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_spdci_registry_type() -> String {
    "ns:org:RegistryType:DR".to_string()
}

fn default_spdci_record_type() -> String {
    "spdci-extensions-dci:DisabledPerson".to_string()
}

fn default_spdci_search_limit() -> u32 {
    100
}

/// HTTP listener and adjacent server-wide knobs.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    #[serde(default)]
    pub admin_bind: Option<SocketAddr>,
    #[serde(default = "default_openapi_requires_auth")]
    pub openapi_requires_auth: bool,
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,
    #[serde(default = "default_xlsx_max_file_bytes")]
    pub xlsx_max_file_bytes: u64,
    #[serde(default = "default_max_source_file_bytes")]
    pub max_source_file_bytes: u64,
    #[serde(default)]
    pub trust_proxy: TrustProxyConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,
    #[serde(default = "default_request_body_timeout", with = "humantime_serde")]
    pub request_body_timeout: Duration,
    #[serde(
        default = "default_http1_header_read_timeout",
        with = "humantime_serde"
    )]
    pub http1_header_read_timeout: Duration,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_request_body_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_http1_header_read_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_max_connections() -> usize {
    1024
}

fn default_openapi_requires_auth() -> bool {
    true
}

fn default_cache_dir() -> PathBuf {
    PathBuf::from("./cache")
}

fn default_xlsx_max_file_bytes() -> u64 {
    256 * 1024 * 1024
}

fn default_max_source_file_bytes() -> u64 {
    256 * 1024 * 1024
}

/// `X-Forwarded-For` policy. Until the `ipnet` crate lands in deps we
/// keep CIDR specs as strings and validate format in
/// [`validate::run`].
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustProxyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

/// CORS allowlist; default-deny per Section 17 item 7.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// Catalog-level metadata surfaced by `/metadata/*` and DCAT outputs.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CatalogConfig {
    pub title: String,
    pub base_url: String,
    pub publisher: String,
    #[serde(default)]
    pub participant_id: Option<String>,
    /// BRegDCAT-AP: identifier IRI for the `foaf:Agent` publisher. Use a
    /// controlled-vocabulary corporate body IRI when publishing strict
    /// BRegDCAT-AP.
    #[serde(default)]
    pub publisher_iri: Option<String>,
    /// BRegDCAT-AP: type IRI for the `foaf:Agent` publisher. When set, emits
    /// `dcterms:type` on the publisher node.
    ///
    /// BRegDCAT-AP 2.1.0 SHACL checks publisher type values against the ADMS
    /// publishertype scheme (`http://purl.org/adms/publishertype/...`).
    /// The relay does not enforce a vocabulary: any IRI passes through.
    #[serde(default)]
    pub authority_type: Option<String>,
    /// BRegDCAT-AP: default `dcterms:spatial` IRI applied to datasets that
    /// do not declare their own `spatial_coverage`. Typically an EU
    /// authority country IRI under
    /// `http://publications.europa.eu/resource/authority/country/`.
    #[serde(default)]
    pub default_spatial_coverage: Option<String>,
}

/// Authentication configuration. Exactly one of `api_keys` and `oidc`
/// is consumed at startup, gated by `mode`; cross-field validation in
/// [`validate`] enforces that only the active block is populated.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub mode: AuthMode,
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    /// Local, coarse, in-process throttle on repeated authentication
    /// failures from one client address. Disabled by default.
    #[serde(default)]
    pub failure_throttle: AuthFailureThrottleConfig,
}

/// Local backstop against repeated authentication failures from a single
/// client address. This is not the primary defense: ingress rate limiting
/// in front of the relay (declared via `deployment.evidence.ingress_rate_limit`)
/// is expected to absorb abusive traffic before it reaches this process.
/// Disabled by default so deployments that never set this block observe no
/// behavior change.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthFailureThrottleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_auth_failure_throttle_max_failures")]
    pub max_failures: u32,
    #[serde(default = "default_auth_failure_throttle_window_seconds")]
    pub window_seconds: u64,
}

impl Default for AuthFailureThrottleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_failures: default_auth_failure_throttle_max_failures(),
            window_seconds: default_auth_failure_throttle_window_seconds(),
        }
    }
}

fn default_auth_failure_throttle_max_failures() -> u32 {
    20
}

fn default_auth_failure_throttle_window_seconds() -> u64 {
    60
}

/// Authentication mode tag. Drives the provider built at startup in
/// `crate::auth`. A given deployment runs in exactly one mode at a time;
/// mixed-mode operation is not supported.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Hashed shared secret in an environment variable.
    ApiKey,
    /// Bearer JWT validated against an external OIDC / OAuth2 provider.
    Oidc,
}

/// One configured API key, identified by an id and a fingerprint reference.
/// The raw key never appears in config.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyConfig {
    pub id: String,
    pub fingerprint: CredentialFingerprintRef,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// OIDC / OAuth2 resource-server configuration. The relay validates
/// incoming bearer JWTs against a configured external IdP. No tokens
/// are minted here.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Issuer URL. Compared verbatim against the JWT `iss` claim.
    pub issuer: String,
    /// One or more accepted `aud` values. Tokens with no `aud`, or
    /// whose `aud` does not intersect this list, are rejected.
    pub audiences: Vec<String>,
    /// JWKS endpoint. Either this or `discovery_url` must be set.
    /// `discovery_url` takes precedence: when both are configured the
    /// validator rejects the document.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// OIDC discovery document URL
    /// (`.well-known/openid-configuration`). The JWKS URL is resolved
    /// from `jwks_uri` in the discovered document.
    #[serde(default)]
    pub discovery_url: Option<String>,
    /// Development-only escape hatch that permits loopback HTTP issuer,
    /// discovery, and JWKS URLs. Private non-loopback networks and cloud
    /// metadata endpoints remain denied by the platform fetch policy.
    #[serde(default)]
    pub allow_dev_insecure_fetch_urls: bool,
    /// Signature algorithms accepted by the verifier. Defaults to
    /// RS256, ES256, EdDSA. HS\* and `none` are intentionally absent
    /// from [`OidcAlgorithm`].
    #[serde(default = "default_oidc_algorithms")]
    pub allowed_algorithms: Vec<OidcAlgorithm>,
    /// JWKS cache TTL. Default 10 minutes. The provider also refreshes
    /// on unknown `kid` (rate-limited) so this controls the steady-state
    /// rotation pickup latency, not the upper bound.
    #[serde(default = "default_oidc_jwks_cache_ttl", with = "humantime_serde")]
    pub jwks_cache_ttl: Duration,
    /// Clock skew tolerance applied to `exp` and (when present) `nbf`.
    /// Default 60 seconds. Bounded at 5 minutes by validation.
    #[serde(default = "default_oidc_leeway", with = "humantime_serde")]
    pub leeway: Duration,
    /// JWT claim whose value carries scopes. Defaults to `scope`, the
    /// RFC 8693 / RFC 9068 space-separated form. Some IdPs use `scp`
    /// or `permissions`; the value may be a string, an array of strings,
    /// or an object keyed by scope name.
    #[serde(default = "default_oidc_scope_claim")]
    pub scope_claim: String,
    /// Optional rename map: `external_scope -> internal_scope`. Applied
    /// after parsing the scope claim, before scope-based access checks
    /// run. Useful for adapting IdP role names (`role:foo`) to the
    /// relay's `<dataset_id>:<level>` shape.
    #[serde(default)]
    pub scope_map: BTreeMap<String, String>,
    /// Keys that must be present inside object-valued role claim values
    /// before the role key is treated as an active scope. Object-valued
    /// claims grant no scopes when this list is empty.
    /// This is useful for IdPs such as Zitadel where role values are
    /// keyed by organization id.
    #[serde(default)]
    pub scope_object_required_keys: Vec<String>,
    /// Optional allowlist of client identifiers, matched against the
    /// token's `azp` (preferred) or `client_id` claim. Empty list
    /// means any client is accepted.
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    /// Accepted `typ` JOSE header values. Defaults to `JWT` and
    /// `at+jwt` (RFC 9068). ID tokens (`id+jwt`) are not access tokens
    /// and are rejected by default. Tokens without `typ` are rejected by
    /// the shared verifier.
    #[serde(default = "default_oidc_token_types")]
    pub allowed_token_types: Vec<String>,
}

/// JWS signature algorithms accepted by the OIDC verifier. Symmetric
/// algorithms (`HS*`) and `none` are intentionally absent: shared-secret
/// JWTs are unsafe between a resource server and an IdP, and `none`
/// disables verification entirely.
///
/// YAML values are the canonical JWA `alg` strings (`RS256`, `ES256`,
/// `EdDSA`), case-sensitive.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum OidcAlgorithm {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

fn default_oidc_algorithms() -> Vec<OidcAlgorithm> {
    vec![
        OidcAlgorithm::Rs256,
        OidcAlgorithm::Es256,
        OidcAlgorithm::EdDsa,
    ]
}

fn default_oidc_jwks_cache_ttl() -> Duration {
    Duration::from_secs(600)
}

fn default_oidc_leeway() -> Duration {
    Duration::from_secs(60)
}

fn default_oidc_scope_claim() -> String {
    "scope".to_string()
}

fn default_oidc_token_types() -> Vec<String> {
    vec!["JWT".to_string(), "at+jwt".to_string()]
}

/// Audit configuration. Sink choice gates further fields via the
/// tagged `AuditSinkConfig` enum. The enum is flattened onto the
/// containing struct so that the YAML `sink:` key acts as the
/// discriminator, matching the public example configuration.
///
/// `deny_unknown_fields` is deliberately omitted here: `serde` does
/// not support combining it with `#[serde(flatten)]` on an internally
/// tagged enum (unknown keys in `audit` are caught by the enum's own
/// `deny_unknown_fields`).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AuditConfig {
    #[serde(flatten)]
    pub sink: AuditSinkConfig,
    #[serde(default = "default_audit_format")]
    pub format: AuditFormat,
    #[serde(default)]
    pub chain: bool,
    #[serde(default)]
    pub include_health: bool,
    /// Behavior when an audit record fails to write.
    ///
    /// `fail_closed` (default) fails the request with a stable error code so
    /// that no request outcome is returned without a durable audit record.
    /// `availability_first` logs the failure and lets the request succeed for
    /// deployments that explicitly accept best-effort audit durability.
    /// Per-route-family selection is out of scope; this is a single
    /// deployment-wide policy.
    #[serde(default = "default_audit_write_policy")]
    pub write_policy: AuditWritePolicy,
    /// Name of the environment variable holding the per-deploy secret
    /// used to HMAC sensitive audit values (single-record primary keys,
    /// sensitive query parameters). Runtime startup fails closed when
    /// this field is unset, empty, or points to a missing, empty, or
    /// weak secret. Direct middleware tests can opt into the explicit
    /// unkeyed dev-only hasher without using runtime config.
    #[serde(default)]
    pub hash_secret_env: Option<String>,
}

fn default_audit_format() -> AuditFormat {
    AuditFormat::Jsonl
}

fn default_audit_write_policy() -> AuditWritePolicy {
    AuditWritePolicy::FailClosed
}

/// Audit serialisation format. JSONL is the only V1 format.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditFormat {
    /// JSON Lines: one record per line, UTF-8, LF-terminated.
    Jsonl,
}

/// Audit sink tagged on `sink:` per the YAML example. `file` carries
/// the rotation policy inline.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "sink", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum AuditSinkConfig {
    Stdout {},
    File {
        path: PathBuf,
        #[serde(default)]
        rotate: RotateConfig,
    },
    Syslog {},
}

/// In-process rotation for the `file` audit sink.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RotateConfig {
    pub max_size_mb: u64,
    pub max_files: u32,
}

impl Default for RotateConfig {
    fn default() -> Self {
        // Spec Section 13.2 examples: 100 MB, 14 files. Operators
        // override per deployment.
        Self {
            max_size_mb: 100,
            max_files: 14,
        }
    }
}

/// BRegDCAT-AP `adms:status` vocabulary. Maps to the EU ADMS status codelists.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmsStatus {
    UnderDevelopment,
    Completed,
    Deprecated,
    Withdrawn,
}

/// A single dataset declaration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DatasetConfig {
    pub id: DatasetId,
    pub title: String,
    pub description: String,
    pub owner: String,
    pub sensitivity: Sensitivity,
    pub access_rights: AccessRights,
    pub update_frequency: UpdateFrequency,
    #[serde(default)]
    pub conforms_to: Vec<String>,
    /// DCAT-AP `dcatap:applicableLegislation` IRIs. This is evidence
    /// published for standard consumers, not an application-specific
    /// authorization or source-of-truth verdict.
    #[serde(default)]
    pub applicable_legislation: Vec<String>,
    /// BRegDCAT-AP: `dct:spatial` IRI for this dataset. Overrides the
    /// catalog-level `default_spatial_coverage` when set.
    #[serde(default)]
    pub spatial_coverage: Option<String>,
    /// BRegDCAT-AP: `adms:status` for this dataset. Defaults to
    /// `UnderDevelopment` when not set: it is the weakest ADMS lifecycle
    /// claim and forces an explicit opt-in to anything stronger.
    #[serde(default)]
    pub status: Option<AdmsStatus>,
    /// CPSV public services that produce this dataset. Registry Relay emits
    /// them as standard `cpsv:PublicService` nodes; consumers decide how to
    /// interpret that evidence.
    #[serde(default)]
    pub public_services: Vec<PublicServiceConfig>,
    #[serde(default)]
    pub defaults: DatasetDefaultsConfig,
    #[serde(default)]
    pub tables: Vec<ResourceConfig>,
    #[serde(default)]
    pub entities: Vec<EntityConfig>,
    #[serde(default)]
    pub aggregates: Vec<AggregateConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicServiceConfig {
    #[serde(default)]
    pub id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Optional table defaults for reducing repetition within one dataset.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DatasetDefaultsConfig {
    #[serde(default)]
    pub refresh: Option<RefreshConfig>,
    #[serde(default)]
    pub materialization: Option<MaterializationMode>,
}

impl DatasetConfig {
    /// Storage-layer tables owned by this dataset.
    pub fn table_configs(&self) -> impl Iterator<Item = &ResourceConfig> {
        self.tables.iter()
    }
}

/// Source plugin selection. Tagged on `type:` so HTTP, S3, or additional
/// database variants can land additively later.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SourceConfig {
    File {
        path: PathBuf,
        #[serde(default)]
        format: Option<ResourceFormatConfig>,
    },
    Postgres {
        connection_env: String,
        #[serde(default)]
        table: Option<PostgresTableConfig>,
        #[serde(default)]
        query: Option<String>,
        #[serde(default)]
        change_token_sql: Option<String>,
        #[serde(default = "default_postgres_connect_timeout", with = "humantime_serde")]
        connect_timeout: Duration,
        #[serde(default = "default_postgres_query_timeout", with = "humantime_serde")]
        query_timeout: Duration,
        #[serde(default = "default_postgres_live_max_connections")]
        live_max_connections: usize,
        #[serde(default = "default_postgres_live_max_rows")]
        live_max_rows: usize,
    },
}

impl SourceConfig {
    pub fn format(&self) -> Option<&ResourceFormatConfig> {
        match self {
            SourceConfig::File { format, .. } => format.as_ref(),
            SourceConfig::Postgres { .. } => None,
        }
    }
}

/// Structured database table reference. Keeping schema/name separate
/// avoids parsing dotted identifiers and leaves quoting to connectors.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PostgresTableConfig {
    pub schema: String,
    pub name: String,
}

fn default_postgres_connect_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_postgres_query_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_postgres_live_max_connections() -> usize {
    8
}

fn default_postgres_live_max_rows() -> usize {
    10_000
}

/// Refresh policy. Tagged on `mode:`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum RefreshConfig {
    /// Poll source mtime on `interval` and re-ingest on change.
    Mtime {
        #[serde(default = "default_mtime_interval", with = "humantime_serde")]
        interval: Duration,
    },
    /// Unconditionally re-ingest on `interval`.
    Interval {
        #[serde(with = "humantime_serde")]
        interval: Duration,
    },
    /// Re-ingest only on explicit admin call.
    Manual {},
}

fn default_mtime_interval() -> Duration {
    // Default to a short refresh interval for modified local files.
    Duration::from_secs(60)
}

/// How a configured private table is registered for query planning.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationMode {
    Snapshot,
    Live,
}

/// One private storage table under a dataset.
///
/// The public API should not expose these ids. Entity config maps one
/// resource into one domain resource, with optional field renaming and
/// relationship declarations.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfig {
    pub id: ResourceId,
    pub source: SourceConfig,
    #[serde(default)]
    pub refresh: Option<RefreshConfig>,
    #[serde(default)]
    pub materialization: Option<MaterializationMode>,
    #[serde(default)]
    pub primary_key: Option<String>,
    pub schema: SchemaConfig,
    #[serde(default)]
    pub access: ResourceAccessConfig,
    #[serde(default)]
    pub api: ResourceApiConfig,
    #[serde(default)]
    pub aggregates: Vec<AggregateConfig>,
}

/// Storage table format override. If omitted, ingest infers the format
/// from the source file extension.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceFormatConfig {
    #[serde(default)]
    pub csv: Option<CsvFormatConfig>,
    #[serde(default)]
    pub xlsx: Option<XlsxFormatConfig>,
    #[serde(default)]
    pub parquet: Option<ParquetFormatConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CsvFormatConfig {
    #[serde(default)]
    pub header_row: Option<u32>,
    #[serde(default)]
    pub delimiter: Option<u8>,
    #[serde(default)]
    pub quote: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XlsxFormatConfig {
    #[serde(default)]
    pub sheet: Option<String>,
    #[serde(default)]
    pub header_row: Option<u32>,
    #[serde(default)]
    pub data_range: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ParquetFormatConfig {}

impl ResourceConfig {
    pub fn format_name(&self) -> Option<&'static str> {
        let format = self.source_format()?;
        if format.csv.is_some() {
            Some("csv")
        } else if format.xlsx.is_some() {
            Some("xlsx")
        } else if format.parquet.is_some() {
            Some("parquet")
        } else {
            None
        }
    }

    pub fn xlsx_sheet(&self) -> Option<String> {
        self.source_format()
            .and_then(|format| format.xlsx.as_ref())
            .and_then(|xlsx| xlsx.sheet.clone())
    }

    pub fn xlsx_header_row(&self) -> Option<u32> {
        self.source_format()
            .and_then(|format| format.xlsx.as_ref())
            .and_then(|xlsx| xlsx.header_row)
    }

    pub fn header_row(&self) -> Option<u32> {
        self.source_format().and_then(|format| {
            format
                .xlsx
                .as_ref()
                .and_then(|xlsx| xlsx.header_row)
                .or_else(|| format.csv.as_ref().and_then(|csv| csv.header_row))
        })
    }

    pub fn xlsx_data_range(&self) -> Option<String> {
        self.source_format()
            .and_then(|format| format.xlsx.as_ref())
            .and_then(|xlsx| xlsx.data_range.clone())
    }

    pub fn csv_delimiter(&self) -> Option<u8> {
        self.source_format()
            .and_then(|format| format.csv.as_ref())
            .and_then(|csv| csv.delimiter)
    }

    pub fn csv_quote(&self) -> Option<u8> {
        self.source_format()
            .and_then(|format| format.csv.as_ref())
            .and_then(|csv| csv.quote)
    }

    pub fn effective_refresh<'a>(
        &'a self,
        dataset: &'a DatasetConfig,
    ) -> Option<&'a RefreshConfig> {
        self.refresh.as_ref().or(dataset.defaults.refresh.as_ref())
    }

    pub fn effective_materialization(&self, dataset: &DatasetConfig) -> MaterializationMode {
        self.materialization
            .or(dataset.defaults.materialization)
            .unwrap_or(MaterializationMode::Snapshot)
    }

    fn source_format(&self) -> Option<&ResourceFormatConfig> {
        self.source.format()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EntityConfig {
    pub name: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub table: ResourceId,
    #[serde(default)]
    pub concept_uri: Option<String>,
    #[serde(default)]
    pub fields: Vec<EntityFieldConfig>,
    #[serde(default)]
    pub relationships: Vec<EntityRelationshipConfig>,
    pub access: EntityAccessConfig,
    pub api: EntityApiConfig,
    #[serde(default)]
    pub aggregates: Vec<AggregateConfig>,
    #[serde(default)]
    pub publicschema: Option<EntityPublicSchemaConfig>,
    #[serde(default)]
    pub spatial: Option<EntitySpatialConfig>,
    /// Governed identity attribute-release profiles attached to this entity.
    /// Each profile resolves exactly one subject and returns only the
    /// configured, minimised claims. Empty by default (feature opt-in).
    #[serde(default)]
    pub attribute_release_profiles: Vec<AttributeReleaseProfile>,
}

/// A governed identity attribute-release profile. A profile is a
/// projection-limited, exactly-one-subject lookup that maps a configured set of
/// source fields (or CEL-computed expressions) into a minimised
/// OIDC/UserInfo-style claim bundle. It is *optionally* purpose-bound: a profile
/// that declares a `purpose` requires a matching `data-purpose` at resolve time;
/// one that omits it does not. Identified globally by the `(id, version)` pair;
/// both are required path segments at resolve time.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AttributeReleaseProfile {
    /// Profile identifier, lower-kebab/snake (`^[a-z][a-z0-9_-]*$`). Globally
    /// unique with `version`.
    pub id: String,
    /// Profile version. Globally unique with `id`; no silent "latest".
    pub version: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Data-purpose this profile is bound to. Required (and must be a member
    /// of the entity's `governed_policy.permitted_purposes`) when the backing
    /// entity declares any permitted purposes.
    #[serde(default)]
    pub purpose: Option<String>,
    /// Dataset-bound scope a caller must hold to invoke this release. Must
    /// differ from the entity's `read_scope`.
    pub release_scope: String,
    /// How the subject is identified and looked up.
    pub subject: ReleaseSubjectConfig,
    /// Optional CEL release-condition gate evaluated before projection.
    #[serde(default)]
    pub release_conditions: Option<ReleaseConditionsConfig>,
    /// Claims released on success. Non-empty; at least one `required`.
    pub claims: Vec<ReleaseClaimConfig>,
    /// Response envelope controls.
    #[serde(default)]
    pub response: ReleaseResponseConfig,
}

/// Subject-identification controls for an attribute-release profile.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSubjectConfig {
    /// Request input that carries the subject identifier.
    pub input: String,
    /// Source field used to match the subject. Must be an exposed entity field.
    pub source_field: String,
    /// Optional accepted identifier type label.
    #[serde(default)]
    pub id_type: Option<String>,
    /// Expected subject cardinality. Defaults to exactly one.
    #[serde(default = "default_subject_cardinality")]
    pub cardinality: SubjectCardinality,
}

/// Expected number of subjects a release lookup may match.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectCardinality {
    One,
    Many,
}

fn default_subject_cardinality() -> SubjectCardinality {
    SubjectCardinality::One
}

/// CEL release-condition gate. When present, the predicate must hold before
/// any claim is projected; failure fails closed (subject denied).
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseConditionsConfig {
    pub expression: ReleaseExpressionConfig,
    /// Optional internal audit code for a release-condition denial.
    #[serde(default)]
    pub denied_code: Option<String>,
}

/// A single CEL expression evaluated over the subject's source projection.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseExpressionConfig {
    pub cel: String,
}

/// A single released claim. Exactly one of `source_field` or `expression`
/// must be set: a claim is either a direct source-field projection or a
/// CEL-computed value.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseClaimConfig {
    /// Released claim name (lower-snake).
    pub name: String,
    /// Source field projected into the claim. XOR with `expression`.
    #[serde(default)]
    pub source_field: Option<String>,
    /// CEL-computed claim value. XOR with `source_field`.
    #[serde(default)]
    pub expression: Option<ReleaseExpressionConfig>,
    /// Whether the claim must be present; a missing required claim denies.
    #[serde(default)]
    pub required: bool,
    /// Optional privacy sensitivity label.
    #[serde(default)]
    pub sensitivity: Option<ClaimSensitivity>,
    /// Optional value format hint.
    #[serde(default)]
    pub format: Option<String>,
    /// Optional locale hint.
    #[serde(default)]
    pub locale: Option<String>,
    /// Whether the claim may be shared downstream. Defaults to true.
    #[serde(default = "default_claim_shareable")]
    pub shareable: bool,
}

fn default_claim_shareable() -> bool {
    true
}

/// Closed privacy-sensitivity classification for a released claim. This is a
/// separate, release-specific taxonomy and is intentionally not the
/// dataset-level `Sensitivity` enum.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSensitivity {
    DirectIdentifier,
    Personal,
    Public,
    Pseudonymous,
}

/// Response-envelope controls for an attribute-release profile.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseResponseConfig {
    /// Whether to include profile-sourced metadata in the response body.
    #[serde(default)]
    pub include_source_metadata: bool,
    /// Optional cache lifetime hint for the released bundle, in seconds.
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
}

pub const CRS84: &str = "http://www.opengis.net/def/crs/OGC/1.3/CRS84";

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EntitySpatialConfig {
    #[serde(default)]
    pub collection_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub geometry: SpatialGeometryConfig,
    #[serde(default)]
    pub bbox_fields: Option<SpatialBboxFieldsConfig>,
    #[serde(default)]
    pub datetime_field: Option<String>,
    #[serde(default = "default_max_bbox_degrees")]
    pub max_bbox_degrees: f64,
    #[serde(default = "default_max_geometry_vertices")]
    pub max_geometry_vertices: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpatialGeometryConfig {
    Point {
        longitude_field: String,
        latitude_field: String,
        crs: String,
    },
    Geojson {
        field: String,
        crs: String,
    },
    Wkt {
        field: String,
        crs: String,
    },
    Wkb {
        field: String,
        crs: String,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SpatialBboxFieldsConfig {
    pub min_x: String,
    pub min_y: String,
    pub max_x: String,
    pub max_y: String,
}

fn default_max_bbox_degrees() -> f64 {
    5.0
}

fn default_max_geometry_vertices() -> u32 {
    10_000
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EntityPublicSchemaConfig {
    /// PublicSchema concept name, for example `Person`.
    pub target: String,
    /// Path to a PublicSchema CEL mapping YAML document.
    pub mapping_path: PathBuf,
    /// JSON-LD context URL embedded in the issued VC. Defaults to the
    /// canonical PublicSchema draft context.
    #[serde(default)]
    pub context_url: Option<String>,
    /// JSON Schema URL embedded in `credentialSchema.id`. Defaults to
    /// `https://publicschema.org/schemas/{target}.schema.json`.
    #[serde(default)]
    pub schema_url: Option<String>,
    /// Optional local JSON Schema used to validate mapped
    /// credentialSubject output before signing.
    #[serde(default)]
    pub schema_validation_path: Option<PathBuf>,
    /// VC `type[1]` value. Defaults to `{target}` so a Person mapping
    /// issues a `["VerifiableCredential", "Person"]` credential.
    #[serde(default)]
    pub credential_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EntityFieldConfig {
    pub name: String,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub concept_uri: Option<String>,
    #[serde(default)]
    pub codelist: Option<String>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EntityRelationshipConfig {
    pub name: String,
    pub kind: RelationshipKind,
    pub target: String,
    pub foreign_key: String,
    #[serde(default)]
    pub concept_uri: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    BelongsTo,
    HasMany,
    HasOne,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EntityAccessConfig {
    pub metadata_scope: String,
    pub aggregate_scope: String,
    pub read_scope: String,
    #[serde(default)]
    pub evidence_verification_scope: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EntityApiConfig {
    pub default_limit: u32,
    pub max_limit: u32,
    #[serde(default)]
    pub require_purpose_header: bool,
    #[serde(default)]
    pub governed_policy: Option<GovernedPolicyConfig>,
    /// Alternative fields that can satisfy the row-scope gate. A
    /// principal-bound equality filter on any listed field is sufficient, so
    /// list multiple fields only when each is an acceptable boundary.
    #[serde(default)]
    pub required_filters: Vec<String>,
    /// Principal-derived bindings that both satisfy the required filter gate
    /// and are applied to the query.
    #[serde(default)]
    pub required_filter_bindings: Vec<RequiredFilterBindingConfig>,
    #[serde(default)]
    pub allowed_filters: Vec<AllowedFilter>,
    #[serde(default)]
    pub allowed_expansions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequiredFilterBindingConfig {
    pub field: String,
    #[serde(default)]
    pub source: RequiredFilterBindingSource,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequiredFilterBindingSource {
    #[default]
    PrincipalId,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GovernedPolicyConfig {
    #[serde(default)]
    pub permitted_purposes: Vec<String>,
    #[serde(default)]
    pub permitted_jurisdictions: Vec<String>,
    #[serde(default)]
    pub allowed_assurance: Vec<String>,
    #[serde(default)]
    pub minimum_assurance: Option<String>,
    #[serde(default)]
    pub max_source_age_seconds: Option<u64>,
    #[serde(default)]
    pub require_legal_basis: bool,
    #[serde(default)]
    pub require_consent: bool,
    #[serde(default)]
    pub redaction_fields: Vec<String>,
    #[serde(default)]
    pub trusted_context: GovernedTrustedContextConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GovernedTrustedContextConfig {
    #[serde(default)]
    pub jurisdiction: Option<String>,
    #[serde(default)]
    pub asserted_assurance: Option<String>,
    #[serde(default)]
    pub legal_basis_ref: Option<String>,
    #[serde(default)]
    pub consent_ref: Option<String>,
    #[serde(default)]
    pub source_observed_age_seconds: Option<u64>,
}

/// Declared resource schema. `strict` is the spec's `strict_schema`
/// flag; on mismatch ingestion refuses to register the resource.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SchemaConfig {
    #[serde(default)]
    pub strict: bool,
    pub fields: Vec<FieldConfig>,
}

/// One column in a resource schema. Physical type and optional
/// semantic annotations used by catalog and schema metadata.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FieldConfig {
    pub name: String,
    pub r#type: FieldType,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub concept_uri: Option<String>,
    #[serde(default)]
    pub codelist: Option<String>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

/// Physical type of a column. The set is fixed in V1; semantic types
/// are carried via `concept_uri`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    String,
    Number,
    Integer,
    Boolean,
    Date,
    Timestamp,
}

/// Resource-level scope assignments. Private tables are not exposed as row
/// resources in beta; row access is configured on public entities.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceAccessConfig {
    pub metadata_scope: String,
    pub aggregate_scope: String,
}

/// Resource-level API knobs: per-field filter allowlist, limit caps,
/// and the `Data-Purpose` requirement.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceApiConfig {
    pub default_limit: u32,
    pub max_limit: u32,
    #[serde(default)]
    pub require_purpose_header: bool,
    #[serde(default)]
    pub allowed_filters: Vec<AllowedFilter>,
}

impl Default for ResourceApiConfig {
    fn default() -> Self {
        Self {
            default_limit: 100,
            max_limit: 1000,
            require_purpose_header: false,
            allowed_filters: Vec::new(),
        }
    }
}

/// A single allowed filter: field name + permitted operators.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AllowedFilter {
    pub field: String,
    pub ops: Vec<FilterOp>,
}

/// Filter operator opted into per field.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Eq,
    In,
    Gte,
    Lte,
    Between,
}

/// Aggregate declaration: group-by columns, measures, disclosure
/// control.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AggregateConfig {
    pub id: AggregateId,
    #[serde(default)]
    pub title: Option<String>,
    pub description: String,
    #[serde(default)]
    pub source_entity: Option<String>,
    #[serde(default)]
    pub default_group_by: Vec<String>,
    #[serde(default)]
    pub dimensions: Vec<AggregateDimensionConfig>,
    #[serde(default)]
    pub indicators: Vec<AggregateIndicatorConfig>,
    #[serde(default)]
    pub allowed_filters: Vec<AllowedFilter>,
    /// Alternative fields or dimensions that can satisfy the aggregate gate. A
    /// principal-bound equality filter on any listed field is sufficient, so
    /// list multiple fields only when each is an acceptable boundary.
    #[serde(default)]
    pub required_filters: Vec<String>,
    /// Principal-derived bindings that both satisfy the required filter gate
    /// and are applied to the aggregate query.
    #[serde(default)]
    pub required_filter_bindings: Vec<RequiredFilterBindingConfig>,
    #[serde(default)]
    pub temporal_field: Option<String>,
    #[serde(default)]
    pub access: Option<AggregateAccessConfig>,
    #[serde(default)]
    pub spatial: Option<AggregateSpatialConfig>,
    /// Legacy entity-local aggregate fields. These stay parseable while
    /// the public surface moves to dataset-level aggregates.
    #[serde(default)]
    pub joins: Vec<AggregateJoinConfig>,
    #[serde(default)]
    pub group_by: Vec<String>,
    #[serde(default)]
    pub measures: Vec<AggregateMeasure>,
    pub disclosure_control: DisclosureControlConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AggregateAccessConfig {
    #[serde(default)]
    pub metadata_scope: Option<String>,
    #[serde(default)]
    pub aggregate_scope: Option<String>,
    #[serde(default)]
    pub aggregate_only_execution: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AggregateDimensionConfig {
    pub id: String,
    pub label: String,
    pub field: String,
    #[serde(default)]
    pub codelist: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AggregateIndicatorConfig {
    pub id: String,
    pub label: String,
    pub function: AggregateFunction,
    pub column: String,
    pub unit_measure: String,
    #[serde(default)]
    pub unit_mult: Option<i32>,
    #[serde(default)]
    pub decimals: Option<u32>,
    #[serde(default)]
    pub frequency: Option<String>,
    #[serde(default)]
    pub definition_uri: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum AggregateSpatialConfig {
    AdminArea {
        #[serde(default)]
        collection_id: Option<String>,
        dimension: String,
        geometry_entity: String,
        geometry_id_field: String,
        geometry_field: String,
        #[serde(default)]
        bbox_fields: Option<SpatialBboxFieldsConfig>,
        #[serde(default = "default_max_geometry_vertices")]
        max_geometry_vertices: u32,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AggregateJoinConfig {
    pub relationship: String,
}

/// One measure inside an aggregate.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AggregateMeasure {
    pub name: String,
    pub function: AggregateFunction,
    pub column: String,
}

/// Aggregate function. V1 supports the basic set plus the
/// optional functions (`median`, `count_distinct`, `stddev`).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AggregateFunction {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    Median,
    CountDistinct,
    Stddev,
}

/// Disclosure control settings per aggregate. Defaults to
/// `min_group_size: 5`, `suppression: omit`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureControlConfig {
    #[serde(default = "default_disclosure_methods")]
    pub method: Vec<String>,
    #[serde(default = "default_min_group_size")]
    pub min_cell_size: u32,
    #[serde(default)]
    pub min_group_size: Option<u32>,
    #[serde(default)]
    pub suppression: Suppression,
    #[serde(default)]
    pub report_suppressed_rows: bool,
}

fn default_min_group_size() -> u32 {
    5
}

fn default_disclosure_methods() -> Vec<String> {
    vec!["k-anonymity".to_string()]
}

impl DisclosureControlConfig {
    #[must_use]
    pub fn effective_min_cell_size(&self) -> u32 {
        self.min_group_size.unwrap_or(self.min_cell_size)
    }
}

/// Disclosure suppression strategy.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Suppression {
    /// Remove rows below the threshold from the response entirely.
    #[default]
    Omit,
    /// Keep the group key, null out the measures.
    Mask,
    /// Standards-facing alias for `mask`: values are represented as JSON null.
    Null,
}

/// Sensitivity classification. Operator-defined values cover common
/// personal and public dataset classifications in V1.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Sensitivity {
    Public,
    Internal,
    Personal,
    Confidential,
    Secret,
}

/// Access rights classification, mirrors DCAT-AP `dcterms:accessRights`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AccessRights {
    Public,
    Restricted,
    NonPublic,
}

/// Update cadence; mirrors DCAT-AP `dcterms:accrualPeriodicity`. The
/// V1 set is the codes used by the example plus the common alternates.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UpdateFrequency {
    Continuous,
    Daily,
    Weekly,
    Termly,
    Monthly,
    Quarterly,
    Annual,
    Irregular,
    AsNeeded,
    Unknown,
}

// ---------------------------------------------------------------------
// ID newtypes. Format is validated in `validate::run`.
// ---------------------------------------------------------------------

/// Dataset identifier. Lower-snake, starts with a letter.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(transparent)]
pub struct DatasetId(String);

/// Resource identifier within a dataset.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(transparent)]
pub struct ResourceId(String);

/// Aggregate identifier within a resource.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(transparent)]
pub struct AggregateId(String);

macro_rules! impl_id {
    ($ty:ident) => {
        impl $ty {
            /// Borrow the inner string. Equivalent to `as_ref()` but
            /// available in const contexts is not required here.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

impl_id!(DatasetId);
impl_id!(ResourceId);
impl_id!(AggregateId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_newtypes_display_and_as_ref() {
        let id = DatasetId("hello".to_string());
        assert_eq!(id.as_ref(), "hello");
        assert_eq!(id.to_string(), "hello");
    }

    #[test]
    fn default_request_timeout_is_30s() {
        assert_eq!(default_request_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn default_transport_limits_are_bounded() {
        assert_eq!(default_request_body_timeout(), Duration::from_secs(10));
        assert_eq!(default_http1_header_read_timeout(), Duration::from_secs(10));
        assert_eq!(default_max_connections(), 1024);
    }

    #[test]
    fn default_cache_dir_is_cache() {
        assert_eq!(default_cache_dir(), PathBuf::from("./cache"));
    }

    #[test]
    fn default_xlsx_max_file_bytes_is_256_mib() {
        assert_eq!(default_xlsx_max_file_bytes(), 256 * 1024 * 1024);
    }

    #[test]
    fn default_max_source_file_bytes_is_256_mib() {
        assert_eq!(default_max_source_file_bytes(), 256 * 1024 * 1024);
    }

    #[test]
    fn default_mtime_interval_is_60s() {
        assert_eq!(default_mtime_interval(), Duration::from_secs(60));
    }

    #[test]
    fn default_min_group_size_is_5() {
        assert_eq!(default_min_group_size(), 5);
    }

    #[test]
    fn suppression_default_is_omit() {
        assert_eq!(Suppression::default(), Suppression::Omit);
    }

    #[test]
    fn default_subject_cardinality_is_one() {
        assert_eq!(default_subject_cardinality(), SubjectCardinality::One);
    }

    #[test]
    fn default_claim_shareable_is_true() {
        assert!(default_claim_shareable());
    }

    #[test]
    fn release_response_config_default_is_minimal() {
        let response = ReleaseResponseConfig::default();
        assert!(!response.include_source_metadata);
        assert_eq!(response.max_age_seconds, None);
    }

    #[test]
    fn auth_failure_throttle_config_defaults_to_disabled() {
        let throttle = AuthFailureThrottleConfig::default();
        assert!(!throttle.enabled);
        assert_eq!(throttle.max_failures, 20);
        assert_eq!(throttle.window_seconds, 60);
    }
}
