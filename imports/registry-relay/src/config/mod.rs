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

use serde::{Deserialize, Serialize};

pub mod capabilities;
pub mod loader;
pub mod provenance;
pub mod validate;
pub mod vocabularies;

pub use loader::{load, load_metadata_manifest, load_with_metadata, LoadedConfig};
pub use provenance::{
    ClaimValidity, DelegatedIssuerConfig, GatewayIssuerConfig, IssuerConfig, KmsProvider,
    KmsSignerConfig, ProvenanceAlgorithm, ProvenanceConfig, RetiredKeyConfig, SignerConfig,
    SoftwareSignerConfig,
};

/// Root configuration document. Parsed from YAML at startup.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
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
    /// Optional claim-verification runtime secret configuration. Required
    /// when any entity declares `claim_verification`.
    #[serde(default)]
    pub claim_verification: Option<ClaimVerificationConfig>,
    /// Runtime controls for evidence-offering verification.
    #[serde(default)]
    pub evidence_verification: EvidenceVerificationConfig,
    /// Deprecated embedded Evidence Server config.
    ///
    /// Registry Relay no longer runs Evidence Server. The field remains in
    /// the parser only so validation can reject old non-null configs with a
    /// migration error instead of surfacing an unknown-field parse error.
    #[serde(default = "default_ignored_evidence_config")]
    pub evidence: serde_yml::Value,
    /// Optional external standards adapters. The config model is parsed
    /// in every build so feature-disabled binaries can reject it with a
    /// stable taxonomy code.
    #[serde(default)]
    pub standards: StandardsConfig,
}

/// Optional split metadata manifest loaded alongside the runtime config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataConfig {
    pub manifest_path: PathBuf,
}

fn default_ignored_evidence_config() -> serde_yml::Value {
    serde_yml::Value::Null
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimVerificationConfig {
    #[serde(default = "default_claim_verification_binding_key_id")]
    pub binding_key_id: String,
    pub binding_key_env: String,
}

fn default_claim_verification_binding_key_id() -> String {
    "v1".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceVerificationConfig {
    #[serde(default)]
    pub rate_limit: EvidenceVerificationRateLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceVerificationRateLimitConfig {
    #[serde(default = "default_evidence_rate_limit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_evidence_rate_limit_burst")]
    pub burst: u32,
    #[serde(default = "default_evidence_rate_limit_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_evidence_rate_limit_max_buckets")]
    pub max_buckets: usize,
}

impl Default for EvidenceVerificationRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_evidence_rate_limit_enabled(),
            burst: default_evidence_rate_limit_burst(),
            window_seconds: default_evidence_rate_limit_window_seconds(),
            max_buckets: default_evidence_rate_limit_max_buckets(),
        }
    }
}

const fn default_evidence_rate_limit_enabled() -> bool {
    true
}

const fn default_evidence_rate_limit_burst() -> u32 {
    120
}

const fn default_evidence_rate_limit_window_seconds() -> u64 {
    60
}

const fn default_evidence_rate_limit_max_buckets() -> usize {
    8192
}

/// External standards adapters layered over configured entities.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardsConfig {
    #[serde(default)]
    pub spdci: Option<SpdciStandardsConfig>,
}

/// Social Protection Digital Convergence Initiative (SP DCI) adapter
/// configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpdciStandardsConfig {
    #[serde(default)]
    pub disability_registry: Option<SpdciDisabilityRegistryConfig>,
    #[serde(default)]
    pub registries: BTreeMap<String, SpdciRegistryConfig>,
}

/// Runtime binding from a DCI registry sync search API to one configured
/// Registry Relay entity.
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    #[serde(default)]
    pub admin_bind: Option<SocketAddr>,
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
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(30)
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
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustProxyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

/// CORS allowlist; default-deny per Section 17 item 7.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// Catalog-level metadata surfaced by `/metadata/*` and DCAT outputs.
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub mode: AuthMode,
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
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

/// One configured API key, identified by an id and a `hash_env` env
/// var name. The raw hash never appears in config; it is read at
/// startup from the named env var.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyConfig {
    pub id: String,
    pub hash_env: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// OIDC / OAuth2 resource-server configuration. The relay validates
/// incoming bearer JWTs against a configured external IdP. No tokens
/// are minted here.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Issuer URL. Compared verbatim against the JWT `iss` claim.
    pub issuer: String,
    /// One or more accepted `aud` values. Tokens with no `aud`, or
    /// whose `aud` does not intersect this list, are rejected.
    pub audience: Vec<String>,
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
    /// Signature algorithms accepted by the verifier. Defaults to
    /// RS256, ES256, EdDSA. HS\* and `none` are intentionally absent
    /// from [`OidcAlgorithm`].
    #[serde(default = "default_oidc_algorithms")]
    pub algorithms: Vec<OidcAlgorithm>,
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
    /// or `permissions`; the value may be either a string or an array
    /// of strings.
    #[serde(default = "default_oidc_scope_claim")]
    pub scope_claim: String,
    /// Optional rename map: `external_scope -> internal_scope`. Applied
    /// after parsing the scope claim, before scope-based access checks
    /// run. Useful for adapting IdP role names (`role:foo`) to the
    /// relay's `<dataset_id>:<level>` shape.
    #[serde(default)]
    pub scope_map: BTreeMap<String, String>,
    /// Optional allowlist of client identifiers, matched against the
    /// token's `azp` (preferred) or `client_id` claim. Empty list
    /// means any client is accepted.
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    /// Accepted `typ` JOSE header values. Defaults to `JWT` and
    /// `at+jwt` (RFC 9068). ID tokens (`id+jwt`) are not access tokens
    /// and are rejected by default.
    #[serde(default = "default_oidc_token_types")]
    pub token_types: Vec<String>,
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
#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    #[serde(flatten)]
    pub sink: AuditSinkConfig,
    #[serde(default = "default_audit_format")]
    pub format: AuditFormat,
    #[serde(default)]
    pub chain: bool,
    #[serde(default)]
    pub include_health: bool,
}

fn default_audit_format() -> AuditFormat {
    AuditFormat::Jsonl
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicServiceConfig {
    #[serde(default)]
    pub id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Optional table defaults for reducing repetition within one dataset.
#[derive(Debug, Clone, Default, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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

/// Refresh policy. Tagged on `mode:`.
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceFormatConfig {
    #[serde(default)]
    pub csv: Option<CsvFormatConfig>,
    #[serde(default)]
    pub xlsx: Option<XlsxFormatConfig>,
    #[serde(default)]
    pub parquet: Option<ParquetFormatConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsvFormatConfig {
    #[serde(default)]
    pub header_row: Option<u32>,
    #[serde(default)]
    pub delimiter: Option<u8>,
    #[serde(default)]
    pub quote: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XlsxFormatConfig {
    #[serde(default)]
    pub sheet: Option<String>,
    #[serde(default)]
    pub header_row: Option<u32>,
    #[serde(default)]
    pub data_range: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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
    #[serde(default)]
    pub claim_verification: Option<EntityClaimVerificationConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityClaimVerificationConfig {
    #[serde(default)]
    pub rulesets: BTreeMap<String, ClaimVerificationRulesetConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimVerificationRulesetConfig {
    pub mode: String,
    pub required_claims: Vec<String>,
    pub candidate_lookup: Vec<String>,
    pub match_fields: BTreeMap<String, String>,
    #[serde(default)]
    pub subject_id_claim: Option<String>,
    #[serde(default)]
    pub allow_subject_id_targeting: bool,
    #[serde(default)]
    pub expose_ambiguous: bool,
    #[serde(default)]
    pub diagnostics: bool,
    #[serde(default)]
    pub scope: Option<String>,
}

impl ClaimVerificationRulesetConfig {
    pub const NORMALIZED_EXACT_MODE: &'static str = "normalized_exact";

    /// Scope required to use this ruleset. A ruleset-specific scope
    /// overrides the entity-level claim verification scope. If neither
    /// is configured, callers are denied by default.
    pub fn required_scope<'a>(&'a self, access: &'a EntityAccessConfig) -> Option<&'a str> {
        self.scope
            .as_deref()
            .or_else(|| access.claim_verification_required_scope())
    }
}

pub const CRS84: &str = "http://www.opengis.net/def/crs/OGC/1.3/CRS84";

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityAccessConfig {
    pub metadata_scope: String,
    pub aggregate_scope: String,
    pub read_scope: String,
    #[serde(default)]
    pub evidence_verification_scope: String,
    #[serde(default)]
    pub claim_verification_scope: Option<String>,
}

impl EntityAccessConfig {
    /// Entity-level scope for the internal submitted-claim engine. Older
    /// configs may omit this field; absence intentionally means the engine is
    /// denied unless a ruleset declares its own scope.
    pub fn claim_verification_required_scope(&self) -> Option<&str> {
        self.claim_verification_scope.as_deref()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityApiConfig {
    pub default_limit: u32,
    pub max_limit: u32,
    #[serde(default)]
    pub require_purpose_header: bool,
    #[serde(default)]
    pub required_filters: Vec<String>,
    #[serde(default)]
    pub allowed_filters: Vec<AllowedFilter>,
    #[serde(default)]
    pub allowed_expansions: Vec<String>,
}

/// Declared resource schema. `strict` is the spec's `strict_schema`
/// flag; on mismatch ingestion refuses to register the resource.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaConfig {
    #[serde(default)]
    pub strict: bool,
    pub fields: Vec<FieldConfig>,
}

/// One column in a resource schema. Physical type and optional
/// semantic annotations used by catalog and schema metadata.
#[derive(Debug, Clone, Deserialize)]
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

/// Resource-level scope assignments. Each resource opts in to which
/// scopes gate metadata / aggregate / row access.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAccessConfig {
    pub metadata_scope: String,
    pub aggregate_scope: String,
    pub row_scope: String,
}

/// Resource-level API knobs: per-field filter allowlist, limit caps,
/// and the `Data-Purpose` requirement.
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateConfig {
    pub id: AggregateId,
    pub description: String,
    #[serde(default)]
    pub joins: Vec<AggregateJoinConfig>,
    pub group_by: Vec<String>,
    pub measures: Vec<AggregateMeasure>,
    pub disclosure_control: DisclosureControlConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateJoinConfig {
    pub relationship: String,
}

/// One measure inside an aggregate.
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureControlConfig {
    #[serde(default = "default_min_group_size")]
    pub min_group_size: u32,
    #[serde(default)]
    pub suppression: Suppression,
}

fn default_min_group_size() -> u32 {
    5
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
}
