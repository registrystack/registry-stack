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

use serde::Deserialize;

pub mod capabilities;
pub mod loader;
pub mod provenance;
pub mod validate;
pub mod vocabularies;

pub use loader::load;
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

/// Catalog-level metadata surfaced by `/catalog` and DCAT-AP outputs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogConfig {
    pub title: String,
    pub base_url: String,
    pub publisher: String,
    #[serde(default)]
    pub participant_id: Option<String>,
}

/// Authentication configuration. V1 supports api_key only.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub mode: AuthMode,
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,
}

/// Authentication mode tag. Non-exhaustive so JWT/dataspace variants
/// land additively in V2.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthMode {
    /// Hashed shared secret in an environment variable.
    ApiKey,
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

/// Audit configuration. Sink choice gates further fields via the
/// tagged `AuditSinkConfig` enum. The enum is flattened onto the
/// containing struct so that the YAML `sink:` key acts as the
/// discriminator, matching the example in Spec.md Section 4.
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
    #[serde(default)]
    pub defaults: DatasetDefaultsConfig,
    #[serde(default)]
    pub source: Option<SourceConfig>,
    #[serde(default)]
    pub refresh: Option<RefreshConfig>,
    #[serde(default)]
    pub tables: Vec<ResourceConfig>,
    #[serde(default)]
    pub resources: Vec<ResourceConfig>,
    #[serde(default)]
    pub entities: Vec<EntityConfig>,
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
    /// Storage-layer tables, accepting `resources` as a legacy alias
    /// until all fixtures and deployments migrate.
    pub fn table_configs(&self) -> impl Iterator<Item = &ResourceConfig> {
        self.tables.iter().chain(self.resources.iter())
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
        #[serde(default)]
        header_row: Option<u32>,
        #[serde(default)]
        data_range: Option<String>,
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
    // Spec.md Section 6.1: "default 60s".
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
    #[serde(default)]
    pub source: Option<SourceConfig>,
    #[serde(default)]
    pub refresh: Option<RefreshConfig>,
    #[serde(default)]
    pub materialization: Option<MaterializationMode>,
    #[serde(default)]
    pub format: Option<ResourceFormatConfig>,
    #[serde(default)]
    pub sheet: Option<String>,
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
        let format = self.source_format().or(self.format.as_ref())?;
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
            .or(self.format.as_ref())
            .and_then(|format| format.xlsx.as_ref())
            .and_then(|xlsx| xlsx.sheet.clone())
            .or_else(|| self.sheet.clone())
    }

    pub fn xlsx_header_row(&self) -> Option<u32> {
        self.source_format()
            .or(self.format.as_ref())
            .and_then(|format| format.xlsx.as_ref())
            .and_then(|xlsx| xlsx.header_row)
    }

    pub fn xlsx_data_range(&self) -> Option<String> {
        self.source_format()
            .or(self.format.as_ref())
            .and_then(|format| format.xlsx.as_ref())
            .and_then(|xlsx| xlsx.data_range.clone())
    }

    pub fn csv_delimiter(&self) -> Option<u8> {
        self.source_format()
            .or(self.format.as_ref())
            .and_then(|format| format.csv.as_ref())
            .and_then(|csv| csv.delimiter)
    }

    pub fn csv_quote(&self) -> Option<u8> {
        self.source_format()
            .or(self.format.as_ref())
            .and_then(|format| format.csv.as_ref())
            .and_then(|csv| csv.quote)
    }

    pub fn effective_refresh<'a>(
        &'a self,
        dataset: &'a DatasetConfig,
    ) -> Option<&'a RefreshConfig> {
        self.refresh
            .as_ref()
            .or(dataset.defaults.refresh.as_ref())
            .or(dataset.refresh.as_ref())
    }

    pub fn effective_materialization(&self, dataset: &DatasetConfig) -> MaterializationMode {
        self.materialization
            .or(dataset.defaults.materialization)
            .unwrap_or(MaterializationMode::Snapshot)
    }

    pub fn effective_source<'a>(&'a self, dataset: &'a DatasetConfig) -> Option<&'a SourceConfig> {
        self.source.as_ref().or(dataset.source.as_ref())
    }

    fn source_format(&self) -> Option<&ResourceFormatConfig> {
        self.source.as_ref().and_then(SourceConfig::format)
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
    pub verify_scope: String,
    pub bulk_export_scope: String,
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
/// semantic annotations per Spec.md Section 11.bis.
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

/// Filter operator opted into per field. Per Spec.md Section 9.
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

/// Aggregate function. Spec.md Section 10 supported set plus the
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

/// Disclosure control settings per aggregate. Per Spec.md Section
/// 10.1: defaults to `min_group_size: 5`, `suppression: omit`.
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

/// Sensitivity classification. Operator-defined per Spec.md Section
/// 4; common values cover personal / public datasets in V1.
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
